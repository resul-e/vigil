//! One connection attempt: drive a TLS handshake with the first flight written our way,
//! then issue a real HTTP request so success means *end to end*, not just a ServerHello.
//!
//! rustls is driven manually rather than through `Stream` so we own the exact `write()`
//! boundaries of the first flight. That is the entire point of the harness.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection};
use rustls_pki_types::ServerName;
use vigil_core::{chunks, Outcome, SplitPoint};

use crate::socks_client;

pub struct Attempt {
    pub outcome: Outcome,
    /// Size of the ClientHello we actually put on the wire. Must be reported: a flight
    /// larger than the MSS is pre-split by the kernel and is not a valid baseline.
    pub client_hello_len: usize,
    /// First line of the HTTP response, when we got that far.
    pub status_line: Option<String>,
}

/// Classify an I/O error into the vocabulary the report uses.
fn classify(e: &std::io::Error) -> Outcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted | BrokenPipe => Outcome::Reset,
        WouldBlock | TimedOut => Outcome::Timeout,
        UnexpectedEof => Outcome::Closed,
        _ => Outcome::Other(format!("{:?}", e.kind())),
    }
}

/// Where the TCP connection goes: straight to the target, or via a SOCKS5 proxy that is
/// asked for the target by hostname.
#[derive(Debug, Clone, Copy)]
pub enum Route {
    Direct,
    Socks5(SocketAddr),
}

pub fn run_via(
    host: &str,
    addr: SocketAddr,
    split: &SplitPoint,
    cfg: Arc<ClientConfig>,
    timeout: Duration,
    route: Route,
) -> Attempt {
    let mut out = Attempt {
        outcome: Outcome::Ok,
        client_hello_len: 0,
        status_line: None,
    };

    let name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => {
            out.outcome = Outcome::Other(format!("bad server name: {e}"));
            return out;
        }
    };
    let mut conn = match ClientConnection::new(cfg, name) {
        Ok(c) => c,
        Err(e) => {
            out.outcome = Outcome::Other(format!("tls init: {e}"));
            return out;
        }
    };

    let mut sock = match route {
        Route::Direct => match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => s,
            Err(e) => {
                out.outcome = classify(&e);
                return out;
            }
        },
        Route::Socks5(p) => match socks_client::connect(p, host, addr.port(), timeout) {
            Ok(s) => s,
            Err(socks_client::Error::Io(e)) => {
                out.outcome = classify(&e);
                return out;
            }
            Err(e) => {
                out.outcome = Outcome::Other(format!("socks: {e}"));
                return out;
            }
        },
    };
    let _ = sock.set_nodelay(true);
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    // Phase 1 — capture the first flight, then write it with the split applied.
    let mut flight = Vec::new();
    while conn.wants_write() {
        if let Err(e) = conn.write_tls(&mut flight) {
            out.outcome = Outcome::Other(format!("write_tls: {e}"));
            return out;
        }
    }
    out.client_hello_len = flight.len();
    for part in chunks(&flight, split) {
        if let Err(e) = sock.write_all(part) {
            out.outcome = classify(&e);
            return out;
        }
    }

    // Phase 2 — ordinary handshake, straight to the socket now.
    while conn.is_handshaking() {
        if conn.wants_write() {
            if let Err(e) = conn.write_tls(&mut sock) {
                out.outcome = classify(&e);
                return out;
            }
            continue;
        }
        match conn.read_tls(&mut sock) {
            Ok(0) => {
                out.outcome = Outcome::Closed;
                return out;
            }
            Ok(_) => {}
            Err(e) => {
                out.outcome = classify(&e);
                return out;
            }
        }
        if let Err(e) = conn.process_new_packets() {
            out.outcome = Outcome::TlsError;
            let _ = e;
            return out;
        }
    }
    // flush any remaining handshake bytes
    while conn.wants_write() {
        if let Err(e) = conn.write_tls(&mut sock) {
            out.outcome = classify(&e);
            return out;
        }
    }

    // Phase 3 — a real request, so "ok" means the session actually carries data.
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: dpi-probe\r\n\r\n"
    );
    if conn.writer().write_all(req.as_bytes()).is_err() {
        out.outcome = Outcome::Other("request write".into());
        return out;
    }
    while conn.wants_write() {
        if let Err(e) = conn.write_tls(&mut sock) {
            out.outcome = classify(&e);
            return out;
        }
    }

    let mut plain = Vec::new();
    loop {
        match conn.read_tls(&mut sock) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                out.outcome = classify(&e);
                return out;
            }
        }
        let state = match conn.process_new_packets() {
            Ok(s) => s,
            Err(_) => {
                out.outcome = Outcome::TlsError;
                return out;
            }
        };
        if state.plaintext_bytes_to_read() > 0 {
            let mut buf = vec![0u8; state.plaintext_bytes_to_read()];
            if conn.reader().read_exact(&mut buf).is_ok() {
                plain.extend_from_slice(&buf);
            }
        }
        if plain.contains(&b'\n') || plain.len() > 4096 {
            break;
        }
        if state.peer_has_closed() {
            break;
        }
    }

    match String::from_utf8_lossy(&plain).lines().next() {
        Some(l) if !l.trim().is_empty() => {
            out.status_line = Some(l.trim().to_string());
            out.outcome = Outcome::Ok;
        }
        _ => out.outcome = Outcome::Closed,
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn reset_family_maps_to_reset() {
        for k in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
        ] {
            assert_eq!(classify(&Error::new(k, "x")), Outcome::Reset, "{k:?}");
        }
    }

    #[test]
    fn timeout_family_maps_to_timeout() {
        for k in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
            assert_eq!(classify(&Error::new(k, "x")), Outcome::Timeout, "{k:?}");
        }
    }

    #[test]
    fn eof_maps_to_closed() {
        assert_eq!(
            classify(&Error::new(ErrorKind::UnexpectedEof, "x")),
            Outcome::Closed
        );
    }

    /// Unknown kinds must stay visible rather than being silently folded into a known bucket.
    #[test]
    fn unknown_kind_is_reported_not_swallowed() {
        let o = classify(&Error::new(ErrorKind::PermissionDenied, "x"));
        match o {
            Outcome::Other(s) => assert!(s.contains("PermissionDenied")),
            other => panic!("expected Other, got {other}"),
        }
    }
}
