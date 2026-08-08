//! A minimal SOCKS5 client, so the harness can measure *through* the proxy.
//!
//! Reuses `vigil_proxy::socks5` for the wire format rather than reimplementing it — if the
//! encoder and the decoder disagree, these tests are where it shows.
//!
//! Deliberately requests the target by **hostname**, not by resolved address: the proxy has
//! to see the name for hostname-derived split markers to mean anything, and it is what a
//! browser configured with a SOCKS5 proxy does.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use vigil_proxy::socks5;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The proxy refused the handshake or the CONNECT.
    Refused(u8),
    /// The proxy spoke something other than SOCKS5.
    Protocol,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Refused(c) => write!(f, "proxy refused, rep={c:#04x}"),
            Error::Protocol => f.write_str("not socks5"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Connect to `proxy`, ask it for `host:port`, and hand back the established stream.
pub fn connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, Error> {
    let mut s = TcpStream::connect_timeout(&proxy, timeout)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;

    s.write_all(&[socks5::VERSION, 1, socks5::METHOD_NO_AUTH])?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m)?;
    if m[0] != socks5::VERSION {
        return Err(Error::Protocol);
    }
    if m[1] != socks5::METHOD_NO_AUTH {
        return Err(Error::Refused(m[1]));
    }

    let mut req = vec![socks5::VERSION, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != socks5::VERSION {
        return Err(Error::Protocol);
    }
    if head[1] != 0x00 {
        return Err(Error::Refused(head[1]));
    }
    // Consume the bound address, whose length depends on the address type.
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n)?;
            n[0] as usize + 2
        }
        0x04 => 16 + 2,
        _ => return Err(Error::Protocol),
    };
    let mut sink = vec![0u8; rest];
    s.read_exact(&mut sink)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Stand up a real vigil proxy and a stub upstream, then drive both through this client.
    /// The point is that the client and the server were written against the same module and
    /// must agree on the wire.
    #[test]
    fn round_trips_through_a_real_vigil_proxy() {
        let up = TcpListener::bind("127.0.0.1:0").expect("stub");
        let up_addr = up.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in up.incoming() {
                let Ok(mut c) = c else { continue };
                std::thread::spawn(move || {
                    let mut b = [0u8; 4096];
                    while let Ok(n) = c.read(&mut b) {
                        if n == 0 || c.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let cfg = vigil_proxy::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            strategy: vigil_core::strategy::Strategy::measured_default(),
            ..Default::default()
        };
        let server = vigil_proxy::Server::new(cfg);
        let l = server.bind().expect("bind");
        let paddr = l.local_addr().unwrap();
        std::thread::spawn(move || server.serve(l));

        let mut s = connect(paddr, "127.0.0.1", up_addr.port(), Duration::from_secs(5))
            .expect("socks connect");
        let payload = b"\x16\x03\x01\x00\x20some client hello-ish bytes here";
        s.write_all(payload).expect("write");
        let mut back = vec![0u8; payload.len()];
        s.read_exact(&mut back).expect("echo");
        assert_eq!(back, payload, "payload corrupted through the proxy");
    }

    #[test]
    fn a_dead_proxy_is_an_error_not_a_hang() {
        // port 1 on loopback: nothing listens
        let err = connect(
            "127.0.0.1:1".parse().unwrap(),
            "example.com",
            443,
            Duration::from_millis(500),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got {err}");
    }

    #[test]
    fn a_server_that_is_not_socks5_is_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                // Read the greeting before answering, the way any server does, and stay open until
                // the client has finished. Both halves are needed on Windows: answering a peer that
                // has not spoken yet, and then closing while the reply is still in flight, made the
                // client read a reset instead of the reply — `Error::Io` where this test is about
                // `Error::Protocol`. Measured on the Windows target: 2 failures in 5 runs originally,
                // 1 in 8 with only the second half. Linux passed every time, which is how it survived
                // this long. The trailing read returns 0 the moment the client drops its end, so this
                // waits no longer than the test does.
                let mut greeting = [0u8; 3];
                let _ = c.read_exact(&mut greeting);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                let mut sink = [0u8; 1];
                let _ = c.read(&mut sink);
            }
        });
        let err = connect(a, "example.com", 443, Duration::from_secs(2)).unwrap_err();
        assert!(matches!(err, Error::Protocol), "got {err}");
    }
}
