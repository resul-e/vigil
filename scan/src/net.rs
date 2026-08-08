//! Two ways to ask the same question: does a ClientHello for this name get an answer?
//!
//! Directly, and through a proxy. The pair is the whole point — either alone is a number
//! without a comparison, and this project's rule is that a cell without its control is not a
//! measurement.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Straight at the server, one write, the shape of client this DPI blocks.
pub fn direct(host: &str) -> Result<(), String> {
    let addr = vigil_proxy::resolver::Resolver::default()
        .resolve(host, 443)
        .first()
        .copied()
        .ok_or_else(|| "dns".to_string())?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .map_err(|_| "connect".to_string())?;
    hello(&mut s, host)
}

/// Through an HTTP `CONNECT` proxy — the dialect Windows can actually be told to use.
pub fn via_proxy(proxy: &str, host: &str) -> Result<(), String> {
    let addr: SocketAddr = proxy.parse().map_err(|_| "addr".to_string())?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .map_err(|_| "proxy".to_string())?;
    let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|_| "proxy")?;
    let mut head = [0u8; 256];
    let n = s.read(&mut head).map_err(|_| "proxy")?;
    if !String::from_utf8_lossy(&head[..n]).contains("200") {
        return Err("proxy-refused".into());
    }
    hello(&mut s, host)
}

/// Write a ClientHello and see whether anything comes back. The handshake is never completed:
/// the DPI acts on the first flight, so an answer of any kind is the measurement.
fn hello(s: &mut TcpStream, host: &str) -> Result<(), String> {
    let _ = s.set_nodelay(true);
    let _ = s.set_read_timeout(Some(Duration::from_secs(8)));
    let min = vigil_core::synth::min_len(host).map_err(|e| e.to_string())?;
    let ch =
        vigil_core::synth::client_hello(host, min.max(300), nonce()).map_err(|e| e.to_string())?;
    s.write_all(&ch).map_err(|_| "write".to_string())?;
    let mut back = [0u8; 512];
    match s.read(&mut back) {
        Ok(0) => Err("closed".into()),
        Ok(_) => Ok(()),
        Err(e) => Err(match e.kind() {
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => "rst",
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "timeout",
            _ => "err",
        }
        .to_string()),
    }
}

/// Different every call, deterministic within a call: two connections must not look identical
/// to a server, and the crate that builds the hello deliberately owns no clock.
fn nonce() -> [u8; 32] {
    use std::sync::atomic::{AtomicU8, Ordering};
    static N: AtomicU8 = AtomicU8::new(1);
    let k = N.fetch_add(7, Ordering::Relaxed);
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = k.wrapping_mul(31).wrapping_add(i as u8).wrapping_add(0x5A);
    }
    out
}
