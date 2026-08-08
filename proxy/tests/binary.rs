//! Tests that run the `vigil` binary itself.
//!
//! `panel.rs` builds a `PanelState` by hand, so it can prove the panel renders correctly but
//! not that `main` wired the right values into it. This file exists because exactly that went
//! wrong: the panel reported the *panel's* own address as `listen`, which is the field a user
//! reads to point a client at vigil — so it named a port that speaks HTTP and no proxy
//! protocol at all.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Take a port the OS is willing to give out, then let it go. Racy in principle; in practice
/// the binary claims it microseconds later and a collision fails loudly rather than silently.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind for a free port");
    l.local_addr().expect("addr").port()
}

struct Vigil(Child);

impl Drop for Vigil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

/// Start the binary and wait for its panel to answer.
fn start(proxy_port: u16, panel_port: u16) -> (Vigil, SocketAddr) {
    let child = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .arg(format!("127.0.0.1:{proxy_port}"))
        .arg("--split")
        .arg("--panel")
        .arg(format!("127.0.0.1:{panel_port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vigil");
    let v = Vigil(child);
    let panel: SocketAddr = format!("127.0.0.1:{panel_port}").parse().expect("addr");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(body) = http_get(panel, "/api/status") {
            if body.contains("\"listen\"") {
                return (v, panel);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("vigil's panel never answered on {panel}");
}

/// The regression: `listen` must name the proxy, which is the address a client connects to.
#[test]
fn the_panel_reports_the_proxy_address_not_its_own() {
    let (proxy_port, panel_port) = (free_port(), free_port());
    assert_ne!(proxy_port, panel_port, "test needs two distinct ports");
    let (_v, panel) = start(proxy_port, panel_port);

    let body = http_get(panel, "/api/status").expect("status");
    assert!(
        body.contains(&format!(r#""listen":"127.0.0.1:{proxy_port}""#)),
        "panel should report the proxy port {proxy_port}, not the panel port {panel_port}: {body}"
    );
    assert!(
        !body.contains(&format!(r#""listen":"127.0.0.1:{panel_port}""#)),
        "panel reported its own address as the one to point clients at: {body}"
    );
}

/// The binary must actually serve all three dialects on the port it advertises — the whole
/// point of the change, checked against the shipped entry point rather than the library.
#[test]
fn the_binary_serves_every_dialect_it_advertises() {
    let (proxy_port, panel_port) = (free_port(), free_port());
    let (_v, panel) = start(proxy_port, panel_port);
    let proxy: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().expect("addr");

    // An upstream that accepts and immediately closes is enough: we are testing that the
    // handshake completes, not that anything is relayed (e2e.rs covers relaying).
    let up = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let up_port = up.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for c in up.incoming().take(3) {
            drop(c);
        }
    });

    // SOCKS5
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).expect("socks5 method reply");
    assert_eq!(m, [0x05, 0x00]);

    // SOCKS4
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&up_port.to_be_bytes());
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.push(0);
    s.write_all(&req).unwrap();
    let mut r = [0u8; 8];
    s.read_exact(&mut r).expect("socks4 reply");
    assert_eq!(r[1], 0x5A, "socks4 CONNECT refused by the shipped binary");

    // HTTP CONNECT
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut buf = [0u8; 32];
    let n = s.read(&mut buf).expect("http reply");
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(
        head.starts_with("HTTP/1.1 200 "),
        "http CONNECT refused by the shipped binary: {head:?}"
    );

    // and the panel agrees it saw one of each
    let body = http_get(panel, "/api/status").expect("status");
    for want in [r#""socks5":1"#, r#""socks4":1"#, r#""http_connect":1"#] {
        assert!(body.contains(want), "expected {want} in {body}");
    }
}
