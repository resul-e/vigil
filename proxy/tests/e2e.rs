//! End-to-end tests for the SOCKS5 server — real sockets, no network.
//!
//! A stub upstream runs in-process, so these exercise the whole datapath (accept, handshake,
//! connect, first-flight plan, bidirectional relay) without depending on the internet or on
//! anything being blocked. The live-network checks belong to the `probe` harness.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use vigil_core::strategy::Strategy;
use vigil_proxy::{Config, Server};

/// Upstream that records the sizes of the reads it sees, then echoes everything.
///
/// Read boundaries are the only visible proxy of write boundaries over loopback, and with
/// TCP_NODELAY on both ends they track them closely enough to tell one write from two.
fn stub_upstream() -> (SocketAddr, mpsc::Receiver<Vec<usize>>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = l.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_millis(700)));
                let mut sizes = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            sizes.push(n);
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tx.send(sizes);
            });
        }
    });
    (addr, rx)
}

fn start_proxy(spec: &str) -> (SocketAddr, std::sync::Arc<vigil_proxy::Stats>) {
    let mut cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        strategy: Strategy::parse(spec).expect("test strategy must parse"),
        ..Default::default()
    };
    cfg.io_timeout = Duration::from_secs(5);
    let server = Server::new(cfg);
    let listener = server.bind().expect("bind proxy");
    let addr = listener.local_addr().expect("addr");
    let stats = std::sync::Arc::clone(&server.stats);
    std::thread::spawn(move || server.serve(listener));
    (addr, stats)
}

/// Perform a SOCKS5 CONNECT and return the established stream.
fn socks_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;

    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m)?;
    assert_eq!(m, [0x05, 0x00], "server did not accept no-auth");

    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    assert_eq!(rep[0], 0x05);
    assert_eq!(rep[1], 0x00, "CONNECT failed with rep={:#04x}", rep[1]);
    Ok(s)
}

#[test]
fn relays_a_payload_end_to_end() {
    let (up, sizes) = stub_upstream();
    let (proxy, _stats) = start_proxy("none");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    let payload = b"\x16\x03\x01\x00\x10hello upstream!!";
    s.write_all(payload).expect("write");
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back).expect("read echo");
    assert_eq!(back, payload, "payload did not survive the round trip");
    drop(s);

    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen.iter().sum::<usize>(),
        payload.len(),
        "upstream saw a different number of bytes than we sent"
    );
}

#[test]
fn passthrough_sends_the_first_flight_as_one_write() {
    let (up, sizes) = stub_upstream();
    let (proxy, _stats) = start_proxy("none");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    let flight = vec![0x16u8; 300];
    s.write_all(&flight).expect("write");
    let mut back = vec![0u8; flight.len()];
    s.read_exact(&mut back).expect("echo");
    drop(s);

    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen.first(),
        Some(&300),
        "passthrough must not split: {seen:?}"
    );
}

/// The proxy really applies the transform. Asserted from the proxy's own counter rather
/// than from how the bytes happen to land, because read boundaries are not write boundaries:
/// over loopback the kernel is free to coalesce a 1-byte write with the 299 that follow it,
/// and that is the kernel's choice, not this code's behaviour.
#[test]
fn split_transforms_the_first_flight_and_preserves_it() {
    let (up, sizes) = stub_upstream();
    let (proxy, stats) = start_proxy("split:1");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    let flight = vec![0x16u8; 300];
    s.write_all(&flight).expect("write");
    let mut back = vec![0u8; flight.len()];
    s.read_exact(&mut back).expect("echo");
    assert_eq!(back, flight, "split corrupted the stream");
    drop(s);

    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen.iter().sum::<usize>(),
        300,
        "byte count changed: {seen:?}"
    );
    assert_eq!(
        stats.transformed.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "proxy did not report applying the transform"
    );
}

/// With a delay between writes the split becomes observable on the wire, which is the
/// property the technique actually depends on: two segments, not one.
#[test]
fn a_delayed_split_is_visibly_two_writes_upstream() {
    let (up, sizes) = stub_upstream();
    let (proxy, _stats) = start_proxy("split:1@20");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    let flight = vec![0x16u8; 300];
    s.write_all(&flight).expect("write");
    let mut back = vec![0u8; flight.len()];
    s.read_exact(&mut back).expect("echo");
    assert_eq!(back, flight);
    drop(s);

    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen.first(),
        Some(&1),
        "first write was not one byte: {seen:?}"
    );
    assert_eq!(
        seen.iter().sum::<usize>(),
        300,
        "byte count changed: {seen:?}"
    );
}

/// Exact write boundaries, made observable with a delay for the same reason as above: without
/// one the kernel is free to coalesce, and then the test measures the kernel rather than us.
#[test]
fn a_multi_split_produces_the_expected_write_boundaries() {
    let (up, sizes) = stub_upstream();
    let (proxy, _stats) = start_proxy("split:1,3,7@20");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    let flight = vec![0xABu8; 100];
    s.write_all(&flight).expect("write");
    let mut back = vec![0u8; flight.len()];
    s.read_exact(&mut back).expect("echo");
    assert_eq!(back, flight, "multi split corrupted the stream");
    drop(s);

    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen,
        vec![1, 2, 4, 93],
        "cuts at 1,3,7 of a 100-byte flight should land exactly here"
    );
}

#[test]
fn large_transfers_survive_intact_in_both_directions() {
    let (up, _sizes) = stub_upstream();
    let (proxy, _stats) = start_proxy("split:1");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    // 1 MiB, deterministic content so corruption is detectable, not just length loss.
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let mut writer = s.try_clone().expect("clone");
    let expect = payload.clone();
    let w = std::thread::spawn(move || writer.write_all(&expect));

    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back).expect("read all back");
    w.join().expect("writer joined").expect("write ok");
    assert_eq!(back, payload, "1 MiB round trip was corrupted");
}

#[test]
fn an_unreachable_target_gets_a_failure_reply_not_a_hang() {
    let (proxy, _stats) = start_proxy("none");
    let mut s = TcpStream::connect(proxy).expect("connect proxy");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).unwrap();

    // port 1 on loopback: nothing listens there
    let host = "127.0.0.1";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&1u16.to_be_bytes());
    s.write_all(&req).unwrap();

    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).expect("must reply, not hang");
    assert_eq!(rep[0], 0x05);
    assert_ne!(rep[1], 0x00, "should not report success for a dead port");
}

#[test]
fn a_client_offering_no_acceptable_method_is_rejected_cleanly() {
    let (proxy, _stats) = start_proxy("none");
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[0x05, 0x01, 0x02]).unwrap(); // GSSAPI only
    let mut m = [0u8; 2];
    s.read_exact(&mut m).expect("reply");
    assert_eq!(m, [0x05, 0xFF], "must answer 'no acceptable methods'");
}

#[test]
fn an_unsupported_command_is_answered_not_dropped() {
    let (proxy, _stats) = start_proxy("none");
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).unwrap();

    // BIND (0x02) — we do not implement it
    let mut req = vec![0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).expect("reply");
    assert_eq!(rep[1], 0x07, "expected COMMAND_NOT_SUPPORTED");
}

#[test]
fn many_concurrent_connections_all_complete() {
    let (up, _sizes) = stub_upstream();
    let (proxy, _stats) = start_proxy("split:1");
    let mut handles = Vec::new();
    for i in 0..40u8 {
        handles.push(std::thread::spawn(move || {
            let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");
            let payload = vec![i; 512];
            s.write_all(&payload).expect("write");
            let mut back = vec![0u8; payload.len()];
            s.read_exact(&mut back).expect("echo");
            assert_eq!(back, payload, "connection {i} was corrupted");
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        h.join()
            .unwrap_or_else(|_| panic!("connection {i} panicked"));
    }
}

// ---------------------------------------------------------------------------------------
// The other two dialects.
//
// Windows' system proxy setting cannot say "SOCKS5". Measured on 2026-08-04: `socks=` makes
// Chromium speak SOCKS4, and only the HTTP form reaches the Discord updater at all. These
// tests exist so that the datapath for those two is proved by the suite and not only by a
// live-network run that needs a human and a blocked domain.
// ---------------------------------------------------------------------------------------

/// Perform a SOCKS4 CONNECT to an IPv4 target and return the established stream.
fn socks4_connect(proxy: SocketAddr, ip: [u8; 4], port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip);
    req.push(0x00); // empty user id, exactly as Chromium sends
    s.write_all(&req)?;

    let mut rep = [0u8; 8];
    s.read_exact(&mut rep)?;
    assert_eq!(rep[0], 0x00, "SOCKS4 replies are version 0, not 4");
    assert_eq!(rep[1], 0x5A, "CONNECT failed with cd={:#04x}", rep[1]);
    Ok(s)
}

/// Perform a SOCKS4a CONNECT, naming the host rather than resolving it.
fn socks4a_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&[0, 0, 0, 1]); // the 4a marker
    req.push(0x00);
    req.extend_from_slice(host.as_bytes());
    req.push(0x00);
    s.write_all(&req)?;

    let mut rep = [0u8; 8];
    s.read_exact(&mut rep)?;
    assert_eq!(rep[1], 0x5A, "CONNECT failed with cd={:#04x}", rep[1]);
    Ok(s)
}

/// Read an HTTP response head, up to and including the blank line.
fn read_http_head(s: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut b)?;
        if n == 0 {
            break;
        }
        head.push(b[0]);
        if head.len() > 4096 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Perform an HTTP CONNECT and return the established stream.
fn http_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
    )?;
    let head = read_http_head(&mut s)?;
    assert!(
        head.starts_with("HTTP/1.1 200 "),
        "CONNECT failed: {head:?}"
    );
    Ok(s)
}

#[test]
fn socks4_relays_a_payload_end_to_end() {
    let (up, sizes) = stub_upstream();
    let (proxy, stats) = start_proxy("none");
    let mut s = socks4_connect(proxy, [127, 0, 0, 1], up.port()).expect("connect");

    let payload = b"\x16\x03\x01\x00\x10hello upstream!!";
    s.write_all(payload).expect("write");
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back).expect("read echo");
    assert_eq!(back, payload);
    drop(s);

    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(seen.iter().sum::<usize>(), payload.len());
    assert_eq!(
        stats.by_socks4.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        stats.by_socks5.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn socks4a_relays_a_payload_end_to_end() {
    let (up, _sizes) = stub_upstream();
    let (proxy, stats) = start_proxy("none");
    let mut s = socks4a_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    let payload = b"hello over socks4a";
    s.write_all(payload).expect("write");
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back).expect("read echo");
    assert_eq!(back, payload);
    assert_eq!(
        stats.by_socks4.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn http_connect_relays_a_payload_end_to_end() {
    let (up, sizes) = stub_upstream();
    let (proxy, stats) = start_proxy("none");
    let mut s = http_connect(proxy, "127.0.0.1", up.port()).expect("connect");

    let payload = b"\x16\x03\x01\x00\x10hello upstream!!";
    s.write_all(payload).expect("write");
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back).expect("read echo");
    assert_eq!(back, payload);
    drop(s);

    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(seen.iter().sum::<usize>(), payload.len());
    assert_eq!(
        stats
            .by_http_connect
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

/// The point of the whole exercise: the transform must be applied no matter which dialect
/// carried the request. A split that only happens for SOCKS5 clients helps nobody on Windows.
///
/// The delay is there for the same reason as in the tests above — without one the kernel may
/// coalesce the two writes and the test would measure the kernel rather than us.
#[test]
fn every_dialect_gets_the_first_flight_split() {
    let flight = vec![0x16u8; 300];
    for dialect in ["socks5", "socks4", "http"] {
        let (up, sizes) = stub_upstream();
        // 200 ms, not 20: the delay has to outlast the stub thread being descheduled, which
        // under a loaded `cargo test --workspace` it is. At 20 ms both writes could land in
        // the receive buffer before the stub's first read and arrive as one 300-byte read —
        // the test then measured the scheduler rather than the proxy, and failed about one
        // run in four.
        let (proxy, stats) = start_proxy("split:1@200");
        let mut s = match dialect {
            "socks5" => socks_connect(proxy, "127.0.0.1", up.port()),
            "socks4" => socks4_connect(proxy, [127, 0, 0, 1], up.port()),
            _ => http_connect(proxy, "127.0.0.1", up.port()),
        }
        .expect("connect");

        s.write_all(&flight).expect("write");
        let mut back = vec![0u8; flight.len()];
        s.read_exact(&mut back).expect("read echo");
        assert_eq!(back, flight, "{dialect}: flight did not survive");
        drop(s);

        let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
        assert_eq!(
            seen.first().copied(),
            Some(1),
            "{dialect}: first write upstream should be the 1-byte record-header split, got {seen:?}"
        );
        assert_eq!(seen.iter().sum::<usize>(), flight.len(), "{dialect}");
        assert_eq!(
            stats.transformed.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "{dialect}: transform was not counted"
        );
    }
}

#[test]
fn a_socks4_connect_to_an_unreachable_target_is_rejected_not_dropped() {
    let (proxy, _stats) = start_proxy("none");
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // Port 1 on loopback: resolvable, nothing listening.
    let mut req = vec![0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00];
    req.truncate(9);
    s.write_all(&req).expect("write");
    let mut rep = [0u8; 8];
    s.read_exact(&mut rep)
        .expect("no reply at all — client would hang");
    assert_eq!(rep[0], 0x00);
    assert_eq!(rep[1], 0x5B, "expected a rejection");
}

#[test]
fn an_http_connect_to_an_unreachable_target_gets_a_status_not_a_hang() {
    let (proxy, _stats) = start_proxy("none");
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
        .expect("write");
    let head = read_http_head(&mut s).expect("no reply at all — client would hang");
    assert!(
        head.starts_with("HTTP/1.1 50"),
        "expected a 5xx, got {head:?}"
    );
}

/// Chromium sends absolute-form GETs to a general HTTP proxy. We scope ourselves to https so
/// they should never arrive, but if one does it must be refused rather than left hanging.
#[test]
fn an_absolute_form_get_is_refused_cleanly() {
    let (proxy, _stats) = start_proxy("none");
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("write");
    // Either a 405 or a clean close is acceptable; a hang is not.
    let head = read_http_head(&mut s).expect("read");
    assert!(
        head.is_empty() || head.starts_with("HTTP/1.1 4"),
        "expected a refusal, got {head:?}"
    );
}

/// Opening bytes that match no dialect must be dropped, counted, and must not wedge a thread.
#[test]
fn unrecognised_opening_bytes_are_counted_and_dropped() {
    let (proxy, stats) = start_proxy("none");
    let mut s = TcpStream::connect(proxy).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // A raw TLS record: no proxy handshake at all.
    s.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00]).expect("write");
    let mut back = Vec::new();
    let _ = s.read_to_end(&mut back);
    assert!(back.is_empty(), "nothing should be sent back");
    assert_eq!(
        stats
            .unrecognised
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

/// Switching mode while the proxy is running changes what the next connection puts on the
/// wire — and does not disturb the one already open.
///
/// The interface exposes this, so the thing it promises has to be true of the datapath and not
/// only of the label in the window. Asserted through the delay form, because a delayed second
/// write is the one boundary loopback cannot coalesce away.
#[test]
fn a_mode_change_reaches_the_next_connection() {
    let (up, sizes) = stub_upstream();
    let cfg = Config {
        listen: "127.0.0.1:0".parse().expect("literal"),
        strategy: Strategy::passthrough(),
        io_timeout: Duration::from_secs(5),
        // One attempt, so one client connection is exactly one upstream connection. With
        // retrying on, a re-sent first flight adds a second set of write sizes to the channel
        // and the next assertion reads the wrong connection's — which is how this test failed
        // once before it was pinned down. Retrying has its own tests.
        first_flight_attempts: 1,
        ..Default::default()
    };
    let server = std::sync::Arc::new(Server::new(cfg));
    let listener = server.bind().expect("bind");
    let addr = listener.local_addr().expect("addr");
    let s2 = std::sync::Arc::clone(&server);
    std::thread::spawn(move || s2.serve(listener));

    // As it starts: passthrough, one write.
    let mut c = socks_connect(addr, "127.0.0.1", up.port()).expect("connect");
    c.write_all(&vec![0x16u8; 300]).expect("write");
    let mut back = vec![0u8; 300];
    c.read_exact(&mut back).expect("echo");
    drop(c);
    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen.first(),
        Some(&300),
        "passthrough must not split: {seen:?}"
    );

    // Change it. The next connection must split.
    server.set_mode(vigil_proxy::Mode::Fixed(
        Strategy::parse("split:1@40").expect("spec"),
    ));
    assert_eq!(
        server.mode(),
        vigil_proxy::Mode::Fixed(Strategy::parse("split:1@40").expect("spec")),
        "the proxy should report the mode it was given"
    );

    let mut c = socks_connect(addr, "127.0.0.1", up.port()).expect("connect");
    c.write_all(&vec![0x16u8; 300]).expect("write");
    let mut back = vec![0u8; 300];
    c.read_exact(&mut back).expect("echo");
    drop(c);
    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen.first(),
        Some(&1),
        "after the switch the first write must be one byte: {seen:?}"
    );

    // And back again, so the switch is not one-way.
    server.set_mode(vigil_proxy::Mode::Fixed(Strategy::passthrough()));
    let mut c = socks_connect(addr, "127.0.0.1", up.port()).expect("connect");
    c.write_all(&vec![0x16u8; 300]).expect("write");
    let mut back = vec![0u8; 300];
    c.read_exact(&mut back).expect("echo");
    drop(c);
    let seen = sizes.recv_timeout(Duration::from_secs(5)).expect("sizes");
    assert_eq!(
        seen.first(),
        Some(&300),
        "switching back must restore it: {seen:?}"
    );
}

/// Like `start_proxy`, but keeps the server so a test can read back what it recorded.
fn start_recording_proxy(spec: &str) -> (SocketAddr, std::sync::Arc<Server>) {
    let mut cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        strategy: Strategy::parse(spec).expect("test strategy must parse"),
        record_hosts: true,
        ..Default::default()
    };
    cfg.io_timeout = Duration::from_secs(5);
    let server = std::sync::Arc::new(Server::new(cfg));
    let listener = server.bind().expect("bind proxy");
    let addr = listener.local_addr().expect("addr");
    let s2 = std::sync::Arc::clone(&server);
    std::thread::spawn(move || s2.serve(listener));
    (addr, server)
}

/// One TLS record with a plausible handshake body, big enough for a record-level plan to have
/// something to do.
fn tls_record(len: usize) -> Vec<u8> {
    let mut v = vec![0x16, 0x03, 0x01];
    v.extend_from_slice(&(len as u16).to_be_bytes());
    v.push(0x01); // ClientHello
    v.extend_from_slice(&[0u8; 3]);
    v.extend(std::iter::repeat_n(0x42u8, len.saturating_sub(4)));
    v
}

/// What arrived has to be recorded with more than its name.
///
/// The Superonline report of 2026-08-07 said "updates.discord.com arrived" and could not say
/// whether that was one lookup or a client looping on retries, which strategy was actually
/// applied to it, or which program asked — and each of those was the question that mattered.
#[test]
fn what_arrived_is_recorded_with_counts_and_the_strategy_applied() {
    let (up, _sizes) = stub_upstream();
    let (proxy, server) = start_recording_proxy("tlsrec:64+split:1");

    for _ in 0..3 {
        let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");
        s.write_all(&tls_record(300)).expect("write");
        let mut back = [0u8; 8];
        let _ = s.read(&mut back);
        drop(s);
    }

    let detail = server.seen_detail();
    let (host, rec) = detail
        .iter()
        .find(|(h, _)| h == "127.0.0.1")
        .expect("the name it was asked for must be recorded");
    assert_eq!(host, "127.0.0.1");
    assert_eq!(rec.connections, 3, "three connections, not three names");
    assert!(
        rec.applied.contains("tlsrec:64+split:1"),
        "the strategy actually used must be recorded, got {:?}",
        rec.applied
    );
    assert_eq!(rec.untouched, 0, "a TLS record should not pass through");

    // `seen_hosts` is what the testbench already reads, and must keep meaning the same thing.
    assert!(server.seen_hosts().contains(&"127.0.0.1".to_string()));

    // Off Windows there is no owning-process table, so the record says "unknown" rather than
    // guessing. The Windows path is covered by `platform::owner`'s own tests.
    #[cfg(not(windows))]
    assert!(rec.clients.is_empty());
}

/// Passing a flight through unchanged is a different observation from transforming it, and the
/// record has to separate them — an excluded host looks identical otherwise.
#[test]
fn a_flight_that_was_not_touched_is_counted_separately() {
    let (up, _sizes) = stub_upstream();
    let (proxy, server) = start_recording_proxy("none");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");
    s.write_all(&tls_record(300)).expect("write");
    let mut back = [0u8; 8];
    let _ = s.read(&mut back);
    drop(s);

    let detail = server.seen_detail();
    let (_, rec) = detail
        .iter()
        .find(|(h, _)| h == "127.0.0.1")
        .expect("recorded");
    assert_eq!(rec.connections, 1);
    assert_eq!(rec.untouched, 1, "passthrough must be visible as untouched");
    assert!(rec.applied.contains("none"), "{:?}", rec.applied);
}

/// Clearing between phases must clear the counts too, not only the names.
#[test]
fn clearing_forgets_the_detail_as_well_as_the_names() {
    let (up, _sizes) = stub_upstream();
    let (proxy, server) = start_recording_proxy("none");
    let mut s = socks_connect(proxy, "127.0.0.1", up.port()).expect("connect");
    s.write_all(&tls_record(64)).expect("write");
    let mut back = [0u8; 8];
    let _ = s.read(&mut back);
    drop(s);
    assert!(!server.seen_detail().is_empty());
    server.clear_seen();
    assert!(server.seen_detail().is_empty());
    assert!(server.seen_hosts().is_empty());
}
