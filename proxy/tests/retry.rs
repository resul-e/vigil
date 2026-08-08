//! Re-sending a first flight that was reset.
//!
//! Measured on Türk Telekom 2026-08-05: the Discord updater's real 175 B ClientHello, split at
//! byte 1, is answered 9/20 and reset 11/20 — from the far side, three hops past the local
//! injector, which a TTL sweep showed never fires on a split flight. The application's own
//! answer is to reconnect 2.3 seconds later; the proxy's is to reconnect immediately.
//!
//! What these tests hold in place: the retry is invisible to the client, it is bounded, and it
//! never reaches the calibrator — a strategy that needs two attempts must not be recorded as
//! one that works.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vigil_core::strategy::Strategy;
use vigil_proxy::{Config, Mode, Server};

/// Upstream that resets its first `reset` connections, then serves.
///
/// A real `RST` rather than a clean close: closing a socket that still has unread data in its
/// receive buffer sends one, on every OS this runs on, and needs no unstable `SO_LINGER`. So
/// the flight is deliberately left unread. (If a platform ever sent a plain FIN here the test
/// would still hold — the proxy treats "no answer" the same way — but the intent is the reset
/// the far end actually sends.)
fn resetting_upstream(reset: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
                if seen.fetch_add(1, Ordering::Relaxed) < reset {
                    // Let the flight land in the receive buffer, then close without reading it.
                    std::thread::sleep(Duration::from_millis(30));
                    return;
                }
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"\x16\x03\x03\x00\x02\x02\x00");
                let mut sink = [0u8; 4096];
                while let Ok(k) = s.read(&mut sink) {
                    if k == 0 || s.write_all(&sink[..k]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, counter)
}

fn start(mode: Mode, attempts: usize) -> (SocketAddr, Arc<Server>) {
    let cfg = Config {
        listen: "127.0.0.1:0".parse().expect("literal"),
        strategy: Strategy::passthrough(),
        mode,
        first_flight_attempts: attempts,
        io_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let server = Arc::new(Server::new(cfg));
    let l = server.bind().expect("bind");
    let addr = l.local_addr().expect("addr");
    let s2 = Arc::clone(&server);
    std::thread::spawn(move || s2.serve(l));
    (addr, server)
}

fn socks_connect(proxy: SocketAddr, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(6)))?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m)?;
    let host = "127.0.0.1";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    assert_eq!(rep[1], 0x00, "CONNECT failed");
    Ok(s)
}

fn flight() -> Vec<u8> {
    let mut f = vec![0x16u8, 0x03, 0x01, 0x01, 0x2b];
    f.extend(std::iter::repeat_n(0xAAu8, 299));
    f
}

/// One connection, and whether the client ever saw an answer.
fn attempt(proxy: SocketAddr, up: u16) -> bool {
    let Ok(mut s) = socks_connect(proxy, up) else {
        return false;
    };
    if s.write_all(&flight()).is_err() {
        return false;
    }
    let mut back = [0u8; 16];
    matches!(s.read(&mut back), Ok(n) if n > 0)
}

/// The point of the whole thing: the client sees an answer even though the first flight was
/// reset, and never learns that anything happened.
#[test]
fn a_reset_first_flight_is_sent_again_and_the_client_never_notices() {
    let (up, _) = resetting_upstream(1);
    let (proxy, server) = start(Mode::Auto, 3);

    assert!(
        attempt(proxy, up.port()),
        "the client should have been answered on the retry"
    );
    assert_eq!(
        server.stats.first_flight_retries.load(Ordering::Relaxed),
        1,
        "exactly one retry should have been needed"
    );
}

/// Bounded. An endpoint that resets everything must not be hammered, and the connection must
/// still end rather than hang.
#[test]
fn retrying_stops_at_the_configured_number_of_attempts() {
    let (up, seen) = resetting_upstream(usize::MAX);
    let (proxy, server) = start(Mode::Auto, 3);

    assert!(
        !attempt(proxy, up.port()),
        "nothing should have got through"
    );
    assert_eq!(
        server.stats.first_flight_retries.load(Ordering::Relaxed),
        2,
        "three attempts means two retries, no more"
    );
    assert_eq!(
        seen.load(Ordering::Relaxed),
        3,
        "the upstream should have seen exactly three connections"
    );
}

/// One attempt means one attempt. The escape hatch has to actually close the door.
#[test]
fn one_attempt_disables_retrying() {
    let (up, seen) = resetting_upstream(1);
    let (proxy, server) = start(Mode::Auto, 1);

    assert!(!attempt(proxy, up.port()));
    assert_eq!(server.stats.first_flight_retries.load(Ordering::Relaxed), 0);
    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

/// The retry must not launder a strategy into the cache. A candidate that only worked on the
/// second go is a candidate that failed, and the calibrator has to be told the failure — or
/// it settles on something that needs a retry every single time.
#[test]
fn the_calibrator_is_told_about_the_first_attempt_only() {
    // Every odd connection is served, so each client attempt succeeds — but only ever on a
    // retry. Nothing may settle.
    let (up, _) = resetting_upstream(1);
    let (proxy, server) = start(Mode::Auto, 3);

    assert!(attempt(proxy, up.port()));
    let cache = server.cache.lock().expect("cache");
    assert!(
        cache.get("127.0.0.1").is_none(),
        "a strategy that only worked on the second attempt was recorded as working"
    );
}
