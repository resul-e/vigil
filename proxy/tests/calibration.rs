//! Auto-calibration end to end.
//!
//! These cover the **wiring**: that a connection outcome reaches the calibrator, that a
//! settled strategy lands in the cache, that the cache is written and reloaded. They do not
//! try to judge strategies by how the bytes land, because over loopback the kernel may
//! coalesce a 1-byte write with what follows and the stub would then see every strategy as
//! identical. Write-boundary behaviour is covered by `e2e.rs` (with an explicit delay, which
//! makes it observable) and by the live `probe` runs.
//!
//! So the stub here refuses a fixed number of connections and then serves — enough for the
//! calibrator to have to advance through candidates, fail, and eventually settle.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vigil_core::calibrate::Cache;
use vigil_core::strategy::Strategy;
use vigil_proxy::{Config, Mode, Server};

/// Upstream that refuses its first `refuse` connections, then serves every later one.
fn censoring_upstream(refuse: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let resets = Arc::new(AtomicUsize::new(0));
    let r2 = Arc::clone(&resets);
    let seen = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            let r = Arc::clone(&r2);
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                if seen.fetch_add(1, Ordering::Relaxed) < refuse {
                    // Stand in for the injected reset: close without answering. The proxy
                    // sees end-of-stream where a served connection would have data, which is
                    // the same signal it uses on the real line.
                    r.fetch_add(1, Ordering::Relaxed);
                    return;
                }
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
    (addr, resets)
}

fn start(mode: Mode, cache: Option<std::path::PathBuf>) -> (SocketAddr, Arc<Server>) {
    let cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        strategy: Strategy::passthrough(),
        mode,
        cache_path: cache,
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

fn socks_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(6)))?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m)?;
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    assert_eq!(rep[1], 0x00, "CONNECT failed");
    Ok(s)
}

/// Drive one connection carrying a whole "ClientHello" and report whether it survived.
fn attempt(proxy: SocketAddr, host: &str, port: u16) -> bool {
    let Ok(mut s) = socks_connect(proxy, host, port) else {
        return false;
    };
    let mut flight = vec![0x16u8, 0x03, 0x01, 0x01, 0x2b];
    flight.extend(std::iter::repeat_n(0xAAu8, 299));
    if s.write_all(&flight).is_err() {
        return false;
    }
    let mut back = [0u8; 16];
    matches!(s.read(&mut back), Ok(n) if n > 0)
}

/// The gate: left alone, the calibrator finds a strategy that works and settles on it.
#[test]
fn the_calibrator_settles_on_a_working_strategy_unattended() {
    // Refuse the first three connections, so the calibrator has to advance past three
    // candidates before anything can hold.
    let (up, resets) = censoring_upstream(3);
    let (proxy, server) = start(Mode::Auto, None);

    let mut reached = 0;
    for _ in 0..16 {
        if attempt(proxy, "127.0.0.1", up.port()) {
            reached += 1;
        }
    }

    let cache = server.cache.lock().expect("cache");
    assert!(
        cache.get("127.0.0.1").is_some(),
        "calibrator never settled; {reached}/16 reached, {} resets",
        resets.load(Ordering::Relaxed)
    );
    assert!(
        reached >= 5,
        "expected the sweep to converge and then keep working, got {reached}/16"
    );
}

/// A strategy learned in one process must be there in the next. That is the whole point of
/// persisting it.
#[test]
fn a_learned_strategy_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("vigil-cal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("cache.txt");

    let (up, _r) = censoring_upstream(2);
    {
        let (proxy, server) = start(Mode::Auto, Some(path.clone()));
        for _ in 0..16 {
            attempt(proxy, "127.0.0.1", up.port());
        }
        assert!(
            server.cache.lock().unwrap().get("127.0.0.1").is_some(),
            "did not settle in the first run"
        );
    }

    let text = std::fs::read_to_string(&path).expect("cache file was written");
    let (reloaded, skipped) = Cache::from_text(&text);
    assert!(skipped.is_empty(), "cache did not round trip: {skipped:?}");
    let learned = reloaded
        .get("127.0.0.1")
        .cloned()
        .expect("host missing after reload");

    // second process
    let (_proxy2, server2) = start(Mode::Auto, Some(path.clone()));
    assert_eq!(
        server2.cache.lock().unwrap().get("127.0.0.1"),
        Some(&learned),
        "the strategy did not survive the restart"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Once settled, later connections come from the cache rather than re-sweeping.
#[test]
fn a_settled_host_is_served_from_cache() {
    let (up, _r) = censoring_upstream(2);
    let (proxy, server) = start(Mode::Auto, None);
    for _ in 0..16 {
        attempt(proxy, "127.0.0.1", up.port());
    }
    assert!(server.cache.lock().unwrap().get("127.0.0.1").is_some());

    let before = server.stats.cache_hits.load(Ordering::Relaxed);
    for _ in 0..5 {
        attempt(proxy, "127.0.0.1", up.port());
    }
    let after = server.stats.cache_hits.load(Ordering::Relaxed);
    assert!(
        after >= before + 5,
        "cache was not consulted: {before} -> {after}"
    );
}

/// Fixed mode must not touch the cache at all — it is not learning anything.
#[test]
fn fixed_mode_never_writes_to_the_cache() {
    let (up, _r) = censoring_upstream(0);
    let (proxy, server) = start(Mode::Fixed(Strategy::measured_default()), None);
    for _ in 0..8 {
        attempt(proxy, "127.0.0.1", up.port());
    }
    assert!(
        server.cache.lock().unwrap().is_empty(),
        "fixed mode learned something it should not have"
    );
    assert_eq!(server.stats.calibrated.load(Ordering::Relaxed), 0);
}

/// A cache file full of nonsense must not stop the proxy from starting.
#[test]
fn a_corrupt_cache_file_does_not_prevent_startup() {
    let dir = std::env::temp_dir().join(format!("vigil-bad-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("cache.txt");
    std::fs::write(&path, "this is not a cache\n@@@@\ndiscord.com wibble:1\n").expect("write");

    let (proxy, server) = start(Mode::Auto, Some(path.clone()));
    assert!(server.cache.lock().unwrap().is_empty());
    // and it still serves. `censoring_upstream(0)` refuses nothing, so a proxy that came up
    // properly must get an answer through — `|| true` made this assertion unfailable, which
    // is worse than not having it: it read as coverage.
    let (up, _r) = censoring_upstream(0);
    assert!(
        attempt(proxy, "127.0.0.1", up.port()),
        "a corrupt cache file left the proxy unable to serve"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
