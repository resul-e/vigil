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
    start_io(mode, cache, Duration::from_secs(5))
}

/// [`start`] with the relay timeout named, for the tests that have to wait for it to expire.
fn start_io(
    mode: Mode,
    cache: Option<std::path::PathBuf>,
    io_timeout: Duration,
) -> (SocketAddr, Arc<Server>) {
    let cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        strategy: Strategy::passthrough(),
        mode,
        cache_path: cache,
        io_timeout,
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

/// [`start`] with per-host recording on, so a test can read which strategy each connection
/// actually put on the wire rather than only what the calibrator ended up believing.
fn start_recording(mode: Mode) -> (SocketAddr, Arc<Server>) {
    let cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        strategy: Strategy::passthrough(),
        mode,
        io_timeout: Duration::from_secs(5),
        record_hosts: true,
        ..Default::default()
    };
    let server = Arc::new(Server::new(cfg));
    let l = server.bind().expect("bind");
    let addr = l.local_addr().expect("addr");
    let s2 = Arc::clone(&server);
    std::thread::spawn(move || s2.serve(l));
    (addr, server)
}

/// An upstream that always answers, except that its `hold_nth` connection (1-based) announces
/// itself on a channel and then **blocks** until it is released before writing its reply.
///
/// A channel and not a sleep: this file already carries one test whose comment records a release
/// being stopped by a suite that trusted loopback timing. The gate has to be an event.
#[allow(clippy::type_complexity)]
fn gated_upstream(
    hold_nth: usize,
) -> (
    SocketAddr,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let (announce_tx, announce_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
    let seen = Arc::new(AtomicUsize::new(0));

    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            let announce = announce_tx.clone();
            let release = Arc::clone(&release_rx);
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf); // the first flight
                if seen.fetch_add(1, Ordering::Relaxed) + 1 == hold_nth {
                    // The proxy has written the flight and is now blocked in its peek — which is
                    // *after* it snapshotted the mode for this connection.
                    let _ = announce.send(());
                    if let Ok(rx) = release.lock() {
                        let _ = rx.recv_timeout(Duration::from_secs(10));
                    }
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
    (addr, announce_rx, release_tx)
}

/// **A connection is judged under the mode it was served with, not the one in force when it
/// finishes.**
///
/// `handle` takes one snapshot of the mode per connection, and `set_mode`'s doc promises exactly
/// that. Nothing tested it: re-reading `shared.mode()` at record time — or moving the snapshot
/// inside the attempt loop — left the whole workspace green. In the field a user flips the tray
/// menu from `auto` to `tlsrec:64` while a connection is between its first flight and its peek, and
/// the trial is then silently dropped (`record_outcome` returns early once the mode is not `Auto`);
/// flipping the other way credits an outcome produced under a fixed strategy to whatever candidate
/// the calibrator happens to hold.
///
/// The switch is landed at the one instant that matters, gated on a channel rather than a sleep:
/// the upstream holds the fifth connection after reading its flight, the test flips the mode while
/// it is held, then releases it. Four successes are already banked, so this fifth one is the trial
/// that settles the host — and only if it was recorded under the mode it started with.
#[test]
fn a_mode_switch_mid_connection_does_not_discard_that_connections_trial() {
    use vigil_core::calibrate::CONFIRM;

    let (up, announced, release) = gated_upstream(CONFIRM);
    let (proxy, server) = start(Mode::Auto, None);

    // CONFIRM - 1 clean successes: the calibrator is one away from settling.
    for i in 1..CONFIRM {
        assert!(
            attempt(proxy, "127.0.0.1", up.port()),
            "warm-up connection {i} should have been answered"
        );
    }
    assert!(
        server
            .cache
            .lock()
            .expect("cache")
            .get("127.0.0.1")
            .is_none(),
        "the host must not have settled yet, or the fifth connection decides nothing"
    );

    let port = up.port();
    let last = std::thread::spawn(move || attempt(proxy, "127.0.0.1", port));

    // Wait for the proxy to be *inside* that connection, past its mode snapshot.
    announced
        .recv_timeout(Duration::from_secs(10))
        .expect("the upstream should have taken the held connection");
    server.set_mode(Mode::Fixed(Strategy::passthrough()));
    let _ = release.send(());

    assert!(last.join().expect("thread"), "the held connection failed");

    assert!(
        server
            .cache
            .lock()
            .expect("cache")
            .get("127.0.0.1")
            .is_some(),
        "the trial was thrown away because the mode changed after the connection started — a \
         connection must be judged under the mode it was served with"
    );
    assert_eq!(
        server.stats.calibrated.load(Ordering::Relaxed),
        1,
        "exactly one host should have settled"
    );
}

/// **The sweep must actually sweep.**
///
/// Every test here reads the calibrator's *conclusion*; none read what the datapath put on the
/// wire. So making the `Mode::Auto` cache-miss branch of `Shared::strategy_for` return
/// `Strategy::measured_default()` unconditionally — ignoring the candidate the calibrator has
/// advanced to — left the whole workspace green. In the field that is worse than it looks: the
/// calibrator advances through candidates and settles on candidate N on the strength of five
/// successes that candidate 0 earned, because candidate 0 is what every connection actually sent.
/// On both measured networks candidate 0 works, so this would have shipped silently and only
/// failed on a third network — where Auto would be indistinguishable from a fixed default.
///
/// Asserted on `HostRecord::applied`, which is the spec string the connection really used. That is
/// a value the datapath recorded, never a read boundary, so there is nothing here for a busy
/// scheduler to coalesce.
///
/// **The upstream refuses everything, deliberately.** With an upstream that eventually serves, the
/// calibrator settles and later connections are answered from the *cache* — which supplies a
/// second, different spec string all by itself, so `applied` holds two entries whether or not the
/// sweep ever reached the wire. That version of this test passed against the mutation. Refusing
/// every connection means nothing ever settles, the cache never fills, and every single connection
/// has to go through the branch under test.
#[test]
fn auto_puts_the_candidate_it_is_sweeping_on_the_wire() {
    let (up, _) = censoring_upstream(usize::MAX);
    let (proxy, server) = start_recording(Mode::Auto);

    for _ in 0..16 {
        attempt(proxy, "127.0.0.1", up.port());
    }
    assert!(
        server
            .cache
            .lock()
            .expect("cache")
            .get("127.0.0.1")
            .is_none(),
        "nothing may settle here, or the cache would answer instead of the sweep"
    );

    let seen = server.seen_detail();
    let (_, rec) = seen
        .iter()
        .find(|(h, _)| h == "127.0.0.1")
        .expect("the host should have been recorded");

    assert!(
        rec.applied.len() >= 2,
        "every connection used the same strategy {:?}, so the sweep never swept — the calibrator \
         is advancing through candidates while the datapath ignores which one it holds",
        rec.applied
    );
    assert!(
        rec.applied.iter().any(|s| s != "tlsrec:64+split:1"),
        "only the default was ever applied: {:?}",
        rec.applied
    );
}

/// The gate: left alone, the calibrator finds a strategy that works and settles on it.
#[test]
fn the_calibrator_settles_on_a_working_strategy_unattended() {
    // Refuse the first three upstream connections. `first_flight_attempts` is 3, so all three
    // land inside the *first* client connection and fold into a single recorded failure: the sweep
    // advances one step, not three. (The comment here used to say three, which is what the number
    // 3 looks like if you forget that the retry is invisible to the calibrator by design — see
    // `retry.rs`.)
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

/// **An upstream that swallows the flight and says nothing**, holding the socket open until the
/// proxy gives up.
///
/// The double this suite did not have. `censoring_upstream` *closes*, so the proxy sees
/// end-of-stream — which is the second network's mechanism only after a `split:*` provokes a reset.
/// Its baseline is silence: the flight is accepted, nothing comes back, and the connection stays
/// open for six seconds. Every counter and every trial decision behaves differently against silence
/// than against a close, and nothing in the suite could express it.
fn silent_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                // Drain whatever arrives and answer none of it. Holding the socket is the point:
                // the proxy has to time out rather than being told anything.
                let mut buf = [0u8; 8192];
                let _ = s.set_read_timeout(Some(Duration::from_secs(4)));
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// **Silence must be visible in the counters.** Before the relay counters existed, a censor that
/// accepted every flight and answered nothing produced `handshake errors 0`, `upstream errors 0` and
/// a report indistinguishable from a healthy run — on the one network whose entire mechanism is
/// silence.
#[test]
fn a_silent_upstream_is_counted_as_answering_nothing() {
    let up = silent_upstream();
    // A short relay timeout, because this test has to *wait for it*: the downstream copy sits in
    // `read()` until it expires, and the accounting happens when it returns. With the default five
    // seconds the counters are still empty when a test would look.
    let (proxy, server) = start_io(Mode::Auto, None, Duration::from_millis(700));
    // The literal, like every other test here: the proxy would otherwise have to resolve a name,
    // and what is under test is the relay's accounting rather than the resolver.
    let host = "127.0.0.1";

    for _ in 0..5 {
        // Not `attempt`: we want the connection relayed and then closed by us, so the relay's own
        // accounting runs. `attempt` would report failure and tell us nothing new.
        if let Ok(mut c) = socks_connect(proxy, host, up.port()) {
            let hello = vigil_core::synth::client_hello("silent.example", 300, [7u8; 32])
                .expect("a 300 byte hello");
            let _ = c.write_all(&hello);
            let mut buf = [0u8; 64];
            let _ = c.set_read_timeout(Some(Duration::from_millis(600)));
            let _ = c.read(&mut buf);
        }
    }
    // Long enough for every relay to have hit the timeout above and recorded itself.
    std::thread::sleep(Duration::from_millis(2500));

    let empty = server
        .stats
        .closed_empty
        .load(std::sync::atomic::Ordering::Relaxed);
    let back = server
        .stats
        .bytes_from_upstream
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        empty >= 5,
        "five connections got nothing back and the counter says {empty}"
    );
    assert_eq!(back, 0, "the upstream never wrote, so this must be zero");
    let to_up = server
        .stats
        .bytes_to_upstream
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(to_up > 0, "the flight did reach the upstream");
}

/// **The other half of the silence counter, and the half that was wrong.**
///
/// A probe is shaped like this: send a ClientHello, read the answer, drop the socket. The answer
/// arrives during the watch — into `early`, before the relay exists — and the client hangs up, so the
/// relay copies nothing in that direction and `write_all` fails on the way back. With the byte count
/// taken after the write and `early` left out, **every** such connection was recorded as "the
/// upstream never answered", beside `bytes from upstream 0`. That is 114 connections in a default
/// scan run, on a report whose whole purpose is to tell a healthy line from a censored one, and it
/// was byte-identical to a genuinely silent upstream.
#[test]
fn an_upstream_that_answers_is_not_counted_as_silent() {
    // Refuse nothing: every connection is served.
    let (up, _resets) = censoring_upstream(0);
    let (proxy, server) = start_io(Mode::Auto, None, Duration::from_millis(700));

    for _ in 0..5 {
        let Ok(mut c) = socks_connect(proxy, "127.0.0.1", up.port()) else {
            continue;
        };
        let hello = vigil_core::synth::client_hello("answered.example", 300, [9u8; 32]).expect("h");
        let _ = c.write_all(&hello);
        let mut back = [0u8; 64];
        let _ = c.set_read_timeout(Some(Duration::from_millis(600)));
        let n = c.read(&mut back).unwrap_or(0);
        assert!(n > 0, "the stub answers, so the client must see bytes");
        // And then it hangs up, which is the shape that broke the accounting.
        drop(c);
    }
    std::thread::sleep(Duration::from_millis(2000));

    use std::sync::atomic::Ordering::Relaxed;
    let empty = server.stats.closed_empty.load(Relaxed);
    let back = server.stats.bytes_from_upstream.load(Relaxed);
    assert_eq!(
        empty, 0,
        "five answered connections were recorded as silent"
    );
    assert!(back > 0, "the answer must be counted, got {back} bytes");
}

/// An upstream that serves its first `serve` connections and refuses every one after — the shape a
/// censor that *starts* blocking has, and the one `censoring_upstream` cannot express because it does
/// the opposite.
fn upstream_that_turns(serve: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let seen = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                if seen.fetch_add(1, Ordering::Relaxed) >= serve {
                    // Close without answering: end-of-stream where a served connection has data,
                    // which is the same signal the real line gives.
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
    addr
}

/// **A strategy thrown away mid-run has to be counted.**
///
/// This is the project's only answer to "the censor changed", and on the second network it has already
/// happened: one run's counters read `calibrated 15` above a learned table with fourteen rows, and
/// working out which host was missing took a set difference and an argument. The counter was added
/// afterwards and **had no test** — an independent mutation that emptied the whole branch, counter and
/// eviction together, left the workspace green.
#[test]
fn a_strategy_thrown_away_mid_run_is_counted() {
    use std::sync::atomic::Ordering::Relaxed;

    // Enough served connections for the calibrator to settle, then nothing but failures.
    let up = upstream_that_turns(10);
    let (proxy, server) = start(Mode::Auto, None);

    let mut reached = 0;
    for _ in 0..10 {
        if attempt(proxy, "127.0.0.1", up.port()) {
            reached += 1;
        }
    }
    assert!(
        server
            .cache
            .lock()
            .expect("cache")
            .get("127.0.0.1")
            .is_some(),
        "the calibrator has to settle first; only {reached}/10 reached"
    );
    assert_eq!(
        server.stats.abandoned.load(Relaxed),
        0,
        "nothing has been abandoned yet"
    );

    // ABANDON is 3, so four failures are enough with room to spare.
    for _ in 0..4 {
        let _ = attempt(proxy, "127.0.0.1", up.port());
    }
    assert!(
        server.stats.abandoned.load(Relaxed) >= 1,
        "the learned strategy was dropped and the counter says {}",
        server.stats.abandoned.load(Relaxed)
    );
    // And the row really is gone, which is the thing the counter exists to explain: a report whose
    // `calibrated` count exceeds its learned table by exactly this number.
    assert!(
        server
            .cache
            .lock()
            .expect("cache")
            .get("127.0.0.1")
            .is_none(),
        "the counter fired but the entry survived"
    );
}
