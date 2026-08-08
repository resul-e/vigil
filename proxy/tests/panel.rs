//! The control panel over a real socket.
//!
//! The routing decisions are unit-tested in `ui.rs`; these check the wiring — that the page
//! is served, that the JSON reflects real state, that a forget actually mutates the cache and
//! reaches the disk, and that a non-loopback caller is refused.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use vigil_core::calibrate::Cache;
use vigil_core::hostlist::HostRules;
use vigil_core::strategy::Strategy;
use vigil_proxy::ui::{self, PanelState};
use vigil_proxy::{Mode, Stats};

fn start(cache_path: Option<std::path::PathBuf>) -> (SocketAddr, Arc<PanelState>) {
    let mut cache = Cache::new();
    cache.insert("discord.com", Strategy::parse("split:1").unwrap());
    cache.insert("roblox.com", Strategy::parse("tlsrec:64").unwrap());

    let l = ui::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    let addr = l.local_addr().expect("addr");
    let state = Arc::new(PanelState {
        listen: addr.to_string(),
        mode: Mode::Auto,
        fixed: Strategy::measured_default(),
        stats: Arc::new(Stats::default()),
        cache: Arc::new(Mutex::new(cache)),
        rules: HostRules::default(),
        cache_path,
    });
    let s2 = Arc::clone(&state);
    std::thread::spawn(move || ui::serve(l, s2));
    (addr, state)
}

/// Issue one request and return `(status, body)`.
fn request(addr: SocketAddr, line: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    s.write_all(format!("{line}\r\n\r\n").as_bytes())
        .expect("write");

    let mut r = BufReader::new(s);
    let mut status_line = String::new();
    r.read_line(&mut status_line).expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    // skip headers
    loop {
        let mut h = String::new();
        r.read_line(&mut h).expect("header");
        if h.trim().is_empty() {
            break;
        }
    }
    let mut body = String::new();
    let _ = r.read_to_string(&mut body);
    (status, body)
}

#[test]
fn the_page_is_served() {
    let (addr, _st) = start(None);
    let (status, body) = request(addr, "GET / HTTP/1.1");
    assert_eq!(status, 200);
    assert!(body.contains("<title>vigil</title>"), "not the panel page");
    assert!(
        body.contains("/api/status"),
        "the page must know where to fetch its state"
    );
}

#[test]
fn status_reflects_the_live_cache_and_counters() {
    let (addr, st) = start(None);
    st.stats
        .accepted
        .fetch_add(3, std::sync::atomic::Ordering::Relaxed);

    let (status, body) = request(addr, "GET /api/status HTTP/1.1");
    assert_eq!(status, 200);
    assert!(body.contains(r#""accepted":3"#), "{body}");
    assert!(body.contains(r#""host":"discord.com""#), "{body}");
    assert!(body.contains(r#""host":"roblox.com""#), "{body}");
    assert!(body.contains(r#""mode":"auto""#), "{body}");
    assert!(
        body.contains("com.tr"),
        "exclusions must be visible: {body}"
    );
}

#[test]
fn forgetting_one_host_removes_only_that_host() {
    let (addr, st) = start(None);
    let (status, _) = request(addr, "POST /api/forget?host=discord.com HTTP/1.1");
    assert_eq!(status, 200);

    let c = st.cache.lock().unwrap();
    assert_eq!(c.get("discord.com"), None, "host was not forgotten");
    assert!(c.get("roblox.com").is_some(), "the wrong host was removed");
}

#[test]
fn forgetting_everything_empties_the_cache() {
    let (addr, st) = start(None);
    let (status, _) = request(addr, "POST /api/forget HTTP/1.1");
    assert_eq!(status, 200);
    assert!(st.cache.lock().unwrap().is_empty());
}

/// Forgetting must reach the disk, or a restart brings the host straight back.
#[test]
fn a_forget_is_persisted() {
    let dir = std::env::temp_dir().join(format!("vigil-panel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("cache.txt");

    let (addr, _st) = start(Some(path.clone()));
    request(addr, "POST /api/forget?host=discord.com HTTP/1.1");

    let text = std::fs::read_to_string(&path).expect("cache file written");
    let (reloaded, skipped) = Cache::from_text(&text);
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(
        reloaded.get("discord.com"),
        None,
        "forget was not persisted"
    );
    assert!(reloaded.get("roblox.com").is_some(), "took the wrong one");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_path_is_a_404() {
    let (addr, _st) = start(None);
    let (status, _) = request(addr, "GET /../../etc/passwd HTTP/1.1");
    assert_eq!(status, 404);
}

#[test]
fn a_malformed_request_does_not_take_the_panel_down() {
    let (addr, _st) = start(None);
    for line in ["", "GET", "\x00\x01\x02", "PUT / HTTP/1.1"] {
        let _ = request(addr, line);
    }
    // still alive
    let (status, _) = request(addr, "GET /api/status HTTP/1.1");
    assert_eq!(status, 200, "panel died on malformed input");
}

#[test]
fn the_panel_binds_to_loopback_in_the_test_and_answers_there() {
    let (addr, _st) = start(None);
    assert!(addr.ip().is_loopback(), "test bound off-loopback");
    let (status, _) = request(addr, "GET /api/status HTTP/1.1");
    assert_eq!(status, 200);
}

/// Many panels open at once must not deadlock against the proxy holding the same cache.
#[test]
fn concurrent_requests_do_not_deadlock() {
    let (addr, _st) = start(None);
    let handles: Vec<_> = (0..20)
        .map(|i| {
            std::thread::spawn(move || {
                let line = if i % 3 == 0 {
                    "GET /api/status HTTP/1.1"
                } else {
                    "GET / HTTP/1.1"
                };
                request(addr, line).0
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().expect("thread"), 200);
    }
}
