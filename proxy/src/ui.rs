//! The local control panel: a tiny HTTP server on loopback.
//!
//! No GUI framework. Two of the five deleted iterations died of UI-first with Slint, and a
//! desktop toolkit would add a build dependency, a packaging story and a platform difference
//! for what is a status page with three buttons. HTTP is already in the process.
//!
//! Everything that decides *what* to answer is pure — [`route`] takes a request line and
//! returns a [`Response`] — so the whole surface is unit-testable without a socket, on Linux,
//! in milliseconds. The I/O is a dozen lines at the bottom.
//!
//! Bound to loopback only. This endpoint can change how traffic is handled, so it must never
//! be reachable from the network.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use vigil_core::calibrate::Cache;
use vigil_core::hostlist::HostRules;
use vigil_core::strategy::Strategy;

use crate::server::{Mode, Stats};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    pub fn ok_html(body: impl Into<String>) -> Self {
        Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: body.into(),
        }
    }
    pub fn ok_json(body: impl Into<String>) -> Self {
        Response {
            status: 200,
            content_type: "application/json; charset=utf-8",
            body: body.into(),
        }
    }
    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: "text/plain; charset=utf-8",
            body: "not found\n".into(),
        }
    }
    pub fn bad_request(why: &str) -> Self {
        Response {
            status: 400,
            content_type: "text/plain; charset=utf-8",
            body: format!("{why}\n"),
        }
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "Error",
        };
        format!(
            "HTTP/1.1 {} {reason}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Cache-Control: no-store\r\n\
             Connection: close\r\n\r\n{}",
            self.status,
            self.content_type,
            self.body.len(),
            self.body
        )
        .into_bytes()
    }
}

/// Everything the panel can see.
pub struct View<'a> {
    pub listen: String,
    pub mode: &'a Mode,
    pub fixed: &'a Strategy,
    pub stats: &'a Stats,
    pub cache: &'a Cache,
    pub rules: &'a HostRules,
}

/// What a request asked us to change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Forget one learned host so it is recalibrated.
    ForgetHost(String),
    /// Forget everything learned.
    ForgetAll,
}

/// Decide the response and any state change. Pure.
pub fn route(request_line: &str, v: &View<'_>) -> (Response, Action) {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    match (method, path) {
        ("GET", "/") => (Response::ok_html(PAGE), Action::None),
        ("GET", "/api/status") => (Response::ok_json(status_json(v)), Action::None),
        ("POST", "/api/forget") => match query_value(query, "host") {
            Some(h) if !h.is_empty() => {
                (Response::ok_json(r#"{"ok":true}"#), Action::ForgetHost(h))
            }
            Some(_) => (
                Response::bad_request("host must not be empty"),
                Action::None,
            ),
            None => (Response::ok_json(r#"{"ok":true}"#), Action::ForgetAll),
        },
        ("GET", _) | ("POST", _) => (Response::not_found(), Action::None),
        _ => (Response::bad_request("unsupported method"), Action::None),
    }
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(c) => {
                        out.push(c as char);
                        i += 3;
                    }
                    Err(_) => {
                        out.push('%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// JSON without a serialisation dependency. Small enough to be obviously correct, and every
/// string that reaches it goes through [`esc`].
pub fn status_json(v: &View<'_>) -> String {
    let s = v.stats;
    let mode = match v.mode {
        Mode::Auto => "auto".to_string(),
        Mode::Fixed(st) => format!("fixed:{st}"),
    };
    let learned: Vec<String> = v
        .cache
        .hosts()
        .map(|h| {
            format!(
                r#"{{"host":"{}","strategy":"{}"}}"#,
                esc(h),
                esc(&v.cache.get(h).map(|s| s.to_string()).unwrap_or_default())
            )
        })
        .collect();
    let excluded: Vec<String> = v
        .rules
        .excludes()
        .iter()
        .map(|p| format!(r#""{}""#, esc(&p.to_string())))
        .collect();

    format!(
        r#"{{"listen":"{}","mode":"{}","strategy":"{}","counters":{{"accepted":{},"completed":{},"transformed":{},"excluded":{},"cache_hits":{},"calibrated":{},"handshake_errors":{},"upstream_errors":{},"refused":{},"first_flight_retries":{}}},"dialects":{{"socks5":{},"socks4":{},"http_connect":{},"unrecognised":{}}},"learned":[{}],"excluded_patterns":[{}]}}"#,
        esc(&v.listen),
        esc(&mode),
        esc(&v.fixed.to_string()),
        s.accepted.load(Ordering::Relaxed),
        s.completed.load(Ordering::Relaxed),
        s.transformed.load(Ordering::Relaxed),
        s.excluded.load(Ordering::Relaxed),
        s.cache_hits.load(Ordering::Relaxed),
        s.calibrated.load(Ordering::Relaxed),
        s.handshake_errors.load(Ordering::Relaxed),
        s.upstream_errors.load(Ordering::Relaxed),
        s.refused_over_capacity.load(Ordering::Relaxed),
        s.first_flight_retries.load(Ordering::Relaxed),
        s.by_socks5.load(Ordering::Relaxed),
        s.by_socks4.load(Ordering::Relaxed),
        s.by_http_connect.load(Ordering::Relaxed),
        s.unrecognised.load(Ordering::Relaxed),
        learned.join(","),
        excluded.join(",")
    )
}

/// Escape for a JSON string literal. Hostnames come off the wire, so this is not optional.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub const PAGE: &str = include_str!("ui.html");

// ---------------------------------------------------------------------------- I/O
//
// Everything below is plumbing. It reads a request line, hands it to `route`, applies the
// action and writes the response. No decisions live here.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Mutex;

/// The shared state the panel reads and mutates.
pub struct PanelState {
    pub listen: String,
    pub mode: Mode,
    pub fixed: Strategy,
    pub stats: Arc<Stats>,
    pub cache: Arc<Mutex<Cache>>,
    pub rules: HostRules,
    pub cache_path: Option<std::path::PathBuf>,
}

/// Serve the panel until the listener errors. Blocks; run it on its own thread.
pub fn serve(listener: TcpListener, state: Arc<PanelState>) {
    for conn in listener.incoming() {
        let Ok(mut sock) = conn else { continue };
        // Loopback only, and a panel request is tiny — a short deadline is plenty and stops a
        // stuck client from holding a thread.
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut line = String::new();
            let peer = sock.peer_addr().ok();
            if BufReader::new(&sock).read_line(&mut line).is_err() {
                return;
            }
            if !peer.map(|p| p.ip().is_loopback()).unwrap_or(false) {
                // Belt and braces: the listener is bound to loopback, but this endpoint can
                // change how traffic is handled and must never answer anyone else.
                let _ = sock.write_all(&Response::not_found().to_wire());
                return;
            }
            let resp = handle(line.trim_end(), &state);
            let _ = sock.write_all(&resp.to_wire());
        });
    }
}

fn handle(request_line: &str, state: &PanelState) -> Response {
    let (resp, action) = {
        let cache = match state.cache.lock() {
            Ok(c) => c,
            Err(_) => return Response::bad_request("state unavailable"),
        };
        let view = View {
            listen: state.listen.clone(),
            mode: &state.mode,
            fixed: &state.fixed,
            stats: &state.stats,
            cache: &cache,
            rules: &state.rules,
        };
        route(request_line, &view)
    };

    match action {
        Action::None => {}
        Action::ForgetHost(h) => {
            if let Ok(mut c) = state.cache.lock() {
                c.forget(&h);
            }
            persist(state);
        }
        Action::ForgetAll => {
            if let Ok(mut c) = state.cache.lock() {
                c.clear();
            }
            persist(state);
        }
    }
    resp
}

fn persist(state: &PanelState) {
    let Some(p) = &state.cache_path else { return };
    let Ok(c) = state.cache.lock() else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, c.to_text());
}

pub fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(
        stats: &'a Stats,
        cache: &'a Cache,
        rules: &'a HostRules,
        mode: &'a Mode,
        fixed: &'a Strategy,
    ) -> View<'a> {
        View {
            listen: "127.0.0.1:1080".into(),
            mode,
            fixed,
            stats,
            cache,
            rules,
        }
    }

    #[test]
    fn the_root_path_serves_the_page() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        let (r, a) = route("GET / HTTP/1.1", &view(&st, &ca, &ru, &m, &f));
        assert_eq!(r.status, 200);
        assert!(r.content_type.starts_with("text/html"));
        assert!(r.body.contains("vigil"), "page does not mention the tool");
        assert_eq!(a, Action::None);
    }

    #[test]
    fn status_reports_the_counters_and_the_learned_hosts() {
        let st = Stats::default();
        st.accepted.fetch_add(7, Ordering::Relaxed);
        st.transformed.fetch_add(5, Ordering::Relaxed);
        st.excluded.fetch_add(2, Ordering::Relaxed);
        let mut ca = Cache::new();
        ca.insert("discord.com", Strategy::parse("split:1").unwrap());
        let ru = HostRules::default();
        let (m, f) = (Mode::Auto, Strategy::measured_default());

        let (r, _) = route("GET /api/status HTTP/1.1", &view(&st, &ca, &ru, &m, &f));
        assert_eq!(r.status, 200);
        assert!(r.body.contains(r#""accepted":7"#), "{}", r.body);
        assert!(r.body.contains(r#""transformed":5"#));
        assert!(r.body.contains(r#""excluded":2"#));
        assert!(r.body.contains(r#""host":"discord.com""#));
        assert!(r.body.contains(r#""strategy":"split:1""#));
        assert!(r.body.contains(r#""mode":"auto""#));
        assert!(
            r.body.contains("com.tr"),
            "the exclude list must be visible; it is the thing users need to trust"
        );
        assert!(
            r.body.contains(r#""dialects""#),
            "which protocol clients arrive on is the difference between the tool running \
             and the tool being used: {}",
            r.body
        );
    }

    #[test]
    fn fixed_mode_is_reported_with_its_strategy() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let f = Strategy::parse("tlsrec:64+split:1").unwrap();
        let m = Mode::Fixed(f.clone());
        let (r, _) = route("GET /api/status HTTP/1.1", &view(&st, &ca, &ru, &m, &f));
        assert!(
            r.body.contains(r#""mode":"fixed:tlsrec:64+split:1""#),
            "{}",
            r.body
        );
    }

    #[test]
    fn forgetting_one_host_is_requested_by_query() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        let (r, a) = route(
            "POST /api/forget?host=discord.com HTTP/1.1",
            &view(&st, &ca, &ru, &m, &f),
        );
        assert_eq!(r.status, 200);
        assert_eq!(a, Action::ForgetHost("discord.com".into()));
    }

    #[test]
    fn forgetting_without_a_host_clears_everything() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        let (_, a) = route("POST /api/forget HTTP/1.1", &view(&st, &ca, &ru, &m, &f));
        assert_eq!(a, Action::ForgetAll);
    }

    #[test]
    fn a_percent_encoded_host_is_decoded() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        let (_, a) = route(
            "POST /api/forget?host=a%2Eb%2Ecom HTTP/1.1",
            &view(&st, &ca, &ru, &m, &f),
        );
        assert_eq!(a, Action::ForgetHost("a.b.com".into()));
    }

    #[test]
    fn an_unknown_path_is_a_404_and_changes_nothing() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        for line in ["GET /wibble HTTP/1.1", "POST /etc/passwd HTTP/1.1"] {
            let (r, a) = route(line, &view(&st, &ca, &ru, &m, &f));
            assert_eq!(r.status, 404, "{line}");
            assert_eq!(a, Action::None, "{line}");
        }
    }

    #[test]
    fn an_unsupported_method_is_rejected_and_changes_nothing() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        for line in ["DELETE / HTTP/1.1", "PUT /api/forget HTTP/1.1", "garbage"] {
            let (r, a) = route(line, &view(&st, &ca, &ru, &m, &f));
            assert!(r.status >= 400, "{line} returned {}", r.status);
            assert_eq!(a, Action::None, "{line}");
        }
    }

    /// A hostname reaches the panel straight off the wire. If it is not escaped, one
    /// connection to a maliciously named host breaks the page for everyone looking at it.
    #[test]
    fn hostnames_are_escaped_into_json() {
        let mut ca = Cache::new();
        ca.insert("evil\"host\\x", Strategy::parse("split:1").unwrap());
        let (st, ru) = (Stats::default(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        let (r, _) = route("GET /api/status HTTP/1.1", &view(&st, &ca, &ru, &m, &f));
        assert!(
            !r.body.contains(r#"evil"host"#),
            "unescaped quote: {}",
            r.body
        );
        assert!(r.body.contains(r#"evil\"host"#), "{}", r.body);
    }

    #[test]
    fn escaping_covers_control_characters() {
        assert_eq!(esc("a\"b"), "a\\\"b");
        assert_eq!(esc("a\\b"), "a\\\\b");
        assert_eq!(esc("a\nb"), "a\\nb");
        assert_eq!(esc("a\u{1}b"), "a\\u0001b");
        assert_eq!(esc("plain"), "plain");
    }

    #[test]
    fn the_wire_form_has_a_correct_content_length() {
        let r = Response::ok_json(r#"{"a":1}"#);
        let wire = String::from_utf8(r.to_wire()).unwrap();
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("Content-Length: 7\r\n"));
        assert!(wire.ends_with(r#"{"a":1}"#));
    }

    #[test]
    fn arbitrary_request_lines_never_panic() {
        let (st, ca, ru) = (Stats::default(), Cache::new(), HostRules::default());
        let (m, f) = (Mode::Auto, Strategy::measured_default());
        let v = view(&st, &ca, &ru, &m, &f);
        let mut seed = 0x1357_9BDFu64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 60) as usize;
            let s: String = (0..n)
                .map(|_| char::from(b'\x20' + (next() % 90) as u8))
                .collect();
            let _ = route(&s, &v);
        }
        // and the shapes most likely to trip a hand-rolled parser
        for line in [
            "",
            "GET",
            "GET ",
            "GET /api/forget?host= HTTP/1.1",
            "GET /?a=%",
            "GET /?a=%zz",
            "POST /api/forget?host=%",
        ] {
            let _ = route(line, &v);
        }
    }
}
