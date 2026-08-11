//! The I/O half: open a socket, drive TLS with our own first flight, read one response.
//!
//! Every decision is in [`crate::http`] and tested on Linux. This file opens sockets and does what
//! it is told, and it is written to be readable rather than clever, because it runs on a line that
//! misbehaves and the thing that goes wrong will be diagnosed from its log.
//!
//! rustls is driven by hand rather than through `Stream`, the same way `probe/src/attempt.rs` does
//! it, for the same reason: we own the exact `write()` boundaries of the first flight, and that is
//! the entire technique. Those twenty lines are deliberately duplicated rather than shared —
//! making the measurement harness a dependency of a shipping binary would be the wrong direction,
//! and `probe/` is allowed to change shape for a measurement in a way a shipping updater is not.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;
use vigil_core::strategy::Strategy;
use vigil_proxy::{plan_first_write, Resolver};

use crate::http::{
    action_for, parse_head, request_for, resolve_redirect, strategies, Action, HttpError, Url,
    MAX_BODY, MAX_REDIRECTS,
};

/// How long each stage may take. Explicit and separate, because "it hung" is the failure mode of a
/// silently-dropping line and one timeout for the whole operation cannot tell a slow download from
/// a dead one.
#[derive(Debug, Clone, Copy)]
pub struct Deadlines {
    pub connect: Duration,
    /// From request sent to the response head being complete.
    pub head: Duration,
    /// The longest a body may take in total.
    pub body: Duration,
    /// The longest a single read may return nothing before the attempt is abandoned.
    pub stall: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Deadlines {
            connect: Duration::from_secs(5),
            head: Duration::from_secs(10),
            // A 2.5 MB binary on a slow Turkish line, with room to spare.
            body: Duration::from_secs(300),
            stall: Duration::from_secs(20),
        }
    }
}

/// What one fetch attempt did, whether or not it worked. Printed for every attempt, because on this
/// line the reply *latency* is what separates the local injector from the far end, and reading a
/// reset without its timing has cost this project a day twice.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub url: String,
    pub address: Option<SocketAddr>,
    pub strategy: String,
    pub client_hello_len: usize,
    pub reply_ms: u128,
    pub status: Option<u16>,
    pub bytes: usize,
    pub error: Option<String>,
}

impl core::fmt::Display for Attempt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} via {} addr={} ch={} {}ms",
            self.url,
            self.strategy,
            self.address
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".into()),
            self.client_hello_len,
            self.reply_ms
        )?;
        match (&self.status, &self.error) {
            (Some(s), _) => write!(f, " HTTP {s} {} bytes", self.bytes),
            (None, Some(e)) => write!(f, " FAILED {e}"),
            (None, None) => f.write_str(" no reply"),
        }
    }
}

/// A fetched body, and the trail of attempts it took.
#[derive(Debug)]
pub struct Fetched {
    pub body: Vec<u8>,
    pub attempts: Vec<Attempt>,
    /// The URL the bytes finally came from, after redirects.
    pub final_url: String,
}

fn tls_config() -> Arc<ClientConfig> {
    // One classical key-exchange group, no post-quantum share — the same choice `probe/` makes, and
    // for the same measured reason: rustls' default ClientHello is ~1730 B and the kernel splits it
    // before it reaches the wire, which would make our own transform meaningless.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions are always valid")
        .with_root_certificates(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();
    // No session resumption. A resumed handshake sends a different ClientHello, which would make
    // the second fetch of a run a different experiment from the first.
    cfg.resumption = rustls::client::Resumption::disabled();
    Arc::new(cfg)
}

/// GET a URL, following redirects, trying the transform and then plain.
///
/// The host allowlist is checked here and again on every redirect. Returns the first body that
/// arrives complete; a short body is an error, never a truncated success.
pub fn get(
    url: &Url,
    resolver: &Resolver,
    dl: Deadlines,
) -> Result<Fetched, (HttpError, Vec<Attempt>)> {
    let mut attempts = Vec::new();
    let mut current = url.clone();
    let mut hops = 0usize;

    loop {
        if !crate::http::host_allowed(&current.host) {
            return Err((HttpError::HostNotAllowed(current.host), attempts));
        }
        let addrs = resolver.resolve(&current.host, current.port);
        if addrs.is_empty() {
            let e = HttpError::Resolve(format!("{} resolved to nothing usable", current.host));
            attempts.push(Attempt {
                url: current.to_string_https(),
                address: None,
                strategy: "-".into(),
                client_hello_len: 0,
                reply_ms: 0,
                status: None,
                bytes: 0,
                error: Some(e.to_string()),
            });
            return Err((e, attempts));
        }

        let mut last: Option<HttpError> = None;
        let mut got: Option<(Option<Head>, Vec<u8>)> = None;
        'tries: for strategy in strategies() {
            for addr in &addrs {
                let started = Instant::now();
                let mut at = Attempt {
                    url: current.to_string_https(),
                    address: Some(*addr),
                    strategy: strategy.to_string(),
                    client_hello_len: 0,
                    reply_ms: 0,
                    status: None,
                    bytes: 0,
                    error: None,
                };
                match one_attempt(&current, *addr, &strategy, dl, &mut at) {
                    Ok((head, body)) => {
                        at.reply_ms = started.elapsed().as_millis();
                        at.status = Some(head.status);
                        at.bytes = body.len();
                        attempts.push(at);
                        got = Some((Some(head), body));
                        break 'tries;
                    }
                    Err(e) => {
                        at.reply_ms = started.elapsed().as_millis();
                        at.error = Some(e.to_string());
                        attempts.push(at);
                        last = Some(e);
                    }
                }
            }
        }

        let Some((Some(head), body)) = got else {
            return Err((
                last.unwrap_or(HttpError::Io("no attempt ran".into())),
                attempts,
            ));
        };

        match action_for(head.status) {
            Ok(Action::Body) => {
                return Ok(Fetched {
                    body,
                    attempts,
                    final_url: current.to_string_https(),
                })
            }
            Ok(Action::Redirect) => {
                hops += 1;
                if hops > MAX_REDIRECTS {
                    return Err((HttpError::TooManyRedirects, attempts));
                }
                let Some(loc) = head.location.as_deref() else {
                    return Err((HttpError::RedirectWithoutLocation, attempts));
                };
                match resolve_redirect(&current, loc) {
                    Ok(next) => current = next,
                    Err(e) => return Err((e, attempts)),
                }
            }
            Err(e) => return Err((e, attempts)),
        }
    }
}

use crate::http::Head;

/// One TCP connection, one TLS handshake with our first flight, one request, one response.
fn one_attempt(
    url: &Url,
    addr: SocketAddr,
    strategy: &Strategy,
    dl: Deadlines,
    at: &mut Attempt,
) -> Result<(Head, Vec<u8>), HttpError> {
    let name = ServerName::try_from(url.host.clone())
        .map_err(|e| HttpError::Tls(format!("bad server name: {e}")))?;
    let mut conn = ClientConnection::new(tls_config(), name)
        .map_err(|e| HttpError::Tls(format!("init: {e}")))?;

    let mut sock = TcpStream::connect_timeout(&addr, dl.connect).map_err(io)?;
    let _ = sock.set_nodelay(true);
    let _ = sock.set_read_timeout(Some(dl.stall));
    let _ = sock.set_write_timeout(Some(dl.stall));

    // The first flight, captured and then written our way. This is the whole technique.
    let mut flight = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut flight)
            .map_err(|e| HttpError::Tls(format!("write_tls: {e}")))?;
    }
    at.client_hello_len = flight.len();
    let plan = plan_first_write(&flight, strategy);
    for w in &plan.writes {
        sock.write_all(&w.bytes).map_err(io)?;
        if w.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(w.delay_ms as u64));
        }
    }

    // The rest of the handshake goes straight to the socket.
    let handshake_deadline = Instant::now() + dl.head;
    while conn.is_handshaking() {
        if Instant::now() > handshake_deadline {
            return Err(HttpError::Io("handshake timed out".into()));
        }
        if conn.wants_write() {
            conn.write_tls(&mut sock).map_err(io)?;
            continue;
        }
        match conn.read_tls(&mut sock) {
            Ok(0) => return Err(HttpError::Io("closed during handshake".into())),
            Ok(_) => {}
            Err(e) => return Err(io(e)),
        }
        conn.process_new_packets()
            .map_err(|e| HttpError::Tls(e.to_string()))?;
    }
    while conn.wants_write() {
        conn.write_tls(&mut sock).map_err(io)?;
    }

    conn.writer()
        .write_all(request_for(url).as_bytes())
        .map_err(io)?;
    while conn.wants_write() {
        conn.write_tls(&mut sock).map_err(io)?;
    }

    // Read until the head is complete, then until the declared length arrives.
    let mut buf: Vec<u8> = Vec::new();
    let mut head: Option<Head> = None;
    let overall = Instant::now() + dl.body;
    let mut head_by = Instant::now() + dl.head;

    loop {
        if Instant::now() > overall {
            return Err(HttpError::Io("body timed out".into()));
        }
        if head.is_none() && Instant::now() > head_by {
            return Err(HttpError::Io("response head timed out".into()));
        }
        let closed = match conn.read_tls(&mut sock) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => return Err(io(e)),
        };
        let state = conn
            .process_new_packets()
            .map_err(|e| HttpError::Tls(e.to_string()))?;
        let pending = state.plaintext_bytes_to_read();
        if pending > 0 {
            let before = buf.len();
            buf.resize(before + pending, 0);
            conn.reader().read_exact(&mut buf[before..]).map_err(io)?;
        }

        if head.is_none() {
            if let Some(h) = parse_head(&buf)? {
                let len = h.content_length.ok_or(HttpError::LengthRequired)?;
                if len > MAX_BODY {
                    return Err(HttpError::BodyTooLarge(len));
                }
                // From here the body has its own clock, so a complete head cannot be starved by
                // the head deadline.
                head_by = overall;
                head = Some(h);
            }
        }
        if let Some(h) = &head {
            let want = h.content_length.unwrap_or(0);
            let have = buf.len().saturating_sub(h.head_len) as u64;
            if have >= want {
                let body = buf[h.head_len..h.head_len + want as usize].to_vec();
                return Ok((h.clone(), body));
            }
            if closed || state.peer_has_closed() {
                // The shape censorship takes on a silently-dropping line. It must never look like
                // a complete body.
                return Err(HttpError::ShortBody { want, got: have });
            }
        } else if closed {
            return Err(HttpError::BadResponse("closed before the head".into()));
        }
    }
}

fn io(e: std::io::Error) -> HttpError {
    HttpError::Io(format!("{:?}", e.kind()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deadlines are separate on purpose: one timeout for the whole operation cannot tell a
    /// slow 2.5 MB download from a line that has stopped answering.
    #[test]
    fn the_deadlines_are_ordered_the_way_the_stages_are() {
        let d = Deadlines::default();
        assert!(d.connect < d.head, "connecting is quicker than answering");
        assert!(d.head < d.body, "a head is quicker than a body");
        assert!(
            d.stall < d.body,
            "a stall must be caught before the body deadline"
        );
        assert!(d.body >= Duration::from_secs(120), "a slow line needs room");
    }

    /// Build the first flight offline — no network — and measure it. Same shape as
    /// `probe/src/profile.rs`, deliberately: this is the same measurement, on the config the
    /// updater actually uses.
    fn flight_len(host: &str) -> usize {
        let name =
            ServerName::try_from(host.to_string()).expect("allowlisted host is a valid name");
        let mut conn = ClientConnection::new(tls_config(), name).expect("client connection");
        let mut buf = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut buf)
                .expect("write_tls into a Vec cannot fail");
        }
        buf.len()
    }

    /// Margin below the MSS the flight must clear. A ClientHello that merely *happens* to fit
    /// today is not a guarantee — hostname length and extension changes move it by tens of bytes.
    const SAFE_MARGIN: usize = 200;

    /// **The single key-exchange group is the whole reason the updater's transform means
    /// anything**, and nothing pinned it.
    ///
    /// With rustls' default provider the X25519MLKEM768 hybrid share pushes the ClientHello to
    /// ~1730 B, past the MSS, and the kernel segments it before it reaches the wire — at which
    /// point vigil is no longer the thing deciding where the flight is cut, and the updater is not
    /// running the experiment that was measured. Deleting that one line left the whole suite green.
    ///
    /// Every allowlisted host, not just `github.com`: the binding case is the longest name,
    /// `release-assets.githubusercontent.com`, and iterating means a host added to the allowlist
    /// later is length-checked for free.
    #[test]
    fn the_first_flight_fits_one_segment_for_every_allowed_host() {
        for host in crate::manifest::ALLOWED_HOSTS {
            let n = flight_len(host);
            assert!(
                n + SAFE_MARGIN <= vigil_core::TYPICAL_MSS,
                "{host}: ClientHello is {n} B; needs <= {} B or the kernel splits it before we do",
                vigil_core::TYPICAL_MSS - SAFE_MARGIN
            );
        }
        assert!(
            !webpki_roots::TLS_SERVER_ROOTS.is_empty(),
            "no roots loaded"
        );
    }

    /// A TLS config that resumes sessions would make the second fetch of a run a different
    /// experiment from the first — a resumed handshake sends a different, shorter ClientHello.
    ///
    /// The test that used to carry this name asserted `Arc::strong_count(&cfg) >= 1`, which is
    /// true of every `Arc` ever created, so the line it claimed to guard could be deleted freely.
    #[test]
    fn the_tls_config_does_not_resume() {
        assert_eq!(
            format!("{:?}", tls_config().resumption),
            format!("{:?}", rustls::client::Resumption::disabled()),
            "session resumption was re-enabled: the second fetch of a run would send a different \
             ClientHello from the first"
        );
    }

    #[test]
    fn an_attempt_prints_its_address_strategy_hello_length_and_latency() {
        let a = Attempt {
            url: "https://github.com/x".into(),
            address: Some("140.82.121.4:443".parse().expect("addr")),
            strategy: "tlsrec:64+split:1".into(),
            client_hello_len: 231,
            reply_ms: 64,
            status: Some(200),
            bytes: 512,
            error: None,
        };
        let s = a.to_string();
        for want in [
            "140.82.121.4:443",
            "tlsrec:64+split:1",
            "ch=231",
            "64ms",
            "HTTP 200",
            "512 bytes",
        ] {
            assert!(s.contains(want), "{want:?} missing from {s:?}");
        }
    }

    /// A failed attempt must still print its latency, because on this line 2 ms is the local
    /// injector and 4 ms is the far end, and that distinction has cost this project a day twice.
    #[test]
    fn a_failed_attempt_still_reports_its_timing() {
        let a = Attempt {
            url: "https://github.com/x".into(),
            address: Some("140.82.121.4:443".parse().expect("addr")),
            strategy: "none".into(),
            client_hello_len: 231,
            reply_ms: 2,
            status: None,
            bytes: 0,
            error: Some("io: ConnectionReset".into()),
        };
        let s = a.to_string();
        assert!(s.contains("2ms"), "{s}");
        assert!(s.contains("FAILED"), "{s}");
        assert!(s.contains("ConnectionReset"), "{s}");
    }
}
