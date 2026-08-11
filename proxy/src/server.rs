//! The listener.
//!
//! It accepts SOCKS5, SOCKS4/4a and HTTP `CONNECT` on one port, choosing between them from
//! the first bytes — see [`crate::dialect`] for why all three are necessary rather than
//! generous.
//!
//! This module only moves bytes. Every protocol decision lives in [`crate::socks5`],
//! [`crate::socks4`] and [`crate::http_connect`], and every decision about *how* to write the
//! first flight lives in `vigil_core::transform`. What is left here is I/O, which is the part
//! that cannot be unit tested — so there is deliberately very little of it.
//!
//! Threading is one thread per direction per connection. That is heavier than an async
//! runtime but it has no dependencies and no hidden scheduling behaviour, and the plan says
//! to measure before optimising. `max_connections` bounds the damage.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vigil_core::calibrate::{Cache, Calibrator, Trial};
use vigil_core::hostlist::HostRules;
use vigil_core::strategy::{Plan, Strategy};

use crate::dialect::{sniff, Dialect, Sniff};
use crate::socks5::{self, Error as S5, Rep};
use crate::{http_connect, socks4};

/// How the first flight is treated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// One strategy for everything. `Strategy::passthrough()` is a plain relay.
    Fixed(Strategy),
    /// Learn per host: sweep candidates until one holds, remember it, fall back when it stops.
    Auto,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    /// Passthrough writes the first flight exactly as the client sent it.
    pub strategy: Strategy,
    pub mode: Mode,
    /// Hosts the tool must leave completely alone.
    pub rules: HostRules,
    /// Where the learned per-host strategies live. `None` keeps them in memory only.
    pub cache_path: Option<std::path::PathBuf>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_connections: usize,
    /// How many times the first flight may be sent before giving up, on a fresh connection
    /// each time. 1 disables retrying. Only applies where the outcome is watched anyway.
    pub first_flight_attempts: usize,
    /// Keep the set of hostnames that arrived, in memory, for a measurement run.
    ///
    /// **Opt-in, and off in the shipped product.** What passes through a proxy is the user's
    /// browsing; a testbench needs to know whether an application under test reached us at
    /// all, and nothing else does. `vigil-bench` turns it on for the minutes it runs and
    /// reports only the names of the application it was asked about.
    pub record_hosts: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:1080".parse().expect("literal is a valid addr"),
            strategy: Strategy::passthrough(),
            mode: Mode::Fixed(Strategy::passthrough()),
            rules: HostRules::default(),
            cache_path: None,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(60),
            max_connections: 512,
            // Three: measured, not chosen. A single attempt reaches the Discord updater's
            // endpoint 9/20; three independent attempts at that rate leave roughly one start
            // in ten to the client's own retry, and each costs 4 ms rather than 2.3 s.
            first_flight_attempts: 3,
            record_hosts: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub accepted: AtomicUsize,
    pub completed: AtomicUsize,
    pub refused_over_capacity: AtomicUsize,
    pub handshake_errors: AtomicUsize,
    pub upstream_errors: AtomicUsize,
    /// Connections whose first flight was split rather than passed through.
    pub transformed: AtomicUsize,
    /// Connections served from a learned per-host strategy.
    pub cache_hits: AtomicUsize,
    /// Hosts whose strategy the calibrator settled on during this run.
    pub calibrated: AtomicUsize,
    /// Connections left untouched because the host is on the exclude list.
    pub excluded: AtomicUsize,
    /// How clients are reaching us, split by protocol. Worth counting on its own: the whole
    /// reason v1 could not help the Discord updater was that nothing on Windows was speaking
    /// the one dialect we listened for, and a plain "accepted" count cannot show that.
    pub by_socks5: AtomicUsize,
    pub by_socks4: AtomicUsize,
    pub by_http_connect: AtomicUsize,
    /// Connections whose opening bytes matched no dialect we speak.
    pub unrecognised: AtomicUsize,
    /// Names that resolved to nothing usable. Counted separately from upstream errors
    /// because "the censor owns your DNS" and "the server is down" need different answers.
    pub dns_failures: AtomicUsize,
    /// First flights sent again on a fresh connection after the previous one was reset.
    /// Worth its own number: it is the difference between "the strategy works" and "the
    /// strategy works often enough that retrying hides the rest".
    pub first_flight_retries: AtomicUsize,
    /// Bytes relayed each way, and connections that got **nothing back**.
    ///
    /// Added 2026-08-10 because the counters could not tell a healthy run from a censored one.
    /// `copy()` turns every error into `Ok(total)` — deliberately, since the read timeouts this
    /// proxy sets would otherwise read as failures — and both call sites discarded even that. So a
    /// censor that accepted every flight and then reset every connection mid-stream produced
    /// `handshake errors 0`, `upstream errors 0`, and a report that looked perfect.
    ///
    /// `closed_empty` is the one that matters: a relayed connection over which the upstream never
    /// sent a single byte. On a line whose mechanism is a silent drop that is what censorship looks
    /// like from in here, and it was invisible.
    pub bytes_to_upstream: AtomicUsize,
    pub bytes_from_upstream: AtomicUsize,
    pub closed_empty: AtomicUsize,
    /// Hosts whose learned strategy was **thrown away** after `ABANDON` consecutive failures.
    ///
    /// The counter for the thing that already happened and no report could say. On the second
    /// network, one run's counters read `calibrated 15` above a learned table with fourteen rows,
    /// and working out which host was missing took a set difference and an argument.
    ///
    /// It is the project's only answer to "the censor changed" — and it is **blind to the shape of
    /// censorship the second network actually uses.** `record_failure` is only reached when a trial
    /// was scored as failed, and a read timeout is currently scored as *reached*, so on a line whose
    /// mechanism is silence this counter stays at zero however completely the strategy has stopped
    /// working. `cevapsiz kapanan` is the number to read there until the third trial state exists.
    pub abandoned: AtomicUsize,
}

/// What the client asked for, however it asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// What to hand the connector, e.g. `discord.com:443` or `162.159.138.232:443`.
    /// The hostname the client named — `None` when it resolved DNS itself, which SOCKS4
    /// clients always do.
    pub domain: Option<String>,
    /// The address text, used as a last-resort key when no name is available anywhere.
    pub fallback_host: String,
    /// Kept apart from the host so resolution never has to re-split a joined string — and so
    /// an IPv6 literal cannot be mistaken for a `host:port` on the way through.
    pub port: u16,
}

/// The name to key host rules and calibration on.
///
/// A SOCKS4 client resolves DNS itself and hands over an address, so its request carries no
/// hostname at all — but its ClientHello does. Without this fallback the exclude list would
/// silently stop applying to every SOCKS4 client, and `*.gov.tr` would be calibrated and
/// split like anything else. That is the step-8 gate quietly coming undone, which is exactly
/// the class of failure that killed `primitive_dpibypassapp`.
pub fn host_for(domain: Option<&str>, flight: &[u8], fallback: &str) -> String {
    if let Some(d) = domain {
        return d.to_string();
    }
    if let Ok(ch) = vigil_core::clienthello::parse(flight) {
        if let Some(h) = ch.host_str() {
            if !h.is_empty() {
                return h.to_string();
            }
        }
    }
    fallback.to_string()
}

/// Decide how to write the client's first flight.
///
/// A thin wrapper so the call site reads clearly; all the logic is pure and lives in
/// `vigil_core::strategy`. A transform that cannot apply is skipped, never fatal.
pub fn plan_first_write(flight: &[u8], strategy: &Strategy) -> Plan {
    strategy.plan(flight)
}

/// What was observed about one hostname during a measurement run.
///
/// A set of names was all this recorded until 2026-08-08, and a set could not answer the
/// question a SansürOn report actually raised: forty-seven connections arrived from
/// "other programs" while Discord's Chromium half sent nothing, and whether any of those came
/// from a browser is what decides whether Windows' proxy setting was in force at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRecord {
    /// How many connections asked for this name. One is a lookup; thirty in a minute is a
    /// client retrying, which reads completely differently.
    pub connections: usize,
    /// The strategy specs actually applied, not the ones the cache holds.
    pub applied: std::collections::BTreeSet<String>,
    /// Connections whose first flight went out unchanged — excluded hosts, or a plan that
    /// found nothing to do.
    pub untouched: usize,
    /// Image names of the programs that asked, when the owner could be identified.
    pub clients: std::collections::BTreeSet<String>,
}

pub struct Server {
    cfg: Config,
    /// What arrived this run, keyed by hostname, when `Config::record_hosts` is on.
    seen: Arc<Mutex<std::collections::BTreeMap<String, HostRecord>>>,
    /// The live mode. Behind a lock because the interface can change it while connections are
    /// in flight, and a connection must not see it change halfway through its own first
    /// flight — each one takes a snapshot when it starts.
    mode: Arc<Mutex<Mode>>,
    pub resolver: Arc<crate::resolver::Resolver>,
    pub stats: Arc<Stats>,
    /// What we have learned, and what we are still learning.
    pub cache: Arc<Mutex<Cache>>,
    calibrators: Arc<Mutex<HashMap<String, Calibrator>>>,
}

impl Server {
    pub fn new(cfg: Config) -> Self {
        let cache = match &cfg.cache_path {
            Some(p) => match std::fs::read_to_string(p) {
                Ok(text) => {
                    let (c, skipped) = Cache::from_text(&text);
                    for s in &skipped {
                        eprintln!("cache: skipping {s}");
                    }
                    c
                }
                Err(_) => Cache::new(),
            },
            None => Cache::new(),
        };
        // `Config` carries the strategy twice — `strategy`, and again inside `Mode::Fixed`.
        // Only the first was ever read, so the live mode is built from it and the copy inside
        // `Mode::Fixed` is ignored exactly as before. Everything after startup goes through
        // `set_mode`, which carries its strategy inside the mode and has one source of truth.
        let live_mode = match &cfg.mode {
            Mode::Auto => Mode::Auto,
            Mode::Fixed(_) => Mode::Fixed(cfg.strategy.clone()),
        };
        Server {
            seen: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            mode: Arc::new(Mutex::new(live_mode)),
            cfg,
            resolver: Arc::new(crate::resolver::Resolver::default()),
            stats: Arc::new(Stats::default()),
            cache: Arc::new(Mutex::new(cache)),
            calibrators: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Use a resolver other than the default. The default asks an interception-resistant
    /// server before the operating system; `Resolver::system_only()` restores the old
    /// behaviour for comparison.
    pub fn with_resolver(mut self, r: crate::resolver::Resolver) -> Self {
        self.resolver = Arc::new(r);
        self
    }

    /// Every hostname that arrived, sorted. Empty unless `Config::record_hosts` is on.
    pub fn seen_hosts(&self) -> Vec<String> {
        self.seen
            .lock()
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The same names with what was observed about each: how many connections, which strategy
    /// was applied, and which programs asked.
    pub fn seen_detail(&self) -> Vec<(String, HostRecord)> {
        self.seen
            .lock()
            .map(|s| s.iter().map(|(h, r)| (h.clone(), r.clone())).collect())
            .unwrap_or_default()
    }

    /// Forget what has been seen so far, so the next stretch of a measurement starts empty.
    ///
    /// A testbench needs this between phases: without it, names its own probes sent through
    /// the proxy are already in the set when an application starts, and the application's own
    /// traffic is then invisible as "not new". That produced a confident, wrong "Discord does
    /// not use the proxy" on first run.
    pub fn clear_seen(&self) {
        if let Ok(mut s) = self.seen.lock() {
            s.clear();
        }
    }

    /// What the proxy is doing right now.
    pub fn mode(&self) -> Mode {
        self.mode
            .lock()
            .map(|m| m.clone())
            .unwrap_or_else(|_| self.cfg.mode.clone())
    }

    /// The hosts this proxy leaves completely alone — the same `cfg.rules` the datapath enforces.
    ///
    /// An accessor rather than a constant, because the interface must report what this server was
    /// actually configured with. Reading `DEFAULT_EXCLUDES` instead would agree today only by
    /// coincidence and would lie in the dangerous direction — listing `*.com.tr` as excluded when a
    /// custom rule set had replaced it — and it would lie invisibly, which is how the tray came to
    /// show this list as empty in the first place.
    pub fn excludes(&self) -> &[vigil_core::hostlist::Pattern] {
        self.cfg.rules.excludes()
    }

    /// Change it, for connections that start from here on.
    ///
    /// Connections already in flight keep the mode they started with — see `handle`. Leaving
    /// on `Auto` is what learns per host; switching to `Fixed` does **not** clear what was
    /// learned, so switching back finds the cache as it was.
    pub fn set_mode(&self, mode: Mode) {
        if let Ok(mut m) = self.mode.lock() {
            *m = mode;
        }
    }

    /// Bind and return the listener, so tests can ask for port 0 and learn the port.
    pub fn bind(&self) -> std::io::Result<TcpListener> {
        TcpListener::bind(self.cfg.listen)
    }

    /// Cheap clone of the shared state a connection thread needs.
    fn clone_handles(&self) -> Shared {
        Shared {
            mode: Arc::clone(&self.mode),
            seen: Arc::clone(&self.seen),
            resolver: Arc::clone(&self.resolver),
            cache: Arc::clone(&self.cache),
            calibrators: Arc::clone(&self.calibrators),
            stats: Arc::clone(&self.stats),
            cache_path: self.cfg.cache_path.clone(),
        }
    }

    /// Serve until the listener errors. Blocks.
    pub fn serve(&self, listener: TcpListener) {
        let live = Arc::new(AtomicUsize::new(0));
        for conn in listener.incoming() {
            let Ok(client) = conn else { continue };
            self.stats.accepted.fetch_add(1, Ordering::Relaxed);

            if live.load(Ordering::Relaxed) >= self.cfg.max_connections {
                self.stats
                    .refused_over_capacity
                    .fetch_add(1, Ordering::Relaxed);
                // Nothing has been read yet, so the client's dialect is unknown and any
                // reply we invent would be unparseable to two clients out of three. A close
                // is understood by all of them.
                let _ = client.shutdown(Shutdown::Both);
                continue;
            }

            let cfg = self.cfg.clone();
            let stats = Arc::clone(&self.stats);
            let live2 = Arc::clone(&live);
            live.fetch_add(1, Ordering::Relaxed);
            let me = self.clone_handles();
            std::thread::spawn(move || {
                handle(client, &cfg, &stats, &me);
                live2.fetch_sub(1, Ordering::Relaxed);
                stats.completed.fetch_add(1, Ordering::Relaxed);
            });
        }
    }
}

/// Read until `f` accepts the buffer or the peer goes away.
///
/// Generic over the error type so the same loop drives all three dialects; `incomplete` is
/// the value that means "not yet", and is what a hang-up is reported as.
fn read_until<T, E: PartialEq>(
    s: &mut TcpStream,
    buf: &mut Vec<u8>,
    incomplete: E,
    f: impl Fn(&[u8]) -> Result<(T, usize), E>,
) -> Result<(T, usize), E> {
    let mut tmp = [0u8; 1024];
    loop {
        match f(buf) {
            Err(ref e) if *e == incomplete => {}
            other => return other,
        }
        match s.read(&mut tmp) {
            Ok(0) => return Err(incomplete),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(incomplete),
        }
    }
}

/// Why a connection is being turned away, in dialect-neutral terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The target could not be resolved.
    Unreachable,
    /// The target resolved but would not accept a connection.
    Refused,
}

/// Turn a client away in the protocol it is speaking.
///
/// Answering a SOCKS4 client with a SOCKS5 reply, or an HTTP client with either, leaves it
/// waiting for bytes that will never parse — a hang instead of an error.
fn refuse(client: &mut TcpStream, dialect: Dialect, why: Refusal) {
    let _ = match dialect {
        Dialect::Socks5 => client.write_all(&socks5::reply(match why {
            Refusal::Unreachable => Rep::HostUnreachable,
            Refusal::Refused => Rep::ConnectionRefused,
        })),
        Dialect::Socks4 => client.write_all(&socks4::reply(socks4::REJECTED)),
        Dialect::HttpConnect => client.write_all(&http_connect::error_response(match why {
            Refusal::Unreachable => 504,
            Refusal::Refused => 502,
        })),
    };
}

/// Read until the opening bytes identify a dialect, or the peer goes away.
fn read_dialect(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Dialect> {
    let mut tmp = [0u8; 1024];
    loop {
        match sniff(buf) {
            Sniff::Known(d) => return Some(d),
            Sniff::Unrecognised(_) => return None,
            Sniff::Need => {}
        }
        match s.read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

/// Complete the handshake for `dialect` and return what the client asked for.
///
/// Failure replies are written here, in the dialect the client is speaking — answering a
/// SOCKS4 client with a SOCKS5 reply leaves it hanging until it times out.
fn negotiate(
    client: &mut TcpStream,
    dialect: Dialect,
    buf: &mut Vec<u8>,
    stats: &Stats,
) -> Option<Target> {
    match dialect {
        Dialect::Socks5 => {
            let Ok((methods, used)) =
                read_until(client, buf, S5::Incomplete, socks5::parse_greeting)
            else {
                stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            buf.drain(..used);
            let method = socks5::select_method(&methods);
            if client.write_all(&socks5::method_reply(method)).is_err()
                || method != socks5::METHOD_NO_AUTH
            {
                stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            match read_until(client, buf, S5::Incomplete, socks5::parse_request) {
                Ok((r, used)) => {
                    buf.drain(..used);
                    let domain = match &r.addr {
                        socks5::Addr::Domain(d) => Some(d.clone()),
                        _ => None,
                    };
                    Some(Target {
                        domain,
                        fallback_host: r.addr.to_string(),
                        port: r.port,
                    })
                }
                Err(e) => {
                    stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
                    let rep = match e {
                        S5::UnsupportedCommand(_) => Rep::CommandNotSupported,
                        S5::UnsupportedAddressType(_) => Rep::AddressTypeNotSupported,
                        _ => Rep::GeneralFailure,
                    };
                    let _ = client.write_all(&socks5::reply(rep));
                    None
                }
            }
        }
        Dialect::Socks4 => {
            match read_until(
                client,
                buf,
                socks4::Error::Incomplete,
                socks4::parse_request,
            ) {
                Ok((r, used)) => {
                    buf.drain(..used);
                    let domain = match &r.addr {
                        socks4::Addr::Domain(d) => Some(d.clone()),
                        socks4::Addr::V4(_) => None,
                    };
                    Some(Target {
                        domain,
                        fallback_host: r.addr.to_string(),
                        port: r.port,
                    })
                }
                Err(_) => {
                    stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
                    let _ = client.write_all(&socks4::reply(socks4::REJECTED));
                    None
                }
            }
        }
        Dialect::HttpConnect => {
            match read_until(
                client,
                buf,
                http_connect::Error::Incomplete,
                http_connect::parse_request,
            ) {
                Ok((r, used)) => {
                    buf.drain(..used);
                    Some(Target {
                        domain: Some(r.host.clone()),
                        fallback_host: r.host,
                        port: r.port,
                    })
                }
                Err(e) => {
                    stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
                    let code = match e {
                        http_connect::Error::NotConnect(_) => 405,
                        _ => 400,
                    };
                    let _ = client.write_all(&http_connect::error_response(code));
                    None
                }
            }
        }
    }
}

/// The per-connection view of the server's shared state.
#[derive(Clone)]
pub struct Shared {
    mode: Arc<Mutex<Mode>>,
    seen: Arc<Mutex<std::collections::BTreeMap<String, HostRecord>>>,
    pub resolver: Arc<crate::resolver::Resolver>,
    cache: Arc<Mutex<Cache>>,
    calibrators: Arc<Mutex<HashMap<String, Calibrator>>>,
    stats: Arc<Stats>,
    cache_path: Option<std::path::PathBuf>,
}

impl Shared {
    /// The mode as it stands right now. Taken once per connection, so a mode change cannot
    /// land between a connection's strategy and the outcome recorded against it.
    fn mode(&self) -> Mode {
        self.mode
            .lock()
            .map(|m| m.clone())
            .unwrap_or_else(|_| Mode::Fixed(Strategy::passthrough()))
    }

    fn strategy_for(&self, host: &str, mode: &Mode) -> Strategy {
        match mode {
            Mode::Fixed(s) => s.clone(),
            Mode::Auto => {
                if let Ok(c) = self.cache.lock() {
                    if let Some(s) = c.get(host) {
                        self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                        return s.clone();
                    }
                }
                let Ok(mut cals) = self.calibrators.lock() else {
                    return Strategy::measured_default();
                };
                cals.entry(host.to_ascii_lowercase())
                    .or_insert_with(Calibrator::with_builtin_candidates)
                    .current()
                    .cloned()
                    .unwrap_or_else(Strategy::measured_default)
            }
        }
    }

    fn save(&self) {
        let Some(p) = &self.cache_path else { return };
        let Ok(c) = self.cache.lock() else { return };
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(p, c.to_text());
    }

    fn record_outcome(&self, host: &str, reached: bool, mode: &Mode) {
        if *mode != Mode::Auto {
            return;
        }
        let key = host.to_ascii_lowercase();
        let known = self
            .cache
            .lock()
            .ok()
            .map(|c| c.get(&key).is_some())
            .unwrap_or(false);
        if known {
            if let Ok(mut c) = self.cache.lock() {
                if reached {
                    c.record_success(&key);
                } else if c.record_failure(&key) {
                    self.stats.abandoned.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut cals) = self.calibrators.lock() {
                        cals.remove(&key);
                    }
                }
            }
            return;
        }
        let settled = {
            let Ok(mut cals) = self.calibrators.lock() else {
                return;
            };
            let cal = cals
                .entry(key.clone())
                .or_insert_with(Calibrator::with_builtin_candidates);
            cal.record(if reached {
                Trial::Reached
            } else {
                Trial::Failed
            });
            cal.result().cloned()
        };
        if let Some(s) = settled {
            if let Ok(mut c) = self.cache.lock() {
                c.insert(&key, s);
            }
            self.stats.calibrated.fetch_add(1, Ordering::Relaxed);
            self.save();
        }
    }
}

fn handle(mut client: TcpStream, cfg: &Config, stats: &Stats, shared: &Shared) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(cfg.io_timeout));
    let _ = client.set_write_timeout(Some(cfg.io_timeout));

    // --- which protocol is this? ---
    let mut buf = Vec::with_capacity(512);
    let Some(dialect) = read_dialect(&mut client, &mut buf) else {
        stats.unrecognised.fetch_add(1, Ordering::Relaxed);
        stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    match dialect {
        Dialect::Socks5 => stats.by_socks5.fetch_add(1, Ordering::Relaxed),
        Dialect::Socks4 => stats.by_socks4.fetch_add(1, Ordering::Relaxed),
        Dialect::HttpConnect => stats.by_http_connect.fetch_add(1, Ordering::Relaxed),
    };

    // --- handshake ---
    let Some(req) = negotiate(&mut client, dialect, &mut buf, stats) else {
        return;
    };

    // --- upstream ---
    // Resolved through `crate::resolver`, not the operating system. On a line whose resolver
    // answers blocked names with a block page, handing the OS a hostname means splitting a
    // perfect ClientHello and sending it to the censor.
    let name = req.domain.as_deref().unwrap_or(&req.fallback_host);
    let addrs: Vec<SocketAddr> = shared.resolver.resolve(name, req.port);
    if addrs.is_empty() {
        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
        stats.dns_failures.fetch_add(1, Ordering::Relaxed);
        refuse(&mut client, dialect, Refusal::Unreachable);
        return;
    }
    let connect = |addrs: &[SocketAddr]| -> Option<TcpStream> {
        for a in addrs {
            if let Ok(s) = TcpStream::connect_timeout(a, cfg.connect_timeout) {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(cfg.io_timeout));
                let _ = s.set_write_timeout(Some(cfg.io_timeout));
                return Some(s);
            }
        }
        None
    };
    let Some(mut upstream) = connect(&addrs) else {
        stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
        refuse(&mut client, dialect, Refusal::Refused);
        return;
    };
    let granted = match dialect {
        Dialect::Socks5 => client.write_all(&socks5::reply(Rep::Succeeded)),
        Dialect::Socks4 => client.write_all(&socks4::reply(socks4::GRANTED)),
        Dialect::HttpConnect => client.write_all(http_connect::RESPONSE_OK),
    };
    if granted.is_err() {
        return;
    }

    // --- first flight ---
    // Anything the client pipelined behind the request is already in `buf`; otherwise wait
    // for it, because the whole technique depends on seeing the first write as one buffer.
    if buf.is_empty() {
        let mut tmp = [0u8; 8192];
        match client.read(&mut tmp) {
            Ok(0) | Err(_) => {
                let _ = upstream.shutdown(Shutdown::Both);
                return;
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let host_name = host_for(req.domain.as_deref(), &buf, &req.fallback_host);
    // An excluded host is relayed untouched, and never enters the calibrator: measuring a
    // host we will never act on would poison the statistics with a strategy we did not apply.
    let eligible = cfg.rules.applies_to(&host_name);
    if !eligible {
        stats.excluded.fetch_add(1, Ordering::Relaxed);
    }
    // One snapshot for the whole connection: the mode may change under us at any moment, and
    // a connection that split its flight under one mode must be judged under that same one.
    let mode = shared.mode();
    let strategy = if eligible {
        shared.strategy_for(&host_name, &mode)
    } else {
        Strategy::passthrough()
    };
    let plan = plan_first_write(&buf, &strategy);
    if !plan.did_nothing() {
        stats.transformed.fetch_add(1, Ordering::Relaxed);
    }

    // Recorded here rather than as soon as the name was known, because the interesting parts of
    // the record — which strategy was actually applied, whether anything was — do not exist
    // until now. Asking the operating system who owns the client socket costs one table read
    // per connection, and only when a measurement asked for it.
    if cfg.record_hosts {
        let who = client
            .peer_addr()
            .ok()
            .and_then(|a| vigil_platform::owner::program_for_local_port(a.port()));
        if let Ok(mut s) = shared.seen.lock() {
            // Bounded: a runaway client must not turn a measurement into a memory leak.
            if s.len() < 4096 {
                let e = s.entry(host_name.to_ascii_lowercase()).or_default();
                e.connections += 1;
                // **The spec, plus a mark when it did not all run.** `applied` is documented as
                // "the strategy specs actually applied" and recorded the requested spec, so a
                // `tlsrec:64+split:1` that silently degraded into a bare `split:1` — because the
                // record transform refuses a partial record and the composition swallows the error
                // — was indistinguishable in every report from one that worked. On the second
                // network that degradation is the difference between the only transform that works
                // there and the one strategy that is 0/300 *and* converts a silent drop into an
                // active reset.
                //
                // The spec string stays, because it is what carries the parameters a reader needs
                // (`:64`, `@40`) and what every report is read with. What is added is the mark: the
                // strategy asked for a record split and no record split ran.
                let asked_tlsrec = strategy.tls_record.is_some();
                let ran_tlsrec = plan.applied.contains(&"tlsrec");
                if asked_tlsrec && !ran_tlsrec {
                    e.applied.insert(format!("{strategy} (tlsrec UYGULANMADI)"));
                } else {
                    e.applied.insert(strategy.to_string());
                }
                if plan.did_nothing() {
                    e.untouched += 1;
                }
                if let Some(w) = who {
                    e.clients.insert(w);
                }
            }
        }
    }

    // --- write the first flight, and watch what comes back ---
    //
    // A DPI reset arrives within a round trip or so of the ClientHello, and a server that
    // liked it answers in the same window. Whatever is read here is handed to the relay, so
    // nothing is lost by looking.
    //
    // Looking also buys a second attempt, which is worth more than it sounds. Measured on
    // the home line 2026-08-05: the Discord updater's real 175 B ClientHello, split at byte 1,
    // is answered about half the time and reset the rest — and the reset is **not** the local
    // injector. That one sits three hops away and never fires on a split flight; a TTL sweep
    // of the same flight produced no reset at all up to TTL 8 and only found one once the
    // packet could travel ten hops. The client's own answer is to reconnect 2.3 seconds
    // later, which is what the user sees as Discord hanging at startup. Ours is to reconnect
    // immediately, on a connection the client has not yet been told anything about.
    //
    // The calibrator is deliberately told about the **first** attempt only. A strategy that
    // needs two goes is not a strategy that works, and letting the retry launder it would
    // teach the cache exactly the wrong thing.
    //
    // Watching costs nothing when the far end answers — it is the same read the relay would
    // have done a moment later. It costs a wait only when a server says nothing at all after a
    // first flight, which for the TLS traffic this proxy exists for does not happen. Auto mode
    // has paid that price since step 6; a fixed strategy pays it too when retrying is on,
    // because `vigil --split` failing where `vigil --auto` recovers would be a nasty surprise.
    let attempts = cfg.first_flight_attempts.max(1);
    let watch = eligible && (mode == Mode::Auto || attempts > 1);
    let mut early = Vec::new();
    let mut recorded = false;
    for attempt in 0..attempts {
        if attempt > 0 {
            let _ = upstream.shutdown(Shutdown::Both);
            let Some(fresh) = connect(&addrs) else { break };
            upstream = fresh;
            stats.first_flight_retries.fetch_add(1, Ordering::Relaxed);
        }

        let mut wrote = true;
        for chunk in &plan.writes {
            if chunk.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(chunk.delay_ms as u64));
            }
            if upstream.write_all(&chunk.bytes).is_err() {
                wrote = false;
                break;
            }
            // Counted here as well as in the relay, because the first flight is the *only* thing
            // some connections ever send — a client that writes a ClientHello and waits produces
            // zero relay bytes in that direction, and "bytes to upstream: 0" would then be a lie
            // about a flight that went out.
            stats
                .bytes_to_upstream
                .fetch_add(chunk.bytes.len(), Ordering::Relaxed);
        }
        if !watch {
            if !wrote {
                let _ = client.shutdown(Shutdown::Both);
                return;
            }
            break;
        }
        // A reset can land on the write as easily as on the read, and means the same thing.
        let reached = wrote && {
            let _ = upstream.set_read_timeout(Some(Duration::from_millis(2500)));
            let mut peek = [0u8; 8192];
            let r = match upstream.read(&mut peek) {
                Ok(0) => false,
                Ok(n) => {
                    early.clear();
                    early.extend_from_slice(&peek[..n]);
                    true
                }
                // A timeout is not a reset: nothing killed the flight, so there is nothing to
                // retry, and re-sending would only cost the client another 2.5 seconds.
                Err(e) => !matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                ),
            };
            let _ = upstream.set_read_timeout(Some(cfg.io_timeout));
            r
        };
        if !recorded {
            shared.record_outcome(&host_name, reached, &mode);
            recorded = true;
        }
        if reached {
            break;
        }
    }
    if !early.is_empty() && client.write_all(&early).is_err() {
        return;
    }

    // --- relay ---
    let (mut c2, mut u2) = match (client.try_clone(), upstream.try_clone()) {
        (Ok(c), Ok(u)) => (c, u),
        _ => return,
    };
    let to_up = Arc::clone(&shared.stats);
    let up = std::thread::spawn(move || {
        let n = copy(&mut c2, &mut u2).unwrap_or(0);
        to_up
            .bytes_to_upstream
            .fetch_add(n as usize, Ordering::Relaxed);
        let _ = u2.shutdown(Shutdown::Write);
    });
    // `early` is the first thing the upstream said — read during the watch above, before the relay
    // existed — so it belongs in this direction's total and in the decision below. Leaving it out
    // made **every** probe-shaped connection look silent: the answer arrives in `early`, the client
    // reads it and hangs up, the relay copies nothing, and the counter that exists to say "the
    // upstream never answered" fired on a connection that was answered.
    let back = early.len() as u64 + copy(&mut upstream, &mut client).unwrap_or(0);
    shared
        .stats
        .bytes_from_upstream
        .fetch_add(back as usize, Ordering::Relaxed);
    // Nothing at all came back, in the relay *or* in the watch above. The flight was written, the
    // upstream accepted the connection, and then it said nothing — which is exactly what a
    // silent-drop censor looks like from in here.
    if back == 0 {
        shared.stats.closed_empty.fetch_add(1, Ordering::Relaxed);
    }
    let _ = client.shutdown(Shutdown::Write);
    let _ = up.join();
}

/// Like `io::copy` but tolerant of the timeouts we set: a read timeout ends the direction
/// rather than being treated as a hard error.
fn copy(from: &mut TcpStream, to: &mut TcpStream) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        match from.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                // **Counted before the write, and a failed write ends the direction rather than
                // erasing it.** `write_all` fails whenever the other side has already hung up —
                // which is the ordinary shape of a probe: send a ClientHello, read the answer, drop
                // the socket. It used to be `total += n` *after* a `?`, so the failing case
                // propagated an `Err` and every caller's `.unwrap_or(0)` threw the whole
                // direction's total away. A served connection then read as "nothing came back", on
                // the one counter whose purpose is to tell a censored line from a healthy one.
                //
                // Read errors were already treated as end-of-direction two arms down, for the same
                // reason: this proxy sets read timeouts on purpose, so an error here is ordinary
                // rather than exceptional. The write side now agrees with the read side.
                total += n as u64;
                if to.write_all(&buf[..n]).is_err() {
                    return Ok(total);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Ok(total),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::strategy::Strategy;

    fn hello(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&((2 + 1 + 2 + h.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&((1 + 2 + h.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
        ext.extend_from_slice(h);
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn passthrough_writes_the_flight_unchanged_in_one_go() {
        let b = hello("discord.com");
        let plan = plan_first_write(&b, &Strategy::passthrough());
        assert_eq!(plan.writes.len(), 1);
        assert!(plan.did_nothing());
        assert_eq!(plan.writes[0].bytes, b);
    }

    #[test]
    fn a_strategy_splits_and_reports_that_it_did() {
        let b = hello("discord.com");
        let plan = plan_first_write(&b, &Strategy::split_only());
        assert_eq!(plan.writes.len(), 2);
        assert!(!plan.did_nothing());
        assert_eq!(plan.flatten(), b);
    }

    /// The shipped default has to do both things, because the two measured networks need
    /// different ones: the home line yields to a byte-1 split, SansürOn only to TLS record
    /// fragmentation. A default that did one of them would fail half the connections.
    #[test]
    fn the_default_both_fragments_records_and_splits() {
        let b = hello("discord.com");
        let plan = plan_first_write(&b, &Strategy::measured_default());
        assert!(plan.applied.contains(&"tlsrec"), "{:?}", plan.applied);
        assert!(plan.applied.contains(&"split"), "{:?}", plan.applied);
        assert!(!plan.did_nothing());
        // and the server must still reassemble the identical handshake
        let wire = plan.flatten();
        let mut payload = Vec::new();
        let mut i = 0usize;
        while i + 5 <= wire.len() {
            let n = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
            payload.extend_from_slice(&wire[i + 5..i + 5 + n]);
            i += 5 + n;
        }
        assert_eq!(payload, &b[5..], "the default changed the handshake");
    }

    /// Whatever the strategy, the server must reassemble the same handshake.
    #[test]
    fn every_candidate_preserves_what_the_server_reassembles() {
        let b = hello("cdn.prod.website-files.com");
        for s in vigil_core::candidates() {
            let wire = plan_first_write(&b, &s).flatten();
            let mut payload = Vec::new();
            let mut i = 0usize;
            while i + 5 <= wire.len() {
                let n = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
                payload.extend_from_slice(&wire[i + 5..i + 5 + n]);
                i += 5 + n;
            }
            assert_eq!(payload, &b[5..], "{s} changed the handshake");
        }
    }

    /// A transform that cannot resolve must not break the connection.
    #[test]
    fn an_unresolvable_strategy_falls_back_to_passthrough() {
        let not_tls = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let s = Strategy::parse("split:midsld").expect("parses");
        let plan = plan_first_write(not_tls, &s);
        assert_eq!(plan.flatten(), not_tls, "connection must not be dropped");
        assert!(plan.did_nothing());
    }

    /// **Exact write boundaries, asserted where they are a fact rather than a race.**
    ///
    /// This claim used to live in `e2e.rs`, against a real socket with a 20 ms delay between
    /// writes, and it measured the scheduler: under a loaded workspace run the stub's reader was
    /// descheduled past all three gaps, read `[100]` where the proxy had performed four writes, and
    /// failed with a message that reads exactly like a split-transform regression. Reproduced at
    /// 4 runs in 8 under load. The same collapse had already been diagnosed twice in that file — at
    /// 20 ms and again at 40 ms — and both times the fix was applied to one test and not to this
    /// one.
    ///
    /// A delay is a probability. The boundaries are arithmetic. This is where the arithmetic goes,
    /// and it covers the part the pure `core` tests do not: that the *spec string* reaches them.
    #[test]
    fn a_multi_cut_spec_produces_exactly_those_boundaries() {
        let s = Strategy::parse("split:1,3,7").expect("parses");
        let plan = plan_first_write(&[0xABu8; 100], &s);
        assert_eq!(
            plan.writes
                .iter()
                .map(|w| w.bytes.len())
                .collect::<Vec<_>>(),
            vec![1, 2, 4, 93],
            "cuts at 1,3,7 of a 100-byte flight land exactly here"
        );
        assert_eq!(plan.flatten(), [0xABu8; 100], "the bytes are unchanged");
    }

    #[test]
    fn a_non_tls_flight_still_splits_at_a_byte_offset() {
        let http = b"GET / HTTP/1.1\r\n\r\n";
        let plan = plan_first_write(http, &Strategy::measured_default());
        assert_eq!(plan.writes.len(), 2);
        assert_eq!(plan.flatten(), http);
    }

    #[test]
    fn an_empty_flight_produces_an_empty_write_not_a_panic() {
        let plan = plan_first_write(&[], &Strategy::measured_default());
        assert!(plan.flatten().is_empty());
    }

    // ------------------------------------------------------- naming the host

    #[test]
    fn a_named_host_is_used_as_given() {
        let h = host_for(Some("discord.com"), &hello("ignored.example"), "1.2.3.4");
        assert_eq!(h, "discord.com", "the client's own name wins");
    }

    /// SOCKS4 clients resolve DNS themselves, so the request names an address and the only
    /// hostname on the wire is the one inside the ClientHello.
    #[test]
    fn an_address_only_request_recovers_the_host_from_the_clienthello() {
        let h = host_for(None, &hello("discord.com"), "162.159.138.232");
        assert_eq!(h, "discord.com");
    }

    /// The step-8 gate must survive the dialect. Without the SNI fallback a SOCKS4 client
    /// would present `*.gov.tr` as a bare address and the exclude list would never match it.
    #[test]
    fn the_exclude_list_still_applies_to_an_address_only_request() {
        let rules = HostRules::default();
        for host in ["ziraatbank.com.tr", "turkiye.gov.tr", "metu.edu.tr"] {
            let name = host_for(None, &hello(host), "10.0.0.1");
            assert_eq!(name, host);
            assert!(
                !rules.applies_to(&name),
                "{host} would have been transformed when reached over SOCKS4"
            );
        }
    }

    #[test]
    fn a_flight_with_no_usable_name_falls_back_to_the_address() {
        for flight in [&b""[..], b"GET / HTTP/1.1\r\n\r\n", &[0x16, 0x03, 0x01]] {
            assert_eq!(host_for(None, flight, "162.159.138.232"), "162.159.138.232");
        }
    }

    #[test]
    fn default_config_listens_on_loopback_only() {
        let c = Config::default();
        assert!(
            c.listen.ip().is_loopback(),
            "must not be reachable from the network by default"
        );
        assert_eq!(c.listen.port(), 1080);
        assert_eq!(c.strategy, Strategy::passthrough());
    }

    /// **What was read is counted even when it cannot be forwarded.**
    ///
    /// `copy` had `total += n` *after* `to.write_all(..)?`, so a write that failed threw away the
    /// whole direction's byte count. That is not an exotic case: a client that sends a request, reads
    /// the answer and hangs up leaves the relay holding bytes it can no longer deliver, and the
    /// caller's `.unwrap_or(0)` then read a served connection as "nothing came back" — on the one
    /// counter whose purpose is to tell a censored line from a healthy one.
    #[test]
    fn bytes_read_are_counted_even_when_the_far_side_has_gone() {
        use std::net::TcpListener;

        // A pair to read from, with data waiting in it.
        let src = TcpListener::bind("127.0.0.1:0").expect("bind");
        let src_addr = src.local_addr().expect("addr");
        let feeder = std::thread::spawn(move || {
            let mut w = TcpStream::connect(src_addr).expect("connect");
            let _ = w.write_all(&[0x5Au8; 4096]);
            let _ = w.shutdown(Shutdown::Write);
            // Held until the test is done reading, so the stream is not torn down early.
            std::thread::sleep(Duration::from_millis(400));
        });
        let (mut from, _) = src.accept().expect("accept");

        // A destination that cannot be written to, deterministically: our own write half is shut
        // down, so `write_all` fails on its first attempt with a broken pipe. Closing the *peer*
        // does not do it — a peer's FIN is a half-close and writing after one is legal, so the
        // bytes go into the socket buffer and the write succeeds, which is why the first version of
        // this test could not tell the two orderings apart.
        let dst = TcpListener::bind("127.0.0.1:0").expect("bind");
        let dst_addr = dst.local_addr().expect("addr");
        let mut to = TcpStream::connect(dst_addr).expect("connect");
        let (_peer, _) = dst.accept().expect("accept");
        to.shutdown(Shutdown::Write).expect("shutdown write");

        // `copy` returns `Err` here, and every caller does `.unwrap_or(0)` — so the count has to be
        // right *in the error*, which is only true if the read is counted before the write.
        let total = copy(&mut from, &mut to).unwrap_or(0);
        let _ = feeder.join();
        assert!(
            total >= 4096,
            "4096 bytes were read and could not be forwarded; the count says {total}"
        );
    }
}
