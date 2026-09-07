//! Name resolution that survives a hostile resolver.
//!
//! vigil used to hand hostnames to the operating system and connect to whatever came back.
//! On 2026-08-04 that stopped being safe on the development line itself: the ISP resolver
//! began answering `discord.com` and four other names with `195.175.254.2`, its own block
//! page, and `vigil --split` went from 10/10 to 0/8 without a line of code changing. The
//! split was perfect. It was being applied to a connection to the wrong server.
//!
//! That is not a new failure. It is how `primitive_dpibypassapp` died on its second machine
//! in January, and the postmortem said so at the time.
//!
//! # Why plain DNS on an odd port, and not DoH — and what changed on 2026-09-07
//!
//! The original answer was that DoH needs TLS, TLS needs a dependency, and this crate had none
//! beyond our own core. That reason is now spent: this crate links rustls deliberately, and the
//! DoH mechanism sits in [`crate::doh`]. What has *not* changed is that the odd port still works
//! and is still measured, so it stays — as the fallback, not as the excuse.
//!
//! The rest of this section is why the trick worked at all, and it is still true: the
//! interception here covers **port 53**, not DNS itself.
//! Measured on the affected line, same moment, same names —
//!
//! | resolver | `discord.com` |
//! |---|---|
//! | system (ISP) | `195.175.254.2` — block page |
//! | `1.1.1.1:53`, `9.9.9.9:53`, `8.8.8.8:53` | no reply at all |
//! | **`77.88.8.8:1253`** | **the real Cloudflare addresses** |
//!
//! The Turkish GoodbyeDPI fork ships `--dns-port 1253` for precisely this reason. Sixty lines
//! of RFC 1035 and a UDP socket get us the same escape hatch.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vigil_core::dnsmsg;

/// Addresses that are never a legitimate answer for a public hostname.
///
/// A last line of defence for the system-resolver fallback: if the only answer we can get is
/// one of these, we have not resolved the name, we have been handed a censor's address, and
/// connecting to it would produce a measurement — or a user experience — of the wrong thing.
///
/// `195.175.254.2` is the home line's block page, documented by OONI and observed directly.
/// another provider another provider has been documented answering `127.0.0.1` for `twitter.com`.
const BLOCK_PAGES: &[Ipv4Addr] = &[
    Ipv4Addr::new(195, 175, 254, 2),
    Ipv4Addr::new(127, 0, 0, 1),
    Ipv4Addr::new(0, 0, 0, 0),
];

/// Is this address a censor's, rather than a server's?
pub fn is_block_page(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => BLOCK_PAGES.contains(v4),
        IpAddr::V6(_) => false,
    }
}

/// Drop censor addresses from an answer.
///
/// Returns `None` when nothing usable is left, which is deliberately different from "the
/// name does not resolve": the caller should try another resolver rather than report the
/// host unreachable.
pub fn usable(addrs: Vec<IpAddr>) -> Option<Vec<IpAddr>> {
    let kept: Vec<IpAddr> = addrs.into_iter().filter(|a| !is_block_page(a)).collect();
    (!kept.is_empty()).then_some(kept)
}

/// Where to ask, in order.
///
/// The odd-port resolver is first because it is the one measured to survive interception;
/// the port-53 ones follow because they are correct when nothing is intercepting, and cost
/// nothing when they are silent.
pub fn default_servers() -> Vec<SocketAddr> {
    [
        "77.88.8.8:1253",
        "77.88.8.1:1253",
        "1.1.1.1:53",
        "9.9.9.9:53",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

/// Sweep expired entries once the cache reaches this size. Cheap — a scan of a few hundred — and
/// only ever paid on insertion, which is the only thing that grows the map.
const SWEEP_AT: usize = 512;

/// The hard ceiling. Reached only if that many entries are all still live, at which point the
/// cache is cleared: unbounded growth in a process meant to run for weeks is worse than a cold
/// start, and a workload with this many live names in one TTL window is not one a cache helps.
const CAP: usize = 4096;

/// How long to wait before starting the next server. See [`Resolver::ask_all`].
const STAGGER: Duration = Duration::from_millis(150);

/// How long a name whose forwarded lookup failed is answered the old way before trying again.
const FORWARD_MEMO: Duration = Duration::from_secs(20);

/// The ceiling put on a forwarded record's TTL, for the same reason the A path caps its own: a
/// vigil that stops must not leave the machine holding a long-lived answer nobody can refresh.
const TTL_FORWARDED: u32 = 60;

/// One question to one server. A free function on purpose: [`Resolver::ask_all`] runs these on
/// detached threads, and a method borrowing `&self` could not be moved into one.
/// What one server said. **Three states, not two** — this distinction is the whole of a correct
/// negative cache.
///
/// The first version of the negative cache had only "some addresses" and "no addresses", so a lost
/// UDP packet and a real "there is no such name" were the same thing, and one dropped packet took a
/// name off the entire machine for twenty seconds. On a lossy line that is worse than the stall it
/// was added to fix. Two independent reviewers found it; it is fixed here by making the code able to
/// say which of the two happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// At least one address we are willing to use.
    Addresses(Vec<IpAddr>),
    /// The server answered and there is genuinely nothing here: NXDOMAIN, NODATA, or a name that
    /// only has IPv6. An authoritative no — worth remembering briefly, and worth **stopping the
    /// sweep** for: asking three more servers whether a name that does not exist still does not
    /// exist is four times the work for one answer, and Windows asks for names that do not exist
    /// constantly.
    Nothing,
    /// The server answered, and every address in it was a censor block page. Also "no addresses",
    /// but for the opposite reason — this is a line lying to us, so the *other* servers are exactly
    /// who to ask next. Kept apart from [`Reply::Nothing`] for that one difference.
    Filtered,
    /// No usable reply arrived: dropped, timed out, or unreadable. We learned nothing, and
    /// remembering "nothing" would be recording our own bad luck as a fact about the name.
    Silent,
}

/// Where a question can be sent.
///
/// One variant today, and that is the point: the enum lands before the transport that needs it, so
/// the step that adds DoH changes `ask_one`'s body and nothing else. `Clone` rather than `Copy`
/// deliberately — `Copy` compiles for a `SocketAddr` and would hand the breakage to the variant
/// that carries a path and a flag, which is exactly the work this refactor exists to do early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Upstream {
    /// Plain DNS over UDP. The odd-port entries are here, and so is anything on 53.
    Udp(SocketAddr),
    /// DNS over HTTPS, RFC 8484.
    ///
    /// **Addressed by `SocketAddr` and carrying no name field at all.** DoH needs HTTPS, HTTPS
    /// needs a name, a name needs DNS — so a variant that *could* hold a hostname is one that can
    /// deadlock the resolver on its own first query. The recursion is closed here by the type
    /// rather than by a rule somebody has to remember.
    Doh {
        addr: SocketAddr,
        path: &'static str,
        alpn: bool,
    },
}

impl core::fmt::Display for Upstream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Upstream::Udp(a) => write!(f, "{a}"),
            Upstream::Doh { addr, path, .. } => write!(f, "doh://{addr}{path}"),
        }
    }
}

/// `1.1.1.1` or `1.1.1.1:443` — never a hostname.
///
/// A name here would be the recursion the type above exists to prevent, so it is refused at the
/// flag rather than resolved and accepted.
pub fn parse_doh_endpoint(s: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 443));
    }
    Err(format!(
        "--doh needs an IP address, not {s:?}: a DoH server named by hostname would need DNS to \
         reach DNS"
    ))
}

/// What one upstream has been asked and what it said.
///
/// **Nothing branches on these.** Adaptive selection and auto-disable were rejected on 2026-09-07
/// with the measurement behind the refusal recorded in `docs/19-dns.md` §6: on this line loss is a
/// property of the *name* and not of the path, so a score would learn the censor's per-name policy
/// as server unreliability and demote the one upstream measured to survive interception. These
/// exist to be **read** — by a report, by a person — and by nothing else.
#[derive(Debug, Default)]
pub struct UpstreamCounts {
    /// Launched. Counted when the question goes out, not when an answer arrives.
    pub asked: AtomicUsize,
    pub answered: AtomicUsize,
    pub nothing: AtomicUsize,
    pub filtered: AtomicUsize,
    pub silent: AtomicUsize,
    /// Why a DoH upstream produced nothing. Every one of these is a [`Reply::Silent`] — a
    /// transport failure teaches nothing about the name — but a counter that cannot say *which*
    /// cannot be acted on. Nothing branches on them.
    pub doh_tls: AtomicUsize,
    pub doh_http: AtomicUsize,
    pub doh_timeout: AtomicUsize,
    pub doh_short: AtomicUsize,
    pub doh_alpn: AtomicUsize,
    pub doh_io: AtomicUsize,
}

/// Dispatch. The transport is chosen here and nowhere else.
fn ask_one(
    up: &Upstream,
    host: &str,
    timeout: Duration,
    id: u16,
    cfgs: &[Arc<rustls::ClientConfig>; 2],
    counts: Option<&UpstreamCounts>,
) -> Reply {
    match up {
        Upstream::Udp(a) => ask_one_udp(*a, host, timeout, id),
        Upstream::Doh { addr, path, alpn } => {
            ask_one_doh(*addr, path, *alpn, host, timeout, cfgs, counts)
        }
    }
}

/// One DoH question, mapped into the same four states plain DNS produces.
///
/// **No new [`Reply`] variant.** The four states, and the rule that only `Nothing` is
/// negative-cached, are the fix for the 2026-08-09 defect where a dropped packet and a real "no
/// such name" were the same thing and one lost datagram took a name off the machine for twenty
/// seconds. What a transport failure needs is *visibility*, and that is a named counter.
#[allow(clippy::too_many_arguments)]
fn ask_one_doh(
    addr: SocketAddr,
    path: &'static str,
    alpn: bool,
    host: &str,
    timeout: Duration,
    cfgs: &[Arc<rustls::ClientConfig>; 2],
    counts: Option<&UpstreamCounts>,
) -> Reply {
    let Ok(q) = dnsmsg::encode_query(host, 0) else {
        return Reply::Silent;
    };
    let ep = crate::doh::Endpoint {
        ip: addr.ip(),
        port: addr.port(),
        path,
    };
    let deadline = Instant::now() + timeout;
    let body = match crate::doh::query(&ep, &cfgs[alpn as usize], &q, deadline) {
        Ok(b) => b,
        Err(e) => {
            if let Some(c) = counts {
                // Exhaustive on purpose: a variant added later fails to compile until somebody
                // decides which counter it belongs to.
                let field = match e {
                    crate::doh::DohError::Timeout => &c.doh_timeout,
                    crate::doh::DohError::Io(_) => &c.doh_io,
                    crate::doh::DohError::Tls(_) => &c.doh_tls,
                    crate::doh::DohError::Alpn => &c.doh_alpn,
                    crate::doh::DohError::Http(_)
                    | crate::doh::DohError::ContentType(_)
                    | crate::doh::DohError::Chunked
                    | crate::doh::DohError::HeadTooLong
                    | crate::doh::DohError::LengthRequired
                    | crate::doh::DohError::TooLarge(_)
                    | crate::doh::DohError::Redirect
                    | crate::doh::DohError::Malformed(_) => &c.doh_http,
                    crate::doh::DohError::Short { .. } => &c.doh_short,
                };
                field.fetch_add(1, Ordering::Relaxed);
            }
            return Reply::Silent;
        }
    };
    // The id is 0 both ways: RFC 8484 §4.1 asks clients to send 0, and an HTTP cache may answer a
    // different question's body with the same 0.
    match dnsmsg::decode_answers(&body, 0) {
        Ok(v4s) => {
            let addrs: Vec<IpAddr> = v4s.into_iter().map(IpAddr::V4).collect();
            let empty = addrs.is_empty();
            match usable(addrs) {
                Some(a) => Reply::Addresses(a),
                None if empty => Reply::Nothing,
                None => Reply::Filtered,
            }
        }
        Err(dnsmsg::Error::NoAddress) => Reply::Nothing,
        // A malformed body is `Silent` and not a `continue`: the UDP arm re-reads up to four
        // datagrams because a spoof can arrive before the real answer, and there is no second
        // HTTP body to read.
        Err(_) => Reply::Silent,
    }
}

fn ask_one_udp(server: SocketAddr, host: &str, timeout: Duration, id: u16) -> Reply {
    let Ok(q) = dnsmsg::encode_query(host, id) else {
        return Reply::Silent;
    };
    let bind: &str = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(sock) = bind
        .parse::<SocketAddr>()
        .map_err(|_| ())
        .and_then(|a| UdpSocket::bind(a).map_err(|_| ()))
    else {
        return Reply::Silent;
    };
    if sock.set_read_timeout(Some(timeout)).is_err() || sock.send_to(&q, server).is_err() {
        return Reply::Silent;
    }

    let mut buf = [0u8; 1500];
    // Bounded, because on an intercepting network the wrong answers may keep coming.
    for _ in 0..4 {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            return Reply::Silent;
        };
        // **It has to come from the server we asked.** `recv_from` will hand over a datagram from
        // anybody who guesses the port, and an off-path forgery only has to arrive before the real
        // answer to win. Cheap to check and there is no reason not to; it matters more now that a
        // lookup keeps four of these sockets open at once.
        if from != server {
            continue;
        }
        match dnsmsg::decode_answers(&buf[..n], id) {
            Ok(v4s) => {
                let addrs: Vec<IpAddr> = v4s.into_iter().map(IpAddr::V4).collect();
                let empty = addrs.is_empty();
                return match usable(addrs) {
                    Some(a) => Reply::Addresses(a),
                    // No addresses at all: a real no.
                    None if empty => Reply::Nothing,
                    // It sent addresses and every one was a block page. Somebody is lying to us —
                    // the other servers are exactly who to ask next.
                    None => Reply::Filtered,
                };
            }
            // A well-formed answer carrying no A record: NXDOMAIN, NODATA, or a name that only has
            // IPv6. The server spoke and the answer is "nothing here" — the distinction this whole
            // enum exists for, and `dnsmsg` had it all along as its own error variant.
            Err(dnsmsg::Error::NoAddress) => return Reply::Nothing,
            // SERVFAIL / REFUSED / NOTIMP / FORMERR. The server answered *about itself*, not about
            // the name, so this is `Silent` and not `Nothing`: the sweep must go on to the next
            // upstream — which is the entire reason there are four of them — and nothing may be
            // written to the negative cache. On the wire this is byte-for-byte the shape of
            // NXDOMAIN, so it read as an authoritative no until `dnsmsg` started reading the rcode.
            Err(dnsmsg::Error::SoftFailure) => return Reply::Silent,
            // A response that is not ours — a spoof, or a straggler. Keep reading.
            Err(dnsmsg::Error::Malformed) => continue,
            Err(_) => return Reply::Silent,
        }
    }
    Reply::Silent
}

pub struct Resolver {
    upstreams: Vec<Upstream>,
    /// Parallel to `upstreams`, one for one. Read-only from the outside; see [`UpstreamCounts`]
    /// for why nothing may branch on them.
    counts: Vec<Arc<UpstreamCounts>>,
    /// `None` disables the fallback entirely, for callers who would rather fail than use a
    /// resolver they do not trust.
    allow_system: bool,
    timeout: Duration,
    ttl: Duration,
    /// How long a *failure* is remembered. Much shorter than a success: a name that could not be
    /// resolved is usually a name that is about to work, and caching that for five minutes would
    /// turn a blip into an outage.
    negative_ttl: Duration,
    /// Keyed by name. **An empty vector is a remembered failure**, not an absent entry — that is
    /// the negative cache, and without it every name with no usable A record cost a fresh sweep of
    /// every upstream, every single time it was asked. Windows asks for `wpad` a great deal.
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
    next_id: AtomicU16,
    /// Names whose forwarded lookup just failed, and when. See [`Resolver::forward`].
    forward_failed: Mutex<HashMap<String, Instant>>,
    /// Indexed by `alpn as usize`. Built in the constructor and **never at query time**: a
    /// warm-up handshake at construction would spend the budget of whatever asked first, and a
    /// config built per query would put a mutex-backed session cache on the hot path.
    doh_cfg: [Arc<rustls::ClientConfig>; 2],
}

impl core::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Resolver")
            .field("upstreams", &self.upstreams)
            .field("allow_system", &self.allow_system)
            .finish()
    }
}

impl Default for Resolver {
    /// **`default_upstreams()`, not `default_servers()`.**
    ///
    /// It was the latter until 2026-09-07, and for the hour after DoH was put at the head of
    /// `default_upstreams()` that flip reached nothing at all: every shipped binary builds its
    /// resolver here. The unit test was green throughout, because it asserted the *list* and not
    /// that the resolver uses it — caught by running the binary and reading its own counters, which
    /// showed four UDP upstreams and no DoH row.
    fn default() -> Self {
        Resolver::with_upstreams(default_upstreams(), true)
    }
}

/// The upstreams as they ship, in order. **DoH first since 2026-09-07.**
///
/// The order is a measured fact written as code, and the measurement is in `docs/19-dns.md` §5b:
/// five runs of `vigil-scan dns` on this line, DoH **10/10 in every one**, while `1.1.1.1:53`,
/// `9.9.9.9:53` and `8.8.8.8:53` all read `<no reply>` for every blocked name. Same operator, same
/// address, two transports — `:53` is dropped and `:443` is not. Before that, gate A: 96/96
/// SNI-less TLS handshakes and `discord.com` 8/8 over DoH against a control that spoke 8/8.
///
/// `8.8.8.8` was 8/8 in gate A too and is the documented second choice; it is **not** listed,
/// because a second DoH entry costs another stagger in the worst case and buys nothing measured.
///
/// The odd port stays, behind it. It is still 8/8 here and it is the fallback for the day a line
/// blocks `:443` to a resolver address — which no line has been measured to do, and which is
/// exactly why it is a fallback and not a deletion.
///
/// **The fallback needs no new code.** A `Reply::Silent` from the DoH arm falls through the empty
/// match arm in `ask_all` and the loop launches the next upstream; if the DoH worker is still
/// hanging, the stagger wait expires and the loop advances anyway. Worst case, every upstream dead:
/// `1500 + 150 × 4 = 2100 ms` before this change and **2250 ms** after it.
pub fn default_upstreams() -> Vec<Upstream> {
    let mut out = vec![Upstream::Doh {
        addr: SocketAddr::from(([1, 1, 1, 1], 443)),
        path: "/dns-query",
        alpn: true,
    }];
    out.extend(default_servers().into_iter().map(Upstream::Udp));
    out
}

impl Resolver {
    /// The address form, kept so that none of the existing call sites move.
    pub fn new(servers: Vec<SocketAddr>, allow_system: bool) -> Self {
        Resolver::with_upstreams(
            servers.into_iter().map(Upstream::Udp).collect(),
            allow_system,
        )
    }

    pub fn with_upstreams(upstreams: Vec<Upstream>, allow_system: bool) -> Self {
        let counts = upstreams
            .iter()
            .map(|_| Arc::new(UpstreamCounts::default()))
            .collect();
        Resolver {
            upstreams,
            counts,
            allow_system,
            // 3 s was too long to be useful. Windows' own resolver gives a server about a second
            // before it retries and then fails over to the secondary, so an answer that arrives at
            // three seconds arrives after the client has stopped listening — we pay the delay and
            // it buys nothing. Failing faster lets the client fail over deliberately instead.
            timeout: Duration::from_millis(1500),
            ttl: Duration::from_secs(300),
            negative_ttl: Duration::from_secs(20),
            cache: Mutex::new(HashMap::new()),
            next_id: AtomicU16::new(1),
            forward_failed: Mutex::new(HashMap::new()),
            doh_cfg: [crate::doh::tls_config(false), crate::doh::tls_config(true)],
        }
    }

    /// **Forward a query whose type this server cannot encode, and hand the answer back intact.**
    ///
    /// Pure over the transport, so every composition rule below is a Linux unit test. The order is
    /// the whole function: ask with id 0, validate against id 0, then restore the client's id and
    /// clamp the TTLs. Validating after restoring the id checks a message against an id it was
    /// never sent with.
    ///
    /// `None` on anything unexpected — the caller then answers exactly what it answers today.
    pub fn forward_with(
        query: &[u8],
        q: &dnsmsg::Question,
        max_ttl: u32,
        mut ask: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let mut upstream_query = query.to_vec();
        dnsmsg::set_id(&mut upstream_query, 0).ok()?;
        let mut answer = ask(&upstream_query)?;
        dnsmsg::rewrite_forwarded(&mut answer, 0, q.id, q, max_ttl).ok()?;
        Some(answer)
    }

    /// The same, over this resolver's **DoH** upstreams.
    ///
    /// DoH only, and that is not a preference: `encode_query` sends no OPT record, so a UDP answer
    /// is capped at 512 bytes with TC set — and forwarding a truncated answer as complete hands a
    /// browser half a SvcParams set, which is worse than forwarding nothing.
    ///
    /// A **fan-out with the same staggered start as `ask_all`**, never a loop: "ask each in turn,
    /// each with its own timeout" is the sequential sweep the 2026-08-09 rewrite removed, and this
    /// runs inside a worker holding one of the DNS server's in-flight slots.
    pub fn forward(&self, query: &[u8], q: &dnsmsg::Question) -> Option<Vec<u8>> {
        // A name that just failed is not retried for a while. What is remembered is *"answer this
        // type the way we did before this feature existed, for 20 s"* — which takes nothing off
        // the machine, unlike a remembered A-record silence, which takes the name off it. And it
        // is not the resolver scoring rejected in docs/19-dns.md §6: keyed by name, not upstream;
        // it changes no order; it expires.
        if let Ok(memo) = self.forward_failed.lock() {
            if let Some(at) = memo.get(&q.name) {
                if at.elapsed() < FORWARD_MEMO {
                    return None;
                }
            }
        }

        let doh: Vec<(usize, Upstream)> = self
            .upstreams
            .iter()
            .enumerate()
            .filter(|(_, u)| matches!(u, Upstream::Doh { .. }))
            .map(|(i, u)| (i, u.clone()))
            .collect();
        if doh.is_empty() {
            return None;
        }

        let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
        let deadline = Instant::now() + self.timeout + STAGGER * (doh.len() as u32);
        let mut launched = 0usize;
        let mut heard = 0usize;
        let mut out = None;

        for (i, up) in doh {
            let Upstream::Doh { addr, path, alpn } = up else {
                continue;
            };
            let cfg = self.doh_cfg[alpn as usize].clone();
            let timeout = self.timeout;
            let counts = self.counts.get(i).cloned();
            let tx = tx.clone();
            let sent = query.to_vec();
            let question = q.clone();
            match std::thread::Builder::new()
                .name("vigil-dns-forward".into())
                .spawn(move || {
                    let r = Resolver::forward_with(&sent, &question, TTL_FORWARDED, |bytes| {
                        let ep = crate::doh::Endpoint {
                            ip: addr.ip(),
                            port: addr.port(),
                            path,
                        };
                        match crate::doh::query(&ep, &cfg, bytes, Instant::now() + timeout) {
                            Ok(body) => Some(body),
                            Err(_) => {
                                if let Some(c) = counts.as_deref() {
                                    c.doh_timeout.fetch_add(1, Ordering::Relaxed);
                                }
                                None
                            }
                        }
                    });
                    let _ = tx.send(r);
                }) {
                Ok(_) => launched += 1,
                Err(_) => break,
            }
            let wait = STAGGER.min(deadline.saturating_duration_since(Instant::now()));
            if let Ok(reply) = rx.recv_timeout(wait) {
                heard += 1;
                if reply.is_some() {
                    out = reply;
                    break;
                }
            }
        }
        while out.is_none() && heard < launched {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok(reply) => {
                    heard += 1;
                    if reply.is_some() {
                        out = reply;
                    }
                }
                Err(_) => break,
            }
        }

        if out.is_none() {
            if let Ok(mut memo) = self.forward_failed.lock() {
                if memo.len() >= CAP {
                    memo.clear();
                }
                memo.insert(q.name.clone(), Instant::now());
            }
        }
        out
    }

    /// Replace the roots the DoH arm trusts.
    ///
    /// A method on the real type and not a second constructor, so the configuration under test is
    /// the one production builds — [`crate::doh::client_config`] is the single builder and the
    /// roots are its only parameter. Still no I/O: two configurations, built here.
    pub fn with_doh_roots(mut self, roots: rustls::RootCertStore) -> Self {
        self.doh_cfg = [
            crate::doh::client_config(roots.clone(), false),
            crate::doh::client_config(roots, true),
        ];
        self
    }

    /// Only the operating system, as before. Kept so the old behaviour is still reachable and
    /// can be compared against.
    pub fn system_only() -> Self {
        Resolver::new(Vec::new(), true)
    }

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let c = self.cache.lock().ok()?;
        let (addrs, at) = c.get(host)?;
        let ttl = if addrs.is_empty() {
            self.negative_ttl
        } else {
            self.ttl
        };
        (at.elapsed() < ttl).then(|| addrs.clone())
    }

    fn remember(&self, host: &str, addrs: &[IpAddr]) {
        if let Ok(mut c) = self.cache.lock() {
            // Nothing ever removed an entry. `cached` declines to *serve* a stale one but leaves it
            // in the map, so every name the machine has ever asked for stayed for the life of the
            // process — and since this resolver became the whole machine's, that is every name
            // every program asks. A reviewer measured 29 871 unique names in ten seconds taking RSS
            // from 2.0 MB to 7.9 MB, about 200 bytes each; realistic churn is around a megabyte a
            // day in a tray application meant to run for weeks.
            //
            // Swept here rather than on a timer: this is the only place the map grows, so it is the
            // only place it can grow *unboundedly*, and a timer would be a second thing to reason
            // about for a job that costs a scan of a few hundred entries at the moment of insertion.
            if c.len() >= SWEEP_AT {
                let ttl = self.ttl;
                let negative_ttl = self.negative_ttl;
                c.retain(|_, (a, at)| at.elapsed() < if a.is_empty() { negative_ttl } else { ttl });
                // Everything is live and there are still too many. Start again rather than grow
                // without limit: a resolver that has seen `CAP` live names in five minutes is
                // being used by something that does not benefit from a cache anyway, and the cost
                // of being wrong is one extra lookup each.
                if c.len() >= CAP {
                    c.clear();
                }
            }
            c.insert(host.to_string(), (addrs.to_vec(), Instant::now()));
        }
    }

    /// Ask every server, but **start them staggered** and take the first usable answer.
    ///
    /// This replaced a plain `for server in &self.servers` that waited for each one to time out
    /// before trying the next. With four servers and a three-second timeout, one name that nothing
    /// would answer cost twelve seconds — and because the DNS server handled one query at a time,
    /// every other lookup on the machine waited behind it. Measured: five such names did not finish
    /// in two minutes. That is what made Roblox, whose names are the blocked ones on this line and
    /// whose queries to the port-53 upstreams are dropped outright, take long enough to give up on.
    ///
    /// Staggered rather than all-at-once so the ordinary case still puts **one** query on the wire:
    /// the first server usually answers inside 150 ms, and the others wake, see that the answer has
    /// arrived, and exit without sending anything. Only a slow or silent first server actually costs
    /// extra traffic — which is exactly when the redundancy is worth having. The order in
    /// `default_servers` still means something: the odd-port resolver goes first because it is the
    /// one measured to survive interception here.
    /// **The only place a classification counter changes.**
    ///
    /// Deliberately separate from `ask_one`: a reply that arrives after the lookup has already
    /// returned is still an answer *from that upstream* and is counted here, while a count taken
    /// inside the transport would attribute it to whoever happened to be reading.
    fn tally(&self, i: usize, r: &Reply) {
        let Some(c) = self.counts.get(i) else {
            return;
        };
        let field = match r {
            Reply::Addresses(_) => &c.answered,
            Reply::Nothing => &c.nothing,
            Reply::Filtered => &c.filtered,
            Reply::Silent => &c.silent,
        };
        field.fetch_add(1, Ordering::Relaxed);
    }

    /// One line, for a report or a person. `77.88.8.8:1253 12/14 s2` — answered over asked, and
    /// how many said nothing at all.
    pub fn counts_line(&self) -> String {
        self.upstreams
            .iter()
            .zip(self.counts.iter())
            .map(|(up, c)| {
                format!(
                    "{up} {}/{} s{}",
                    c.answered.load(Ordering::Relaxed),
                    c.asked.load(Ordering::Relaxed),
                    c.silent.load(Ordering::Relaxed)
                )
            })
            .collect::<Vec<_>>()
            .join("  ")
    }

    /// The upstreams, in the order they are asked. For a report that has to name them.
    pub fn upstreams(&self) -> &[Upstream] {
        &self.upstreams
    }

    /// Asked, answered, nothing, filtered, silent — for tests and for a report.
    pub fn counts_of(&self, i: usize) -> (usize, usize, usize, usize, usize) {
        match self.counts.get(i) {
            Some(c) => (
                c.asked.load(Ordering::Relaxed),
                c.answered.load(Ordering::Relaxed),
                c.nothing.load(Ordering::Relaxed),
                c.filtered.load(Ordering::Relaxed),
                c.silent.load(Ordering::Relaxed),
            ),
            None => (0, 0, 0, 0, 0),
        }
    }

    fn ask_all(&self, host: &str) -> Reply {
        let n = self.upstreams.len();
        if n == 0 {
            return Reply::Silent;
        }
        let (tx, rx) = mpsc::channel::<(usize, Reply)>();
        let deadline = Instant::now() + self.timeout + STAGGER * (n as u32);
        let mut launched = 0usize;
        let mut heard = 0usize;
        // Did anybody answer with nothing but block pages? That is not an authoritative no — it is a
        // line lying to us — so it does not stop the sweep and it is not worth remembering.
        let mut filtered = false;

        for (i, up) in self.upstreams.iter().enumerate() {
            // **Launch lazily.** The threads used to all be spawned at once, each sleeping until its
            // turn — so every lookup cost one thread per server whether or not the later ones were
            // ever needed. A reviewer measured the result: a 400-query burst peaked at 642 live
            // threads, because the 128-query cap is really a 128 × (1 + servers) cap.
            //
            // Started one at a time instead, with a `STAGGER` wait between.
            //
            // Measured, and the honest version is narrower than the obvious claim. A *lone* lookup
            // spawns one thread and returns: the first server answers in about 80 ms on this line,
            // inside the 150 ms stagger, so the rest are never born. Under a **burst** that stops
            // being true — 128 concurrent queries do not come back inside 150 ms, so the second
            // server starts for nearly all of them. Peak live threads for a 400-query burst went
            // from 642 to 265: about two per query rather than five, not one. The remaining lever is
            // `IN_FLIGHT` itself, not the stagger.
            //
            // Every server still gets the full `timeout`. An earlier attempt ran the first server on
            // the calling thread to spawn nothing at all, and that quietly cut its budget to one
            // stagger — giving up at 150 ms on the one resolver measured to survive interception
            // here. Saving a thread is not worth abandoning the answer we most want.
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let tx = tx.clone();
            let host_owned = host.to_string();
            let timeout = self.timeout;
            let for_thread = up.clone();
            let cfgs = self.doh_cfg.clone();
            // Into the thread, so the DoH failure kinds are recorded on the path that actually
            // runs and not only on the spawn-failure fallback below.
            let counts = self.counts.get(i).cloned();
            // Counted when the question goes out, not when an answer arrives: an upstream that was
            // asked and said nothing has to be distinguishable from one that was never reached.
            self.counts[i].asked.fetch_add(1, Ordering::Relaxed);
            match std::thread::Builder::new()
                .name("vigil-dns-upstream".into())
                .spawn(move || {
                    let _ = tx.send((
                        i,
                        ask_one(
                            &for_thread,
                            &host_owned,
                            timeout,
                            id,
                            &cfgs,
                            counts.as_deref(),
                        ),
                    ));
                }) {
                Ok(_) => launched += 1,
                // No thread to be had. Ask here instead of losing the server entirely.
                //
                // This arm never reaches either receive loop below, so it tallies its own reply or
                // the answer is uncounted.
                Err(_) => {
                    let reply = ask_one(
                        up,
                        host,
                        self.timeout,
                        id,
                        &self.doh_cfg,
                        self.counts.get(i).map(|c| c.as_ref()),
                    );
                    self.tally(i, &reply);
                    match reply {
                        Reply::Addresses(addrs) => return Reply::Addresses(addrs),
                        // An authoritative no ends it: see `Reply::Nothing`.
                        Reply::Nothing => return Reply::Nothing,
                        Reply::Filtered | Reply::Silent => {}
                    }
                }
            }

            // Give whatever is running a stagger's worth of time before starting the next one.
            let wait = STAGGER.min(deadline.saturating_duration_since(Instant::now()));
            if let Ok((from, reply)) = rx.recv_timeout(wait) {
                heard += 1;
                self.tally(from, &reply);
                match reply {
                    Reply::Addresses(addrs) => return Reply::Addresses(addrs),
                    Reply::Nothing => return Reply::Nothing,
                    Reply::Filtered => filtered = true,
                    Reply::Silent => {}
                }
            }
        }

        // Everything that could be started has been. Wait out the rest, bounded by one timeout plus
        // the stagger — never by the sum of them, which is what the sequential sweep used to cost.
        while heard < launched {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok((from, reply)) => {
                    self.tally(from, &reply);
                    match reply {
                        Reply::Addresses(addrs) => return Reply::Addresses(addrs),
                        Reply::Nothing => return Reply::Nothing,
                        Reply::Filtered => {
                            filtered = true;
                            heard += 1;
                        }
                        Reply::Silent => heard += 1,
                    }
                }
                Err(_) => break,
            }
        }

        if filtered {
            Reply::Filtered
        } else {
            Reply::Silent
        }
    }

    fn system(&self, host: &str) -> Option<Vec<IpAddr>> {
        let addrs: Vec<IpAddr> = (host, 0u16)
            .to_socket_addrs()
            .ok()?
            .map(|s| s.ip())
            .collect();
        usable(addrs)
    }

    /// Resolve `host` to socket addresses on `port`.
    ///
    /// An address literal is returned as itself: asking a resolver about `162.159.138.232`
    /// would be pointless, and on some systems it is also slow.
    pub fn resolve(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![SocketAddr::new(ip, port)];
        }
        let addrs = self.lookup(host);
        addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }

    /// Resolve **without ever asking the operating system**, for the DNS server.
    ///
    /// The system fallback is a reasonable last resort for the proxy. For the DNS server it is a
    /// loop and, since queries got their own threads, an exponential one: when vigil *is* the
    /// machine's resolver, `system()` calls `to_socket_addrs`, the OS asks 127.0.0.1:53, that is us,
    /// and each self-query spawns another worker that fails upstream and asks again. Serial handling
    /// used to hide this — the inner query simply sat unread until the outer one timed out — so
    /// threading the server turned a self-limiting mistake into a fork bomb. Found by an adversarial
    /// reviewer, who proved it against the real types.
    ///
    /// It is not a loss. When vigil serves DNS the operating system's resolver is either vigil
    /// itself or the ISP's — and the ISP's is the thing this project exists because of.
    pub fn resolve_no_system(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![SocketAddr::new(ip, port)];
        }
        self.lookup_inner(host, false)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }

    fn lookup(&self, host: &str) -> Vec<IpAddr> {
        self.lookup_inner(host, self.allow_system)
    }

    fn lookup_inner(&self, host: &str, allow_system: bool) -> Vec<IpAddr> {
        if let Some(hit) = self.cached(host) {
            return hit;
        }
        let heard = self.ask_all(host);
        if let Reply::Addresses(addrs) = heard {
            self.remember(host, &addrs);
            return addrs;
        }
        if allow_system {
            if let Some(addrs) = self.system(host) {
                self.remember(host, &addrs);
                return addrs;
            }
        }
        // Remember the failure — **but only when somebody actually said there was nothing there.**
        //
        // Caching the negative is what stops a dead name sweeping every upstream on every ask, and
        // Windows asks for `wpad` (NXDOMAIN here) constantly. Caching *silence* is a different thing
        // entirely: it records one lost packet as a fact about the name and takes it off the whole
        // machine for twenty seconds. The first version of this did not tell the two apart, and on a
        // lossy line that is worse than the stall it was written to fix.
        if heard == Reply::Nothing {
            self.remember(host, &[]);
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // ---------------------------------------------------------------- block pages

    /// The address that broke the line on 2026-08-04.
    #[test]
    fn the_turk_telekom_block_page_is_recognised() {
        assert!(is_block_page(&v4(195, 175, 254, 2)));
    }

    #[test]
    fn documented_censor_answers_are_recognised() {
        // another provider another provider answered 127.0.0.1 for twitter.com (OONI, 2023).
        assert!(is_block_page(&v4(127, 0, 0, 1)));
        assert!(is_block_page(&v4(0, 0, 0, 0)));
    }

    #[test]
    fn real_addresses_are_not_block_pages() {
        for a in [
            v4(162, 159, 138, 232),
            v4(104, 20, 23, 154),
            v4(185, 159, 159, 140),
            v4(1, 1, 1, 1),
        ] {
            assert!(!is_block_page(&a), "{a} is a real address");
        }
    }

    /// A v6 answer is never matched against the v4 list, which would be a type confusion
    /// waiting to reject something legitimate.
    #[test]
    fn ipv6_is_never_a_block_page() {
        assert!(!is_block_page(&"::1".parse().unwrap()));
        assert!(!is_block_page(&"2606:4700::1".parse().unwrap()));
    }

    // -------------------------------------------------------------------- usable

    #[test]
    fn a_censor_address_is_dropped_from_a_mixed_answer() {
        let got = usable(vec![v4(195, 175, 254, 2), v4(162, 159, 138, 232)]);
        assert_eq!(got, Some(vec![v4(162, 159, 138, 232)]));
    }

    /// "Only the block page" must read as *no answer*, so the caller tries another resolver
    /// rather than reporting the host unreachable — or worse, connecting to it.
    #[test]
    fn an_answer_that_is_only_a_block_page_is_no_answer() {
        assert_eq!(usable(vec![v4(195, 175, 254, 2)]), None);
        assert_eq!(usable(vec![]), None);
    }

    #[test]
    fn a_clean_answer_survives_intact() {
        let a = vec![v4(162, 159, 138, 232), v4(162, 159, 135, 232)];
        assert_eq!(usable(a.clone()), Some(a));
    }

    // ------------------------------------------------------------------- servers

    /// The odd port must be tried first: it is the only one measured to survive the
    /// interception that motivated this module.
    #[test]
    fn the_interception_resistant_resolver_is_asked_first() {
        let s = default_servers();
        assert!(!s.is_empty());
        assert_eq!(s[0].port(), 1253, "port 53 first would defeat the purpose");
        assert!(
            s.iter().any(|a| a.port() == 53),
            "port 53 resolvers are still worth asking when nothing is intercepting"
        );
    }

    // ------------------------------------------------------------------ resolving

    /// An address literal must not become a DNS query.
    #[test]
    fn an_address_literal_resolves_to_itself_without_asking_anyone() {
        // No servers and no system fallback: if this tried to look anything up it would fail.
        let r = Resolver::new(Vec::new(), false);
        assert_eq!(
            r.resolve("162.159.138.232", 443),
            vec!["162.159.138.232:443".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            r.resolve("::1", 443),
            vec!["[::1]:443".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn a_resolver_with_nowhere_to_ask_returns_nothing_rather_than_hanging() {
        let r = Resolver::new(Vec::new(), false);
        assert!(r.resolve("discord.com", 443).is_empty());
    }

    /// The cache must not grow without limit.
    ///
    /// It had no eviction at all: `cached` declined to serve a stale entry and left it in the map,
    /// so every name the machine ever asked for stayed for the life of the process. A reviewer
    /// measured 29 871 names in ten seconds taking RSS from 2.0 MB to 7.9 MB.
    #[test]
    fn expired_entries_are_swept_rather_than_kept_forever() {
        let mut r = Resolver::new(Vec::new(), false);
        r.ttl = Duration::from_millis(30);
        r.negative_ttl = Duration::from_millis(30);

        // Fill past the sweep threshold with entries that are about to expire.
        for i in 0..SWEEP_AT {
            r.remember(&format!("old{i}.example"), &[v4(1, 1, 1, 1)]);
        }
        assert!(r.cache.lock().unwrap().len() >= SWEEP_AT);

        std::thread::sleep(Duration::from_millis(60));
        // One more insertion is what triggers the sweep — deliberately, because insertion is the
        // only thing that grows the map.
        r.remember("fresh.example", &[v4(2, 2, 2, 2)]);

        let n = r.cache.lock().unwrap().len();
        assert_eq!(
            n, 1,
            "the sweep should have left only the entry just inserted, and left {n}"
        );
        assert_eq!(r.cached("fresh.example"), Some(vec![v4(2, 2, 2, 2)]));
    }

    /// And when everything in it is live, it is capped rather than allowed to grow.
    #[test]
    fn a_cache_full_of_live_entries_is_capped() {
        let r = Resolver::new(Vec::new(), false);
        // Default TTLs, so nothing expires during the test: the sweep can free nothing and the cap
        // is the only thing standing between this and unbounded growth.
        for i in 0..(CAP + 64) {
            r.remember(&format!("live{i}.example"), &[v4(1, 1, 1, 1)]);
        }
        let n = r.cache.lock().unwrap().len();
        assert!(
            n <= CAP,
            "the cache grew to {n} with every entry live; the cap is {CAP}"
        );
    }

    /// A stub upstream that answers every question with **NOERROR and no records** — an
    /// authoritative "there is no such address here", which is what NXDOMAIN and NODATA both look
    /// like to this resolver.
    fn stub_saying_nothing() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
        let addr = sock.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(q) = dnsmsg::parse_question(&buf[..n]) else {
                    continue;
                };
                if let Ok(r) = dnsmsg::encode_response(&buf[..n], &q, &[], 30, 0) {
                    let _ = sock.send_to(&r, from);
                }
            }
        });
        addr
    }

    /// An authoritative no is worth remembering: it is what stops `wpad` — NXDOMAIN on this line and
    /// asked for constantly by Windows — sweeping every upstream on every single ask.
    #[test]
    fn an_authoritative_no_is_remembered() {
        let mut r = Resolver::new(vec![stub_saying_nothing()], false);
        r.timeout = Duration::from_millis(500);

        assert!(r.lookup("wpad.example").is_empty());
        assert_eq!(
            r.cached("wpad.example"),
            Some(Vec::new()),
            "a server that said there is nothing here must be believed, briefly"
        );
    }

    /// The same, but it waits first — the only way to make one upstream's reply land *after* a
    /// later upstream has been launched and answered, which is the timeline a per-upstream counter
    /// has to get right.
    fn stub_answering_after(delay: Duration, addr: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
        let at = sock.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(q) = dnsmsg::parse_question(&buf[..n]) else {
                    continue;
                };
                std::thread::sleep(delay);
                if let Ok(r) = dnsmsg::encode_response(&buf[..n], &q, &[addr], 30, 0) {
                    let _ = sock.send_to(&r, from);
                }
            }
        });
        at
    }

    // ---------------------------------------------------------------- DoH, over real TLS

    /// The fixture root, as the only root a test client trusts.
    ///
    /// Through [`crate::doh::client_config`] and never assembled here: a test that builds its own
    /// configuration proves something about a configuration nothing ships. The roots are the one
    /// parameter, which is exactly why that function takes them.
    fn fixture_roots() -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls_pki_types::CertificateDer::from(
                include_bytes!("../tests/data/doh-stub-root.der").to_vec(),
            ))
            .expect("the fixture root parses");
        roots
    }

    const LEAF_IP: &[u8] = include_bytes!("../tests/data/doh-stub-leaf-ip.der");
    const LEAF_NOIP: &[u8] = include_bytes!("../tests/data/doh-stub-leaf-noip.der");

    /// A loopback DoH server. One thread per accepted connection, so a stub cannot serialise the
    /// clients it is meant to be answering in parallel.
    ///
    /// The handler is given the request **body** — the DNS query as it arrived on the wire — and
    /// returns the whole HTTP response. That is what makes "what id did the client send" and "what
    /// does the client do when the id comes back as something else" testable at all.
    fn tls_stub(
        leaf: &'static [u8],
        alpn: Vec<Vec<u8>>,
        handler: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> SocketAddr {
        let cert = rustls_pki_types::CertificateDer::from(leaf.to_vec());
        let key = rustls_pki_types::PrivateKeyDer::try_from(
            include_bytes!("../tests/data/doh-stub-leaf.privkey.der").to_vec(),
        )
        .expect("the fixture key parses");
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("the fixture certificate and key agree");
        cfg.alpn_protocols = alpn;
        let cfg = Arc::new(cfg);

        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let at = l.local_addr().expect("addr");
        let handler = Arc::new(handler);
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut sock) = stream else { break };
                let cfg = Arc::clone(&cfg);
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    let Ok(mut conn) = rustls::ServerConnection::new(cfg) else {
                        return;
                    };
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
                    if conn.complete_io(&mut sock).is_err() {
                        return;
                    }
                    let mut req = Vec::new();
                    // Read until the head is complete and then the promised body.
                    loop {
                        if conn.complete_io(&mut sock).is_err() {
                            return;
                        }
                        let mut chunk = [0u8; 4096];
                        match std::io::Read::read(&mut conn.reader(), &mut chunk) {
                            Ok(0) => break,
                            Ok(n) => req.extend_from_slice(&chunk[..n]),
                            Err(_) => break,
                        }
                        if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                            let want = String::from_utf8_lossy(&req[..end])
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("Content-Length: ")
                                        .and_then(|v| v.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if req.len() >= end + 4 + want {
                                let body = req[end + 4..end + 4 + want].to_vec();
                                let out = handler(&body);
                                let _ = std::io::Write::write_all(&mut conn.writer(), &out);
                                let _ = conn.complete_io(&mut sock);
                                conn.send_close_notify();
                                let _ = conn.complete_io(&mut sock);
                                return;
                            }
                        }
                    }
                });
            }
        });
        at
    }

    /// Wrap a DNS message in the HTTP response a DoH server would send.
    fn dns_response(body: Vec<u8>) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(&body);
        out
    }

    fn doh_resolver(at: SocketAddr, alpn: bool) -> Resolver {
        let mut r = Resolver::with_upstreams(
            vec![Upstream::Doh {
                addr: at,
                path: "/dns-query",
                alpn,
            }],
            false,
        )
        .with_doh_roots(fixture_roots());
        r.timeout = Duration::from_millis(1500);
        r
    }

    /// **Every DoH answer shape maps to the same four states plain DNS produces — and only one of
    /// them is remembered as a negative.**
    ///
    /// The cache assertion is the point. Writing a negative entry for a censored or a failed
    /// answer is the 2026-08-09 class of defect: a dropped packet and a real "no such name" were
    /// the same thing, and one lost datagram took a name off the machine for twenty seconds.
    #[test]
    fn a_doh_answer_maps_to_the_four_states_and_only_a_real_no_is_remembered() {
        // NOERROR with an address.
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], |q| {
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(
                dnsmsg::encode_response(q, &question, &[Ipv4Addr::new(203, 0, 113, 7)], 60, 0)
                    .expect("encode"),
            )
        });
        let r = doh_resolver(at, true);
        assert_eq!(
            r.lookup("ok.test"),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
        );
        assert_eq!(r.counts_of(0).1, 1, "answered");
        assert!(r.cached("ok.test").is_some());

        // NXDOMAIN — an authoritative no, and the one thing worth remembering.
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], |q| {
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(dnsmsg::encode_response(q, &question, &[], 60, 3).expect("encode"))
        });
        let r = doh_resolver(at, true);
        assert!(r.lookup("gone.test").is_empty());
        assert_eq!(
            r.cached("gone.test"),
            Some(vec![]),
            "an authoritative no is remembered, briefly"
        );

        // SERVFAIL — the server spoke about itself, not about the name.
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], |q| {
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(
                dnsmsg::encode_response(q, &question, &[], 60, dnsmsg::RCODE_SERVFAIL)
                    .expect("encode"),
            )
        });
        let r = doh_resolver(at, true);
        assert!(r.lookup("sf.test").is_empty());
        assert_eq!(r.cached("sf.test"), None, "SERVFAIL must not be remembered");

        // Nothing but a block page: somebody is lying, and it is not a negative either.
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], |q| {
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(
                dnsmsg::encode_response(q, &question, &[Ipv4Addr::new(195, 175, 254, 2)], 60, 0)
                    .expect("encode"),
            )
        });
        let r = doh_resolver(at, true);
        assert!(r.lookup("lied.test").is_empty());
        assert_eq!(
            r.cached("lied.test"),
            None,
            "a censored answer is not an authoritative no"
        );
    }

    /// An HTTP failure is silence, counted by kind, and never remembered.
    #[test]
    fn a_doh_http_failure_is_silence_with_a_name() {
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], |_| {
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n".to_vec()
        });
        let r = doh_resolver(at, true);
        assert!(r.lookup("five.test").is_empty());
        assert_eq!(r.cached("five.test"), None);
        assert_eq!(r.counts_of(0), (1, 0, 0, 0, 1), "asked once, silent once");
        assert_eq!(
            r.counts_of(0).1 + r.counts_of(0).2,
            0,
            "nothing was learned about the name"
        );
        assert!(r.counts_line().contains("0/1 s1"), "{}", r.counts_line());
    }

    /// **A redirect is never followed, and the proof is that the server is asked exactly once.**
    ///
    /// A client that "followed" by re-requesting the same server with a new path would leave the
    /// verdict unchanged; only the request count catches it.
    #[test]
    fn a_redirect_is_refused_and_never_followed() {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], move |_| {
            counter.fetch_add(1, Ordering::Relaxed);
            b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/dns-query\r\nContent-Length: 0\r\n\r\n".to_vec()
        });
        let r = doh_resolver(at, true);
        assert!(r.lookup("moved.test").is_empty());
        assert_eq!(r.cached("moved.test"), None);
        assert_eq!(
            asked.load(Ordering::Relaxed),
            1,
            "asked once and never again — a redirect is how a middlebox steers a query"
        );
    }

    /// **The client sends id 0, and accepts id 0 back whatever it asked.**
    ///
    /// RFC 8484 §4.1: the HTTP exchange already pairs answer with question, so a varying id buys
    /// nothing and defeats caching. A stub that *echoed* the id would be green for any id at all,
    /// which is why this one asserts the bytes and then answers with a fixed 0.
    #[test]
    fn the_doh_query_carries_id_zero_and_a_zero_answer_is_accepted() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], move |q| {
            if let Ok(mut g) = record.lock() {
                g.push(q[..2].to_vec());
            }
            let question = dnsmsg::parse_question(q).expect("question");
            // Answered with id 0 regardless of what arrived — what an HTTP cache does.
            let mut body =
                dnsmsg::encode_response(q, &question, &[Ipv4Addr::new(203, 0, 113, 8)], 60, 0)
                    .expect("encode");
            body[0] = 0;
            body[1] = 0;
            dns_response(body)
        });
        let r = doh_resolver(at, true);
        assert_eq!(
            r.lookup("zero.test"),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))]
        );
        assert_eq!(
            seen.lock().expect("lock").as_slice(),
            &[vec![0u8, 0]],
            "RFC 8484 asks for a zero id in every request"
        );
    }

    /// **One slow DoH answer does not hold up the others.**
    ///
    /// The 2026-08-09 regression in its new shape: twenty names took 1.79 s serially and 0.13 s
    /// once the sweep ran in parallel. A DoH upstream opens a TCP connection and a TLS handshake
    /// per query, so it is exactly the transport that would quietly serialise if a lock or a
    /// shared connection crept in. The stub sleeps 100 ms per request and answers twenty at once.
    #[test]
    fn twenty_doh_queries_do_not_serialise() {
        let at = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], |q| {
            std::thread::sleep(Duration::from_millis(100));
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(
                dnsmsg::encode_response(q, &question, &[Ipv4Addr::new(203, 0, 113, 20)], 60, 0)
                    .expect("encode"),
            )
        });
        let r = Arc::new(doh_resolver(at, true));
        let started = Instant::now();
        let mut hands = Vec::new();
        for i in 0..20 {
            let r = Arc::clone(&r);
            hands.push(std::thread::spawn(move || {
                !r.lookup(&format!("many{i}.test")).is_empty()
            }));
        }
        let answered = hands
            .into_iter()
            .filter(|_| true)
            .map(|h| h.join().unwrap_or(false))
            .filter(|ok| *ok)
            .count();
        let took = started.elapsed();
        assert_eq!(answered, 20, "every one of them must be answered");
        assert!(
            took > Duration::from_millis(100),
            "the stub sleeps 100 ms; {took:?} means it never ran"
        );
        assert!(
            took < Duration::from_millis(1500),
            "serial would be about two seconds: {took:?}"
        );
    }

    /// **A resolver that has retired HTTP/1.1 is a resolver finding, not a line finding.**
    ///
    /// Measured live on 2026-09-07: `9.9.9.9` completes the handshake and answers every query with
    /// HTTP 505. This is the unit-test shape of the same thing — the server has protocols
    /// configured and none of them is ours, so it sends the alert. The stub must configure some,
    /// because a server with none simply ignores the extension.
    #[test]
    fn a_server_that_refuses_our_protocol_is_counted_as_alpn() {
        let at = tls_stub(LEAF_IP, vec![b"h2".to_vec()], |q| {
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(
                dnsmsg::encode_response(q, &question, &[Ipv4Addr::new(203, 0, 113, 5)], 60, 0)
                    .expect("encode"),
            )
        });
        let r = doh_resolver(at, true);
        assert!(r.lookup("alpn.test").is_empty());
        assert_eq!(
            r.cached("alpn.test"),
            None,
            "a protocol refusal says nothing about the name"
        );
        assert_eq!(
            r.counts_of(0),
            (1, 0, 0, 0, 1),
            "asked once, and silence is what the resolver learned"
        );
    }

    /// **A certificate with no address in it is refused, and the refusal is counted as TLS.**
    ///
    /// This is trap one's own premise: an IP literal validates against an iPAddress SAN, and a
    /// name-only certificate must not be accepted just because the connection reached a server.
    #[test]
    fn a_certificate_without_an_address_is_refused() {
        let good = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], |q| {
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(
                dnsmsg::encode_response(q, &question, &[Ipv4Addr::new(203, 0, 113, 9)], 60, 0)
                    .expect("encode"),
            )
        });
        let r = doh_resolver(good, true);
        assert!(
            !r.lookup("good.test").is_empty(),
            "the IP-SAN leaf validates"
        );

        let bad = tls_stub(LEAF_NOIP, vec![b"http/1.1".to_vec()], |q| {
            let question = dnsmsg::parse_question(q).expect("question");
            dns_response(
                dnsmsg::encode_response(q, &question, &[Ipv4Addr::new(203, 0, 113, 9)], 60, 0)
                    .expect("encode"),
            )
        });
        let r = doh_resolver(bad, true);
        assert!(
            r.lookup("bad.test").is_empty(),
            "no address in the certificate"
        );
        assert_eq!(r.cached("bad.test"), None);
        assert_eq!(
            r.counts_of(0),
            (1, 0, 0, 0, 1),
            "a refused certificate is silence about the name"
        );
    }

    /// **The composition rules of forwarding, without a socket.**
    ///
    /// The upstream is asked with id 0 and the client gets its own id back; anything the upstream
    /// says that is not an answer to this question produces `None`, and the caller then answers
    /// exactly what it answered before the feature existed.
    #[test]
    fn forwarding_asks_with_id_zero_and_answers_with_the_clients_own() {
        let client_query =
            dnsmsg::encode_query_type("cloudflare.com", 0x1234, dnsmsg::TYPE_HTTPS).expect("q");
        let q = dnsmsg::parse_question(&client_query).expect("question");
        assert_eq!(q.id, 0x1234);

        // What the upstream is handed, recorded.
        let seen = Mutex::new(Vec::new());
        let upstream_answer = {
            let mut a = client_query.clone();
            a[2] |= 0x80; // QR
            a[0..2].copy_from_slice(&[0, 0]); // answered with id 0
            a
        };
        let out = Resolver::forward_with(&client_query, &q, 60, |bytes| {
            seen.lock().expect("lock").push(bytes.to_vec());
            Some(upstream_answer.clone())
        })
        .expect("forwards");
        assert_eq!(
            &seen.lock().expect("lock")[0][..2],
            &[0, 0],
            "the upstream is asked with id 0"
        );
        assert_eq!(&out[..2], &[0x12, 0x34], "the client gets its own id back");

        // The closure is called once, and only once.
        assert_eq!(seen.lock().expect("lock").len(), 1);

        // Nothing back, nothing forwarded.
        assert!(Resolver::forward_with(&client_query, &q, 60, |_| None).is_none());

        // An answer with the wrong id is not ours. This is the arm that catches "validated after
        // restoring the client's id" — under that mistake this would be accepted.
        let mut wrong = upstream_answer.clone();
        wrong[0..2].copy_from_slice(&[0x99, 0x99]);
        assert!(Resolver::forward_with(&client_query, &q, 60, |_| Some(wrong.clone())).is_none());

        // A truncated answer is a partial SvcParams set.
        let mut truncated = upstream_answer.clone();
        truncated[2] |= 0x02;
        assert!(
            Resolver::forward_with(&client_query, &q, 60, |_| Some(truncated.clone())).is_none()
        );
    }

    /// **Nothing dials at construction.**
    ///
    /// A warm-up handshake in the constructor would spend the budget of whoever asked first, and
    /// on a line where the endpoint is dark it would spend it on every start. The two TLS
    /// configurations are built here; no socket is.
    #[test]
    fn building_a_doh_resolver_opens_no_connection() {
        let hole = tcp_hole();
        let started = Instant::now();
        let r = Resolver::with_upstreams(
            vec![Upstream::Doh {
                addr: hole,
                path: "/dns-query",
                alpn: true,
            }],
            false,
        );
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "construction dialled something: {:?}",
            started.elapsed()
        );
        assert_eq!(
            r.counts_of(0),
            (0, 0, 0, 0, 0),
            "nothing has been asked yet"
        );
    }

    /// **A worker does not outlive its budget.**
    ///
    /// The real resource risk of putting TCP+TLS behind `127.0.0.1:53`: eight names against a dark
    /// endpoint must leave eight threads finished, not eight threads waiting. Counted from
    /// `/proc`, so it is an observation and not an argument.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_dark_doh_endpoint_leaves_no_threads_behind() {
        /// **Our workers, by name — not every thread in the process.**
        ///
        /// Counting `/proc/self/task` wholesale made this test fail whenever it ran beside the TLS
        /// stub tests, whose per-connection threads are alive at the same moment. That is a defect
        /// in the measurement, and loosening the bound would have hidden it. Linux carries each
        /// thread's name in `comm` (truncated to fifteen bytes), and `ask_all` names its workers —
        /// so this counts exactly the thing the test is about and nothing else.
        fn dns_workers() -> usize {
            std::fs::read_dir("/proc/self/task")
                .map(|d| {
                    d.filter_map(Result::ok)
                        .filter(|e| {
                            std::fs::read_to_string(e.path().join("comm"))
                                .map(|c| c.trim().starts_with("vigil-dns-up"))
                                .unwrap_or(false)
                        })
                        .count()
                })
                .unwrap_or(0)
        }
        let hole = tcp_hole();
        let mut r = Resolver::with_upstreams(
            vec![Upstream::Doh {
                addr: hole,
                path: "/dns-query",
                alpn: true,
            }],
            false,
        );
        r.timeout = Duration::from_millis(300);
        // **A positive arm, or the negative one proves nothing.**
        //
        // Without this the test asserted zero and got zero for the wrong reason: `lookup` returns
        // after its own deadline, by which time every worker has already exited, so the counter
        // never saw one. Asserting "none is left" is only meaningful once "some existed" is
        // asserted too — the same shape as the SNI test in `doh.rs`.
        let peak = Arc::new(AtomicUsize::new(0));
        let sampler_peak = Arc::clone(&peak);
        let sampler = std::thread::spawn(move || {
            for _ in 0..60 {
                sampler_peak.fetch_max(dns_workers(), Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        for i in 0..8 {
            let _ = r.lookup(&format!("dark{i}.test"));
        }
        let _ = sampler.join();
        assert!(
            peak.load(Ordering::Relaxed) > 0,
            "the counter never saw a worker at all, so the assertion below measures nothing"
        );

        std::thread::sleep(Duration::from_millis(900));
        assert_eq!(
            dns_workers(),
            0,
            "a DoH worker outlived its 300 ms budget by 900 ms"
        );
        // And every one of them was counted as asked and as silent.
        assert_eq!(r.counts_of(0).0, 8);
        assert_eq!(
            r.counts_of(0).4,
            8,
            "a dark endpoint is silence, not an answer"
        );
        assert!(r.counts_of(0).1 == 0, "nothing answered");
    }

    /// A listener that accepts and holds and never writes. It must **accept**: a listener that
    /// never calls `accept` fills its backlog and then refuses instantly, which turns a timeout
    /// test into a connection-refused test that passes for the wrong reason.
    fn tcp_hole() -> SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let at = l.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in l.incoming() {
                match stream {
                    Ok(s) => held.push(s),
                    Err(_) => break,
                }
            }
        });
        at
    }

    /// **The resolver every binary builds is the one the list describes.**
    ///
    /// The gate that was missing. `default_upstreams()` was flipped to DoH-first and
    /// `Resolver::default()` still called `default_servers()`, so nothing shipped changed and the
    /// literal test below stayed green. A list nobody uses is a list that can say anything.
    #[test]
    fn the_default_resolver_uses_the_default_upstreams() {
        assert_eq!(
            Resolver::default().upstreams(),
            default_upstreams().as_slice(),
            "the shipped resolver must be built from the measured list, not from a second one"
        );
    }

    /// **The shipped order, as five literals.**
    ///
    /// Asserted field by field and not with `matches!(u[0], Doh{..})`, which is green for a typo'd
    /// address, a wrong path, or an endpoint nobody measured. The measurement behind this list is
    /// `docs/19-dns.md` §5b — five runs, DoH 10/10 in each. **Change the report before the list.**
    #[test]
    fn the_default_order_is_the_measured_one() {
        assert_eq!(
            default_upstreams(),
            vec![
                Upstream::Doh {
                    addr: SocketAddr::from(([1, 1, 1, 1], 443)),
                    path: "/dns-query",
                    alpn: true,
                },
                Upstream::Udp(SocketAddr::from(([77, 88, 8, 8], 1253))),
                Upstream::Udp(SocketAddr::from(([77, 88, 8, 1], 1253))),
                Upstream::Udp(SocketAddr::from(([1, 1, 1, 1], 53))),
                Upstream::Udp(SocketAddr::from(([9, 9, 9, 9], 53))),
            ],
            "the order is a measured fact; docs/19-dns.md §5b is the measurement"
        );
    }

    /// **A DoH upstream that answered wrongly must not end the sweep.**
    ///
    /// The dangerous shape, and the reason this test exists rather than a firewall arm: a
    /// `Reply::Nothing` ends the sweep *without launching the odd port* and is written to the
    /// negative cache for twenty seconds — machine-wide, because the DNS server resolves through
    /// this. A firewall drop can only produce `Silent` and can never reach that path, so no live
    /// arm can catch it. Only a resolver that **answers**, wrongly, can.
    #[test]
    fn a_doh_upstream_that_answered_wrongly_does_not_end_the_sweep() {
        let good = Ipv4Addr::new(203, 0, 113, 7);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("500", b"HTTP/1.1 500 Server Error\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("404", b"HTTP/1.1 404 Not Found\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("html", b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nhi".to_vec()),
            ("empty", b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ];
        for (label, response) in cases {
            let doh = tls_stub(LEAF_IP, vec![b"http/1.1".to_vec()], move |_| {
                response.clone()
            });
            let udp = stub_answering(good);
            let mut r = Resolver::with_upstreams(
                vec![
                    Upstream::Doh {
                        addr: doh,
                        path: "/dns-query",
                        alpn: true,
                    },
                    Upstream::Udp(udp),
                ],
                false,
            )
            .with_doh_roots(fixture_roots());
            r.timeout = Duration::from_millis(1500);

            let host = format!("wrong-{label}.test");
            assert_eq!(
                r.lookup(&host),
                vec![IpAddr::V4(good)],
                "{label}: the odd port must still be asked"
            );
            assert_eq!(
                r.cached(&host),
                Some(vec![IpAddr::V4(good)]),
                "{label}: and the good answer is what gets remembered"
            );
        }
    }

    /// **A dark DoH endpoint falls through to the odd port, inside the budget.**
    ///
    /// The offline twin of the live arm where the DoH address is blackholed: the flight goes out
    /// and nothing comes back, so the worker is `Silent` and the sweep advances. What is asserted
    /// is that the *client* does not wait for the dark worker — the stagger expires and the next
    /// upstream is launched — so the answer arrives in about one stagger, not one timeout.
    #[test]
    fn a_dark_doh_endpoint_does_not_delay_the_answer_by_its_whole_budget() {
        let good = Ipv4Addr::new(203, 0, 113, 11);
        let mut r = Resolver::with_upstreams(
            vec![
                Upstream::Doh {
                    addr: tcp_hole(),
                    path: "/dns-query",
                    alpn: true,
                },
                Upstream::Udp(stub_answering(good)),
            ],
            false,
        );
        r.timeout = Duration::from_millis(1500);

        let started = Instant::now();
        assert_eq!(r.lookup("dark-doh.test"), vec![IpAddr::V4(good)]);
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(600),
            "the odd port answers after one stagger, not after the DoH budget: {took:?}"
        );
        assert_eq!(r.counts_of(1).1, 1, "the odd port is the one that answered");
    }

    /// The shipped upstreams are the shipped servers, in order.
    ///
    /// Written to survive the step that puts DoH in front: the assertion is about the **Udp tail**,
    /// not about what is first. Asserting `default_upstreams()[0]` is `Udp` would be an assertion
    /// written to be falsified next week.
    #[test]
    fn the_udp_upstreams_are_default_servers_in_order() {
        // The `None` arm arrived with the DoH variant, exactly as this test was written to
        // expect: the assertion is about the Udp tail and never about what comes first.
        let udp: Vec<SocketAddr> = default_upstreams()
            .into_iter()
            .filter_map(|u| match u {
                Upstream::Udp(a) => Some(a),
                Upstream::Doh { .. } => None,
            })
            .collect();
        assert_eq!(
            udp,
            default_servers(),
            "order is a measured fact, not a habit"
        );
        assert_eq!(udp[0].port(), 1253);
    }

    /// **A reply is counted against the upstream that sent it, not against whoever was listening.**
    ///
    /// The fixture is shaped to break the three wrong implementations. Upstream 0 waits 400 ms, so
    /// it is silent through its own stagger; upstream 1 answers SERVFAIL at once while it is the
    /// last one launched; upstream 0's answer then lands in the drain loop. Under "count against
    /// index 0", "count against the last launched" or "count against the number heard so far", the
    /// numbers below come out differently. The obvious fixture — a fast upstream first — is green
    /// under all three, which is why it is not the fixture.
    #[test]
    fn a_reply_is_counted_against_the_upstream_that_sent_it() {
        let slow = stub_answering_after(Duration::from_millis(400), Ipv4Addr::new(203, 0, 113, 9));
        let failing = stub_failing(dnsmsg::RCODE_SERVFAIL);
        let mut r = Resolver::new(vec![slow, failing], false);
        r.timeout = Duration::from_millis(400);

        assert_eq!(
            r.lookup("counted.test"),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]
        );
        assert_eq!(
            r.counts_of(0),
            (1, 1, 0, 0, 0),
            "the slow upstream answered, and the answer is its own"
        );
        assert_eq!(
            r.counts_of(1),
            (1, 0, 0, 0, 1),
            "SERVFAIL is silence, and it belongs to upstream 1"
        );
        assert!(r.counts_line().contains(" 1/1 s0"), "{}", r.counts_line());
    }

    /// A reply that arrives after the lookup has already returned is **not** counted as an answer.
    ///
    /// Upstream 1 answers inside the first stagger and the lookup returns; upstream 0's reply lands
    /// 400 ms later, into a channel nobody is reading. It was asked — that is counted at launch —
    /// and it never answered us.
    #[test]
    fn a_reply_heard_after_the_lookup_returned_is_not_counted() {
        let slow = stub_answering_after(Duration::from_millis(400), Ipv4Addr::new(203, 0, 113, 9));
        let fast = stub_answering(Ipv4Addr::new(203, 0, 113, 10));
        let mut r = Resolver::new(vec![slow, fast], false);
        r.timeout = Duration::from_millis(400);

        assert_eq!(
            r.lookup("late.test"),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]
        );
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            r.counts_of(0),
            (1, 0, 0, 0, 0),
            "asked at launch, and never heard from before the lookup returned"
        );
    }

    /// A stub upstream that answers every question with one address of the caller's choosing.
    fn stub_answering(addr: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
        let at = sock.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(q) = dnsmsg::parse_question(&buf[..n]) else {
                    continue;
                };
                if let Ok(r) = dnsmsg::encode_response(&buf[..n], &q, &[addr], 30, 0) {
                    let _ = sock.send_to(&r, from);
                }
            }
        });
        at
    }

    /// A stub upstream that answers every question with a given failure rcode and no records —
    /// SERVFAIL, REFUSED, whatever the caller passes. **On the wire this is the same shape as the
    /// authoritative no above**: our id, QR set, one question, zero answers. Only byte 3 differs.
    fn stub_failing(rcode: u8) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
        let addr = sock.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(q) = dnsmsg::parse_question(&buf[..n]) else {
                    continue;
                };
                if let Ok(r) = dnsmsg::encode_response(&buf[..n], &q, &[], 30, rcode) {
                    let _ = sock.send_to(&r, from);
                }
            }
        });
        addr
    }

    /// **"I could not answer" is not "the name does not exist".**
    ///
    /// The four upstreams exist so that one bad one cannot take a name down. But a SERVFAIL or a
    /// REFUSED is byte-for-byte the shape of an authoritative no — same id, QR set, one question,
    /// zero answers — and until the codec read the rcode it was scored as one. So a single
    /// rate-limited reply from the *first* upstream ended the sweep before a packet was sent to any
    /// of the other three, and wrote a twenty-second negative entry: every program on the machine
    /// then got SERVFAIL for a name the second resolver would have answered on the first try.
    ///
    /// Both halves are load-bearing. The address proves the sweep continued; the empty cache proves
    /// we did not record one server's bad day as a fact about the name.
    #[test]
    fn a_server_that_could_not_answer_does_not_end_the_sweep() {
        for rcode in [
            dnsmsg::RCODE_SERVFAIL,
            5, /* REFUSED */
            4, /* NOTIMP */
        ] {
            let mut r = Resolver::new(
                vec![
                    stub_failing(rcode),
                    stub_answering(Ipv4Addr::new(203, 0, 113, 7)),
                ],
                false,
            );
            r.timeout = Duration::from_millis(500);

            assert_eq!(
                r.lookup("busy.example"),
                vec![v4(203, 0, 113, 7)],
                "rcode {rcode} stopped the sweep before the upstream that had the answer"
            );
            assert_eq!(
                r.cached("busy.example"),
                Some(vec![v4(203, 0, 113, 7)]),
                "rcode {rcode}: the good answer is what gets remembered"
            );
        }

        // And with no second upstream to save it, the failure must leave *no* trace: remembering an
        // empty vector here is what took the name off the machine for twenty seconds.
        let mut r = Resolver::new(vec![stub_failing(dnsmsg::RCODE_SERVFAIL)], false);
        r.timeout = Duration::from_millis(500);
        assert!(r.lookup("busy2.example").is_empty());
        assert_eq!(
            r.cached("busy2.example"),
            None,
            "a server's own failure is not a fact about the name and must not be cached"
        );
    }

    /// An authoritative "no such name" ends the sweep; a censored answer does not.
    ///
    /// Both used to be the same `Reply::Nothing`, and both kept the sweep running. That is four
    /// times the work for every name that does not exist — and Windows asks for those constantly —
    /// while a *censored* answer is the one case where the remaining servers are exactly who to ask.
    /// The two want opposite handling, so they are two variants.
    ///
    /// Measured as time: the second server here is a black hole, so a sweep that continues costs a
    /// timeout and a sweep that stops costs nothing.
    #[test]
    fn a_real_no_stops_the_sweep_and_a_censored_answer_does_not() {
        let black_hole = {
            let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
            let a = s.local_addr().expect("addr");
            drop(s);
            a
        };

        // 1. First server says "nothing here". The sweep must stop — and be remembered.
        let mut r = Resolver::new(vec![stub_saying_nothing(), black_hole], false);
        r.timeout = Duration::from_millis(800);
        let started = std::time::Instant::now();
        assert!(r.lookup("gone.example").is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "an authoritative no must end the sweep, not start the next server: {:?}",
            started.elapsed()
        );
        assert_eq!(
            r.cached("gone.example"),
            Some(Vec::new()),
            "and it is worth remembering"
        );

        // 2. First server answers with nothing but the censor's block page. The sweep must go on,
        //    and the result must not be remembered as though the name did not exist.
        let block_page = BLOCK_PAGES[0];
        let mut r = Resolver::new(vec![stub_answering(block_page), black_hole], false);
        r.timeout = Duration::from_millis(300);
        assert!(r.lookup("lied-about.example").is_empty());
        assert_eq!(
            r.cached("lied-about.example"),
            None,
            "a censored answer is not a fact about the name — remembering it would do the censor's \
             work for twenty seconds at a time"
        );
    }

    /// **The regression this exists for.** Silence is not an answer.
    ///
    /// The first negative cache could not tell "there is no such name" from "nobody replied", so one
    /// lost UDP packet took a name off the entire machine for twenty seconds. Two independent
    /// adversarial reviewers found it on 2026-08-09. On a lossy line that is worse than the stall the
    /// cache was added to fix, which is the whole reason this test is here and not a comment.
    #[test]
    fn silence_is_never_remembered_as_an_answer() {
        // A port nobody is listening on: the query goes out and nothing comes back.
        let nowhere = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let dead = nowhere.local_addr().expect("addr");
        drop(nowhere);

        let mut r = Resolver::new(vec![dead], false);
        r.timeout = Duration::from_millis(120);

        assert!(
            r.lookup("unlucky.example").is_empty(),
            "no answer, so no addresses"
        );
        assert_eq!(
            r.cached("unlucky.example"),
            None,
            "silence must not be remembered — a dropped packet is our bad luck, not a fact about \
             the name, and recording it takes the name off the machine for the whole negative TTL"
        );
    }

    /// And with nowhere at all to ask, the same rule holds: we learned nothing, so we remember
    /// nothing. This is the shape the first version of the test got wrong — it configured zero
    /// servers and then asserted the failure *was* cached, which was testing the bug.
    #[test]
    fn a_resolver_with_no_servers_remembers_nothing_either() {
        let r = Resolver::new(Vec::new(), false);
        assert!(r.lookup("nowhere.example").is_empty());
        assert_eq!(r.cached("nowhere.example"), None);
    }

    /// And remembered for much less time than a success. A name that would not resolve is usually a
    /// name that is about to; caching that for the full five minutes turns a blip into an outage.
    #[test]
    fn a_remembered_failure_expires_much_sooner_than_a_remembered_answer() {
        let mut r = Resolver::new(Vec::new(), false);
        assert!(
            r.negative_ttl < r.ttl,
            "a failure must not be remembered as long as an answer"
        );
        r.negative_ttl = Duration::from_millis(40);
        r.ttl = Duration::from_secs(60);

        r.remember("gone.example", &[]);
        r.remember("here.example", &[v4(1, 1, 1, 1)]);
        assert_eq!(r.cached("gone.example"), Some(Vec::new()));

        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(
            r.cached("gone.example"),
            None,
            "the failure must have expired"
        );
        assert_eq!(
            r.cached("here.example"),
            Some(vec![v4(1, 1, 1, 1)]),
            "the answer must not have"
        );
    }

    #[test]
    fn the_cache_is_used_and_expires() {
        let mut r = Resolver::new(Vec::new(), false);
        r.ttl = Duration::from_millis(50);
        r.remember("discord.com", &[v4(162, 159, 138, 232)]);
        assert_eq!(r.cached("discord.com"), Some(vec![v4(162, 159, 138, 232)]));
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            r.cached("discord.com"),
            None,
            "a stale entry must not be served"
        );
    }

    #[test]
    fn an_unknown_host_is_not_in_the_cache() {
        let r = Resolver::new(Vec::new(), false);
        assert_eq!(r.cached("nothing.example"), None);
    }

    /// Query ids must not repeat back to back, or a late answer to one lookup could be
    /// accepted as the answer to the next.
    #[test]
    fn query_ids_advance() {
        let r = Resolver::new(Vec::new(), false);
        let a = r.next_id.fetch_add(1, Ordering::Relaxed);
        let b = r.next_id.fetch_add(1, Ordering::Relaxed);
        assert_ne!(a, b);
    }
}
