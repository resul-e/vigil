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
//! # Why plain DNS on an odd port, and not DoH
//!
//! DoH needs TLS, TLS needs a dependency, and this crate has none beyond our own core. It
//! also does not need one: the interception here covers **port 53**, not DNS itself.
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
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vigil_core::dnsmsg;

/// Addresses that are never a legitimate answer for a public hostname.
///
/// A last line of defence for the system-resolver fallback: if the only answer we can get is
/// one of these, we have not resolved the name, we have been handed a censor's address, and
/// connecting to it would produce a measurement — or a user experience — of the wrong thing.
///
/// `195.175.254.2` is Türk Telekom's block page, documented by OONI and observed directly.
/// Vodafone AS15897 has been documented answering `127.0.0.1` for `twitter.com`.
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

fn ask_one(server: SocketAddr, host: &str, timeout: Duration, id: u16) -> Reply {
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
            // A response that is not ours — a spoof, or a straggler. Keep reading.
            Err(dnsmsg::Error::Malformed) => continue,
            Err(_) => return Reply::Silent,
        }
    }
    Reply::Silent
}

pub struct Resolver {
    servers: Vec<SocketAddr>,
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
}

impl core::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Resolver")
            .field("servers", &self.servers)
            .field("allow_system", &self.allow_system)
            .finish()
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Resolver::new(default_servers(), true)
    }
}

impl Resolver {
    pub fn new(servers: Vec<SocketAddr>, allow_system: bool) -> Self {
        Resolver {
            servers,
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
        }
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
    fn ask_all(&self, host: &str) -> Reply {
        let n = self.servers.len();
        if n == 0 {
            return Reply::Silent;
        }
        let (tx, rx) = mpsc::channel();
        let deadline = Instant::now() + self.timeout + STAGGER * (n as u32);
        let mut launched = 0usize;
        let mut heard = 0usize;
        // Did anybody answer with nothing but block pages? That is not an authoritative no — it is a
        // line lying to us — so it does not stop the sweep and it is not worth remembering.
        let mut filtered = false;

        for server in self.servers.iter().copied() {
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
            match std::thread::Builder::new()
                .name("vigil-dns-upstream".into())
                .spawn(move || {
                    let _ = tx.send(ask_one(server, &host_owned, timeout, id));
                }) {
                Ok(_) => launched += 1,
                // No thread to be had. Ask here instead of losing the server entirely.
                Err(_) => match ask_one(server, host, self.timeout, id) {
                    Reply::Addresses(addrs) => return Reply::Addresses(addrs),
                    // An authoritative no ends it: see `Reply::Nothing`.
                    Reply::Nothing => return Reply::Nothing,
                    Reply::Filtered | Reply::Silent => {}
                },
            }

            // Give whatever is running a stagger's worth of time before starting the next one.
            let wait = STAGGER.min(deadline.saturating_duration_since(Instant::now()));
            if let Ok(reply) = rx.recv_timeout(wait) {
                heard += 1;
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
                Ok(Reply::Addresses(addrs)) => return Reply::Addresses(addrs),
                Ok(Reply::Nothing) => return Reply::Nothing,
                Ok(Reply::Filtered) => {
                    filtered = true;
                    heard += 1;
                }
                Ok(Reply::Silent) => heard += 1,
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
        // Vodafone AS15897 answered 127.0.0.1 for twitter.com (OONI, 2023).
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
