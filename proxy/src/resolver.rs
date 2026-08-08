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

pub struct Resolver {
    servers: Vec<SocketAddr>,
    /// `None` disables the fallback entirely, for callers who would rather fail than use a
    /// resolver they do not trust.
    allow_system: bool,
    timeout: Duration,
    ttl: Duration,
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
            timeout: Duration::from_secs(3),
            ttl: Duration::from_secs(300),
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
        (at.elapsed() < self.ttl).then(|| addrs.clone())
    }

    fn remember(&self, host: &str, addrs: &[IpAddr]) {
        if let Ok(mut c) = self.cache.lock() {
            c.insert(host.to_string(), (addrs.to_vec(), Instant::now()));
        }
    }

    fn ask(&self, server: SocketAddr, host: &str) -> Option<Vec<IpAddr>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let q = dnsmsg::encode_query(host, id).ok()?;
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().ok()?
        } else {
            "[::]:0".parse().ok()?
        };
        let sock = UdpSocket::bind(bind).ok()?;
        sock.set_read_timeout(Some(self.timeout)).ok()?;
        sock.send_to(&q, server).ok()?;

        let mut buf = [0u8; 1500];
        // Bounded, because on an intercepting network the wrong answers may keep coming.
        for _ in 0..4 {
            let (n, _) = sock.recv_from(&mut buf).ok()?;
            match dnsmsg::decode_answers(&buf[..n], id) {
                Ok(v4s) => {
                    let addrs: Vec<IpAddr> = v4s.into_iter().map(IpAddr::V4).collect();
                    return usable(addrs);
                }
                // A response that is not ours — a spoof, or a straggler. Keep reading.
                Err(dnsmsg::Error::Malformed) => continue,
                Err(_) => return None,
            }
        }
        None
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

    fn lookup(&self, host: &str) -> Vec<IpAddr> {
        if let Some(hit) = self.cached(host) {
            return hit;
        }
        for s in &self.servers {
            if let Some(addrs) = self.ask(*s, host) {
                self.remember(host, &addrs);
                return addrs;
            }
        }
        if self.allow_system {
            if let Some(addrs) = self.system(host) {
                self.remember(host, &addrs);
                return addrs;
            }
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
