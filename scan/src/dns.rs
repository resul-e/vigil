//! Asking several resolvers the same question, and comparing what they say.
//!
//! The message codec lives in `vigil_core::dnsmsg`; what is here is the socket and the
//! comparison, because comparing is the part that turns two answers into a finding.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use std::time::Duration;
use vigil_proxy::resolver::Upstream;

pub use vigil_core::dnsmsg::{decode_answers, encode_query, Error};

/// Resolvers that are not the subscriber's ISP.
///
/// `1253` is not decoration: Turkish ISPs intercept plain UDP/53, and the Turkish GoodbyeDPI
/// fork ships `--dns-port 1253` for exactly that reason. Asking on a port the interception
/// does not cover is what makes a dependency-free resolver possible at all.
/// **Every upstream vigil itself ships is on this list.** That is asserted below rather than
/// remembered: `77.88.8.1:1253` has been in `resolver::default_servers()` since the beginning and
/// appeared in no report ever taken, on either network — a fallback nobody has ever measured is a
/// fallback nobody knows they have.
pub const PUBLIC_RESOLVERS: &[(&str, &str)] = &[
    ("yandex:1253", "77.88.8.8:1253"),
    ("yandex2:1253", "77.88.8.1:1253"),
    ("cloudflare", "1.1.1.1:53"),
    ("quad9", "9.9.9.9:53"),
    ("google", "8.8.8.8:53"),
    // **Appended, never prepended.** `honest_addrs` takes the first `Ok` in this order, so moving
    // this entry up would change the address every DPI cell in the report is measured against —
    // a transport question quietly rewriting the answer to the blocking question.
    ("doh:1.1.1.1", "doh://1.1.1.1:443"),
];

/// The table above as upstreams, parsed once.
///
/// A `const` cannot hold these: `SocketAddr::new` is not a const function. The strings stay
/// because they are what a person reads in the source; this is what the code compares.
pub fn public_upstreams() -> Vec<(String, Upstream)> {
    PUBLIC_RESOLVERS
        .iter()
        .filter_map(|(name, addr)| {
            let up = match addr.strip_prefix("doh://") {
                Some(rest) => Upstream::Doh {
                    addr: rest.parse().ok()?,
                    path: "/dns-query",
                    alpn: true,
                },
                None => Upstream::Udp(addr.parse().ok()?),
            };
            Some(((*name).to_string(), up))
        })
        .collect()
}

/// **Why a resolver produced no addresses — by layer.**
///
/// Until 2026-09-07 every failure in this module became `Error::NoReply` and rendered
/// `<no reply>`, so a TLS refusal, an HTTP 403 and a dropped SYN were byte-identical to a lost
/// UDP datagram. "Asked and refused" and "never reached at all" are different findings about a
/// line and the report could not express the difference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The answer arrived and would not decode, or nothing arrived at all.
    Dns(Error),
    Connect(String),
    Tls(String),
    Http(u16),
    Timeout,
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Failure::Dns(_) => f.write_str("no reply"),
            Failure::Connect(w) => write!(f, "connect: {w}"),
            Failure::Tls(w) => write!(f, "tls: {w}"),
            Failure::Http(s) => write!(f, "http {s}"),
            Failure::Timeout => f.write_str("timeout"),
        }
    }
}

/// One resolver's answer to one question.
#[derive(Debug, Clone)]
pub struct Answer {
    pub name: String,
    pub via: Upstream,
    pub got: Result<Vec<Ipv4Addr>, Failure>,
}

/// Ask one upstream, whatever its transport.
///
/// **Id 0 on the DoH arm**, and not the sweep's `0x4000 + i`: `decode_answers` refuses any other
/// id as malformed, so every DoH row in every report would read `<no reply>` for a reason that has
/// nothing to do with the line. RFC 8484 §4.1 asks for 0 anyway.
pub fn query_upstream(
    up: &Upstream,
    host: &str,
    id: u16,
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>, Failure> {
    match up {
        Upstream::Udp(a) => query(*a, host, id, timeout).map_err(Failure::Dns),
        Upstream::Doh { addr, path, alpn } => {
            let q = encode_query(host, 0).map_err(Failure::Dns)?;
            let ep = vigil_proxy::doh::Endpoint {
                ip: addr.ip(),
                port: addr.port(),
                path,
            };
            let cfg = vigil_proxy::doh::tls_config(*alpn);
            match vigil_proxy::doh::query(&ep, &cfg, &q, std::time::Instant::now() + timeout) {
                Ok(body) => decode_answers(&body, 0).map_err(Failure::Dns),
                Err(e) => Err(match e {
                    vigil_proxy::doh::DohError::Timeout => Failure::Timeout,
                    vigil_proxy::doh::DohError::Io(w) => Failure::Connect(w),
                    vigil_proxy::doh::DohError::Tls(w) => Failure::Tls(w),
                    vigil_proxy::doh::DohError::Alpn => Failure::Tls("alpn refused".into()),
                    vigil_proxy::doh::DohError::Http(s) => Failure::Http(s),
                    other => Failure::Tls(other.to_string()),
                }),
            }
        }
    }
}

/// Ask one resolver, over plain UDP.
pub fn query(
    resolver: SocketAddr,
    host: &str,
    id: u16,
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>, Error> {
    let q = encode_query(host, id)?;
    let bind: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse().expect("literal")
    } else {
        "[::]:0".parse().expect("literal")
    };
    let sock = UdpSocket::bind(bind).map_err(|_| Error::NoReply)?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|_| Error::NoReply)?;
    sock.send_to(&q, resolver).map_err(|_| Error::NoReply)?;

    let mut buf = [0u8; 1500];
    // Read until an answer carries our id, so a stray or spoofed packet does not end the
    // lookup. Bounded, because on an intercepting network the noise may never stop.
    for _ in 0..4 {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => match decode_answers(&buf[..n], id) {
                Err(Error::Malformed) => continue,
                other => return other,
            },
            Err(_) => return Err(Error::NoReply),
        }
    }
    Err(Error::NoReply)
}

/// Ask every listed upstream about every host.
///
/// The two I/O halves are injected so this is testable without a socket — and that is not
/// tidiness. The renderer prints whatever answers it is handed, so a mutation that filters DoH out
/// *before* the loop is invisible to every render test. Here it is visible.
pub fn compare(
    hosts: &[&str],
    resolvers: &[(String, Upstream)],
    adapter: Option<&Upstream>,
    system: impl Fn(&str) -> Vec<IpAddr>,
    mut ask: impl FnMut(&Upstream, &str, usize) -> Result<Vec<Ipv4Addr>, Failure>,
) -> Vec<Comparison> {
    hosts
        .iter()
        .enumerate()
        .map(|(i, host)| Comparison {
            host: (*host).to_string(),
            system: system(host),
            public: resolvers
                .iter()
                .map(|(name, up)| Answer {
                    name: name.clone(),
                    via: up.clone(),
                    got: ask(up, host, i),
                })
                .collect(),
            adapter: adapter.map(|up| ask(up, host, i)),
        })
        .collect()
}

/// One interface's resolver configuration: alias, servers, and whether DHCP handed them out.
pub type Configured = (String, Vec<String>, bool);

/// **Is the `system=` column about this provider at all?**
///
/// It is only if the machine is asking the resolver the provider gave it. Two ways it stops being
/// so, and both look identical in the verdict column:
///
/// - the adapter is pointed at a public resolver by hand — which is what Windows' "DNS over HTTPS"
///   setting actually does: it replaces the DHCP server with one from its own template list;
/// - the answers disagree with what that configured resolver says over plain DNS.
///
/// **Measured 2026-09-07, and it corrected the first version of this check.** With Windows' DoH on,
/// the adapter read `{1.1.1.1, 1.0.0.1}` and the section said `discord.com  ok
/// system=162.159.138.232`; with it off the adapter read `{192.168.0.1}` from DHCP and the same
/// name read `TAMPERED  system=195.175.254.2`. Every public-resolver row and every transport total
/// was byte-identical across the two — they are direct sockets — so **only this column moved**, and
/// it moved from "clean line" to "poisoned line" with nothing on the wire changing.
///
/// The first version asked "does the system agree with its adapter's resolver". It said yes, and
/// it was right and useless: the machine *was* using its adapter's resolver, the adapter had simply
/// been pointed somewhere else. The question that matters is where the adapter points.
pub fn provenance_line(configured: &[Configured], all: &[Comparison]) -> String {
    let with_servers: Vec<&Configured> = configured.iter().filter(|c| !c.1.is_empty()).collect();
    if with_servers.is_empty() {
        return "(the machine's own resolver configuration could not be read)".into();
    }
    let described: Vec<String> = with_servers
        .iter()
        .map(|(alias, servers, dhcp)| {
            format!(
                "{alias}: {} ({})",
                servers.join(", "),
                if *dhcp { "DHCP" } else { "SET BY HAND" }
            )
        })
        .collect();
    let by_hand = with_servers.iter().any(|(_, _, dhcp)| !*dhcp);

    // How often the system's answer matched what its own configured resolver says over plain DNS.
    let mut compared = 0usize;
    let mut agreed = 0usize;
    for c in all {
        let Some(Ok(theirs)) = &c.adapter else {
            continue;
        };
        if theirs.is_empty() || c.system.is_empty() {
            continue;
        }
        compared += 1;
        if theirs.iter().any(|a| c.system.contains(&IpAddr::V4(*a))) {
            agreed += 1;
        }
    }
    let matched = if compared == 0 {
        "its configured resolver could not be asked directly".to_string()
    } else {
        format!("matches it on {agreed}/{compared} names asked directly")
    };

    if by_hand {
        format!(
            "*** THE VERDICTS BELOW ARE NOT ABOUT THIS PROVIDER *** the machine's resolver was set \
             by hand, not by DHCP — {}; {matched}. Windows' own \"DNS over HTTPS\" setting does \
             exactly this: it replaces the provider's resolver with a public one. Whatever this \
             section says about tampering is a statement about that resolver.",
            described.join("; ")
        )
    } else {
        format!("resolver from DHCP — {}; {matched}", described.join("; "))
    }
}

/// How each transport did, over the whole run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tally {
    pub transport: &'static str,
    pub asked: usize,
    pub answered: usize,
    pub timeout: usize,
    pub tls: usize,
    pub http: usize,
}

/// Grouped by transport, DoH first.
///
/// Separate totals and not one combined number: "the resolvers answered 47 of 60" says nothing
/// about whether the transport this line is being asked to adopt works at all.
pub fn tally(all: &[Comparison]) -> Vec<Tally> {
    let mut out = vec![
        Tally {
            transport: "doh",
            asked: 0,
            answered: 0,
            timeout: 0,
            tls: 0,
            http: 0,
        },
        Tally {
            transport: "udp",
            asked: 0,
            answered: 0,
            timeout: 0,
            tls: 0,
            http: 0,
        },
    ];
    for c in all {
        for a in &c.public {
            let t = match a.via {
                Upstream::Doh { .. } => &mut out[0],
                Upstream::Udp(_) => &mut out[1],
            };
            t.asked += 1;
            match &a.got {
                Ok(_) => t.answered += 1,
                Err(Failure::Timeout) => t.timeout += 1,
                Err(Failure::Tls(_)) => t.tls += 1,
                Err(Failure::Http(_)) => t.http += 1,
                Err(_) => {}
            }
        }
    }
    out
}

/// What the system resolver said, and what everyone else said.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub host: String,
    pub system: Vec<IpAddr>,
    /// One per upstream asked, in the order of [`PUBLIC_RESOLVERS`].
    pub public: Vec<Answer>,
    /// What the machine's **own configured** resolver said, asked directly.
    ///
    /// Deliberately not in `public`: that list is the independent opinion the system answer is
    /// judged against, and the adapter's resolver is usually the very thing being judged. Putting
    /// it there would let the ISP's resolver vouch for the ISP's answer and `integrity` would
    /// report agreement on a poisoned line.
    ///
    /// `None` when it could not be read or asked.
    pub adapter: Option<Result<Vec<Ipv4Addr>, Failure>>,
}

/// The verdict for one hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// System and at least one public resolver agree on at least one address.
    Agrees,
    /// They disagree completely, and no public resolver's answer overlaps the system's.
    /// The system resolver is answering with something nobody else does.
    Tampered,
    /// No public resolver could be reached, so there is nothing to compare against. On a
    /// network that intercepts UDP/53 this is itself suggestive, but it is not proof.
    Unknown,
}

/// Compare one host's answers.
///
/// Agreement is **overlap**, not equality: any large site answers differently to different
/// resolvers and from different places, so requiring identical sets would report tampering
/// on every CDN in the world. One shared address is enough to show the system resolver is
/// pointing at the same service everyone else is.
pub fn integrity(c: &Comparison) -> Integrity {
    let reachable: Vec<&Vec<Ipv4Addr>> = c
        .public
        .iter()
        .filter_map(|a| a.got.as_ref().ok())
        .collect();
    if reachable.is_empty() {
        return Integrity::Unknown;
    }
    if c.system.is_empty() {
        return Integrity::Tampered;
    }
    let overlaps = reachable
        .iter()
        .any(|addrs| addrs.iter().any(|a| c.system.contains(&IpAddr::V4(*a))));
    if overlaps {
        Integrity::Agrees
    } else {
        Integrity::Tampered
    }
}

/// Hostnames whose public-resolver lookups all failed, in a run where other hostnames'
/// lookups succeeded.
///
/// On its own, "no public resolver answered" is [`Integrity::Unknown`] — we failed to look,
/// rather than looked and found nothing. But if the very same resolvers answered happily for
/// *other* names in the same run, the failure is not connectivity. It is the queries for
/// these particular names being dropped, which is interference by any reasonable reading.
///
/// Measured on the home line, 2026-08-04: `1.1.1.1`, `9.9.9.9` and `8.8.8.8` all answered for
/// `protonvpn.com` and all stayed silent for `discord.com`, `roblox.com`,
/// `cdn.discordapp.com` and `updates.discord.com` — while the ISP's own resolver answered
/// those four with the block-page address.
pub fn selectively_blocked(all: &[Comparison]) -> Vec<String> {
    let any_reachable = all.iter().any(|c| c.public.iter().any(|a| a.got.is_ok()));
    if !any_reachable {
        return Vec::new();
    }
    all.iter()
        .filter(|c| !c.public.is_empty() && c.public.iter().all(|a| a.got.is_err()))
        .map(|c| c.host.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The report must measure what vigil actually uses.**
    ///
    /// Two lists, in two crates, saying the same thing in different words, is how one of them ends
    /// up wrong quietly. `resolver::default_servers()` is the order vigil asks in; this list is what
    /// the report asks. If an upstream is in the first and not the second, the report is silent
    /// about a resolver a user's traffic depends on — which is exactly what happened to
    /// `77.88.8.1:1253` for the life of the project.
    ///
    /// A superset is fine and deliberate: `8.8.8.8:53` is here as a fourth opinion and vigil does
    /// not use it.
    #[test]
    fn every_resolver_vigil_ships_is_one_the_report_measures() {
        let measured = public_upstreams();
        for up in vigil_proxy::resolver::default_upstreams() {
            assert!(
                // **Whole values, never `.ip()`.** A shipped `Doh 1.1.1.1:443` would otherwise be
                // "measured" by the existing `Udp 1.1.1.1:53` row, and the guard would be green
                // while no report ever asked DoH at all — the same shape of hole it was written
                // for in the first place.
                measured.iter().any(|(_, m)| *m == up),
                "vigil asks {up} and no report ever measures it; add it to PUBLIC_RESOLVERS"
            );
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // The DNS *codec* tests live in `core/src/dnsmsg.rs`, next to the code they test.
    //
    // A byte-identical copy of them sat here until 2026-08-11 — left behind when the codec moved
    // into core — testing nothing but re-exported functions, and contradicting this module's own
    // header, which says the codec lives in core and this file only compares answers. Two copies of
    // a test suite is one copy that can silently stop matching the code.

    // ----------------------------------------------------------------- transports

    /// **Every listed upstream is asked about every host.**
    ///
    /// The mutation this exists for is a `filter` that drops the DoH entry before the loop: the
    /// renderer prints whatever answers it is handed, so a report with no DoH row looks like a
    /// report where DoH failed, and no render test can tell the difference.
    #[test]
    fn the_comparison_asks_every_listed_upstream_for_every_host() {
        let resolvers = public_upstreams();
        let asked = std::cell::RefCell::new(Vec::new());
        let out = compare(
            &["discord.com", "example.com"],
            &resolvers,
            None,
            |_| vec![],
            |up, host, _| {
                asked.borrow_mut().push((up.clone(), host.to_string()));
                Ok(vec![Ipv4Addr::new(203, 0, 113, 1)])
            },
        );
        let want: Vec<(Upstream, String)> = ["discord.com", "example.com"]
            .iter()
            .flat_map(|h| {
                resolvers
                    .iter()
                    .map(move |(_, up)| (up.clone(), (*h).to_string()))
            })
            .collect();
        assert_eq!(asked.into_inner(), want, "every resolver, every host");
        for c in &out {
            assert_eq!(c.public.len(), resolvers.len());
            for (a, (_, up)) in c.public.iter().zip(resolvers.iter()) {
                assert_eq!(&a.via, up, "each answer records the upstream it came from");
            }
        }
        assert!(
            resolvers
                .iter()
                .any(|(_, u)| matches!(u, Upstream::Doh { .. })),
            "there is a DoH row to drop in the first place"
        );
    }

    /// Totals per transport, never one combined number.
    #[test]
    fn the_tally_keeps_the_transports_apart() {
        let doh = Upstream::Doh {
            addr: "1.1.1.1:443".parse().expect("literal"),
            path: "/dns-query",
            alpn: true,
        };
        let mk = |got: Result<Vec<Ipv4Addr>, Failure>, via: Upstream| Answer {
            name: "x".into(),
            via,
            got,
        };
        let all = vec![Comparison {
            host: "h".into(),
            system: vec![],
            public: vec![
                mk(Ok(vec![Ipv4Addr::new(1, 2, 3, 4)]), doh.clone()),
                mk(Err(Failure::Tls("bad cert".into())), doh),
                mk(Ok(vec![Ipv4Addr::new(1, 2, 3, 4)]), udp(53)),
                mk(Ok(vec![Ipv4Addr::new(1, 2, 3, 4)]), udp(1253)),
            ],
            adapter: None,
        }];
        let t = tally(&all);
        assert_eq!(t[0].transport, "doh");
        assert_eq!((t[0].answered, t[0].asked, t[0].tls), (1, 2, 1));
        assert_eq!(t[1].transport, "udp");
        assert_eq!((t[1].answered, t[1].asked), (2, 2));
    }

    /// **The verdict column is only about this provider if the machine is asking this provider.**
    ///
    /// The first version of this check asked "does the system agree with its adapter's resolver".
    /// Run live with Windows' DoH switched on, it answered *yes* — and it was right and useless:
    /// the machine was using its adapter's resolver, the adapter had simply been pointed at
    /// `1.1.1.1`. Windows' "DNS over HTTPS" setting **replaces the DHCP server with a public one**,
    /// so the question that matters is where the adapter points, not whether it is obeyed.
    #[test]
    fn a_resolver_set_by_hand_makes_the_verdicts_about_something_else() {
        let dhcp: Vec<Configured> = vec![("Ethernet".into(), vec!["192.168.0.1".into()], true)];
        let by_hand: Vec<Configured> = vec![(
            "Ethernet".into(),
            vec!["1.1.1.1".into(), "1.0.0.1".into()],
            false,
        )];

        let line = provenance_line(&by_hand, &[]);
        assert!(line.contains("NOT ABOUT THIS PROVIDER"), "{line}");
        assert!(line.contains("1.1.1.1"), "the resolver is named: {line}");
        assert!(line.contains("SET BY HAND"), "{line}");

        let line = provenance_line(&dhcp, &[]);
        assert!(!line.contains("NOT ABOUT THIS PROVIDER"), "{line}");
        assert!(line.contains("DHCP"), "{line}");
        assert!(line.contains("192.168.0.1"), "{line}");

        // Unreadable is not reassurance.
        let line = provenance_line(&[], &[]);
        assert!(line.contains("could not be read"), "{line}");
        // An interface with no servers is not a configuration.
        let empty: Vec<Configured> = vec![("Wi-Fi".into(), vec![], true)];
        assert!(provenance_line(&empty, &[]).contains("could not be read"));

        // And the direct-ask half is reported when there is one.
        let block_page = Ipv4Addr::new(195, 175, 254, 2);
        let cmp = vec![Comparison {
            host: "discord.com".into(),
            system: vec![IpAddr::V4(block_page)],
            public: vec![],
            adapter: Some(Ok(vec![block_page])),
        }];
        assert!(
            provenance_line(&dhcp, &cmp).contains("matches it on 1/1"),
            "{}",
            provenance_line(&dhcp, &cmp)
        );
    }

    /// **A failure names its layer.**
    ///
    /// "the resolver refused us" and "nothing came back" lead to different next steps, and they
    /// rendered as the same string — `<no reply>` — until 2026-09-07.
    #[test]
    fn a_failure_names_the_layer_it_happened_at() {
        assert_eq!(Failure::Tls("bad cert".into()).to_string(), "tls: bad cert");
        assert_eq!(Failure::Http(403).to_string(), "http 403");
        assert_eq!(Failure::Timeout.to_string(), "timeout");
        assert_eq!(
            Failure::Connect("refused".into()).to_string(),
            "connect: refused"
        );
        assert_eq!(Failure::Dns(Error::NoReply).to_string(), "no reply");
        // And they are all different from one another, or the row says nothing.
        let all = [
            Failure::Tls("x".into()).to_string(),
            Failure::Http(403).to_string(),
            Failure::Timeout.to_string(),
            Failure::Connect("x".into()).to_string(),
            Failure::Dns(Error::NoReply).to_string(),
        ];
        let mut seen = all.to_vec();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), all.len(), "two layers render the same: {all:?}");
    }

    // ----------------------------------------------------------------- integrity

    fn udp(port: u16) -> Upstream {
        Upstream::Udp(SocketAddr::from(([1, 1, 1, 1], port)))
    }

    fn cmp(system: &[Ipv4Addr], public: Vec<(&str, Result<Vec<Ipv4Addr>, Error>)>) -> Comparison {
        Comparison {
            host: "discord.com".into(),
            system: system.iter().map(|a| IpAddr::V4(*a)).collect(),
            public: public
                .into_iter()
                .enumerate()
                .map(|(i, (n, r))| Answer {
                    name: n.to_string(),
                    via: udp(53 + i as u16),
                    got: r.map_err(Failure::Dns),
                })
                .collect(),
            adapter: None,
        }
    }

    /// The exact situation measured on 2026-08-04.
    #[test]
    fn the_sinkhole_answer_is_reported_as_tampering() {
        let c = cmp(
            &[v4(195, 175, 254, 2)],
            vec![("cloudflare", Ok(vec![v4(162, 159, 136, 232)]))],
        );
        assert_eq!(integrity(&c), Integrity::Tampered);
    }

    /// A CDN answering different addresses to different resolvers is normal and must not be
    /// reported as tampering — only one address needs to overlap.
    #[test]
    fn a_partial_overlap_counts_as_agreement() {
        let c = cmp(
            &[v4(104, 20, 23, 154), v4(172, 66, 147, 243)],
            vec![
                ("cloudflare", Ok(vec![v4(172, 66, 147, 243)])),
                ("quad9", Ok(vec![v4(104, 20, 23, 154), v4(1, 1, 1, 1)])),
            ],
        );
        assert_eq!(integrity(&c), Integrity::Agrees);
    }

    /// Disagreeing with one resolver but agreeing with another is agreement: anycast means
    /// two honest resolvers routinely differ.
    #[test]
    fn agreeing_with_any_reachable_resolver_is_enough() {
        let c = cmp(
            &[v4(162, 159, 136, 232)],
            vec![
                ("cloudflare", Ok(vec![v4(1, 2, 3, 4)])),
                ("quad9", Ok(vec![v4(162, 159, 136, 232)])),
            ],
        );
        assert_eq!(integrity(&c), Integrity::Agrees);
    }

    /// If nothing external could be reached there is no comparison to make, and the honest
    /// answer is "unknown" rather than a guess in either direction.
    #[test]
    fn no_reachable_resolver_is_unknown_not_tampered() {
        let c = cmp(
            &[v4(195, 175, 254, 2)],
            vec![
                ("cloudflare", Err(Error::NoReply)),
                ("quad9", Err(Error::NoReply)),
            ],
        );
        assert_eq!(integrity(&c), Integrity::Unknown);
    }

    /// The system resolver refusing to answer at all, while others do, is tampering too —
    /// NXDOMAIN for a live site is a block, not an outage.
    #[test]
    fn the_system_resolver_answering_nothing_is_tampering() {
        let c = cmp(&[], vec![("cloudflare", Ok(vec![v4(162, 159, 136, 232)]))]);
        assert_eq!(integrity(&c), Integrity::Tampered);
    }

    /// The exact pattern measured on the home line, 2026-08-04: the public resolvers answered
    /// for one name and stayed silent for the rest, which is interference rather than a
    /// broken link.
    #[test]
    fn silence_for_some_names_but_not_others_is_selective_blocking() {
        let all = vec![
            cmp(
                &[v4(185, 159, 159, 140)],
                vec![("cloudflare", Ok(vec![v4(185, 159, 159, 140)]))],
            ),
            Comparison {
                host: "discord.com".into(),
                system: vec![IpAddr::V4(v4(195, 175, 254, 2))],
                public: vec![Answer {
                    name: "cloudflare".into(),
                    via: udp(53),
                    got: Err(Failure::Dns(Error::NoReply)),
                }],
                adapter: None,
            },
        ];
        assert_eq!(selectively_blocked(&all), vec!["discord.com".to_string()]);
    }

    /// If nothing was reachable at all, the link is simply down. Blaming the names would be
    /// an invented finding, and this tool exists to not invent findings.
    #[test]
    fn total_silence_is_not_selective_blocking() {
        let all = vec![
            cmp(&[v4(1, 2, 3, 4)], vec![("cloudflare", Err(Error::NoReply))]),
            cmp(&[v4(5, 6, 7, 8)], vec![("cloudflare", Err(Error::NoReply))]),
        ];
        assert!(selectively_blocked(&all).is_empty());
    }

    #[test]
    fn a_clean_run_reports_no_selective_blocking() {
        let all = vec![cmp(
            &[v4(1, 2, 3, 4)],
            vec![("cloudflare", Ok(vec![v4(1, 2, 3, 4)]))],
        )];
        assert!(selectively_blocked(&all).is_empty());
    }
}
