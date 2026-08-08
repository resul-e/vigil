//! Asking several resolvers the same question, and comparing what they say.
//!
//! The message codec lives in `vigil_core::dnsmsg`; what is here is the socket and the
//! comparison, because comparing is the part that turns two answers into a finding.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

pub use vigil_core::dnsmsg::{decode_answers, encode_query, Error};

/// Resolvers that are not the subscriber's ISP.
///
/// `1253` is not decoration: Turkish ISPs intercept plain UDP/53, and the Turkish GoodbyeDPI
/// fork ships `--dns-port 1253` for exactly that reason. Asking on a port the interception
/// does not cover is what makes a dependency-free resolver possible at all.
pub const PUBLIC_RESOLVERS: &[(&str, &str)] = &[
    ("yandex:1253", "77.88.8.8:1253"),
    ("cloudflare", "1.1.1.1:53"),
    ("quad9", "9.9.9.9:53"),
    ("google", "8.8.8.8:53"),
];

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

/// What the system resolver said, and what everyone else said.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub host: String,
    pub system: Vec<IpAddr>,
    /// `(resolver name, addresses or the reason there were none)`
    pub public: Vec<(String, Result<Vec<Ipv4Addr>, Error>)>,
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
        .filter_map(|(_, r)| r.as_ref().ok())
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
/// Measured on Türk Telekom, 2026-08-04: `1.1.1.1`, `9.9.9.9` and `8.8.8.8` all answered for
/// `protonvpn.com` and all stayed silent for `discord.com`, `roblox.com`,
/// `cdn.discordapp.com` and `updates.discord.com` — while the ISP's own resolver answered
/// those four with the block-page address.
pub fn selectively_blocked(all: &[Comparison]) -> Vec<String> {
    let any_reachable = all.iter().any(|c| c.public.iter().any(|(_, r)| r.is_ok()));
    if !any_reachable {
        return Vec::new();
    }
    all.iter()
        .filter(|c| !c.public.is_empty() && c.public.iter().all(|(_, r)| r.is_err()))
        .map(|c| c.host.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // ------------------------------------------------------------------ encoding

    #[test]
    fn a_query_has_the_shape_rfc1035_describes() {
        let q = encode_query("discord.com", 0xABCD).unwrap();
        assert_eq!(&q[0..2], &[0xAB, 0xCD], "id");
        assert_eq!(&q[2..4], &[0x01, 0x00], "recursion desired");
        assert_eq!(&q[4..6], &[0x00, 0x01], "one question");
        // labels: 7 "discord" 3 "com" 0
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"discord");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(&q[25..29], &[0x00, 0x01, 0x00, 0x01], "A IN");
        assert_eq!(q.len(), 29);
    }

    #[test]
    fn bad_names_are_refused() {
        assert_eq!(encode_query("", 1), Err(Error::BadName));
        assert_eq!(encode_query(&"a".repeat(254), 1), Err(Error::BadName));
        assert_eq!(encode_query("a..b", 1), Err(Error::BadName));
        assert_eq!(
            encode_query(&format!("{}.com", "a".repeat(64)), 1),
            Err(Error::BadName)
        );
    }

    // ------------------------------------------------------------------ decoding

    /// A response with one compressed answer, which is what every real resolver sends.
    fn response(id: u16, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&[0x81, 0x80]); // response, recursion available
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // question
        r.push(7);
        r.extend_from_slice(b"discord");
        r.push(3);
        r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // answers, name compressed to offset 12
        for a in addrs {
            r.extend_from_slice(&[0xC0, 0x0C]);
            r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
            r.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // ttl
            r.extend_from_slice(&[0x00, 0x04]);
            r.extend_from_slice(&a.octets());
        }
        r
    }

    #[test]
    fn answers_are_extracted() {
        let r = response(0x1234, &[v4(162, 159, 136, 232), v4(162, 159, 137, 232)]);
        assert_eq!(
            decode_answers(&r, 0x1234).unwrap(),
            vec![v4(162, 159, 136, 232), v4(162, 159, 137, 232)]
        );
    }

    /// The sinkhole answer that started all this must decode like any other.
    #[test]
    fn the_block_page_address_decodes_like_any_other() {
        let r = response(1, &[v4(195, 175, 254, 2)]);
        assert_eq!(decode_answers(&r, 1).unwrap(), vec![v4(195, 175, 254, 2)]);
    }

    /// Accepting a response whose id we did not ask for is how an off-path spoofer wins.
    #[test]
    fn a_response_with_the_wrong_id_is_refused() {
        let r = response(0x1111, &[v4(1, 2, 3, 4)]);
        assert_eq!(decode_answers(&r, 0x2222), Err(Error::Malformed));
    }

    #[test]
    fn a_query_is_not_mistaken_for_a_response() {
        let q = encode_query("discord.com", 7).unwrap();
        assert_eq!(decode_answers(&q, 7), Err(Error::Malformed));
    }

    #[test]
    fn a_response_with_no_a_record_says_so() {
        let r = response(5, &[]);
        assert_eq!(decode_answers(&r, 5), Err(Error::NoAddress));
    }

    #[test]
    fn truncated_responses_never_panic() {
        let full = response(9, &[v4(1, 2, 3, 4)]);
        for n in 0..full.len() {
            let _ = decode_answers(&full[..n], 9);
        }
        assert!(decode_answers(&full, 9).is_ok());
    }

    /// A pointer loop must terminate. This is the classic way a DNS parser hangs.
    #[test]
    fn a_self_referential_name_does_not_hang() {
        let mut r = response(3, &[v4(1, 2, 3, 4)]);
        // point the answer's name at itself
        let at = 12 + 17;
        r[at] = 0xC0;
        r[at + 1] = at as u8;
        let _ = decode_answers(&r, 3);
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0xDEAD_BEEF_1234_5678u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 80) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            let _ = decode_answers(&buf, 1);
        }
    }

    // ----------------------------------------------------------------- integrity

    fn cmp(system: &[Ipv4Addr], public: Vec<(&str, Result<Vec<Ipv4Addr>, Error>)>) -> Comparison {
        Comparison {
            host: "discord.com".into(),
            system: system.iter().map(|a| IpAddr::V4(*a)).collect(),
            public: public
                .into_iter()
                .map(|(n, r)| (n.to_string(), r))
                .collect(),
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

    /// The exact pattern measured on Türk Telekom, 2026-08-04: the public resolvers answered
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
                public: vec![("cloudflare".into(), Err(Error::NoReply))],
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
