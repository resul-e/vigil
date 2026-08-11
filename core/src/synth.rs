//! Building a ClientHello of a chosen size. Pure.
//!
//! Every measurement this project has made was limited by the client it borrowed. `rustls`
//! emits 1462 B, OpenSSL 517 B, Chrome ~1800 B, and the Discord updater 175 B — and since the
//! rule on this line is *"the DPI fails whenever the ClientHello does not fit in one TCP
//! segment"*, the ClientHello's **length is the independent variable** and we have never been
//! able to set it. That is why the "why does the 175-byte updater still get reset sometimes"
//! question is still open: there was no client to ask.
//!
//! This builds one to order.
//!
//! # What this is not
//!
//! It is not a TLS client. There is no key exchange, no crypto, and the handshake is never
//! completed. It does not need to be: the DPI acts on the SNI inside the first flight, so the
//! only question is whether the *response* comes back. A ServerHello and a TLS alert are both
//! proof that the packet reached the far end; an RST or a silent timeout is the DPI.
//!
//! It offers what a real client offers — `supported_versions`, `key_share`, ALPN and the rest
//! — and still needs no crypto, because the `key_share` may be arbitrary bytes: the server
//! answers before it has any reason to care that we cannot finish. That is not a detail. A
//! leaner hello was measured at 9/20 against `discord.com` where a real captured one got
//! 20/20 at the same length and the same split; the far end was refusing half of them, and in
//! the tally that is indistinguishable from censorship. See [`fixed_extensions`].
//!
//! No clock and no randomness: the caller supplies the 32 nonce bytes. That keeps the crate
//! pure, keeps golden tests possible, and — because two connections must not look identical
//! to a server — makes varying them the caller's explicit responsibility.

use crate::tls::{CONTENT_TYPE_HANDSHAKE, RECORD_HEADER_LEN};

/// TLS 1.2. Also what a 1.3 hello puts in `legacy_version`.
const CLIENT_VERSION: [u8; 2] = [0x03, 0x03];
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_EC_POINT_FORMATS: u16 = 0x000B;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_ALPN: u16 = 0x0010;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002D;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;
const GROUP_X25519: u16 = 0x001D;
/// RFC 7685. Ignored by every server, which is exactly why it is the length dial.
const EXT_PADDING: u16 = 0x0015;

/// A `padding` extension costs 4 bytes of header before it can hold a single byte.
const EXT_HEADER_LEN: usize = 4;
/// `legacy_session_id` is capped at 32 bytes by the RFC, and is our fine-grained dial.
const MAX_SESSION_ID: usize = 32;

/// Cipher suites a real client would offer, and that a real server will answer.
///
/// Includes both 1.3 and 1.2 ECDHE suites so the far end has something to pick. The list is
/// fixed because it is part of what makes a measurement reproducible.
const CIPHER_SUITES: [u16; 6] = [
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xC02B, // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
];

const SUPPORTED_GROUPS: [u16; 3] = [0x001D, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
const SIGNATURE_ALGORITHMS: [u16; 5] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The requested length cannot hold a ClientHello for this hostname. Carries the smallest
    /// length that can, so a caller sweeping sizes can start at the right place instead of
    /// guessing.
    TooSmall { minimum: usize },
    /// Beyond what a single TLS record can carry.
    TooLarge { maximum: usize },
    /// A hostname that is empty, over-long, or not a plausible DNS name.
    BadHost,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TooSmall { minimum } => write!(f, "too small, minimum is {minimum}"),
            Error::TooLarge { maximum } => write!(f, "too large, maximum is {maximum}"),
            Error::BadHost => f.write_str("bad host"),
        }
    }
}

/// A TLS record's length field is 16 bits, and the handshake body plus record header must fit.
pub const MAX_LEN: usize = RECORD_HEADER_LEN + u16::MAX as usize;

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// Reject anything that is not a plausible DNS name before it reaches the wire.
///
/// The SNI extension carries raw bytes, so a nonsense host would still produce a *valid*
/// record — and then the measurement would be of something other than what the caller
/// thinks. Failing here keeps a typo from silently becoming a data point.
fn check_host(host: &str) -> Result<(), Error> {
    if host.is_empty() || host.len() > 253 {
        return Err(Error::BadHost);
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(Error::BadHost);
    }
    let ok = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !ok {
        return Err(Error::BadHost);
    }
    Ok(())
}

/// The extensions block, excluding session-id and padding, for a given host.
///
/// The set is not decorative. An earlier version of this module offered only the TLS 1.2
/// essentials, and the result was measured at **9/20** against `discord.com` where a real
/// captured curl hello of the same length, split the same way, got **20/20** — Cloudflare was
/// refusing roughly half of them, and the refusals were indistinguishable from censorship in
/// the tally. The only reason it was caught is that a server's reset arrives at server
/// latency (~4 ms here) while the injected one arrives at ~2 ms.
///
/// So: offer what a real client offers. `supported_versions` and `key_share` are what let the
/// far end answer with a TLS 1.3 ServerHello immediately, and the key share can be arbitrary
/// bytes precisely because the handshake is never completed — the server replies before it
/// has any reason to care whether we can finish.
fn fixed_extensions(host: &str, nonce: &[u8; 32]) -> Vec<u8> {
    let h = host.as_bytes();
    let mut ext = Vec::new();
    let mut put = |typ: u16, body: &[u8]| {
        ext.extend_from_slice(&be16(typ));
        ext.extend_from_slice(&be16(body.len() as u16));
        ext.extend_from_slice(body);
    };

    // server_name — first, as real clients place it
    let mut sni = Vec::new();
    sni.extend_from_slice(&be16((1 + 2 + h.len()) as u16)); // server_name_list length
    sni.push(0x00); // host_name
    sni.extend_from_slice(&be16(h.len() as u16));
    sni.extend_from_slice(h);
    put(EXT_SERVER_NAME, &sni);

    // extended_master_secret, renegotiation_info, session_ticket
    put(EXT_EXTENDED_MASTER_SECRET, &[]);
    put(EXT_RENEGOTIATION_INFO, &[0x00]);
    put(EXT_SESSION_TICKET, &[]);

    // status_request: OCSP, no responder id, no extensions
    put(EXT_STATUS_REQUEST, &[0x01, 0x00, 0x00, 0x00, 0x00]);

    // supported_groups
    let mut g = Vec::new();
    g.extend_from_slice(&be16((SUPPORTED_GROUPS.len() * 2) as u16));
    for x in SUPPORTED_GROUPS {
        g.extend_from_slice(&be16(x));
    }
    put(EXT_SUPPORTED_GROUPS, &g);

    // ec_point_formats: uncompressed
    put(EXT_EC_POINT_FORMATS, &[0x01, 0x00]);

    // signature_algorithms
    let mut s = Vec::new();
    s.extend_from_slice(&be16((SIGNATURE_ALGORITHMS.len() * 2) as u16));
    for x in SIGNATURE_ALGORITHMS {
        s.extend_from_slice(&be16(x));
    }
    put(EXT_SIGNATURE_ALGORITHMS, &s);

    // application_layer_protocol_negotiation: h2, http/1.1
    let mut a = Vec::new();
    let protos: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let body_len: usize = protos.iter().map(|p| 1 + p.len()).sum();
    a.extend_from_slice(&be16(body_len as u16));
    for p in protos {
        a.push(p.len() as u8);
        a.extend_from_slice(p);
    }
    put(EXT_ALPN, &a);

    // supported_versions: TLS 1.3 then 1.2
    put(EXT_SUPPORTED_VERSIONS, &[0x04, 0x03, 0x04, 0x03, 0x03]);

    // psk_key_exchange_modes: psk_dhe_ke
    put(EXT_PSK_KEY_EXCHANGE_MODES, &[0x01, 0x01]);

    // key_share: one x25519 entry. Arbitrary bytes are a valid wire encoding, and the server
    // answers before it could possibly object — we never complete the handshake.
    let mut k = Vec::new();
    k.extend_from_slice(&be16(4 + 32)); // client_shares length
    k.extend_from_slice(&be16(GROUP_X25519));
    k.extend_from_slice(&be16(32));
    k.extend_from_slice(nonce);
    put(EXT_KEY_SHARE, &k);

    ext
}

/// Total record length for a given host with a given session-id and padding size.
fn total_len(host: &str, session_id: usize, padding: Option<usize>) -> usize {
    // Length does not depend on the nonce's value, only its size, so any nonce will do here.
    let ext_fixed = fixed_extensions(host, &[0u8; 32]).len();
    let ext_padding = padding.map_or(0, |p| EXT_HEADER_LEN + p);
    RECORD_HEADER_LEN
        + 4  // handshake header: type + u24 length
        + 2  // client_version
        + 32 // random
        + 1 + session_id
        + 2 + CIPHER_SUITES.len() * 2
        + 1 + 1 // compression methods
        + 2 // extensions length
        + ext_fixed
        + ext_padding
}

/// The smallest ClientHello this builder can produce for `host`.
pub fn min_len(host: &str) -> Result<usize, Error> {
    check_host(host)?;
    Ok(total_len(host, 0, None))
}

/// Build a ClientHello for `host` that is **exactly** `target_len` bytes on the wire.
///
/// The length is hit by two dials: `legacy_session_id` (0–32 bytes, fine-grained and
/// realistic) and a `padding` extension (coarse, unbounded). The awkward band is a gap of
/// 33–35 bytes, which is too big for the session id alone and too small for a session id
/// plus a padding header — there the session id gives back the 4 bytes the header needs.
/// Every length from [`min_len`] upwards is reachable, and the tests assert exactly that
/// rather than trusting this paragraph.
pub fn client_hello(host: &str, target_len: usize, nonce: [u8; 32]) -> Result<Vec<u8>, Error> {
    check_host(host)?;
    let base = total_len(host, 0, None);
    if target_len < base {
        return Err(Error::TooSmall { minimum: base });
    }
    if target_len > MAX_LEN {
        return Err(Error::TooLarge { maximum: MAX_LEN });
    }

    let gap = target_len - base;
    let (session_id, padding) = if gap <= MAX_SESSION_ID {
        (gap, None)
    } else if gap < MAX_SESSION_ID + EXT_HEADER_LEN {
        // 33..=35: give the padding header its 4 bytes out of the session id.
        (gap - EXT_HEADER_LEN, Some(0))
    } else {
        (MAX_SESSION_ID, Some(gap - MAX_SESSION_ID - EXT_HEADER_LEN))
    };

    let mut ext = fixed_extensions(host, &nonce);
    if let Some(p) = padding {
        ext.extend_from_slice(&be16(EXT_PADDING));
        ext.extend_from_slice(&be16(p as u16));
        ext.resize(ext.len() + p, 0);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&CLIENT_VERSION);
    body.extend_from_slice(&nonce);
    body.push(session_id as u8);
    // A session id derived from the nonce, so two connections do not look byte-identical.
    body.extend(nonce.iter().copied().cycle().take(session_id));
    body.extend_from_slice(&be16((CIPHER_SUITES.len() * 2) as u16));
    for c in CIPHER_SUITES {
        body.extend_from_slice(&be16(c));
    }
    body.push(0x01); // compression methods length
    body.push(0x00); // null
    body.extend_from_slice(&be16(ext.len() as u16));
    body.extend_from_slice(&ext);

    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + hs.len());
    rec.push(CONTENT_TYPE_HANDSHAKE);
    rec.extend_from_slice(&CLIENT_VERSION);
    rec.extend_from_slice(&be16(hs.len() as u16));
    rec.extend_from_slice(&hs);

    // Checked in release too, deliberately. A hello that is not the length it was asked for
    // invalidates every size sweep it appears in, and it would do so silently — the caller
    // would tabulate the length it requested, not the one it sent. Cheap insurance against
    // the one bug this module could have that no downstream test would notice.
    if rec.len() != target_len {
        return Err(Error::TooSmall { minimum: rec.len() });
    }
    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clienthello;

    const NONCE: [u8; 32] = [0xA5; 32];

    fn nonce_n(n: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        for (i, b) in x.iter_mut().enumerate() {
            *b = n.wrapping_add(i as u8);
        }
        x
    }

    // ------------------------------------------------------------ length control

    /// The property the whole instrument rests on: ask for a length, get that length.
    /// Exhaustive rather than sampled, because the session-id/padding handover has an awkward
    /// band at a gap of 33–35 and an off-by-one there would silently skew every size sweep.
    #[test]
    fn every_reachable_length_is_hit_exactly() {
        for host in ["a.co", "discord.com", "updates.discord.com"] {
            let min = min_len(host).unwrap();
            for len in min..min + 2000 {
                let ch = client_hello(host, len, NONCE)
                    .unwrap_or_else(|e| panic!("{host} at {len}: {e}"));
                assert_eq!(ch.len(), len, "{host} asked for {len}");
            }
        }
    }

    /// The awkward band, called out on its own so a failure names itself.
    #[test]
    fn the_session_id_to_padding_handover_band_is_exact() {
        let host = "discord.com";
        let min = min_len(host).unwrap();
        for gap in 30..40 {
            let len = min + gap;
            assert_eq!(
                client_hello(host, len, NONCE).unwrap().len(),
                len,
                "gap {gap}"
            );
        }
    }

    #[test]
    fn the_declared_minimum_is_actually_the_minimum() {
        for host in ["a.co", "discord.com", &"x".repeat(60)] {
            let min = min_len(host).unwrap();
            assert!(
                client_hello(host, min, NONCE).is_ok(),
                "{host} at its minimum"
            );
            assert_eq!(
                client_hello(host, min - 1, NONCE),
                Err(Error::TooSmall { minimum: min }),
                "{host} below its minimum"
            );
        }
    }

    /// A longer hostname needs a longer hello. If this ever inverted, a size sweep would be
    /// comparing different things across targets without saying so.
    #[test]
    fn a_longer_host_has_a_larger_minimum() {
        let a = min_len("a.co").unwrap();
        let b = min_len("discord.com").unwrap();
        let c = min_len("updates.discord.com").unwrap();
        assert!(a < b && b < c, "{a} {b} {c}");
        assert_eq!(
            c - b,
            "updates.".len(),
            "minimum should track the host length exactly"
        );
    }

    // ------------------------------------------------------- it is a real ClientHello

    /// Round-trip through our own parser — the same code the proxy runs on live traffic.
    #[test]
    fn our_own_parser_finds_the_hostname_back() {
        for host in [
            "discord.com",
            "updates.discord.com",
            "a.co",
            "www.turkiye.gov.tr",
        ] {
            let min = min_len(host).unwrap();
            for len in [min, min + 1, min + 33, min + 40, min + 500, min + 1800] {
                let ch = client_hello(host, len, NONCE).unwrap();
                let parsed = clienthello::parse(&ch)
                    .unwrap_or_else(|e| panic!("{host} at {len} did not parse: {e:?}"));
                assert_eq!(parsed.host_str(), Some(host), "{host} at {len}");
                assert!(!parsed.is_record_truncated(), "{host} at {len}");
            }
        }
    }

    /// The split positions the strategies use must all resolve against a synthetic hello,
    /// otherwise the strategy sweep would silently fall back to passthrough and report that
    /// splitting "does not help".
    #[test]
    fn every_split_marker_resolves_on_a_synthetic_hello() {
        let ch = client_hello("discord.com", 600, NONCE).unwrap();
        let parsed = clienthello::parse(&ch).unwrap();
        for m in [
            clienthello::Marker::RecordHeader,
            clienthello::Marker::MidSld,
            clienthello::Marker::SniStart,
        ] {
            let off = parsed.marker_offset(m);
            assert!(off.is_some(), "{m:?} did not resolve");
            let off = off.unwrap();
            assert!(off > 0 && off < ch.len(), "{m:?} offset {off} out of range");
        }
    }

    #[test]
    fn the_record_header_declares_the_right_length() {
        for len in [300usize, 517, 1000, 1460, 1800] {
            let ch = client_hello("discord.com", len, NONCE).unwrap();
            assert_eq!(ch[0], CONTENT_TYPE_HANDSHAKE);
            let declared = u16::from_be_bytes([ch[3], ch[4]]) as usize;
            assert_eq!(
                declared + RECORD_HEADER_LEN,
                ch.len(),
                "record length field disagrees with the buffer at {len}"
            );
            // and the handshake header agrees with the record
            let hs_len = u32::from_be_bytes([0, ch[6], ch[7], ch[8]]) as usize;
            assert_eq!(hs_len + 4, declared, "handshake length disagrees at {len}");
        }
    }

    /// Two connections must not be byte-identical, or a server or a DPI may treat the second
    /// as a replay of the first.
    #[test]
    fn a_different_nonce_gives_different_bytes_at_the_same_length() {
        let a = client_hello("discord.com", 700, nonce_n(1)).unwrap();
        let b = client_hello("discord.com", 700, nonce_n(2)).unwrap();
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b, "identical bytes across nonces");
        // but the hostname is still there in both
        for ch in [&a, &b] {
            assert_eq!(
                clienthello::parse(ch).unwrap().host_str(),
                Some("discord.com")
            );
        }
    }

    #[test]
    fn the_same_inputs_always_give_the_same_bytes() {
        for _ in 0..3 {
            assert_eq!(
                client_hello("discord.com", 800, NONCE).unwrap(),
                client_hello("discord.com", 800, NONCE).unwrap()
            );
        }
    }

    // ------------------------------------------------------------------ rejections

    #[test]
    fn rejects_hosts_that_are_not_plausible_names() {
        for host in [
            "",
            ".leading",
            "trailing.",
            "double..dot",
            "has space.com",
            "has_underscore.com",
            "üñíçø∂é.com",
            "tab\t.com",
        ] {
            assert_eq!(
                min_len(host),
                Err(Error::BadHost),
                "{host:?} should be refused"
            );
            assert_eq!(
                client_hello(host, 1000, NONCE),
                Err(Error::BadHost),
                "{host:?} should be refused"
            );
        }
    }

    #[test]
    fn rejects_an_over_long_host() {
        let host = "a".repeat(254);
        assert_eq!(min_len(&host), Err(Error::BadHost));
        let ok = "a".repeat(253);
        assert!(min_len(&ok).is_ok());
    }

    #[test]
    fn rejects_a_length_beyond_one_record() {
        let e = client_hello("discord.com", MAX_LEN + 1, NONCE);
        assert_eq!(e, Err(Error::TooLarge { maximum: MAX_LEN }));
    }

    /// The largest hello that still fits one record must build, because the size sweep is
    /// allowed to walk right up to the ceiling. This is also where the 16-bit length fields
    /// are closest to overflowing: the extensions block is ~65 KiB at this size, and a `as
    /// u16` truncation there would produce a hello that parses as garbage.
    #[test]
    fn the_maximum_length_builds_and_parses() {
        let ch = client_hello("discord.com", MAX_LEN, NONCE).unwrap();
        assert_eq!(ch.len(), MAX_LEN);
        assert_eq!(
            clienthello::parse(&ch).unwrap().host_str(),
            Some("discord.com")
        );
        // every nested length field must still agree at the ceiling
        let declared = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(declared + RECORD_HEADER_LEN, ch.len());
        let hs_len = u32::from_be_bytes([0, ch[6], ch[7], ch[8]]) as usize;
        assert_eq!(hs_len + 4, declared);
    }

    /// Walk the extensions block by hand at several sizes and confirm it is internally
    /// consistent — that the declared extensions length lands exactly on the end of the
    /// buffer. Our own parser stops once it has the SNI, so it would not notice a padding
    /// extension whose length field disagreed with the bytes that follow it.
    #[test]
    fn the_extensions_block_ends_exactly_where_it_says() {
        for len in [300usize, 400, 517, 1000, 1460, 2000, 9000, MAX_LEN] {
            let ch = client_hello("discord.com", len, NONCE).unwrap();
            // record(5) + hs header(4) + version(2) + random(32)
            let mut i = 5 + 4 + 2 + 32;
            i += 1 + ch[i] as usize; // session id
            let cs = u16::from_be_bytes([ch[i], ch[i + 1]]) as usize;
            i += 2 + cs; // cipher suites
            i += 1 + ch[i] as usize; // compression methods
            let ext_len = u16::from_be_bytes([ch[i], ch[i + 1]]) as usize;
            i += 2;
            assert_eq!(
                i + ext_len,
                ch.len(),
                "extensions overrun/underrun at {len}"
            );

            // and every extension inside it is well formed
            let end = i + ext_len;
            let mut seen = 0;
            while i < end {
                assert!(i + 4 <= end, "extension header past the end at {len}");
                let body = u16::from_be_bytes([ch[i + 2], ch[i + 3]]) as usize;
                i += 4 + body;
                seen += 1;
                assert!(i <= end, "extension body past the end at {len}");
            }
            assert_eq!(i, end, "extensions did not land exactly at {len}");
            assert!(
                seen >= 4,
                "expected the fixed extensions at {len}, saw {seen}"
            );
        }
    }

    /// **The extension set is the instrument's calibration, and nothing pinned it.**
    ///
    /// This hello is what every size and strategy sweep is measured with, and it only measures
    /// *censorship* if a real server will complete a handshake with it. Drop `supported_versions`,
    /// `key_share` or `alpn` and Cloudflare starts refusing it — at which point every cell in every
    /// sweep is a mixture of the censor and the server, and by the docs' own precedent that reads
    /// as roughly 9/20 where the truth is 20/20. The instrument would be fabricating findings about
    /// the network, silently, and the whole suite would stay green.
    ///
    /// The temptation is concrete and recorded: dropping those three lowers the 221 B floor toward
    /// the 175 B the Discord updater emits, which is a length this project has actively wanted to
    /// reach. See `docs/12-dpi-scan.md` §2 before shortening anything here.
    #[test]
    fn the_extension_set_is_exactly_what_a_server_will_complete_a_handshake_with() {
        let types_in = |ch: &[u8]| -> Vec<u16> {
            let mut i = 5 + 4 + 2 + 32;
            i += 1 + ch[i] as usize; // session id
            let cs = u16::from_be_bytes([ch[i], ch[i + 1]]) as usize;
            i += 2 + cs; // cipher suites
            i += 1 + ch[i] as usize; // compression methods
            let end = i + 2 + u16::from_be_bytes([ch[i], ch[i + 1]]) as usize;
            i += 2;
            let mut out = Vec::new();
            while i < end {
                out.push(u16::from_be_bytes([ch[i], ch[i + 1]]));
                i += 4 + u16::from_be_bytes([ch[i + 2], ch[i + 3]]) as usize;
            }
            out
        };

        let expected = vec![
            EXT_SERVER_NAME,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_SESSION_TICKET,
            EXT_STATUS_REQUEST,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_ALPN,
            EXT_SUPPORTED_VERSIONS,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_KEY_SHARE,
        ];

        // At the floor there is no room for padding, so this is the set exactly.
        let floor = min_len("discord.com").unwrap();
        assert_eq!(
            types_in(&client_hello("discord.com", floor, NONCE).unwrap()),
            expected,
            "the fixed extension set changed; a server may now refuse this hello"
        );

        // Above the floor the only permitted addition is padding, and it comes last.
        let mut padded = expected.clone();
        padded.push(EXT_PADDING);
        for len in [600usize, 1460, 2000] {
            assert_eq!(
                types_in(&client_hello("discord.com", len, NONCE).unwrap()),
                padded,
                "at {len} B the set must be the fixed extensions plus padding, nothing else"
            );
        }
    }

    /// No input, however hostile, may panic the builder.
    #[test]
    fn arbitrary_inputs_never_panic() {
        let mut seed = 0xC0FF_EE00_1234_5678u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 300) as usize;
            let host: String = (0..n)
                .map(|_| (b'a' + (next() % 40) as u8) as char)
                .collect();
            let len = (next() % 80_000) as usize;
            let _ = client_hello(&host, len, NONCE);
            let _ = min_len(&host);
        }
    }
}
