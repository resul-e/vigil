//! Deciding which proxy protocol a client is speaking, from its first bytes. Pure.
//!
//! vigil listens for three dialects on one port because Windows gives the user no way to say
//! "SOCKS5". Measured on 2026-08-04:
//!
//! - `ProxyServer=socks=127.0.0.1:1080` — the only SOCKS form the registry accepts — is read
//!   as **SOCKS4** by Chromium (its own documentation: "if the scheme is omitted it will be
//!   understood as SOCKSv4 rather than HTTP"), and WinINET's SOCKS support is version 4 only.
//!   Chrome was observed sending `04 01 01bb …` under exactly that setting.
//! - `ProxyServer=https=127.0.0.1:1080` produces HTTP `CONNECT`, and is the only form the
//!   Discord updater — the blocked half of Discord — honours at all.
//!
//! A SOCKS5-only listener therefore answers nothing that the system proxy setting can
//! produce. Sniffing costs one byte and removes the entire class of failure.
//!
//! The three dialects are trivially separable: SOCKS greetings begin with their version byte
//! (0x04 / 0x05), and no HTTP method begins with either.

use crate::http_connect;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Socks5,
    Socks4,
    HttpConnect,
}

impl Dialect {
    pub fn name(self) -> &'static str {
        match self {
            Dialect::Socks5 => "socks5",
            Dialect::Socks4 => "socks4",
            Dialect::HttpConnect => "http-connect",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniff {
    /// Not enough bytes to tell yet. Read more and call again.
    Need,
    Known(Dialect),
    /// Nothing we speak. The first byte is included so the log can say what arrived.
    Unrecognised(u8),
}

/// Classify a connection from its opening bytes.
pub fn sniff(buf: &[u8]) -> Sniff {
    let Some(&first) = buf.first() else {
        return Sniff::Need;
    };
    match first {
        0x05 => Sniff::Known(Dialect::Socks5),
        0x04 => Sniff::Known(Dialect::Socks4),
        _ if http_connect::looks_like(buf) => {
            // `looks_like` accepts prefixes, so only commit once the whole method is in.
            if buf.len() >= 7 {
                Sniff::Known(Dialect::HttpConnect)
            } else {
                Sniff::Need
            }
        }
        _ => Sniff::Unrecognised(first),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_a_socks5_greeting() {
        assert_eq!(sniff(&[0x05, 0x01, 0x00]), Sniff::Known(Dialect::Socks5));
    }

    /// The shape Chromium sends under `ProxyServer=socks=127.0.0.1:1080`, captured from the
    /// wire: version 4, CONNECT, port 443, an IPv4 address, empty user id.
    #[test]
    fn recognises_the_socks4_request_chromium_actually_sends() {
        let b = [0x04, 0x01, 0x01, 0xBB, 0xA2, 0x9F, 0x8A, 0xE8, 0x00];
        assert_eq!(sniff(&b), Sniff::Known(Dialect::Socks4));
    }

    #[test]
    fn recognises_an_http_connect() {
        assert_eq!(
            sniff(b"CONNECT updates.discord.com:443 HTTP/1.1\r\n"),
            Sniff::Known(Dialect::HttpConnect)
        );
    }

    #[test]
    fn waits_for_more_bytes_rather_than_guessing() {
        assert_eq!(sniff(b""), Sniff::Need);
        for n in 1..7 {
            assert_eq!(sniff(&b"CONNECT"[..n]), Sniff::Need, "prefix {n}");
        }
        assert_eq!(sniff(b"CONNECT"), Sniff::Known(Dialect::HttpConnect));
    }

    #[test]
    fn rejects_what_it_does_not_speak() {
        // A raw TLS record: something routed us bytes without a proxy handshake.
        assert_eq!(
            sniff(&[0x16, 0x03, 0x01, 0x02, 0x00]),
            Sniff::Unrecognised(0x16)
        );
        // An absolute-form GET: we scope ourselves to https, so this should never arrive.
        assert_eq!(sniff(b"GET http://x/ HTTP/1.1"), Sniff::Unrecognised(b'G'));
    }

    /// Every dialect must be decided by the first byte alone except CONNECT, so a client that
    /// sends its greeting one byte at a time still classifies correctly.
    #[test]
    fn classification_is_stable_as_bytes_arrive() {
        for (full, want) in [
            (&b"\x05\x01\x00"[..], Dialect::Socks5),
            (
                &b"\x04\x01\x01\xBB\x01\x02\x03\x04\x00"[..],
                Dialect::Socks4,
            ),
            (&b"CONNECT a:1 HTTP/1.1\r\n\r\n"[..], Dialect::HttpConnect),
        ] {
            let mut decided = None;
            for n in 1..=full.len() {
                match sniff(&full[..n]) {
                    Sniff::Need => assert!(decided.is_none(), "flip-flopped back to Need"),
                    Sniff::Known(d) => {
                        if let Some(prev) = decided {
                            assert_eq!(prev, d, "changed its mind at {n} bytes");
                        }
                        decided = Some(d);
                    }
                    Sniff::Unrecognised(b) => panic!("{want:?} misread as unrecognised {b:#04x}"),
                }
            }
            assert_eq!(decided, Some(want));
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x5EED_1234_ABCD_9876u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 30) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            let _ = sniff(&buf);
        }
    }
}
