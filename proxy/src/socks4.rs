//! SOCKS4 / SOCKS4a wire format — pure. No sockets, no I/O.
//!
//! This module exists because of a measured fact about Windows, not because SOCKS4 is
//! interesting. `ProxyServer=socks=127.0.0.1:1080` — the only way to name a SOCKS proxy in
//! Windows' system proxy settings — does **not** mean SOCKS5:
//!
//! - WinINET's SOCKS support is version 4 only.
//! - Chromium reads the same string and, per its own documentation, "if the scheme is omitted
//!   it will be understood as SOCKSv4 rather than HTTP".
//!
//! So every Windows application that honours the system proxy — including every Electron app,
//! which is what the Discord desktop client is — opens the connection with `0x04`, and a
//! SOCKS5-only listener rejects it before the target hostname is ever spoken. Speaking
//! SOCKS4 is not a nicety; without it the system-proxy integration reaches nothing at all.
//!
//! Chromium never emits SOCKS4a (it resolves the hostname itself and sends an address), but
//! other clients do, and parsing it costs a dozen lines.
//!
//! Reference: the original SOCKS4 protocol note, and the SOCKS4A extension.

use core::fmt;

pub const VERSION: u8 = 0x04;
pub const CMD_CONNECT: u8 = 0x01;

/// A SOCKS4 reply carries version 0, not 4. Sending 4 here makes curl and Chromium both
/// abandon the connection.
pub const REPLY_VERSION: u8 = 0x00;

pub const GRANTED: u8 = 0x5A;
pub const REJECTED: u8 = 0x5B;

/// The maximum we will read looking for a null terminator before calling the request
/// malformed. A client that sends an unterminated user id is not going to send one later,
/// and an unbounded search is a memory-exhaustion invitation.
const MAX_FIELD: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not enough bytes yet — read more and call again. Never an error condition.
    Incomplete,
    /// Version byte was not 4.
    BadVersion(u8),
    /// A command we do not implement. SOCKS4 BIND (0x02) is the realistic one.
    UnsupportedCommand(u8),
    /// A SOCKS4a domain that is empty, over-long or not valid UTF-8.
    BadDomain,
    /// A user id field with no terminator within [`MAX_FIELD`] bytes.
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Incomplete => f.write_str("incomplete"),
            Error::BadVersion(v) => write!(f, "bad version {v:#04x}"),
            Error::UnsupportedCommand(c) => write!(f, "unsupported command {c:#04x}"),
            Error::BadDomain => f.write_str("bad domain"),
            Error::Malformed => f.write_str("malformed"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    V4([u8; 4]),
    /// SOCKS4a only. Kept as a string for the same reason as in SOCKS5: the hostname is the
    /// most useful thing the proxy learns.
    Domain(String),
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(o) => write!(f, "{}.{}.{}.{}", o[0], o[1], o[2], o[3]),
            Addr::Domain(d) => f.write_str(d),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub addr: Addr,
    pub port: u16,
    /// The USERID field. Logged, never trusted, never used for a decision.
    pub user: Vec<u8>,
}

impl Request {
    /// `host:port` as the upstream connector wants it.
    pub fn target(&self) -> String {
        format!("{}:{}", self.addr, self.port)
    }
}

/// `0.0.0.x` with `x` non-zero is the SOCKS4a signal that a hostname follows the user id.
///
/// `0.0.0.0` is deliberately excluded: it is a malformed address rather than the marker, and
/// treating it as 4a would make us wait forever for a hostname that is not coming.
fn is_socks4a_marker(ip: [u8; 4]) -> bool {
    ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0
}

/// Read a null-terminated field starting at `from`. Returns the bytes and the offset just
/// past the terminator.
fn read_cstring(buf: &[u8], from: usize) -> Result<(&[u8], usize), Error> {
    let rest = buf.get(from..).ok_or(Error::Incomplete)?;
    match rest.iter().position(|&b| b == 0) {
        Some(i) => Ok((&rest[..i], from + i + 1)),
        // No terminator yet. Distinguish "still arriving" from "never going to arrive", or a
        // client that sends 64 KB of non-zero bytes keeps us reading forever.
        None if rest.len() > MAX_FIELD => Err(Error::Malformed),
        None => Err(Error::Incomplete),
    }
}

/// Parse a SOCKS4 or SOCKS4a CONNECT request.
///
/// Returns the request and how many bytes were consumed, so the caller can keep whatever the
/// client pipelined behind it — which for a TLS client is the ClientHello this whole tool
/// exists to reshape.
pub fn parse_request(buf: &[u8]) -> Result<(Request, usize), Error> {
    let ver = *buf.first().ok_or(Error::Incomplete)?;
    if ver != VERSION {
        return Err(Error::BadVersion(ver));
    }
    match *buf.get(1).ok_or(Error::Incomplete)? {
        CMD_CONNECT => {}
        other => return Err(Error::UnsupportedCommand(other)),
    }
    let p = buf.get(2..4).ok_or(Error::Incomplete)?;
    let port = u16::from_be_bytes([p[0], p[1]]);
    let s = buf.get(4..8).ok_or(Error::Incomplete)?;
    let ip = [s[0], s[1], s[2], s[3]];

    let (user, after_user) = read_cstring(buf, 8)?;
    let user = user.to_vec();

    if !is_socks4a_marker(ip) {
        return Ok((
            Request {
                addr: Addr::V4(ip),
                port,
                user,
            },
            after_user,
        ));
    }

    let (host, after_host) = read_cstring(buf, after_user)?;
    if host.is_empty() || host.len() > 255 {
        return Err(Error::BadDomain);
    }
    let host = core::str::from_utf8(host).map_err(|_| Error::BadDomain)?;
    Ok((
        Request {
            addr: Addr::Domain(host.to_string()),
            port,
            user,
        },
        after_host,
    ))
}

/// Build a reply. The port and address fields are ignored by every client for a CONNECT, so
/// they are zeroed rather than echoed — the same choice, for the same reason, as in SOCKS5.
pub fn reply(code: u8) -> [u8; 8] {
    [REPLY_VERSION, code, 0, 0, 0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_v4(ip: [u8; 4], port: u16, user: &str) -> Vec<u8> {
        let mut v = vec![VERSION, CMD_CONNECT];
        v.extend_from_slice(&port.to_be_bytes());
        v.extend_from_slice(&ip);
        v.extend_from_slice(user.as_bytes());
        v.push(0);
        v
    }

    fn req_v4a(host: &str, port: u16, user: &str) -> Vec<u8> {
        let mut v = req_v4([0, 0, 0, 1], port, user);
        v.extend_from_slice(host.as_bytes());
        v.push(0);
        v
    }

    // ------------------------------------------------------------------ socks4

    /// The shape Chromium actually sends: it resolves the name itself, so the proxy is handed
    /// an address and an empty user id.
    #[test]
    fn parses_the_request_chromium_sends() {
        let b = req_v4([162, 159, 138, 232], 443, "");
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.addr, Addr::V4([162, 159, 138, 232]));
        assert_eq!(r.port, 443);
        assert!(r.user.is_empty());
        assert_eq!(n, b.len());
        assert_eq!(r.target(), "162.159.138.232:443");
    }

    #[test]
    fn parses_a_request_with_a_user_id() {
        let b = req_v4([1, 2, 3, 4], 80, "resul");
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.user, b"resul");
        assert_eq!(n, b.len());
    }

    // ----------------------------------------------------------------- socks4a

    #[test]
    fn parses_a_socks4a_domain() {
        let b = req_v4a("discord.com", 443, "");
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.addr, Addr::Domain("discord.com".into()));
        assert_eq!(r.port, 443);
        assert_eq!(n, b.len());
        assert_eq!(r.target(), "discord.com:443");
    }

    /// `0.0.0.0` is not the 4a marker. Reading it as one would make the parser block waiting
    /// for a hostname the client never sends.
    #[test]
    fn all_zero_address_is_not_treated_as_socks4a() {
        let b = req_v4([0, 0, 0, 0], 443, "");
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.addr, Addr::V4([0, 0, 0, 0]));
        assert_eq!(n, b.len(), "must not wait for a domain that is not coming");
    }

    #[test]
    fn any_nonzero_last_octet_is_the_socks4a_marker() {
        for last in [1u8, 7, 255] {
            let mut b = req_v4([0, 0, 0, last], 443, "");
            b.extend_from_slice(b"roblox.com\0");
            let (r, _) = parse_request(&b).unwrap();
            assert_eq!(r.addr, Addr::Domain("roblox.com".into()), "last={last}");
        }
    }

    /// A real address that merely starts with a zero octet must not be mistaken for 4a.
    #[test]
    fn an_address_with_a_leading_zero_octet_is_still_an_address() {
        let b = req_v4([0, 1, 2, 3], 443, "");
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.addr, Addr::V4([0, 1, 2, 3]));
        assert_eq!(n, b.len());
    }

    // ------------------------------------------------------------ partial reads

    #[test]
    fn every_prefix_of_every_request_shape_says_incomplete() {
        for full in [
            req_v4([1, 2, 3, 4], 443, ""),
            req_v4([1, 2, 3, 4], 443, "user"),
            req_v4a("discord.com", 443, ""),
            req_v4a("discord.com", 443, "user"),
        ] {
            for n in 0..full.len() {
                assert_eq!(
                    parse_request(&full[..n]),
                    Err(Error::Incomplete),
                    "prefix {n} of {full:?}"
                );
            }
            assert!(parse_request(&full).is_ok());
        }
    }

    /// The first flight follows the request immediately on the same socket. Swallowing it
    /// would destroy the only bytes this tool cares about.
    #[test]
    fn request_consumes_only_its_own_bytes() {
        for mut b in [req_v4([1, 2, 3, 4], 443, ""), req_v4a("a.example", 443, "")] {
            let want = b.len();
            b.extend_from_slice(b"\x16\x03\x01\x02\x00");
            let (_, n) = parse_request(&b).unwrap();
            assert_eq!(n, want);
        }
    }

    // --------------------------------------------------------------- rejections

    #[test]
    fn rejects_a_socks5_greeting() {
        // The reverse of the bug this module fixes: a SOCKS5 client must be recognised as
        // such, not misparsed as a SOCKS4 request.
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00]),
            Err(Error::BadVersion(0x05))
        );
    }

    #[test]
    fn rejects_unsupported_commands() {
        for cmd in [0x00u8, 0x02, 0x03, 0xFF] {
            let mut b = req_v4([1, 2, 3, 4], 443, "");
            b[1] = cmd;
            assert_eq!(
                parse_request(&b),
                Err(Error::UnsupportedCommand(cmd)),
                "cmd {cmd:#04x}"
            );
        }
    }

    #[test]
    fn rejects_an_unterminated_user_id_rather_than_reading_forever() {
        let mut b = vec![VERSION, CMD_CONNECT, 0x01, 0xBB, 1, 2, 3, 4];
        b.extend(core::iter::repeat_n(b'a', MAX_FIELD + 1));
        assert_eq!(parse_request(&b), Err(Error::Malformed));
    }

    #[test]
    fn rejects_an_unterminated_socks4a_domain_rather_than_reading_forever() {
        let mut b = vec![VERSION, CMD_CONNECT, 0x01, 0xBB, 0, 0, 0, 1, 0];
        b.extend(core::iter::repeat_n(b'a', MAX_FIELD + 1));
        assert_eq!(parse_request(&b), Err(Error::Malformed));
    }

    #[test]
    fn rejects_an_empty_socks4a_domain() {
        let mut b = req_v4([0, 0, 0, 1], 443, "");
        b.push(0); // zero-length hostname
        assert_eq!(parse_request(&b), Err(Error::BadDomain));
    }

    #[test]
    fn rejects_a_non_utf8_socks4a_domain() {
        let mut b = req_v4([0, 0, 0, 1], 443, "");
        b.extend_from_slice(&[0xFF, 0xFE, 0x00]);
        assert_eq!(parse_request(&b), Err(Error::BadDomain));
    }

    #[test]
    fn handles_a_maximum_length_socks4a_domain() {
        let host = "a".repeat(255);
        let b = req_v4a(&host, 443, "");
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.addr, Addr::Domain(host));
        assert_eq!(n, b.len());
    }

    #[test]
    fn rejects_an_over_length_socks4a_domain() {
        let host = "a".repeat(256);
        let b = req_v4a(&host, 443, "");
        assert_eq!(parse_request(&b), Err(Error::BadDomain));
    }

    // ------------------------------------------------------------------ replies

    /// A reply that echoes version 4 instead of 0 is rejected by Chromium and by curl. This
    /// assertion is the whole reason [`REPLY_VERSION`] is a named constant.
    #[test]
    fn replies_carry_version_zero() {
        for code in [GRANTED, REJECTED] {
            let r = reply(code);
            assert_eq!(r[0], 0x00, "SOCKS4 replies are version 0, not 4");
            assert_eq!(r[1], code);
            assert_eq!(r.len(), 8);
        }
    }

    /// No input, however hostile, may panic the protocol layer.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x0BAD_C0DE_DEAD_BEEFu64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 40) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            let _ = parse_request(&buf);
        }
        // and specifically around the shape the parser walks
        for _ in 0..20_000 {
            let n = (next() % 300) as usize;
            let mut buf = vec![VERSION, CMD_CONNECT, 1, 0xBB, 0, 0, 0, 1];
            buf.extend((0..n).map(|_| (next() & 0xFF) as u8));
            let _ = parse_request(&buf);
        }
    }
}
