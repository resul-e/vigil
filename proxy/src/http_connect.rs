//! HTTP `CONNECT` tunnelling — pure. No sockets, no I/O.
//!
//! This is the dialect that actually reaches the application this tool was built for.
//!
//! Measured on 2026-08-04: the Discord desktop client is two network stacks, not one. Its
//! Electron/Chromium side honours the Windows system proxy in either form, but its **native
//! updater** — the component that fetches `updates.discord.com`, whose ClientHello is 175
//! bytes and which is therefore the only part of Discord this line actually blocks — ignores
//! `ProxyServer=socks=...` completely and is only reachable when the system proxy is
//! advertised as an HTTP proxy. Until vigil speaks `CONNECT`, the blocked half of Discord
//! cannot be helped at all.
//!
//! Only the authority-form request (`CONNECT host:port HTTP/1.1`) is accepted. Absolute-form
//! requests (`GET http://host/path`) are deliberately **not** handled: [`crate::sysproxy`]'s
//! registry value scopes us to `https` only, so plain HTTP never arrives here and stays on
//! its direct path. Handling it would mean writing a forwarding HTTP proxy — keep-alive,
//! chunked bodies, header rewriting — for traffic that carries no SNI and that this DPI does
//! not filter.
//!
//! RFC 9110 §9.3.6.

use core::fmt;

/// The response every client is waiting for before it sends its first flight.
pub const RESPONSE_OK: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// The largest request head we will buffer. A client that has not finished its headers in
/// 8 KiB is not going to, and an unbounded search is a memory-exhaustion invitation.
const MAX_HEAD: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not enough bytes yet — read more and call again. Never an error condition.
    Incomplete,
    /// A method we do not tunnel. Carries the method so the log says which.
    NotConnect(String),
    /// The request-target was not a usable `host:port`.
    BadAuthority,
    /// Structurally invalid, or a head larger than [`MAX_HEAD`].
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Incomplete => f.write_str("incomplete"),
            Error::NotConnect(m) => write!(f, "not a CONNECT ({m})"),
            Error::BadAuthority => f.write_str("bad authority"),
            Error::Malformed => f.write_str("malformed"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Hostname or IP literal, without brackets for IPv6.
    pub host: String,
    pub port: u16,
}

impl Request {
    /// `host:port` as the upstream connector wants it, re-bracketing IPv6 literals.
    pub fn target(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Does this buffer look like the start of an HTTP `CONNECT`?
///
/// Used to pick a dialect from the first bytes on the wire. Kept deliberately narrow: a
/// SOCKS greeting starts with 0x04 or 0x05, neither of which can begin `CONNECT`, and any
/// prefix of `CONNECT` is treated as "maybe, read more".
pub fn looks_like(buf: &[u8]) -> bool {
    let n = buf.len().min(7);
    buf[..n].eq_ignore_ascii_case(&b"CONNECT"[..n])
}

/// Split an authority into host and port.
///
/// A missing port is rejected rather than defaulted to 443. Authority-form requires one, and
/// silently inventing a port would turn a client bug into a mysterious connection to the
/// wrong service.
fn split_authority(s: &str) -> Result<(String, u16), Error> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal: [::1]:443
        let (h, after) = rest.split_once(']').ok_or(Error::BadAuthority)?;
        let p = after.strip_prefix(':').ok_or(Error::BadAuthority)?;
        (h.to_string(), p)
    } else {
        let (h, p) = s.rsplit_once(':').ok_or(Error::BadAuthority)?;
        if h.contains(':') {
            // A bare IPv6 literal with no brackets: ambiguous, so refuse it.
            return Err(Error::BadAuthority);
        }
        (h.to_string(), p)
    };
    if host.is_empty() || host.len() > 255 {
        return Err(Error::BadAuthority);
    }
    let port: u16 = port.parse().map_err(|_| Error::BadAuthority)?;
    if port == 0 {
        return Err(Error::BadAuthority);
    }
    Ok((host, port))
}

/// Parse a `CONNECT` request head.
///
/// Returns the request and how many bytes were consumed — everything past the blank line is
/// the client's own data and must be preserved, because for a TLS client that is the
/// ClientHello this whole tool exists to reshape.
pub fn parse_request(buf: &[u8]) -> Result<(Request, usize), Error> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        // No complete head yet. Distinguish "still arriving" from "never going to arrive".
        return if buf.len() > MAX_HEAD {
            Err(Error::Malformed)
        } else {
            Err(Error::Incomplete)
        };
    };
    let consumed = end + 4;
    let head = core::str::from_utf8(&buf[..end]).map_err(|_| Error::Malformed)?;
    let line = head.lines().next().ok_or(Error::Malformed)?;

    let mut parts = line.split(' ');
    let method = parts.next().ok_or(Error::Malformed)?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(Error::NotConnect(method.to_string()));
    }
    let authority = parts.next().ok_or(Error::Malformed)?;
    // The HTTP-version token must be present; its value we do not care about.
    if parts.next().is_none() {
        return Err(Error::Malformed);
    }
    let (host, port) = split_authority(authority)?;
    Ok((Request { host, port }, consumed))
}

/// A minimal failure response. The body is empty; clients only read the status line.
pub fn error_response(status: u16) -> Vec<u8> {
    let reason = match status {
        405 => "Method Not Allowed",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Bad Request",
    };
    format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n\r\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(target: &str) -> Vec<u8> {
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes()
    }

    /// The exact shape the Discord updater sends, and the reason this module exists.
    #[test]
    fn parses_the_request_the_discord_updater_sends() {
        let b = head("updates.discord.com:443");
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.host, "updates.discord.com");
        assert_eq!(r.port, 443);
        assert_eq!(n, b.len());
        assert_eq!(r.target(), "updates.discord.com:443");
    }

    #[test]
    fn parses_an_ipv4_authority() {
        let (r, _) = parse_request(&head("162.159.138.232:443")).unwrap();
        assert_eq!(r.host, "162.159.138.232");
        assert_eq!(r.target(), "162.159.138.232:443");
    }

    #[test]
    fn parses_a_bracketed_ipv6_authority_and_re_brackets_it() {
        let (r, _) = parse_request(&head("[2606:4700::1]:443")).unwrap();
        assert_eq!(r.host, "2606:4700::1");
        assert_eq!(r.port, 443);
        assert_eq!(
            r.target(),
            "[2606:4700::1]:443",
            "v6 target must be bracketed"
        );
    }

    #[test]
    fn accepts_a_lowercase_method() {
        assert!(parse_request(b"connect a.example:443 HTTP/1.1\r\n\r\n").is_ok());
    }

    #[test]
    fn accepts_a_head_with_many_headers() {
        let b = b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\
                  Proxy-Connection: keep-alive\r\nUser-Agent: x\r\n\r\n";
        let (r, n) = parse_request(b).unwrap();
        assert_eq!(r.host, "a.example");
        assert_eq!(n, b.len());
    }

    // ------------------------------------------------------------ partial reads

    #[test]
    fn every_prefix_of_a_head_says_incomplete() {
        let full = head("updates.discord.com:443");
        for n in 0..full.len() {
            assert_eq!(
                parse_request(&full[..n]),
                Err(Error::Incomplete),
                "prefix {n}"
            );
        }
        assert!(parse_request(&full).is_ok());
    }

    /// The first flight is pipelined behind the head by some clients. Swallowing it would
    /// destroy the only bytes this tool cares about.
    #[test]
    fn request_consumes_only_its_own_bytes() {
        let mut b = head("a.example:443");
        let want = b.len();
        b.extend_from_slice(b"\x16\x03\x01\x02\x00");
        let (_, n) = parse_request(&b).unwrap();
        assert_eq!(n, want);
    }

    // --------------------------------------------------------------- rejections

    #[test]
    fn rejects_a_non_connect_method_and_says_which() {
        // Chromium sends absolute-form GETs for plain http:// when it is configured as a
        // general HTTP proxy. We scope ourselves to https so this should never arrive, but
        // it must be a clean refusal rather than a hang.
        let b = b"GET http://clients2.google.com/x HTTP/1.1\r\nHost: clients2.google.com\r\n\r\n";
        assert_eq!(parse_request(b), Err(Error::NotConnect("GET".to_string())));
    }

    #[test]
    fn rejects_an_authority_without_a_port() {
        assert_eq!(
            parse_request(&head("a.example")),
            Err(Error::BadAuthority),
            "defaulting the port would turn a client bug into a silent misconnection"
        );
    }

    #[test]
    fn rejects_a_bad_port() {
        for target in [
            "a.example:0",
            "a.example:70000",
            "a.example:https",
            "a.example:",
        ] {
            assert_eq!(
                parse_request(&head(target)),
                Err(Error::BadAuthority),
                "{target}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_host() {
        assert_eq!(parse_request(&head(":443")), Err(Error::BadAuthority));
    }

    #[test]
    fn rejects_an_unbracketed_ipv6_literal_rather_than_guessing() {
        assert_eq!(
            parse_request(&head("2606:4700::1:443")),
            Err(Error::BadAuthority)
        );
    }

    #[test]
    fn rejects_a_truncated_request_line() {
        assert_eq!(parse_request(b"CONNECT\r\n\r\n"), Err(Error::Malformed));
        assert_eq!(
            parse_request(b"CONNECT a.example:443\r\n\r\n"),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn rejects_an_over_long_head_rather_than_reading_forever() {
        let mut b = b"CONNECT a.example:443 HTTP/1.1\r\nX: ".to_vec();
        b.extend(core::iter::repeat_n(b'a', MAX_HEAD + 1));
        assert_eq!(parse_request(&b), Err(Error::Malformed));
    }

    // ------------------------------------------------------------- dialect sniff

    #[test]
    fn recognises_connect_and_its_prefixes() {
        for s in [
            &b"C"[..],
            b"CON",
            b"CONNECT",
            b"connect",
            b"CONNECT a:1 HTTP/1.1\r\n",
        ] {
            assert!(looks_like(s), "{:?}", core::str::from_utf8(s));
        }
    }

    /// The whole point of the sniff: it must never claim a SOCKS greeting.
    #[test]
    fn never_mistakes_a_socks_greeting_for_connect() {
        assert!(!looks_like(&[0x05, 0x01, 0x00]));
        assert!(!looks_like(&[0x04, 0x01, 0x01, 0xBB]));
        assert!(!looks_like(b"GET / HTTP/1.1"));
        assert!(!looks_like(&[0x16, 0x03, 0x01]));
    }

    // ------------------------------------------------------------------ replies

    #[test]
    fn the_success_response_is_what_clients_wait_for() {
        assert!(RESPONSE_OK.starts_with(b"HTTP/1.1 200 "));
        assert!(RESPONSE_OK.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn error_responses_are_well_formed() {
        for code in [400u16, 405, 502, 504] {
            let r = error_response(code);
            let s = core::str::from_utf8(&r).unwrap();
            assert!(s.starts_with(&format!("HTTP/1.1 {code} ")), "{s}");
            assert!(s.ends_with("\r\n\r\n"), "{s}");
        }
    }

    /// No input, however hostile, may panic the protocol layer.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0xFEED_FACE_CAFE_1234u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 60) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            let _ = parse_request(&buf);
            let _ = looks_like(&buf);
        }
        // and specifically around the shape the parser walks
        for _ in 0..20_000 {
            let n = (next() % 60) as usize;
            let mut buf = b"CONNECT ".to_vec();
            buf.extend((0..n).map(|_| (next() & 0xFF) as u8));
            buf.extend_from_slice(b"\r\n\r\n");
            let _ = parse_request(&buf);
        }
    }
}
