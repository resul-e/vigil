//! SOCKS5 wire format — pure. No sockets, no I/O.
//!
//! Keeping the protocol layer free of I/O means every message shape, every truncation and
//! every malformed input can be exercised in a unit test that runs in milliseconds. The
//! server module below only moves bytes; it makes no protocol decisions of its own.
//!
//! SOCKS5 rather than HTTP CONNECT because Firefox keeps ECH working over SOCKS5 but not over
//! an HTTP proxy, and because SOCKS5 carries UDP ASSOCIATE if a later version needs it.
//!
//! RFC 1928.

use core::fmt;

pub const VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_UNACCEPTABLE: u8 = 0xFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not enough bytes yet — read more and call again. Never an error condition.
    Incomplete,
    /// Version byte was not 5.
    BadVersion(u8),
    /// A command we do not implement.
    UnsupportedCommand(u8),
    /// Address type byte was not 1, 3 or 4.
    UnsupportedAddressType(u8),
    /// A domain name that is not valid UTF-8, or a zero-length one.
    BadDomain,
    /// Structurally impossible, e.g. a greeting claiming zero methods.
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Incomplete => f.write_str("incomplete"),
            Error::BadVersion(v) => write!(f, "bad version {v:#04x}"),
            Error::UnsupportedCommand(c) => write!(f, "unsupported command {c:#04x}"),
            Error::UnsupportedAddressType(a) => write!(f, "unsupported address type {a:#04x}"),
            Error::BadDomain => f.write_str("bad domain"),
            Error::Malformed => f.write_str("malformed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    Connect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    V4([u8; 4]),
    /// Kept as a string because the whole point of this proxy is to see the hostname.
    Domain(String),
    V6([u8; 16]),
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(o) => write!(f, "{}.{}.{}.{}", o[0], o[1], o[2], o[3]),
            Addr::Domain(d) => f.write_str(d),
            Addr::V6(o) => {
                let groups: Vec<String> = o
                    .chunks(2)
                    .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                    .collect();
                write!(f, "[{}]", groups.join(":"))
            }
        }
    }
}

/// Reply codes. Only the ones we actually emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rep {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub cmd: Cmd,
    pub addr: Addr,
    pub port: u16,
}

impl Request {
    /// `host:port` as the upstream connector wants it.
    pub fn target(&self) -> String {
        // Bracketing for IPv6 lives in `impl fmt::Display for Addr`, so every variant formats
        // the same way here. This used to be a two-arm match with character-identical bodies.
        format!("{}:{}", self.addr, self.port)
    }
}

/// Parse the client greeting. Returns the offered methods and how many bytes were consumed.
pub fn parse_greeting(buf: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let ver = *buf.first().ok_or(Error::Incomplete)?;
    if ver != VERSION {
        return Err(Error::BadVersion(ver));
    }
    let n = *buf.get(1).ok_or(Error::Incomplete)? as usize;
    if n == 0 {
        // RFC 1928: NMETHODS is 1..255. Zero means the client offered nothing.
        return Err(Error::Malformed);
    }
    let end = 2 + n;
    if buf.len() < end {
        return Err(Error::Incomplete);
    }
    Ok((buf[2..end].to_vec(), end))
}

/// Choose a method from what the client offered.
pub fn select_method(offered: &[u8]) -> u8 {
    if offered.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_UNACCEPTABLE
    }
}

pub fn method_reply(method: u8) -> [u8; 2] {
    [VERSION, method]
}

/// Parse a CONNECT request. Returns the request and how many bytes were consumed.
pub fn parse_request(buf: &[u8]) -> Result<(Request, usize), Error> {
    let ver = *buf.first().ok_or(Error::Incomplete)?;
    if ver != VERSION {
        return Err(Error::BadVersion(ver));
    }
    let cmd = match *buf.get(1).ok_or(Error::Incomplete)? {
        0x01 => Cmd::Connect,
        other => return Err(Error::UnsupportedCommand(other)),
    };
    // buf[2] is RSV, ignored per RFC.
    let atyp = *buf.get(3).ok_or(Error::Incomplete)?;
    let (addr, after) = match atyp {
        0x01 => {
            let s = buf.get(4..8).ok_or(Error::Incomplete)?;
            (Addr::V4([s[0], s[1], s[2], s[3]]), 8)
        }
        0x03 => {
            let n = *buf.get(4).ok_or(Error::Incomplete)? as usize;
            if n == 0 {
                return Err(Error::BadDomain);
            }
            let s = buf.get(5..5 + n).ok_or(Error::Incomplete)?;
            let d = core::str::from_utf8(s).map_err(|_| Error::BadDomain)?;
            (Addr::Domain(d.to_string()), 5 + n)
        }
        0x04 => {
            let s = buf.get(4..20).ok_or(Error::Incomplete)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(s);
            (Addr::V6(o), 20)
        }
        other => return Err(Error::UnsupportedAddressType(other)),
    };
    let p = buf.get(after..after + 2).ok_or(Error::Incomplete)?;
    let port = u16::from_be_bytes([p[0], p[1]]);
    Ok((Request { cmd, addr, port }, after + 2))
}

/// Build a reply. The bound address is echoed as all-zero IPv4, which every client accepts
/// and which avoids leaking the proxy's own addressing.
pub fn reply(rep: Rep) -> [u8; 10] {
    [VERSION, rep as u8, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------- greeting

    #[test]
    fn greeting_with_no_auth() {
        let (methods, n) = parse_greeting(&[0x05, 0x01, 0x00]).unwrap();
        assert_eq!(methods, vec![0x00]);
        assert_eq!(n, 3);
        assert_eq!(select_method(&methods), METHOD_NO_AUTH);
    }

    #[test]
    fn greeting_with_several_methods_picks_no_auth() {
        let (m, n) = parse_greeting(&[0x05, 0x03, 0x02, 0x00, 0x01]).unwrap();
        assert_eq!(m, vec![0x02, 0x00, 0x01]);
        assert_eq!(n, 5);
        assert_eq!(select_method(&m), METHOD_NO_AUTH);
    }

    #[test]
    fn greeting_without_no_auth_is_rejected() {
        let (m, _) = parse_greeting(&[0x05, 0x01, 0x02]).unwrap();
        assert_eq!(select_method(&m), METHOD_UNACCEPTABLE);
    }

    #[test]
    fn every_prefix_of_a_greeting_says_incomplete() {
        let full = [0x05u8, 0x02, 0x00, 0x02];
        for n in 0..full.len() {
            assert_eq!(
                parse_greeting(&full[..n]),
                Err(Error::Incomplete),
                "prefix {n}"
            );
        }
        assert!(parse_greeting(&full).is_ok());
    }

    #[test]
    fn greeting_rejects_wrong_version() {
        assert_eq!(
            parse_greeting(&[0x04, 0x01, 0x00]),
            Err(Error::BadVersion(0x04))
        );
    }

    #[test]
    fn greeting_rejects_zero_methods() {
        assert_eq!(parse_greeting(&[0x05, 0x00]), Err(Error::Malformed));
    }

    #[test]
    fn greeting_consumes_only_its_own_bytes() {
        let buf = [0x05, 0x01, 0x00, 0xDE, 0xAD];
        let (_, n) = parse_greeting(&buf).unwrap();
        assert_eq!(n, 3, "must not swallow the request that follows");
    }

    // ---------------------------------------------------------------- request

    fn domain_req(host: &str, port: u16) -> Vec<u8> {
        let mut v = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    #[test]
    fn parses_a_domain_connect() {
        let b = domain_req("discord.com", 443);
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.cmd, Cmd::Connect);
        assert_eq!(r.addr, Addr::Domain("discord.com".into()));
        assert_eq!(r.port, 443);
        assert_eq!(n, b.len());
        assert_eq!(r.target(), "discord.com:443");
    }

    #[test]
    fn parses_an_ipv4_connect() {
        let b = [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB];
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.addr, Addr::V4([93, 184, 216, 34]));
        assert_eq!(r.port, 443);
        assert_eq!(n, 10);
        assert_eq!(r.target(), "93.184.216.34:443");
    }

    #[test]
    fn parses_an_ipv6_connect() {
        let mut b = vec![0x05, 0x01, 0x00, 0x04];
        b.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        b.extend_from_slice(&443u16.to_be_bytes());
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(n, 22);
        assert!(matches!(r.addr, Addr::V6(_)));
        assert!(r.target().starts_with('['), "v6 target must be bracketed");
    }

    #[test]
    fn every_prefix_of_every_request_shape_says_incomplete() {
        let mut v6 = vec![0x05, 0x01, 0x00, 0x04];
        v6.extend_from_slice(&[0u8; 16]);
        v6.extend_from_slice(&443u16.to_be_bytes());
        for full in [
            domain_req("discord.com", 443),
            vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB],
            v6,
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

    #[test]
    fn rejects_unsupported_commands() {
        for cmd in [0x02u8, 0x03, 0x00, 0xFF] {
            let b = [0x05, cmd, 0x00, 0x01, 1, 2, 3, 4, 0, 443u16 as u8];
            assert_eq!(
                parse_request(&b),
                Err(Error::UnsupportedCommand(cmd)),
                "cmd {cmd:#04x}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_address_types() {
        for atyp in [0x00u8, 0x02, 0x05, 0xFF] {
            let b = [0x05, 0x01, 0x00, atyp, 1, 2, 3, 4];
            assert_eq!(
                parse_request(&b),
                Err(Error::UnsupportedAddressType(atyp)),
                "atyp {atyp:#04x}"
            );
        }
    }

    #[test]
    fn rejects_a_zero_length_domain() {
        let b = [0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xBB];
        assert_eq!(parse_request(&b), Err(Error::BadDomain));
    }

    #[test]
    fn rejects_a_non_utf8_domain() {
        let b = [0x05, 0x01, 0x00, 0x03, 0x02, 0xFF, 0xFE, 0x01, 0xBB];
        assert_eq!(parse_request(&b), Err(Error::BadDomain));
    }

    #[test]
    fn request_consumes_only_its_own_bytes() {
        let mut b = domain_req("discord.com", 443);
        let want = b.len();
        b.extend_from_slice(b"\x16\x03\x01"); // the TLS flight that follows immediately
        let (_, n) = parse_request(&b).unwrap();
        assert_eq!(n, want, "must not swallow the client's first flight");
    }

    /// A domain of the maximum length must round-trip; the length byte is u8 so 255 is the
    /// ceiling and an off-by-one here truncates hostnames.
    #[test]
    fn handles_a_maximum_length_domain() {
        let host = "a".repeat(255);
        let b = domain_req(&host, 443);
        let (r, n) = parse_request(&b).unwrap();
        assert_eq!(r.addr, Addr::Domain(host));
        assert_eq!(n, b.len());
    }

    // ---------------------------------------------------------------- replies

    #[test]
    fn replies_are_well_formed() {
        let r = reply(Rep::Succeeded);
        assert_eq!(r[0], VERSION);
        assert_eq!(r[1], 0x00);
        assert_eq!(r[3], 0x01, "bound address is advertised as IPv4");
        assert_eq!(r.len(), 10);
    }

    #[test]
    fn failure_replies_carry_their_code() {
        for (rep, code) in [
            (Rep::GeneralFailure, 0x01),
            (Rep::HostUnreachable, 0x04),
            (Rep::ConnectionRefused, 0x05),
            (Rep::CommandNotSupported, 0x07),
            (Rep::AddressTypeNotSupported, 0x08),
        ] {
            assert_eq!(reply(rep)[1], code, "{rep:?}");
        }
    }

    #[test]
    fn method_reply_is_two_bytes() {
        assert_eq!(method_reply(METHOD_NO_AUTH), [0x05, 0x00]);
        assert_eq!(method_reply(METHOD_UNACCEPTABLE), [0x05, 0xFF]);
    }

    /// No input, however hostile, may panic the protocol layer.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 40) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            let _ = parse_greeting(&buf);
            let _ = parse_request(&buf);
        }
    }
}
