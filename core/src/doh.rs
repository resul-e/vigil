//! DNS over HTTPS, RFC 8484 — the pure half.
//!
//! Bytes in, bytes out: the request a DoH query is, and the rules for reading the response head
//! that comes back. No socket, no TLS, no clock. The transport that carries these bytes lives
//! where it can link rustls; this module is here so the decisions it encodes — *is this response
//! one we are willing to parse as a DNS message* — can be unit-tested on Linux against a table of
//! hand-written heads, and mutation-checked, which is not possible for logic that lives inside an
//! I/O loop.
//!
//! The DNS message itself needs nothing new. RFC 8484 carries **the same wire format** as
//! [`crate::dnsmsg`] already encodes and decodes; DoH is that message in an HTTP body. So a query
//! is [`crate::dnsmsg::encode_query`] and an answer is [`crate::dnsmsg::decode_answers`], and what
//! is added here is only the envelope.
//!
//! # Why this exists at all
//!
//! Today's resolver speaks plain DNS on an odd port, and it works because the interception on the
//! measured line filters the **port** rather than the protocol. That is a trick with a life
//! expectancy. DoH is the durable answer, and its first requirement decides this module's shape:
//! the server is addressed by **IP literal**, never by name, or DNS would need DNS.

use core::fmt;
use std::net::IpAddr;

/// The largest response head we will read before giving up.
///
/// Copied from the updater's HTTP client rather than invented: a head that never ends is how a
/// client is made to read forever, and the bound has to be checked *before* parsing rather than
/// after, or the parse is the thing that has already read too much.
pub const MAX_HEAD: usize = 16 * 1024;

/// The largest DNS message a DoH response may carry.
///
/// RFC 8484 §6: the `application/dns-message` media type "restricts the maximum size of the DNS
/// message to 65535 bytes", which is the two-byte length prefix DNS-over-TCP uses. A body larger
/// than this is not a big answer, it is something else.
pub const MAX_BODY: usize = 65_535;

/// The media type, exactly. Compared case-insensitively and without parameters.
pub const MEDIA_TYPE: &str = "application/dns-message";

/// Why a DoH exchange will not be read further.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The head is not a response we can parse at all.
    Malformed(String),
    /// A framing this client does not implement and will not guess at. Its own variant rather than
    /// a `Malformed` carrying a string, because the layer above maps **variants** to counters and
    /// matching on message text is how a mapping quietly stops firing.
    Chunked(String),
    /// The head passed [`MAX_HEAD`] without ending. A server that streams headers forever is how a
    /// client with a time bound and no byte bound still fills memory.
    HeadTooLong,
    /// The head arrived and the status is not 200. Carried rather than collapsed: a 403 from a
    /// resolver refusing us and a 502 from something in the middle are different findings.
    Status(u16),
    /// A 200 that is not a DNS message. The value is carried because the *content* of a wrong
    /// content type is the diagnosis: `text/html` is a block page, and a block page answering 200
    /// is exactly the shape a censor's sinkhole takes.
    NotDnsMessage(String),
    /// No `Content-Length`. There is no chunked decoder here and there will not be one; a DoH
    /// answer is a small, known-length message and anything else is a different protocol.
    LengthRequired,
    /// Longer than RFC 8484 permits.
    BodyTooLarge(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(w) => write!(f, "malformed response: {w}"),
            Error::Chunked(te) => write!(f, "Transfer-Encoding {te:?}, which is not implemented"),
            Error::HeadTooLong => write!(f, "head over {MAX_HEAD} B and still not finished"),
            Error::Status(s) => write!(f, "HTTP {s}"),
            Error::NotDnsMessage(t) => write!(f, "content-type {t:?}, not {MEDIA_TYPE}"),
            Error::LengthRequired => f.write_str("no Content-Length"),
            Error::BodyTooLarge(n) => write!(f, "body {n} B, over the {MAX_BODY} B limit"),
        }
    }
}

/// The `Host` header for an address literal.
///
/// A v6 address is bracketed, per RFC 3986 §3.2.2. Not decoration: an unbracketed v6 address in a
/// `Host` header contains colons that read as a port separator, and the request is then either
/// refused or, worse, routed somewhere else.
pub fn host_header(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// The bytes of an RFC 8484 POST.
///
/// **POST and not GET**, deliberately. The GET form base64url-encodes the query into the URL,
/// which buys HTTP cache friendliness — worth nothing here, because the resolver already keeps its
/// own cache and every query goes to a fixed IP over a connection we opened — and costs a
/// variable-length URL that is one more thing distinguishable on the wire. POST's body is the wire
/// format unmodified: RFC 8484 §6, "the message MUST NOT be encoded".
///
/// `Connection: close` because this is one query per connection. Reusing a connection across
/// queries is a real saving and a real hazard — shared mutable state across the threads
/// [`crate::dnsmsg`]'s callers run on — so it is a separate change with its own gate, not a
/// property smuggled in here.
pub fn request(host_header: &str, path: &str, query: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Accept: {MEDIA_TYPE}\r\n\
         Content-Type: {MEDIA_TYPE}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        query.len()
    );
    let mut out = Vec::with_capacity(head.len() + query.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(query);
    out
}

/// What a response head said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub content_length: Option<u64>,
    /// Lower-cased, with any parameters after the first `;` removed — `application/dns-message`
    /// and `application/dns-message; charset=utf-8` are the same media type and one of them
    /// arriving must not be read as a different protocol.
    pub content_type: Option<String>,
    /// Where the body starts.
    pub head_len: usize,
}

/// Parse a response head out of `buf`, if all of it has arrived.
///
/// `Ok(None)` means "not yet" — keep reading. `Err` means this is not a response we will act on.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, Error> {
    if buf.len() > MAX_HEAD {
        return Err(Error::HeadTooLong);
    }
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let text = core::str::from_utf8(&buf[..end])
        .map_err(|_| Error::Malformed("head is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::Malformed("no status line".into()))?;

    let mut parts = status_line.split(' ');
    let version = parts
        .next()
        .ok_or_else(|| Error::Malformed("no version".into()))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Error::Malformed(format!("version {version:?}")));
    }
    let code = parts
        .next()
        .ok_or_else(|| Error::Malformed("no status code".into()))?;
    if code.len() != 3 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::Malformed(format!("status {code:?}")));
    }
    let status: u16 = code
        .parse()
        .map_err(|_| Error::Malformed(format!("status {code:?}")))?;

    let mut content_length = None;
    let mut content_type = None;
    let mut transfer_encoding = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Malformed(format!("header {line:?}")));
        };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| Error::Malformed(format!("Content-Length {value:?}")))?;
                // Two different Content-Lengths is a request-smuggling shape, not a quirk.
                if content_length.is_some_and(|prev| prev != n) {
                    return Err(Error::Malformed("two Content-Lengths".into()));
                }
                content_length = Some(n);
            }
            "content-type" => {
                let v = value.split(';').next().unwrap_or("").trim();
                content_type = Some(v.to_ascii_lowercase());
            }
            "transfer-encoding" => transfer_encoding = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    // No chunked decoder, and no silent fallback into one either.
    if let Some(te) = transfer_encoding {
        if te != "identity" {
            return Err(Error::Chunked(te));
        }
    }

    Ok(Some(Head {
        status,
        content_length,
        content_type,
        head_len: end + 4,
    }))
}

/// **The one place a DoH response is accepted or refused**, and the body length it promises.
///
/// A separate function on purpose. In the client this logic was copied from it lives inside the
/// read loop, where no unit test can reach it — so the checks that decide whether a censor's block
/// page gets parsed as a DNS answer were, structurally, untested. Here every arm is a table row.
///
/// The order matters and is asserted: status first, because a 403 is a refusal whatever it carries;
/// then the media type, because a 200 `text/html` is the sinkhole shape; then the length.
pub fn accept(head: &Head) -> Result<usize, Error> {
    if head.status != 200 {
        return Err(Error::Status(head.status));
    }
    let ct = head.content_type.as_deref().unwrap_or("");
    if ct != MEDIA_TYPE {
        return Err(Error::NotDnsMessage(ct.to_string()));
    }
    let Some(n) = head.content_length else {
        return Err(Error::LengthRequired);
    };
    if n > MAX_BODY as u64 {
        return Err(Error::BodyTooLarge(n));
    }
    Ok(n as usize)
}

/// The body, once all of it has arrived. `None` means keep reading.
pub fn body_of<'a>(buf: &'a [u8], head: &Head) -> Option<&'a [u8]> {
    let n = head.content_length? as usize;
    let end = head.head_len.checked_add(n)?;
    (buf.len() >= end).then(|| &buf[head.head_len..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn head_of(text: &str) -> Head {
        parse_head(text.as_bytes())
            .expect("parses")
            .expect("complete")
    }

    /// **The example from the RFC, byte for byte.**
    ///
    /// RFC 8484 §4.1.1 gives the wire bytes for a query for `www.example.com`, and this asserts
    /// that `dnsmsg` already emits exactly them — which is the claim the whole design rests on:
    /// DoH needs no new codec, only an envelope.
    #[test]
    fn the_rfc8484_post_example_is_reproduced_byte_for_byte() {
        let q = crate::dnsmsg::encode_query("www.example.com", 0).expect("encodes");
        assert_eq!(
            q,
            vec![
                0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
                0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
                0x00, 0x00, 0x01, 0x00, 0x01,
            ],
            "RFC 8484 §4.1.1"
        );

        let req = request("1.1.1.1", "/dns-query", &q);
        let text = String::from_utf8_lossy(&req).to_string();
        assert!(text.starts_with("POST /dns-query HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Host: 1.1.1.1\r\n"), "{text}");
        assert!(
            text.contains("Accept: application/dns-message\r\n"),
            "{text}"
        );
        assert!(
            text.contains("Content-Type: application/dns-message\r\n"),
            "{text}"
        );
        assert!(text.contains("Content-Length: 33\r\n"), "{text}");
        assert!(req.ends_with(&q), "the body is the wire format, unmodified");
    }

    /// The id is 0, and that is a protocol requirement rather than a habit: RFC 8484 §4.1 says a
    /// client "SHOULD use a DNS ID of 0 in every DNS request", because the HTTP exchange already
    /// pairs the answer with the question and a varying id defeats HTTP caching for no gain.
    #[test]
    fn the_query_id_is_zero() {
        let q = crate::dnsmsg::encode_query("example.com", 0).expect("encodes");
        assert_eq!(&q[..2], &[0, 0]);
    }

    /// Each refusal asserted by **variant**, not by `is_err()`. Asserting only that something
    /// failed lets a neighbouring check cover for a deleted one, and then the mutation that removes
    /// a check stays green.
    #[test]
    fn accept_refuses_each_thing_it_must() {
        let base = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 33\r\n\r\n";
        assert_eq!(accept(&head_of(base)), Ok(33));

        let bad_status = head_of(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/dns-message\r\nContent-Length: 33\r\n\r\n",
        );
        assert_eq!(accept(&bad_status), Err(Error::Status(500)));

        let html =
            head_of("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 33\r\n\r\n");
        assert_eq!(accept(&html), Err(Error::NotDnsMessage("text/html".into())));

        let no_len = head_of("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n");
        assert_eq!(accept(&no_len), Err(Error::LengthRequired));

        let too_big = head_of(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 65536\r\n\r\n",
        );
        assert_eq!(accept(&too_big), Err(Error::BodyTooLarge(65536)));

        // Parameters are not a different media type.
        let with_charset = head_of(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message; charset=x\r\nContent-Length: 65535\r\n\r\n",
        );
        assert_eq!(accept(&with_charset), Ok(65535));

        // A 200 with no content type at all is not a DNS message either.
        let bare = head_of("HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n");
        assert_eq!(accept(&bare), Err(Error::NotDnsMessage(String::new())));
    }

    /// A 403 that also happens to be HTML must report the **status**, not the type. Which check
    /// fires first is the difference between "the resolver refused us" and "something answered for
    /// it", and those lead to different next steps.
    #[test]
    fn the_status_is_read_before_the_media_type() {
        let h = head_of(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 9\r\n\r\n",
        );
        assert_eq!(accept(&h), Err(Error::Status(403)));
    }

    #[test]
    fn chunked_is_refused() {
        let r = parse_head(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert!(matches!(r, Err(Error::Chunked(_))), "{r:?}");
        // `identity` is the one value that is not a different framing.
        let ok = parse_head(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: identity\r\nContent-Length: 1\r\n\r\n",
        );
        assert!(ok.is_ok(), "{ok:?}");
    }

    #[test]
    fn contradictory_content_lengths_are_refused() {
        let r = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\nContent-Length: 34\r\n\r\n");
        assert!(matches!(r, Err(Error::Malformed(_))), "{r:?}");
        // The same length twice is a duplicate, not a smuggle.
        let same =
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\nContent-Length: 33\r\n\r\n");
        assert!(same.is_ok(), "{same:?}");
    }

    /// Every prefix of a real head must read as "not yet" and never as an error or a `Head`.
    /// A parser that decides early is a parser that decides on half a header.
    #[test]
    fn every_prefix_of_a_head_is_not_yet() {
        let full = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 33\r\n\r\n";
        for i in 0..full.len() - 1 {
            assert_eq!(
                parse_head(&full[..i]),
                Ok(None),
                "prefix of {i} bytes decided something"
            );
        }
        assert!(parse_head(full).expect("parses").is_some());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..2000 {
            let mut buf = Vec::new();
            for _ in 0..(seed as usize % 200) {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                buf.push((seed >> 33) as u8);
            }
            let _ = parse_head(&buf);
        }
        assert_eq!(parse_head(&[b'\r'; MAX_HEAD + 1]), Err(Error::HeadTooLong));
    }

    #[test]
    fn a_v6_endpoint_gets_a_bracketed_host_header() {
        assert_eq!(
            host_header(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            "1.1.1.1"
        );
        assert_eq!(
            host_header(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
            ))),
            "[2606:4700:4700::1111]"
        );
    }

    #[test]
    fn the_body_is_only_handed_over_once_all_of_it_is_there() {
        let head_text =
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\n";
        let h = head_of(head_text);
        let mut buf = head_text.as_bytes().to_vec();
        assert_eq!(body_of(&buf, &h), None, "no body yet");
        buf.extend_from_slice(&[1, 2, 3]);
        assert_eq!(body_of(&buf, &h), None, "still short");
        buf.push(4);
        assert_eq!(body_of(&buf, &h), Some(&[1u8, 2, 3, 4][..]));
        // Extra bytes after the body are ignored rather than returned.
        buf.push(5);
        assert_eq!(body_of(&buf, &h), Some(&[1u8, 2, 3, 4][..]));
    }
}
