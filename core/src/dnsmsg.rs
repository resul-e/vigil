//! DNS message encoding and decoding. Pure — no sockets, no clock.
//!
//! This exists because the system resolver cannot be trusted. Measured on Türk Telekom,
//! 2026-08-04: the ISP resolver answered `discord.com`, `updates.discord.com`,
//! `cdn.discordapp.com`, `roblox.com` and `4chan.org` with `195.175.254.2` — its own block
//! page — and outbound queries for exactly those names to `1.1.1.1`, `9.9.9.9` and `8.8.8.8`
//! were dropped, while queries for other names on the same line at the same moment were
//! answered normally.
//!
//! `vigil --split` went from 10/10 to 0/8 that day without a line of code changing, because
//! it was dialling a block page. That is the same failure that ended iteration #1 on its
//! second machine in January.
//!
//! A resolver that speaks this can therefore ask somebody else, on a port the interception
//! does not cover. Sixty lines and no dependency — a DoH client would need TLS, and TLS would
//! need a dependency this crate does not have and does not want.
//!
//! RFC 1035.

use std::net::Ipv4Addr;

/// Resolvers that are not the subscriber's ISP. Queried on plain UDP/53, which is itself
/// informative: Turkish ISPs are documented to intercept that port, so no answer at all is a
/// finding rather than an error.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The name could not be put on the wire (empty, over-long, bad label).
    BadName,
    /// The response was not a well-formed answer to our question.
    Malformed,
    /// A well-formed response carrying no A record.
    NoAddress,
    /// Nothing came back.
    NoReply,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::BadName => "bad name",
            Error::Malformed => "malformed response",
            Error::NoAddress => "no A record",
            Error::NoReply => "no reply",
        })
    }
}

/// Build a standard recursive A query for `host`.
///
/// `id` is supplied rather than generated so the encoder stays pure and a golden test can
/// pin the exact bytes.
pub fn encode_query(host: &str, id: u16) -> Result<Vec<u8>, Error> {
    if host.is_empty() || host.len() > 253 {
        return Err(Error::BadName);
    }
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // one question
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // no an/ns/ar

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::BadName);
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&[0x00, 0x01]); // A
    q.extend_from_slice(&[0x00, 0x01]); // IN
    Ok(q)
}

/// Walk a (possibly compressed) name and return the offset just past it.
///
/// Compression pointers are followed only far enough to skip the name; a pointer that does
/// not advance is refused rather than followed, because a self-referential one is how a
/// malicious response turns a parser into an infinite loop.
fn skip_name(buf: &[u8], mut at: usize) -> Result<usize, Error> {
    let mut hops = 0;
    loop {
        let len = *buf.get(at).ok_or(Error::Malformed)? as usize;
        if len == 0 {
            return Ok(at + 1);
        }
        if len & 0xC0 == 0xC0 {
            // A pointer ends the name at this level, and is always two bytes.
            buf.get(at + 1).ok_or(Error::Malformed)?;
            return Ok(at + 2);
        }
        at += 1 + len;
        hops += 1;
        if hops > 128 || at > buf.len() {
            return Err(Error::Malformed);
        }
    }
}

/// Extract every A record from a response to a query with this `id`.
pub fn decode_answers(buf: &[u8], id: u16) -> Result<Vec<Ipv4Addr>, Error> {
    if buf.len() < 12 {
        return Err(Error::Malformed);
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != id {
        // Not an answer to what we asked. Treating it as one is how an off-path spoofer gets
        // its answer accepted.
        return Err(Error::Malformed);
    }
    if buf[2] & 0x80 == 0 {
        return Err(Error::Malformed); // not a response
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut at = 12;
    for _ in 0..qd {
        at = skip_name(buf, at)?;
        at = at.checked_add(4).ok_or(Error::Malformed)?; // qtype + qclass
    }

    let mut out = Vec::new();
    for _ in 0..an {
        at = skip_name(buf, at)?;
        let head = buf.get(at..at + 10).ok_or(Error::Malformed)?;
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let rdlen = u16::from_be_bytes([head[8], head[9]]) as usize;
        at += 10;
        let data = buf.get(at..at + rdlen).ok_or(Error::Malformed)?;
        if rtype == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        at += rdlen;
    }
    if out.is_empty() {
        return Err(Error::NoAddress);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// The other direction: reading a query and writing an answer.
//
// vigil answers DNS for the whole machine, not only for traffic that goes through its proxy.
// Measured 2026-08-05: the Roblox client ignores the system proxy setting entirely, so on a
// line whose resolver answers `roblox.com` with the block page it was being sent to the
// censor before a single TLS byte was written. A program that reads neither the proxy setting
// nor the environment variables can still be given an honest address.
//
// The parser below reads packets from anything on the machine that asks. It is therefore the
// only part of this crate that faces hostile input by design, which is why it bounds
// everything and why `arbitrary_inputs_never_panic` exists at the bottom of this file.
// ---------------------------------------------------------------------------------------

/// The question a client asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    /// The name, lower-cased, without the trailing root dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset just past the question, so a response can echo it byte for byte.
    pub end: usize,
    /// Whether the client wants us to recurse. Echoed back; no client here ever clears it.
    pub recursion_desired: bool,
}

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// Response codes, the two this server ever sends.
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;

/// Read the question out of a query.
///
/// Refuses compression pointers in a *question*: no real client sends one — there is nothing
/// earlier in the packet to point at — and following one here is how a crafted packet gets a
/// parser to walk backwards through itself.
pub fn parse_question(buf: &[u8]) -> Result<Question, Error> {
    if buf.len() < 12 {
        return Err(Error::Malformed);
    }
    if buf[2] & 0x80 != 0 {
        return Err(Error::Malformed); // a response, not a query
    }
    if u16::from_be_bytes([buf[4], buf[5]]) != 1 {
        // Exactly one question. Zero is nothing to answer; more than one is not a thing real
        // clients send and not a thing this server will guess at.
        return Err(Error::Malformed);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let recursion_desired = buf[2] & 0x01 != 0;

    let mut name = String::new();
    let mut at = 12usize;
    loop {
        let len = *buf.get(at).ok_or(Error::Malformed)? as usize;
        if len & 0xC0 != 0 {
            return Err(Error::Malformed); // pointer, or reserved bits
        }
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 || name.len() + len > 253 {
            return Err(Error::BadName);
        }
        let label = buf.get(at..at + len).ok_or(Error::Malformed)?;
        // A label is bytes, not text. Anything that is not a plausible host character makes
        // this not a name we are willing to answer for.
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err(Error::BadName);
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        at += len;
    }
    let tail = buf.get(at..at + 4).ok_or(Error::Malformed)?;
    if name.is_empty() {
        return Err(Error::BadName);
    }
    Ok(Question {
        id,
        name,
        qtype: u16::from_be_bytes([tail[0], tail[1]]),
        qclass: u16::from_be_bytes([tail[2], tail[3]]),
        end: at + 4,
        recursion_desired,
    })
}

/// Build a response to `query` carrying `addrs`, or none of them.
///
/// An empty `addrs` with `RCODE_NOERROR` is a NODATA answer: "this name exists, just not with
/// the record you asked for". That is the correct reply to an `AAAA` question from a resolver
/// that only does `A`, and answering `NXDOMAIN` instead would tell the client the name does
/// not exist at all — which on Windows makes it stop asking for the `A` record too.
pub fn encode_response(
    query: &[u8],
    q: &Question,
    addrs: &[Ipv4Addr],
    ttl: u32,
    rcode: u8,
) -> Result<Vec<u8>, Error> {
    let question = query.get(12..q.end).ok_or(Error::Malformed)?;
    let mut r = Vec::with_capacity(q.end + addrs.len() * 16);
    r.extend_from_slice(&q.id.to_be_bytes());
    // QR=1, opcode 0, AA=0, TC=0, RD echoed | RA=1, rcode
    r.push(0x80 | u8::from(q.recursion_desired));
    r.push(0x80 | (rcode & 0x0F));
    r.extend_from_slice(&1u16.to_be_bytes()); // one question, echoed
    r.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]); // no authority, no additional
    r.extend_from_slice(question);

    for a in addrs {
        // A pointer back to the question's name, which is always at offset 12.
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&TYPE_A.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&a.octets());
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // ------------------------------------------------- answering, not only asking

    /// A query we built ourselves must parse back to the question we put in it. The two
    /// halves of this module have to agree, or the server answers a different name than the
    /// one that was asked for.
    #[test]
    fn a_query_round_trips_through_the_parser() {
        for host in [
            "discord.com",
            "a.co",
            "apis.roblox.com",
            "updates.discord.com",
            "sin6c2-128-116-46-3.roblox.com",
        ] {
            let q = encode_query(host, 0x1234).unwrap();
            let parsed = parse_question(&q).unwrap();
            assert_eq!(parsed.name, host);
            assert_eq!(parsed.id, 0x1234);
            assert_eq!(parsed.qtype, TYPE_A);
            assert_eq!(parsed.qclass, CLASS_IN);
            assert_eq!(
                parsed.end,
                q.len(),
                "question must end where the query does"
            );
            assert!(parsed.recursion_desired);
        }
    }

    #[test]
    fn a_name_is_lower_cased_so_the_cache_cannot_be_split_by_case() {
        let mut q = encode_query("Discord.COM", 1).unwrap();
        // encode_query preserves case on the wire; the parser is what normalises.
        assert_eq!(parse_question(&q).unwrap().name, "discord.com");
        q[2] |= 0x80;
        assert_eq!(
            parse_question(&q),
            Err(Error::Malformed),
            "a response is not a query"
        );
    }

    /// Everything a hostile packet can be, refused rather than trusted.
    #[test]
    fn malformed_queries_are_refused_one_by_one() {
        let good = encode_query("discord.com", 7).unwrap();

        assert_eq!(parse_question(&[]), Err(Error::Malformed), "empty");
        assert_eq!(
            parse_question(&good[..8]),
            Err(Error::Malformed),
            "truncated header"
        );
        assert_eq!(
            parse_question(&good[..good.len() - 2]),
            Err(Error::Malformed),
            "truncated qtype/qclass"
        );

        // A compression pointer in the question: nothing legitimate sends one.
        let mut ptr = good.clone();
        ptr[12] = 0xC0;
        ptr[13] = 0x0C;
        assert_eq!(
            parse_question(&ptr),
            Err(Error::Malformed),
            "pointer in question"
        );

        // A label that claims more bytes than the packet holds.
        let mut over = good.clone();
        over[12] = 63;
        assert_eq!(
            parse_question(&over),
            Err(Error::Malformed),
            "label past the end"
        );

        // Two questions: not answered rather than half-answered.
        let mut two = good.clone();
        two[5] = 2;
        assert_eq!(parse_question(&two), Err(Error::Malformed), "two questions");

        // Zero questions.
        let mut none = good.clone();
        none[5] = 0;
        assert_eq!(parse_question(&none), Err(Error::Malformed), "no question");

        // The root, which is a question we have no answer for.
        let root = [0u8, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        assert_eq!(parse_question(&root), Err(Error::BadName), "root");
    }

    /// A response has to be a response: the client checks the id and the QR bit, and a server
    /// that gets either wrong is one whose answers are silently dropped.
    #[test]
    fn a_response_answers_the_question_it_was_asked() {
        let q = encode_query("discord.com", 0xBEEF).unwrap();
        let question = parse_question(&q).unwrap();
        let addrs = [v4(162, 159, 138, 232), v4(162, 159, 136, 232)];
        let r = encode_response(&q, &question, &addrs, 60, RCODE_NOERROR).unwrap();

        assert_eq!(&r[0..2], &[0xBE, 0xEF], "id must be echoed");
        assert_eq!(r[2] & 0x80, 0x80, "QR must say response");
        assert_eq!(r[3] & 0x0F, 0, "rcode NOERROR");
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 1, "question echoed");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 2, "two answers");

        // And our own decoder — the one the resolver uses — reads it back.
        assert_eq!(decode_answers(&r, 0xBEEF).unwrap(), addrs.to_vec());
    }

    /// The AAAA case, which is not a detail: answering NXDOMAIN there makes Windows stop
    /// asking for the A record as well, and the name goes dark on a machine we were fixing.
    #[test]
    fn no_addresses_is_a_nodata_answer_not_a_nonexistent_name() {
        let q = encode_query("discord.com", 3).unwrap();
        let question = parse_question(&q).unwrap();
        let r = encode_response(&q, &question, &[], 60, RCODE_NOERROR).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_NOERROR, "must not be NXDOMAIN");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no answers");
        assert_eq!(decode_answers(&r, 3), Err(Error::NoAddress));
    }

    #[test]
    fn servfail_carries_no_answers_and_says_so() {
        let q = encode_query("discord.com", 9).unwrap();
        let question = parse_question(&q).unwrap();
        let r = encode_response(&q, &question, &[], 0, RCODE_SERVFAIL).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_SERVFAIL);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0);
    }

    /// The parser reads packets from anything on the machine. No input, however hostile, may
    /// panic it — a panic in the DNS thread takes the machine's name resolution with it.
    #[test]
    fn arbitrary_inputs_never_panic() {
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let good = encode_query("discord.com", 1).unwrap();
        for _ in 0..40_000 {
            let n = (next() % 600) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            let _ = parse_question(&buf);
            if let Ok(q) = parse_question(&buf) {
                let _ = encode_response(&buf, &q, &[v4(1, 2, 3, 4)], 60, RCODE_NOERROR);
            }

            // And the same again with a real query corrupted at one byte, which is the shape
            // of input most likely to get past a shallow check.
            let mut bent = good.clone();
            let i = (next() as usize) % bent.len();
            bent[i] = (next() & 0xFF) as u8;
            if let Ok(q) = parse_question(&bent) {
                let _ = encode_response(&bent, &q, &[v4(1, 2, 3, 4)], 60, RCODE_NOERROR);
            }
        }
    }

    /// A question parsed out of one packet must never be used to slice another: `end` is an
    /// offset into the buffer it came from, and mixing them is how a server reads memory that
    /// belongs to a different question.
    #[test]
    fn encoding_against_a_shorter_buffer_fails_instead_of_slicing_wildly() {
        let long = encode_query("a-very-long-name.example.com", 1).unwrap();
        let q = parse_question(&long).unwrap();
        let short = encode_query("a.co", 1).unwrap();
        assert_eq!(
            encode_response(&short, &q, &[], 60, RCODE_NOERROR),
            Err(Error::Malformed)
        );
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
}
