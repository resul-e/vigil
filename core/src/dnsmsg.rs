//! DNS message encoding and decoding. Pure — no sockets, no clock.
//!
//! This exists because the system resolver cannot be trusted. Measured on the home line,
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
    /// A well-formed response carrying no A record: NOERROR with an empty answer section
    /// (NODATA), or NXDOMAIN. **An authoritative "there is nothing here."**
    NoAddress,
    /// The server answered that it could not answer: SERVFAIL, REFUSED, NOTIMP, FORMERR.
    ///
    /// This is **not** [`Self::NoAddress`] and the distinction is the whole point of the variant.
    /// On the wire the two are the same shape — our id, QR set, one question, zero answers — so
    /// until this existed a rate-limited or DNSSEC-failing upstream was recorded as an
    /// authoritative "this name does not exist". The caller's fallback sweep exists precisely so
    /// that one bad upstream cannot take a name down, and the sweep stops on an authoritative no:
    /// so one REFUSED from the first resolver stopped the sweep, was negative-cached for 20 s,
    /// and every program on the machine got SERVFAIL for a name the next resolver would have
    /// answered correctly.
    SoftFailure,
    /// Nothing came back.
    NoReply,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::BadName => "bad name",
            Error::Malformed => "malformed response",
            Error::NoAddress => "no A record",
            Error::SoftFailure => "server could not answer",
            Error::NoReply => "no reply",
        })
    }
}

/// HTTPS/SVCB. **Carries the ECH parameter**, and vigil's own DNS server answers it with NODATA
/// today — which is not "we did not look", it is "this name has no HTTPS record", and a browser
/// told that turns ECH off.
pub const TYPE_HTTPS: u16 = 65;

/// Build a standard recursive A query for `host`.
///
/// `id` is supplied rather than generated so the encoder stays pure and a golden test can
/// pin the exact bytes.
pub fn encode_query(host: &str, id: u16) -> Result<Vec<u8>, Error> {
    encode_query_type(host, id, TYPE_A)
}

/// The same, for any question type.
///
/// Separate because nothing on Windows can ask a type-65 question: `nslookup`'s type table has no
/// `HTTPS`, and PowerShell's `Resolve-DnsName` refuses the number — measured 2026-09-07, it lists
/// its accepted values and 65 is not among them. So the only way to find out what a resolver says
/// about an HTTPS record on this machine is to build the query here.
pub fn encode_query_type(host: &str, id: u16, qtype: u16) -> Result<Vec<u8>, Error> {
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
    q.extend_from_slice(&qtype.to_be_bytes());
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
    // Byte 3's low nibble is the rcode, and reading it is the difference between "this name does
    // not exist" and "this server is having a bad day". Only NOERROR (0 — NODATA when the answer
    // section is empty) and NXDOMAIN (3) are answers *about the name*; everything else is the
    // server declining, and telling the caller that a name is absent on the strength of a REFUSED
    // is how one rate-limited upstream takes a hostname down for the whole machine.
    //
    // After the id check above, deliberately: a forged failure carrying somebody else's id stays
    // `Malformed` rather than becoming a cheap way to make us give up on a name.
    let rcode = buf[3] & 0x0F;
    if rcode != 0 && rcode != 3 {
        return Err(Error::SoftFailure);
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

/// EDNS(0)'s pseudo-record. **Its TTL field is not a TTL** — it carries EXTENDED-RCODE, VERSION,
/// the DO bit and Z (RFC 6891 §6.1.3) — so anything that walks records rewriting TTLs has to skip
/// it or it corrupts the flags into a duration.
pub const TYPE_OPT: u16 = 41;

/// Put a different id on a message already on the wire.
///
/// `Err` under two bytes rather than a panic: this runs on whatever a resolver sent back.
pub fn set_id(buf: &mut [u8], id: u16) -> Result<(), Error> {
    let head = buf.get_mut(..2).ok_or(Error::Malformed)?;
    head.copy_from_slice(&id.to_be_bytes());
    Ok(())
}

/// Is this response an answer to **this** question, safe to hand back unchanged?
///
/// **Not `parse_question`**, and that is the landmine on this path: `parse_question` refuses a
/// message with QR set, because it exists to read *queries*. Everything here has QR set. So the
/// question is read at offset 12 by hand.
///
/// `TC` is refused: a truncated answer is a *partial* SvcParams set, and forwarding one as complete
/// is worse than not forwarding at all — a browser would act on half a record.
pub fn validate_response(buf: &[u8], expected_id: u16, q: &Question) -> Result<(), Error> {
    if buf.len() < 12 {
        return Err(Error::Malformed);
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != expected_id {
        return Err(Error::Malformed);
    }
    if buf[2] & 0x80 == 0 {
        return Err(Error::Malformed); // not a response
    }
    if buf[2] & 0x02 != 0 {
        return Err(Error::Malformed); // truncated
    }
    match buf[3] & 0x0F {
        0 | 3 => {}
        // The server answered about itself, not about the name. Same distinction the A path draws.
        _ => return Err(Error::SoftFailure),
    }
    if u16::from_be_bytes([buf[4], buf[5]]) != 1 {
        return Err(Error::Malformed);
    }
    // The echoed question, read by hand because the response has QR set.
    let mut name = String::new();
    let mut at = 12usize;
    loop {
        let len = *buf.get(at).ok_or(Error::Malformed)? as usize;
        if len & 0xC0 != 0 {
            return Err(Error::Malformed);
        }
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 || name.len() + len > 253 {
            return Err(Error::BadName);
        }
        let label = buf.get(at..at + len).ok_or(Error::Malformed)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        at += len;
    }
    let tail = buf.get(at..at + 4).ok_or(Error::Malformed)?;
    if name != q.name
        || u16::from_be_bytes([tail[0], tail[1]]) != q.qtype
        || u16::from_be_bytes([tail[2], tail[3]]) != q.qclass
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Cap every record's TTL at `max`, in place, without touching anything else.
///
/// **`min`, never assignment**: a TTL of 0 means "do not cache this" and raising it to `max` would
/// be inventing a promise the origin refused to make.
///
/// **`TYPE_OPT` is skipped**, because its TTL field is not a TTL.
///
/// Compression pointers and record data are never rewritten, so an `ech` SvcParam survives by
/// construction — this function moves four bytes per record and nothing else.
pub fn clamp_ttls(buf: &mut [u8], max: u32) -> Result<(), Error> {
    if buf.len() < 12 {
        return Err(Error::Malformed);
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let records = (u16::from_be_bytes([buf[6], buf[7]]) as usize)
        + (u16::from_be_bytes([buf[8], buf[9]]) as usize)
        + (u16::from_be_bytes([buf[10], buf[11]]) as usize);

    let mut at = 12usize;
    for _ in 0..qd {
        at = skip_name(buf, at)?;
        at = at.checked_add(4).ok_or(Error::Malformed)?;
        if at > buf.len() {
            return Err(Error::Malformed);
        }
    }
    for _ in 0..records {
        at = skip_name(buf, at)?;
        // type(2) class(2) ttl(4) rdlength(2)
        let head = buf.get(at..at + 10).ok_or(Error::Malformed)?;
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let rdlen = u16::from_be_bytes([head[8], head[9]]) as usize;
        if rtype != TYPE_OPT {
            let ttl = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
            let capped = ttl.min(max);
            if capped != ttl {
                buf[at + 4..at + 8].copy_from_slice(&capped.to_be_bytes());
            }
        }
        at = at
            .checked_add(10 + rdlen)
            .filter(|end| *end <= buf.len())
            .ok_or(Error::Malformed)?;
    }
    Ok(())
}

/// Make an upstream's response safe to hand to the client that asked.
///
/// **The order is the whole function.** Validate against the id the *upstream* was asked with,
/// then put the client's id on, then clamp. Validating after restoring the id checks the message
/// against an id it was never sent with, which is no check at all.
pub fn rewrite_forwarded(
    buf: &mut [u8],
    upstream_id: u16,
    client_id: u16,
    q: &Question,
    max_ttl: u32,
) -> Result<(), Error> {
    validate_response(buf, upstream_id, q)?;
    set_id(buf, client_id)?;
    clamp_ttls(buf, max_ttl)
}

/// The SvcParamKeys in an HTTPS/SVCB record's rdata, in order.
///
/// Only for looking: it proves a fixture really carries key 5 (`ech`) rather than being assumed to,
/// and it lets an instrument say what a record contained. Nothing rewrites these.
pub fn https_svcparam_keys(rdata: &[u8]) -> Result<Vec<u16>, Error> {
    // priority(2), then an uncompressed TargetName, then (key, len, value) triples.
    let mut at = 2usize;
    loop {
        let len = *rdata.get(at).ok_or(Error::Malformed)? as usize;
        if len & 0xC0 != 0 {
            return Err(Error::Malformed); // no compression in SVCB TargetName
        }
        at += 1;
        if len == 0 {
            break;
        }
        at = at.checked_add(len).ok_or(Error::Malformed)?;
    }
    let mut keys = Vec::new();
    while at < rdata.len() {
        let head = rdata.get(at..at + 4).ok_or(Error::Malformed)?;
        keys.push(u16::from_be_bytes([head[0], head[1]]));
        let vlen = u16::from_be_bytes([head[2], head[3]]) as usize;
        at = at
            .checked_add(4 + vlen)
            .filter(|end| *end <= rdata.len())
            .ok_or(Error::Malformed)?;
    }
    Ok(keys)
}

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

    // ------------------------------------------------------------- forwarding type 65

    /// A hand-built HTTPS/SVCB response with all four sections, an **`ech` parameter**, and an
    /// EDNS OPT record whose TTL field is not a TTL.
    ///
    /// Offsets, computed by hand and asserted below so a mistake here cannot pass quietly:
    ///   12   question `cloudflare.com` / 65 / IN, 16 name bytes + 4 = 20 -> ends at 32
    ///   32   AN  ptr(2) type(2) class(2) TTL@38 rdlen@42 rdata@44..86   (rdlen 42)
    ///   86   NS  ptr(2) type(2) class(2) TTL@92 rdlen@96 rdata@98..100
    ///  100   AR  A   ptr(2) type(2) class(2) TTL@106 rdlen@110 rdata@112..116
    ///  116   AR  OPT root(1) type(2) class(2) "TTL"@121 rdlen@125 -> ends at 127
    fn https_fixture() -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&[0x00, 0x00]); // id 0 — what a DoH query sends
        b.extend_from_slice(&[0x81, 0x80]); // QR, RD, RA, rcode 0
        b.extend_from_slice(&[0x00, 0x01]); // qd 1
        b.extend_from_slice(&[0x00, 0x01]); // an 1
        b.extend_from_slice(&[0x00, 0x01]); // ns 1
        b.extend_from_slice(&[0x00, 0x02]); // ar 2 (an A, and the OPT)
        b.extend_from_slice(b"\x0acloudflare\x03com\x00");
        b.extend_from_slice(&[0x00, 0x41, 0x00, 0x01]); // type 65, IN

        // AN: the HTTPS record.
        let mut rdata: Vec<u8> = vec![0x00, 0x01, 0x00]; // priority 1, TargetName "."
        rdata.extend_from_slice(&[0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2']); // key 1 alpn
        rdata.extend_from_slice(&[0x00, 0x05, 0x00, 0x10]); // key 5 ech, 16 bytes
        rdata.extend_from_slice(&[0xAA; 16]);
        rdata.extend_from_slice(&[0x00, 0x04, 0x00, 0x08]); // key 4 ipv4hint
        rdata.extend_from_slice(&[104, 16, 132, 229, 104, 16, 133, 229]);
        b.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x41, 0x00, 0x01]);
        b.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // ttl 3600
        b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        b.extend_from_slice(&rdata);

        // NS, so the walk has to leave the answer section.
        b.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x02, 0x00, 0x01]);
        b.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // ttl 3600
        b.extend_from_slice(&[0x00, 0x02, 0xC0, 0x0C]);

        // AR: an A record, and then the OPT.
        b.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        b.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // ttl 3600
        b.extend_from_slice(&[0x00, 0x04, 104, 16, 132, 229]);
        b.extend_from_slice(&[0x00]); // OPT name is root
        b.extend_from_slice(&[0x00, 0x29, 0x10, 0x00]); // type 41, "class" = 4096 udp size
        b.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]); // EXTENDED-RCODE|VERSION|DO — NOT a ttl
        b.extend_from_slice(&[0x00, 0x00]); // rdlen 0
        b
    }

    fn https_question() -> Question {
        Question {
            id: 0,
            name: "cloudflare.com".into(),
            qtype: TYPE_HTTPS,
            qclass: CLASS_IN,
            end: 32,
            recursion_desired: true,
        }
    }

    /// **The record is forwarded intact, only the id and the TTLs move — and the OPT is left
    /// alone.**
    ///
    /// The expected bytes are a *second* copy patched at hand-computed offsets rather than
    /// anything derived from the function under test, so a builder that is wrong in the same way
    /// cannot cancel out. It catches, and this list is the reason each part is here: a wrong TTL
    /// offset; a walk that stops after the answer section (the NS and AR TTLs would stay 3600 and
    /// the stranded-cache defence would be quietly gone for them); the OPT not being skipped
    /// (`00 00 80 00` would become `00 00 00 3C`, turning EDNS flags into a duration); and any
    /// byte of rdata being touched, which would break `ech`.
    #[test]
    fn a_forwarded_https_record_keeps_its_ech_and_loses_only_its_ttls() {
        let mut got = https_fixture();

        // The offsets this test is written against, asserted rather than trusted.
        assert_eq!(&got[34..36], &[0x00, 0x41], "AN type at 34");
        assert_eq!(&got[38..42], &[0x00, 0x00, 0x0E, 0x10], "AN ttl at 38");
        assert_eq!(&got[92..96], &[0x00, 0x00, 0x0E, 0x10], "NS ttl at 92");
        assert_eq!(&got[106..110], &[0x00, 0x00, 0x0E, 0x10], "AR A ttl at 106");
        assert_eq!(&got[117..119], &[0x00, 0x29], "OPT type at 117");
        assert_eq!(
            &got[121..125],
            &[0x00, 0x00, 0x80, 0x00],
            "OPT flags at 121"
        );
        assert_eq!(got.len(), 127);

        // The fixture is *proven* to carry ech rather than assumed to.
        let rdlen = u16::from_be_bytes([got[42], got[43]]) as usize;
        assert_eq!(
            https_svcparam_keys(&got[44..44 + rdlen]).expect("parses"),
            vec![1, 5, 4],
            "alpn, ech, ipv4hint — in the order the record carries them"
        );

        let mut want = https_fixture();
        want[0..2].copy_from_slice(&[0xBE, 0xEF]);
        for at in [38usize, 92, 106] {
            want[at..at + 4].copy_from_slice(&60u32.to_be_bytes());
        }

        rewrite_forwarded(&mut got, 0, 0xBEEF, &https_question(), 60).expect("rewrites");
        assert_eq!(got, want, "only the id and the three real TTLs may move");
    }

    /// A TTL of zero means "do not cache this" and must survive a clamp, because raising it would
    /// invent a promise the origin refused to make.
    #[test]
    fn clamping_never_raises_a_ttl() {
        let mut b = https_fixture();
        b[38..42].copy_from_slice(&0u32.to_be_bytes());
        clamp_ttls(&mut b, 60).expect("clamps");
        assert_eq!(&b[38..42], &[0, 0, 0, 0]);
    }

    /// Each refusal by variant. `Malformed` and `SoftFailure` are different answers to the caller:
    /// one is "this is not our answer", the other is "the server spoke about itself".
    #[test]
    fn a_response_that_is_not_ours_is_refused() {
        let q = https_question();

        let mut truncated = https_fixture();
        truncated[2] |= 0x02;
        assert_eq!(
            validate_response(&truncated, 0, &q),
            Err(Error::Malformed),
            "a truncated answer is a partial SvcParams set"
        );

        // The id is checked against what the *upstream* was asked with. This is the arm that
        // catches "validated after restoring the client's id".
        let wrong_id = https_fixture();
        assert_eq!(
            validate_response(&wrong_id, 0x1234, &q),
            Err(Error::Malformed)
        );

        let mut not_a_response = https_fixture();
        not_a_response[2] &= !0x80;
        assert_eq!(
            validate_response(&not_a_response, 0, &q),
            Err(Error::Malformed)
        );

        let mut servfail = https_fixture();
        servfail[3] = (servfail[3] & 0xF0) | 2;
        assert_eq!(validate_response(&servfail, 0, &q), Err(Error::SoftFailure));

        // NXDOMAIN is an answer about the name and is allowed through.
        let mut nxdomain = https_fixture();
        nxdomain[3] = (nxdomain[3] & 0xF0) | 3;
        assert_eq!(validate_response(&nxdomain, 0, &q), Ok(()));

        // A different question entirely.
        let other = Question {
            name: "example.com".into(),
            ..https_question()
        };
        assert_eq!(
            validate_response(&https_fixture(), 0, &other),
            Err(Error::Malformed)
        );
        let other_type = Question {
            qtype: TYPE_A,
            ..https_question()
        };
        assert_eq!(
            validate_response(&https_fixture(), 0, &other_type),
            Err(Error::Malformed),
            "an A answer is not an answer to a type-65 question"
        );
    }

    /// Every one of these runs on whatever a resolver sent back, so none may panic.
    #[test]
    fn the_forwarding_helpers_never_panic() {
        let full = https_fixture();
        for i in 0..full.len() {
            let mut prefix = full[..i].to_vec();
            let _ = validate_response(&prefix, 0, &https_question());
            let _ = clamp_ttls(&mut prefix, 60);
            let _ = set_id(&mut prefix, 1);
            let _ = https_svcparam_keys(&prefix);
        }
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..2000 {
            let mut b = full.clone();
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let at = (seed >> 33) as usize % b.len();
            b[at] ^= 0xFF;
            let _ = validate_response(&b, 0, &https_question());
            let _ = clamp_ttls(&mut b, 60);
            let _ = https_svcparam_keys(&b);
        }
        assert!(set_id(&mut [], 1).is_err());
        assert!(set_id(&mut [0], 1).is_err());
    }

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

    /// **"This server could not answer" must not read as "this name does not exist".**
    ///
    /// The two are identical on the wire apart from four bits in byte 3 — same id, QR set, one
    /// question, zero answers — and this decoder used to read byte 2 and skip straight past byte 3.
    /// So a rate-limited or DNSSEC-failing upstream produced `NoAddress`, which the resolver treats
    /// as an authoritative no: sweep stopped at the first server, name negative-cached for the
    /// whole machine. NXDOMAIN(3) and NOERROR(0) are the only two rcodes that say anything about
    /// the *name*, and they must stay on the `NoAddress` path or `wpad` — NXDOMAIN here and asked
    /// for constantly by Windows — goes back to sweeping four upstreams on every single ask.
    #[test]
    fn a_server_failure_is_not_an_authoritative_no() {
        let question = parse_question(&encode_query("busy.example", 11).unwrap()).unwrap();
        let query = encode_query("busy.example", 11).unwrap();
        let with = |rcode: u8| {
            decode_answers(
                &encode_response(&query, &question, &[], 30, rcode).unwrap(),
                11,
            )
        };

        // The name says nothing about itself: authoritative, cacheable, stops the sweep.
        assert_eq!(with(0), Err(Error::NoAddress), "NOERROR/NODATA");
        assert_eq!(with(3), Err(Error::NoAddress), "NXDOMAIN");

        // The server says something about itself: keep asking, remember nothing.
        assert_eq!(with(RCODE_SERVFAIL), Err(Error::SoftFailure), "SERVFAIL");
        assert_eq!(with(5), Err(Error::SoftFailure), "REFUSED");
        assert_eq!(with(4), Err(Error::SoftFailure), "NOTIMP");
        assert_eq!(with(1), Err(Error::SoftFailure), "FORMERR");

        // A failure carrying *someone else's* id stays a forgery, not a reason to give up: the id
        // check has to come first, or an off-path spoofer gets a cheap way to kill a name.
        assert_eq!(
            decode_answers(
                &encode_response(&query, &question, &[], 30, RCODE_SERVFAIL).unwrap(),
                999
            ),
            Err(Error::Malformed)
        );
    }

    /// **An A record whose `rdlen` is not 4 must be skipped, not read as an address.**
    ///
    /// The guard is `rtype == 1 && rdlen == 4`, and the `rdlen` half had no test: dropping it makes
    /// `Ipv4Addr::new(data[0], .., data[3])` index a slice that may be shorter, panicking the
    /// thread that parses replies for the whole machine — on input that arrives from the network,
    /// from anybody who can guess a source port.
    #[test]
    fn an_a_record_with_the_wrong_length_is_skipped_rather_than_read() {
        // A well-formed response, then its single answer's rdlen bent to 2 with the body cut to
        // match, so the record is internally consistent and only its *type* is a lie.
        let good = response(21, &[v4(9, 9, 9, 9)]);
        let mut bent = good.clone();
        let n = bent.len();
        // rdlen is the last two bytes before the 4-byte body.
        bent[n - 6] = 0;
        bent[n - 5] = 2;
        bent.truncate(n - 2);
        assert_eq!(
            decode_answers(&bent, 21),
            Err(Error::NoAddress),
            "a 2-byte A record is not an address and must not be read as one"
        );

        // And the same at every length from 0 to 8, none of which may panic.
        for rdlen in 0u16..=8 {
            let mut b = response(22, &[v4(1, 2, 3, 4)]);
            let n = b.len();
            b[n - 6] = (rdlen >> 8) as u8;
            b[n - 5] = (rdlen & 0xFF) as u8;
            let _ = decode_answers(&b, 22);
        }
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
