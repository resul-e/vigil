//! ClientHello parsing, far enough to locate the SNI and derive split positions.
//!
//! Two properties are non-negotiable here, both learned from the deleted iterations:
//!
//! 1. **Never panic.** This runs on the first TCP segment of every connection, which is
//!    routinely a partial record. A panic in a proxy datapath is a dropped connection.
//! 2. **Never assume a fixed offset.** Browsers randomise extension order and inject GREASE,
//!    so the SNI position must be walked, not hardcoded.
//!
//! And one that is easy to get wrong: a ClientHello that does not fit in one segment must be
//! reported as [`ParseError::Truncated`], not silently treated as "no SNI". The previous
//! iteration returned `false` for exactly this case and thereby disabled itself for Chrome,
//! whose ClientHello is ~1800 B and never fits one segment.

use core::ops::Range;

use crate::reader::Reader;
use crate::tls::{CONTENT_TYPE_HANDSHAKE, RECORD_HEADER_LEN};

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_NAME_TYPE_HOST: u8 = 0x00;
const RANDOM_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Not a TLS handshake record at all.
    NotHandshake,
    /// A handshake record, but not a ClientHello.
    NotClientHello,
    /// Ran out of bytes. Usually means "this is only the first segment" — buffer more and
    /// retry rather than giving up.
    Truncated,
    /// Structurally invalid: a length field points outside its container.
    Malformed,
}

/// Where the SNI lives inside the flight buffer. Offsets are absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sni {
    /// The hostname bytes.
    pub host: Range<usize>,
    /// Offset of the SNI extension's `extension_type` field.
    pub ext: usize,
}

#[derive(Debug, Clone)]
pub struct ClientHello<'a> {
    raw: &'a [u8],
    sni: Option<Sni>,
    /// True when the record header declared more bytes than the buffer holds.
    record_truncated: bool,
}

/// A named position to cut the flight at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// Inside the 5-byte TLS record header. The measured-reliable default: the DPI cannot
    /// parse a record header out of a 1-byte segment and gives up outright.
    RecordHeader,
    /// First byte of the SNI hostname.
    SniStart,
    /// Just past the last byte of the SNI hostname.
    SniEnd,
    /// Middle of the second-level domain, so neither segment contains the whole label.
    MidSld,
    /// Start of the SNI extension.
    SniExt,
}

impl<'a> ClientHello<'a> {
    pub fn sni(&self) -> Option<&Sni> {
        self.sni.as_ref()
    }

    pub fn host_bytes(&self) -> Option<&'a [u8]> {
        let s = self.sni.as_ref()?;
        self.raw.get(s.host.clone())
    }

    pub fn host_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.host_bytes()?).ok()
    }

    /// True when the record declares more bytes than we hold — i.e. the ClientHello spans
    /// more than this buffer. The SNI may still have been found in what we do hold.
    pub fn is_record_truncated(&self) -> bool {
        self.record_truncated
    }

    /// Resolve a marker to an absolute byte offset in the flight buffer.
    ///
    /// Returns `None` when the marker needs an SNI that was not found, or when the resulting
    /// cut would be degenerate (offset 0, or at/after the end of the buffer) — a cut there is
    /// not a split at all.
    pub fn marker_offset(&self, m: Marker) -> Option<usize> {
        let off = match m {
            Marker::RecordHeader => 1,
            Marker::SniStart => self.sni.as_ref()?.host.start,
            Marker::SniEnd => self.sni.as_ref()?.host.end,
            Marker::SniExt => self.sni.as_ref()?.ext,
            Marker::MidSld => {
                let s = self.sni.as_ref()?;
                let host = self.host_str()?;
                let sld = second_level_label(host)?;
                s.host.start + sld.start + (sld.end - sld.start) / 2
            }
        };
        (off > 0 && off < self.raw.len()).then_some(off)
    }
}

/// Byte range of the second-level label within `host`.
///
/// `discord.com` -> `discord`; `cdn.prod.website-files.com` -> `website-files`.
///
/// Returns `None` when there is no label that can be split *strictly inside*:
/// a single label, an IP literal, or a second-level label shorter than two bytes. A one-byte
/// label would put the cut at its first byte, which leaves the whole label intact in the
/// second segment — the opposite of what this marker is for.
///
/// A trailing dot (`discord.com.`, the fully-qualified form) is ignored rather than counted
/// as an empty label, which would otherwise select `com`.
fn second_level_label(host: &str) -> Option<Range<usize>> {
    if host.is_empty() || host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let mut bounds: Vec<Range<usize>> = Vec::new();
    let mut start = 0usize;
    for (i, c) in host.char_indices() {
        if c == '.' {
            bounds.push(start..i);
            start = i + 1;
        }
    }
    bounds.push(start..host.len());
    // Drop a trailing empty label produced by a fully-qualified name.
    while bounds.last().is_some_and(|b| b.end == b.start) {
        bounds.pop();
    }
    if bounds.len() < 2 {
        return None;
    }
    let sld = bounds[bounds.len() - 2].clone();
    (sld.end - sld.start >= 2).then_some(sld)
}

/// How a parse ended, which decides what a short read means.
struct Walk {
    sni: Option<Sni>,
    /// The walk stopped early because it ran out of bytes.
    ran_short: bool,
}

/// Parse a ClientHello out of the beginning of a TLS flight.
///
/// Three rules the implementation holds to, each of which was violated by an earlier version
/// and caught by adversarial review:
///
/// - **A located SNI is never discarded.** Every early exit carries it out. Otherwise the
///   answer is non-monotonic in buffer length: growing the buffer by one byte could make a
///   hostname disappear and reappear.
/// - **Parsing is bounded by the record and the handshake message**, not by the raw buffer.
///   A handshake may legally be split across records (RFC 8446 §5.1); without the bound the
///   walk reads a following record's header as if it were extension data.
/// - **`Truncated` means "bytes are still coming".** A record that has fully arrived and is
///   structurally broken is `Malformed`. Telling a proxy to wait for bytes the client already
///   finished sending stalls the connection until timeout.
pub fn parse(buf: &[u8]) -> Result<ClientHello<'_>, ParseError> {
    let mut r = Reader::new(buf);

    // --- record layer ---
    let content_type = r.u8().ok_or(ParseError::Truncated)?;
    if content_type != CONTENT_TYPE_HANDSHAKE {
        return Err(ParseError::NotHandshake);
    }
    let _legacy = r.u16().ok_or(ParseError::Truncated)?;
    let declared = r.u16().ok_or(ParseError::Truncated)? as usize;
    let record_end = RECORD_HEADER_LEN
        .checked_add(declared)
        .ok_or(ParseError::Malformed)?;
    let record_truncated = record_end > buf.len();

    // Everything below reads through this view, so no length field can walk us out of the
    // record. The view is a prefix of `buf`, so offsets stay absolute.
    let limit = record_end.min(buf.len());
    let short = if record_truncated {
        ParseError::Truncated
    } else {
        ParseError::Malformed
    };
    let mut r = Reader::new(&buf[..limit]);
    r.take(RECORD_HEADER_LEN).ok_or(short)?;

    // --- handshake layer ---
    let hs_type = r.u8().ok_or(short)?;
    if hs_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ParseError::NotClientHello);
    }
    let hs_len = r.u24().ok_or(short)? as usize;
    let hs_end = r.pos().checked_add(hs_len).ok_or(ParseError::Malformed)?;
    let _client_version = r.u16().ok_or(short)?;
    r.take(RANDOM_LEN).ok_or(short)?;
    r.skip_u8_vec().ok_or(short)?; // legacy_session_id
    r.skip_u16_vec().ok_or(short)?; // cipher_suites
    r.skip_u8_vec().ok_or(short)?; // legacy_compression_methods

    // --- extensions ---
    let ext_total = match r.u16() {
        Some(n) => n as usize,
        // Out of bytes at the extensions-length field. If more are coming the SNI may still
        // be ahead of us; if the record is complete there simply is no extensions block,
        // which is legal in TLS 1.2.
        None => {
            return finish(
                buf,
                Walk {
                    sni: None,
                    ran_short: record_truncated,
                },
                record_truncated,
            )
        }
    };
    let ext_end = r
        .pos()
        .checked_add(ext_total)
        .ok_or(ParseError::Malformed)?;
    // The block may not claim more than the handshake message or the record hold.
    if ext_end > hs_end && !record_truncated {
        return Err(ParseError::Malformed);
    }
    let walk_end = ext_end.min(hs_end).min(limit);

    let mut sni = None;
    let mut ran_short = record_truncated && ext_end > limit;
    while r.pos() < walk_end {
        let ext_off = r.pos();
        // An extension header is 4 bytes; anything less and the block ends mid-header.
        if walk_end - ext_off < 4 {
            ran_short = true;
            break;
        }
        let (Some(ext_type), Some(ext_len)) = (r.u16(), r.u16()) else {
            ran_short = true;
            break;
        };
        let ext_len = ext_len as usize;
        let body_start = r.pos();
        // Bounded by the block, not merely by the buffer: an extension may not spill past
        // the container that declared it.
        if body_start + ext_len > walk_end {
            ran_short = true;
            break;
        }
        let Some(body) = r.take(ext_len) else {
            ran_short = true;
            break;
        };
        if ext_type == EXT_SERVER_NAME && sni.is_none() {
            if let Some(found) = parse_sni_body(body, body_start) {
                sni = Some(Sni {
                    host: found,
                    ext: ext_off,
                });
            }
        }
    }

    finish(buf, Walk { sni, ran_short }, record_truncated)
}

fn finish(buf: &[u8], walk: Walk, record_truncated: bool) -> Result<ClientHello<'_>, ParseError> {
    // A hostname we already located is always reported, whatever else went wrong after it.
    if walk.sni.is_some() {
        return Ok(ClientHello {
            raw: buf,
            sni: walk.sni,
            record_truncated,
        });
    }
    if walk.ran_short {
        return Err(if record_truncated {
            // More bytes are coming and the SNI may be among them.
            ParseError::Truncated
        } else {
            // Everything the record promised has arrived and it still does not add up.
            ParseError::Malformed
        });
    }
    // Walked the whole block cleanly and there was no server_name extension.
    Ok(ClientHello {
        raw: buf,
        sni: None,
        record_truncated,
    })
}

/// Parse a `server_name` extension body, returning the absolute range of the host_name.
///
/// Bounded by the declared list, not by the body: a name that runs past the list it belongs
/// to is malformed, and accepting it would let a lying length field point the split position
/// at bytes the server will never treat as the hostname.
fn parse_sni_body(body: &[u8], base: usize) -> Option<Range<usize>> {
    let mut r = Reader::new(body);
    let list_len = r.u16()? as usize;
    let list_end = r.pos().checked_add(list_len)?;
    if list_end > body.len() {
        return None;
    }
    while r.pos() < list_end {
        let name_type = r.u8()?;
        let name_len = r.u16()? as usize;
        let start = r.pos();
        if start + name_len > list_end {
            return None;
        }
        r.take(name_len)?;
        // RFC 6066: HostName is `opaque HostName<1..2^16-1>` — empty is not a hostname, and
        // an empty range would make every SNI marker degenerate.
        if name_type == SNI_NAME_TYPE_HOST && name_len > 0 {
            return Some(base + start..base + start + name_len);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but structurally valid ClientHello carrying one SNI.
    ///
    /// A trailing extension is appended after the SNI on purpose: in every real ClientHello
    /// the SNI has extensions after it, so without one the hostname would end exactly at the
    /// buffer boundary and `SniEnd` would be a degenerate cut.
    fn build(host: &str) -> Vec<u8> {
        build_with(host, &[])
    }

    /// `lead_exts` is spliced in before the SNI, so callers can put GREASE or unknown
    /// extensions ahead of it without doing offset arithmetic by hand.
    fn build_with(host: &str, lead_exts: &[u8]) -> Vec<u8> {
        let h = host.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(lead_exts);
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        let sni_body_len = 2 + 1 + 2 + h.len();
        ext.extend_from_slice(&(sni_body_len as u16).to_be_bytes());
        ext.extend_from_slice(&((1 + 2 + h.len()) as u16).to_be_bytes());
        ext.push(SNI_NAME_TYPE_HOST);
        ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
        ext.extend_from_slice(h);
        // ec_point_formats(11), a small extension that commonly trails the SNI
        ext.extend_from_slice(&11u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&[0x01, 0x00]);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0); // session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni_in_a_synthetic_hello() {
        let b = build("discord.com");
        let ch = parse(&b).expect("parses");
        assert_eq!(ch.host_str(), Some("discord.com"));
        assert!(!ch.is_record_truncated());
    }

    #[test]
    fn sni_range_points_at_the_actual_bytes() {
        let b = build("example.org");
        let ch = parse(&b).unwrap();
        let r = ch.sni().unwrap().host.clone();
        assert_eq!(&b[r], b"example.org");
    }

    #[test]
    fn rejects_non_handshake_records() {
        let mut b = build("a.com");
        b[0] = 0x17; // application_data
        assert!(matches!(parse(&b), Err(ParseError::NotHandshake)));
    }

    #[test]
    fn rejects_handshake_that_is_not_a_client_hello() {
        let mut b = build("a.com");
        b[5] = 0x02; // ServerHello
        assert!(matches!(parse(&b), Err(ParseError::NotClientHello)));
    }

    /// Every prefix must either parse or return an error — never panic. This is the property
    /// that keeps a partial first segment from taking down a connection.
    #[test]
    fn every_truncation_is_handled_without_panicking() {
        let b = build("discord.com");
        for n in 0..b.len() {
            let _ = parse(&b[..n]);
        }
    }

    #[test]
    fn truncation_before_the_sni_reports_truncated_not_absent() {
        let b = build("discord.com");
        // cut strictly inside the hostname, derived from the parse rather than guessed
        let host = parse(&b).unwrap().sni().unwrap().host.clone();
        let cut = host.start + 2;
        match parse(&b[..cut]) {
            Err(ParseError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn unknown_and_grease_extensions_are_skipped() {
        let host = "discord.com";
        // two GREASE values and one unknown extension, all ahead of the SNI
        let lead = [
            0x0a, 0x0a, 0x00, 0x03, 0xde, 0xad, 0xbe, // GREASE 0x0a0a, 3 bytes
            0x1a, 0x1a, 0x00, 0x00, // GREASE 0x1a1a, empty
            0x00, 0x17, 0x00, 0x01, 0x42, // extended_master_secret-ish, 1 byte
        ];
        let b = build_with(host, &lead);
        let ch = parse(&b).expect("parses with GREASE present");
        assert_eq!(ch.host_str(), Some(host));
    }

    #[test]
    fn marker_offsets_land_where_expected() {
        let b = build("discord.com");
        let ch = parse(&b).unwrap();
        let host = ch.sni().unwrap().host.clone();

        assert_eq!(ch.marker_offset(Marker::RecordHeader), Some(1));
        assert_eq!(ch.marker_offset(Marker::SniStart), Some(host.start));
        assert_eq!(ch.marker_offset(Marker::SniEnd), Some(host.end));
        // "discord" is 7 long -> midpoint at +3
        assert_eq!(ch.marker_offset(Marker::MidSld), Some(host.start + 3));
        assert!(ch.marker_offset(Marker::SniExt).unwrap() < host.start);
    }

    #[test]
    fn midsld_splits_inside_the_second_level_label() {
        for (host, sld) in [
            ("discord.com", "discord"),
            ("cdn.prod.website-files.com", "website-files"),
            ("r6---sn-u0g3uxax3-pnuk.gvt1.com", "gvt1"),
            ("www.google.com", "google"),
        ] {
            let b = build(host);
            let ch = parse(&b).unwrap();
            let off = ch.marker_offset(Marker::MidSld).expect("has midsld");
            let hr = ch.sni().unwrap().host.clone();
            let rel = off - hr.start;
            let idx = host.find(sld).unwrap();
            assert!(
                rel > idx && rel < idx + sld.len(),
                "{host}: midsld at {rel} is not strictly inside {sld:?} at {idx}..{}",
                idx + sld.len()
            );
        }
    }

    #[test]
    fn single_label_and_ip_hosts_have_no_midsld() {
        assert!(second_level_label("localhost").is_none());
        assert!(second_level_label("192.168.1.1").is_none());
        assert!(second_level_label("").is_none());
    }

    #[test]
    fn degenerate_cut_positions_are_refused() {
        // A marker resolving to 0 or to the buffer end is not a split.
        let b = build("a.com");
        let ch = parse(&b).unwrap();
        assert!(ch.marker_offset(Marker::SniEnd).is_some());
        // synthesise the degenerate case directly
        let tiny = ClientHello {
            raw: &b[..1],
            sni: None,
            record_truncated: false,
        };
        assert_eq!(tiny.marker_offset(Marker::RecordHeader), None);
    }
}
