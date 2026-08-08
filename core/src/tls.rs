//! Minimal TLS record inspection.
//!
//! Step 0 only needs enough to *describe* the first flight — its record type and declared
//! length — so measurements can report the ClientHello size. Full ClientHello/SNI parsing is
//! step 1 and lands in this module later.
//!
//! Reporting the size is not cosmetic. Three TLS stacks emit wildly different ClientHellos:
//! OpenSSL ~517 B, rustls ~1462 B, Chrome ~1800 B. At MSS 1460 the latter two are already
//! split by the kernel, so a "no split" arm built on them is not a baseline at all — it
//! silently pre-splits and reports the bypass as working when nothing was done.

/// Standard Ethernet MSS: 1500 MTU − 20 B IP − 20 B TCP.
pub const TYPICAL_MSS: usize = 1460;

/// TLS record content type for handshake messages.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// The fixed part of a TLS record: type(1) + version(2) + length(2).
pub const RECORD_HEADER_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub content_type: u8,
    pub legacy_version: u16,
    /// Length the record *claims*, which is not necessarily what arrived.
    pub declared_len: usize,
}

impl RecordHeader {
    pub fn is_handshake(&self) -> bool {
        self.content_type == CONTENT_TYPE_HANDSHAKE
    }

    /// Total size of the record if it is complete: header + declared payload.
    pub fn total_len(&self) -> usize {
        RECORD_HEADER_LEN + self.declared_len
    }
}

/// Parse the 5-byte record header. `None` if there are not enough bytes.
pub fn record_header(buf: &[u8]) -> Option<RecordHeader> {
    if buf.len() < RECORD_HEADER_LEN {
        return None;
    }
    Some(RecordHeader {
        content_type: buf[0],
        legacy_version: u16::from_be_bytes([buf[1], buf[2]]),
        declared_len: u16::from_be_bytes([buf[3], buf[4]]) as usize,
    })
}

/// How many bytes of the record are missing, if it is truncated.
///
/// The fake ClientHello inherited through three of the deleted iterations declared 193 bytes
/// and carried 71 — a 122-byte shortfall nobody noticed for four generations. Surfacing this
/// makes that class of bug visible instead of silent.
pub fn shortfall(buf: &[u8]) -> Option<usize> {
    let h = record_header(buf)?;
    h.total_len().checked_sub(buf.len()).filter(|&n| n > 0)
}

/// Whether a flight of `len` bytes must occupy more than one TCP segment at the given MSS.
///
/// This is the measured rule on this line: the DPI fails whenever the ClientHello does not
/// fit in one segment, regardless of where the boundary falls.
pub fn spans_multiple_segments(len: usize, mss: usize) -> bool {
    mss > 0 && len > mss
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real 517-byte OpenSSL-style ClientHello prefix.
    fn ch_prefix(declared: u16) -> Vec<u8> {
        let mut v = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        v.extend_from_slice(&declared.to_be_bytes());
        v
    }

    #[test]
    fn parses_a_handshake_record_header() {
        let h = record_header(&ch_prefix(0x0200)).unwrap();
        assert_eq!(h.content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(h.legacy_version, 0x0301);
        assert_eq!(h.declared_len, 512);
        assert_eq!(h.total_len(), 517);
        assert!(h.is_handshake());
    }

    #[test]
    fn short_buffer_yields_none_not_panic() {
        for n in 0..RECORD_HEADER_LEN {
            assert!(record_header(&vec![0x16u8; n]).is_none(), "len {n}");
        }
        assert!(record_header(&[0x16u8; RECORD_HEADER_LEN]).is_some());
    }

    #[test]
    fn non_handshake_content_type_is_flagged() {
        let mut b = ch_prefix(10);
        b[0] = 0x17; // application_data
        assert!(!record_header(&b).unwrap().is_handshake());
    }

    #[test]
    fn shortfall_detects_a_truncated_record() {
        // Declares 512 bytes of payload, carries none: 512 missing.
        let b = ch_prefix(0x0200);
        assert_eq!(shortfall(&b), Some(512));
    }

    /// Regression guard for the exact bug carried through three deleted iterations:
    /// a 71-byte fake ClientHello declaring a 193-byte record.
    #[test]
    fn shortfall_catches_the_inherited_fake_clienthello_bug() {
        let mut b = vec![0x16, 0x03, 0x01, 0x00, 0xbc]; // declares 188 payload -> 193 total
        b.extend_from_slice(&[0u8; 66]); // 71 bytes on the wire
        assert_eq!(b.len(), 71);
        assert_eq!(shortfall(&b), Some(122));
    }

    #[test]
    fn complete_record_has_no_shortfall() {
        let mut b = ch_prefix(4);
        b.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(shortfall(&b), None);
    }

    #[test]
    fn oversized_buffer_has_no_shortfall() {
        let mut b = ch_prefix(2);
        b.extend_from_slice(&[1, 2, 3, 4]); // more than declared
        assert_eq!(shortfall(&b), None);
    }

    #[test]
    fn segment_spanning_matches_the_measured_stacks() {
        // OpenSSL fits one segment -> blocked on this line.
        assert!(!spans_multiple_segments(517, TYPICAL_MSS));
        // rustls and Chrome do not -> they get the bypass for free.
        assert!(spans_multiple_segments(1462, TYPICAL_MSS));
        assert!(spans_multiple_segments(1800, TYPICAL_MSS));
        // exact boundary
        assert!(!spans_multiple_segments(1460, TYPICAL_MSS));
        assert!(spans_multiple_segments(1461, TYPICAL_MSS));
    }

    #[test]
    fn zero_mss_never_claims_spanning() {
        assert!(!spans_multiple_segments(9999, 0));
    }
}
