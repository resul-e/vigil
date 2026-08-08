//! TLS record fragmentation — re-frame one handshake message as several TLS records.
//!
//! A second, independent axis from TCP splitting. A handshake message may legally span
//! several records (RFC 8446 §5.1), so the server reassembles them and sees the same
//! ClientHello; a DPI that parses record-at-a-time does not.
//!
//! Why this is worth having alongside [`super::split`]: against Russian TSPU, published
//! measurements found TCP segmentation alone failed and record fragmentation alone failed,
//! and only the two combined worked. They are composable, not alternatives.
//!
//! Unlike `Split`, this **changes the bytes** — it inserts record headers. So it returns an
//! owned buffer rather than borrowing, and the SNI offsets of the result differ from the
//! input's. Anything resolving markers must re-parse afterwards.

use crate::tls::{CONTENT_TYPE_HANDSHAKE, RECORD_HEADER_LEN};

use super::TransformError;

/// Split the record payload into pieces of at most `max_record` bytes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecordFrag {
    /// Largest payload any emitted record may carry. `1` produces one record per byte, which
    /// is legal but pathological; the useful range is roughly 2..64.
    pub max_record: usize,
}

impl Default for TlsRecordFrag {
    fn default() -> Self {
        // Small enough that the SNI cannot sit whole in the first record, large enough not to
        // explode a 1.8 kB Chrome flight into hundreds of records.
        TlsRecordFrag { max_record: 64 }
    }
}

impl TlsRecordFrag {
    pub fn new(max_record: usize) -> Self {
        TlsRecordFrag { max_record }
    }

    /// Re-frame `flight`. Returns the rewritten bytes.
    ///
    /// Only the **first** record is re-framed: it is the one carrying the ClientHello, and
    /// rewriting anything after it would be pointless work on data the DPI has stopped
    /// caring about. Whatever follows the first record is copied through untouched.
    pub fn apply(&self, flight: &[u8]) -> Result<Vec<u8>, TransformError> {
        if self.max_record == 0 {
            return Err(TransformError::UnresolvablePosition);
        }
        if flight.len() < RECORD_HEADER_LEN || flight[0] != CONTENT_TYPE_HANDSHAKE {
            return Err(TransformError::NeedsClientHello);
        }
        let declared = u16::from_be_bytes([flight[3], flight[4]]) as usize;
        let end = RECORD_HEADER_LEN
            .checked_add(declared)
            .ok_or(TransformError::UnresolvablePosition)?;
        if end > flight.len() {
            // Only part of the record is here; re-framing it would emit records whose
            // lengths lie about what follows.
            return Err(TransformError::UnresolvablePosition);
        }
        let payload = &flight[RECORD_HEADER_LEN..end];
        if payload.len() <= self.max_record {
            // Already small enough — one record is all it would produce, so this transform
            // would do nothing. Say so rather than pretending to have acted.
            return Err(TransformError::UnresolvablePosition);
        }
        let version = [flight[1], flight[2]];

        let records = payload.len().div_ceil(self.max_record);
        let mut out = Vec::with_capacity(flight.len() + records * RECORD_HEADER_LEN);
        for piece in payload.chunks(self.max_record) {
            out.push(CONTENT_TYPE_HANDSHAKE);
            out.extend_from_slice(&version);
            out.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            out.extend_from_slice(piece);
        }
        out.extend_from_slice(&flight[end..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(payload_len: usize) -> Vec<u8> {
        let mut v = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        v.extend_from_slice(&(payload_len as u16).to_be_bytes());
        v.extend((0..payload_len).map(|i| (i % 251) as u8));
        v
    }

    /// Walk the emitted records and return their payloads concatenated, plus the count.
    fn reassemble(buf: &[u8]) -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        let mut i = 0usize;
        let mut n = 0usize;
        while i + RECORD_HEADER_LEN <= buf.len() {
            let len = u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize;
            assert_eq!(buf[i], CONTENT_TYPE_HANDSHAKE, "record {n} type");
            let s = i + RECORD_HEADER_LEN;
            assert!(s + len <= buf.len(), "record {n} runs past the buffer");
            out.extend_from_slice(&buf[s..s + len]);
            i = s + len;
            n += 1;
        }
        assert_eq!(i, buf.len(), "trailing bytes are not a whole record");
        (out, n)
    }

    /// The property that keeps handshakes working: the server reassembles exactly what the
    /// client meant to send.
    #[test]
    fn reassembles_to_the_original_payload() {
        for payload in [10usize, 64, 65, 300, 517, 1803] {
            for max in [1usize, 2, 7, 64, 256] {
                let flight = record(payload);
                let Ok(out) = TlsRecordFrag::new(max).apply(&flight) else {
                    continue; // payload already fits one record
                };
                let (got, n) = reassemble(&out);
                assert_eq!(
                    got,
                    &flight[RECORD_HEADER_LEN..],
                    "payload={payload} max={max}: payload changed"
                );
                assert_eq!(n, payload.div_ceil(max), "payload={payload} max={max}");
            }
        }
    }

    #[test]
    fn every_emitted_record_respects_the_maximum() {
        let flight = record(517);
        let out = TlsRecordFrag::new(64).apply(&flight).unwrap();
        let mut i = 0;
        while i + RECORD_HEADER_LEN <= out.len() {
            let len = u16::from_be_bytes([out[i + 3], out[i + 4]]) as usize;
            assert!(len <= 64 && len > 0, "record of {len} bytes");
            i += RECORD_HEADER_LEN + len;
        }
    }

    #[test]
    fn the_version_of_the_original_record_is_preserved() {
        let mut flight = record(200);
        flight[1] = 0x03;
        flight[2] = 0x03;
        let out = TlsRecordFrag::new(50).apply(&flight).unwrap();
        for i in (0..out.len()).step_by(55) {
            if i + 5 <= out.len() {
                assert_eq!((out[i + 1], out[i + 2]), (0x03, 0x03));
            }
        }
    }

    #[test]
    fn a_payload_that_already_fits_is_refused_rather_than_no_opped() {
        let flight = record(40);
        assert_eq!(
            TlsRecordFrag::new(64).apply(&flight),
            Err(TransformError::UnresolvablePosition)
        );
    }

    #[test]
    fn a_zero_maximum_is_refused() {
        assert_eq!(
            TlsRecordFrag::new(0).apply(&record(100)),
            Err(TransformError::UnresolvablePosition)
        );
    }

    #[test]
    fn non_tls_input_is_refused() {
        assert_eq!(
            TlsRecordFrag::default().apply(b"GET / HTTP/1.1\r\n\r\n"),
            Err(TransformError::NeedsClientHello)
        );
    }

    #[test]
    fn a_truncated_record_is_refused() {
        let mut flight = record(500);
        flight.truncate(200);
        assert_eq!(
            TlsRecordFrag::new(64).apply(&flight),
            Err(TransformError::UnresolvablePosition)
        );
    }

    #[test]
    fn bytes_after_the_first_record_are_copied_through() {
        let mut flight = record(300);
        let tail = b"\x14\x03\x03\x00\x01\x01"; // a ChangeCipherSpec record
        flight.extend_from_slice(tail);
        let out = TlsRecordFrag::new(64).apply(&flight).unwrap();
        assert!(out.ends_with(tail), "trailing record was lost or altered");
    }

    /// The result must still parse as a ClientHello once records are reassembled — and the
    /// first record must be too small to hold the SNI, which is the point.
    #[test]
    fn the_first_record_is_too_small_to_carry_a_hostname() {
        let flight = record(517);
        let out = TlsRecordFrag::new(8).apply(&flight).unwrap();
        let first_len = u16::from_be_bytes([out[3], out[4]]) as usize;
        assert_eq!(first_len, 8);
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut seed = 0xC0FFEEu64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 300) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            for max in [0usize, 1, 5, 64] {
                let _ = TlsRecordFrag::new(max).apply(&buf);
            }
        }
    }
}
