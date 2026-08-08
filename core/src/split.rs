//! How the first client-to-server flight is chopped into separate writes.
//!
//! This is the whole technique on this line: the DPI fails whenever the ClientHello does not
//! arrive in a single TCP segment. Splitting the buffer into several `write()` calls forces
//! that, regardless of where the cut falls.
//!
//! Pure: no sockets, no clock. That is what makes it testable.

/// Where to cut the first flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitPoint {
    /// Write the flight in one call. On this line, a single-segment ClientHello is blocked.
    None,
    /// Cut inside the 5-byte TLS record header. Measured reliable (8/8) because the DPI
    /// cannot parse a record header out of a 1-byte segment and gives up outright.
    RecordHeader,
    /// Cut at an absolute byte offset.
    At(usize),
    /// Cut at several offsets, in ascending order.
    Multi(Vec<usize>),
}

impl SplitPoint {
    /// Resolve to concrete cut offsets for a buffer of `len` bytes.
    ///
    /// Offsets are deduplicated, sorted, and any that fall outside `1..len` are dropped —
    /// a cut at 0 or at `len` would produce an empty chunk, which is not a split at all.
    pub fn offsets(&self, len: usize) -> Vec<usize> {
        let mut v = match self {
            SplitPoint::None => Vec::new(),
            SplitPoint::RecordHeader => vec![1],
            SplitPoint::At(n) => vec![*n],
            SplitPoint::Multi(ns) => ns.clone(),
        };
        v.retain(|&n| n > 0 && n < len);
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Split `buf` into the chunks that should be written separately.
///
/// Guarantees, all covered by tests below:
/// - the chunks concatenate back to `buf` exactly, in order
/// - no chunk is empty
/// - an empty input yields no chunks
pub fn chunks<'a>(buf: &'a [u8], point: &SplitPoint) -> Vec<&'a [u8]> {
    if buf.is_empty() {
        return Vec::new();
    }
    let cuts = point.offsets(buf.len());
    if cuts.is_empty() {
        return vec![buf];
    }
    let mut out = Vec::with_capacity(cuts.len() + 1);
    let mut prev = 0usize;
    for c in cuts {
        out.push(&buf[prev..c]);
        prev = c;
    }
    out.push(&buf[prev..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.iter().flat_map(|p| p.iter().copied()).collect()
    }

    #[test]
    fn none_yields_single_chunk() {
        let b = b"hello world";
        let c = chunks(b, &SplitPoint::None);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], b);
    }

    #[test]
    fn record_header_cuts_after_first_byte() {
        let b = b"\x16\x03\x01\x02\x00rest";
        let c = chunks(b, &SplitPoint::RecordHeader);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], b"\x16");
        assert_eq!(c[1], b"\x03\x01\x02\x00rest");
    }

    #[test]
    fn at_cuts_where_asked() {
        let b = b"0123456789";
        let c = chunks(b, &SplitPoint::At(4));
        assert_eq!(c, vec![&b"0123"[..], &b"456789"[..]]);
    }

    #[test]
    fn multi_produces_n_plus_one_chunks() {
        let b = b"0123456789";
        let c = chunks(b, &SplitPoint::Multi(vec![2, 5, 8]));
        assert_eq!(c, vec![&b"01"[..], &b"234"[..], &b"567"[..], &b"89"[..]]);
    }

    #[test]
    fn multi_is_order_independent_and_deduped() {
        let b = b"0123456789";
        let a = chunks(b, &SplitPoint::Multi(vec![5, 2, 5, 8, 2]));
        let e = chunks(b, &SplitPoint::Multi(vec![2, 5, 8]));
        assert_eq!(a, e);
    }

    /// The property that matters: splitting must never lose, duplicate or reorder a byte.
    #[test]
    fn chunks_always_reassemble_to_input() {
        let b: Vec<u8> = (0..=255u8).cycle().take(1500).collect();
        let points = [
            SplitPoint::None,
            SplitPoint::RecordHeader,
            SplitPoint::At(1),
            SplitPoint::At(2),
            SplitPoint::At(5),
            SplitPoint::At(1499),
            SplitPoint::Multi(vec![1, 5, 700, 1499]),
        ];
        for p in &points {
            let c = chunks(&b, p);
            assert_eq!(cat(&c), b, "reassembly failed for {p:?}");
            assert!(!c.iter().any(|x| x.is_empty()), "empty chunk for {p:?}");
        }
    }

    #[test]
    fn out_of_range_cuts_are_dropped_not_panicking() {
        let b = b"0123456789";
        // 0 and len would make an empty chunk; beyond len is nonsense. All ignored.
        for p in [
            SplitPoint::At(0),
            SplitPoint::At(10),
            SplitPoint::At(99),
            SplitPoint::Multi(vec![0, 10, 99]),
        ] {
            let c = chunks(b, &p);
            assert_eq!(c.len(), 1, "{p:?} should degrade to a single chunk");
            assert_eq!(cat(&c), b);
        }
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        assert!(chunks(b"", &SplitPoint::RecordHeader).is_empty());
        assert!(chunks(b"", &SplitPoint::None).is_empty());
    }

    #[test]
    fn record_header_on_tiny_buffer_degrades_safely() {
        // A 1-byte flight cannot be split; must not panic, must not lose the byte.
        let c = chunks(b"\x16", &SplitPoint::RecordHeader);
        assert_eq!(c, vec![&b"\x16"[..]]);
    }
}
