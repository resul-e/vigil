//! A bounds-checked cursor over a byte slice.
//!
//! Every read returns `Option`, so a truncated or malformed ClientHello produces `None`
//! rather than a panic. This matters more than it looks: the parser runs on the first TCP
//! segment of a connection, which is *routinely* a partial record — and a panic in the
//! datapath of a proxy is a dropped connection.

/// Cursor with a position that never advances past the end of the slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    /// TLS uses 24-bit lengths for handshake messages.
    pub fn u24(&mut self) -> Option<u32> {
        let s = self.take(3)?;
        Some(u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Skip a vector whose length is encoded in a single leading byte.
    pub fn skip_u8_vec(&mut self) -> Option<()> {
        let n = self.u8()? as usize;
        self.take(n).map(|_| ())
    }

    /// Skip a vector whose length is encoded in two leading bytes.
    pub fn skip_u16_vec(&mut self) -> Option<()> {
        let n = self.u16()? as usize;
        self.take(n).map(|_| ())
    }

    /// A sub-reader over the next `n` bytes, advancing self past them.
    pub fn sub(&mut self, n: usize) -> Option<Reader<'a>> {
        let start = self.pos;
        let s = self.take(n)?;
        let _ = s;
        Some(Reader {
            buf: &self.buf[start..start + n],
            pos: 0,
        })
    }

    /// Absolute offset of this reader's cursor, given the reader's own base offset.
    pub fn abs(&self, base: usize) -> usize {
        base + self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_in_order() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(r.u8(), Some(0x01));
        assert_eq!(r.u16(), Some(0x0203));
        assert_eq!(r.u24(), Some(0x040506));
        assert!(r.is_empty());
    }

    #[test]
    fn never_reads_past_the_end() {
        let mut r = Reader::new(&[0x01]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.u8(), None);
        assert_eq!(r.u16(), None);
        assert_eq!(r.u24(), None);
        assert_eq!(r.take(1), None);
    }

    #[test]
    fn partial_multibyte_read_fails_without_consuming() {
        let mut r = Reader::new(&[0xAA]);
        assert_eq!(r.u16(), None, "one byte is not a u16");
        // position must not have moved past the end
        assert!(r.pos() <= 1);
    }

    #[test]
    fn take_beyond_end_is_none_not_panic() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take(4), None);
        assert_eq!(r.take(usize::MAX), None, "must not overflow");
        assert_eq!(r.take(3).map(|s| s.len()), Some(3));
    }

    #[test]
    fn vectors_skip_exactly_their_length() {
        let mut r = Reader::new(&[0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC, 0xFF]);
        assert_eq!(r.skip_u8_vec(), Some(()));
        assert_eq!(r.skip_u16_vec(), Some(()));
        assert_eq!(r.u8(), Some(0xFF));
        assert!(r.is_empty());
    }

    #[test]
    fn truncated_vector_is_rejected() {
        // says 5 bytes follow, only 2 do
        let mut r = Reader::new(&[0x05, 0xAA, 0xBB]);
        assert_eq!(r.skip_u8_vec(), None);
    }

    #[test]
    fn sub_reader_is_bounded_to_its_window() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5]);
        let mut s = r.sub(2).unwrap();
        assert_eq!(s.u8(), Some(1));
        assert_eq!(s.u8(), Some(2));
        assert_eq!(s.u8(), None, "sub-reader must not see the parent's tail");
        assert_eq!(r.u8(), Some(3), "parent advanced past the window");
    }
}
