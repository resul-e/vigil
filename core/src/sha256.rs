//! SHA-256, by hand, because `core/` has no dependencies and this is where it belongs.
//!
//! Three jobs, all part of updating the tool over a line that censors the download:
//!
//! 1. **Per-file integrity.** The signed manifest names a digest for every binary; a file whose
//!    bytes do not hash to it never reaches the application folder.
//! 2. **The delta strategy.** Hash what is already on disk, skip anything that already matches.
//!    No binary diffing, no patch format, and re-running a check costs nothing.
//! 3. **Resume without a log.** A half-finished update is described entirely by which files hash
//!    to what, so the next run works out what is left by looking rather than by trusting a
//!    journal it may have failed to write.
//!
//! Adding a crate for this was the alternative. `sha2` is well maintained and would be one line
//! — but it reaches this project's *only* dependency-free crate, the one whose whole point is
//! that the transforms can be read end to end, and it would be the first dependency `core/`
//! ever had. A hundred and fifty lines of the most tested algorithm in computing, checked
//! against the published vectors and against `sha256sum` on the real binaries, is the cheaper
//! trade.
//!
//! FIPS 180-4, §6.2. No `unsafe`, no allocation beyond the caller's buffer, and it streams — the
//! largest thing hashed here is a 2.5 MB executable, but reading one into memory to hash it
//! would be a habit worth not forming.

/// The first thirty-two bits of the fractional parts of the cube roots of the first sixty-four
/// primes. FIPS 180-4 §4.2.2.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The fractional parts of the square roots of the first eight primes. FIPS 180-4 §5.3.3.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// A digest, and the only form this module hands one out in.
pub type Digest = [u8; 32];

/// An in-progress hash. Feed it with [`update`], finish with [`finish`].
#[derive(Debug, Clone)]
pub struct Sha256 {
    h: [u32; 8],
    /// Bytes not yet part of a full block.
    buf: [u8; 64],
    buf_len: usize,
    /// Total message length in **bits**, which is what the padding encodes.
    ///
    /// `u64` rather than `usize`: on a 32-bit build a `usize` byte count would overflow at 512 MB
    /// and produce a confidently wrong digest, and "confidently wrong" is the failure mode this
    /// whole module exists to prevent.
    bits: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 {
            h: H0,
            buf: [0u8; 64],
            buf_len: 0,
            bits: 0,
        }
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add more of the message.
    pub fn update(&mut self, mut data: &[u8]) {
        self.bits = self.bits.wrapping_add((data.len() as u64) * 8);

        // Top up a partial block first.
        if self.buf_len > 0 {
            let want = 64 - self.buf_len;
            let take = want.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        // Then whole blocks straight out of the caller's slice.
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            self.compress(&b);
            data = rest;
        }

        // Whatever is left is the new partial block.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Pad, absorb the length, and produce the digest.
    pub fn finish(mut self) -> Digest {
        let bits = self.bits;
        // A single 1 bit, then zeroes, then the length as a 64-bit big-endian count — with the
        // whole thing landing exactly on a block boundary. When the 1 bit and the length do not
        // both fit in the current block, the length goes into the next one.
        self.update_no_count(&[0x80]);
        while self.buf_len != 56 {
            self.update_no_count(&[0x00]);
        }
        self.update_no_count(&bits.to_be_bytes());

        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Absorb bytes without counting them. Padding is not part of the message length, and
    /// counting it would put the wrong number into the padding it is producing.
    fn update_no_count(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.buf_len] = b;
            self.buf_len += 1;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (dst, src) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *dst = dst.wrapping_add(src);
        }
    }
}

/// Hash a slice in one call.
pub fn hash(data: &[u8]) -> Digest {
    let mut s = Sha256::new();
    s.update(data);
    s.finish()
}

/// Lowercase hex, which is what the manifest carries and what `sha256sum` prints.
pub fn hex(d: &Digest) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    s
}

/// Parse 64 hex characters into a digest. `None` for anything else at all.
///
/// Strict on purpose: this reads a signed manifest, and a lenient parser is a way for two
/// readers to disagree about what was signed.
pub fn from_hex(s: &str) -> Option<Digest> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        // Uppercase hex parses, but the manifest is written lowercase and comparing the parsed
        // digests rather than the strings makes the case question moot.
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Compare two digests without an early return.
///
/// Not because a timing attack on a public digest is plausible — it is not — but because the
/// habit costs nothing here and this function is one refactor away from being used on something
/// where it would matter.
pub fn eq(a: &Digest, b: &Digest) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> String {
        hex(&hash(s.as_bytes()))
    }

    /// FIPS 180-4 and the NIST CAVS short-message vectors. The published answers, not answers
    /// this implementation produced and then had written down for it.
    #[test]
    fn the_published_vectors_pass() {
        assert_eq!(
            h(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            h("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            h("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            h("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
        // One byte, and a byte that is not printable.
        assert_eq!(
            hex(&hash(&[0x00])),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        assert_eq!(
            hex(&hash(&[0xbd])),
            "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b"
        );
    }

    /// The million-a vector, which is the one that exercises the block loop and the 64-bit
    /// length together.
    #[test]
    fn the_long_vector_passes() {
        let mut s = Sha256::new();
        for _ in 0..1000 {
            s.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&s.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// The padding boundaries, one by one, against `sha256sum`.
    ///
    /// 55 is the last length whose terminating 1 bit and 64-bit length still fit in the same
    /// block; 56 is the first that needs a second block; 64 is a whole block followed by a whole
    /// block of nothing but padding. Every off-by-one in `finish` lives in this range.
    ///
    /// Three constants across this module were wrong when they were written from memory, and
    /// `sha256sum` caught all three. Every expected value here is copied from its output, never
    /// from this implementation's — an implementation checked against itself is not checked.
    #[test]
    fn every_padding_boundary_is_right() {
        let expected: &[(usize, &str)] = &[
            (
                54,
                "a3f01b6939256127582ac8ae9fb47a382a244680806a3f613a118851c1ca1d47",
            ),
            (
                55,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            (
                56,
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                57,
                "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
            ),
            (
                63,
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            (
                64,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                65,
                "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
            ),
            (
                119,
                "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
            ),
            (
                120,
                "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
            ),
        ];
        for (n, want) in expected {
            assert_eq!(&hex(&hash(&vec![b'a'; *n])), want, "{n} bytes of 'a'");
        }
    }

    /// Feeding the same message in different chunk sizes must not change the answer. This is
    /// where a streaming implementation goes wrong, and the update path here has three branches
    /// — top up a partial block, consume whole blocks, keep the remainder — that all have to
    /// agree.
    #[test]
    fn chunking_does_not_change_the_digest() {
        let msg: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let once = hash(&msg);
        for chunk in [1usize, 2, 3, 7, 31, 63, 64, 65, 127, 128, 999, 1000] {
            let mut s = Sha256::new();
            for part in msg.chunks(chunk) {
                s.update(part);
            }
            assert!(eq(&s.finish(), &once), "chunk size {chunk}");
        }
        // And an empty update in the middle must be a no-op.
        let mut s = Sha256::new();
        s.update(&msg[..100]);
        s.update(&[]);
        s.update(&msg[100..]);
        assert!(eq(&s.finish(), &once));
    }

    #[test]
    fn a_megabyte_hashes_and_matches_the_streamed_form() {
        let big = vec![0x5au8; 1024 * 1024];
        let once = hash(&big);
        let mut s = Sha256::new();
        for part in big.chunks(4096) {
            s.update(part);
        }
        assert!(eq(&s.finish(), &once));
    }

    #[test]
    fn hex_round_trips_and_rejects_everything_else() {
        let d = hash(b"abc");
        assert_eq!(from_hex(&hex(&d)), Some(d));
        // Uppercase parses to the same digest, so comparing digests rather than strings makes
        // the manifest's case irrelevant.
        assert_eq!(from_hex(&hex(&d).to_uppercase()), Some(d));

        for bad in [
            "",
            "ba7816bf",
            &"a".repeat(63),
            &"a".repeat(65),
            &"g".repeat(64),
            &format!("{} ", "a".repeat(63)),
            &"a".repeat(62).to_string().to_owned().replace("aa", "a-"),
        ] {
            assert_eq!(from_hex(bad), None, "{bad:?} should not parse");
        }
    }

    #[test]
    fn comparison_says_yes_only_for_identical_digests() {
        let a = hash(b"one");
        let b = hash(b"two");
        assert!(eq(&a, &a));
        assert!(!eq(&a, &b));
        // Differing in exactly one bit, in every position.
        for i in 0..32 {
            for bit in 0..8 {
                let mut c = a;
                c[i] ^= 1 << bit;
                assert!(!eq(&a, &c), "byte {i} bit {bit}");
            }
        }
    }
}
