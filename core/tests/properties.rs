//! Properties and differential checks — code checking code.
//!
//! `corpus.rs` asserts the parser produces the answers *we expect*. That is only as good as
//! our expectations. These tests instead check the parser against an **independent method**
//! and against **invariants that must hold for every input**, including inputs nobody wrote
//! down.
//!
//! Three families here:
//!
//! 1. differential — find the SNI a completely different way and demand agreement
//! 2. invariants — properties that must hold for arbitrary bytes
//! 3. mutation — deterministic corruption of real captures, hunting for panics and
//!    self-inconsistency

use std::fs;
use std::path::Path;

use vigil_core::clienthello::{parse, Marker, ParseError};
use vigil_core::{chunks, SplitPoint};

fn fixtures() -> Vec<(String, String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut v: Vec<_> = fs::read_dir(&dir)
        .expect("fixtures dir")
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension()? != "bin" {
                return None;
            }
            let stem = p.file_stem()?.to_string_lossy().to_string();
            let (client, host) = stem.split_once("__")?;
            Some((
                client.to_string(),
                host.to_string(),
                fs::read(&p).expect("read"),
            ))
        })
        .collect();
    v.sort();
    assert!(!v.is_empty(), "corpus is empty");
    v
}

// ---------------------------------------------------------------- differential

/// An independent SNI locator that shares no code with the parser.
///
/// It does not walk the TLS structure at all: it scans for the literal
/// `server_name` extension shape — type 0x0000, then ext_len, list_len, name_type 0x00,
/// host_len — and checks the three nested lengths agree with each other. Structurally naive,
/// but it fails in completely different ways from a real parser, which is the point.
fn find_sni_by_scanning(buf: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i + 9 <= buf.len() {
        if buf[i] == 0x00 && buf[i + 1] == 0x00 {
            let ext_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            let list_len = u16::from_be_bytes([buf[i + 4], buf[i + 5]]) as usize;
            let name_type = buf[i + 6];
            let host_len = u16::from_be_bytes([buf[i + 7], buf[i + 8]]) as usize;
            let start = i + 9;
            let consistent = ext_len == list_len + 2
                && list_len == host_len + 3
                && name_type == 0x00
                && host_len > 0
                && start + host_len <= buf.len();
            if consistent {
                let host = &buf[start..start + host_len];
                // a hostname is ASCII letters/digits/dot/hyphen — cheap sanity filter
                if host
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                {
                    hits.push(start..start + host_len);
                }
            }
        }
        i += 1;
    }
    hits
}

/// The parser and the scanner must agree on every real capture.
#[test]
fn differential_parser_agrees_with_independent_scanner() {
    let mut checked = 0;
    for (client, host, bytes) in fixtures() {
        let ch = parse(&bytes).expect("parses");
        let parsed = ch.sni().expect("has sni").host.clone();
        let scanned = find_sni_by_scanning(&bytes);
        assert!(
            scanned.contains(&parsed),
            "{client} {host}: parser says {parsed:?}, independent scan found {scanned:?}"
        );
        assert_eq!(&bytes[parsed], host.as_bytes());
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} fixtures — corpus shrank?");
}

/// The hostname the parser reports must be the one in the filename, found a third way:
/// by searching the raw bytes for the expected string.
#[test]
fn differential_reported_offset_matches_a_raw_byte_search() {
    for (client, host, bytes) in fixtures() {
        let ch = parse(&bytes).expect("parses");
        let r = ch.sni().expect("has sni").host.clone();
        let occurrences: Vec<usize> = bytes
            .windows(host.len())
            .enumerate()
            .filter(|(_, w)| *w == host.as_bytes())
            .map(|(i, _)| i)
            .collect();
        assert!(
            occurrences.contains(&r.start),
            "{client} {host}: parser offset {} not among raw occurrences {occurrences:?}",
            r.start
        );
    }
}

// ---------------------------------------------------------------- invariants

/// Whatever the parser returns, its own accessors must agree with each other.
fn assert_self_consistent(buf: &[u8]) {
    if let Ok(ch) = parse(buf) {
        if let Some(sni) = ch.sni() {
            assert!(
                sni.host.end <= buf.len(),
                "sni range {:?} escapes buffer of {}",
                sni.host,
                buf.len()
            );
            assert!(sni.host.start <= sni.host.end, "inverted range");
            assert!(sni.ext <= sni.host.start, "ext header after the hostname");
            let bytes = ch.host_bytes().expect("range was in bounds");
            assert_eq!(
                bytes,
                &buf[sni.host.clone()],
                "host_bytes disagrees with range"
            );
            if let Some(s) = ch.host_str() {
                assert_eq!(s.as_bytes(), bytes, "host_str disagrees with host_bytes");
            }
        }
        for m in [
            Marker::RecordHeader,
            Marker::SniStart,
            Marker::SniEnd,
            Marker::MidSld,
            Marker::SniExt,
        ] {
            if let Some(off) = ch.marker_offset(m) {
                assert!(
                    off > 0 && off < buf.len(),
                    "{m:?} -> {off} outside 1..{}",
                    buf.len()
                );
                // and a split there must be lossless
                let parts = chunks(buf, &SplitPoint::At(off));
                assert_eq!(parts.concat(), buf, "{m:?} split lost bytes");
            }
        }
    }
}

#[test]
fn parser_is_self_consistent_on_every_fixture() {
    for (_, _, bytes) in fixtures() {
        assert_self_consistent(&bytes);
    }
}

/// Parsing must be a pure function: same bytes in, same answer out, every time.
#[test]
fn parsing_is_deterministic() {
    for (client, host, bytes) in fixtures() {
        let a = parse(&bytes)
            .ok()
            .and_then(|c| c.host_str().map(str::to_owned));
        let b = parse(&bytes)
            .ok()
            .and_then(|c| c.host_str().map(str::to_owned));
        assert_eq!(a, b, "{client} {host}: parse is not deterministic");
    }
}

/// Every prefix of every capture: never panic, and never claim a hostname that is not
/// actually sitting at the offset it reports.
#[test]
fn every_prefix_is_safe_and_self_consistent() {
    for (_, _, bytes) in fixtures() {
        for n in 0..=bytes.len() {
            assert_self_consistent(&bytes[..n]);
        }
    }
}

// ---------------------------------------------------------------- mutation

/// Deterministic xorshift so failures reproduce exactly. No dev-dependency needed, which
/// keeps `core` free of dependencies even in tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Corrupt real captures in the ways a hostile or broken peer would, and demand that the
/// parser stays safe and self-consistent. Length fields are the interesting target: those are
/// what a parser gets wrong.
#[test]
fn random_mutations_never_panic_or_lie() {
    let fx = fixtures();
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let mut mutated = 0usize;

    for (_, _, original) in &fx {
        for _ in 0..200 {
            let mut b = original.clone();
            match rng.below(4) {
                // flip a random byte
                0 => {
                    let i = rng.below(b.len());
                    b[i] ^= 1 << rng.below(8);
                }
                // smash a random 2-byte big-endian field to a huge value
                1 => {
                    if b.len() >= 2 {
                        let i = rng.below(b.len() - 1);
                        b[i] = 0xFF;
                        b[i + 1] = 0xFF;
                    }
                }
                // truncate somewhere
                2 => {
                    let n = rng.below(b.len() + 1);
                    b.truncate(n);
                }
                // splice out a run of bytes, shifting every later length out of alignment
                _ => {
                    if b.len() > 20 {
                        let i = rng.below(b.len() - 10);
                        let n = 1 + rng.below(9);
                        b.drain(i..i + n);
                    }
                }
            }
            assert_self_consistent(&b);
            mutated += 1;
        }
    }
    assert!(mutated >= 5000, "only {mutated} mutations ran");
}

/// Pure random noise must never be parsed as a valid ClientHello with a hostname.
#[test]
fn random_noise_is_not_mistaken_for_a_clienthello() {
    let mut rng = Rng(0xD15EA5E_u64);
    let mut accepted_with_sni = 0usize;
    for _ in 0..20_000 {
        let n = 1 + rng.below(200);
        let buf: Vec<u8> = (0..n).map(|_| (rng.next() & 0xFF) as u8).collect();
        assert_self_consistent(&buf);
        if let Ok(ch) = parse(&buf) {
            if ch.sni().is_some() {
                accepted_with_sni += 1;
            }
        }
    }
    // Random bytes starting with 0x16 0x?? 0x?? then 0x01 are astronomically unlikely to
    // also carry a well-formed SNI; anything above a handful means the walk is too lax.
    assert!(
        accepted_with_sni <= 2,
        "{accepted_with_sni} random buffers were accepted as ClientHellos with an SNI"
    );
}

/// A ClientHello whose record header is intact but whose body is progressively corrupted
/// must degrade to an error, never to a wrong hostname.
#[test]
fn corrupting_length_fields_never_yields_a_wrong_hostname() {
    for (client, host, original) in fixtures() {
        let ch = parse(&original).expect("parses");
        let sni_start = ch.sni().unwrap().host.start;
        // Walk every 2-byte window before the SNI and set it to a huge length.
        for i in (5..sni_start.saturating_sub(1)).step_by(7) {
            let mut b = original.clone();
            b[i] = 0xFF;
            b[i + 1] = 0xFF;
            if let Ok(c) = parse(&b) {
                if let Some(h) = c.host_str() {
                    assert_eq!(
                        h, host,
                        "{client}: corrupting offset {i} produced hostname {h:?}"
                    );
                }
            }
        }
    }
}

/// `Truncated` must mean "buffer more", so it must never be returned for a buffer that
/// actually contains the whole record.
#[test]
fn complete_records_are_never_reported_truncated() {
    for (client, host, bytes) in fixtures() {
        match parse(&bytes) {
            Err(ParseError::Truncated) => {
                panic!(
                    "{client} {host}: complete {}-byte flight reported Truncated",
                    bytes.len()
                )
            }
            Ok(ch) => assert!(
                !ch.is_record_truncated(),
                "{client} {host}: complete flight flagged as record-truncated"
            ),
            Err(_) => {}
        }
    }
}
