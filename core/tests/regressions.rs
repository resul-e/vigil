//! Regression tests for defects found by adversarial review of the parser.
//!
//! Every test here failed before its fix. They are kept separate from `properties.rs` so the
//! provenance stays visible: these are not properties someone imagined, they are bugs that
//! shipped a green gate and were caught only by attacking the code deliberately.

use std::fs;
use std::path::Path;

use vigil_core::clienthello::{parse, Marker, ParseError};
use vigil_core::{shortfall, RECORD_HEADER_LEN};

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut v: Vec<_> = fs::read_dir(&dir)
        .expect("fixtures dir")
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension()? != "bin" {
                return None;
            }
            Some((
                p.file_stem()?.to_string_lossy().to_string(),
                fs::read(&p).ok()?,
            ))
        })
        .collect();
    v.sort();
    v
}

/// Build a structurally valid ClientHello with arbitrary leading extensions and an optional
/// trailer, deriving every length from the bytes actually emitted so the only lies are the
/// ones a test asks for.
fn hello(host: &str, lead: &[u8], trail: &[u8]) -> Vec<u8> {
    let h = host.as_bytes();
    let mut ext = Vec::new();
    ext.extend_from_slice(lead);
    ext.extend_from_slice(&0u16.to_be_bytes()); // server_name
    ext.extend_from_slice(&((2 + 1 + 2 + h.len()) as u16).to_be_bytes());
    ext.extend_from_slice(&((1 + 2 + h.len()) as u16).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
    ext.extend_from_slice(h);
    ext.extend_from_slice(trail);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01u8];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16u8, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// A trailing filler extension, so the SNI is never the last thing in the block.
fn filler(n: usize) -> Vec<u8> {
    let mut v = vec![0x00, 0x0b];
    v.extend_from_slice(&(n as u16).to_be_bytes());
    v.extend(std::iter::repeat_n(0xAAu8, n));
    v
}

// ---------------------------------------------------------------------------
// HIGH: a located hostname was discarded when the buffer ended inside a later
// extension header, making the answer non-monotonic in buffer length.
// ---------------------------------------------------------------------------

#[test]
fn a_found_hostname_is_never_lost_as_the_buffer_grows() {
    for (name, bytes) in fixtures() {
        let full = parse(&bytes).expect("full flight parses");
        let end = full.sni().expect("has sni").host.end;
        let mut first_seen: Option<usize> = None;
        for n in end..=bytes.len() {
            let got = parse(&bytes[..n])
                .ok()
                .and_then(|c| c.host_str().map(str::to_owned));
            match (&first_seen, &got) {
                (None, Some(_)) => first_seen = Some(n),
                (Some(at), None) => panic!(
                    "{name}: hostname was present at prefix {at} but gone at {n} \
                     (buffer grew, answer regressed)"
                ),
                _ => {}
            }
        }
        assert!(
            first_seen.is_some(),
            "{name}: hostname never appeared even at full length"
        );
    }
}

// ---------------------------------------------------------------------------
// HIGH/MEDIUM: `Truncated` must mean "more bytes are coming".
// ---------------------------------------------------------------------------

#[test]
fn a_complete_record_is_never_reported_truncated() {
    // Every single-byte mutation of a valid hello, keeping only mutants whose record has
    // fully arrived. None may claim truncation. 971 of these failed before the fix.
    let base = hello("discord.com", &[], &filler(4));
    let mut offenders = Vec::new();
    for i in 0..base.len() {
        for v in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
            let mut b = base.clone();
            if b[i] == v {
                continue;
            }
            b[i] = v;
            if shortfall(&b).is_some() {
                continue; // record genuinely incomplete — Truncated is correct
            }
            if matches!(parse(&b), Err(ParseError::Truncated)) {
                offenders.push((i, v));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "{} complete-record mutants reported Truncated, first few: {:?}",
        offenders.len(),
        &offenders[..offenders.len().min(8)]
    );
}

#[test]
fn a_dangling_extension_header_in_a_complete_record_is_malformed_not_truncated() {
    for stray in 1..=3usize {
        let b = hello("discord.com", &[], &vec![0xAA; stray]);
        assert_eq!(
            shortfall(&b),
            None,
            "test setup: record must be exactly complete"
        );
        match parse(&b) {
            // The SNI was found before the stray bytes, so reporting it is also correct.
            Ok(ch) => assert_eq!(ch.host_str(), Some("discord.com")),
            Err(ParseError::Malformed) => {}
            Err(e) => panic!("{stray} stray byte(s): expected Malformed or the SNI, got {e:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// MEDIUM: parsing must be bounded by the record and the handshake message.
// ---------------------------------------------------------------------------

#[test]
fn bytes_beyond_the_declared_record_are_not_parsed() {
    // Two records back to back. The second carries a different SNI. A parser that ignores
    // the record boundary walks into it and reports the attacker's hostname.
    let first = hello("discord.com", &[], &filler(4));
    let second = hello("attacker.example", &[], &filler(4));
    let mut both = first.clone();
    both.extend_from_slice(&second);

    let ch = parse(&both).expect("parses");
    assert_eq!(
        ch.host_str(),
        Some("discord.com"),
        "parser read past the first record's declared end"
    );
    let record_end = RECORD_HEADER_LEN + u16::from_be_bytes([both[3], both[4]]) as usize;
    let sni = ch.sni().unwrap();
    assert!(
        sni.host.end <= record_end,
        "sni at {:?} lies outside the declared record ending at {record_end}",
        sni.host
    );
}

#[test]
fn an_extension_may_not_spill_past_the_extensions_block() {
    // extensions_length covers only the server_name header; its body runs past the block.
    let mut b = hello("discord.com", &[], &[]);
    // locate and shrink the extensions_length field: it precedes the first extension
    let ext_len_pos = b.len()
        - (2 + 2 + 2 + 1 + 2 + "discord.com".len()) // the server_name extension
        - 2; // the extensions_length field itself
    b[ext_len_pos..ext_len_pos + 2].copy_from_slice(&4u16.to_be_bytes());
    if let Ok(ch) = parse(&b) {
        assert!(
            ch.sni().is_none(),
            "accepted an SNI whose body lies outside the declared extensions block"
        );
    }
}

// ---------------------------------------------------------------------------
// LOW: SNI body must be bounded by its own list, and empty names rejected.
// ---------------------------------------------------------------------------

#[test]
fn an_empty_hostname_is_not_accepted_as_an_sni() {
    let b = hello("", &[], &filler(4));
    if let Ok(ch) = parse(&b) {
        assert!(
            ch.sni().is_none(),
            "zero-length HostName accepted; RFC 6066 requires at least one byte"
        );
    }
}

// ---------------------------------------------------------------------------
// MEDIUM/LOW: MidSld must split strictly inside the second-level label.
// ---------------------------------------------------------------------------

#[test]
fn midsld_is_strictly_inside_the_label_or_absent() {
    for host in [
        "discord.com",
        "x.com", // 1-char SLD — must not degenerate to SniStart
        "t.co",
        "discord.com.", // fully qualified — must not select "com"
        "www.google.com.",
        "cdn.prod.website-files.com",
    ] {
        let b = hello(host, &[], &filler(4));
        let ch = parse(&b).expect("parses");
        let hr = ch.sni().expect("has sni").host.clone();
        let start = ch.marker_offset(Marker::SniStart).expect("sni start");
        match ch.marker_offset(Marker::MidSld) {
            None => {
                // Only acceptable when no label is long enough to split inside.
                assert!(
                    host.split('.').filter(|l| !l.is_empty()).count() < 2
                        || host
                            .split('.')
                            .filter(|l| !l.is_empty())
                            .rev()
                            .nth(1)
                            .is_some_and(|l| l.len() < 2),
                    "{host}: MidSld absent but a splittable label exists"
                );
            }
            Some(mid) => {
                assert_ne!(mid, start, "{host}: MidSld collapsed onto SniStart");
                assert!(
                    mid > hr.start && mid < hr.end,
                    "{host}: MidSld {mid} not inside hostname {hr:?}"
                );
                // and the label it lands in must be the second-level one
                let rel = mid - hr.start;
                let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
                let sld = labels[labels.len() - 2];
                let sld_at = host.find(sld).unwrap();
                assert!(
                    rel > sld_at && rel < sld_at + sld.len(),
                    "{host}: MidSld at {rel} is not strictly inside {sld:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The corpus must still behave, with the stricter parser.
// ---------------------------------------------------------------------------

#[test]
fn every_fixture_still_yields_its_hostname() {
    for (name, bytes) in fixtures() {
        let host = name.split_once("__").unwrap().1;
        let ch = parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(ch.host_str(), Some(host), "{name}");
    }
}

/// The real 175-byte Discord updater flight, and the strategy vigil actually ships.
///
/// Left open in `docs/17-the-notification-that-never-fired.md` §8: `tlsrec:64` had only ever been
/// validated against synthetic hellos and against the *scanner's* connections, never against the
/// updater's own captured bytes. It is the smallest flight this project has seen — 175 B, where
/// `tlsrec:64` should produce three records — and small flights are where a record-fragmentation
/// plan is most likely to degenerate into doing nothing at all.
///
/// Costs no volunteer time, which is why it should not have waited.
#[test]
fn the_real_updater_flight_is_actually_fragmented_by_the_shipped_default() {
    use vigil_core::strategy::Strategy;

    let (_, flight) = fixtures()
        .into_iter()
        .find(|(name, _)| name.starts_with("discord-updater__"))
        .expect("the captured updater flight is in the corpus");
    assert_eq!(flight.len(), 175, "the capture must be the real one");

    let s = Strategy::measured_default();
    assert_eq!(
        s.to_string(),
        "tlsrec:64+split:1",
        "the shipped default moved"
    );
    let plan = s.plan(&flight);

    assert!(
        !plan.did_nothing(),
        "the smallest real flight we have must still be transformed, applied={:?}",
        plan.applied
    );
    // Not one byte more or less on the wire than the record headers add.
    let added = plan.total_bytes() - flight.len();
    assert_eq!(
        added % RECORD_HEADER_LEN,
        0,
        "growth must be whole record headers, grew by {added}"
    );

    // What the shipped default actually puts on the wire for the smallest real flight we have,
    // written down because it is not what a reader would guess: **three TLS records delivered in
    // two writes**, `[1, 184]`. `tlsrec` re-frames *inside* a write — the record boundaries are
    // what this DPI cannot follow — and `split:1` adds the one-byte segment on top. Asserting
    // the write count alone would have been asserting the wrong thing.
    let wire = plan.flatten();
    assert_eq!(
        record_count(&wire),
        3,
        "175 B at a 64-byte boundary is three records, got {:?}",
        record_lengths(&wire)
    );
    assert_eq!(
        plan.writes
            .iter()
            .map(|w| w.bytes.len())
            .collect::<Vec<_>>(),
        vec![1, 184],
        "the one-byte segment and the remainder"
    );

    // The point of the exercise: no single write may contain a parseable ClientHello with the
    // hostname in it. A DPI that reassembles nothing sees no SNI to match.
    for (i, w) in plan.writes.iter().enumerate() {
        if let Ok(h) = parse(&w.bytes) {
            assert!(
                h.sni().is_none(),
                "write {i} still carries a complete SNI: the flight was not fragmented"
            );
        }
    }

    // And the bytes must survive: a transform that loses or reorders data would be a far worse
    // bug than one that fails to evade.
    let mut rebuilt = Vec::new();
    for w in &plan.writes {
        rebuilt.extend_from_slice(&w.bytes);
    }
    assert_eq!(
        unwrap_records(&rebuilt),
        unwrap_records(&flight),
        "the handshake bytes must be identical once the records are unwrapped"
    );
}

/// Concatenate the payloads of every TLS record in `b`, so two framings of the same handshake
/// can be compared. Returns the input unchanged if it does not look like records at all.
fn unwrap_records(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut at = 0usize;
    while at + RECORD_HEADER_LEN <= b.len() {
        if b[at] != 0x16 {
            return b.to_vec();
        }
        let n = u16::from_be_bytes([b[at + 3], b[at + 4]]) as usize;
        let start = at + RECORD_HEADER_LEN;
        let end = (start + n).min(b.len());
        out.extend_from_slice(&b[start..end]);
        at = end;
    }
    out
}

/// Lengths of the TLS records in a flattened plan.
fn record_lengths(b: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + RECORD_HEADER_LEN <= b.len() && b[at] == 0x16 {
        let n = u16::from_be_bytes([b[at + 3], b[at + 4]]) as usize;
        out.push(n);
        at += RECORD_HEADER_LEN + n;
    }
    out
}

fn record_count(b: &[u8]) -> usize {
    record_lengths(b).len()
}

/// The cross-check that matters for `sha256`: real files, and digests that came from
/// `sha256sum` rather than from this implementation.
///
/// The published NIST vectors are in the module's own tests and cover the algorithm. This covers
/// the thing the algorithm is *for*: hashing a file off disk, in chunks, and getting the same
/// answer as the tool everybody else uses. It was also verified once by hand against all six
/// release binaries — 730 KB to 2.8 MB, byte-identical on every one — but those live under
/// `target/` and cannot be a test. Fixtures can.
#[test]
fn hashing_a_real_file_agrees_with_sha256sum() {
    use vigil_core::sha256::{hex, Sha256};

    let expected: &[(&str, &str)] = &[
        (
            "chrome__discord.com",
            "8bf082bcd940bff733f10a3bc1bcb69efc339d61df6026d1ab2bee8a9dfa998b",
        ),
        (
            "discord-updater__updates.discord.com",
            "07f03bef7625960c57d1759a7cf772619c79d71482cdcd05ee7d53478c0ac834",
        ),
        (
            "curl__discord.com",
            "930fa1a11b0edccf8e6b76397e3bf79a1516ea652a62bfeffe9d53ba9fc0f779",
        ),
    ];
    let fx = fixtures();
    for (name, want) in expected {
        let (_, bytes) = fx
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("fixture {name} is missing"));

        // In one call, and again in awkward chunks, because the update path has three branches
        // and a release will hash a 2.5 MB file in 64 KB pieces.
        assert_eq!(&hex(&vigil_core::sha256::hash(bytes)), want, "{name}");
        for chunk in [1usize, 7, 64, 65, 1024] {
            let mut s = Sha256::new();
            for part in bytes.chunks(chunk) {
                s.update(part);
            }
            assert_eq!(&hex(&s.finish()), want, "{name} in {chunk}-byte chunks");
        }
    }
}
