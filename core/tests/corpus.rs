//! The step-1 gate: parse real ClientHellos, not hand-made ones.
//!
//! `tests/fixtures/` holds first flights captured off the wire from five client profiles —
//! OpenSSL (curl, python), BoringSSL (Chromium), and rustls in two configurations — ranging
//! from 231 B to 1848 B. Filenames encode the expected hostname: `{client}__{host}.bin`.
//!
//! Hand-written vectors would not have caught GREASE, extension reordering, or the fact that
//! Chrome's ClientHello never fits one TCP segment. Real bytes do.

use std::fs;
use std::path::{Path, PathBuf};

use vigil_core::clienthello::{parse, Marker, ParseError};

struct Fixture {
    client: String,
    host: String,
    bytes: Vec<u8>,
    path: PathBuf,
}

fn load() -> Vec<Fixture> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out = Vec::new();
    for e in fs::read_dir(&dir).expect("fixtures dir exists") {
        let p = e.expect("dir entry").path();
        if p.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        let stem = p.file_stem().unwrap().to_string_lossy().to_string();
        let (client, host) = stem.split_once("__").expect("name is client__host.bin");
        out.push(Fixture {
            client: client.to_string(),
            host: host.to_string(),
            bytes: fs::read(&p).expect("read fixture"),
            path: p,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    assert!(!out.is_empty(), "corpus is empty — fixtures missing");
    out
}

/// THE GATE: every real ClientHello must yield its exact hostname.
#[test]
fn sni_is_extracted_from_every_real_clienthello() {
    let fx = load();
    let mut failures = Vec::new();
    for f in &fx {
        match parse(&f.bytes) {
            Ok(ch) => match ch.host_str() {
                Some(h) if h == f.host => {}
                Some(h) => failures.push(format!("{}: got {h:?}, want {:?}", f.client, f.host)),
                None => failures.push(format!("{} {}: no SNI found", f.client, f.host)),
            },
            Err(e) => failures.push(format!("{} {}: {e:?}", f.client, f.host)),
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} fixtures failed:\n  {}",
        failures.len(),
        fx.len(),
        failures.join("\n  ")
    );
}

/// The corpus must actually cover the stacks we claim it does, or the gate is hollow.
#[test]
fn corpus_covers_every_client_profile_and_both_segment_classes() {
    let fx = load();
    for want in ["curl", "python", "chrome", "rustls", "rustls-small"] {
        assert!(
            fx.iter().any(|f| f.client == want),
            "corpus has no {want} sample"
        );
    }
    let mss = vigil_core::TYPICAL_MSS;
    assert!(
        fx.iter().any(|f| f.bytes.len() <= mss),
        "corpus has no single-segment ClientHello"
    );
    assert!(
        fx.iter().any(|f| f.bytes.len() > mss),
        "corpus has no multi-segment ClientHello — Chrome's case would go untested"
    );
}

/// Parsing any prefix of any real flight must never panic. The proxy sees partial first
/// segments constantly; a panic there is a dropped connection.
#[test]
fn no_prefix_of_any_fixture_panics() {
    for f in load() {
        for n in 0..=f.bytes.len() {
            let _ = parse(&f.bytes[..n]);
        }
    }
}

/// A flight cut before the SNI must say Truncated, never "parsed fine, no SNI".
///
/// The previous iteration got this wrong in the other direction and silently disabled itself
/// for every browser with a multi-segment ClientHello.
#[test]
fn cutting_before_the_sni_reports_truncated() {
    for f in load() {
        let ch = parse(&f.bytes).expect("full flight parses");
        let start = ch.sni().expect("has sni").host.start;
        for cut in [5usize, start / 2, start.saturating_sub(1), start + 1] {
            if cut == 0 || cut >= f.bytes.len() {
                continue;
            }
            match parse(&f.bytes[..cut]) {
                Err(ParseError::Truncated) => {}
                Ok(ch) if ch.sni().is_none() => panic!(
                    "{} {}: cut at {cut} (sni at {start}) reported no-SNI instead of Truncated",
                    f.client, f.host
                ),
                Ok(_) => panic!(
                    "{} {}: cut at {cut} (sni at {start}) claimed a complete parse",
                    f.client, f.host
                ),
                Err(_) => {}
            }
        }
    }
}

/// Every marker must resolve to a position strictly inside the flight, and the SNI-relative
/// ones must sit where their names say.
#[test]
fn markers_resolve_sanely_on_real_flights() {
    for f in load() {
        let ch = parse(&f.bytes).expect("parses");
        let host = ch.sni().expect("has sni").host.clone();

        for m in [
            Marker::RecordHeader,
            Marker::SniStart,
            Marker::SniEnd,
            Marker::MidSld,
            Marker::SniExt,
        ] {
            let off = ch
                .marker_offset(m)
                .unwrap_or_else(|| panic!("{} {}: {m:?} did not resolve", f.client, f.host));
            assert!(
                off > 0 && off < f.bytes.len(),
                "{} {}: {m:?} -> {off} is outside 1..{}",
                f.client,
                f.host,
                f.bytes.len()
            );
        }

        assert_eq!(ch.marker_offset(Marker::SniStart), Some(host.start));
        assert_eq!(ch.marker_offset(Marker::SniEnd), Some(host.end));
        assert!(ch.marker_offset(Marker::SniExt).unwrap() < host.start);

        let mid = ch.marker_offset(Marker::MidSld).unwrap();
        assert!(
            mid > host.start && mid < host.end,
            "{} {}: midsld {mid} not inside hostname {host:?}",
            f.client,
            f.host
        );
    }
}

/// Splitting at any marker must preserve the bytes exactly — this is what actually goes on
/// the wire, so a byte lost here is a corrupted handshake.
#[test]
fn splitting_at_markers_preserves_every_byte() {
    use vigil_core::{chunks, SplitPoint};
    for f in load() {
        let ch = parse(&f.bytes).expect("parses");
        for m in [Marker::RecordHeader, Marker::MidSld, Marker::SniStart] {
            let off = ch.marker_offset(m).expect("resolves");
            let parts = chunks(&f.bytes, &SplitPoint::At(off));
            assert_eq!(
                parts.len(),
                2,
                "{} {}: {m:?} did not split",
                f.client,
                f.host
            );
            let joined: Vec<u8> = parts.concat();
            assert_eq!(
                joined, f.bytes,
                "{} {}: {m:?} lost or reordered bytes",
                f.client, f.host
            );
        }
    }
}
