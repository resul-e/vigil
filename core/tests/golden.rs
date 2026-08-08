//! Golden tests for the split transform — step 2's gate.
//!
//! Known ClientHello in, exact expected buffers out. The offsets below were computed once
//! from the real captures and checked by hand; they are frozen here so that any drift in the
//! parser or the split logic shows up as a specific number changing, not as a vague
//! "something is different".
//!
//! Worked example, `chrome__cdn.prod.website-files.com`: the hostname occupies bytes
//! 127..153 and is `cdn.prod.website-files.com`. Its second-level label is `website-files`,
//! which starts 9 bytes into the hostname and is 13 long, so the midpoint is 9 + 13/2 = 15
//! and `MidSld` must resolve to 127 + 15 = 142.

use std::fs;
use std::path::Path;

use vigil_core::clienthello::{parse, Marker};
use vigil_core::transform::split::At;
use vigil_core::{flatten, Ctx, Split, Transform};

/// One frozen expectation: a fixture and every offset the parser must produce for it.
struct Golden {
    name: &'static str,
    len: usize,
    sni: (usize, usize),
    record_header: usize,
    sni_ext: usize,
    sni_start: usize,
    mid_sld: usize,
    sni_end: usize,
}

#[rustfmt::skip]
const GOLDEN: &[Golden] = &[
    Golden { name: "curl__discord.com",                  len:  517, sni: (153, 164), record_header: 1, sni_ext: 144, sni_start: 153, mid_sld: 156, sni_end: 164 },
    Golden { name: "python__github.com",                 len:  517, sni: (153, 163), record_header: 1, sni_ext: 144, sni_start: 153, mid_sld: 156, sni_end: 163 },
    Golden { name: "chrome__discord.com",                len: 1803, sni: (236, 247), record_header: 1, sni_ext: 227, sni_start: 236, mid_sld: 239, sni_end: 247 },
    Golden { name: "rustls-small__discord.com",          len:  232, sni: (170, 181), record_header: 1, sni_ext: 161, sni_start: 170, mid_sld: 173, sni_end: 181 },
    Golden { name: "chrome__cdn.prod.website-files.com", len: 1786, sni: (127, 153), record_header: 1, sni_ext: 118, sni_start: 127, mid_sld: 142, sni_end: 153 },
];

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.bin"));
    fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn fixtures_have_not_drifted() {
    for g in GOLDEN {
        let name = g.name;
        let b = fixture(name);
        assert_eq!(b.len(), g.len, "{name}: fixture size changed");
        let ch = parse(&b).unwrap_or_else(|err| panic!("{name}: {err:?}"));
        let sni = ch.sni().expect("has sni").host.clone();
        assert_eq!((sni.start, sni.end), g.sni, "{name}: sni range moved");
        let host = name.split_once("__").unwrap().1;
        assert_eq!(ch.host_str(), Some(host), "{name}");
    }
}

#[test]
fn markers_resolve_to_the_frozen_offsets() {
    for g in GOLDEN {
        let (name, rec, ext, start, mid, end) = (
            g.name,
            g.record_header,
            g.sni_ext,
            g.sni_start,
            g.mid_sld,
            g.sni_end,
        );
        let b = fixture(name);
        let ch = parse(&b).unwrap();
        for (m, want) in [
            (Marker::RecordHeader, rec),
            (Marker::SniExt, ext),
            (Marker::SniStart, start),
            (Marker::MidSld, mid),
            (Marker::SniEnd, end),
        ] {
            assert_eq!(ch.marker_offset(m), Some(want), "{name}: {m:?} moved");
        }
    }
}

/// THE GATE: a known ClientHello produces exactly the expected two buffers.
#[test]
fn split_produces_the_exact_expected_buffers() {
    for g in GOLDEN {
        let (name, len, rec, ext, start, mid, end) = (
            g.name,
            g.len,
            g.record_header,
            g.sni_ext,
            g.sni_start,
            g.mid_sld,
            g.sni_end,
        );
        let b = fixture(name);
        let ch = parse(&b).unwrap();
        let ctx = Ctx { hello: Some(&ch) };

        for (at, cut) in [
            (At::RecordHeader, rec),
            (At::Marker(Marker::SniExt), ext),
            (At::Marker(Marker::SniStart), start),
            (At::Marker(Marker::MidSld), mid),
            (At::Marker(Marker::SniEnd), end),
        ] {
            let plan = Split::at(at.clone())
                .apply(&b, ctx)
                .unwrap_or_else(|e| panic!("{name} {at:?}: {e:?}"));

            assert_eq!(plan.len(), 2, "{name} {at:?}: expected two writes");
            assert_eq!(
                plan[0].bytes.len(),
                cut,
                "{name} {at:?}: first buffer length"
            );
            assert_eq!(
                plan[1].bytes.len(),
                len - cut,
                "{name} {at:?}: second buffer length"
            );
            // byte-exact, not just length-exact
            assert_eq!(
                plan[0].bytes,
                &b[..cut],
                "{name} {at:?}: first buffer bytes"
            );
            assert_eq!(
                plan[1].bytes,
                &b[cut..],
                "{name} {at:?}: second buffer bytes"
            );
            assert_eq!(flatten(&plan), b, "{name} {at:?}: stream not preserved");
        }
    }
}

/// The default configuration is the one that was measured 20/20 on the live line. Freeze it:
/// a change here silently changes what every user gets.
#[test]
fn the_default_split_is_one_byte_with_no_delay() {
    let s = Split::default();
    assert_eq!(s.delay_ms, 0, "default gained a latency cost");
    let b = fixture("curl__discord.com");
    let plan = s.apply(&b, Ctx::default()).unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].bytes.len(), 1, "default cut moved off byte 1");
    assert_eq!(
        plan[0].bytes,
        &[0x16],
        "first write is the record type byte"
    );
    assert_eq!(plan[1].bytes.len(), b.len() - 1);
}

/// Every fixture, every position: the wire stream is byte-identical to the input.
#[test]
fn no_configuration_ever_alters_the_byte_stream() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut checked = 0;
    for entry in fs::read_dir(&dir).expect("fixtures") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        let b = fs::read(&p).expect("read");
        let ch = parse(&b).expect("parses");
        let ctx = Ctx { hello: Some(&ch) };
        for at in [
            At::RecordHeader,
            At::Absolute(2),
            At::Multi(vec![1, 2, 3]),
            At::Marker(Marker::SniStart),
            At::Marker(Marker::MidSld),
            At::Marker(Marker::SniEnd),
            At::Marker(Marker::SniExt),
        ] {
            let plan = Split::at(at.clone()).apply(&b, ctx).expect("resolves");
            assert_eq!(
                flatten(&plan),
                b,
                "{:?} {at:?}: corrupted the stream",
                p.file_name().unwrap()
            );
            assert!(plan.iter().all(|c| !c.bytes.is_empty()));
        }
        checked += 1;
    }
    assert!(checked >= 25, "only {checked} fixtures exercised");
}
