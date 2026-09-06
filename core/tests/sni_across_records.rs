//! Where a `tlsrec` boundary actually falls relative to the hostname.
//!
//! This file exists because the codebase asserted something about `tlsrec` that is not true of
//! the size it ships. `strategy.rs` justified rejecting `tlsrec + split:<sni marker>` with
//! "tlsrec spreads the SNI across records" — which holds at `tlsrec:8` and **fails at
//! `tlsrec:64`**, the shipped default. The rejection is still right, for the other reason
//! stated there; the sentence was not.
//!
//! The distinction is not cosmetic, because it changes what the second network's measurement
//! means. `tlsrec:8` (name split across records) and `tlsrec:64` (name whole inside one record)
//! both scored 10/10 there. Since the one that leaves the name contiguous works just as well as
//! the one that breaks it up, **breaking up the name cannot be the reason either of them works** —
//! what they share is that no single record holds a parseable ClientHello, because the first
//! record's payload is shorter than the handshake length it declares and the later records carry
//! no handshake header at all.
//!
//! So this is a guard against re-deriving a wrong story from the same numbers, and against a
//! future change to the default size silently moving the boundary onto or off the hostname.

use vigil_core::clienthello::{parse, Marker};
use vigil_core::synth;

/// Does a record boundary of `max_record` fall strictly inside the hostname?
fn boundary_splits_name(host: &str, len: usize, max_record: usize) -> bool {
    let ch = synth::client_hello(host, len, [3u8; 32]).expect("a hello for this host and length");
    let p = parse(&ch).expect("it parses");
    let start = p.marker_offset(Marker::SniStart).expect("has an SNI");
    let end = p.marker_offset(Marker::SniEnd).expect("has an SNI");
    // `tlsrec` chunks the first record's *payload*, which begins after the 5-byte record header.
    let (first, last) = (start - 5, end - 1 - 5);
    first / max_record != last / max_record
}

/// Names that matter on both measured lines, at their own minimum and at a browser-sized hello.
const CASES: &[&str] = &[
    "discord.com",
    "www.roblox.com",
    "updates.discord.com",
    "gateway.discord.gg",
];

/// **The shipped size leaves the hostname whole.** Not "usually" — for every name and both
/// lengths measured here.
#[test]
fn tlsrec_64_never_splits_the_hostname() {
    for host in CASES {
        for len in [synth::min_len(host).expect("a floor"), 1800] {
            assert!(
                !boundary_splits_name(host, len, 64),
                "{host} at {len} B: tlsrec:64 was expected to leave the name contiguous"
            );
        }
    }
}

/// **And the small size always splits it**, which is what makes the pair a discriminator at all.
#[test]
fn tlsrec_8_always_splits_the_hostname() {
    for host in CASES {
        for len in [synth::min_len(host).expect("a floor"), 1800] {
            assert!(
                boundary_splits_name(host, len, 8),
                "{host} at {len} B: tlsrec:8 was expected to cut the name"
            );
        }
    }
}

/// The two sizes must disagree, or the sweep is measuring one thing twice and the conclusion
/// above has nothing holding it up.
#[test]
fn the_two_swept_sizes_are_a_real_discriminator() {
    for host in CASES {
        let len = synth::min_len(host).expect("a floor");
        assert_ne!(
            boundary_splits_name(host, len, 8),
            boundary_splits_name(host, len, 64),
            "{host}: tlsrec:8 and tlsrec:64 place the boundary the same way, so measuring both \
             says nothing about whether the censor needs the hostname contiguous"
        );
    }
}
