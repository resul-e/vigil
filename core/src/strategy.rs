//! A strategy is an ordered composition of transforms, plus a stable textual name.
//!
//! The name matters as much as the behaviour: the calibrator has to persist "what worked for
//! this host", and a per-host cache keyed on a struct is a cache nobody can read, diff or
//! paste into a bug report. So a strategy round-trips through a short string —
//! `tlsrec:64+split:1` — and that round trip is a tested property.
//!
//! Composition order is fixed and not configurable: rewrite first, then choose write
//! boundaries. The reverse is meaningless, because rewriting moves every offset the split
//! would have chosen.

use core::fmt;

use crate::clienthello::{parse, Marker};
use crate::transform::split::{At, Split};
use crate::transform::tlsrec::TlsRecordFrag;
use crate::transform::{Ctx, Transform};

/// One write the proxy performs. Owned, because a rewriting transform produces new bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    pub bytes: Vec<u8>,
    pub delay_ms: u32,
}

/// The result of planning: what to write, and which transforms actually applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub writes: Vec<Write>,
    /// Names of the transforms that ran. Empty means the flight goes out untouched.
    pub applied: Vec<&'static str>,
}

impl Plan {
    pub fn total_bytes(&self) -> usize {
        self.writes.iter().map(|w| w.bytes.len()).sum()
    }

    /// The byte stream this plan puts on the wire.
    pub fn flatten(&self) -> Vec<u8> {
        self.writes
            .iter()
            .flat_map(|w| w.bytes.iter().copied())
            .collect()
    }

    pub fn did_nothing(&self) -> bool {
        self.applied.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Strategy {
    /// Re-frame the ClientHello into smaller TLS records.
    pub tls_record: Option<TlsRecordFrag>,
    /// Choose the TCP write boundaries.
    pub split: Option<Split>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseStrategyError {
    UnknownTransform(String),
    BadArg(String),
    /// The parts are individually fine but cannot mean anything together.
    Incoherent(&'static str),
}

/// Why `tlsrec` and an SNI-derived split cannot be combined. A named constant so the test and
/// the implementation cannot drift apart.
pub const TLSREC_MARKER_CONFLICT: &str =
    "tlsrec spreads the SNI across records, so an SNI-derived split position cannot resolve; \
     use a byte offset with tlsrec";

impl fmt::Display for ParseStrategyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseStrategyError::UnknownTransform(t) => write!(f, "unknown transform {t:?}"),
            ParseStrategyError::BadArg(p) => write!(f, "bad argument in {p:?}"),
            ParseStrategyError::Incoherent(why) => write!(f, "incoherent strategy: {why}"),
        }
    }
}

impl Strategy {
    /// The default that holds on **both** measured networks.
    ///
    /// It was `split:1` alone until 2026-08-04, on the strength of 20/20 against Türk
    /// Telekom. Then SansürOn was measured for the first time, and every TCP-splitting
    /// strategy scored **0/10** there — that censor reassembles the stream, and splitting it
    /// merely converts a silent drop into an active reset. `tlsrec:64` and
    /// `tlsrec:64+split:1` were 10/10 on both lines.
    ///
    /// So the default fragments at the TLS record layer *and* splits, because the two defeat
    /// different censors and neither costs anything against the other's. A single national
    /// preset was never going to work; this is the closest thing to one.
    pub fn measured_default() -> Self {
        Strategy {
            tls_record: Some(TlsRecordFrag::new(64)),
            split: Some(Split::default()),
        }
    }

    /// Split at byte 1 and nothing else — the old default, kept because it is what 20/20 on
    /// the home line was measured with and the golden tests are written against it.
    pub fn split_only() -> Self {
        Strategy {
            tls_record: None,
            split: Some(Split::default()),
        }
    }

    pub fn passthrough() -> Self {
        Strategy::default()
    }

    /// Plan the writes for `flight`.
    ///
    /// A transform that cannot apply is skipped, not fatal: the connection still goes
    /// through, and `Plan::applied` reports what really happened so nobody has to guess.
    pub fn plan(&self, flight: &[u8]) -> Plan {
        let mut applied = Vec::new();

        // 1. rewrite
        let rewritten: Vec<u8> = match &self.tls_record {
            Some(t) => match t.apply(flight) {
                Ok(v) => {
                    applied.push("tlsrec");
                    v
                }
                Err(_) => flight.to_vec(),
            },
            None => flight.to_vec(),
        };

        // 2. chunk. Markers resolve against the *rewritten* bytes — offsets moved.
        let writes = match &self.split {
            Some(s) => {
                let hello = parse(&rewritten).ok();
                let ctx = Ctx {
                    hello: hello.as_ref(),
                };
                match s.apply(&rewritten, ctx) {
                    Ok(chunks) => {
                        applied.push("split");
                        chunks
                            .into_iter()
                            .map(|c| Write {
                                bytes: c.bytes.to_vec(),
                                delay_ms: c.delay_ms,
                            })
                            .collect()
                    }
                    Err(_) => vec![Write {
                        bytes: rewritten.clone(),
                        delay_ms: 0,
                    }],
                }
            }
            None => vec![Write {
                bytes: rewritten.clone(),
                delay_ms: 0,
            }],
        };

        Plan { writes, applied }
    }

    /// Reject combinations that cannot mean what they say.
    ///
    /// Silently skipping half of a two-part strategy would leave something that claims to do
    /// two things and does one — the failure mode this project exists to avoid.
    pub fn validate(&self) -> Result<(), ParseStrategyError> {
        if self.tls_record.is_some() {
            if let Some(Split {
                at: At::Marker(m), ..
            }) = &self.split
            {
                if !matches!(m, Marker::RecordHeader) {
                    return Err(ParseStrategyError::Incoherent(TLSREC_MARKER_CONFLICT));
                }
            }
        }
        Ok(())
    }

    /// Parse the textual form. `none` is passthrough.
    pub fn parse(s: &str) -> Result<Strategy, ParseStrategyError> {
        let s = s.trim();
        if s.is_empty() || s == "none" {
            return Ok(Strategy::passthrough());
        }
        let mut out = Strategy::default();
        for part in s.split('+') {
            let part = part.trim();
            let (kind, arg) = part.split_once(':').unwrap_or((part, ""));
            let bad = || ParseStrategyError::BadArg(part.to_string());
            match kind {
                "tlsrec" => {
                    let n: usize = arg.parse().map_err(|_| bad())?;
                    if n == 0 {
                        return Err(bad());
                    }
                    out.tls_record = Some(TlsRecordFrag::new(n));
                }
                "split" => {
                    let (at_s, delay) = match arg.split_once('@') {
                        Some((a, d)) => (a, d.parse().map_err(|_| bad())?),
                        None => (arg, 0u32),
                    };
                    let at = match at_s {
                        "" | "1" | "rec" => At::RecordHeader,
                        "midsld" => At::Marker(Marker::MidSld),
                        "sni" => At::Marker(Marker::SniStart),
                        "sniend" => At::Marker(Marker::SniEnd),
                        "sniext" => At::Marker(Marker::SniExt),
                        n if n.contains(',') => At::Multi(
                            n.split(',')
                                .map(|x| x.trim().parse())
                                .collect::<Result<_, _>>()
                                .map_err(|_| bad())?,
                        ),
                        n => At::Absolute(n.parse().map_err(|_| bad())?),
                    };
                    out.split = Some(Split {
                        at,
                        delay_ms: delay,
                    });
                }
                _ => return Err(ParseStrategyError::UnknownTransform(kind.to_string())),
            }
        }
        out.validate()?;
        Ok(out)
    }
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if let Some(t) = &self.tls_record {
            parts.push(format!("tlsrec:{}", t.max_record));
        }
        if let Some(s) = &self.split {
            let at = match &s.at {
                At::RecordHeader | At::Marker(Marker::RecordHeader) => "1".to_string(),
                At::Absolute(n) => n.to_string(),
                At::Multi(ns) => ns
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                At::Marker(Marker::MidSld) => "midsld".into(),
                At::Marker(Marker::SniStart) => "sni".into(),
                At::Marker(Marker::SniEnd) => "sniend".into(),
                At::Marker(Marker::SniExt) => "sniext".into(),
            };
            if s.delay_ms > 0 {
                parts.push(format!("split:{at}@{}", s.delay_ms));
            } else {
                parts.push(format!("split:{at}"));
            }
        }
        if parts.is_empty() {
            f.write_str("none")
        } else {
            f.write_str(&parts.join("+"))
        }
    }
}

/// The strategies the calibrator sweeps, cheapest and most reliable first.
///
/// Ordering is not cosmetic: the calibrator stops at the first that verifies, so a strategy
/// that costs latency must never sit ahead of one that does not, and one measured unreliable
/// must not sit ahead of one measured reliable.
///
/// Measured on the home line against `discord.com`, 5 trials each, 2026-08-03:
///
/// | strategy | result |
/// |----------|--------|
/// | `none` (control) | 0/5 blocked |
/// | `split:1`, `split:2`, `split:1,2,3` | 5/5 |
/// | `tlsrec:64`, `tlsrec:64+split:1`, `tlsrec:8+split:1` | 5/5 |
/// | `split:1@15` | 5/5 |
/// | `split:midsld` | **1/5 — flaky** |
///
/// `tlsrec` alone clears the block, which makes TLS-record fragmentation a genuinely
/// independent axis from TCP splitting rather than a variation on it. `midsld` is demoted to
/// the end on measurement, not taste: splitting inside the hostname leaves the record header
/// intact, so the DPI still engages its reassembly path and the outcome becomes a race.
pub fn candidates() -> Vec<Strategy> {
    // Ordered by how widely each is measured to work, not by how simple it is. The
    // calibrator tries them in turn, so a candidate that fails on half the country's
    // connections costs every user on that half a burnt connection before it moves on.
    //
    //   tlsrec:64+split:1  10/10 the home line, 10/10 SansürOn
    //   tlsrec:64          10/10 the home line, 10/10 SansürOn
    //   split:1            20/20 the home line,  0/10 SansürOn
    //   split:midsld        2/10 the home line,  0/10 SansürOn  — last, on measurement
    [
        "tlsrec:64+split:1",
        "tlsrec:64",
        "tlsrec:8+split:1",
        "split:1",
        "split:2",
        "split:1,2,3",
        "split:1@15",
        "split:midsld",
        "split:midsld@15",
    ]
    .iter()
    .map(|s| Strategy::parse(s).expect("built-in candidate must parse"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(host: &str, pad: usize) -> Vec<u8> {
        let h = host.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&((2 + 1 + 2 + h.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&((1 + 2 + h.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
        ext.extend_from_slice(h);
        ext.extend_from_slice(&21u16.to_be_bytes()); // padding extension
        ext.extend_from_slice(&(pad as u16).to_be_bytes());
        ext.extend(core::iter::repeat_n(0u8, pad));

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

    // ------------------------------------------------------------ round trip

    #[test]
    fn every_candidate_round_trips_through_its_text_form() {
        for s in candidates() {
            let text = s.to_string();
            let back = Strategy::parse(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(back, s, "{text} did not round trip");
            assert_eq!(back.to_string(), text, "{text} is not a fixed point");
        }
    }

    #[test]
    fn passthrough_is_spelled_none() {
        assert_eq!(Strategy::passthrough().to_string(), "none");
        assert_eq!(Strategy::parse("none").unwrap(), Strategy::passthrough());
        assert_eq!(Strategy::parse("").unwrap(), Strategy::passthrough());
    }

    #[test]
    fn parses_the_forms_a_human_would_type() {
        for (input, want) in [
            ("split:1", "split:1"),
            ("split:midsld@15", "split:midsld@15"),
            ("tlsrec:8+split:1", "tlsrec:8+split:1"),
            (" tlsrec:64 + split:2 ", "tlsrec:64+split:2"),
            ("split:1,2,3", "split:1,2,3"),
        ] {
            assert_eq!(
                Strategy::parse(input).unwrap().to_string(),
                want,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn rejects_nonsense_rather_than_guessing() {
        for bad in [
            "wibble",
            "split:banana",
            "tlsrec:0",
            "tlsrec:x",
            "split:1@x",
        ] {
            assert!(Strategy::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    /// `tlsrec` moves every byte, so an SNI-derived cut has nothing to resolve against in the
    /// first record. That combination is rejected rather than silently degraded.
    #[test]
    fn tlsrec_with_an_sni_marker_split_is_rejected() {
        for bad in [
            "tlsrec:64+split:sni",
            "tlsrec:8+split:midsld",
            "tlsrec:64+split:sniext",
            "tlsrec:64+split:sniend",
        ] {
            assert_eq!(
                Strategy::parse(bad).unwrap_err(),
                ParseStrategyError::Incoherent(TLSREC_MARKER_CONFLICT),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn tlsrec_composes_with_a_byte_offset_split() {
        let flight = hello("discord.com", 400);
        for good in [
            "tlsrec:64+split:1",
            "tlsrec:8+split:2",
            "tlsrec:64+split:1,2",
        ] {
            let s = Strategy::parse(good).unwrap_or_else(|e| panic!("{good}: {e}"));
            let plan = s.plan(&flight);
            assert_eq!(plan.applied, vec!["tlsrec", "split"], "{good}");
            assert!(plan.writes.len() >= 2, "{good}: split did not run");
        }
    }

    // ------------------------------------------------------------ planning

    /// The invariant everything rests on: whatever the strategy, the server must receive a
    /// stream that reassembles to the same handshake.
    #[test]
    fn no_strategy_changes_what_the_server_reassembles() {
        let flight = hello("discord.com", 400);
        let original_payload = &flight[5..];
        for s in candidates() {
            let wire = s.plan(&flight).flatten();
            let mut payload = Vec::new();
            let mut i = 0usize;
            while i + 5 <= wire.len() {
                let n = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
                assert!(i + 5 + n <= wire.len(), "{s}: record runs past the buffer");
                payload.extend_from_slice(&wire[i + 5..i + 5 + n]);
                i += 5 + n;
            }
            assert_eq!(i, wire.len(), "{s}: emitted a partial record");
            assert_eq!(
                payload, original_payload,
                "{s}: server would reassemble different bytes"
            );
        }
    }

    #[test]
    fn passthrough_emits_exactly_one_untouched_write() {
        let flight = hello("discord.com", 100);
        let plan = Strategy::passthrough().plan(&flight);
        assert_eq!(plan.writes.len(), 1);
        assert_eq!(plan.writes[0].bytes, flight);
        assert!(plan.did_nothing());
    }

    #[test]
    fn the_measured_default_splits_at_byte_one() {
        let flight = hello("discord.com", 100);
        let plan = Strategy::split_only().plan(&flight);
        assert_eq!(plan.applied, vec!["split"]);
        assert_eq!(plan.writes.len(), 2);
        assert_eq!(plan.writes[0].bytes, vec![0x16]);
        assert_eq!(plan.total_bytes(), flight.len());
    }

    #[test]
    fn composition_applies_the_rewrite_before_the_split() {
        let flight = hello("discord.com", 400);
        let plan = Strategy::parse("tlsrec:64+split:1").unwrap().plan(&flight);
        assert_eq!(plan.applied, vec!["tlsrec", "split"]);
        assert!(
            plan.total_bytes() > flight.len(),
            "record headers were not added"
        );
        assert_eq!(plan.writes.len(), 2, "split did not run on the rewrite");
    }

    /// A transform that cannot apply is skipped, and the plan says so — the connection is
    /// never dropped just because a strategy did not fit this flight.
    #[test]
    fn an_inapplicable_transform_is_skipped_not_fatal() {
        let http = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let plan = Strategy::parse("tlsrec:8+split:1").unwrap().plan(http);
        assert_eq!(plan.flatten(), http, "payload must survive regardless");
        assert!(
            !plan.applied.contains(&"tlsrec"),
            "tlsrec cannot apply to non-TLS and must not claim it did"
        );
        assert!(
            plan.applied.contains(&"split"),
            "a byte split still applies"
        );
    }

    #[test]
    fn an_empty_flight_produces_an_empty_wire_not_a_panic() {
        for s in candidates() {
            assert!(s.plan(&[]).flatten().is_empty(), "{s}");
        }
    }

    /// `midsld` measured 1/5 on the live line while the byte-offset splits measured 5/5, so
    /// it must never be tried before them.
    #[test]
    fn measured_unreliable_candidates_are_ordered_last() {
        let names: Vec<String> = candidates().iter().map(|s| s.to_string()).collect();
        let midsld = names
            .iter()
            .position(|n| n.contains("midsld"))
            .expect("midsld is a candidate");
        for reliable in ["split:1", "split:2", "split:1,2,3", "tlsrec:64"] {
            let at = names
                .iter()
                .position(|n| n == reliable)
                .unwrap_or_else(|| panic!("{reliable} missing from candidates"));
            assert!(
                at < midsld,
                "{reliable} (measured 5/5) is ordered after midsld (measured 1/5)"
            );
        }
    }

    /// Ordering rule, in priority order: measured reliability first, then cost.
    ///
    /// An earlier version of this test asserted only "no free strategy after a delayed one",
    /// which is too simple — `split:midsld` is free and measured 1/5, `split:1@15` costs
    /// 15 ms and measured 5/5, and the reliable one must win. So the cost rule applies
    /// *within* the measured-reliable group, not across the whole list.
    #[test]
    fn within_the_reliable_group_cheaper_comes_first() {
        let c = candidates();
        let reliable: Vec<&Strategy> = c
            .iter()
            .filter(|s| !s.to_string().contains("midsld"))
            .collect();
        let first_delayed = reliable
            .iter()
            .position(|s| s.split.as_ref().is_some_and(|x| x.delay_ms > 0));
        let last_free = reliable
            .iter()
            .rposition(|s| s.split.as_ref().is_none_or(|x| x.delay_ms == 0));
        if let (Some(f), Some(l)) = (first_delayed, last_free) {
            assert!(
                f > l,
                "a latency-costing strategy is ordered ahead of a free one of equal reliability"
            );
        }
    }

    #[test]
    fn every_candidate_is_distinct() {
        let mut names: Vec<String> = candidates().iter().map(|s| s.to_string()).collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate candidates: {names:?}");
    }

    #[test]
    fn arbitrary_bytes_never_panic_any_candidate() {
        let mut seed = 0xABCD_EF12u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let cands = candidates();
        for _ in 0..3_000 {
            let n = (next() % 400) as usize;
            let buf: Vec<u8> = (0..n).map(|_| (next() & 0xFF) as u8).collect();
            for s in &cands {
                let plan = s.plan(&buf);
                assert_eq!(plan.total_bytes(), plan.flatten().len());
            }
        }
    }
}
