//! The measured technique: issue the first flight as several writes instead of one.
//!
//! On this line the DPI fails whenever the ClientHello does not arrive in a single TCP
//! segment — 20/20 with a split, 0/20 without, across four blocked domains on four different
//! server infrastructures. *Where* the cut falls does not matter for the DPI; it matters for
//! reliability, and byte 1 wins because a one-byte segment carries no parseable record header
//! for the DPI to work from.

use crate::clienthello::Marker;
use crate::split::{chunks, SplitPoint};

use super::{Chunk, Ctx, Transform, TransformError};

/// Where to cut, expressed either as a fixed offset or as something to be located in the
/// parsed ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum At {
    /// Inside the 5-byte TLS record header. The default, and the only position measured
    /// reliable on every target tried.
    RecordHeader,
    /// A fixed byte offset.
    Absolute(usize),
    /// Several fixed byte offsets.
    Multi(Vec<usize>),
    /// A position derived from the ClientHello's structure.
    Marker(Marker),
}

/// Split the first flight into separate writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    pub at: At,
    /// Milliseconds to wait between writes. Zero is the measured-sufficient default; a delay
    /// only helps against a DPI that coalesces, and it costs latency on every connection.
    pub delay_ms: u32,
}

impl Default for Split {
    fn default() -> Self {
        Split {
            at: At::RecordHeader,
            delay_ms: 0,
        }
    }
}

impl Split {
    pub fn at(at: At) -> Self {
        Split { at, delay_ms: 0 }
    }

    pub fn with_delay(mut self, ms: u32) -> Self {
        self.delay_ms = ms;
        self
    }

    /// Resolve `self.at` to a concrete [`SplitPoint`] for this flight.
    fn point(&self, flight: &[u8], ctx: Ctx<'_, '_>) -> Result<SplitPoint, TransformError> {
        Ok(match &self.at {
            At::RecordHeader => SplitPoint::RecordHeader,
            At::Absolute(n) => SplitPoint::At(*n),
            At::Multi(ns) => SplitPoint::Multi(ns.clone()),
            At::Marker(m) => {
                let hello = ctx.hello.ok_or(TransformError::NeedsClientHello)?;
                let off = hello
                    .marker_offset(*m)
                    .ok_or(TransformError::UnresolvablePosition)?;
                // Guard against a marker resolved against a different buffer than the one we
                // are about to cut. Cheap, and the alternative is a corrupted handshake.
                if off == 0 || off >= flight.len() {
                    return Err(TransformError::UnresolvablePosition);
                }
                SplitPoint::At(off)
            }
        })
    }
}

impl Transform for Split {
    fn name(&self) -> &'static str {
        "split"
    }

    fn apply<'a>(
        &self,
        flight: &'a [u8],
        ctx: Ctx<'a, '_>,
    ) -> Result<Vec<Chunk<'a>>, TransformError> {
        let point = self.point(flight, ctx)?;
        let parts = chunks(flight, &point);
        // A "split" that produced one chunk did not split. Say so rather than silently
        // writing the flight in one go and reporting success.
        if parts.len() < 2 && !flight.is_empty() {
            return Err(TransformError::UnresolvablePosition);
        }
        Ok(parts
            .into_iter()
            .enumerate()
            .map(|(i, bytes)| Chunk {
                bytes,
                delay_ms: if i == 0 { 0 } else { self.delay_ms },
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clienthello::parse;
    use crate::transform::flatten;

    /// Structurally valid ClientHello with a trailing extension, so the SNI is never last.
    fn hello(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&((2 + 1 + 2 + h.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&((1 + 2 + h.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
        ext.extend_from_slice(h);
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

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

    #[test]
    fn default_cuts_after_the_first_byte() {
        let b = hello("discord.com");
        let plan = Split::default().apply(&b, Ctx::default()).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].bytes, &b[..1]);
        assert_eq!(plan[1].bytes, &b[1..]);
        assert_eq!(flatten(&plan), b);
    }

    #[test]
    fn absolute_cuts_where_asked() {
        let b = hello("discord.com");
        let plan = Split::at(At::Absolute(40))
            .apply(&b, Ctx::default())
            .unwrap();
        assert_eq!(plan[0].bytes.len(), 40);
        assert_eq!(flatten(&plan), b);
    }

    #[test]
    fn multi_produces_one_more_chunk_than_cuts() {
        let b = hello("discord.com");
        let plan = Split::at(At::Multi(vec![1, 10, 40]))
            .apply(&b, Ctx::default())
            .unwrap();
        assert_eq!(plan.len(), 4);
        assert_eq!(flatten(&plan), b);
    }

    #[test]
    fn marker_needs_a_parsed_hello() {
        let b = hello("discord.com");
        let err = Split::at(At::Marker(Marker::MidSld))
            .apply(&b, Ctx::default())
            .unwrap_err();
        assert_eq!(err, TransformError::NeedsClientHello);
    }

    #[test]
    fn marker_resolves_against_the_hello() {
        let b = hello("discord.com");
        let ch = parse(&b).unwrap();
        let ctx = Ctx { hello: Some(&ch) };
        let plan = Split::at(At::Marker(Marker::MidSld))
            .apply(&b, ctx)
            .unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(flatten(&plan), b);
        // "discord" is 7 long, midpoint +3
        let host = ch.sni().unwrap().host.clone();
        assert_eq!(plan[0].bytes.len(), host.start + 3);
    }

    #[test]
    fn an_unresolvable_marker_is_an_error_not_a_silent_passthrough() {
        // No SNI in this flight, so SNI-derived markers cannot resolve.
        let b = hello("x");
        let ch = parse(&b).unwrap();
        let ctx = Ctx { hello: Some(&ch) };
        let err = Split::at(At::Marker(Marker::MidSld))
            .apply(&b, ctx)
            .unwrap_err();
        assert_eq!(err, TransformError::UnresolvablePosition);
    }

    /// A split that cannot split must fail loudly. Silently writing the flight in one go
    /// would report success while doing nothing — the exact shape of bug that let five
    /// iterations believe they were working.
    #[test]
    fn a_cut_that_would_not_split_is_rejected() {
        let b = hello("discord.com");
        for at in [
            At::Absolute(0),
            At::Absolute(b.len()),
            At::Absolute(b.len() + 100),
        ] {
            assert_eq!(
                Split::at(at.clone()).apply(&b, Ctx::default()).unwrap_err(),
                TransformError::UnresolvablePosition,
                "{at:?} should not have produced a plan"
            );
        }
    }

    #[test]
    fn delay_applies_to_every_chunk_but_the_first() {
        let b = hello("discord.com");
        let plan = Split::at(At::Multi(vec![1, 10]))
            .with_delay(15)
            .apply(&b, Ctx::default())
            .unwrap();
        assert_eq!(plan[0].delay_ms, 0);
        assert_eq!(plan[1].delay_ms, 15);
        assert_eq!(plan[2].delay_ms, 15);
    }

    /// The invariant that keeps handshakes intact: a transform reorders writes, never bytes.
    #[test]
    fn every_configuration_preserves_the_byte_stream() {
        let b = hello("cdn.prod.website-files.com");
        let ch = parse(&b).unwrap();
        let ctx = Ctx { hello: Some(&ch) };
        let configs = [
            At::RecordHeader,
            At::Absolute(1),
            At::Absolute(2),
            At::Absolute(b.len() - 1),
            At::Multi(vec![1, 2, 3, 50]),
            At::Marker(Marker::SniStart),
            At::Marker(Marker::MidSld),
            At::Marker(Marker::SniExt),
        ];
        for at in configs {
            let plan = Split::at(at.clone()).apply(&b, ctx).unwrap();
            assert_eq!(flatten(&plan), b, "{at:?} corrupted the stream");
            assert!(
                plan.iter().all(|c| !c.bytes.is_empty()),
                "{at:?} produced an empty write"
            );
            assert!(plan.len() >= 2, "{at:?} did not split");
        }
    }
}
