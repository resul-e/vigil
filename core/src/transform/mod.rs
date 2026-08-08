//! Transforms — the composable pieces the strategy engine assembles.
//!
//! A transform takes the first client-to-server flight and returns the sequence of writes the
//! proxy should perform instead of the single write the client asked for. That is the whole
//! contract. No sockets, no clock, no driver: bytes in, a plan for bytes out.
//!
//! Delay is expressed as **data** (`Chunk::delay_ms`), never by sleeping. Core must stay
//! pure — a transform that could sleep is a transform that cannot be unit tested, and that is
//! precisely why the five deleted iterations had no tests.

pub mod split;
pub mod tlsrec;

use crate::clienthello::ClientHello;

pub use split::Split;
pub use tlsrec::TlsRecordFrag;

/// One write, in order. The proxy waits `delay_ms` before issuing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk<'a> {
    pub bytes: &'a [u8],
    /// Milliseconds to wait *before* this write. Zero for the first chunk in practice.
    pub delay_ms: u32,
}

impl<'a> Chunk<'a> {
    pub fn now(bytes: &'a [u8]) -> Self {
        Chunk { bytes, delay_ms: 0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformError {
    /// The transform needs a parsed ClientHello and did not get one.
    NeedsClientHello,
    /// The requested position could not be resolved for this flight — e.g. a marker that
    /// depends on an SNI the flight does not carry, or a cut that would be degenerate.
    UnresolvablePosition,
}

/// Everything a transform may look at besides the raw bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ctx<'a, 'b> {
    /// The parsed ClientHello, when the flight is one and parsing succeeded.
    pub hello: Option<&'b ClientHello<'a>>,
}

/// A single technique. Pure: same inputs, same plan, always.
pub trait Transform {
    fn name(&self) -> &'static str;

    /// Produce the writes to issue for this flight.
    ///
    /// Implementations must guarantee that concatenating the returned chunks reproduces
    /// `flight` exactly — a transform may reorder *writes*, never bytes.
    fn apply<'a>(
        &self,
        flight: &'a [u8],
        ctx: Ctx<'a, '_>,
    ) -> Result<Vec<Chunk<'a>>, TransformError>;
}

/// Concatenate a plan back into the byte stream it will produce on the wire.
///
/// Used by tests and by the proxy's own debug assertions: if this does not equal the input,
/// the transform corrupted the handshake.
pub fn flatten(chunks: &[Chunk<'_>]) -> Vec<u8> {
    chunks
        .iter()
        .flat_map(|c| c.bytes.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_reassembles_a_plan() {
        let b = b"hello world";
        let plan = vec![Chunk::now(&b[..5]), Chunk::now(&b[5..])];
        assert_eq!(flatten(&plan), b);
    }

    #[test]
    fn chunk_now_has_no_delay() {
        assert_eq!(Chunk::now(b"x").delay_ms, 0);
    }

    #[test]
    fn flatten_of_an_empty_plan_is_empty() {
        assert!(flatten(&[]).is_empty());
    }
}
