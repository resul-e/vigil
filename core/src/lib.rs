//! Pure logic for the DPI-bypass tool.
//!
//! Nothing in this crate performs I/O, reads the clock, or touches a driver. Every function
//! is bytes-in / bytes-out or numbers-in / verdict-out, which is what makes the whole thing
//! unit-testable and is why it compiles and runs natively on Linux.
//!
//! The five previous iterations could not be tested at all because their packet logic was
//! welded to WinDivert — nothing ran without the driver, so nothing was ever asserted.
//! Keeping this crate dependency-free is a deliberate structural fix, not tidiness.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod calibrate;
pub mod clienthello;
pub mod dnsmsg;
pub mod hostlist;
pub mod reader;
pub mod split;
pub mod strategy;
pub mod synth;
pub mod tls;
pub mod transform;
pub mod verdict;

pub use calibrate::{Cache, Calibrator, Progress, Trial};
pub use clienthello::{parse, ClientHello, Marker, ParseError, Sni};
pub use hostlist::{HostRules, Pattern};
pub use reader::Reader;
pub use split::{chunks, SplitPoint};
pub use strategy::{candidates, Plan, Strategy, Write};
pub use synth::{client_hello, min_len};
pub use tls::{
    record_header, shortfall, spans_multiple_segments, RecordHeader, RECORD_HEADER_LEN, TYPICAL_MSS,
};
pub use transform::{flatten, Chunk, Ctx, Split, TlsRecordFrag, Transform, TransformError};
pub use verdict::{verdict, Outcome, Tally, Verdict, MIN_TRIALS};
