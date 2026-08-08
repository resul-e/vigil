//! vigil's desktop interface.
//!
//! Split the same way as everything else here: [`model`] decides *what* the interface says
//! and where its pieces go, and is pure enough to test on Linux; the Win32 shell only turns
//! those decisions into windows and pixels.
//!
//! The split is not tidiness. Two of the five deleted iterations died of being written
//! interface-first, and the rule that followed was that the interface may never be load-
//! bearing. Here it observes a snapshot and emits commands; the proxy runs on its own thread
//! and never calls into it, so a wedged message loop cannot stop traffic.

pub mod model;

#[cfg(windows)]
pub mod win;
