//! Host-integration decisions: what to write into the system's proxy settings, how to roll
//! back, and how to make sure only one vigil runs at a time.
//!
//! Everything here that can be pure is pure, so it tests on Linux in milliseconds. The parts
//! that must call Windows are behind `cfg(windows)` and contain no logic worth testing.

pub mod autostart;
pub mod dnsclient;
pub mod engage;
pub mod envproxy;
pub mod envreg;
pub mod instance;
pub mod locale;
pub mod owner;
pub mod paths;
pub mod process;
pub mod proxydiag;
pub mod registry;
pub mod shutdown;
pub mod sysdns;
pub mod sysproxy;

pub use engage::{start, stop, Start, Stop};
pub use instance::InstanceLock;
pub use sysproxy::{points_at_us, settings_for, ProxySettings};
