//! vigil's local SOCKS5 proxy.
//!
//! Split into a pure protocol layer ([`socks5`]) and an I/O layer ([`server`]) so that
//! everything except the byte-moving itself can be unit tested without opening a socket.

pub mod dialect;
pub mod dnsserver;
pub mod http_connect;
pub mod resolver;
pub mod server;
pub mod socks4;
pub mod socks5;
pub mod ui;

pub use dialect::{sniff, Dialect, Sniff};
pub use resolver::Resolver;
pub use server::{
    host_for, plan_first_write, Config, HostRecord, Mode, Server, Shared, Stats, Target,
};
