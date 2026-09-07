//! Updating vigil, over a line that censors the download.
//!
//! The design is in `docs/18-auto-update.md`. The short version of why this is its own crate: it
//! is the only one that links the signature verifier, and it keeps that — and the updater itself —
//! out of `vigil-repair.exe`, which is the safety net and must keep working when everything else
//! has gone wrong.
//!
//! It used to be the only crate linking rustls as well. Since 2026-09-07 it is not: the resolver
//! in `vigil-proxy` speaks DoH, which is TLS, so `vigil.exe` and `vigil-app.exe` carry it too.
//! That was a decision and not a drift — the alternatives and the reason are in
//! docs/10-v6-plan.md's DoH row.
//!
//! Dependency direction is `update → proxy → platform`, never the reverse, and a test asserts it
//! rather than trusting anybody to remember.
//!
//! What is here so far is the half that decides **whether** an update may happen: the manifest,
//! the version comparison, and the trust checks. All pure, all tested on Linux.

pub mod apply;
pub mod fetch;
pub mod guard;
pub mod http;
pub mod manifest;
pub mod plan;
pub mod release;
pub mod stage;
pub mod verify;
pub mod version;

pub use manifest::{check_trust, is_newer_than, Manifest, Reject, Trust};
pub use plan::{plan, Digests, Plan, Refusal, SwapStep};
pub use verify::{verify, verify_with, Verified, VerifyError};
pub use version::Version;
