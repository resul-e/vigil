//! Updating vigil, over a line that censors the download.
//!
//! The design is in `docs/18-auto-update.md`. The short version of why this is its own crate:
//! it is the only one that links rustls and a signature verifier, so neither reaches
//! `vigil-app.exe` — which every user runs — or `vigil-repair.exe`, which is the safety net and
//! must keep working when everything else has gone wrong.
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
pub mod stage;
pub mod verify;
pub mod version;

pub use manifest::{check_trust, is_newer_than, Manifest, Reject, Trust};
pub use plan::{plan, Digests, Plan, Refusal, SwapStep};
pub use verify::{verify, verify_with, Verified, VerifyError};
pub use version::Version;
