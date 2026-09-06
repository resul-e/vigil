//! Where vigil keeps the two files that decide whether a machine can be un-stranded.
//!
//! Both live next to each other so that a user who has to clean up by hand has one place to
//! look, and so `vigil-repair` can find a snapshot written by a `vigil` it never spoke to.

use std::path::PathBuf;

/// `%APPDATA%\vigil` on Windows, `$XDG_CONFIG_HOME/vigil` or `~/.config/vigil` elsewhere.
pub fn state_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|b| PathBuf::from(b).join("vigil"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|b| b.join("vigil"))
    }
}

/// What the system proxy looked like before vigil touched it.
pub fn snapshot() -> Option<PathBuf> {
    state_dir().map(|d| d.join("sysproxy-snapshot.txt"))
}

/// What the proxy environment variables were before vigil touched them. Kept apart from the
/// registry snapshot because the two are restored independently: one of them can be somebody
/// else's while the other is ours.
pub fn env_snapshot() -> Option<PathBuf> {
    state_dir().map(|d| d.join("envproxy-snapshot.txt"))
}

/// What the machine's DNS servers were before vigil pointed them at itself.
pub fn dns_snapshot() -> Option<PathBuf> {
    state_dir().map(|d| d.join("sysdns-snapshot.txt"))
}

/// Which process currently owns the system proxy setting.
pub fn lock() -> Option<PathBuf> {
    state_dir().map(|d| d.join("instance.lock"))
}

/// The staging folder an update is downloaded into, **beside the binaries, not in the state dir**:
/// the swap is a rename and a rename has to stay on one volume.
///
/// Here rather than in `update/` because two crates need it and only one of them may depend on the
/// updater. `vigil-app.exe` copies the runner into this folder before handing over, and
/// `vigil-update.exe` looks for it there — and until 2026-08-12 each spelled the two names itself,
/// `ui/src/win.rs` with bare literals and `update/` with `stage::STAGING` / `apply::runner_path`.
/// Nothing connected them, so changing one would have left the tray writing the runner somewhere
/// the updater never looks, on the one path that cannot be fixed by a later update.
///
/// `ui` must not gain a dependency on `update` to share them — that is what keeps rustls and the
/// signature verifier out of the binary every user runs, and `update/tests/dependency_isolation.rs`
/// enforces it — so the shared home is the crate they both already depend on.
pub const STAGING_DIR: &str = ".vigil-update";

/// The copy of the updater that runs from inside [`STAGING_DIR`], so the one beside the
/// application is idle and can be replaced like any other file.
pub const RUNNER_EXE: &str = "runner.exe";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_files_live_together_and_are_distinct() {
        let (s, l) = (snapshot(), lock());
        if let (Some(s), Some(l)) = (s, l) {
            assert_eq!(
                s.parent(),
                l.parent(),
                "a user cleaning up should find one place"
            );
            assert_ne!(s, l);
            assert_eq!(s.parent(), state_dir().as_deref());
        }
    }

    /// The tray copies the runner in; the updater runs it from there. Two crates, one spelling.
    #[test]
    fn the_staging_names_are_shared_rather_than_spelled_twice() {
        assert_eq!(STAGING_DIR, ".vigil-update");
        assert_eq!(RUNNER_EXE, "runner.exe");
        // Beside the binaries, never in the state directory: the swap is a rename.
        assert!(!STAGING_DIR.contains('/') && !STAGING_DIR.contains('\\'));
    }

    /// The repair tool has its own copy of this path. If they ever disagree, a snapshot
    /// written by vigil becomes invisible to the tool that exists to use it.
    #[test]
    fn the_snapshot_is_named_what_the_repair_tool_looks_for() {
        if let Some(p) = snapshot() {
            assert_eq!(
                p.file_name().and_then(|s| s.to_str()),
                Some("sysproxy-snapshot.txt")
            );
            assert!(
                p.ends_with("vigil/sysproxy-snapshot.txt")
                    || p.ends_with("vigil\\sysproxy-snapshot.txt")
            );
        }
    }
}
