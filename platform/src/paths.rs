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
