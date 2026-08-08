//! Single-instance enforcement.
//!
//! Two vigils fighting over the system proxy setting is a machine with no internet: whichever
//! exits last writes its idea of "before" over the other's. A lock file holding the owning
//! pid makes the second one refuse to start, and makes a stale lock recognisable.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum Held {
    /// We own it.
    Acquired,
    /// Someone else owns it; this is their pid.
    Busy(u32),
}

#[derive(Debug)]
pub struct InstanceLock {
    path: PathBuf,
    owned: bool,
}

impl InstanceLock {
    /// Try to take the lock. A lock file whose pid is not running is treated as stale and
    /// taken over — otherwise a crash would need a manual delete before the tool could start.
    pub fn acquire(path: impl AsRef<Path>, alive: impl Fn(u32) -> bool) -> std::io::Result<Held> {
        let path = path.as_ref().to_path_buf();
        if let Ok(text) = fs::read_to_string(&path) {
            if let Some(pid) = parse_pid(&text) {
                if pid != std::process::id() && alive(pid) {
                    return Ok(Held::Busy(pid));
                }
            }
        }
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&path, format!("{}\n", std::process::id()))?;
        Ok(Held::Acquired)
    }

    pub fn take(
        path: impl AsRef<Path>,
        alive: impl Fn(u32) -> bool,
    ) -> std::io::Result<Option<Self>> {
        match Self::acquire(&path, alive)? {
            Held::Acquired => Ok(Some(InstanceLock {
                path: path.as_ref().to_path_buf(),
                owned: true,
            })),
            Held::Busy(_) => Ok(None),
        }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        if self.owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn parse_pid(text: &str) -> Option<u32> {
    text.trim().lines().next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vigil-lock-{}-{name}", std::process::id()))
    }

    #[test]
    fn an_absent_lock_is_acquired() {
        let p = tmp("absent");
        let _ = fs::remove_file(&p);
        assert_eq!(InstanceLock::acquire(&p, |_| true).unwrap(), Held::Acquired);
        assert!(p.exists());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn a_live_owner_blocks_a_second_instance() {
        let p = tmp("live");
        fs::write(&p, "424242\n").unwrap();
        assert_eq!(
            InstanceLock::acquire(&p, |pid| pid == 424242).unwrap(),
            Held::Busy(424242)
        );
        let _ = fs::remove_file(&p);
    }

    /// A crash must not require a manual delete before the tool will start again.
    #[test]
    fn a_stale_lock_is_taken_over() {
        let p = tmp("stale");
        fs::write(&p, "424242\n").unwrap();
        assert_eq!(
            InstanceLock::acquire(&p, |_| false).unwrap(),
            Held::Acquired,
            "a lock owned by a dead pid must not block startup"
        );
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn a_garbage_lock_file_is_taken_over() {
        let p = tmp("garbage");
        fs::write(&p, "not a pid at all\n").unwrap();
        assert_eq!(InstanceLock::acquire(&p, |_| true).unwrap(), Held::Acquired);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn the_lock_is_released_on_drop() {
        let p = tmp("drop");
        let _ = fs::remove_file(&p);
        {
            let l = InstanceLock::take(&p, |_| true).unwrap();
            assert!(l.is_some());
            assert!(p.exists());
        }
        assert!(!p.exists(), "lock file survived the guard");
    }

    #[test]
    fn take_returns_none_when_busy() {
        let p = tmp("busy");
        fs::write(&p, "424242\n").unwrap();
        assert!(InstanceLock::take(&p, |pid| pid == 424242)
            .unwrap()
            .is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn parses_a_pid_and_rejects_anything_else() {
        assert_eq!(parse_pid("1234\n"), Some(1234));
        assert_eq!(parse_pid("  1234  "), Some(1234));
        assert_eq!(parse_pid("1234\nextra"), Some(1234));
        for bad in ["", "abc", "-1", "12.5", "\n"] {
            assert_eq!(parse_pid(bad), None, "{bad:?}");
        }
    }
}
