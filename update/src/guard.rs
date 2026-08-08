//! The checks that run before a single file is replaced.
//!
//! One failure has actually happened to this project: on 2026-08-06 a machine was shut down with
//! the proxy engaged and came back with **no internet at all** until `vigil-repair` was run by
//! hand. Every safeguard was in place and none of them fired, because the process was killed rather
//! than asked to stop.
//!
//! An update is the same shape of risk with a longer fuse: settings held, binaries moving. So the
//! ordering is that the settings come back *first*, and this module is the part that refuses to
//! believe it without looking.
//!
//! ## Two processes, not one
//!
//! `vigil-app.exe` disengages and reads the registry back to confirm. Then it spawns the runner,
//! and **the runner checks again, independently, in a different process.** That is not belt and
//! braces for its own sake: a bug in the first check is exactly the kind of bug that ships, and the
//! second check is what stops it reaching the disk.
//!
//! The decision itself is pure and tested on Linux; only the reading is Windows-only.

/// What the guard decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Guard {
    /// The system does not point at a vigil. Safe to replace files.
    Clear,
    /// The system points at a vigil that is **still running**. Abort: replacing its binaries under
    /// it is how a machine ends up pointing at something that no longer exists.
    LiveOwner,
    /// The system points at a vigil that is gone — a stranded machine. Restore the settings first,
    /// using the same code `vigil-repair` runs, and then proceed. Fixing it is strictly better than
    /// refusing, because the alternative is leaving the user without internet.
    StrandedRestoreFirst,
}

/// Decide from the two things that can be observed.
///
/// `points_at_us` is whether the system proxy or the environment names a loopback address;
/// `owner_alive` is whether the instance lock's owner process still exists.
///
/// Pure, so the table is readable and the reasoning is testable. The Windows reads that feed it are
/// below and contain no decisions.
pub fn decide(points_at_us: bool, owner_alive: bool) -> Guard {
    match (points_at_us, owner_alive) {
        (false, _) => Guard::Clear,
        (true, true) => Guard::LiveOwner,
        (true, false) => Guard::StrandedRestoreFirst,
    }
}

impl Guard {
    /// May files be replaced once this guard has been acted on?
    pub fn may_proceed(&self) -> bool {
        !matches!(self, Guard::LiveOwner)
    }

    /// What to tell the user. Short, because it appears in a log they will paste into a message.
    pub fn explain(&self) -> &'static str {
        match self {
            Guard::Clear => "settings are clear",
            Guard::LiveOwner => "another vigil is running and the system points at it",
            Guard::StrandedRestoreFirst => {
                "the system points at a vigil that is gone — repairing first"
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::Guard;
    use std::path::Path;

    /// Read the machine and decide. Windows-only; the decision is [`super::decide`].
    ///
    /// `listen` is the address vigil serves on, so the question can be "does the machine point at
    /// **us**" rather than "at anything on this host". Those are different questions and answering
    /// the second one is how a user's own local proxy gets mistaken for a stranded vigil.
    pub fn check(listen: &str) -> Guard {
        let points_at_us = registry_points_at_us(listen) || env_points_at_us(listen);
        let owner_alive = lock_owner_alive();
        super::decide(points_at_us, owner_alive)
    }

    /// Both arms used to match `contains("127.0.0.1")`, and the environment arm scanned **every**
    /// variable — including `NO_PROXY`, whose value `envproxy::NO_PROXY_VALUE` literally begins
    /// `localhost,127.0.0.1,…`. So the bypass list, which exists to say "do *not* proxy these", was
    /// read as evidence that the machine was proxying through us.
    ///
    /// The consequences interlock, which is why both arms and `vigil-repair` were changed together:
    /// a third-party `HTTPS_PROXY=http://127.0.0.1:8888` made this true, the lock file is absent, so
    /// the guard decided `StrandedRestoreFirst` and ran the old `vigil-repair` — which, finding no
    /// snapshot (because vigil correctly never wrote one over somebody else's setting), cleared all
    /// four variables. It destroyed a configuration it had nothing to restore from, hitting precisely
    /// the user the "somebody else owns this" branch exists to protect.
    ///
    /// `points_at_us` compares the listen address and is tested in `vigil_platform`.
    fn registry_points_at_us(listen: &str) -> bool {
        vigil_platform::registry::read_current()
            .map(|c| vigil_platform::sysproxy::points_at_us(&c, listen))
            .unwrap_or(false)
    }

    fn env_points_at_us(listen: &str) -> bool {
        vigil_platform::envreg::read_current()
            .map(|e| vigil_platform::envproxy::points_at_us(&e, listen))
            .unwrap_or(false)
    }

    /// Is the instance lock's owner still there?
    ///
    /// Conservative in the direction that matters: when the answer cannot be determined, say alive.
    /// Refusing an update is an annoyance; replacing the binaries of a running vigil is the 2026-08-06
    /// failure with extra steps.
    fn lock_owner_alive() -> bool {
        match vigil_platform::paths::lock() {
            None => true,
            Some(p) => match std::fs::read_to_string(&p) {
                Err(_) => false,
                Ok(text) => match text.trim().parse::<u32>() {
                    Err(_) => true,
                    Ok(pid) => vigil_platform::process::is_alive(pid),
                },
            },
        }
    }

    /// Put the settings back by running the repair tool that is already sitting in the folder.
    ///
    /// Not by reimplementing the restore. `vigil-repair.exe` is the code that has been exercised on
    /// a real stranded machine, it ships from day one for exactly this, and a second implementation
    /// of "put the settings back" is a second thing that can be subtly wrong on the one path where
    /// being wrong means somebody has no internet.
    ///
    /// Note the ordering this implies: the **old** repair tool does this, before any file is
    /// replaced. That is deliberate — the one being trusted here is the one that has been on the
    /// machine and working, not the one that just arrived over the network.
    pub fn repair_settings(repair_exe: &Path) -> Result<(), String> {
        match std::process::Command::new(repair_exe).output() {
            Err(e) => Err(format!("could not run {}: {e}", repair_exe.display())),
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(format!(
                "{} exited with {:?}",
                repair_exe.display(),
                o.status.code()
            )),
        }
    }

    /// Wait for a process to exit, up to a limit. Returns whether it is gone.
    ///
    /// Bounded because a wedged parent must not wedge the update forever, and because the honest
    /// answer to "it never exited" is to abort rather than to replace files underneath it.
    pub fn wait_for_exit(pid: u32, limit: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        while std::time::Instant::now() < deadline {
            if !vigil_platform::process::is_alive(pid) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
        !vigil_platform::process::is_alive(pid)
    }

    /// Run the freshly replaced safety net and see whether it works.
    ///
    /// The one thing in the whole update verified by *running* it rather than by hashing it, because
    /// a hash proves the bytes arrived and says nothing about whether the machine can execute them.
    pub fn run_repair_version(path: &Path) -> Result<(), String> {
        match std::process::Command::new(path).arg("--version").output() {
            Err(e) => Err(format!("could not run it: {e}")),
            Ok(o) if !o.status.success() => Err(format!("exited with {:?}", o.status.code())),
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                if text.contains("vigil-repair") {
                    Ok(())
                } else {
                    Err(format!("said {:?} instead of its version", text.trim()))
                }
            }
        }
    }

    /// Start the application again, detached, so the updater can exit.
    /// Start the application again, detached, so the updater can exit.
    ///
    /// **Detached means the handles too.** A plain `spawn()` gives the child this process's stdin,
    /// stdout and stderr, and `vigil-app.exe` then holds that stdout pipe for as long as it runs —
    /// which is until the user quits it, possibly days. Anything reading the runner's output waits
    /// for the pipe to close and therefore waits forever. That is not theoretical: it hung a test
    /// the first time this path was exercised from one, and the same shape would hang any tooling
    /// that captured an `--apply` run.
    pub fn relaunch(app: &Path) -> Result<(), String> {
        std::process::Command::new(app)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Guard;
    use std::path::Path;

    /// Off Windows there is nothing to guard against and no settings to hold. Reported as clear so
    /// the tests can exercise the rest of the flow.
    pub fn check(_listen: &str) -> Guard {
        Guard::Clear
    }
    pub fn repair_settings(_repair_exe: &Path) -> Result<(), String> {
        Err("only on Windows".into())
    }
    pub fn wait_for_exit(_pid: u32, _limit: std::time::Duration) -> bool {
        true
    }
    pub fn run_repair_version(path: &Path) -> Result<(), String> {
        match std::process::Command::new(path).arg("--version").output() {
            Err(e) => Err(format!("could not run it: {e}")),
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(format!("exited with {:?}", o.status.code())),
        }
    }
    pub fn relaunch(_app: &Path) -> Result<(), String> {
        Err("only on Windows".into())
    }
}

pub use imp::{check, relaunch, repair_settings, run_repair_version, wait_for_exit};

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole table, in one place, because it is three lines of logic guarding the one failure
    /// this project has actually caused.
    #[test]
    fn the_guard_table_is_exactly_three_outcomes() {
        assert_eq!(decide(false, false), Guard::Clear);
        assert_eq!(decide(false, true), Guard::Clear);
        assert_eq!(decide(true, true), Guard::LiveOwner);
        assert_eq!(decide(true, false), Guard::StrandedRestoreFirst);
    }

    /// A live owner is the one case that must stop the update. Everything else proceeds — including
    /// the stranded case, because leaving a user without internet in order to avoid touching their
    /// files is the wrong trade.
    #[test]
    fn only_a_live_owner_stops_the_update() {
        assert!(Guard::Clear.may_proceed());
        assert!(Guard::StrandedRestoreFirst.may_proceed());
        assert!(!Guard::LiveOwner.may_proceed());
    }

    #[test]
    fn every_outcome_explains_itself_in_one_line() {
        for g in [Guard::Clear, Guard::LiveOwner, Guard::StrandedRestoreFirst] {
            let e = g.explain();
            assert!(!e.is_empty());
            assert!(!e.contains('\n'), "{e:?} must be one line");
        }
        assert!(Guard::LiveOwner.explain().contains("another vigil"));
        assert!(Guard::StrandedRestoreFirst.explain().contains("repairing"));
    }

    /// Running a program that is not there is an error rather than a panic, and the message says
    /// what was tried — this runs on somebody else's machine.
    #[test]
    fn checking_a_missing_repair_tool_fails_gracefully() {
        let missing = std::env::temp_dir().join("vigil-does-not-exist-at-all.exe");
        let e = run_repair_version(&missing).expect_err("must fail");
        assert!(e.contains("could not run it"), "{e}");
    }
}
