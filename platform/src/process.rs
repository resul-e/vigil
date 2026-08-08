//! Is that process still running?
//!
//! Needed by the instance lock: a lock file whose owner has died must be taken over, or a
//! single crash would mean the tool refuses to start until someone deletes a file by hand.
//! Getting this wrong in the *other* direction is worse — treating a live owner as dead lets
//! two vigils fight over the system proxy, and whichever exits last writes its idea of
//! "before" over the other's.

/// Whether a process with this id currently exists.
///
/// Conservative by design: when the answer cannot be determined, it says **alive**, because
/// refusing to start is a recoverable annoyance and double-engaging the system proxy is not.
pub fn is_alive(pid: u32) -> bool {
    imp::is_alive(pid)
}

#[cfg(windows)]
mod imp {
    // Same reasoning as `shutdown`: two declarations are easier to audit than a bindings
    // crate, and this crate exists to keep the OS-touching surface small.
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        fn CloseHandle(h: isize) -> i32;
        fn GetLastError() -> u32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_INVALID_PARAMETER: u32 = 87;

    pub fn is_alive(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h != 0 {
            unsafe { CloseHandle(h) };
            return true;
        }
        // "No such process" is the only error that means dead. Access-denied means it exists
        // and belongs to someone else, which for our purposes is very much alive.
        unsafe { GetLastError() != ERROR_INVALID_PARAMETER }
    }
}

#[cfg(not(windows))]
mod imp {
    // `kill(pid, 0)` rather than `/proc/{pid}`, and the difference is not cosmetic: macOS has
    // no `/proc`, so the old check reported **every** process as dead. That inverts this
    // module's own rule — "when the answer cannot be determined, say alive" — and the thing it
    // protects is the instance lock, so the failure would have been two vigils fighting over
    // the system proxy, each writing its idea of "before" over the other's.
    //
    // Declared by hand, like `shutdown`: two lines are easier to audit than a bindings crate.
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }

    /// "No such process". The only errno that means dead.
    const ESRCH: i32 = 3;

    pub fn is_alive(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        // A value that does not fit `pid_t` cannot be a running process, so it is dead —
        // and it must be, or a lock file holding a nonsense pid could never be reclaimed.
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        // Signal 0 performs the permission and existence checks and sends nothing.
        if unsafe { kill(pid, 0) } == 0 {
            return true;
        }
        // EPERM means it exists and belongs to somebody else, which is very much alive.
        // Anything unrecognised is alive too, for the same reason the Windows arm says so.
        std::io::Error::last_os_error().raw_os_error() != Some(ESRCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_alive() {
        assert!(is_alive(std::process::id()));
    }

    #[test]
    fn pid_zero_is_never_a_lock_owner() {
        assert!(
            !is_alive(0),
            "pid 0 is not a process we could be waiting on"
        );
    }

    /// A pid that cannot exist must read as dead, or a stale lock would never be reclaimed
    /// and the tool would refuse to start after a single crash.
    #[test]
    fn an_impossible_pid_is_dead() {
        assert!(!is_alive(u32::MAX - 1));
        // Just past `pid_t`, which is where the Unix arm has to decide rather than ask.
        assert!(!is_alive(i32::MAX as u32 + 1));
    }

    /// The rule the instance lock depends on, stated as a test: an answer we cannot determine
    /// must come back *alive*. Declaring a live owner dead is what lets two vigils fight over
    /// the system proxy, and the loser's idea of "before" is what gets restored.
    #[test]
    fn a_process_we_may_not_query_still_counts_as_alive() {
        // pid 1 exists on every Unix and belongs to root; on Windows the same reasoning is
        // covered by the access-denied branch. Either way the answer must be "alive".
        #[cfg(not(windows))]
        assert!(is_alive(1), "pid 1 must never read as dead");
    }
}
