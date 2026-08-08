//! Running one piece of cleanup when the process is asked to stop.
//!
//! Without this, Ctrl-C or closing the console window leaves the system proxy pointing at a
//! listener that is no longer there — the exact state `vigil-repair` exists to undo, reached
//! by the most ordinary way anyone stops a command-line program.
//!
//! Windows gives a console control handler a few seconds before it kills the process, which
//! is far more than a handful of registry writes needs.
//!
//! The declaration is written out by hand rather than pulling in a Windows bindings crate:
//! it is four lines, and this crate's whole point is that the parts touching the OS are small
//! enough to read.

use std::sync::OnceLock;

static ON_STOP: OnceLock<fn()> = OnceLock::new();

/// Run `f` when the process is asked to stop. Only the first call registers.
///
/// Returns whether a handler could actually be installed; on platforms where it cannot, the
/// caller still gets its normal exit path and nothing is silently pretended.
pub fn on_stop(f: fn()) -> bool {
    if ON_STOP.set(f).is_err() {
        return false;
    }
    install()
}

/// Only the Windows handler calls this; on other platforms nothing can invoke it, which is
/// the honest state of affairs rather than something to paper over.
#[cfg_attr(not(windows), allow(dead_code))]
fn run_registered() {
    if let Some(f) = ON_STOP.get() {
        f();
    }
}

#[cfg(windows)]
mod imp {
    use super::run_registered;

    // BOOL WINAPI SetConsoleCtrlHandler(PHANDLER_ROUTINE, BOOL);
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    /// Ctrl-C, Ctrl-Break, console closed, user logging off, machine shutting down. All of
    /// them mean "we are about to stop", and all of them can strand the proxy setting.
    unsafe extern "system" fn handler(event: u32) -> i32 {
        const CTRL_C: u32 = 0;
        const CTRL_BREAK: u32 = 1;
        const CTRL_CLOSE: u32 = 2;
        const CTRL_LOGOFF: u32 = 5;
        const CTRL_SHUTDOWN: u32 = 6;
        match event {
            CTRL_C | CTRL_BREAK | CTRL_CLOSE | CTRL_LOGOFF | CTRL_SHUTDOWN => {
                run_registered();
                // FALSE, not TRUE, and the difference is the whole point.
                //
                // TRUE means *handled — carry on running*. Measured 2026-08-06: with TRUE,
                // Ctrl-C restored the system proxy and left vigil running, so the user who
                // pressed it got the worst of both — a process still alive, no longer
                // protecting anything, and no sign that either had happened.
                //
                // FALSE lets Windows' default handler end the process, which is what the
                // person pressing Ctrl-C asked for. The cleanup has already run by then;
                // that is the only ordering that matters here.
                0
            }
            _ => 0,
        }
    }

    pub fn install() -> bool {
        unsafe { SetConsoleCtrlHandler(Some(handler), 1) != 0 }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::run_registered;

    // Hand-declared, like the Windows arm: this crate's point is that the OS-touching surface
    // stays small enough to read.
    unsafe extern "C" {
        fn signal(sig: i32, handler: usize) -> usize;
        fn _exit(code: i32) -> !;
    }

    const SIGHUP: i32 = 1;
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    const SIG_ERR: usize = usize::MAX;

    /// Runs the cleanup and ends the process.
    ///
    /// `_exit` rather than `std::process::exit`: a signal handler may not run destructors or
    /// take locks the interrupted thread might already hold, and the cleanup this project
    /// needs — putting host settings back — has already happened by the time we get here. The
    /// same ordering the Windows handler relies on.
    extern "C" fn handler(_sig: i32) {
        run_registered();
        unsafe { _exit(0) }
    }

    pub fn install() -> bool {
        let f = handler as extern "C" fn(i32) as usize;
        let mut ok = false;
        for sig in [SIGINT, SIGTERM, SIGHUP] {
            ok |= unsafe { signal(sig, f) } != SIG_ERR;
        }
        ok
    }
}

use imp::install;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    fn bump() {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    /// Registering twice must not replace the first handler: the cleanup that matters is the
    /// one installed by whoever engaged the system proxy.
    #[test]
    fn only_the_first_registration_wins() {
        assert!(ON_STOP.set(bump).is_ok() || ON_STOP.get().is_some());
        let first = *ON_STOP.get().expect("registered");
        let _ = on_stop(bump);
        assert_eq!(
            *ON_STOP.get().expect("still registered") as usize,
            first as usize,
            "a second registration replaced the first"
        );
    }

    /// The registered function is what gets run, and running it with nothing registered is
    /// not a panic.
    #[test]
    fn running_the_registered_hook_calls_it() {
        let _ = ON_STOP.set(bump);
        let before = CALLS.load(Ordering::SeqCst);
        run_registered();
        assert_eq!(CALLS.load(Ordering::SeqCst), before + 1);
    }
}
