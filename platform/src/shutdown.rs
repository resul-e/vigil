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
///
/// **A second call reports the first call's answer, not failure.** It used to return `false` as soon
/// as `ON_STOP.set` failed — which is exactly what a *successful* second call looks like, since the
/// handler is already registered and pointing at the same function. `vigil-scan` engages twice in a
/// default run (the application phase, then the watch window), so every double-click printed "no
/// shutdown handler here — use vigil-repair if this is killed" immediately before the three minutes
/// in which the volunteer is told to use his computer normally, and it named the one safety net this
/// whole project is organised around as absent while it was armed.
///
/// The cached value is `install()`'s, not `true`: a genuine `SetConsoleCtrlHandler` failure has to
/// keep reporting itself, because a caller branches on it.
pub fn on_stop(f: fn()) -> bool {
    // **One initialisation, not two.** This used to `ON_STOP.set(f)`, then `install()`, then
    // `INSTALLED.set(ok)` — three steps across two separate `OnceLock`s, with a window between the
    // first and the last. A second caller arriving inside that window found `ON_STOP` already
    // taken and `INSTALLED` still empty, so it reported `false` for a handler that was in the act
    // of being installed successfully: the same false "no shutdown handler here" the cache was
    // added to stop, now reachable by timing instead of by call count.
    //
    // `get_or_init` closes it: exactly one caller runs the body, and every other caller blocks
    // until it finishes and then reads the same answer. `ON_STOP` is still set first inside it,
    // because on Windows the handler can fire the instant `install()` returns and it reads that.
    *INSTALLED.get_or_init(|| {
        let _ = ON_STOP.set(f);
        install()
    })
}

/// Whether the platform handler was installed, so a second `on_stop` can answer truthfully.
static INSTALLED: OnceLock<bool> = OnceLock::new();

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
        // Through `on_stop`, not `ON_STOP.set`. These tests share one process and one `OnceLock`,
        // so a test that sets `ON_STOP` behind the entry point's back leaves `INSTALLED` empty —
        // and then whichever test runs next sees a state the real program can never be in. That
        // made `a_second_registration_reports_what_the_first_installed` fail 2 runs in 40,
        // depending only on which test won the race.
        on_stop(bump);
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
        on_stop(bump); // see `only_the_first_registration_wins`: never `ON_STOP.set` directly
        let before = CALLS.load(Ordering::SeqCst);
        run_registered();
        assert_eq!(CALLS.load(Ordering::SeqCst), before + 1);
    }

    /// **A second registration must report the installation, not describe itself.**
    ///
    /// `vigil-scan` engages twice in a default run, and the second call returned `false` because
    /// `ON_STOP.set` failed — which is precisely what success looks like the second time. Every
    /// double-click printed "no shutdown handler here — use vigil-repair if this is killed" right
    /// before the window in which the volunteer is told to use his computer normally, naming the one
    /// safety net this project is organised around as absent while it was armed.
    #[test]
    fn a_second_registration_reports_what_the_first_installed() {
        // Whatever ran before in this process, the handler is registered by the end of this line.
        let first = on_stop(bump);
        let second = on_stop(bump);
        assert_eq!(
            second, first,
            "the second call must answer for the installation, not for itself"
        );
        // And the answer is the *installation's*, cached — not a fixed `true`, so a platform where
        // `install()` fails keeps reporting that on every later call rather than being papered over.
        assert_eq!(INSTALLED.get().copied(), Some(first));
        // A third call too: nothing about the count may change the answer.
        assert_eq!(on_stop(bump), first);
        // Honest limit of this test: on Linux `install()` succeeds, so replacing the cached value
        // with a constant `true` is indistinguishable here. What pins that is the equality above —
        // the returned value and the cache must be the same thing — and a platform where `install()`
        // fails would then fail this test rather than quietly reporting success.
    }

    /// **Concurrent callers must all get the installation's answer.**
    ///
    /// `on_stop` was three steps over two `OnceLock`s — set the function, install, cache the
    /// result — and a caller arriving between the first and the last found the function already
    /// registered and the cache still empty, so it answered `false` for a handler that was being
    /// installed successfully at that moment. That is the same false "no shutdown handler here —
    /// use vigil-repair if this is killed" the cache exists to prevent, reachable by timing rather
    /// than by call count. It surfaced as `a_second_registration...` failing 2 runs in 40 and then
    /// 6 in 60, which is what a race looks like when it is mistaken for an ordering problem.
    ///
    /// Every thread must agree, and none may say `false` while another says `true`.
    #[test]
    fn concurrent_registrations_all_report_the_same_installation() {
        let answers: Vec<bool> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..16).map(|_| s.spawn(|| on_stop(bump))).collect();
            hs.into_iter().map(|h| h.join().expect("thread")).collect()
        });
        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "callers disagreed about whether the handler was installed: {answers:?}"
        );
        assert_eq!(
            INSTALLED.get().copied(),
            Some(answers[0]),
            "the cache and the answers must be the same thing"
        );
    }
}
