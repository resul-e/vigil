//! Reading and writing the user's proxy environment variables. The only part of
//! [`crate::envproxy`] that talks to Windows.
//!
//! Deliberately thin: read four values, write or delete four values, then tell the shell. Every
//! decision about *what* to write is pure and tested on Linux.
//!
//! `HKCU\Environment` rather than the process environment, because the point is to reach
//! applications the user starts *later* — a game launched from the Start menu inherits from
//! Explorer, which reloads this on the broadcast below. A process already running keeps the
//! environment it was born with, so a client that was open before the toggle has to be
//! restarted. That is a real limitation and the interface says so rather than pretending.

use crate::envproxy::EnvProxy;
#[cfg(windows)]
use crate::envproxy::NAMES;

#[cfg(windows)]
const KEY: &str = "Environment";

#[derive(Debug)]
pub enum Error {
    Unsupported,
    Io(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Unsupported => f.write_str("environment proxy control is Windows-only"),
            Error::Io(e) => f.write_str(e),
        }
    }
}

#[cfg(windows)]
pub fn read_current() -> Result<EnvProxy, Error> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let k = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(KEY)
        .map_err(|e| Error::Io(e.to_string()))?;
    // Windows registry value names are case-insensitive, so one lookup finds `http_proxy` too.
    let get = |name: &str| {
        k.get_value::<String, _>(name)
            .ok()
            .filter(|v| !v.is_empty())
    };
    Ok(EnvProxy {
        http: get(NAMES[0]),
        https: get(NAMES[1]),
        all: get(NAMES[2]),
        no_proxy: get(NAMES[3]),
    })
}

#[cfg(windows)]
pub fn apply(e: &EnvProxy) -> Result<(), Error> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;

    let k = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(KEY, KEY_SET_VALUE)
        .map_err(|e| Error::Io(e.to_string()))?;
    for (name, value) in e.pairs() {
        match value {
            // Deleted, not blanked. An empty `HTTP_PROXY` means "proxy of empty name" to some
            // clients and "no proxy" to others; absent means the same thing to all of them.
            None => {
                let _ = k.delete_value(name);
            }
            Some(v) => k
                .set_value(name, &v.to_string())
                .map_err(|e| Error::Io(e.to_string()))?,
        }
    }
    broadcast();
    Ok(())
}

/// Tell the shell the environment changed, so processes started from now on see it.
///
/// `SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment")` is the documented
/// way. Without it Explorer keeps handing out the old block until the next sign-in, and the
/// setting looks like it did nothing.
#[cfg(windows)]
fn broadcast() {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    let param: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result: usize = 0;
    // A hung top-level window must not hold the interface thread — hence the timeout and
    // `SMTO_ABORTIFHUNG`.
    //
    // **But "returns after the timeout" is not what this does, and the comment used to say it was.**
    // Windows documents `HWND_BROADCAST` as applying the timeout *per window*, so the worst case is
    // the timeout multiplied by however many top-level windows the desktop has. Measured here at
    // ~220 ms on a machine with 280 of them, seventeen already not responding — cheap in practice,
    // and unbounded in principle. That is why the caller does this **last** when disengaging: the
    // one path where being slow costs a stranded machine is session end, and there the registry
    // restore has to be finished before anything can decide we are hung.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(PCWSTR(param.as_ptr()).as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            3000,
            Some(&mut result),
        );
    }
}

#[cfg(not(windows))]
pub fn read_current() -> Result<EnvProxy, Error> {
    Err(Error::Unsupported)
}

#[cfg(not(windows))]
pub fn apply(_e: &EnvProxy) -> Result<(), Error> {
    Err(Error::Unsupported)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    /// The stubs must fail loudly rather than pretending. A silent no-op would let the app
    /// report "engaged" on a platform where nothing was written.
    #[test]
    fn the_non_windows_stubs_report_unsupported() {
        assert!(matches!(read_current(), Err(Error::Unsupported)));
        assert!(matches!(
            apply(&EnvProxy::default()),
            Err(Error::Unsupported)
        ));
    }
}
