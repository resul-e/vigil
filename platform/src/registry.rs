//! The only part of this crate that talks to Windows.
//!
//! Deliberately thin: read three values, write three values. Every decision about *what* to
//! write lives in [`crate::sysproxy`], which is pure and tested on Linux.
//!
//! On non-Windows this compiles to stubs so the rest of the crate — and its tests — build
//! anywhere.

use crate::sysproxy::ProxySettings;

#[cfg(windows)]
const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Debug)]
pub enum Error {
    Unsupported,
    Io(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Unsupported => f.write_str("system proxy control is Windows-only"),
            Error::Io(e) => f.write_str(e),
        }
    }
}

#[cfg(windows)]
pub fn read_current() -> Result<ProxySettings, Error> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let k = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(KEY)
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(ProxySettings {
        enabled: k.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1,
        server: k.get_value::<String, _>("ProxyServer").unwrap_or_default(),
        bypass: k
            .get_value::<String, _>("ProxyOverride")
            .unwrap_or_default(),
    })
}

#[cfg(windows)]
pub fn apply(s: &ProxySettings) -> Result<(), Error> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;

    let k = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(KEY, KEY_SET_VALUE)
        .map_err(|e| Error::Io(e.to_string()))?;
    k.set_value("ProxyEnable", &u32::from(s.enabled))
        .map_err(|e| Error::Io(e.to_string()))?;
    k.set_value("ProxyServer", &s.server)
        .map_err(|e| Error::Io(e.to_string()))?;
    k.set_value("ProxyOverride", &s.bypass)
        .map_err(|e| Error::Io(e.to_string()))?;
    refresh();
    Ok(())
}

/// Tell WinINET the settings changed; without this, already-running apps keep the old ones,
/// and the flat values we just wrote are not necessarily what a WinINET client resolves.
///
/// **This did not work until 2026-08-08.** It shelled out to
/// `rundll32.exe wininet.dll,InternetSetOption 0 39 0 0`, an incantation that is widely copied
/// and cannot work: `rundll32` calls its entry point as
/// `(HWND, HINSTANCE, LPSTR lpCmdLine, int nCmdShow)`, so the four "arguments" arrive as a
/// single string — `dwOption` receives wininet's own module handle and `lpBuffer` receives a
/// pointer to the text `"0 39 0 0"`. WinINET was never notified, in any build, on any machine,
/// while the comment above claimed it was. Found while looking for why a volunteer's Chromium
/// ignored a proxy this function had just written; see `docs/14-second-network.md` §7.
///
/// Declared by hand rather than through a bindings crate, the same call the rest of this crate
/// makes: two declarations are easier to audit than a dependency.
#[cfg(windows)]
fn refresh() {
    #[link(name = "wininet")]
    unsafe extern "system" {
        fn InternetSetOptionW(
            handle: *mut core::ffi::c_void,
            option: u32,
            buffer: *const core::ffi::c_void,
            length: u32,
        ) -> i32;
    }
    // The order is not arbitrary: SETTINGS_CHANGED says the stored configuration is different,
    // REFRESH makes WinINET re-read it. Both take a null handle and no buffer.
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    unsafe {
        InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            core::ptr::null(),
            0,
        );
        InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            core::ptr::null(),
            0,
        );
    }
}

#[cfg(not(windows))]
pub fn read_current() -> Result<ProxySettings, Error> {
    Err(Error::Unsupported)
}

#[cfg(not(windows))]
pub fn apply(_s: &ProxySettings) -> Result<(), Error> {
    Err(Error::Unsupported)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    /// On Linux the stubs must fail loudly rather than pretending to have worked. A silent
    /// no-op here would mean the proxy thinks it owns the system settings when it does not.
    #[test]
    fn the_non_windows_stubs_report_unsupported() {
        assert!(matches!(read_current(), Err(Error::Unsupported)));
        assert!(matches!(
            apply(&ProxySettings::default()),
            Err(Error::Unsupported)
        ));
    }
}
