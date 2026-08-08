//! `vigil-app` — the desktop application.
//!
//! No console: this lives in the tray, and a command window flashing up behind it would be
//! the first thing anyone noticed and the last thing they trusted.
#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() {
    #[cfg(windows)]
    vigil_ui::win::run();
    #[cfg(not(windows))]
    eprintln!("vigil-app is a Windows application; use `vigil` on other platforms.");
}
