//! Starting with Windows. The decisions are pure; only three registry calls are not.
//!
//! `HKCU\...\Run` rather than a service or a scheduled task: no administrator rights, no
//! installer, and a user can see and delete it with the tools they already know. Three of the
//! five deleted iterations lost time to service registration going wrong, and none of them
//! needed it.

use std::path::Path;

/// Where Windows looks for things to start at logon, for this user only.
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Our value's name under that key.
pub const VALUE_NAME: &str = "vigil";

/// The command line to register for `exe`.
///
/// Quoted unconditionally. `Program Files` and `Masaüstü` both contain characters that turn
/// an unquoted path into two arguments, and the failure is silent: Windows runs the first
/// word and reports nothing.
pub fn command_for(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

/// Is this registry value ours, and pointing at this executable?
///
/// Compared case-insensitively and with quotes ignored, because a value written by an older
/// build — or edited by hand — should still be recognised as ours rather than left behind as
/// a second copy that starts a program that has moved.
pub fn is_ours(value: &str, exe: &Path) -> bool {
    let strip = |s: &str| s.trim().trim_matches('"').to_ascii_lowercase();
    strip(value) == strip(&exe.display().to_string())
}

/// What the value should say after a change, or `None` when it should be removed.
pub fn desired(enable: bool, exe: &Path) -> Option<String> {
    enable.then(|| command_for(exe))
}

#[cfg(windows)]
mod imp {
    use super::*;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    fn key() -> std::io::Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(RUN_KEY)
            .map(|(k, _)| k)
    }

    pub fn is_enabled(exe: &Path) -> bool {
        key()
            .and_then(|k| k.get_value::<String, _>(VALUE_NAME))
            .map(|v| is_ours(&v, exe))
            .unwrap_or(false)
    }

    pub fn set(enable: bool, exe: &Path) -> std::io::Result<()> {
        let k = key()?;
        match desired(enable, exe) {
            Some(v) => k.set_value(VALUE_NAME, &v),
            None => match k.delete_value(VALUE_NAME) {
                // Already absent is the state we wanted, not a failure.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                other => other,
            },
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn is_enabled(_exe: &Path) -> bool {
        false
    }

    pub fn set(_enable: bool, _exe: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "autostart is Windows-only",
        ))
    }
}

pub use imp::{is_enabled, set};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    /// The failure this quoting prevents is silent: Windows runs the first word and says
    /// nothing about the rest.
    #[test]
    fn the_command_is_quoted_so_a_space_cannot_split_it() {
        let c = command_for(&p(r"C:\Program Files\vigil\vigil-app.exe"));
        assert!(c.starts_with('"') && c.ends_with('"'), "{c}");
        assert!(c.contains("Program Files"));
    }

    #[test]
    fn a_turkish_path_survives() {
        let c = command_for(&p(r"C:\Users\resul\Masaüstü\vigil-app.exe"));
        assert!(c.contains("Masaüstü"));
        assert!(is_ours(&c, &p(r"C:\Users\resul\Masaüstü\vigil-app.exe")));
    }

    #[test]
    fn our_own_value_is_recognised() {
        let exe = p(r"C:\vigil\vigil-app.exe");
        assert!(is_ours(&command_for(&exe), &exe));
    }

    /// An older build may have written the path unquoted, and Windows itself is
    /// case-insensitive about paths. Failing to recognise those would leave a stale entry
    /// starting a program that has moved.
    #[test]
    fn an_unquoted_or_differently_cased_value_is_still_ours() {
        let exe = p(r"C:\vigil\vigil-app.exe");
        assert!(is_ours(r"C:\vigil\vigil-app.exe", &exe));
        assert!(is_ours(r"c:\VIGIL\Vigil-App.exe", &exe));
        assert!(is_ours("  \"C:\\vigil\\vigil-app.exe\"  ", &exe));
    }

    /// Somebody else's autostart entry must never be claimed, or disabling ours would delete
    /// theirs.
    #[test]
    fn another_programs_value_is_not_ours() {
        let exe = p(r"C:\vigil\vigil-app.exe");
        assert!(!is_ours(r"C:\other\thing.exe", &exe));
        assert!(!is_ours("", &exe));
        assert!(!is_ours(r"C:\vigil\vigil-app.exe --flag", &exe));
    }

    /// A moved executable must read as *not* enabled, so the interface offers to fix it
    /// rather than showing a tick over a path that no longer exists.
    #[test]
    fn the_same_name_in_another_folder_is_not_ours() {
        assert!(!is_ours(
            r"C:\old\vigil-app.exe",
            &p(r"C:\new\vigil-app.exe")
        ));
    }

    #[test]
    fn disabling_asks_for_removal_rather_than_an_empty_value() {
        let exe = p(r"C:\vigil\vigil-app.exe");
        assert_eq!(
            desired(false, &exe),
            None,
            "an empty value would still be a value"
        );
        assert!(desired(true, &exe).is_some());
    }

    /// The key is per-user, which is what keeps this free of administrator rights.
    #[test]
    fn the_key_is_the_per_user_one() {
        assert!(RUN_KEY.starts_with("Software\\"));
        assert!(!RUN_KEY.to_ascii_lowercase().contains("wow6432"));
    }
}
