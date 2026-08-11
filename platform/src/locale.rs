//! What language this machine is set to.
//!
//! One call, and the decision it feeds lives in `vigil_ui::lang` where it can be tested on
//! Linux. This module only fetches the number.
//!
//! `GetUserDefaultUILanguage` rather than `GetUserDefaultLocaleName`, deliberately: the *UI*
//! language is the one Windows itself is displayed in, which is what a person reading a tray
//! menu expects to match. The locale is a formatting preference — somebody in Istanbul running
//! English Windows with Turkish date formats wants an English menu, and asking the wrong
//! question would hand them a Turkish one.
//!
//! Declared by hand like the rest of this crate: one function is easier to audit than a
//! bindings crate.

/// The `VIGIL_LANG` override, read here so the whole language decision has one home.
///
/// For anyone whose system language is not the language they read, and for testing the other
/// language without changing Windows' own settings.
pub const LANG_ENV: &str = "VIGIL_LANG";

/// The Windows user interface language as a LANGID, or `None` when it cannot be asked.
///
/// Never an error: a tool that refuses to start because it could not decide on a language would
/// be worse than one that guesses. The caller falls back to its own default, which is English.
pub fn ui_langid() -> Option<u16> {
    imp::ui_langid()
}

/// The language the user picked from the menu, if they ever picked one.
///
/// Persisted on purpose, and worth saying why given that the *mode* deliberately is not: a mode
/// like passthrough is a diagnostic, and a diagnostic that quietly survives a reboot is a trap.
/// A language is not a diagnostic — it is the language the person reads, and asking them to
/// choose it again on every launch would be the bug.
pub fn saved_lang() -> Option<String> {
    saved_lang_in(&crate::paths::state_dir()?)
}

/// The same, from a directory the caller names.
///
/// Exists so the tests can use a temporary directory instead of moving `XDG_CONFIG_HOME` out from
/// under the whole process. Two tests doing that at once raced and failed exactly once, which is the
/// worst way for a test to be wrong.
pub fn saved_lang_in(dir: &std::path::Path) -> Option<String> {
    let s = std::fs::read_to_string(dir.join("lang.txt")).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Remember the chosen language. Best effort: failing to write a preference must never take the
/// interface down, and the worst case is that the next launch follows the system again.
pub fn save_lang(tag: &str) -> std::io::Result<()> {
    let Some(dir) = crate::paths::state_dir() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no state directory",
        ));
    };
    save_lang_in(&dir, tag)
}

pub fn save_lang_in(dir: &std::path::Path, tag: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("lang.txt"), tag)
}

/// The `VIGIL_LANG` value, if the user set one.
pub fn lang_override() -> Option<String> {
    std::env::var(LANG_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
}

#[cfg(windows)]
mod imp {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }

    pub fn ui_langid() -> Option<u16> {
        Some(unsafe { GetUserDefaultUILanguage() })
    }
}

#[cfg(not(windows))]
mod imp {
    /// Off Windows there is no answer to give, and inventing one from `LANG` would mean the
    /// Linux test runs quietly disagree with the product. The caller's default is the answer.
    pub fn ui_langid() -> Option<u16> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_or_blank_override_is_no_override() {
        // Whatever the environment happens to hold, blank must never count as a choice.
        std::env::set_var(LANG_ENV, "   ");
        assert_eq!(lang_override(), None);
        std::env::set_var(LANG_ENV, "tr");
        assert_eq!(lang_override().as_deref(), Some("tr"));
        std::env::remove_var(LANG_ENV);
        assert_eq!(lang_override(), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_it_declines_rather_than_guessing() {
        assert_eq!(ui_langid(), None);
    }

    /// A real round trip through a real file, in a directory this test owns.
    ///
    /// The parse rule matters — a blank or half-written file is not a choice — but so does the
    /// part no unit test of a closure can reach: that the directory is created, that the write
    /// lands, and that reading it back gives the same tag.
    ///
    /// **Through `saved_lang_in`/`save_lang_in`, not the environment.** This test used to
    /// `set_var("XDG_CONFIG_HOME")` for the whole process, and `cargo test` runs tests in threads:
    /// every sibling that resolves a state directory — `prefs::read` among them — read whatever this
    /// happened to have set at that instant, and one of them failed for it once. The `_in` variants
    /// exist precisely so a test can own a directory instead of moving the environment out from under
    /// 90-odd others. Fixing this one and leaving the same pattern here was half a fix.
    #[test]
    fn the_saved_language_survives_a_round_trip_and_blank_is_not_a_choice() {
        let dir = std::env::temp_dir().join(format!(
            "vigil-locale-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");

        assert_eq!(saved_lang_in(&dir), None, "nothing saved yet");
        save_lang_in(&dir, "tr").expect("write");
        assert_eq!(saved_lang_in(&dir).as_deref(), Some("tr"));
        save_lang_in(&dir, "en").expect("overwrite");
        assert_eq!(saved_lang_in(&dir).as_deref(), Some("en"));

        // What a half-written file looks like.
        let f = dir.join("lang.txt");
        assert!(f.exists(), "save_lang_in must write {}", f.display());
        std::fs::write(&f, "  \n").expect("write blank");
        assert_eq!(
            saved_lang_in(&dir),
            None,
            "blank must not count as a choice"
        );
        std::fs::write(&f, " tr \n").expect("write padded");
        assert_eq!(
            saved_lang_in(&dir).as_deref(),
            Some("tr"),
            "surrounding space is not part of it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
