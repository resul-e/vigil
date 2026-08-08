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
}
