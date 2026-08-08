//! The two things about updating that have to survive a restart.
//!
//! Whether to check at all, and when we last did. One file, `key=value`, the same shape as every
//! other thing this project writes to disk.
//!
//! Kept apart from the strategy cache and the settings snapshots on purpose: those are state the
//! tool manages for itself, and these two are *the user's answer to a question*. A file whose whole
//! content is a decision somebody made should be findable and editable by the person who made it.

use std::path::PathBuf;

/// `updates.txt` beside the strategy cache.
pub fn path() -> Option<PathBuf> {
    crate::paths::state_dir().map(|d| d.join("updates.txt"))
}

/// What the file says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefs {
    /// Whether to look for updates at all.
    ///
    /// Default **on**. A censorship-circumvention tool that silently stops receiving fixes is worse
    /// than one that asks an occasional question, and the whole reason this feature exists is that
    /// a fix currently reaches a user only if somebody sends them a zip over WhatsApp.
    pub enabled: bool,
    /// When a check last completed, in seconds since the Unix epoch. `None` means never.
    ///
    /// Shown in the details window rather than kept private: "last checked" is how a user tells
    /// "no updates" apart from "not looking", and those are very different situations on a line
    /// that may be blocking the download.
    pub last_check: Option<u64>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            enabled: true,
            last_check: None,
        }
    }
}

/// Parse the file. Anything unreadable is the default, because a malformed preference file must not
/// stop the program — and defaulting to *on* means a corrupt file cannot silently disable updates.
pub fn parse(text: &str) -> Prefs {
    let mut p = Prefs::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Both sides trimmed. Unlike the signed manifest, which refuses whitespace because two
        // byte-different files must not parse the same, this is a file a person edits in Notepad —
        // somebody who writes `enabled = 0` means it, and refusing them would be pedantry with a
        // consequence.
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "enabled" => p.enabled = v.trim() != "0",
                "last_check" => p.last_check = v.trim().parse().ok(),
                _ => {}
            }
        }
    }
    p
}

pub fn render(p: &Prefs) -> String {
    let mut s = String::from("# vigil update preferences\n");
    s.push_str(&format!("enabled={}\n", u8::from(p.enabled)));
    if let Some(t) = p.last_check {
        s.push_str(&format!("last_check={t}\n"));
    }
    s
}

pub fn read() -> Prefs {
    crate::paths::state_dir()
        .map(|d| read_in(&d))
        .unwrap_or_default()
}

/// The same, from a directory the caller names — so a test owns its own directory instead of moving
/// the environment out from under the whole process. See `locale::saved_lang_in` for why.
pub fn read_in(dir: &std::path::Path) -> Prefs {
    std::fs::read_to_string(dir.join("updates.txt"))
        .ok()
        .map(|t| parse(&t))
        .unwrap_or_default()
}

/// Best effort. A preference that fails to save is one the user sets again; refusing to act on their
/// answer because it could not be written down would be worse.
pub fn write(p: &Prefs) -> std::io::Result<()> {
    let Some(dir) = crate::paths::state_dir() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no state directory",
        ));
    };
    write_in(&dir, p)
}

pub fn write_in(dir: &std::path::Path, p: &Prefs) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("updates.txt"), render(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default has to be *on*, and a broken file has to land on the default. Otherwise a corrupt
    /// preference file is a silent way to stop a user receiving fixes.
    #[test]
    fn anything_unreadable_leaves_updates_switched_on() {
        assert!(Prefs::default().enabled);
        for junk in [
            "",
            "   ",
            "nonsense",
            "enabled",
            "=0",
            "# only a comment\n",
            "\0",
        ] {
            assert!(parse(junk).enabled, "{junk:?} must not disable updates");
        }
    }

    #[test]
    fn only_an_explicit_zero_switches_them_off() {
        assert!(!parse("enabled=0").enabled);
        assert!(!parse("enabled=0\n").enabled);
        assert!(!parse("  enabled = 0  ").enabled);
        for on in ["enabled=1", "enabled=yes", "enabled=true", "enabled=x"] {
            assert!(parse(on).enabled, "{on:?}");
        }
    }

    #[test]
    fn the_last_check_time_round_trips_and_a_bad_one_is_simply_absent() {
        assert_eq!(
            parse("last_check=1760000000").last_check,
            Some(1_760_000_000)
        );
        assert_eq!(parse("last_check=never").last_check, None);
        assert_eq!(parse("last_check=").last_check, None);

        let p = Prefs {
            enabled: false,
            last_check: Some(42),
        };
        assert_eq!(parse(&render(&p)), p);
        let never = Prefs {
            enabled: true,
            last_check: None,
        };
        assert_eq!(parse(&render(&never)), never);
    }

    #[test]
    fn unknown_keys_are_ignored_rather_than_fatal() {
        let p = parse("enabled=0\nchannel=beta\nlast_check=7\n");
        assert!(!p.enabled);
        assert_eq!(p.last_check, Some(7));
    }

    /// A real round trip through a real file, in a directory this test owns rather than by moving
    /// the environment for the whole process — which is what made a sibling test fail once.
    #[test]
    fn the_preferences_survive_a_round_trip_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "vigil-prefs-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");

        assert_eq!(read_in(&dir), Prefs::default(), "nothing written yet");
        let p = Prefs {
            enabled: false,
            last_check: Some(1_760_000_000),
        };
        write_in(&dir, &p).expect("writes");
        assert_eq!(read_in(&dir), p);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
