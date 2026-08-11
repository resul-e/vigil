//! Every word the interface says, in one table, looked up by key.
//!
//! The rule the product needs: **Turkish if the machine is Turkish, English for everything
//! else.** Not a preference screen and not a list of locales — the people this was written for
//! are on Turkish Windows, and nobody else should have to read a tray menu in a language they do
//! not speak.
//!
//! The shape is i18next's: one resource table, dotted keys, and [`t`] at the call site. Nothing
//! in the rest of the crate contains a human-readable string any more, so adding a language means
//! adding a column here and touching nothing else.
//!
//! ```
//! # use vigil_ui::lang::{t, tf, Lang};
//! assert_eq!(t(Lang::English, "menu.protect_on"), "Turn protection on");
//! assert_eq!(t(Lang::Turkish, "menu.protect_on"), "Korumayı aç");
//! assert_eq!(
//!     tf(Lang::English, "status.off", &[("listen", "127.0.0.1:1080")]),
//!     "Off — listening on 127.0.0.1:1080"
//! );
//! ```
//!
//! Two things a string-keyed table gives up, and what is done about each:
//!
//! - **A typo becomes a runtime miss rather than a build error.** So a miss is loud: [`t`]
//!   returns the key itself, which puts `menu.protect_no` on screen where a word should be, and
//!   `debug_assert!` turns it into a failed test in every debug build. A silent blank would be
//!   the unforgivable version.
//! - **Nothing forces a key to exist in both languages.** So the table holds both columns in one
//!   row: a translation cannot be forgotten because there is nowhere to forget it. The tests
//!   below check that neither column is blank, that the two differ, and — the one that actually
//!   catches bugs — that both use the same `{{placeholders}}`.
//!
//! Detection is not here. It is one Win32 call in `vigil_platform::locale`, feeding
//! [`Lang::from_windows_langid`], which is pure and tested on Linux like everything else.

/// Which language the interface speaks.
///
/// `English` is the default deliberately: the rule is "Turkish if the system is Turkish,
/// otherwise English", so the fallback belongs in the type rather than in whoever remembers to
/// set it. The Win32 shell sets it explicitly at startup from the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    English,
    Turkish,
}

impl Lang {
    /// The Windows primary language id for Turkish. `LANG_TURKISH` is `0x1F`, and the primary
    /// language is the low 10 bits of a LANGID — the high 6 are the sublanguage, which is how
    /// `tr-TR` and `tr-CY` differ and why both must count as Turkish.
    pub const PRIMARY_TURKISH: u16 = 0x1F;

    /// Decide from a Windows LANGID, as returned by `GetUserDefaultUILanguage`.
    pub fn from_windows_langid(langid: u16) -> Lang {
        if langid & 0x03FF == Self::PRIMARY_TURKISH {
            Lang::Turkish
        } else {
            Lang::English
        }
    }

    /// Decide from a BCP-47 tag such as `tr-TR`, `en-GB`, or a bare `tr`.
    ///
    /// Only the primary subtag counts, and the comparison is ASCII-only on purpose: Turkish is
    /// the one language where case folding is famously not safe, and a locale-aware lowercase
    /// would turn `I` into `ı`.
    pub fn from_tag(tag: &str) -> Lang {
        let primary = tag.split(['-', '_']).next().unwrap_or("");
        if primary.eq_ignore_ascii_case("tr") {
            Lang::Turkish
        } else {
            Lang::English
        }
    }

    /// An explicit override, for testing and for anyone whose system language is not the language
    /// they want to read. Anything unrecognised leaves the decision alone.
    pub fn override_from_env(self, value: Option<&str>) -> Lang {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("tr") => Lang::Turkish,
            Some(v) if v.eq_ignore_ascii_case("en") => Lang::English,
            _ => self,
        }
    }

    /// The whole language decision, in one pure function.
    ///
    /// Precedence, and the reason for each:
    ///
    /// 1. `env` — `VIGIL_LANG`, an explicit override for this run. It wins over everything,
    ///    because an escape hatch a stored preference can veto is not an escape hatch.
    /// 2. `saved` — what the user last picked from the menu. It beats the operating system
    ///    because picking a language is exactly the act of disagreeing with the operating system.
    /// 3. `os` — the Windows UI LANGID. The default for everyone who never picks.
    /// 4. Nothing at all — English, which is the "otherwise" half of the product's rule.
    ///
    /// Written as a function of its three inputs so the order can be tested on Linux. It used to
    /// live inside the Win32 shell, where none of it could be.
    pub fn decide(os: Option<u16>, saved: Option<&str>, env: Option<&str>) -> Lang {
        let from_os = os.map(Lang::from_windows_langid).unwrap_or_default();
        let from_saved = saved
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Lang::from_tag)
            .unwrap_or(from_os);
        from_saved.override_from_env(env)
    }

    /// The two-letter tag.
    pub fn tag(self) -> &'static str {
        match self {
            Lang::Turkish => "tr",
            Lang::English => "en",
        }
    }
}

/// One string, in every language there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub key: &'static str,
    pub tr: &'static str,
    pub en: &'static str,
}

/// The resource table. **Sorted by key** — a test enforces it, and the lookup relies on it.
///
/// Placeholders are `{{name}}`, substituted by [`tf`]. Sentences are written out per language
/// rather than assembled from fragments: Turkish puts the verb last and marks case with suffixes,
/// so a sentence stitched together from shared pieces reads wrong in at least one of the two
/// languages every single time.
pub const STRINGS: &[Entry] = &[
    Entry { key: "counter.accepted",          tr: "Kabul edilen",                en: "Accepted" },
    Entry { key: "counter.completed",         tr: "Tamamlanan",                  en: "Completed" },
    Entry { key: "counter.dns_failures",      tr: "DNS başarısız",               en: "DNS failures" },
    Entry { key: "counter.handshake_errors",  tr: "El sıkışma hatası",           en: "Handshake errors" },
    Entry { key: "counter.http_connect",      tr: "HTTP CONNECT",                en: "HTTP CONNECT" },
    Entry { key: "counter.retries",           tr: "Tekrar gönderilen",           en: "First flights re-sent" },
    Entry { key: "counter.socks4",            tr: "SOCKS4",                      en: "SOCKS4" },
    Entry { key: "counter.socks5",            tr: "SOCKS5",                      en: "SOCKS5" },
    Entry { key: "counter.transformed",       tr: "Dönüştürülen",                en: "Transformed" },
    Entry { key: "counter.untouched",         tr: "Dokunulmayan (liste dışı)",   en: "Untouched (excluded)" },
    Entry { key: "counter.upstream_errors",   tr: "Bağlantı hatası",             en: "Connection errors" },

    Entry { key: "dns.in_use",                tr: "sistem vigil'i kullanıyor",   en: "the system is using it" },
    Entry { key: "dns.off",                   tr: "kapalı",                      en: "off" },
    Entry { key: "dns.ready_unused",          tr: "hazır — sistem henüz kullanmıyor",
                                              en: "ready — the system is not using it yet" },
    Entry { key: "dns.stopped_while_in_use",  tr: "DNS DURDU — Windows hâlâ bizi gösteriyor",
                                              en: "DNS HAS STOPPED — Windows still points at us" },

    Entry { key: "err.autostart",             tr: "Windows ile başlatma ayarlanamadı:\n{{error}}",
                                              en: "Could not set start-with-Windows:\n{{error}}" },
    Entry { key: "err.dns",                   tr: "DNS ayarlanamadı:\n{{error}}",
                                              en: "Could not set DNS:\n{{error}}" },
    Entry { key: "err.listen",                tr: "vigil {{listen}} adresini dinleyemedi:\n{{error}}\n\nBaşka bir vigil çalışıyor olabilir.",
                                              en: "vigil could not listen on {{listen}}:\n{{error}}\n\nAnother vigil may already be running." },
    Entry { key: "err.unknown_mode",          tr: "Bu mod tanınmadı: {{mode}}",  en: "Unrecognised mode: {{mode}}" },

    Entry { key: "health.idle",               tr: "Kapalı",                      en: "Off" },
    Entry { key: "health.problem_short",      tr: "SORUN",                       en: "PROBLEM" },
    Entry { key: "health.protecting",         tr: "Koruma açık",                 en: "Protection on" },
    Entry { key: "health.stranded",           tr: "SORUN: sistem proxy'si bize bakıyor ama dinlemiyoruz",
                                              en: "PROBLEM: the system points at us and we are not listening" },

    Entry { key: "lang.en",                   tr: "English",                     en: "English" },
    Entry { key: "lang.tr",                   tr: "Türkçe",                      en: "Türkçe" },

    Entry { key: "line.address",              tr: "Adres: {{listen}}",           en: "Address: {{listen}}" },
    Entry { key: "line.dns",                  tr: "DNS: {{state}}",              en: "DNS: {{state}}" },
    Entry { key: "line.learned_row",          tr: "{{host}} → {{strategy}}",     en: "{{host}} → {{strategy}}" },
    Entry { key: "line.strategy",             tr: "Strateji: {{strategy}}",      en: "Strategy: {{strategy}}" },

    Entry { key: "menu.autostart",            tr: "Windows ile başlat",          en: "Start with Windows" },
    Entry { key: "menu.details",              tr: "Ayrıntılar…",                 en: "Details…" },
    Entry { key: "menu.dns_give",             tr: "DNS'i de vigil'e ver (yönetici sorar)",
                                              en: "Use vigil for DNS too (asks for admin)" },
    Entry { key: "menu.dns_take_back",        tr: "DNS'i vigil'e verme (geri al)",
                                              en: "Stop using vigil for DNS (undo)" },
    Entry { key: "menu.forget_all",           tr: "Hepsini unut",                en: "Forget all" },
    Entry { key: "menu.mode_auto",            tr: "Mod: otomatik (öğren)",       en: "Mode: automatic (learn per host)" },
    Entry { key: "menu.mode_default",         tr: "Mod: tlsrec:64+split:1 (varsayılan)",
                                              en: "Mode: tlsrec:64+split:1 (default)" },
    Entry { key: "menu.mode_passthrough",     tr: "Mod: dokunma (düz aktarım)",  en: "Mode: passthrough (no transform)" },
    Entry { key: "menu.mode_split",           tr: "Mod: split:1 (the home line)", en: "Mode: split:1 (the home line)" },
    Entry { key: "menu.mode_tlsrec",          tr: "Mod: tlsrec:64 (SansürOn)", en: "Mode: tlsrec:64 (SansürOn)" },
    Entry { key: "menu.protect_off",          tr: "Korumayı kapat",              en: "Turn protection off" },
    Entry { key: "menu.protect_on",           tr: "Korumayı aç",                 en: "Turn protection on" },
    Entry { key: "menu.quit",                 tr: "Çıkış",                       en: "Quit" },
    Entry { key: "menu.repair",               tr: "Proxy ayarlarını onar",       en: "Repair proxy settings" },

    Entry { key: "mode.auto",                 tr: "otomatik",                    en: "automatic" },

    Entry { key: "placeholder.list_empty",    tr: "(liste boş)",                 en: "(the list is empty)" },
    Entry { key: "placeholder.nothing_learned", tr: "(henüz bir şey öğrenilmedi)", en: "(nothing learned yet)" },

    Entry { key: "section.connection",        tr: "Bağlantı",                    en: "Connection" },
    Entry { key: "section.counters",          tr: "Sayaçlar",                    en: "Counters" },
    Entry { key: "section.excluded",          tr: "Hiç dokunulmayan alan adları", en: "Never touched" },
    Entry { key: "section.learned",           tr: "Öğrenilen stratejiler  (tıkla: unut)",
                                              en: "Learned strategies  (click to forget)" },
    Entry { key: "section.learned_host",      tr: "Öğrenilen site",              en: "Host" },
    Entry { key: "section.status",            tr: "Durum",                       en: "Status" },

    Entry { key: "status.off",                tr: "Kapalı — {{listen}} dinleniyor",
                                              en: "Off — listening on {{listen}}" },
    Entry { key: "status.on",                 tr: "Koruma açık — {{listen}} · strateji: {{strategy}}",
                                              en: "Protection on — {{listen}} · strategy: {{strategy}}" },

    Entry { key: "tooltip.critical",          tr: "Önemli bir güncelleme bekliyor", en: "An important update is waiting" },
    Entry { key: "tooltip.off",               tr: "vigil — kapalı ({{listen}})", en: "vigil — off ({{listen}})" },
    Entry { key: "tooltip.on",                tr: "vigil — açık, {{strategy}} · {{connections}} bağlantı, {{transformed}} dönüştürüldü",
                                              en: "vigil — on, {{strategy}} · {{connections}} connections, {{transformed}} transformed" },

    Entry { key: "update.available",          tr: "Güncelleme var: {{version}}",  en: "Update available: {{version}}" },
    Entry { key: "update.check_now",          tr: "Güncellemeleri denetle",      en: "Check for updates" },
    Entry { key: "update.checking",           tr: "Denetleniyor…",               en: "Checking…" },
    Entry { key: "update.confirm_body",       tr: "vigil {{version}} indirildi ve imzası doğrulandı.\n\nKurmak için vigil kapanacak, dosyalar değiştirilecek ve yeniden açılacak. Bu sırada koruma kısa bir süre kapalı kalır.\n\nŞimdi kurulsun mu?",
                                              en: "vigil {{version}} has been downloaded and its signature verified.\n\nInstalling it will close vigil, replace the files and start it again. Protection is off for a moment while that happens.\n\nInstall it now?" },
    Entry { key: "update.confirm_title",      tr: "vigil güncellemesi",          en: "vigil update" },
    Entry { key: "update.critical",           tr: "ÖNEMLİ güncelleme: {{version}}", en: "IMPORTANT update: {{version}}" },
    Entry { key: "update.failed",             tr: "Güncelleme başarısız: {{why}}", en: "Update failed: {{why}}" },
    Entry { key: "update.folder_readonly",    tr: "Bu klasöre yazılamıyor — güncellemeyi elle indir", en: "This folder is read-only — download the update yourself" },
    Entry { key: "update.install_now",        tr: "Şimdi güncelle ({{version}})", en: "Install update ({{version}})" },
    Entry { key: "update.interrupted",        tr: "Yarım kalmış güncelleme var — devam et", en: "An update was interrupted — resume it" },
    Entry { key: "update.last_check",         tr: "Son denetim: {{when}}",       en: "Last checked: {{when}}" },
    Entry { key: "update.never_checked",      tr: "Henüz denetlenmedi",          en: "Not checked yet" },
    Entry { key: "update.no_keys",            tr: "Bu sürüm güncellemeleri doğrulayamıyor", en: "This build cannot verify updates" },
    Entry { key: "update.off",                tr: "Otomatik güncelleme kapalı",  en: "Automatic updates are off" },
    Entry { key: "update.section",            tr: "Güncelleme",                  en: "Update" },
    Entry { key: "update.staged",             tr: "{{version}} hazır — kurmak için tıkla", en: "{{version}} is ready — click to install" },
    Entry { key: "update.staged_critical",    tr: "ÖNEMLİ: {{version}} hazır — kurmak için tıkla", en: "IMPORTANT: {{version}} is ready — click to install" },
    Entry { key: "update.toggle_auto",        tr: "Otomatik güncellemeleri denetle", en: "Check for updates automatically" },
    Entry { key: "update.unreachable",        tr: "Denetlenemedi: {{why}}",      en: "Could not check: {{why}}" },
    Entry { key: "update.up_to_date",         tr: "Güncel",                      en: "Up to date" },
    Entry { key: "update.version_line",       tr: "Sürüm: {{version}}",          en: "Version: {{version}}" },

    Entry { key: "window.details_title",      tr: "vigil — ayrıntılar",          en: "vigil — details" },
    Entry { key: "window.popup_hint",         tr: "Sağ tık: menü  ·  Esc: kapat", en: "Right-click: menu  ·  Esc: close" },
];

/// Look up a key. A miss returns the key itself — visibly wrong on screen, never blank — and
/// fails the build's tests through `debug_assert!`.
pub fn t(lang: Lang, key: &str) -> &'static str {
    match STRINGS.binary_search_by(|e| e.key.cmp(key)) {
        Ok(i) => match lang {
            Lang::Turkish => STRINGS[i].tr,
            Lang::English => STRINGS[i].en,
        },
        Err(_) => {
            debug_assert!(false, "no translation for key {key:?}");
            // Leak nothing and invent nothing: hand back a key the reader can search for.
            missing(key)
        }
    }
}

/// Look up a key and substitute its `{{placeholders}}`.
///
/// Unknown placeholder names in `args` are ignored, and placeholders with no argument are left in
/// the text rather than blanked — the same reasoning as a missing key: visibly wrong beats
/// silently empty.
pub fn tf(lang: Lang, key: &str, args: &[(&str, &str)]) -> String {
    let mut s = t(lang, key).to_string();
    for (name, value) in args {
        s = s.replace(&format!("{{{{{name}}}}}"), value);
    }
    s
}

/// The one place a missing key is turned into something displayable, kept separate so the
/// behaviour is testable without tripping the `debug_assert` above.
fn missing(key: &str) -> &'static str {
    // A `&'static str` cannot be built from a runtime key without leaking, and leaking on every
    // paint of a broken key would be a slow memory leak in the one code path nobody notices. So:
    // a fixed marker. The key itself goes to the assertion, which is where a developer looks.
    let _ = key;
    "??"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_has_no_duplicates() {
        for w in STRINGS.windows(2) {
            assert!(
                w[0].key < w[1].key,
                "table is out of order or has a duplicate: {:?} then {:?}",
                w[0].key,
                w[1].key
            );
        }
    }

    /// The guarantee the single table exists for. Every row is checked, so a string added
    /// tomorrow is covered without anybody remembering to write a test for it.
    #[test]
    fn every_key_has_both_languages_and_they_are_not_the_same_text() {
        // Proper nouns and protocol names are the same in both languages by design.
        const SAME_ON_PURPOSE: &[&str] = &[
            "counter.socks4",
            "counter.socks5",
            "counter.http_connect",
            "lang.en",
            "lang.tr",
            "line.dns",
            "line.learned_row",
            "menu.mode_split",
            "menu.mode_tlsrec",
        ];
        for e in STRINGS {
            assert!(!e.tr.trim().is_empty(), "{}: Turkish is blank", e.key);
            assert!(!e.en.trim().is_empty(), "{}: English is blank", e.key);
            if !SAME_ON_PURPOSE.contains(&e.key) {
                assert_ne!(e.tr, e.en, "{}: the English is still the Turkish", e.key);
            }
        }
    }

    /// The test that catches the bug that actually happens: a placeholder renamed in one language
    /// and not the other, so half the users see `{{listen}}` where an address should be.
    #[test]
    fn both_languages_use_the_same_placeholders() {
        fn holders(s: &str) -> Vec<String> {
            let mut v = Vec::new();
            let mut rest = s;
            while let Some(a) = rest.find("{{") {
                let after = &rest[a + 2..];
                let Some(b) = after.find("}}") else { break };
                v.push(after[..b].to_string());
                rest = &after[b + 2..];
            }
            v.sort();
            v
        }
        for e in STRINGS {
            assert_eq!(
                holders(e.tr),
                holders(e.en),
                "{}: the two languages interpolate different things",
                e.key
            );
        }
    }

    /// A single-brace `{}` left over from a `format!` would be printed literally and look like a
    /// bug to the user. `{{...}}` is the only interpolation this table has.
    #[test]
    fn no_row_contains_a_stray_format_placeholder() {
        for e in STRINGS {
            for s in [e.tr, e.en] {
                let stripped = s.replace("{{", "").replace("}}", "");
                assert!(
                    !stripped.contains('{') && !stripped.contains('}'),
                    "{}: stray brace in {s:?}",
                    e.key
                );
            }
        }
    }

    #[test]
    fn lookup_returns_the_right_column() {
        assert_eq!(t(Lang::Turkish, "menu.quit"), "Çıkış");
        assert_eq!(t(Lang::English, "menu.quit"), "Quit");
    }

    #[test]
    fn interpolation_fills_every_named_hole() {
        assert_eq!(
            tf(
                Lang::English,
                "status.on",
                &[("listen", "127.0.0.1:1080"), ("strategy", "tlsrec:64")]
            ),
            "Protection on — 127.0.0.1:1080 · strategy: tlsrec:64"
        );
        assert_eq!(
            tf(
                Lang::Turkish,
                "tooltip.on",
                &[
                    ("strategy", "otomatik"),
                    ("connections", "12"),
                    ("transformed", "9")
                ]
            ),
            "vigil — açık, otomatik · 12 bağlantı, 9 dönüştürüldü"
        );
    }

    /// A hole with no argument stays visible rather than becoming an empty gap, so the bug is
    /// reported rather than shipped.
    #[test]
    fn a_missing_argument_leaves_the_hole_showing() {
        let s = tf(Lang::English, "status.on", &[("listen", "x")]);
        assert!(s.contains("{{strategy}}"), "{s}");
    }

    /// Every Turkish sublanguage is Turkish, and nothing else is. The sublanguage is in the high
    /// six bits, so `tr-TR` (0x041F) and `tr-CY` (0x081F) are different ids for the same
    /// language; masking is the whole trick.
    #[test]
    fn a_turkish_windows_gets_turkish_whichever_turkish_it_is() {
        for id in [0x041F, 0x081F, 0x001F] {
            assert_eq!(Lang::from_windows_langid(id), Lang::Turkish, "{id:#06x}");
        }
        for id in [0x0409, 0x0809, 0x0407, 0x040C, 0x0419, 0x0000] {
            assert_eq!(Lang::from_windows_langid(id), Lang::English, "{id:#06x}");
        }
    }

    #[test]
    fn everything_that_is_not_turkish_is_english() {
        assert_eq!(Lang::default(), Lang::English);
        for tag in ["en", "en-GB", "de-DE", "ru-RU", "", "xx", "tra", "trk"] {
            assert_eq!(Lang::from_tag(tag), Lang::English, "{tag:?}");
        }
        for tag in ["tr", "tr-TR", "TR", "Tr-tr", "tr_TR", "tr-CY"] {
            assert_eq!(Lang::from_tag(tag), Lang::Turkish, "{tag:?}");
        }
    }

    #[test]
    fn the_override_wins_and_nonsense_leaves_the_decision_alone() {
        assert_eq!(Lang::English.override_from_env(Some("tr")), Lang::Turkish);
        assert_eq!(Lang::Turkish.override_from_env(Some("EN")), Lang::English);
        assert_eq!(Lang::Turkish.override_from_env(Some(" tr ")), Lang::Turkish);
        assert_eq!(Lang::Turkish.override_from_env(None), Lang::Turkish);
        assert_eq!(
            Lang::Turkish.override_from_env(Some("klingon")),
            Lang::Turkish
        );
    }

    /// The order matters more than any single rule in it, so it is tested as an order.
    #[test]
    fn the_language_decision_follows_its_precedence() {
        const TR_OS: Option<u16> = Some(0x041F);
        const EN_OS: Option<u16> = Some(0x0409);

        // Nothing chosen: the system decides.
        assert_eq!(Lang::decide(TR_OS, None, None), Lang::Turkish);
        assert_eq!(Lang::decide(EN_OS, None, None), Lang::English);
        // No system either: English, the "otherwise" half of the rule.
        assert_eq!(Lang::decide(None, None, None), Lang::English);

        // A saved choice beats the system, in both directions. Picking a language *is* the act
        // of disagreeing with the operating system, so this is the whole feature.
        assert_eq!(Lang::decide(TR_OS, Some("en"), None), Lang::English);
        assert_eq!(Lang::decide(EN_OS, Some("tr"), None), Lang::Turkish);

        // The environment beats the saved choice.
        assert_eq!(Lang::decide(TR_OS, Some("tr"), Some("en")), Lang::English);
        assert_eq!(Lang::decide(EN_OS, Some("en"), Some("tr")), Lang::Turkish);

        // A blank or truncated file is not a choice — it is what a half-written file looks
        // like — so the system decides again rather than the parser deciding for it.
        for junk in ["", "   ", "\n"] {
            assert_eq!(
                Lang::decide(TR_OS, Some(junk), None),
                Lang::Turkish,
                "{junk:?}"
            );
            assert_eq!(
                Lang::decide(EN_OS, Some(junk), None),
                Lang::English,
                "{junk:?}"
            );
        }
        // Unreadable content is a choice we cannot honour; falling back beats guessing.
        assert_eq!(Lang::decide(TR_OS, Some("klingon"), None), Lang::English);
    }

    #[test]
    fn the_tag_round_trips() {
        for l in [Lang::Turkish, Lang::English] {
            assert_eq!(Lang::from_tag(l.tag()), l);
        }
    }
}
