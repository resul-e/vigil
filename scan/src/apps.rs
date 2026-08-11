//! Which applications to test, what they talk to, and how to find them. Pure data.
//!
//! The list is not decoration. Every entry is here because it was measured to behave
//! differently from the others:
//!
//! - **Discord** is two network stacks in one application. Its Electron half honours the
//!   registry proxy and emits ~1800 B ClientHellos that partly evade this DPI by accident; its
//!   native updater emits 175 B, is blocked outright, and gates startup. That "partly evades"
//!   is a the home line property and does not travel: on SansürOn, measured 2026-08-07,
//!   every ClientHello length from 250 B to 2200 B is 0/8, so there the Electron half has no
//!   accident to be saved by and must come through the proxy or not run at all.
//! - **Roblox** ignores the registry setting completely — measured 2026-08-05: five direct
//!   sockets to port 443 and none to the proxy — and honours the curl environment variables
//!   instead. Every hostname it needs is blocked on the home line and reachable through vigil.
//!
//! A machine where those two behave differently from here is a machine worth hearing about,
//! which is the whole point of handing this to somebody on another ISP.

/// One application under test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    /// What the report calls it.
    pub name: &'static str,
    /// Hostname suffixes that belong to this application. Used for two things: choosing what
    /// to measure, and deciding which of the names that reached the proxy may be *reported*.
    /// Anything else that arrives is counted and never named — a testbench has no business
    /// writing down what else the volunteer had open.
    pub suffixes: &'static [&'static str],
    /// Hostnames measured directly, one cell each. Ordered so the report reads sensibly.
    pub probes: &'static [&'static str],
    /// Where the executable usually lives, as a glob under the user profile, and the registry
    /// protocol handler that names it exactly when there is one.
    pub exe_glob: Option<&'static str>,
    pub protocol_key: Option<&'static str>,
    /// Names without which the application cannot finish starting. Reported when they are
    /// missing, because "two names arrived" reads as success and is not: Discord's native
    /// updater gates startup, so a run where `updates.discord.com` never appeared explains an
    /// application that talked to us and still never opened.
    pub critical: &'static [&'static str],
    /// Image names to stop afterwards, so the volunteer's desktop is left as it was found.
    pub processes: &'static [&'static str],
    /// The Start-menu shortcut's file name. Searched for under both Start-menu trees rather
    /// than looked up at one fixed path: an installer puts it where it likes, and a testbench
    /// that reports "not installed" because a folder is spelled differently on somebody else's
    /// machine has answered the wrong question. `shortcut_rel` stays as the fast path.
    pub shortcut_name: Option<&'static str>,
    /// The usual location, tried first. Preferred when it exists, because it
    /// carries the arguments the application needs and is the path a user's double-click
    /// actually takes. Discord's `Update.exe` with no arguments exits immediately and reaches
    /// nothing — measured, and it made the first run report Discord as ignoring the proxy.
    pub shortcut: Option<&'static str>,
    /// A substring of the Microsoft Store package name, when the application has a packaged
    /// build. Searched last, and only added because it was needed: on 2026-08-07 this tool told
    /// a volunteer's machine "Roblox kurulu degil" while all three of its probes were specific
    /// to the classic installer. A packaged build has no `.lnk`, no `roblox-player` protocol
    /// handler and no `Versions` directory, so absence of those three says nothing at all.
    pub packaged_name: Option<&'static str>,
    /// Extra places to look, as globs under an environment variable's directory. `(var, glob)`.
    pub extra_globs: &'static [(&'static str, &'static str)],
}

pub const APPS: &[App] = &[
    App {
        name: "Discord",
        suffixes: &[
            "discord.com",
            "discordapp.com",
            "discordapp.net",
            "discord.gg",
        ],
        // The last two are the package downloads, added 2026-08-08. The SansürOn run showed
        // the *manifest* host reaching the proxy and the client still not opening, and the
        // obvious next question — is the thing it then tries to download blocked? — could not
        // be answered because neither host had ever been measured on that line. On the home line
        // `stable.dl2.discordapp.net` is 8/8, which is why it is a probe and not an assumption.
        probes: &[
            "discord.com",
            "updates.discord.com",
            "cdn.discordapp.com",
            "gateway.discord.gg",
            "dl.discordapp.net",
            "stable.dl2.discordapp.net",
        ],
        exe_glob: Some(r"AppData\Local\Discord\Update.exe"),
        protocol_key: None,
        // Two names, two different failures. `updates.discord.com` gates startup: blocked, the
        // application stalls at five processes. `discord.com` is what the Electron half must
        // fetch before it can draw anything, and it was added after a SansürOn run where it
        // never arrived — only the updater did — and the report still said "opened, uses the
        // proxy" while Discord sat at the same five processes it reached with vigil switched
        // off. If Chromium is using the proxy this name always arrives; if it never does,
        // Chromium is not using it and nothing else in the report matters.
        //
        // `gateway.discord.gg` is deliberately not here even though it is equally blocked: the
        // client only opens the gateway once a session is signed in, so a logged-out machine
        // would be reported as broken when it is merely logged out.
        critical: &["updates.discord.com", "discord.com"],
        processes: &["Discord.exe", "Update.exe"],
        shortcut_name: Some("Discord.lnk"),
        shortcut: Some(r"Microsoft\Windows\Start Menu\Programs\Discord Inc\Discord.lnk"),
        // Discord ships no Store build; a packaged search here would only be a slow no.
        packaged_name: None,
        extra_globs: &[],
    },
    App {
        name: "Roblox",
        suffixes: &["roblox.com", "rbxcdn.com", "rbx.com"],
        probes: &[
            "roblox.com",
            "www.roblox.com",
            "apis.roblox.com",
            "auth.roblox.com",
            "gamejoin.roblox.com",
            "clientsettings.roblox.com",
            "clientsettingscdn.roblox.com",
            "versioncompatibility.api.roblox.com",
            "assetdelivery.roblox.com",
            "setup.rbxcdn.com",
        ],
        exe_glob: Some(r"AppData\Local\Roblox\Versions\*\RobloxPlayerBeta.exe"),
        protocol_key: Some(r"roblox-player\shell\open\command"),
        // `auth` is deliberately absent: the client does not touch it until somebody signs
        // in, so listing it printed a "missing, needed to start" line on a run where Roblox
        // opened perfectly. A critical name has to be one the application needs *to start*.
        critical: &["clientsettings.roblox.com"],
        // `Windows10Universal.exe` is the Store build's image name. Harmless when that build is
        // absent — `tasklist` simply matches nothing — and the difference between finding the
        // application and reporting it missing when it is there.
        processes: &["RobloxPlayerBeta.exe", "Windows10Universal.exe"],
        shortcut_name: Some("Roblox Player.lnk"),
        shortcut: None,
        packaged_name: Some("roblox"),
        // The machine-wide install, which the user-profile glob cannot see.
        extra_globs: &[(
            "ProgramFiles(x86)",
            r"Roblox\Versions\*\RobloxPlayerBeta.exe",
        )],
    },
];

/// Hosts that must be reachable everywhere. A run where one of these fails is a broken run,
/// not an interesting one, and the report says so rather than presenting the rest as findings.
pub const CONTROLS: &[&str] = &["example.com", "wikipedia.org", "media.discordapp.net"];

#[cfg_attr(not(windows), allow(dead_code))]
/// Does `host` belong to `app`?
///
/// Suffix matching on label boundaries: `notroblox.com` is not Roblox, and `a.b.roblox.com` is.
pub fn belongs_to(app: &App, host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    app.suffixes.iter().any(|s| {
        let s = s.to_ascii_lowercase();
        h == s || h.ends_with(&format!(".{s}"))
    })
}

#[cfg_attr(not(windows), allow(dead_code))]
/// Split what the proxy saw into "names belonging to this application" and "how many others".
///
/// The count is deliberately all that survives of the rest. Handing this binary to a friend
/// means it runs beside their whole desktop, and a report that listed every site they had open
/// would be a privacy leak dressed up as a measurement.
pub fn partition_seen<'a>(app: &App, seen: &'a [String]) -> (Vec<&'a str>, usize) {
    let mut mine = Vec::new();
    let mut others = 0usize;
    for h in seen {
        if belongs_to(app, h) {
            mine.push(h.as_str());
        } else {
            others += 1;
        }
    }
    (mine, others)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str) -> &'static App {
        APPS.iter().find(|a| a.name == name).expect("app")
    }

    #[test]
    fn a_subdomain_belongs_and_a_lookalike_does_not() {
        let r = app("Roblox");
        for yes in [
            "roblox.com",
            "apis.roblox.com",
            "a.b.roblox.com",
            "setup.rbxcdn.com",
        ] {
            assert!(belongs_to(r, yes), "{yes} should belong to Roblox");
        }
        for no in [
            "notroblox.com",
            "roblox.com.evil.net",
            "example.com",
            "robloxcom",
        ] {
            assert!(!belongs_to(r, no), "{no} must not be taken for Roblox");
        }
    }

    #[test]
    fn matching_ignores_case_and_a_trailing_dot() {
        let r = app("Roblox");
        assert!(belongs_to(r, "APIS.Roblox.COM"));
        assert!(belongs_to(r, "apis.roblox.com."));
    }

    /// A critical name must be one of the application's own, and must be something the run
    /// actually watches for — otherwise the report would explain a failure with a name that
    /// could never have appeared.
    #[test]
    fn critical_names_belong_to_their_app() {
        for a in APPS {
            assert!(!a.critical.is_empty(), "{} lists no critical name", a.name);
            for c in a.critical {
                assert!(belongs_to(a, c), "{}: {c} is not its own name", a.name);
            }
        }
    }

    #[test]
    fn every_probe_belongs_to_the_app_that_lists_it() {
        for a in APPS {
            for p in a.probes {
                assert!(
                    belongs_to(a, p),
                    "{} lists {p}, which is not its own",
                    a.name
                );
            }
        }
    }

    /// Added after the SansürOn report of 2026-08-07 read as a success. Only the updater
    /// reached the proxy; the name the Electron half cannot draw a window without never did,
    /// and nothing in the report objected. The gateway stays out on purpose — it is reached
    /// only by a signed-in client, so requiring it would fail every logged-out machine.
    #[test]
    fn discord_cannot_start_without_the_name_its_window_is_made_of() {
        let d = app("Discord");
        assert!(d.critical.contains(&"discord.com"));
        assert!(d.critical.contains(&"updates.discord.com"));
        assert!(
            !d.critical.contains(&"gateway.discord.gg"),
            "the gateway is only reached once signed in; a logged-out machine is not broken"
        );
        for c in d.critical {
            assert!(d.probes.contains(c), "{c} is never measured, so never seen");
        }
    }

    /// Two applications must never claim the same hostname, or the report would attribute a
    /// connection to whichever happened to be first in the list.
    #[test]
    fn no_two_apps_claim_the_same_name() {
        for a in APPS {
            for b in APPS {
                if a.name == b.name {
                    continue;
                }
                for p in a.probes {
                    assert!(
                        !belongs_to(b, p),
                        "{} and {} both claim {p}",
                        a.name,
                        b.name
                    );
                }
            }
        }
    }

    /// The privacy rule, held in place by a test: whatever else was on the machine is counted,
    /// never named.
    #[test]
    fn only_the_apps_own_names_are_reportable() {
        let seen = vec![
            "apis.roblox.com".to_string(),
            "example-bank.com.tr".to_string(),
            "something.private".to_string(),
            "setup.rbxcdn.com".to_string(),
        ];
        let (mine, others) = partition_seen(app("Roblox"), &seen);
        assert_eq!(mine, vec!["apis.roblox.com", "setup.rbxcdn.com"]);
        assert_eq!(others, 2, "the rest must survive only as a count");
    }

    #[test]
    fn a_control_is_nobodys_application() {
        for c in CONTROLS {
            // media.discordapp.net is Discord's, and is deliberately also a control: it is the
            // one Discord name that is reachable, so it separates "blocked" from "broken".
            if *c == "media.discordapp.net" {
                continue;
            }
            assert!(
                !APPS.iter().any(|a| belongs_to(a, c)),
                "{c} should not be owned by an app"
            );
        }
    }
}
