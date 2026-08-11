//! What to write into Windows' proxy settings, and how to put them back.
//!
//! The decisions are pure — which key gets which value, what a rollback restores — so they
//! can be tested on Linux without a registry. Only [`apply`] and [`read_current`] touch
//! Windows, and they are thin.
//!
//! This module exists because of a specific bug. `primitive_dpibypassapp` wrote its target
//! domains into `ProxyOverride`, believing it was an include list. It is Windows' **bypass**
//! list, so the sites the tool existed to unblock were the only ones that never went through
//! it. Nothing caught that for the life of the project. Here, the meaning of every key is
//! asserted.

use core::fmt;

/// Registry values under
/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxySettings {
    /// `ProxyEnable` — 0 or 1.
    pub enabled: bool,
    /// `ProxyServer` — e.g. `https=127.0.0.1:1080`. See [`settings_for`] for why that form.
    pub server: String,
    /// `ProxyOverride` — semicolon-separated hosts that **bypass** the proxy.
    ///
    /// Everything listed here goes direct. A blocked host must never appear.
    pub bypass: String,
}

impl fmt::Display for ProxySettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProxyEnable={} ProxyServer={:?} ProxyOverride={:?}",
            u8::from(self.enabled),
            self.server,
            self.bypass
        )
    }
}

/// The default bypass list: loopback and the local network only.
///
/// `<local>` is Windows' token for "hosts without a dot". Nothing else belongs here — every
/// entry is a host the tool will *not* help.
///
/// **RFC 1918's middle block is enumerated, not abbreviated.** It used to read `172.2*`, meaning
/// 172.20–172.29 — but WinINET matches that as a prefix, so it also swallowed `172.2.x.x`, which is
/// public address space. Anything a user reached there went direct, unhelped and unmeasured, and
/// nothing said so. Twelve entries instead of one is a small price for a list whose entire job is
/// to name what the tool refuses to protect.
pub const DEFAULT_BYPASS: &str = "localhost;127.*;10.*;\
                                  172.16.*;172.17.*;172.18.*;172.19.*;\
                                  172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;\
                                  172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;\
                                  172.30.*;172.31.*;192.168.*;<local>";

/// Build the settings that point Windows at our proxy.
///
/// `https=` is not a stylistic choice; it is the only value measured to work, on 2026-08-04:
///
/// | `ProxyServer` | what clients do |
/// |---|---|
/// | `socks=127.0.0.1:1080` | **SOCKS4**, never SOCKS5 — Chromium documents that an omitted scheme "will be understood as SOCKSv4", and WinINET's SOCKS support is v4-only. The Discord updater ignores the value outright. |
/// | `127.0.0.1:1080` | works, but makes us the proxy for `http://` too, which arrives as absolute-form `GET http://...` and would need a forwarding HTTP proxy we have no reason to write. |
/// | `https=127.0.0.1:1080` | HTTP `CONNECT` for exactly the traffic that carries an SNI. Everything else keeps its direct path. |
///
/// The old `socks=` value was worse than useless: it named a dialect our own listener
/// rejected, so the system-proxy integration reached nothing at all while looking configured.
pub fn settings_for(listen: &str) -> ProxySettings {
    ProxySettings {
        enabled: true,
        server: format!("https={listen}"),
        bypass: DEFAULT_BYPASS.to_string(),
    }
}

/// What a rollback should write, given what was there before we started.
///
/// Restoring means putting back exactly what we found, including an empty `ProxyServer` and
/// `ProxyEnable=0`. Leaving a stale `ProxyServer` behind pointing at a proxy that is no
/// longer running is the failure that strands a machine with no internet.
pub fn rollback_to(previous: &ProxySettings) -> ProxySettings {
    previous.clone()
}

/// Every address in a `ProxyServer` value, whatever shape it is in: `host:port`,
/// `scheme=host:port`, or several of the latter joined by `;`.
pub(crate) fn addresses(server: &str) -> impl Iterator<Item = &str> {
    server.split(';').filter_map(|part| {
        let part = part.trim();
        (!part.is_empty()).then(|| part.split_once('=').map_or(part, |(_, a)| a).trim())
    })
}

/// Does the live setting route traffic at our listener?
///
/// Disabled-but-populated is deliberately **false**: nothing is being routed, so the value is
/// a leftover rather than an engagement.
///
/// **The address is compared exactly, and it used to be a substring test.** `contains("127.0.0.1:1080")`
/// is true of `127.0.0.1:10809`, which is v2rayN's default HTTP inbound — so a user running one of
/// those got "already engaged" (no snapshot written, nothing configured) while the tray read
/// *Protecting*, and quitting vigil then blanked their `ProxyServer`. It destroyed a configuration
/// vigil had never touched, with nothing to restore from.
pub fn points_at_us(current: &ProxySettings, listen: &str) -> bool {
    current.enabled && addresses(&current.server).any(|a| a == listen)
}

/// Is this value, byte for byte, something **vigil itself** wrote — for any of its listeners?
///
/// Not "does it point at loopback" and not "does it point at *this* listener". A snapshot that names
/// a loopback address may perfectly well be the user's own proxy (v2rayN on 10809, Clash on 7890,
/// Fiddler on 8888), and treating those as ours blanks a configuration this tool never touched on
/// every quit — the regression [`points_at_us`] records above. And an exact compare against the
/// current listener misses the case that actually happens, which is **two vigils on two ports**: the
/// scanner runs on 1085 and the tray on 1080, so the snapshot one of them takes of the other names
/// neither's own address.
///
/// So the test is the whole triple. `settings_for` writes `enabled`, `https={addr}` and this project's
/// own bypass list; nothing else on a machine writes all three together, and the address must be
/// loopback as well. It is deliberately narrow: a value that is *nearly* ours is somebody else's.
pub fn looks_like_our_own_writing(s: &ProxySettings) -> bool {
    let mut found = addresses(&s.server);
    let Some(addr) = found.next() else {
        return false;
    };
    // More than one entry is not a shape we ever write.
    if found.next().is_some() {
        return false;
    }
    let loopback = addr
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback());
    loopback && *s == settings_for(addr)
}

/// A machine is left broken when the proxy is enabled and points somewhere nothing listens.
///
/// **Deliberately a prefix test, and no longer the same function as [`points_at_us`].** The repair
/// tool passes `"127.0.0.1:"` on purpose: a vigil that was serving on another port still left the
/// setting behind, and it is still ours to clean up. Sharing one predicate meant tightening
/// ownership to an exact address would silently stop `vigil-repair` detecting a genuine strand —
/// with the whole suite staying green, because the test for it used port 9999, which shares no
/// prefix with 1080 and so passed for the wrong reason.
pub fn is_stranded(current: &ProxySettings, our_prefix: &str) -> bool {
    current.enabled && addresses(&current.server).any(|a| a.starts_with(our_prefix))
}

/// Settings that disable the proxy entirely — what the repair tool writes when it cannot
/// find a saved snapshot to restore.
pub fn disabled() -> ProxySettings {
    ProxySettings {
        enabled: false,
        server: String::new(),
        bypass: String::new(),
    }
}

/// Serialise a snapshot so a crashed process's settings can still be restored by another.
pub fn snapshot_to_text(s: &ProxySettings) -> String {
    format!(
        "# vigil system-proxy snapshot — restore with `vigil-repair`\nenabled={}\nserver={}\nbypass={}\n",
        u8::from(s.enabled),
        s.server,
        s.bypass
    )
}

pub fn snapshot_from_text(t: &str) -> Option<ProxySettings> {
    let mut s = ProxySettings::default();
    let mut seen = 0;
    for line in t.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        match k.trim() {
            "enabled" => {
                s.enabled = v.trim() == "1";
                seen += 1;
            }
            "server" => {
                s.server = v.trim().to_string();
                seen += 1;
            }
            "bypass" => {
                s.bypass = v.trim().to_string();
                seen += 1;
            }
            _ => return None,
        }
    }
    (seen == 3).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug that killed an entire previous iteration: `ProxyOverride` is the **bypass**
    /// list. A host we mean to help must never be in it.
    #[test]
    fn the_bypass_list_never_contains_a_target_host() {
        let s = settings_for("127.0.0.1:1080");
        for host in [
            "discord.com",
            "roblox.com",
            "protonvpn.com",
            "4chan.org",
            "updates.discord.com",
        ] {
            assert!(
                !s.bypass.contains(host),
                "{host} is in ProxyOverride, which means it would go DIRECT — \
                 this is exactly the inversion that made primitive_dpibypassapp useless"
            );
        }
    }

    #[test]
    fn the_bypass_list_contains_only_local_destinations() {
        for entry in DEFAULT_BYPASS.split(';') {
            // `starts_with("172.")` used to be enough, which is how `172.2*` — a prefix that
            // also matches the public 172.2.0.0/16 — passed this test for months. RFC 1918's
            // middle block is 172.16 through 172.31 and nothing else.
            let private_172 = entry
                .strip_prefix("172.")
                .and_then(|rest| rest.split('.').next())
                .and_then(|octet| octet.parse::<u8>().ok())
                .is_some_and(|n| (16..=31).contains(&n));
            let ok = entry == "<local>"
                || entry == "localhost"
                || entry.starts_with("127.")
                || entry.starts_with("10.")
                || private_172
                || entry.starts_with("192.168.");
            assert!(
                ok,
                "{entry:?} is not a local destination — an entry here is a host vigil refuses to \
                 help, so a wildcard that reaches public address space silently un-protects it"
            );
        }
    }

    /// Measured 2026-08-04, and the reason v1's system-proxy integration helped nothing:
    /// `socks=` means SOCKS**4** to every Windows client, which our listener answered with
    /// `BadVersion(4)`, and Discord's updater — the only part of Discord this line blocks —
    /// ignores `socks=` altogether.
    #[test]
    fn the_server_value_scopes_us_to_https_and_never_says_socks() {
        let s = settings_for("127.0.0.1:1080");
        assert_eq!(s.server, "https=127.0.0.1:1080");
        assert!(
            !s.server.contains("socks="),
            "`socks=` is read as SOCKS4 by WinINET and Chromium alike, and the Discord \
             updater ignores it entirely — it reaches nothing, got {:?}",
            s.server
        );
        assert!(s.enabled);
    }

    /// Scoping to `https` is what keeps plain HTTP on its direct path. If the value ever
    /// becomes a bare `host:port` again, every `http://` request in the system arrives here
    /// as an absolute-form GET that this proxy deliberately does not implement.
    #[test]
    fn plain_http_is_not_routed_through_us() {
        let s = settings_for("127.0.0.1:1080");
        assert!(
            !s.server.starts_with("http="),
            "http= would route absolute-form GETs at us, got {:?}",
            s.server
        );
        assert!(s.server.starts_with("https="), "got {:?}", s.server);
    }

    #[test]
    fn rollback_restores_exactly_what_was_there() {
        for previous in [
            ProxySettings::default(),
            ProxySettings {
                enabled: true,
                server: "http=corp-proxy:8080".into(),
                bypass: "intranet".into(),
            },
            ProxySettings {
                enabled: false,
                server: "leftover:9999".into(),
                bypass: String::new(),
            },
        ] {
            assert_eq!(
                rollback_to(&previous),
                previous,
                "rollback must be exact, including a disabled-but-populated state"
            );
        }
    }

    /// **A port that merely starts with ours is not ours.** `127.0.0.1:10809` is v2rayN's default
    /// HTTP inbound, and a substring test called it vigil's: `engage::start` then answered
    /// "already engaged", so no snapshot was written and nothing was configured, while the tray
    /// read *Protecting*. Quitting blanked their `ProxyServer` with nothing to restore from.
    #[test]
    fn a_longer_port_that_starts_with_ours_is_somebody_elses() {
        let theirs = ProxySettings {
            enabled: true,
            server: "http=127.0.0.1:10809;https=127.0.0.1:10809".into(),
            bypass: String::new(),
        };
        assert!(
            !points_at_us(&theirs, "127.0.0.1:1080"),
            "v2rayN's proxy was read as ours"
        );
        // And ours, in every shape Windows writes it, still is.
        for server in [
            "https=127.0.0.1:1080",
            "127.0.0.1:1080",
            "http=127.0.0.1:1080;https=127.0.0.1:1080",
            " https=127.0.0.1:1080 ",
        ] {
            let ours = ProxySettings {
                enabled: true,
                server: server.into(),
                bypass: String::new(),
            };
            assert!(points_at_us(&ours, "127.0.0.1:1080"), "{server}");
        }
    }

    /// **And `is_stranded` must stay a prefix test**, because `vigil-repair` calls it with the
    /// port deliberately left off: a vigil that served on 1085 and died still left the setting
    /// behind and it is still ours to clean up. This is the test that would have gone red if the
    /// ownership fix had been applied to one shared predicate.
    #[test]
    fn a_strand_is_recognised_whatever_port_it_was_serving_on() {
        for server in [
            "https=127.0.0.1:1080",
            "https=127.0.0.1:1085",
            "https=127.0.0.1:10809",
        ] {
            let stranded = ProxySettings {
                enabled: true,
                server: server.into(),
                bypass: String::new(),
            };
            assert!(
                is_stranded(&stranded, "127.0.0.1:"),
                "{server} would have been left behind"
            );
        }
        // Somebody else's real proxy is not a strand, and disabled is not a strand.
        let corp = ProxySettings {
            enabled: true,
            server: "http=corp-proxy:8080".into(),
            bypass: String::new(),
        };
        assert!(!is_stranded(&corp, "127.0.0.1:"));
        let off = ProxySettings {
            enabled: false,
            server: "https=127.0.0.1:1080".into(),
            bypass: String::new(),
        };
        assert!(!is_stranded(&off, "127.0.0.1:"));
    }

    /// The failure mode the repair tool exists for: enabled, pointing at us, nothing running.
    ///
    /// Both the current `https=` value and the legacy `socks=` one must be recognised — a
    /// machine stranded by an older build is exactly the machine that needs rescuing, and
    /// matching on the listen address rather than the scheme is what makes that work.
    #[test]
    fn a_stranded_machine_is_recognised() {
        for server in [
            "https=127.0.0.1:1080",
            "socks=127.0.0.1:1080",
            "127.0.0.1:1080",
        ] {
            let ours = ProxySettings {
                enabled: true,
                server: server.into(),
                bypass: DEFAULT_BYPASS.into(),
            };
            assert!(is_stranded(&ours, "127.0.0.1:1080"), "{server}");
        }
        let ours = ProxySettings {
            enabled: true,
            server: "https=127.0.0.1:1080".into(),
            bypass: DEFAULT_BYPASS.into(),
        };
        assert!(is_stranded(&ours, "127.0.0.1:1080"));

        // someone else's proxy: not ours to undo
        let theirs = ProxySettings {
            enabled: true,
            server: "http=corp-proxy:8080".into(),
            bypass: String::new(),
        };
        assert!(!is_stranded(&theirs, "127.0.0.1:1080"));

        // disabled: nothing to repair
        let off = ProxySettings {
            enabled: false,
            server: "socks=127.0.0.1:1080".into(),
            bypass: String::new(),
        };
        assert!(!is_stranded(&off, "127.0.0.1:1080"));
    }

    #[test]
    fn disabled_settings_clear_the_server_too() {
        let d = disabled();
        assert!(!d.enabled);
        assert!(
            d.server.is_empty(),
            "leaving a stale ProxyServer behind is what strands a machine"
        );
    }

    #[test]
    fn a_snapshot_round_trips() {
        for s in [
            ProxySettings::default(),
            settings_for("127.0.0.1:1080"),
            ProxySettings {
                enabled: true,
                server: "http=corp:8080;https=corp:8443".into(),
                bypass: "a;b;<local>".into(),
            },
        ] {
            let text = snapshot_to_text(&s);
            assert_eq!(
                snapshot_from_text(&text).as_ref(),
                Some(&s),
                "snapshot did not round trip: {text}"
            );
        }
    }

    #[test]
    fn a_damaged_snapshot_is_rejected_rather_than_half_applied() {
        for bad in [
            "",
            "enabled=1\n",
            "enabled=1\nserver=x\n",
            "enabled=1\nserver=x\nbypass=y\nextra=z\n",
            "nonsense\n",
        ] {
            assert!(
                snapshot_from_text(bad).is_none(),
                "{bad:?} should not produce settings"
            );
        }
    }

    #[test]
    fn a_snapshot_with_comments_and_blank_lines_still_parses() {
        let t = "# comment\n\nenabled=1\n\nserver=socks=127.0.0.1:1080\nbypass=<local>\n";
        let s = snapshot_from_text(t).expect("parses");
        assert!(s.enabled);
        assert_eq!(s.server, "socks=127.0.0.1:1080");
    }
}
