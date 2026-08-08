//! What a WinINET client *actually resolves*, read and never written.
//!
//! [`crate::registry`] writes three flat values — `ProxyEnable`, `ProxyServer`,
//! `ProxyOverride` — and for four days that was assumed to be the whole story. It is not.
//! WinINET's per-connection configuration lives in an undocumented binary blob,
//! `Connections\DefaultConnectionSettings`, and Chromium reads its configuration through
//! `WinHttpGetIEProxyConfigForCurrentUser`, not by reading our three values directly. If the
//! blob's flag byte does not have the manual-proxy bit set, a Chromium started at that moment
//! resolves DIRECT no matter what the flat values say.
//!
//! This module exists because of one measurement and one bug. On 2026-08-07 a volunteer's
//! Discord sent its native updater to our proxy — which reads `HTTPS_PROXY` — and never sent
//! its Chromium half, which reads WinINET. On 2026-08-08 the reason became a candidate:
//! `registry::refresh()` had never actually notified WinINET at all. So the first thing to know
//! about any machine where this happens is what its blob says, and the honest way to get that
//! is to read it and print it rather than to guess.
//!
//! **Nothing here writes.** The blob's layout is reverse-engineered, not documented, and a bad
//! write to it takes a machine off the internet in a way `vigil-repair` could not undo.
//! Reading is safe; writing is somebody else's mistake to make.

/// Flag bits in the blob's DWORD at offset 8. Reverse-engineered and widely corroborated, but
/// **not** documented by Microsoft — which is exactly why the raw byte is reported too.
pub mod flag {
    /// A direct connection is permitted.
    pub const DIRECT: u32 = 0x01;
    /// The manual proxy is in force. **This is the bit that decides whether vigil is reached.**
    pub const MANUAL_PROXY: u32 = 0x02;
    /// Use an automatic configuration script (`AutoConfigURL`).
    pub const AUTO_CONFIG_SCRIPT: u32 = 0x04;
    /// Automatically detect settings (WPAD).
    pub const AUTO_DETECT: u32 = 0x08;
}

/// The decoded contents of `Connections\DefaultConnectionSettings`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionSettings {
    pub flags: u32,
    pub proxy_server: String,
    pub bypass: String,
    pub auto_config_url: String,
}

impl ConnectionSettings {
    pub fn manual_proxy_live(&self) -> bool {
        self.flags & flag::MANUAL_PROXY != 0
    }

    /// Is an automatic method also enabled? Chromium's automatic path is tried *before* the
    /// manual rules, so this is worth knowing — but only worth worrying about if the automatic
    /// method actually succeeds. A missing WPAD host or an unfetchable PAC is a failure, after
    /// which Chromium falls back to the manual rules. So this is a question, not a verdict.
    pub fn automatic_also_enabled(&self) -> bool {
        self.flags & (flag::AUTO_CONFIG_SCRIPT | flag::AUTO_DETECT) != 0
    }

    pub fn describe_flags(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.flags & flag::DIRECT != 0 {
            v.push("direct");
        }
        if self.flags & flag::MANUAL_PROXY != 0 {
            v.push("manual-proxy");
        }
        if self.flags & flag::AUTO_CONFIG_SCRIPT != 0 {
            v.push("auto-config-script");
        }
        if self.flags & flag::AUTO_DETECT != 0 {
            v.push("auto-detect(WPAD)");
        }
        if v.is_empty() {
            v.push("none");
        }
        v
    }
}

/// Decode the blob. `None` when it is too short to hold even the flags.
///
/// Layout, offset by offset: four bytes of version, four of a write counter, four of flags,
/// then three length-prefixed ASCII strings — proxy server, bypass list, auto-config URL. A
/// truncated tail is not an error: older Windows versions write shorter blobs, and a blob that
/// stops after the flags still answers the only question that matters.
pub fn parse_blob(b: &[u8]) -> Option<ConnectionSettings> {
    if b.len() < 12 {
        return None;
    }
    let flags = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    let mut at = 12usize;
    let mut next = || -> String {
        if at + 4 > b.len() {
            return String::new();
        }
        let n = u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize;
        at += 4;
        // A length that runs past the end means we have misread the layout. Returning what is
        // there beats panicking on somebody else's machine, and the raw bytes are printed too.
        let end = (at + n).min(b.len());
        let s = String::from_utf8_lossy(&b[at..end]).into_owned();
        at = end;
        s
    };
    let proxy_server = next();
    let bypass = next();
    let auto_config_url = next();
    Some(ConnectionSettings {
        flags,
        proxy_server,
        bypass,
        auto_config_url,
    })
}

/// Does the blob agree with the flat values — i.e. would a Chromium starting now see vigil?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agreement {
    /// The blob names the same proxy and has the manual bit set.
    InSync,
    /// The blob exists and does not match. **This is the failure mode worth shipping a
    /// diagnostic for:** the flat values say vigil, WinINET says something else.
    Stale { blob: String, flat: String },
    /// No blob at all. Not necessarily broken — Windows creates it on demand.
    Missing,
}

/// Compare what we wrote with what WinINET will resolve.
///
/// `flat_enabled`/`flat_server` are `ProxyEnable`/`ProxyServer` as [`crate::registry`] wrote
/// them. Deliberately string-compared after trimming only: a blob that names a *different*
/// port is exactly the interesting case, and normalising it away would hide it.
pub fn agreement(
    flat_enabled: bool,
    flat_server: &str,
    blob: Option<&ConnectionSettings>,
) -> Agreement {
    let Some(c) = blob else {
        return Agreement::Missing;
    };
    let live = c.manual_proxy_live();
    let same = c.proxy_server.trim() == flat_server.trim();
    if live == flat_enabled && same {
        Agreement::InSync
    } else {
        Agreement::Stale {
            blob: format!(
                "flags=0x{:02X} ({}) server={:?}",
                c.flags,
                c.describe_flags().join("+"),
                c.proxy_server
            ),
            flat: format!(
                "ProxyEnable={} server={:?}",
                u32::from(flat_enabled),
                flat_server
            ),
        }
    }
}

/// One thing read from the machine: where it came from, and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    pub source: String,
    pub value: String,
}

/// Everything the diagnostic collected. Strings, because its only job is to be printed and
/// read by a human on another city's line.
#[derive(Debug, Clone, Default)]
pub struct Diagnosis {
    pub readings: Vec<Reading>,
    pub blob: Option<ConnectionSettings>,
    pub blob_raw_len: usize,
    pub agreement: Option<Agreement>,
    /// Value names under the `Connections` key other than the default one — each is a named
    /// RAS/VPN/dial-up entry with its own proxy configuration that can outrank the default.
    pub other_connections: Vec<String>,
    /// Policy keys that were present at all. An enterprise proxy policy overrides the user's
    /// settings outright, and a browser policy overrides them for that browser only.
    pub policies: Vec<Reading>,
}

impl Diagnosis {
    /// The one-line answer, for a report that somebody skims.
    pub fn headline(&self) -> String {
        match &self.agreement {
            None => "WinINET durumu okunamadı".into(),
            Some(Agreement::Missing) => {
                "DefaultConnectionSettings yok — Windows bunu gerektiğinde yazar".into()
            }
            Some(Agreement::InSync) => {
                "WinINET bizim yazdığımızı görüyor (blob senkron, manual-proxy biti açık)".into()
            }
            Some(Agreement::Stale { .. }) => {
                "*** WinINET BİZİM YAZDIĞIMIZI GÖRMÜYOR — blob bayat ***".into()
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    const IS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const CONN: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

    fn str_at(root: winreg::HKEY, path: &str, name: &str) -> Option<String> {
        RegKey::predef(root)
            .open_subkey(path)
            .ok()?
            .get_value::<String, _>(name)
            .ok()
    }

    fn u32_at(root: winreg::HKEY, path: &str, name: &str) -> Option<u32> {
        RegKey::predef(root)
            .open_subkey(path)
            .ok()?
            .get_value::<u32, _>(name)
            .ok()
    }

    fn note(out: &mut Vec<Reading>, source: &str, v: Option<String>) {
        out.push(Reading {
            source: source.into(),
            value: v.unwrap_or_else(|| "(yok)".into()),
        });
    }

    pub fn collect() -> Diagnosis {
        let mut d = Diagnosis::default();

        let enabled = u32_at(HKEY_CURRENT_USER, IS, "ProxyEnable").unwrap_or(0) == 1;
        let server = str_at(HKEY_CURRENT_USER, IS, "ProxyServer").unwrap_or_default();

        note(
            &mut d.readings,
            "HKCU ProxyEnable",
            Some(u32::from(enabled).to_string()),
        );
        note(&mut d.readings, "HKCU ProxyServer", Some(server.clone()));
        note(
            &mut d.readings,
            "HKCU ProxyOverride",
            str_at(HKEY_CURRENT_USER, IS, "ProxyOverride"),
        );
        note(
            &mut d.readings,
            "HKCU AutoConfigURL",
            str_at(HKEY_CURRENT_USER, IS, "AutoConfigURL"),
        );
        note(
            &mut d.readings,
            "HKLM ProxyServer",
            str_at(HKEY_LOCAL_MACHINE, IS, "ProxyServer"),
        );

        // The blob, and the named connections beside it.
        if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(CONN) {
            if let Ok(raw) = k.get_raw_value("DefaultConnectionSettings") {
                d.blob_raw_len = raw.bytes.len();
                d.blob = parse_blob(&raw.bytes);
            }
            d.other_connections = k
                .enum_values()
                .filter_map(|r| r.ok().map(|(n, _)| n))
                .filter(|n| n != "DefaultConnectionSettings" && n != "SavedLegacySettings")
                .collect();
        }
        d.agreement = Some(agreement(enabled, &server, d.blob.as_ref()));

        // Policies. Present-or-absent is most of the answer; the value matters only if present.
        for (label, root, path, name) in [
            (
                "policy: WinINET ProxySettingsPerUser",
                HKEY_LOCAL_MACHINE,
                r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
                "ProxySettingsPerUser",
            ),
            (
                "policy: Edge ProxyMode",
                HKEY_LOCAL_MACHINE,
                r"Software\Policies\Microsoft\Edge",
                "ProxyMode",
            ),
            (
                "policy: Edge ProxyServer",
                HKEY_LOCAL_MACHINE,
                r"Software\Policies\Microsoft\Edge",
                "ProxyServer",
            ),
            (
                "policy: Chrome ProxyMode",
                HKEY_LOCAL_MACHINE,
                r"Software\Policies\Google\Chrome",
                "ProxyMode",
            ),
            (
                "policy: Chrome ProxyServer",
                HKEY_LOCAL_MACHINE,
                r"Software\Policies\Google\Chrome",
                "ProxyServer",
            ),
        ] {
            let v = str_at(root, path, name)
                .or_else(|| u32_at(root, path, name).map(|n| n.to_string()));
            if let Some(v) = v {
                d.policies.push(Reading {
                    source: label.into(),
                    value: v,
                });
            }
        }
        d
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Diagnosis;
    pub fn collect() -> Diagnosis {
        Diagnosis::default()
    }
}

/// Read the machine's effective WinINET proxy configuration. Windows-only; elsewhere empty.
pub fn collect() -> Diagnosis {
    imp::collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real blob from the development machine, 2026-08-08, with the proxy engaged. Kept
    /// verbatim because a parser for an undocumented format should be tested against bytes that
    /// actually came off a machine, not against bytes invented to match the parser.
    fn real_blob() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&70u32.to_le_bytes()); // version 0x46
        b.extend_from_slice(&9u32.to_le_bytes()); // write counter
        b.extend_from_slice(&0x0Bu32.to_le_bytes()); // direct + manual + auto-detect
        let server = b"https=127.0.0.1:1080";
        b.extend_from_slice(&(server.len() as u32).to_le_bytes());
        b.extend_from_slice(server);
        let bypass = b"localhost;127.*;192.168.*;<local>";
        b.extend_from_slice(&(bypass.len() as u32).to_le_bytes());
        b.extend_from_slice(bypass);
        b.extend_from_slice(&0u32.to_le_bytes()); // no auto-config URL
        b
    }

    #[test]
    fn the_development_machines_blob_decodes() {
        let c = parse_blob(&real_blob()).expect("parses");
        assert_eq!(c.flags, 0x0B);
        assert_eq!(c.proxy_server, "https=127.0.0.1:1080");
        assert!(c.bypass.contains("<local>"));
        assert_eq!(c.auto_config_url, "");
        assert!(c.manual_proxy_live());
        // Measured on that machine: auto-detect is ON at the same time and the manual proxy is
        // still what gets used. So this bit alone is not an explanation for anything.
        assert!(c.automatic_also_enabled());
        assert_eq!(
            c.describe_flags(),
            vec!["direct", "manual-proxy", "auto-detect(WPAD)"]
        );
    }

    #[test]
    fn a_blob_that_stops_after_the_flags_still_answers_the_question() {
        let mut b = vec![0u8; 12];
        b[8] = flag::MANUAL_PROXY as u8;
        let c = parse_blob(&b).expect("parses");
        assert!(c.manual_proxy_live());
        assert_eq!(c.proxy_server, "");
    }

    #[test]
    fn too_short_to_hold_flags_is_none() {
        assert!(parse_blob(&[]).is_none());
        assert!(parse_blob(&[0u8; 11]).is_none());
    }

    /// A length field that runs off the end must not panic. This runs on a volunteer's machine.
    #[test]
    fn a_lying_length_does_not_panic() {
        let mut b = vec![0u8; 12];
        b[8] = 0x02;
        b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        b.extend_from_slice(b"short");
        let c = parse_blob(&b).expect("parses");
        assert_eq!(c.proxy_server, "short");
    }

    #[test]
    fn in_sync_when_the_blob_names_the_same_proxy() {
        let c = parse_blob(&real_blob()).unwrap();
        assert_eq!(
            agreement(true, "https=127.0.0.1:1080", Some(&c)),
            Agreement::InSync
        );
    }

    /// The case the whole module was written for: the flat values name vigil and WinINET does
    /// not. Before 2026-08-08 nothing in this project could have told the difference.
    #[test]
    fn a_blob_without_the_manual_bit_is_stale_however_right_the_flat_values_look() {
        let mut b = vec![0u8; 12];
        b[8] = flag::DIRECT as u8; // direct only
        let c = parse_blob(&b).unwrap();
        let a = agreement(true, "https=127.0.0.1:1085", Some(&c));
        assert!(matches!(a, Agreement::Stale { .. }), "{a:?}");
        let d = Diagnosis {
            agreement: Some(a),
            ..Default::default()
        };
        assert!(d.headline().contains("GÖRMÜYOR"), "{}", d.headline());
    }

    #[test]
    fn a_blob_naming_a_different_port_is_stale() {
        let mut b = vec![0u8; 12];
        b[8] = 0x03;
        b.extend_from_slice(&20u32.to_le_bytes());
        b.extend_from_slice(b"https=127.0.0.1:9999");
        let c = parse_blob(&b).unwrap();
        assert!(matches!(
            agreement(true, "https=127.0.0.1:1085", Some(&c)),
            Agreement::Stale { .. }
        ));
    }

    #[test]
    fn no_blob_is_reported_as_missing_not_as_broken() {
        assert_eq!(agreement(true, "x", None), Agreement::Missing);
        let d = Diagnosis {
            agreement: Some(Agreement::Missing),
            ..Default::default()
        };
        assert!(!d.headline().contains("GÖRMÜYOR"));
    }

    /// On Linux the collector returns nothing rather than pretending. The scan prints the
    /// section only when there is something in it.
    #[cfg(not(windows))]
    #[test]
    fn the_non_windows_collector_is_empty() {
        let d = collect();
        assert!(d.readings.is_empty());
        assert!(d.agreement.is_none());
        assert_eq!(d.headline(), "WinINET durumu okunamadı");
    }
}
