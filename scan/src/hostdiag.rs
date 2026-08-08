//! Everything about *this machine* that decides whether vigil can be reached at all.
//!
//! The alternative was a block of PowerShell for a volunteer to paste, which is how this kind
//! of question is usually asked and is a bad way to ask it: it puts the error surface on the
//! person doing you a favour, and what comes back is a screenshot of a console. This collects
//! the same facts, writes them into the report beside the measurements, and **changes nothing**.
//!
//! Everything here is read-only. That is not a style preference — the WinINET connection blob
//! is undocumented, and a diagnostic that wrote to it could take somebody's machine off the
//! internet in a way `vigil-repair` was never designed to undo.
//!
//! It exists because of the 2026-08-07 Superonline run: every network measurement said the
//! block was defeated, and Discord's Chromium half never sent us a single request. Nothing in
//! the report could distinguish "Chromium never asked" from "Chromium asked and went direct",
//! and the four candidate explanations all lived in registry values the tool never read.

use vigil_platform::proxydiag::{self, Agreement, Diagnosis};

/// A Microsoft Store / MSIX package that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagedApp {
    pub name: String,
    pub family: String,
    pub location: String,
    /// `Some(true)` when the manifest declares `runFullTrust`. A packaged app *without* it is
    /// an AppContainer, and an AppContainer cannot connect to `127.0.0.1` at all without an
    /// administrator-granted loopback exemption — which would make it unreachable by any proxy,
    /// however the proxy is configured.
    pub full_trust: Option<bool>,
    /// The `<Application Id="...">` from the manifest, which is what `shell:appsFolder\` needs
    /// after the `!`. Read from the manifest rather than assumed to be `App`, because guessing
    /// it wrong looks exactly like "not installed".
    pub app_id: Option<String>,
}

impl PackagedApp {
    /// How Explorer launches it. `shell:appsFolder\<family>!<app id>` is the documented form and
    /// the only one that works for a packaged application — there is no path to double-click.
    pub fn launch_target(&self) -> Option<String> {
        let id = self.app_id.as_deref()?;
        Some(format!("shell:appsFolder\\{}!{}", self.family, id))
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
/// Store packages whose name contains `needle`, case-insensitively. Empty off Windows.
pub fn packaged(needle: &str) -> Vec<PackagedApp> {
    imp::packaged(needle)
}

/// Pull `<Application Id="...">` out of a package manifest.
///
/// A five-line scan rather than an XML dependency: the attribute is the first `Id="` after the
/// `<Application` element, and this crate is handed to volunteers and stays small on purpose.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn manifest_app_id(xml: &str) -> Option<String> {
    let at = xml.find("<Application")?;
    let rest = &xml[at..];
    let idx = rest.find("Id=\"")? + 4;
    let end = rest[idx..].find('"')?;
    Some(rest[idx..idx + end].to_string())
}

/// What was found on the machine. Strings, because its only job is to be read by a human.
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    pub proxy: Diagnosis,
    /// WPAD names asked of the system resolver, and what came back. An answer here means the
    /// automatic path might really outrank the manual proxy; NXDOMAIN means it cannot.
    pub wpad: Vec<(String, String)>,
    pub packaged: Vec<PackagedApp>,
    /// Facts about the Discord install: which `app-*` directories exist, what the Squirrel log
    /// last said, whether the update-skip keys are set.
    pub discord: Vec<(String, String)>,
}

#[cfg_attr(not(windows), allow(dead_code))]
/// Replace the user's profile path with a placeholder wherever it appears.
///
/// The report promises no personal data and then prints file paths, which on most machines
/// contain the person's name. Cheap to fix and it applies to a report that gets forwarded.
pub fn scrub(s: &str, profile: Option<&str>) -> String {
    let Some(p) = profile.map(str::trim).filter(|p| !p.is_empty()) else {
        return s.to_string();
    };
    // Case-insensitively, because Windows hands the same path back in several spellings.
    let lower = s.to_ascii_lowercase();
    let needle = p.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut at = 0usize;
    while let Some(i) = lower[at..].find(&needle) {
        let start = at + i;
        out.push_str(&s[at..start]);
        out.push_str("%USERPROFILE%");
        at = start + needle.len();
    }
    out.push_str(&s[at..]);
    out
}

/// The line that belongs at the *top* of the report, not in a numbered section halfway down.
///
/// Empty unless WinINET and our own values have diverged. A report is skimmed; the one finding
/// that invalidates every "the application did not use the proxy" reading has to be visible
/// before the reader decides what the run means.
pub fn warning(d: &Diagnosis) -> String {
    match d.agreement {
        Some(Agreement::Stale { .. }) => concat!(
            "*** WINDOWS'UN PROXY AYARI GEÇERLİ DEĞİL ***\n",
            "Düz kayıt defteri değerleri vigil'i gösteriyor ama WinINET'in kendi ikili\n",
            "yapılandırması onunla aynı şeyi söylemiyor — bölüm 6'ya bak. Bu makinede\n",
            "tarayıcılar ve Electron uygulamaları proxy'yi göremez, dolayısıyla aşağıdaki\n",
            "\"uygulama vigil'e gelmedi\" satırları uygulamanın değil ayarın sonucudur.\n\n"
        )
        .into(),
        _ => String::new(),
    }
}

/// Render the section. Empty string when there is nothing to say, so a Linux build of the
/// scanner does not print an empty heading.
pub fn render(f: &HostFacts) -> String {
    if f.proxy.readings.is_empty() && f.wpad.is_empty() && f.packaged.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    s.push_str("\n\n6. BU MAKİNEDE PROXY AYARI GERÇEKTEN GEÇERLİ Mİ?\n");
    s.push_str(&"-".repeat(78));
    s.push_str("\nSadece okundu, hiçbir şey değiştirilmedi. Windows'un proxy ayarı iki yerde\n");
    s.push_str("durur: bizim yazdığımız düz değerler, ve WinINET'in gerçekten okuduğu ikili\n");
    s.push_str("blob. İkisi ayrışırsa tarayıcılar ve Electron uygulamaları proxy'yi görmez.\n\n");

    s.push_str(&format!("  {}\n\n", f.proxy.headline()));

    for r in &f.proxy.readings {
        s.push_str(&format!("  {:<28} {}\n", r.source, r.value));
    }

    if let Some(c) = &f.proxy.blob {
        s.push_str(&format!(
            "\n  DefaultConnectionSettings ({} bayt)\n",
            f.proxy.blob_raw_len
        ));
        s.push_str(&format!(
            "    flags                    0x{:02X}  ({})\n",
            c.flags,
            c.describe_flags().join(" + ")
        ));
        s.push_str(&format!(
            "    proxy                    {:?}\n",
            c.proxy_server
        ));
        s.push_str(&format!("    bypass                   {:?}\n", c.bypass));
        s.push_str(&format!(
            "    auto-config              {:?}\n",
            c.auto_config_url
        ));
        if c.automatic_also_enabled() {
            s.push_str(
                "    not: otomatik yöntem de açık. Chromium otomatiği önce dener, ama\n\
                 \x20        başarısız olursa manuel kurallara döner — aşağıdaki WPAD satırı\n\
                 \x20        bunun gerçekten cevap veren biri olup olmadığını söylüyor.\n",
            );
        }
    } else {
        s.push_str("\n  DefaultConnectionSettings: yok\n");
    }

    if let Some(Agreement::Stale { blob, flat }) = &f.proxy.agreement {
        s.push_str("\n  *** AYRIŞMA ***\n");
        s.push_str(&format!("    WinINET : {blob}\n"));
        s.push_str(&format!("    bizim   : {flat}\n"));
        s.push_str(
            "    Bu, ayarı yazdığımız hâlde WinINET okuyan hiçbir programın onu\n\
             \x20   görmediği anlamına gelir.\n",
        );
    }

    if !f.proxy.other_connections.is_empty() {
        s.push_str(&format!(
            "\n  Connections altındaki diğer bağlantılar: {}\n",
            f.proxy.other_connections.join(", ")
        ));
        s.push_str("    Her biri kendi proxy ayarını taşır ve varsayılanı ezebilir.\n");
    }

    s.push_str("\n  Grup ilkeleri (policy)\n");
    if f.proxy.policies.is_empty() {
        s.push_str("    yok — kurumsal bir proxy ilkesi ayarlarımızı ezmiyor\n");
    } else {
        for p in &f.proxy.policies {
            s.push_str(&format!("    {:<40} {}\n", p.source, p.value));
        }
    }

    if !f.wpad.is_empty() {
        s.push_str("\n  WPAD (otomatik ayar keşfi)\n");
        for (name, answer) in &f.wpad {
            s.push_str(&format!("    {name:<28} {answer}\n"));
        }
    }

    s.push_str("\n  Paketli (Microsoft Store) uygulamalar\n");
    if f.packaged.is_empty() {
        s.push_str("    eşleşen paket yok\n");
    } else {
        for p in &f.packaged {
            s.push_str(&format!("    {} ({})\n", p.name, p.family));
            s.push_str(&format!("      konum        {}\n", p.location));
            s.push_str(&format!(
                "      başlatma     {}\n",
                p.launch_target()
                    .unwrap_or_else(|| "manifestte Application Id bulunamadı".into())
            ));
            s.push_str(&format!(
                "      runFullTrust {}\n",
                match p.full_trust {
                    Some(true) => "var — normal bir masaüstü uygulaması gibi ağa çıkar",
                    Some(false) =>
                        "YOK — AppContainer. 127.0.0.1'e hiçbir proxy ayarıyla ulaşamaz;\n\
                         \x20                   yönetici verdiği bir loopback muafiyeti gerekir.",
                    None => "manifest okunamadı",
                }
            ));
        }
    }

    if !f.discord.is_empty() {
        s.push_str("\n  Discord kurulumu\n");
        for (k, v) in &f.discord {
            s.push_str(&format!("    {k:<28} {v}\n"));
        }
    }

    s
}

/// Collect everything. Windows-only; elsewhere returns empty so the scanner still builds.
pub fn collect() -> HostFacts {
    HostFacts {
        proxy: proxydiag::collect(),
        wpad: imp::wpad(),
        packaged: imp::packaged("roblox"),
        discord: imp::discord(),
    }
}

#[cfg(windows)]
mod imp {
    use super::{scrub, PackagedApp};

    fn profile() -> Option<String> {
        std::env::var("USERPROFILE").ok()
    }

    /// Ask the *system* resolver for the WPAD names, because that is what Windows itself asks.
    ///
    /// An answer does not prove the automatic path wins — the PAC still has to be fetched and
    /// parsed. But NXDOMAIN does prove it cannot, and that kills a whole family of theories
    /// about Chromium preferring auto-detect, which is the point of asking.
    pub fn wpad() -> Vec<(String, String)> {
        use std::net::ToSocketAddrs;
        let mut names = vec!["wpad".to_string()];
        if let Some(suffix) = dns_suffix() {
            names.push(format!("wpad.{suffix}"));
        }
        names
            .into_iter()
            .map(|n| {
                let answer = match (n.as_str(), 80u16).to_socket_addrs() {
                    Ok(a) => {
                        let v: Vec<String> = a.map(|s| s.ip().to_string()).collect();
                        if v.is_empty() {
                            "cevap yok".to_string()
                        } else {
                            format!("CEVAP VERDİ: {}", v.join(","))
                        }
                    }
                    Err(_) => "çözülmedi (NXDOMAIN) — otomatik keşif çalışamaz".to_string(),
                };
                (n, answer)
            })
            .collect()
    }

    /// The connection-specific DNS suffix, which is what `wpad.<suffix>` is built from.
    fn dns_suffix() -> Option<String> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let k = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
            .ok()?;
        for name in ["Domain", "DhcpDomain", "SearchList"] {
            if let Ok(v) = k.get_value::<String, _>(name) {
                let first = v.split(',').next().unwrap_or("").trim().to_string();
                if !first.is_empty() {
                    return Some(first);
                }
            }
        }
        None
    }

    /// Store packages whose name contains `needle`.
    ///
    /// Through PowerShell rather than the WinRT `PackageManager`: this crate shells out to
    /// `tasklist` and `taskkill` already, the call happens once, and a WinRT dependency for one
    /// query would be the largest thing in the crate.
    pub fn packaged(needle: &str) -> Vec<PackagedApp> {
        let script = format!(
            "Get-AppxPackage *{needle}* | ForEach-Object {{ \
             $_.Name + '|' + $_.PackageFamilyName + '|' + $_.InstallLocation }}"
        );
        let out = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output();
        let Ok(o) = out else { return Vec::new() };
        let text = String::from_utf8_lossy(&o.stdout);
        let p = profile();
        text.lines()
            .filter_map(|l| {
                let mut it = l.trim().split('|');
                let name = it.next()?.trim().to_string();
                let family = it.next()?.trim().to_string();
                let location = it.next().unwrap_or("").trim().to_string();
                if name.is_empty() {
                    return None;
                }
                let manifest = read_manifest(&location);
                Some(PackagedApp {
                    full_trust: manifest.as_deref().map(|x| x.contains("runFullTrust")),
                    app_id: manifest.as_deref().and_then(super::manifest_app_id),
                    location: scrub(&location, p.as_deref()),
                    name,
                    family,
                })
            })
            .collect()
    }

    /// The package manifest, read directly rather than through PowerShell, so both the trust
    /// level and the application id come from the file and not from a formatting decision.
    fn read_manifest(location: &str) -> Option<String> {
        if location.is_empty() {
            return None;
        }
        std::fs::read_to_string(std::path::Path::new(location).join("AppxManifest.xml")).ok()
    }

    /// Read-only facts about the Discord install, aimed at one question: did the client get
    /// past its native update stage, or is it looping there?
    pub fn discord() -> Vec<(String, String)> {
        let mut out = Vec::new();
        let Ok(local) = std::env::var("LOCALAPPDATA") else {
            return out;
        };
        let root = std::path::Path::new(&local).join("Discord");
        if !root.exists() {
            out.push(("kurulum dizini".into(), "yok".into()));
            return out;
        }
        let mut apps: Vec<String> = std::fs::read_dir(&root)
            .map(|d| {
                d.flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| n.starts_with("app-"))
                    .collect()
            })
            .unwrap_or_default();
        apps.sort();
        out.push((
            "app-* dizinleri".into(),
            if apps.is_empty() {
                "hiç yok — istemci hiç kurulmamış ya da temizlenmiş".into()
            } else {
                apps.join(", ")
            },
        ));
        // More than one is normal during an update and suspicious if it persists: Squirrel
        // leaves the old one until the new one has started successfully at least once.
        if apps.len() > 1 {
            out.push((
                "not".into(),
                "birden fazla sürüm duruyor — güncelleme tamamlanmamış olabilir".into(),
            ));
        }
        let p = profile();
        for log in ["SquirrelSetup.log", "SquirrelTemp\\SquirrelSetup.log"] {
            let path = root.join(log);
            if let Ok(text) = std::fs::read_to_string(&path) {
                let tail: Vec<&str> = text.lines().rev().take(12).collect();
                out.push((format!("{log} (son 12)"), String::new()));
                for line in tail.into_iter().rev() {
                    out.push((String::new(), scrub(line.trim(), p.as_deref())));
                }
            }
        }
        if let Ok(roaming) = std::env::var("APPDATA") {
            let s = std::path::Path::new(&roaming)
                .join("discord")
                .join("settings.json");
            match std::fs::read_to_string(&s) {
                Ok(t) => {
                    out.push((
                        "settings.json".into(),
                        format!(
                            "var, {} bayt; SKIP_HOST_UPDATE={} SKIP_MODULE_UPDATE={}",
                            t.len(),
                            t.contains("SKIP_HOST_UPDATE"),
                            t.contains("SKIP_MODULE_UPDATE")
                        ),
                    ));
                }
                Err(_) => out.push(("settings.json".into(), "yok".into())),
            }
        }
        out
    }
}

#[cfg(not(windows))]
mod imp {
    use super::PackagedApp;
    pub fn wpad() -> Vec<(String, String)> {
        Vec::new()
    }
    pub fn packaged(_needle: &str) -> Vec<PackagedApp> {
        Vec::new()
    }
    pub fn discord() -> Vec<(String, String)> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_path_is_replaced_everywhere_it_appears() {
        let s = r"C:\Users\resul\AppData\Local\Discord and C:\USERS\RESUL\x";
        assert_eq!(
            scrub(s, Some(r"C:\Users\resul")),
            r"%USERPROFILE%\AppData\Local\Discord and %USERPROFILE%\x"
        );
    }

    #[test]
    fn scrubbing_without_a_profile_leaves_the_text_alone() {
        assert_eq!(scrub("abc", None), "abc");
        assert_eq!(scrub("abc", Some("  ")), "abc");
    }

    /// On Linux there is nothing to report, and the scanner must not print an empty heading.
    #[test]
    fn nothing_to_say_renders_nothing() {
        assert_eq!(render(&HostFacts::default()), "");
    }

    /// The divergence has to be impossible to miss, in the rendered text, in the language of
    /// the person reading it.
    #[test]
    fn a_stale_blob_shouts_in_the_report() {
        let f = HostFacts {
            proxy: Diagnosis {
                readings: vec![vigil_platform::proxydiag::Reading {
                    source: "HKCU ProxyServer".into(),
                    value: "https=127.0.0.1:1085".into(),
                }],
                agreement: Some(Agreement::Stale {
                    blob: "flags=0x01 (direct) server=\"\"".into(),
                    flat: "ProxyEnable=1 server=\"https=127.0.0.1:1085\"".into(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render(&f);
        assert!(text.contains("AYRIŞMA"), "{text}");
        assert!(text.contains("GÖRMÜYOR"), "{text}");
        assert!(text.contains("6. BU MAKİNEDE"));
    }

    /// The header warning is what a skimmer sees, so it must exist exactly when the divergence
    /// does and never otherwise.
    #[test]
    fn the_header_warning_appears_only_on_a_divergence() {
        let stale = Diagnosis {
            agreement: Some(Agreement::Stale {
                blob: "b".into(),
                flat: "f".into(),
            }),
            ..Default::default()
        };
        assert!(!warning(&stale).is_empty());
        for ok in [
            Diagnosis::default(),
            Diagnosis {
                agreement: Some(Agreement::InSync),
                ..Default::default()
            },
            Diagnosis {
                agreement: Some(Agreement::Missing),
                ..Default::default()
            },
        ] {
            assert!(warning(&ok).is_empty(), "{:?}", ok.agreement);
        }
    }

    /// An AppContainer package is the one finding that no proxy configuration can fix, so it
    /// has to say so rather than printing a boolean.
    #[test]
    fn an_appcontainer_package_explains_itself() {
        let f = HostFacts {
            proxy: Diagnosis {
                readings: vec![vigil_platform::proxydiag::Reading {
                    source: "x".into(),
                    value: "y".into(),
                }],
                ..Default::default()
            },
            packaged: vec![PackagedApp {
                name: "ROBLOXCORPORATION.ROBLOX".into(),
                family: "ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr".into(),
                location: r"%USERPROFILE%\..\WindowsApps\x".into(),
                full_trust: Some(false),
                app_id: Some("App".into()),
            }],
            ..Default::default()
        };
        let text = render(&f);
        assert!(text.contains("AppContainer"), "{text}");
        assert!(text.contains("loopback muafiyeti"), "{text}");
    }

    /// The launch form is the whole reason the application id is read: guessing `!App` wrong
    /// looks exactly like "not installed", which is the mistake this round is correcting.
    #[test]
    fn a_packaged_app_is_launched_through_the_apps_folder() {
        let p = PackagedApp {
            name: "ROBLOXCORPORATION.ROBLOX".into(),
            family: "ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr".into(),
            location: "x".into(),
            full_trust: Some(true),
            app_id: Some("Roblox".into()),
        };
        assert_eq!(
            p.launch_target().as_deref(),
            Some(r"shell:appsFolder\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr!Roblox")
        );
        assert_eq!(
            PackagedApp { app_id: None, ..p }.launch_target(),
            None,
            "without an id there is nothing to launch, and saying so beats guessing"
        );
    }

    #[test]
    fn the_application_id_comes_out_of_the_manifest() {
        let xml = r#"<?xml version="1.0"?><Package>
            <Identity Name="ROBLOXCORPORATION.ROBLOX" Publisher="CN=x"/>
            <Applications><Application Id="Roblox" Executable="Windows10Universal.exe"
              EntryPoint="Windows.FullTrustApplication"/></Applications>
            <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities></Package>"#;
        assert_eq!(manifest_app_id(xml).as_deref(), Some("Roblox"));
        assert!(xml.contains("runFullTrust"));
        // `Identity Name=` comes first in the file and must not be mistaken for it.
        assert_ne!(
            manifest_app_id(xml).as_deref(),
            Some("ROBLOXCORPORATION.ROBLOX")
        );
        assert_eq!(manifest_app_id("<Package/>"), None);
        assert_eq!(manifest_app_id("<Application Executable=\"x\"/>"), None);
    }

    #[test]
    fn a_wpad_answer_and_an_nxdomain_read_differently() {
        let f = HostFacts {
            proxy: Diagnosis {
                readings: vec![vigil_platform::proxydiag::Reading {
                    source: "x".into(),
                    value: "y".into(),
                }],
                ..Default::default()
            },
            wpad: vec![
                (
                    "wpad".into(),
                    "çözülmedi (NXDOMAIN) — otomatik keşif çalışamaz".into(),
                ),
                ("wpad.home".into(), "CEVAP VERDİ: 192.168.1.1".into()),
            ],
            ..Default::default()
        };
        let text = render(&f);
        assert!(text.contains("NXDOMAIN"));
        assert!(text.contains("CEVAP VERDİ"));
    }
}
