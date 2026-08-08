//! `vigil-repair` — put the system proxy back the way it was.
//!
//! Ships from day one, not last. The failure this exists for is real and specific: the user
//! force-kills vigil (or it crashes), Windows is still pointed at a proxy that is no longer
//! listening, and the machine has no internet until someone finds the setting. Every mature
//! tool in this space ships an equivalent, and the ones that did not are the ones with
//! support threads full of it.
//!
//! Usage:  vigil-repair [--snapshot PATH] [--force]

use std::process::ExitCode;

use vigil_platform::registry;
use vigil_platform::sysproxy::{self, ProxySettings};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut snapshot = default_snapshot_path();
    let mut force = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--snapshot" => {
                i += 1;
                match args.get(i) {
                    Some(p) => snapshot = Some(p.into()),
                    None => {
                        eprintln!("--snapshot needs a PATH");
                        return ExitCode::from(2);
                    }
                }
            }
            "--force" => force = true,
            "-h" | "--help" => {
                eprintln!("usage: vigil-repair [--snapshot PATH] [--force] [--version]");
                return ExitCode::SUCCESS;
            }
            // Exists so an update can *prove* the safety net still works before it replaces
            // anything else. `vigil-update` runs this and refuses to continue if it does not exit
            // zero — a broken repair tool is worse than an old one, and this is the one thing in
            // the whole update that is checked by running it rather than by hashing it.
            "-V" | "--version" => {
                println!("vigil-repair {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let current = match registry::read_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot read the current settings: {e}");
            return ExitCode::from(1);
        }
    };
    println!("current: {current}");

    // Three things vigil can leave behind, and they are independent: a machine can have a
    // clean proxy setting and stranded environment variables, or clean variables and a DNS
    // server pointing at a vigil that is gone. An early return here — which is what this did
    // until 2026-08-05 — means the quieter two are never even looked at.
    if !force && !sysproxy::is_stranded(&current, "127.0.0.1:") {
        println!("proxy: nothing to repair (not pointing at vigil)");
        repair_env(force);
        repair_dns(force);
        println!("(use --force to disable the proxy anyway)");
        return ExitCode::SUCCESS;
    }

    // Prefer restoring exactly what was there before vigil started.
    let target = snapshot
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| sysproxy::snapshot_from_text(&t))
        .map(|prev| {
            println!("restoring the snapshot taken before vigil started");
            sysproxy::rollback_to(&prev)
        })
        .unwrap_or_else(|| {
            println!("no usable snapshot; disabling the proxy instead");
            sysproxy::disabled()
        });

    match registry::apply(&target) {
        Ok(()) => {
            println!("restored: {target}");
            if let Some(p) = &snapshot {
                let _ = std::fs::remove_file(p);
            }
            repair_env(force);
            repair_dns(force);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("could not write the settings: {e}");
            eprintln!("undo it by hand: Settings > Network & Internet > Proxy > off");
            ExitCode::from(1)
        }
    }
}

/// The other half of a stranded machine, and the quieter one.
///
/// `HTTP_PROXY` and friends are read by `git`, `pip`, `npm` and every script that shells out
/// to `curl`. Left pointing at a listener that is gone they fail with connection-refused and
/// nothing on screen mentions a proxy, so this is arguably the harder half to diagnose by
/// hand. Repaired on the same rules: restore the snapshot if there is one, otherwise clear.
fn repair_env(force: bool) {
    use vigil_platform::{envproxy, envreg};

    let current = match envreg::read_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot read the proxy environment variables: {e}");
            return;
        }
    };
    if !force && !envproxy::is_stranded(&current, "127.0.0.1:") {
        println!("environment: nothing to repair");
        return;
    }
    let target = env_snapshot_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| {
            println!("environment: restoring the snapshot taken before vigil started");
            envproxy::snapshot_from_text(&t)
        })
        .unwrap_or_else(|| {
            println!("environment: no usable snapshot; clearing the variables instead");
            envproxy::EnvProxy::default()
        });
    match envreg::apply(&target) {
        Ok(()) => {
            println!("environment: restored");
            if let Some(p) = env_snapshot_path() {
                let _ = std::fs::remove_file(p);
            }
        }
        Err(e) => {
            eprintln!("environment: could not write the variables: {e}");
            eprintln!("undo it by hand: Windows > \"Edit environment variables for your account\"");
        }
    }
}

/// The third thing vigil can leave behind, and the worst of them.
///
/// A stranded proxy setting breaks the programs that read it. A machine whose DNS still points
/// at a vigil that is not running has **no name resolution at all** — nothing resolves, and the
/// error every program shows is about the site, never about a resolver. vigil always writes a
/// public fallback after itself so this should not happen, but "should not" is not a plan.
fn repair_dns(force: bool) {
    use vigil_platform::{dnsclient, sysdns};

    let ifaces = match dnsclient::read_interfaces() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("dns: cannot read the current servers: {e}");
            return;
        }
    };
    let stranded = sysdns::stranded(&ifaces);
    if stranded.is_empty() && !force {
        println!("dns: nothing to repair");
        return;
    }
    let snapshot: Vec<sysdns::Interface> = dns_snapshot_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| sysdns::parse(&t))
        .unwrap_or_default();

    let mut changes: Vec<(u32, Option<Vec<String>>)> = Vec::new();
    for i in &stranded {
        match snapshot.iter().find(|s| s.index == i.index) {
            Some(s) => {
                println!(
                    "dns: {} ({}) -> restoring what was there before",
                    i.alias, i.index
                );
                changes.push((i.index, sysdns::restore_value(s)));
            }
            // No record of what was there: back to DHCP, which is what the overwhelming
            // majority of machines were on and is recoverable from by the router.
            None => {
                println!(
                    "dns: {} ({}) -> no snapshot; handing it back to DHCP",
                    i.alias, i.index
                );
                changes.push((i.index, None));
            }
        }
    }
    if changes.is_empty() {
        println!("dns: nothing to repair");
        return;
    }
    println!("dns: this needs administrator rights — Windows will ask");
    match dnsclient::apply(&changes) {
        Ok(()) => {
            println!("dns: restored");
            if let Some(p) = dns_snapshot_path() {
                let _ = std::fs::remove_file(p);
            }
        }
        Err(e) => {
            eprintln!("dns: could not restore ({e})");
            eprintln!(
                "undo it by hand: Ayarlar > Ağ ve İnternet > adaptör > DNS > Otomatik (DHCP)"
            );
        }
    }
}

fn dns_snapshot_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("APPDATA").map(std::path::PathBuf::from)?;
    Some(base.join("vigil").join("sysdns-snapshot.txt"))
}

fn env_snapshot_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("APPDATA").map(std::path::PathBuf::from)?;
    Some(base.join("vigil").join("envproxy-snapshot.txt"))
}

fn default_snapshot_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("APPDATA").map(std::path::PathBuf::from)?;
    Some(base.join("vigil").join("sysproxy-snapshot.txt"))
}

#[allow(dead_code)]
fn _unused(_: ProxySettings) {}
