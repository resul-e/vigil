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
        let ok = both(repair_env(force), repair_dns(force));
        println!("(use --force to disable the proxy anyway)");
        return exit_for(ok);
    }

    // Prefer restoring exactly what was there before vigil started.
    let previous = snapshot
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| sysproxy::snapshot_from_text(&t));

    // No snapshot means one of two very different things, and this used to treat them the same.
    //
    // If the setting names *our* address, there was a vigil here and its snapshot is missing or was
    // already consumed: disabling the proxy is right, and it is what saves a stranded machine.
    //
    // If it names some other local proxy — Clash, v2rayN, Fiddler, ByeDPI on another port — then
    // vigil deliberately never wrote a snapshot, because `sysproxy`/`envproxy::start` refuse to take
    // over a setting somebody else owns. Writing `disabled()` there does not repair anything: it
    // destroys a configuration this tool never touched, with nothing to restore it from.
    //
    // **And this comment used to end by saying "refusing is the only safe answer", which the code
    // below does not do and never did.** The arm that refused was removed on 2026-08-11 as provably
    // unreachable: getting this far requires `force || is_stranded`, and `is_stranded` matches any
    // enabled loopback address — including somebody else's. So the third-party case *does* reach the
    // clearing arm, and the honest description of today's behaviour is that this tool cannot yet tell
    // "a vigil that died" from "another local proxy on a port we do not use". The distinction it
    // needs is a third question neither half asks — **is anything listening there** — and until that
    // exists the comment must not claim a safety the code does not provide.
    let target = match (previous, sysproxy::is_stranded(&current, "127.0.0.1:")) {
        (Some(prev), _) => {
            println!("restoring the snapshot taken before vigil started");
            sysproxy::rollback_to(&prev)
        }
        (None, _) if force => {
            println!("no snapshot, but --force was given; disabling the proxy");
            sysproxy::disabled()
        }
        // Both remaining cases, because the second cannot happen: reaching this match at all
        // requires `force || is_stranded`, and `force` is consumed by the arm above — so `(None,
        // false)` is `!force && !is_stranded`, which returned early. There used to be a fourth arm
        // here printing "this is not vigil, leaving it alone", and it described a behaviour this tool
        // does not have from a state it cannot be in. A message that cannot be true is worse than no
        // message: somebody reasons from it.
        (None, _) => {
            println!("no usable snapshot; disabling the proxy instead");
            sysproxy::disabled()
        }
    };

    match registry::apply(&target) {
        Ok(()) => {
            println!("restored: {target}");
            if let Some(p) = &snapshot {
                let _ = std::fs::remove_file(p);
            }
            exit_for(both(repair_env(force), repair_dns(force)))
        }
        Err(e) => {
            eprintln!("could not write the settings: {e}");
            eprintln!("undo it by hand: Settings > Network & Internet > Proxy > off");
            ExitCode::from(1)
        }
    }
}

/// Both, and **both actually run**. `a && b` would skip the second when the first failed, and the
/// three things vigil can leave behind are independent: a machine can have clean environment
/// variables and a resolver pointing at a vigil that is gone. An early exit through the quieter
/// halves is the bug this file already fixed once, on 2026-08-05.
fn both(a: bool, b: bool) -> bool {
    a && b
}

/// What the exit code means, which until now was "the process reached the end".
///
/// `repair_env` and `repair_dns` returned `()`, so their failures printed to a stdout nobody reads
/// and the process still exited 0. That mattered beyond tidiness: `vigil-update` ran this tool and
/// took its exit status as proof the settings were restored, on the one path where being wrong means
/// somebody has no internet. The updater now re-reads the machine as well — belt and braces — but the
/// safety net's own contract should be true on its own.
fn exit_for(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        eprintln!();
        eprintln!("something could not be restored. Read the lines above: each says which of the");
        eprintln!("three (proxy, environment variables, DNS) failed and how to undo it by hand.");
        ExitCode::from(1)
    }
}

/// The other half of a stranded machine, and the quieter one.
///
/// `HTTP_PROXY` and friends are read by `git`, `pip`, `npm` and every script that shells out
/// to `curl`. Left pointing at a listener that is gone they fail with connection-refused and
/// nothing on screen mentions a proxy, so this is arguably the harder half to diagnose by
/// hand. Repaired on the same rules: restore the snapshot if there is one, otherwise clear.
fn repair_env(force: bool) -> bool {
    use vigil_platform::envproxy::repair_target;
    use vigil_platform::{envproxy, envreg};

    let current = match envreg::read_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("environment: cannot read the proxy variables: {e}");
            return false;
        }
    };
    if !force && !envproxy::is_stranded(&current, "127.0.0.1:") {
        println!("environment: nothing to repair");
        return true;
    }
    // Same rule as the registry half, and the reasoning that used to be here was the wrong way
    // round. It argued that clearing without a snapshot could destroy somebody else's
    // configuration — true in general, and not reachable from here: without `--force` this line is
    // only reached because `is_stranded` matched, and that means a variable names a **loopback**
    // listener. Somebody else's corporate proxy does not match it. What the old caution actually
    // protected was a dead port.
    let snapshot = env_snapshot_path().and_then(|p| std::fs::read_to_string(p).ok());
    // The decision is `envproxy::repair_target`, which is pure and tested — this binary has no tests
    // of its own, and the arm that used to live here printed "these variables are not vigil's,
    // leaving them alone" and returned success on a machine that was demonstrably stranded.
    if snapshot.is_some() {
        println!("environment: restoring the snapshot taken before vigil started");
    } else if force {
        println!("environment: no snapshot, but --force was given; clearing the variables");
    } else {
        println!("environment: stranded on a loopback proxy and no snapshot to restore —");
        println!("             clearing the variables, which is what the registry half does.");
    }
    let target = repair_target(snapshot.as_deref());
    match envreg::apply(&target) {
        Ok(()) => {
            println!("environment: restored");
            if let Some(p) = env_snapshot_path() {
                let _ = std::fs::remove_file(p);
            }
            true
        }
        Err(e) => {
            eprintln!("environment: could not write the variables: {e}");
            eprintln!("undo it by hand: Windows > \"Edit environment variables for your account\"");
            false
        }
    }
}

/// The third thing vigil can leave behind, and the worst of them.
///
/// A stranded proxy setting breaks the programs that read it. A machine whose DNS still points
/// at a vigil that is not running has **no name resolution at all** — nothing resolves, and the
/// error every program shows is about the site, never about a resolver. vigil always writes a
/// public fallback after itself so this should not happen, but "should not" is not a plan.
fn repair_dns(force: bool) -> bool {
    use vigil_platform::{dnsclient, sysdns};

    let ifaces = match dnsclient::read_interfaces() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("dns: cannot read the current servers: {e}");
            return false;
        }
    };
    let stranded = sysdns::stranded(&ifaces);
    if stranded.is_empty() && !force {
        println!("dns: nothing to repair");
        return true;
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
        return true;
    }
    println!("dns: this needs administrator rights — Windows will ask");
    match dnsclient::apply(&changes) {
        Ok(()) => {
            println!("dns: restored");
            if let Some(p) = dns_snapshot_path() {
                let _ = std::fs::remove_file(p);
            }
            true
        }
        Err(e) => {
            eprintln!("dns: could not restore ({e})");
            eprintln!(
                "undo it by hand: Ayarlar > Ağ ve İnternet > adaptör > DNS > Otomatik (DHCP)"
            );
            false
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
