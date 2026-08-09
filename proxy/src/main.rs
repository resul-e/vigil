//! vigil — a local proxy that keeps blocked sites reachable by splitting the TLS
//! ClientHello across TCP segments.
//!
//! It answers SOCKS5, SOCKS4/4a and HTTP `CONNECT` on the same port. That is not generosity:
//! Windows' system proxy setting cannot name SOCKS5 at all, so a SOCKS5-only listener is
//! unreachable from the setting the tool itself installs.
//!
//! Usage:  vigil [listen-addr] [--split | --passthrough | --strategy SPEC | --auto]
//!                [--cache PATH] [--panel ADDR | --no-panel]
//!
//! SPEC is the textual strategy form, e.g. `split:1`, `tlsrec:64+split:1`, `split:midsld@15`.

use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

use vigil_platform::{engage, instance, paths, process, registry, shutdown, sysproxy};

use vigil_core::strategy::Strategy;
use vigil_proxy::ui::{self, PanelState};
use vigil_proxy::{Config, Mode, Server};

fn main() -> ExitCode {
    let mut cfg = Config::default();
    let mut strategy = Strategy::passthrough();
    let mut auto = false;
    // Whether the caller said anything at all about what to do with the first flight.
    //
    // Nobody who double-clicks this wants a proxy that carries their traffic and transforms
    // none of it, but that is what a bare `vigil.exe` did until 2026-08-06: it printed
    // `strategy=none`, accepted connections from applications still pointing at port 1080 from
    // a previous run, and passed every blocked ClientHello straight through. Working silently
    // is one thing; *not* working silently is another.
    let mut chose_mode = false;
    let mut panel: Option<String> = Some("127.0.0.1:1081".into());
    let mut set_proxy = false;
    let mut system_dns = false;
    let mut resolvers: Vec<std::net::SocketAddr> = Vec::new();
    // Off by default. Serving DNS for the whole machine is a bigger promise than proxying for
    // the programs that opted in, and it is only useful once something points at it.
    let mut dns_listen: Option<String> = None;
    // Pointing the machine's own resolver at us. Separate from `--dns` on purpose: serving is
    // harmless, and telling Windows to depend on us is not.
    let mut set_dns = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0usize;

    // Kept so the periodic status line can show the DNS half too; `None` when --dns was
    // never asked for, or the port was held.
    let mut dns_stats: Option<std::sync::Arc<vigil_proxy::dnsserver::DnsStats>> = None;
    while i < args.len() {
        let arg = args[i].clone();
        i += 1;
        match arg.as_str() {
            "--split" => {
                strategy = Strategy::measured_default();
                chose_mode = true;
            }
            "--auto" => {
                auto = true;
                chose_mode = true;
            }
            "--no-panel" => panel = None,
            "--set-proxy" => set_proxy = true,
            "--system-dns" => system_dns = true,
            "--resolver" => {
                let Some(a) = args.get(i) else {
                    eprintln!("--resolver needs a HOST:PORT");
                    return ExitCode::from(2);
                };
                i += 1;
                match a.parse() {
                    Ok(x) => resolvers.push(x),
                    Err(_) => {
                        eprintln!("--resolver {a:?} is not a HOST:PORT");
                        return ExitCode::from(2);
                    }
                }
            }
            "--panel" => {
                let Some(a) = args.get(i) else {
                    eprintln!("--panel needs an ADDR");
                    return ExitCode::from(2);
                };
                i += 1;
                panel = Some(a.clone());
            }
            "--cache" => {
                let Some(p) = args.get(i) else {
                    eprintln!("--cache needs a PATH");
                    return ExitCode::from(2);
                };
                i += 1;
                cfg.cache_path = Some(p.into());
            }
            // Exposed so the retry can be measured against itself on the same line, in the
            // same minute. A knob whose only justification is a measurement nobody can run is
            // a knob that will be believed instead of checked.
            "--first-flight-attempts" => {
                let Some(n) = args.get(i).and_then(|s| s.parse::<usize>().ok()) else {
                    eprintln!("--first-flight-attempts needs a number (1 disables retrying)");
                    return ExitCode::from(2);
                };
                i += 1;
                cfg.first_flight_attempts = n.max(1);
            }
            // The machine's own resolver, for the programs that never speak to the proxy.
            "--dns" => {
                let a = args
                    .get(i)
                    .filter(|v| !v.starts_with("--"))
                    .cloned()
                    .unwrap_or_else(|| "127.0.0.1:53".to_string());
                if args.get(i).is_some_and(|v| !v.starts_with("--")) {
                    i += 1;
                }
                dns_listen = Some(a);
            }
            "--set-dns" => set_dns = true,
            "--passthrough" => {
                strategy = Strategy::passthrough();
                chose_mode = true;
            }
            "--strategy" => {
                let Some(spec) = args.get(i) else {
                    eprintln!("--strategy needs a SPEC, e.g. tlsrec:64+split:1");
                    return ExitCode::from(2);
                };
                i += 1;
                match Strategy::parse(spec) {
                    Ok(s) => {
                        strategy = s;
                        chose_mode = true;
                    }
                    Err(e) => {
                        eprintln!("bad --strategy {spec:?}: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: vigil [listen-addr] [--split | --passthrough | --strategy SPEC \
                     | --auto] [--cache PATH] [--set-proxy] \
                     [--resolver HOST:PORT]... [--system-dns] \
                     [--first-flight-attempts N] [--dns [ADDR]] [--set-dns]"
                );
                return ExitCode::SUCCESS;
            }
            other => match other.parse() {
                Ok(a) => cfg.listen = a,
                Err(_) => {
                    eprintln!("not an address and not a known flag: {other}");
                    return ExitCode::from(2);
                }
            },
        }
    }
    cfg.strategy = strategy.clone();
    cfg.mode = decide_mode(auto, chose_mode, &strategy);
    // The binary people reach for when they mean the tray application — measured by somebody
    // reaching for it and getting a relay that transformed nothing.
    // ASCII on purpose: a Windows console is not UTF-8 by default, and the rest of this
    // binary's output is English. `vigil-scan` is the Turkish-facing one, and it is read from
    // a file rather than a console.
    eprintln!("(desktop version: vigil-app.exe - tray icon, menu, one click on/off)");
    if !chose_mode {
        eprintln!(
            "no mode given, so: --auto (learns per host). Use --passthrough for a plain relay."
        );
    }

    let resolver = if system_dns {
        vigil_proxy::resolver::Resolver::system_only()
    } else if resolvers.is_empty() {
        vigil_proxy::resolver::Resolver::default()
    } else {
        vigil_proxy::resolver::Resolver::new(resolvers, true)
    };
    let server = Server::new(cfg.clone()).with_resolver(resolver);

    // The machine's resolver, if asked for. Its own thread: a DNS server that stops answering
    // because the proxy is busy would take name resolution down for everything on the machine,
    // and this is exactly the failure the tool exists to prevent.
    if let Some(a) = &dns_listen {
        match a.parse::<std::net::SocketAddr>() {
            Err(_) => {
                eprintln!("--dns {a:?} is not a HOST:PORT");
                return ExitCode::from(2);
            }
            Ok(addr) => match vigil_proxy::dnsserver::DnsServer::bind(addr) {
                Ok(sock) => {
                    let actual = sock.local_addr().unwrap_or(addr);
                    let dns = std::sync::Arc::new(vigil_proxy::dnsserver::DnsServer::new(
                        std::sync::Arc::clone(&server.resolver),
                    ));
                    eprintln!("  dns: {actual} (yalnız loopback)");
                    if actual.port() == 53 {
                        eprintln!(
                            "    sistemi buna yöneltmek için (yönetici):                              netsh interface ip set dns name=\"Wi-Fi\" static 127.0.0.1"
                        );
                    }
                    dns_stats = Some(std::sync::Arc::clone(&dns.stats));
                    std::thread::spawn(move || dns.serve(sock));
                    if set_dns {
                        engage_system_dns(true);
                    }
                }
                Err(e) => eprintln!("  dns unavailable on {addr}: {e}"),
            },
        }
    }
    let listener = match server.bind() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {}: {e}", cfg.listen);
            return ExitCode::from(1);
        }
    };
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    // Read off the mode the engine will actually use, never off the flag that suggested it.
    // Those two disagreed for exactly as long as `--auto` was inferred rather than typed, and
    // the line on screen said `strategy=none` while the proxy was calibrating per host.
    match &cfg.mode {
        Mode::Auto => eprintln!(
            "vigil listening on {actual} (socks5, socks4, http-connect)  \
             strategy=auto (learning per host)"
        ),
        Mode::Fixed(s) => {
            eprintln!("vigil listening on {actual} (socks5, socks4, http-connect)  strategy={s}")
        }
    }
    if let Some(p) = &cfg.cache_path {
        eprintln!("  cache: {}", p.display());
    }

    // The control panel. Loopback only: it can change how traffic is handled.
    if let Some(addr) = &panel {
        match addr
            .parse()
            .map_err(|_| ())
            .and_then(
                |a: std::net::SocketAddr| {
                    if a.ip().is_loopback() {
                        Ok(a)
                    } else {
                        Err(())
                    }
                },
            ) {
            Err(()) => {
                eprintln!("--panel must be a loopback address, got {addr:?}");
                return ExitCode::from(2);
            }
            Ok(a) => match bind_panel(a) {
                Ok(l) => {
                    let panel_addr = l.local_addr().unwrap_or(a);
                    eprintln!("  panel: http://{panel_addr}");
                    let state = std::sync::Arc::new(PanelState {
                        // The proxy's address, not the panel's. This field is what a user
                        // reads to point a client at vigil, so naming the panel here sends
                        // them to a port that speaks HTTP and no proxy protocol at all.
                        listen: actual.to_string(),
                        mode: cfg.mode.clone(),
                        fixed: strategy.clone(),
                        stats: std::sync::Arc::clone(&server.stats),
                        cache: std::sync::Arc::clone(&server.cache),
                        rules: cfg.rules.clone(),
                        cache_path: cfg.cache_path.clone(),
                    });
                    std::thread::spawn(move || ui::serve(l, state));
                }
                Err(e) => eprintln!("  panel unavailable near {a}: {e}"),
            },
        }
    }

    // --- the system proxy, opt-in ---
    // A tool that silently rewires the machine's networking on first run is a tool nobody
    // trusts twice, so this only happens when asked for.
    let mut _lock = None;
    if set_proxy {
        // Two vigils fighting over one registry value is a machine with no internet: whichever
        // exits last writes its idea of "before" over the other's.
        if let Some(p) = paths::lock() {
            match instance::InstanceLock::take(&p, process::is_alive) {
                Ok(Some(l)) => _lock = Some(l),
                Ok(None) => {
                    eprintln!("another vigil already owns the system proxy — not engaging");
                    return ExitCode::from(1);
                }
                Err(e) => eprintln!("instance lock unavailable ({e}); continuing without it"),
            }
        }
        let addr = actual.to_string();
        if engage_system_proxy(&addr) {
            let _ = ENGAGED_ON.set(addr);
            if !shutdown::on_stop(disengage) {
                eprintln!("  note: no console handler here — use vigil-repair if this is killed");
            }
        }
    }

    let stats = std::sync::Arc::clone(&server.stats);
    let dns_line = dns_stats.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
        eprintln!(
            "accepted={} completed={} transformed={} handshake_err={} upstream_err={} refused={}",
            stats.accepted.load(Ordering::Relaxed),
            stats.completed.load(Ordering::Relaxed),
            stats.transformed.load(Ordering::Relaxed),
            stats.handshake_errors.load(Ordering::Relaxed),
            stats.upstream_errors.load(Ordering::Relaxed),
            stats.refused_over_capacity.load(Ordering::Relaxed),
        );
        eprintln!(
            "cache_hits={} calibrated={} first_flight_retries={}",
            stats.cache_hits.load(Ordering::Relaxed),
            stats.calibrated.load(Ordering::Relaxed),
            stats.first_flight_retries.load(Ordering::Relaxed),
        );
        // The DNS half, when it is running. `recv_errors` climbing while `answered` stands still
        // is the signature of the failure that used to kill this server silently — it is printed
        // for that reason, not for completeness.
        if let Some(d) = &dns_line {
            eprintln!("{}", d.line());
        }
        // Worth its own line: if every client is arriving on a dialect we did not expect,
        // that is the difference between "the tool is running" and "the tool is being used".
        eprintln!(
            "by_socks5={} by_socks4={} by_http_connect={} unrecognised={} dns_failures={}",
            stats.by_socks5.load(Ordering::Relaxed),
            stats.by_socks4.load(Ordering::Relaxed),
            stats.by_http_connect.load(Ordering::Relaxed),
            stats.unrecognised.load(Ordering::Relaxed),
            stats.dns_failures.load(Ordering::Relaxed),
        );
    });

    server.serve(listener);
    // Reached only if the listener dies; the ordinary exit path is the console handler.
    disengage();
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------------------
// Turning the system proxy on for the duration of the run.
//
// Opt-in, because a tool that silently rewires the machine's networking the first time it is
// run is a tool nobody trusts twice. Every decision about *whether* to touch the setting is
// in `vigil_platform::engage` and tested there; what is left here is file and registry I/O.
// ---------------------------------------------------------------------------------------

/// The listen address the cleanup hook needs. A console control handler is a plain `fn`, so
/// it cannot capture.
static ENGAGED_ON: OnceLock<String> = OnceLock::new();
/// Whether we pointed the machine's resolver at ourselves, so the exit path knows to undo it.
static DNS_ENGAGED: OnceLock<bool> = OnceLock::new();

fn read_snapshot() -> Option<sysproxy::ProxySettings> {
    let p = paths::snapshot()?;
    let text = std::fs::read_to_string(p).ok()?;
    sysproxy::snapshot_from_text(&text)
}

/// Put the system proxy back. Safe to call more than once.
fn disengage() {
    // The machine's resolver first: a machine that keeps asking a vigil which has already put
    // the proxy back is one that cannot resolve anything at all.
    if DNS_ENGAGED.get().copied().unwrap_or(false) {
        engage_system_dns(false);
    }
    let Some(listen) = ENGAGED_ON.get() else {
        return;
    };
    // The environment variables come off first: a client that reads them must never be sent to
    // a proxy after the registry has already stopped naming one.
    engage_env_proxy(false, listen);
    let Ok(current) = registry::read_current() else {
        return;
    };
    match engage::stop(&current, read_snapshot().as_ref(), listen) {
        engage::Stop::Restore(s) => {
            // The snapshot is deleted only after the restore actually succeeded. Deleting it
            // regardless would turn a half-finished shutdown — which is the likely kind, since
            // a console handler runs while the process is being torn down — into a machine
            // that is still pointing at us with no record of what came before. `vigil-repair`
            // could then only disable the proxy, never put the user's own settings back.
            match registry::apply(&s) {
                Ok(()) => {
                    eprintln!("system proxy restored: {s}");
                    if let Some(p) = paths::snapshot() {
                        let _ = std::fs::remove_file(p);
                    }
                }
                Err(e) => eprintln!(
                    "could not restore the system proxy ({e}) — \
                     snapshot kept; run vigil-repair to fix it"
                ),
            }
        }
        engage::Stop::NotOurs => {
            eprintln!("system proxy is no longer ours; leaving it as the user set it");
        }
    }
}

/// Bind the control panel, stepping past ports somebody else already holds.
///
/// On this machine `wslrelay.exe` takes 1081 often enough that the documented workaround was
/// "pass `--panel 127.0.0.1:1091`" — a note in a file nobody reads at the moment they need it.
/// Ten ports is more than enough, and the address actually used is printed either way.
fn bind_panel(want: std::net::SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let mut last = None;
    for step in 0..10u16 {
        let mut a = want;
        a.set_port(want.port().saturating_add(step));
        match ui::bind(a) {
            Ok(l) => return Ok(l),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no port to bind")))
}

/// What to do with the first flight, given the flags.
///
/// Pure, and separate, because getting it wrong is silent: the failure mode is a proxy that
/// works perfectly and helps with nothing.
fn decide_mode(auto: bool, chose: bool, fixed: &Strategy) -> Mode {
    if auto || !chose {
        // Nothing chosen means the useful default, not the inert one.
        Mode::Auto
    } else {
        Mode::Fixed(fixed.clone())
    }
}

/// Point Windows' own resolver at us, and put it back.
///
/// This is the only thing vigil does that needs administrator rights, and it asks for them out
/// loud: Windows shows its consent dialog. It is also the one change that can take a machine's
/// name resolution down entirely, so it writes a public fallback after itself and snapshots
/// what was there first — and `vigil-repair` can undo it without vigil running.
fn engage_system_dns(on: bool) {
    use vigil_platform::{dnsclient, sysdns};

    let ifaces = match dnsclient::read_interfaces() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("system dns: cannot read the current servers: {e}");
            return;
        }
    };
    let path = paths::dns_snapshot();
    if on {
        let targets = sysdns::targets(&ifaces);
        if targets.is_empty() {
            eprintln!("system dns: already pointing at us, or no interface carries DNS");
            return;
        }
        // Snapshot before the change, and refuse to make it if there is nowhere to record what
        // was there. Every other order leaves a machine that repair can only guess about.
        let snap =
            sysdns::snapshot_to_text(&targets.iter().map(|i| (*i).clone()).collect::<Vec<_>>());
        match &path {
            Some(p) => {
                if let Some(dir) = p.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Err(e) = std::fs::write(p, &snap) {
                    eprintln!("system dns: refusing to engage, cannot save a snapshot: {e}");
                    return;
                }
            }
            None => {
                eprintln!("system dns: refusing to engage, nowhere to save a snapshot");
                return;
            }
        }
        let changes: Vec<(u32, Option<Vec<String>>)> = targets
            .iter()
            .map(|i| (i.index, Some(sysdns::ours())))
            .collect();
        eprintln!("system dns: asking for administrator rights (Windows will prompt)");
        let outcome = dnsclient::apply(&changes);
        // **Read it back rather than believing the return value.** A batch can now fail as a
        // whole while some of its interfaces landed — one stale index is enough — and a machine
        // that is half engaged must still be put back on the way out. `DNS_ENGAGED` is what the
        // exit path consults, so it is set from what Windows says, not from what `apply` said.
        let engaged = dnsclient::read_interfaces()
            .map(|now| !sysdns::stranded(&now).is_empty())
            .unwrap_or(outcome.is_ok());
        if engaged {
            DNS_ENGAGED.set(true).ok();
        } else if outcome.is_err() {
            // Nothing landed, so the record of what was there must not stay behind claiming
            // otherwise. Only when nothing landed: a half-applied batch needs its snapshot.
            if let Some(p) = &path {
                let _ = std::fs::remove_file(p);
            }
        }
        match outcome {
            Ok(()) => {
                for i in &targets {
                    eprintln!("system dns: {} -> {}", i.alias, sysdns::ours().join(", "));
                }
            }
            Err(e) => eprintln!(
                "system dns: {e}{}",
                if engaged {
                    " — but some interfaces did change; they will be put back on exit"
                } else {
                    ""
                }
            ),
        }
    } else {
        let stranded = sysdns::stranded(&ifaces);
        if stranded.is_empty() {
            return;
        }
        let snapshot: Vec<sysdns::Interface> = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| sysdns::parse(&t))
            .unwrap_or_default();
        let changes: Vec<(u32, Option<Vec<String>>)> = stranded
            .iter()
            .map(|i| {
                let back = snapshot
                    .iter()
                    .find(|s| s.index == i.index)
                    .and_then(sysdns::restore_value);
                (i.index, back)
            })
            .collect();
        match dnsclient::apply(&changes) {
            Ok(()) => {
                eprintln!("system dns: restored");
                // The snapshot is the only record of what was there, so it goes only when
                // nothing is left pointing at us — checked, not assumed.
                let clean = dnsclient::read_interfaces()
                    .map(|now| sysdns::stranded(&now).is_empty())
                    .unwrap_or(true);
                if clean {
                    if let Some(p) = &path {
                        let _ = std::fs::remove_file(p);
                    }
                } else {
                    eprintln!(
                        "system dns: something still points at us; keeping the snapshot, run vigil-repair"
                    );
                }
            }
            Err(e) => eprintln!("system dns: could not restore ({e}); run vigil-repair"),
        }
    }
}

/// The curl-convention environment variables, which reach the applications the registry
/// setting does not. Measured 2026-08-05: the Roblox client ignores the registry entirely and
/// honours these. Failure here is reported and not fatal — the registry half is what the
/// engaged/stranded state is read from.
fn engage_env_proxy(on: bool, listen: &str) {
    use vigil_platform::{envproxy, envreg};

    let current = match envreg::read_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("environment proxy: cannot read the current variables: {e}");
            return;
        }
    };
    let snapshot_path = paths::env_snapshot();
    if on {
        match envproxy::start(&current, listen) {
            envproxy::Start::AlreadyEngaged => {}
            envproxy::Start::Occupied => {
                eprintln!("environment proxy: HTTP_PROXY is set by something else; left alone");
            }
            envproxy::Start::Engage { apply, snapshot } => {
                if let Some(p) = &snapshot_path {
                    if let Some(dir) = p.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    if let Err(e) = std::fs::write(p, envproxy::snapshot_to_text(&snapshot)) {
                        eprintln!("environment proxy: no snapshot ({e}); not touching it");
                        return;
                    }
                }
                match envreg::apply(&apply) {
                    Ok(()) => eprintln!(
                        "environment proxy set: HTTP_PROXY/HTTPS_PROXY/ALL_PROXY -> {}",
                        envproxy::url_for(listen)
                    ),
                    Err(e) => eprintln!("environment proxy: {e}"),
                }
            }
        }
    } else {
        let snap = snapshot_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| envproxy::snapshot_from_text(&t));
        match envproxy::stop(&current, snap.as_ref(), listen) {
            envproxy::Stop::NotOurs => {
                eprintln!("environment proxy is no longer ours; leaving it as the user set it");
            }
            envproxy::Stop::Restore(s) => match envreg::apply(&s) {
                Ok(()) => {
                    if let Some(p) = &snapshot_path {
                        let _ = std::fs::remove_file(p);
                    }
                }
                Err(e) => eprintln!("environment proxy: could not restore ({e}); run vigil-repair"),
            },
        }
    }
}

/// Point Windows at us. Returns whether we are now engaged.
fn engage_system_proxy(listen: &str) -> bool {
    let current = match registry::read_current() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("--set-proxy: cannot read the current settings: {e}");
            return false;
        }
    };
    match engage::start(&current, listen) {
        engage::Start::AlreadyEngaged => {
            eprintln!("system proxy already points here; leaving the saved snapshot alone");
            true
        }
        engage::Start::Engage { apply, snapshot } => {
            // The snapshot is written *before* the registry is changed. A crash in the other
            // order leaves a machine pointing at us with no record of what was there before,
            // and then even vigil-repair can only disable rather than restore.
            match paths::snapshot() {
                Some(p) => {
                    if let Some(dir) = p.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    if let Err(e) = std::fs::write(&p, sysproxy::snapshot_to_text(&snapshot)) {
                        eprintln!("--set-proxy: refusing to engage, cannot save a snapshot: {e}");
                        return false;
                    }
                }
                None => {
                    eprintln!("--set-proxy: refusing to engage, nowhere to save a snapshot");
                    return false;
                }
            }
            match registry::apply(&apply) {
                Ok(()) => {
                    eprintln!("system proxy set: {apply}");
                    eprintln!("  previous settings saved; restored on exit, or by vigil-repair");
                    engage_env_proxy(true, listen);
                    true
                }
                Err(e) => {
                    eprintln!("--set-proxy: {e}");
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bare double-click. It used to be a relay that transformed nothing, which is the
    /// worst of the available behaviours: it looks like it is working.
    #[test]
    fn no_flags_means_auto_not_passthrough() {
        assert_eq!(
            decide_mode(false, false, &Strategy::passthrough()),
            Mode::Auto
        );
    }

    /// But an explicit `--passthrough` is still exactly that: it is how the browser A/B and
    /// the throughput comparison are measured, and silently upgrading it would invalidate
    /// every one of those runs.
    #[test]
    fn an_explicit_choice_is_honoured() {
        assert_eq!(
            decide_mode(false, true, &Strategy::passthrough()),
            Mode::Fixed(Strategy::passthrough())
        );
        let s = Strategy::measured_default();
        assert_eq!(decide_mode(false, true, &s), Mode::Fixed(s.clone()));
        assert_eq!(decide_mode(true, true, &s), Mode::Auto);
    }
}
