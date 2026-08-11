//! `vigil-scan` — characterise what a DPI on this line actually does.
//!
//! Work in progress: the developer-facing `cell` mode exists first so the instrument can be
//! validated against a network whose answers are already known, before it is pointed at one
//! whose answers are not.

mod appphase;
mod apps;
mod attempt;
mod dns;
mod hostdiag;
mod net;
mod observe;
mod plan;
mod report;

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use vigil_core::clock;
use vigil_core::strategy::Strategy;
use vigil_core::{Tally, MIN_TRIALS};

fn nonce_for(trial: usize) -> [u8; 32] {
    // Deterministic but different per trial: enough that no two flights are byte-identical,
    // while keeping a run reproducible. No clock, no randomness.
    let mut n = [0u8; 32];
    for (i, b) in n.iter_mut().enumerate() {
        *b = (trial as u8)
            .wrapping_mul(31)
            .wrapping_add(i as u8)
            .wrapping_add(0x5A);
    }
    n
}

fn resolve(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// What the full run should do. One tool, two halves: the first changes nothing, the second
/// engages the proxy on purpose because that is the thing it measures.
#[derive(Debug, Clone, Copy)]
struct Options {
    apps: bool,
    app_wait: u64,
    port: u16,
    /// Seconds to watch the whole machine with the proxy engaged, 0 to skip.
    observe: u64,
    /// Whether `--observe` was given explicitly, which is what makes `--no-apps` inert again.
    ///
    /// The watch window's default went from 0 to 180 so that the measurement that decides whether
    /// this project writes a driver would actually run — a default that needs an argument is a
    /// default that never runs. But `--no-apps` is documented in four places as the half that
    /// changes nothing, and observing engages the system proxy, so from that day `--no-apps` quietly
    /// engaged for three minutes while the banner promised it did not. Both promises are kept by
    /// distinguishing "the default happened to be 180" from "the operator asked for a window".
    observe_was_asked_for: bool,
    /// Wait for Enter before exiting. On by default, because the person this tool is aimed at
    /// **double-clicks it from Explorer** — and a console that closes on exit takes the report's
    /// filename with it.
    pause: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            apps: true,
            // Was 45, raised 2026-08-08. A volunteer's Discord ended the window with the same
            // process count as the control arm, and 45 s after a forced kill is not clearly
            // enough for a Squirrel launcher to hand off to the application at all — so the
            // measurement could not distinguish "did not start" from "not finished starting".
            // Costs about three extra minutes and removes a confound.
            app_wait: 90,
            port: 1085,
            // On by default since 2026-08-09. It was off, on the reasoning that watching is only
            // worth anything while somebody is using the computer — true, and it made the one
            // measurement that decides whether v2 gets built reachable only by typing a flag. The
            // volunteers who have the interesting networks do not use a terminal; they run the
            // `.exe`. A default that needs an argument to be useful is a default that never runs.
            observe: 180,
            observe_was_asked_for: false,
            pause: true,
        }
    }
}

/// Where the report goes: **beside the executable**, not in the working directory.
///
/// A volunteer double-clicks this from Explorer, and Explorer's working directory is not reliably
/// the folder the `.exe` sits in — running it straight out of a zip makes it a temporary folder,
/// where the report is written and then lost with the temp directory. The person then has nothing to
/// send and no way to know why.
fn report_path(name: &str) -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .unwrap_or_else(|| std::path::PathBuf::from(name))
}

/// Open the folder with the report selected, so finding it needs no navigating.
///
/// Best effort and deliberately unchecked: `explorer.exe /select` exits non-zero even when it works,
/// and a testbench that reported failure because a file manager was rude would be worse than one
/// that stays quiet.
#[cfg(windows)]
fn reveal(path: &std::path::Path) {
    let _ = std::process::Command::new("explorer.exe")
        .arg(format!("/select,{}", path.display()))
        .spawn();
}
#[cfg(not(windows))]
fn reveal(_path: &std::path::Path) {}

/// Hold the console open until somebody presses Enter.
///
/// The whole reason this exists: everything this tool prints at the end — where the report is, what
/// to do with it, whether the controls passed — is printed into a window that Windows closes the
/// instant the process exits. For anyone who did not start it from a terminal, that is the same as
/// printing nothing.
fn wait_for_enter() {
    use std::io::Write;
    eprintln!();
    eprint!("Kapatmak için Enter'a bas. / Press Enter to close. ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// Keep the console open if this panics, so the message can be read and sent.
fn hold_window_on_panic() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        eprintln!();
        eprintln!("Beklenmeyen bir hata oldu. Yukarıdaki satırları Resul'e gönder.");
        wait_for_enter();
    }));
}

/// The value after a flag, or `None` without consuming anything.
///
/// `None` when the token is missing **or looks like another flag**. Without the second half,
/// `vigil-scan --app-wait --no-apps` swallowed `--no-apps` as the value of `--app-wait`: the parse
/// failed, the fallback kept the old value, and the run engaged the machine's proxy settings for a
/// command whose whole promise is that it changes nothing. `--observe` is worse still, because its
/// failed parse also sets `observe_was_asked_for`, which is exactly what disarms the guard below.
fn value<'a>(args: &'a [String], i: &mut usize) -> Option<&'a str> {
    match args.get(*i + 1) {
        Some(v) if !v.starts_with("--") => {
            *i += 1;
            Some(v.as_str())
        }
        _ => None,
    }
}

/// A numeric flag value.
///
/// `Ok(None)` when the flag was given no value at all — the flag keeps its default and the next
/// token stays available to be matched as the flag it is. `Err` when a value *was* given and is not
/// a number: on a measurement tool a mistyped value must be refused, never quietly replaced by a
/// fallback that then gets reported as though it had been asked for.
fn num<T: std::str::FromStr>(args: &[String], i: &mut usize, flag: &str) -> Result<Option<T>, u8> {
    match value(args, i) {
        None => {
            eprintln!("{flag} bir değer istiyor; yok sayıldı");
            Ok(None)
        }
        Some(v) => v.parse().map(Some).map_err(|_| {
            eprintln!("{flag}: '{v}' bir sayı değil");
            2
        }),
    }
}

/// Turn a command line into [`Options`].
///
/// Split out of `main` so the one rule this binary promises in four places — that `--no-apps`
/// changes nothing — is a testable function rather than three lines inside a match arm. Deleting
/// those three lines left all 836 tests green while `--no-apps` went back to engaging Windows'
/// system proxy and `HTTPS_PROXY`/`ALL_PROXY` for 180 seconds under a banner reading
/// "(uygulama testi kapalı)".
fn options_from(args: &[String]) -> Result<Options, u8> {
    let mut o = Options::default();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--no-apps" => o.apps = false,
            "--app-wait" => {
                if let Some(n) = num(args, &mut i, "--app-wait")? {
                    o.app_wait = n;
                }
            }
            "--port" => {
                if let Some(n) = num(args, &mut i, "--port")? {
                    o.port = n;
                }
            }
            "--observe" => {
                // **Both fields together, or neither.** `observe_was_asked_for` used to be set
                // unconditionally, so `--observe` with no value — or followed by another flag —
                // disarmed the `--no-apps` guard below while the value fell back to 120. The flag
                // that means "change nothing" then engaged the system proxy for two minutes.
                if let Some(n) = num(args, &mut i, "--observe")? {
                    o.observe = n;
                    o.observe_was_asked_for = true;
                }
            }
            "--no-pause" => o.pause = false,
            other => {
                eprintln!("bilinmeyen seçenek: {other}");
                return Err(2);
            }
        }
        i += 1;
    }
    // `--no-apps` means "change nothing", in the banner, the usage line, `Cargo.toml` and
    // `CLAUDE.md`. The watch window engages the system proxy, so it cannot be left on by
    // default here — but an operator who asks for one by name still gets it.
    if !o.apps && !o.observe_was_asked_for {
        o.observe = 0;
    }
    Ok(o)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("cell") => cell(&args[1..]),
        Some("dns") => dns_report(),
        Some("teshis") | Some("diag") => diag_report(),
        None => {
            // The double-click path. Anything that goes wrong from here is printed into a window
            // Windows closes the moment this process exits, so a panic would reach the volunteer as
            // "it flashed and nothing happened" — the least reportable bug there is.
            hold_window_on_panic();
            run(Options::default())
        }
        Some(a) if a.starts_with("--") => match options_from(&args) {
            Ok(o) => run(o),
            Err(code) => std::process::ExitCode::from(code),
        },
        _ => {
            eprintln!("usage: vigil-scan                 # tam tarama / full scan");
            eprintln!(
                "       vigil-scan --no-apps       # sadece ağ ölçümü, hiçbir ayara dokunmaz"
            );
            eprintln!("       vigil-scan --observe 300    # 5 dk boyunca hangi programlar vigil'i kullanıyor");
            eprintln!("       vigil-scan --observe 0      # makineyi hiç izleme");
            eprintln!("       vigil-scan --no-pause       # bitince Enter bekleme (betik için)");
            eprintln!("       vigil-scan --app-wait 60 --port 1090");
            eprintln!("       vigil-scan dns    # sadece DNS bütünlüğü / DNS integrity only");
            eprintln!(
                "       vigil-scan teshis # bu makinenin proxy ayarı geçerli mi (sadece okur)"
            );
            eprintln!("       vigil-scan cell HOST STRATEGY [TRIALS] [CH_LEN] [--to ADDR] [--flight FILE]");
            std::process::ExitCode::from(2)
        }
    }
}

/// Run a single (host, strategy, size) cell N times and print the tally.
///
/// `--to ADDR` sends the chosen SNI to an address of the caller's choosing. That is the
/// control that separates "this hostname is blocked" from "this address is blocked": the same
/// IP, asked for a permitted name, must answer.
fn cell(args: &[String]) -> std::process::ExitCode {
    let positional: Vec<&String> = args
        .iter()
        .take_while(|a| !a.starts_with("--"))
        .collect::<Vec<_>>();
    let to: Option<String> = args
        .iter()
        .position(|a| a == "--to")
        .and_then(|i| args.get(i + 1).cloned());
    // Loud on failure, deliberately. An unreadable capture that silently fell back to a
    // synthetic hello would produce a plausible-looking table of the wrong experiment.
    let ttl: Option<u32> = args
        .iter()
        .position(|a| a == "--ttl")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok());
    let flight: Option<Vec<u8>> = match args.iter().position(|a| a == "--flight") {
        None => None,
        Some(i) => match args.get(i + 1) {
            None => {
                eprintln!("--flight needs a PATH");
                return std::process::ExitCode::from(2);
            }
            Some(path) => match std::fs::read(path) {
                Ok(b) if !b.is_empty() => Some(b),
                Ok(_) => {
                    eprintln!("--flight {path}: file is empty");
                    return std::process::ExitCode::from(2);
                }
                Err(e) => {
                    eprintln!("--flight {path}: {e}");
                    return std::process::ExitCode::from(2);
                }
            },
        },
    };

    let Some(host) = positional.first().map(|s| s.as_str()) else {
        eprintln!("cell needs a HOST");
        return std::process::ExitCode::from(2);
    };
    let args = &positional[1..];
    let spec = args.first().map(|s| s.as_str()).unwrap_or("none");
    let strategy = match Strategy::parse(spec) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bad strategy {spec:?}: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let trials: usize = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(MIN_TRIALS);
    let ch_len: Option<usize> = args.get(2).and_then(|s| s.parse().ok());

    // Refuse a length this hostname cannot reach, here, before any trial runs. The tally would
    // otherwise fill with build failures and — until the guard in `Tally::verdict` — print
    // them as `blocked`. Loud and early is better: the operator typed a number and wants to
    // know it was impossible, not to read it back as a finding.
    if let Some(len) = ch_len {
        match vigil_core::synth::min_len(host) {
            Ok(min) if len < min => {
                eprintln!(
                    "{host}: a {len} B ClientHello cannot be built — the smallest for this \
                     hostname is {min} B. To measure a smaller real client, capture its first \
                     flight with `wirelog --dump` and pass it with --flight."
                );
                return std::process::ExitCode::from(2);
            }
            Err(e) => {
                eprintln!("{host}: {e}");
                return std::process::ExitCode::from(2);
            }
            _ => {}
        }
        if flight.is_some() {
            eprintln!("--flight supplies the bytes; a CH_LEN cannot be requested as well");
            return std::process::ExitCode::from(2);
        }
    }

    let addr: SocketAddr = match &to {
        Some(t) => {
            let t = if t.contains(':') {
                t.clone()
            } else {
                format!("{t}:443")
            };
            match t.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("--to {t:?}: {e}");
                    return std::process::ExitCode::from(2);
                }
            }
        }
        None => match resolve(host, 443) {
            Ok(a) if !a.is_empty() => a[0],
            Ok(_) => {
                eprintln!("{host}: resolved to nothing");
                return std::process::ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("{host}: dns: {e}");
                return std::process::ExitCode::from(1);
            }
        },
    };

    let mut tally = Tally::default();
    let mut lens = Vec::new();
    let mut times = Vec::new();
    let mut responses = Vec::new();
    let mut writes = 0usize;
    for t in 0..trials {
        let p = attempt::Params {
            host,
            addr,
            client_hello_len: ch_len,
            flight: flight.as_deref(),
            strategy: &strategy,
            timeout: Duration::from_secs(8),
            read_timeout: Duration::from_secs(if ttl.is_some() { 2 } else { 8 }),
            ttl,
            nonce: nonce_for(t),
        };
        let a = attempt::run(&p);
        if a.client_hello_len > 0 {
            lens.push(a.client_hello_len);
        }
        if let Some(ms) = a.reply_ms {
            times.push(ms);
        }
        if let Some(r) = &a.response {
            responses.push(r.label());
        }
        writes = writes.max(a.writes);
        tally.push(a.outcome);
        std::thread::sleep(Duration::from_millis(250));
    }

    let breakdown: Vec<String> = tally
        .breakdown()
        .iter()
        .map(|(k, c)| format!("{k}:{c}"))
        .collect();
    responses.sort();
    responses.dedup();
    println!(
        "{host:<26} {spec:<18} {}/{} {:<11} ip={} ch={} w={} ms={:?} {} {}",
        tally.successes(),
        tally.trials(),
        tally.verdict().to_string(),
        addr.ip(),
        lens.first().copied().unwrap_or(0),
        writes,
        times,
        breakdown.join(","),
        responses.join(",")
    );
    std::process::ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------------------
// The friendly runner. Everything below is what the person on the other ISP actually sees.
// ---------------------------------------------------------------------------------------

const VERSION: &str = concat!("vigil-scan ", env!("CARGO_PKG_VERSION"));

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Which ISP this is, and nothing else.
///
/// A **label** for the line this ran on, carrying no name and no number.
///
/// Over plain HTTP and deliberately without the `query` field, so nothing here can record the
/// address it was learned from. Failure is not an error: the scan is still worth running and the
/// report just says "unknown".
///
/// Two things it used to do and no longer does:
///
/// - **The city.** It asked for `city` until 2026-08-08 and put the answer in the header, so a
///   volunteer's report read `Kadıköy / <provider> / AS…` — a district, a company and a
///   timestamp, in a file whose own header promises "no personal data" and which was written to be
///   forwarded to somebody else.
/// - **The company's name, and its AS number.** Removed 2026-08-10, by decision: no report and no
///   document in this project names an internet provider. What every measurement here actually needs
///   is only the ability to tell one line from another and to line up two runs on the same one, and
///   a stable label does that.
///
/// The label is derived from the AS field, so the same line always produces the same one. **It is a
/// pseudonym and not secrecy** — anyone determined can enumerate the few thousand plausible inputs.
/// It exists so that a name is never written down, not so that a line cannot be identified by
/// somebody who sets out to.
fn network_identity() -> String {
    let Ok(addrs) = resolve("ip-api.com", 80) else {
        return "unknown".into();
    };
    let Some(addr) = addrs.first() else {
        return "unknown".into();
    };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(addr, Duration::from_secs(5)) else {
        return "unknown".into();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    use std::io::{Read, Write};
    if s.write_all(
        b"GET /line/?fields=as HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n",
    )
    .is_err()
    {
        return "unknown".into();
    }
    let mut buf = String::new();
    if s.take(8192).read_to_string(&mut buf).is_err() {
        return "unknown".into();
    }
    match buf.split_once("\r\n\r\n") {
        Some((_, body)) => {
            let parts: Vec<&str> = body
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            label_for(&parts.join(" "))
        }
        None => "unknown".into(),
    }
}

/// Turn whatever the lookup said into a stable label that names nobody. Pure.
///
/// FNV-1a folded to sixteen bits: short enough to read out over a message, stable across runs, and
/// carrying nothing but "this is the same line as last time" or "this is a different one".
fn label_for(raw: &str) -> String {
    let raw = raw.trim();
    // **Only hash something that looks like an answer.** Anything at all on port 80 was laundered
    // into a confident `hat 3f21` — a captive portal, an error page, a proxy's own banner. The worse
    // case is not a wrong label but a *false equality*: the same portal page on two different lines
    // hashes the same, so two volunteers' reports would positively assert "same line".
    let looks_like_an_answer = raw
        .strip_prefix("AS")
        .is_some_and(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()));
    if !looks_like_an_answer {
        return "unknown".into();
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in raw.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("hat {:04x}", (h ^ (h >> 32)) as u16)
}

/// The address to measure against, preferring one a resolver other than the ISP's gave us.
///
/// When the system resolver is lying, measuring against what it said characterises the block
/// page rather than the DPI — and the whole report becomes a description of a web server. The
/// honest address still reaches the real host, so the DPI is still in the path and still gets
/// measured; the tampering is reported separately rather than being allowed to destroy every
/// other section.
fn honest_addrs(dns: &[dns::Comparison], host: &str) -> Option<Vec<std::net::IpAddr>> {
    let c = dns.iter().find(|c| c.host == host)?;
    if dns::integrity(c) == dns::Integrity::Agrees {
        return None;
    }
    c.public
        .iter()
        .find_map(|(_, r)| r.as_ref().ok())
        .filter(|v| !v.is_empty())
        .map(|v| v.iter().map(|a| std::net::IpAddr::V4(*a)).collect())
}

/// Run one cell to completion.
fn measure(cell: &plan::Cell, counter: &mut usize, dns: &[dns::Comparison]) -> report::CellResult {
    let strategy = Strategy::parse(&cell.strategy).unwrap_or_else(|_| Strategy::passthrough());
    // The same-address control asks a permitted name at a blocked host's address.
    let dns_name = cell.via_host_addr.as_deref().unwrap_or(&cell.host);
    let addr = honest_addrs(dns, dns_name)
        .and_then(|v| v.first().map(|ip| SocketAddr::new(*ip, 443)))
        .or_else(|| resolve(dns_name, 443).ok().and_then(|a| a.first().copied()));

    let mut tally = Tally::default();
    let mut reply_ms = Vec::new();
    let mut responses = Vec::new();
    let mut ch_len = 0usize;

    let Some(addr) = addr else {
        for _ in 0..cell.trials {
            tally.push(vigil_core::Outcome::Other("dns".into()));
        }
        return report::CellResult {
            cell: cell.clone(),
            tally,
            addr: format!("{dns_name}: DNS failed"),
            client_hello_len: 0,
            reply_ms,
            responses,
        };
    };

    for _ in 0..cell.trials {
        *counter += 1;
        let p = attempt::Params {
            host: &cell.host,
            addr,
            client_hello_len: cell.client_hello_len,
            flight: None,
            strategy: &strategy,
            timeout: Duration::from_secs(6),
            read_timeout: Duration::from_secs(if cell.ttl.is_some() { 2 } else { 6 }),
            ttl: cell.ttl,
            nonce: nonce_for(*counter),
        };
        let a = attempt::run(&p);
        if a.client_hello_len > 0 {
            ch_len = a.client_hello_len;
        }
        if let Some(ms) = a.reply_ms {
            reply_ms.push(ms);
        }
        if let Some(r) = &a.response {
            responses.push(r.label());
        }
        tally.push(a.outcome);
        std::thread::sleep(Duration::from_millis(120));
    }
    responses.sort();
    responses.dedup();
    report::CellResult {
        cell: cell.clone(),
        tally,
        addr: addr.to_string(),
        client_hello_len: ch_len,
        reply_ms,
        responses,
    }
}

fn execute(
    cells: &[plan::Cell],
    counter: &mut usize,
    done: &mut usize,
    total: usize,
    dns: &[dns::Comparison],
) -> Vec<report::CellResult> {
    let mut out = Vec::new();
    for c in cells {
        let r = measure(c, counter, dns);
        *done += c.trials;
        let pct = (*done * 100).checked_div(total).unwrap_or(100);
        eprintln!(
            "  [{pct:>3}%] {:<14} {:<28} {:<18} {}/{}  {}",
            c.phase.label(),
            c.host,
            // The strategy *and* the length, not one or the other: a transform cell that fixes a
            // browser-sized hello printed only "1800 B" and looked like a size cell, so two
            // different measurements scrolled past under the same label.
            match (c.ttl, c.client_hello_len) {
                (Some(t), _) => format!("ttl:{t}"),
                (None, Some(n)) if c.strategy == "none" => format!("{n} B"),
                (None, Some(n)) => format!("{} @{n}B", c.strategy),
                (None, None) => c.strategy.clone(),
            },
            r.tally.successes(),
            r.tally.trials(),
            r.tally.verdict()
        );
        out.push(r);
    }
    out
}

/// Print the DNS comparison on its own. Diagnostic, and fast enough to run before deciding
/// whether a full scan is even worth starting.
fn dns_report() -> std::process::ExitCode {
    for c in check_dns() {
        let verdict = match dns::integrity(&c) {
            dns::Integrity::Agrees => "ok",
            dns::Integrity::Tampered => "TAMPERED",
            dns::Integrity::Unknown => "unknown",
        };
        let sys: Vec<String> = c.system.iter().map(|a| a.to_string()).collect();
        println!("{:<26} {:<9} system={}", c.host, verdict, sys.join(","));
        for (name, r) in &c.public {
            let got = match r {
                Ok(a) => a
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                Err(e) => format!("<{e}>"),
            };
            println!("    {name:<12} {got}");
        }
    }
    std::process::ExitCode::SUCCESS
}

/// Print what this machine's proxy configuration actually is, and change nothing.
///
/// Seconds, no network measurement, no settings touched. It answers "why did this application
/// not use vigil" more often than any amount of DPI measurement does, and before 2026-08-08
/// there was no way to ask it at all.
fn diag_report() -> std::process::ExitCode {
    let f = hostdiag::collect();
    let text = hostdiag::render(&f);
    if text.is_empty() {
        eprintln!("Bu teşhis sadece Windows'ta bir şey söyler.");
        return std::process::ExitCode::from(2);
    }
    print!("{}{}", hostdiag::warning(&f.proxy), text);
    std::process::ExitCode::SUCCESS
}

/// Ask the system resolver and the public ones the same questions.
fn check_dns() -> Vec<dns::Comparison> {
    let hosts: Vec<&str> = plan::CANDIDATES
        .iter()
        .chain(plan::CONTROLS.iter())
        .copied()
        .collect();
    let mut out = Vec::new();
    for (i, host) in hosts.iter().enumerate() {
        let system: Vec<std::net::IpAddr> = resolve(host, 443)
            .map(|a| a.into_iter().map(|s| s.ip()).collect())
            .unwrap_or_default();
        let public = dns::PUBLIC_RESOLVERS
            .iter()
            .map(|(name, addr)| {
                let r = match addr.parse() {
                    Ok(a) => dns::query(a, host, 0x4000 + i as u16, Duration::from_secs(3)),
                    Err(_) => Err(dns::Error::NoReply),
                };
                ((*name).to_string(), r)
            })
            .collect();
        out.push(dns::Comparison {
            host: (*host).to_string(),
            system,
            public,
        });
    }
    out
}

fn run(opts: Options) -> std::process::ExitCode {
    let d = plan::Depth::default();
    let disc = plan::discovery(d);
    // Worst case: everything is blocked, so the investigation is as large as it can get.
    let worst: Vec<String> = plan::CANDIDATES.iter().map(|s| s.to_string()).collect();
    let total = plan::connections(&disc) + plan::connections(&plan::investigation(&worst, true, d));

    eprintln!("{VERSION}");
    eprintln!("{}", "=".repeat(72));
    eprintln!("Bu araç iki şeyi ölçer ve tek bir rapor dosyası yazar:");
    eprintln!("  1) Bu hattaki engelleme NASIL çalışıyor,");
    if opts.apps {
        eprintln!("  2) vigil devredeyken bu bilgisayardaki uygulamalar açılıyor mu.");
    } else {
        eprintln!("  2) (uygulama testi kapalı — --no-apps verildi)");
    }
    eprintln!();
    eprintln!("  * Yönetici yetkisi istemez, hiçbir şey kurmaz.");
    // On `opts.apps || opts.observe > 0`, not on `opts.apps` — because that is the condition the
    // *engaging* is on, and a banner that promises less than the program does is the only kind of
    // banner that matters.
    if opts.apps || opts.observe > 0 {
        eprintln!("  * BİRİNCİ bölüm hiçbir ayara dokunmaz.");
        eprintln!("  * İKİNCİ bölüm, sadece kendi süresince, Windows'un proxy ayarını ve");
        eprintln!("    HTTP_PROXY değişkenlerini kendine yönlendirir ve Discord/Roblox'u");
        eprintln!("    açıp kapatır — ölçtüğü şey tam olarak bu. Eski hâlleri önce kaydeder,");
        eprintln!("    bitince geri yazar. Yarıda kalırsa: vigil-repair.exe düzeltir.");
    } else {
        eprintln!("  * Bilgisayarında hiçbir şeyi değiştirmez, ayarlara dokunmaz.");
    }
    eprintln!("  * Rapora yazılanlar: site adları, sunucu adresleri, süreler ve hangi");
    eprintln!("    internet sağlayıcısı olduğu. SENİN IP ADRESİN YAZILMAZ. Ölçüm sırasında");
    eprintln!("    açık olan başka programlarının gittiği adresler de YAZILMAZ.");
    eprintln!();
    // An honest range, not an average. A trial that gets an answer or a reset costs about a
    // fifth of a second; a trial that gets nothing costs the full read timeout, and on a
    // network that drops silently — SansürOn does — that is most of them. The old estimate
    // assumed the fast case and told people "3-4 dakika" for a run that took half an hour.
    let app_probes = if opts.apps {
        (apps::APPS.iter().map(|a| a.probes.len()).sum::<usize>() + apps::CONTROLS.len()) * 2 * 6
    } else {
        0
    };
    // Twice per application: once with vigil off, once with it on. The control arm is what
    // turns "the tool did something" into "the tool helped", and it costs exactly its own run.
    let app_minutes = if opts.apps {
        (2 * apps::APPS.len() * (opts.app_wait as usize + 12)) / 60 + 1
    } else {
        0
    };
    // The watch window counts too. Left out, the estimate said four minutes for a run that takes
    // seven, and a volunteer with no terminal reads that gap as "it has hung".
    let observe_minutes = (opts.observe as usize).div_ceil(60);
    let fast = ((total + app_probes) * 200) / 60_000 + 1 + app_minutes + observe_minutes;
    let slow = ((total + app_probes) * 6_200) / 60_000 + 1 + app_minutes + observe_minutes;
    eprintln!("Yaklaşık {total} bağlantı denemesi yapılacak.");
    eprintln!(
        "Süre: engelleme hızlı cevap veriyorsa ~{fast} dakika; sessizce düşürüyorsa \
         {slow} dakikaya kadar çıkabilir."
    );
    eprintln!("Bilgisayarı kullanmaya devam edebilirsin, sadece pencereyi kapatma.");
    eprintln!("{}", "=".repeat(72));
    eprintln!();

    eprint!("Sağlayıcı tespit ediliyor... ");
    let network = network_identity();
    eprintln!("{network}");
    eprintln!();

    // Read the machine before measuring the line. If Windows' proxy setting is not actually in
    // force, the application half below cannot mean what it appears to mean, and the reader has
    // to know that before they read it rather than afterwards.
    eprint!("Makinenin proxy ayarı okunuyor... ");
    let facts = hostdiag::collect();
    eprintln!("{}", facts.proxy.headline());
    eprintln!();

    let ctx = report::Context {
        tool_version: VERSION.into(),
        timestamp: clock::iso8601(now_secs()),
        platform: std::env::consts::OS.into(),
        network,
        host_warning: hostdiag::warning(&facts.proxy),
    };

    // DNS first. Everything after this assumes the addresses are honest, and on 2026-08-04
    // that assumption failed on the development line itself — a full scan ran against a block
    // page and produced an entirely plausible report of the wrong thing.
    eprint!("DNS bütünlüğü kontrol ediliyor... ");
    let dns = check_dns();
    let tampered: Vec<&str> = dns
        .iter()
        .filter(|c| dns::integrity(c) == dns::Integrity::Tampered)
        .map(|c| c.host.as_str())
        .collect();
    let unknown = dns
        .iter()
        .filter(|c| dns::integrity(c) == dns::Integrity::Unknown)
        .count();
    if tampered.is_empty() && unknown == 0 {
        eprintln!("temiz");
    } else if tampered.is_empty() {
        // Saying "clean" here would be a false reassurance: we did not fail to find
        // tampering, we failed to look. On a network that intercepts UDP/53 — which Turkish
        // ISPs are documented to do — this is the expected outcome and it matters.
        eprintln!("KONTROL EDİLEMEDİ: {unknown} isim için hiçbir dış DNS sunucusuna ulaşılamadı");
        eprintln!("  Bu da bir bulgu: bu hat düz DNS trafiğini engelliyor olabilir.");
    } else {
        eprintln!(
            "SORUN: {} isim için sistem çözücüsü sahte adres veriyor",
            tampered.len()
        );
        eprintln!("  ({})", tampered.join(", "));
        eprintln!("  Ölçüm yine de yapılacak, ama rapor bunu açıkça işaretleyecek.");
    }
    eprintln!();

    let mut counter = 0usize;
    let mut done = 0usize;

    eprintln!("1/2  Ne engelli, ne değil:");
    let mut results = execute(&disc, &mut counter, &mut done, total, &dns);

    // Anything that is not reliably reachable is worth investigating. Flaky counts: on this
    // family of networks a partial block is the interesting case, not a rounding error.
    let blocked: Vec<String> = results
        .iter()
        .filter(|r| r.cell.phase == plan::Phase::Baseline && !r.reached())
        .map(|r| r.cell.host.clone())
        .collect();

    eprintln!();
    if blocked.is_empty() {
        eprintln!("Hiçbir aday site engelli çıkmadı. Bu hatta filtre yok gibi görünüyor.");
    } else {
        eprintln!("2/2  Engelli çıkanlar inceleniyor: {}", blocked.join(", "));
        // A TTL sweep only means something against an injector. SansürOn drops silently,
        // and asking it twelve times would return "inconclusive" after two minutes.
        let resets = results.iter().any(|r| {
            r.cell.phase == plan::Phase::Baseline
                && !r.reached()
                && report::mechanism(&r.tally, &r.responses) == report::Mechanism::ResetInjection
        });
        if !resets {
            eprintln!("  (sessiz düşürme tespit edildi — TTL taraması atlanıyor, ölçemez)");
        }
        // Say what the sweep will not cover. Silence here would read as full coverage.
        let (_, unreachable) = plan::sizes_for(&blocked[0]);
        if !unreachable.is_empty() {
            eprintln!(
                "  (boyut taraması: {} B atlandı — bu isim için en küçük ClientHello daha büyük)",
                unreachable
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let inv = plan::investigation(&blocked, plan::ttl_sweep_can_work(resets), d);
        let rest = execute(&inv, &mut counter, &mut done, total, &dns);
        results.extend(rest);
    }

    let mut text = report::render(&ctx, &results, &dns);
    text.push_str(&hostdiag::render(&facts));

    // The second half: does the machine's software actually work with vigil in place? It is
    // the same report because it is the same question asked one layer up, and splitting it
    // into a second tool only produced two logs that had to be read together.
    if opts.apps || opts.observe > 0 {
        eprintln!();
        eprintln!("3/3  vigil devredeyken...");
        if let Some(o) = appphase::run(
            opts.port,
            d.control_trials,
            opts.apps,
            opts.app_wait,
            opts.observe,
        ) {
            text.push_str(&appphase::render(&o));
        }
    } else {
        eprintln!();
        eprintln!("3/3  Uygulama testi atlandı (--no-apps): hiçbir ayara dokunulmadı.");
    }

    // The version belongs in the file name, not only inside the file. On 2026-08-07 a volunteer
    // re-sent a report produced by a build we had already replaced, and nothing short of an
    // md5sum could tell it from the new one — the name and the header were identical.
    let name = format!(
        "vigil-scan-{}-{}.txt",
        env!("CARGO_PKG_VERSION"),
        now_secs()
    );
    let path = report_path(&name);
    let written = std::fs::write(&path, &text);

    eprintln!();
    eprintln!("{}", "=".repeat(72));
    if report::controls_passed(&results) {
        eprintln!("Bitti.");
    } else {
        eprintln!("DİKKAT: her zaman çalışması gereken kontrol siteleri de başarısız oldu.");
        eprintln!(
            "Bu, ölçüm sırasında internetin kesildiği anlamına gelir. Lütfen tekrar çalıştır."
        );
    }
    match written {
        Ok(()) => {
            eprintln!();
            eprintln!("Rapor dosyası:");
            eprintln!("  {}", path.display());
            eprintln!();
            eprintln!("Bu dosyayı Resul'e gönder. İçini açıp okuyabilirsin, düz metindir.");
            eprintln!("Dosyanın bulunduğu klasör şimdi açılıyor.");
            reveal(&path);
        }
        Err(e) => {
            eprintln!("Rapor dosyası yazılamadı ({e}). Rapor aşağıda:");
            println!("{text}");
        }
    }
    eprintln!("{}", "=".repeat(72));
    if opts.pause {
        wait_for_enter();
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **No report names an internet provider.** The label has to be stable — two runs on the same
    /// line must line up column by column, which is the whole reason the header carries anything at
    /// all — and it must not be the name.
    #[test]
    fn the_line_label_is_stable_and_names_nobody() {
        let a = label_for("AS1111 One Provider Inc.");
        let b = label_for("AS2222 Another Provider");
        assert_eq!(a, label_for("AS1111 One Provider Inc."), "must be stable");
        assert_ne!(a, b, "two lines must be distinguishable");
        for l in [&a, &b] {
            assert!(l.starts_with("hat "), "{l}");
            assert_eq!(l.len(), 8, "{l}");
            let lower = l.to_ascii_lowercase();
            for name in ["provider", "inc", "as1111", "as2222", "1111", "2222"] {
                assert!(!lower.contains(name), "{name} survived into {l}");
            }
        }
        assert_eq!(label_for("   "), "unknown");
        assert_eq!(label_for(""), "unknown");
        // And anything that is not an AS answer — a captive portal, an error page — is `unknown`
        // rather than a confident label. Two lines behind the same portal must not read as one.
        for junk in [
            "<html><title>Hotspot</title>",
            "error",
            "ASsomething",
            "{\"status\":\"fail\"}",
        ] {
            assert_eq!(label_for(junk), "unknown", "{junk}");
        }
    }
}

#[cfg(test)]
mod option_tests {
    use super::*;

    fn parse(a: &[&str]) -> Options {
        options_from(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).expect("parses")
    }

    /// **`--no-apps` must change nothing on the machine.**
    ///
    /// It is promised in the banner, the usage line, `Cargo.toml` and `CLAUDE.md`, and the whole
    /// rule was three untested lines inside a `match` arm: deleting them left all 836 tests green
    /// while the run engaged Windows' system proxy and `HTTPS_PROXY`/`ALL_PROXY` for 180 seconds.
    /// It is a regression that has already happened once, from the commit that changed `observe`'s
    /// default from 0 to 180.
    #[test]
    fn no_apps_touches_nothing() {
        let o = parse(&["--no-apps"]);
        assert!(!o.apps, "the application phase must be off");
        assert_eq!(
            o.observe, 0,
            "the watch window engages the system proxy, so it must be off too"
        );
    }

    /// But an operator who asks for a window by name still gets one.
    #[test]
    fn an_explicit_observe_survives_no_apps() {
        let o = parse(&["--no-apps", "--observe", "300"]);
        assert!(!o.apps);
        assert_eq!(o.observe, 300);
        assert!(o.observe_was_asked_for);
    }

    /// The defaults, pinned with literals rather than computed from the constants they are — the
    /// documented failure mode of this repository is a test that asserts the code's current text.
    #[test]
    fn the_double_click_defaults_are_the_documented_ones() {
        let d = Options::default();
        assert!(d.apps, "a plain double-click runs the application phase");
        assert_eq!(d.observe, 180, "and the 180-second watch window");
        assert!(!d.observe_was_asked_for);
    }

    /// `--observe 0` asks for no window and is not `--no-apps`.
    #[test]
    fn observe_zero_is_asked_for_and_leaves_the_app_phase_alone() {
        let o = parse(&["--observe", "0"]);
        assert_eq!(o.observe, 0);
        assert!(o.observe_was_asked_for);
        assert!(o.apps);
    }

    /// **A flag must not be eaten as another flag's value.**
    ///
    /// `--app-wait --no-apps` used to consume `--no-apps` as the value, so the parse failed, the
    /// fallback kept the default, and `--no-apps` never happened at all — on the one command whose
    /// entire promise is that it changes nothing. `--observe` is the worse of the two: its failed
    /// parse also set `observe_was_asked_for`, which is precisely what disarms the guard.
    #[test]
    fn a_missing_value_does_not_swallow_the_next_flag() {
        let o = parse(&["--app-wait", "--no-apps"]);
        assert!(!o.apps, "--no-apps was eaten as the value of --app-wait");
        assert_eq!(o.observe, 0);
        assert_eq!(o.app_wait, Options::default().app_wait);

        let o = parse(&["--observe", "--no-apps"]);
        assert!(!o.apps, "--no-apps was eaten as the value of --observe");
        assert!(
            !o.observe_was_asked_for,
            "a flag that ate the next flag must not count as having been given a value"
        );
        assert_eq!(o.observe, 0, "and the --no-apps guard must still fire");

        // A trailing flag with no value at all is the same case.
        let o = parse(&["--no-apps", "--observe"]);
        assert!(!o.apps);
        assert!(!o.observe_was_asked_for);
        assert_eq!(o.observe, 0);
    }

    #[test]
    fn an_unknown_option_is_refused_rather_than_ignored() {
        let args = ["--nope".to_string()];
        assert!(matches!(options_from(&args), Err(2)));
    }

    /// A mistyped value is refused, not replaced by a fallback. This used to make `--observe abc`
    /// silently run a 120-second window — a number nobody asked for, in the section the driver
    /// question is read from.
    #[test]
    fn a_value_that_is_not_a_number_is_refused() {
        for a in [
            vec!["--observe", "abc"],
            vec!["--app-wait", "9x"],
            vec!["--port", "108o"],
        ] {
            let args: Vec<String> = a.iter().map(|s| (*s).to_string()).collect();
            assert!(
                matches!(options_from(&args), Err(2)),
                "{a:?} should have been refused"
            );
        }
    }
}
