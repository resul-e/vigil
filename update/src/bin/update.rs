//! `vigil-update.exe` — the only binary that talks to the network to update the others, and the
//! only one that replaces a file.
//!
//! Nothing here decides anything. Every decision is in the library, pure and tested on Linux; this
//! is argument parsing, printing, and the order in which the library is called. See
//! `docs/18-auto-update.md`.
//!
//! ```text
//! vigil-update --version
//! vigil-update fetch URL [TRIALS]        measure the transport, change nothing
//! vigil-update --apply [--parent PID] [--die-after BOUNDARY]
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vigil_update::apply::{self, Boundary};
use vigil_update::fetch::{self, Deadlines};
use vigil_update::guard::{self, Guard};
use vigil_update::http::Url;
use vigil_update::plan;
use vigil_update::stage;

/// How long the runner waits for `vigil-app.exe` to exit before giving up.
///
/// Bounded, and giving up means changing nothing: replacing the binaries of a process that is still
/// running is the 2026-08-06 stranding failure with extra steps.
const PARENT_WAIT: Duration = Duration::from_secs(30);

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => version(),
        Some("fetch") => fetch_cmd(&args[1..]),
        Some("--check") => check_cmd(&args[1..]),
        Some("--apply") => apply_cmd(&args[1..]),
        _ => {
            eprintln!("usage: vigil-update --version");
            eprintln!("       vigil-update --check [--dry-run]");
            eprintln!("       vigil-update fetch URL [TRIALS]");
            eprintln!("       vigil-update --apply [--parent PID] [--die-after BOUNDARY]");
            std::process::ExitCode::from(2)
        }
    }
}

fn version() -> std::process::ExitCode {
    println!("vigil-update {}", env!("CARGO_PKG_VERSION"));
    println!(
        "update keys: {}",
        if vigil_update::verify::keys_are_configured() {
            "configured"
        } else {
            "NOT CONFIGURED — this build cannot verify an update"
        }
    );
    std::process::ExitCode::SUCCESS
}

/// The folder this executable lives in — or, when running as the staged runner, the folder above it.
///
/// The runner executes from `.vigil-update/`, so "where am I" and "which folder am I updating" are
/// different questions and getting them confused would have it replacing files inside the staging
/// directory.
fn app_folder(me: &Path) -> PathBuf {
    let dir = me.parent().unwrap_or(Path::new(".")).to_path_buf();
    if dir.file_name().and_then(|n| n.to_str()) == Some(stage::STAGING) {
        dir.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        dir
    }
}

fn fetch_cmd(args: &[String]) -> std::process::ExitCode {
    let Some(raw) = args.first() else {
        eprintln!("fetch needs a URL");
        return std::process::ExitCode::from(2);
    };
    let url = match Url::parse(raw) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::from(2);
        }
    };
    let trials: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8);

    // The same resolver the proxy uses: an odd port asked before the operating system, because on
    // this line the interception covers port 53 rather than DNS.
    let resolver = vigil_proxy::Resolver::default();
    let dl = Deadlines::default();

    let mut ok = 0usize;
    for i in 1..=trials {
        let started = Instant::now();
        match fetch::get(&url, &resolver, dl) {
            Ok(f) => {
                ok += 1;
                for a in &f.attempts {
                    println!("  [{i}] {a}");
                }
                println!(
                    "  [{i}] OK {} bytes from {} in {} ms",
                    f.body.len(),
                    f.final_url,
                    started.elapsed().as_millis()
                );
            }
            Err((e, attempts)) => {
                for a in &attempts {
                    println!("  [{i}] {a}");
                }
                println!("  [{i}] FAILED {e}");
            }
        }
    }
    println!("{ok}/{trials}  {}", url.to_string_https());
    if ok == trials {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    }
}

/// Where the manifest is served from. **The filename must never carry a version**: this endpoint
/// rewrites the tag in the path and leaves the filename alone, so a version-stamped name would 404
/// from the next release onward.
const MANIFEST_URLS: &[&str] = &[
    "https://github.com/resul-e/vigil/releases/latest/download/vigil-manifest.txt",
    "https://raw.githubusercontent.com/resul-e/vigil/main/update/vigil-manifest.txt",
];

/// The last line of `--check`, and the only thing `vigil-app.exe` reads.
///
/// A single `key=value` line rather than an exit code, because the states worth distinguishing are
/// not two — "up to date", "could not look", "this folder is read-only" and "no keys in this build"
/// all need different words on screen, and squeezing them into an integer would lose exactly the
/// distinctions that matter on a censored line.
///
/// `vigil-app.exe` deliberately does **not** link this crate: doing so would put rustls inside the
/// binary every user runs, which is the whole reason the updater is a separate program. So the
/// contract between them is this one line of text, and the parser for it lives in `ui` and is tested
/// there.
fn status_line(status: &str, extra: &[(&str, &str)]) -> String {
    let mut s = format!("vigil-update-status status={status}");
    for (k, v) in extra {
        // Values are single tokens by construction — versions and short reasons — and a space in a
        // reason would silently become another field.
        s.push_str(&format!(" {k}={}", v.replace(' ', "_")));
    }
    s
}

fn check_cmd(args: &[String]) -> std::process::ExitCode {
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let me = std::env::current_exe().unwrap_or_default();
    let folder = app_folder(&me);

    if !vigil_update::verify::keys_are_configured() {
        println!("{}", status_line("nokeys", &[]));
        return std::process::ExitCode::SUCCESS;
    }
    if let Err(e) = stage::check_writable(&folder) {
        println!("{}", status_line("readonly", &[("why", &e.to_string())]));
        return std::process::ExitCode::SUCCESS;
    }

    // A leftover runner from a previous update. Its own process could not delete it.
    apply::sweep_old_runner(&folder);

    let resolver = vigil_proxy::Resolver::default();
    let dl = Deadlines::default();

    // The manifest, then its two signatures, from whichever endpoint answers first.
    let Some((text, sigs)) = fetch_manifest(&resolver, dl) else {
        println!(
            "{}",
            status_line("unreachable", &[("why", "no_endpoint_answered")])
        );
        return std::process::ExitCode::SUCCESS;
    };

    let refs: Vec<&str> = sigs.iter().map(String::as_str).collect();
    if let Err(e) = vigil_update::verify::verify(text.as_bytes(), &refs) {
        println!("{}", status_line("badsig", &[("why", &e.to_string())]));
        return std::process::ExitCode::from(4);
    }
    let m = match vigil_update::manifest::parse(&text) {
        Ok(m) => m,
        Err(e) => {
            println!("{}", status_line("badmanifest", &[("why", &e.to_string())]));
            return std::process::ExitCode::from(4);
        }
    };
    let trust = vigil_update::manifest::Trust {
        now: now_secs(),
        serial_floor: 0,
        running: vigil_update::Version::running(),
    };
    if let Err(e) = vigil_update::manifest::check_trust(&m, &trust) {
        println!("{}", status_line("untrusted", &[("why", &e.to_string())]));
        return std::process::ExitCode::from(4);
    }
    if !vigil_update::manifest::is_newer_than(&m, vigil_update::Version::running()) {
        println!("{}", status_line("current", &[]));
        return std::process::ExitCode::SUCCESS;
    }

    let version = m.version.to_string();
    let critical = if m.critical { "1" } else { "0" };
    if dry_run {
        println!(
            "{}",
            status_line(
                "available",
                &[("version", &version), ("critical", critical)]
            )
        );
        return std::process::ExitCode::SUCCESS;
    }

    // Download. Only into `.vigil-update/`; the application folder is untouched whatever happens.
    let staged = stage::stage(&folder, &m, |url| {
        let u = Url::parse(url).map_err(|e| e.to_string())?;
        fetch::get(&u, &resolver, dl)
            .map(|f| f.body)
            .map_err(|(e, _)| e.to_string())
    });
    match staged {
        Err(e) => {
            println!("{}", status_line("unreachable", &[("why", &e.to_string())]));
            std::process::ExitCode::SUCCESS
        }
        Ok(_) => {
            // Keep the manifest and both signatures beside the files, so the apply can verify
            // again offline rather than trusting that nothing touched the folder in between.
            if let Err(e) = stage::save_inputs(&folder, &text, &sigs) {
                println!("{}", status_line("readonly", &[("why", &e.to_string())]));
                return std::process::ExitCode::SUCCESS;
            }
            println!(
                "{}",
                status_line("staged", &[("version", &version), ("critical", critical)])
            );
            std::process::ExitCode::SUCCESS
        }
    }
}

/// Try each endpoint in turn, and take the first that yields a manifest and at least one signature.
fn fetch_manifest(
    resolver: &vigil_proxy::Resolver,
    dl: Deadlines,
) -> Option<(String, Vec<String>)> {
    for base in MANIFEST_URLS {
        let Ok(url) = Url::parse(base) else { continue };
        let Ok(body) = fetch::get(&url, resolver, dl) else {
            continue;
        };
        let Ok(text) = String::from_utf8(body.body) else {
            continue;
        };
        let mut sigs = Vec::new();
        for suffix in [".minisig", ".minisig2"] {
            if let Ok(u) = Url::parse(&format!("{base}{suffix}")) {
                if let Ok(f) = fetch::get(&u, resolver, dl) {
                    if let Ok(s) = String::from_utf8(f.body) {
                        sigs.push(s);
                    }
                }
            }
        }
        if !sigs.is_empty() {
            return Some((text, sigs));
        }
    }
    None
}

/// Seconds since the Unix epoch. The one place in this binary that reads a clock; everything it
/// feeds takes `now` as a parameter so it can be tested.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `--die-after` names a boundary. Spelled out rather than numbered so a crash-matrix run is
/// readable in a shell history six months later.
fn boundary_from(name: &str) -> Option<Boundary> {
    match name {
        "nothing" => Some(Boundary::BeforeAnything),
        "aside" => Some(Boundary::AfterSettingRepairAside),
        "repair" => Some(Boundary::AfterRepairReplaced),
        "verified" => Some(Boundary::AfterRepairVerified),
        "file0" => Some(Boundary::AfterFile(0)),
        "file1" => Some(Boundary::AfterFile(1)),
        "file2" => Some(Boundary::AfterFile(2)),
        "file3" => Some(Boundary::AfterFile(3)),
        "app" => Some(Boundary::AfterApp),
        "cleanup" => Some(Boundary::AfterCleanup),
        _ => None,
    }
}

fn apply_cmd(args: &[String]) -> std::process::ExitCode {
    let me = std::env::current_exe().unwrap_or_default();
    let folder = app_folder(&me);
    let parent: Option<u32> = args
        .iter()
        .position(|a| a == "--parent")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok());
    let die_after = args
        .iter()
        .position(|a| a == "--die-after")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| boundary_from(s));
    if args.iter().any(|a| a == "--die-after") && die_after.is_none() {
        eprintln!("--die-after needs one of: nothing aside repair verified file0..3 app cleanup");
        return std::process::ExitCode::from(2);
    }

    println!("folder: {}", folder.display());

    // 1. Wait for the application to be gone. Its binary is the last thing replaced, but every one
    //    of these renames wants an idle target.
    if let Some(pid) = parent {
        if !guard::wait_for_exit(pid, PARENT_WAIT) {
            println!("parent {pid} is still running after {PARENT_WAIT:?} — changing nothing");
            return std::process::ExitCode::from(3);
        }
        println!("parent {pid} has exited");
    }

    // 2. The independent check, in this process rather than the one that disengaged.
    let g = guard::check();
    println!("guard: {}", g.explain());
    if !g.may_proceed() {
        return std::process::ExitCode::from(3);
    }
    if g == Guard::StrandedRestoreFirst {
        // The OLD repair tool, before anything is replaced: the one that has been on this machine
        // and working, not the one that just arrived over the network.
        match guard::repair_settings(&folder.join(plan::REPAIR)) {
            Ok(()) => println!("settings repaired"),
            Err(e) => {
                println!("could not repair the settings: {e} — changing nothing");
                return std::process::ExitCode::from(3);
            }
        }
    }

    // 3. Verify again, offline. The staging folder has been sitting on disk since phase A and
    //    anything with write access could have substituted a file; without this the only hash a
    //    substituted file is checked against is the one it brought with it.
    let Some((text, sigs)) = stage::load_inputs(&folder) else {
        println!("nothing staged");
        return std::process::ExitCode::SUCCESS;
    };
    let refs: Vec<&str> = sigs.iter().map(String::as_str).collect();
    match vigil_update::verify::verify(text.as_bytes(), &refs) {
        Ok(v) => println!("signature: ok — {}", v.trusted_comment),
        Err(e) => {
            println!("signature: {e} — changing nothing");
            return std::process::ExitCode::from(4);
        }
    }
    let m = match vigil_update::manifest::parse(&text) {
        Ok(m) => m,
        Err(e) => {
            println!("manifest: {e} — changing nothing");
            return std::process::ExitCode::from(4);
        }
    };

    // 4. Plan against what is actually on disk, so an interrupted update resumes rather than
    //    restarts.
    let on_disk = stage::hash_folder(&folder, &m);
    let staged = stage::hash_folder(&stage::staging_dir(&folder), &m);
    let p = match plan::plan(&m, &on_disk, &staged) {
        Ok(p) => p,
        Err(e) => {
            println!("plan: {e} — changing nothing");
            return std::process::ExitCode::from(4);
        }
    };
    if p.nothing_to_do() {
        println!("already up to date");
        let _ = stage::discard(&folder);
        return std::process::ExitCode::SUCCESS;
    }
    println!(
        "plan: {}",
        p.steps
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(" → ")
    );

    // 5. Replace.
    let mut check = |path: &Path| guard::run_repair_version(path);
    match apply::apply(&folder, &p, &mut check, die_after) {
        Err(e) => {
            println!("FAILED {e}");
            println!("outstanding: {:?}", apply::outstanding(&folder, &m));
            std::process::ExitCode::from(5)
        }
        Ok(out) => {
            for name in &out.replaced {
                println!("  replaced {name}");
            }
            for name in &out.skipped {
                println!("  skipped  {name} (in use)");
            }
            if let Some(b) = out.stopped_at {
                println!("stopped deliberately at {b:?}");
                return std::process::ExitCode::from(9);
            }
            println!(
                "done. folder matches the manifest: {}",
                apply::folder_matches(&folder, &m)
            );
            // 6. Start the application again. Best effort: a user who has to double-click once is
            //    inconvenienced, and that is the whole cost of this failing.
            let app = folder.join(plan::APP);
            if app.exists() {
                match guard::relaunch(&app) {
                    Ok(()) => println!("restarted {}", app.display()),
                    Err(e) => println!("could not restart it: {e} — start it yourself"),
                }
            }
            std::process::ExitCode::SUCCESS
        }
    }
}
