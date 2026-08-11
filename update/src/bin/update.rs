//! `vigil-update.exe` — the only binary that talks to the network to update the others, and the
//! only one that replaces a file.
//!
//! Nothing here decides anything. Every decision is in the library, pure and tested on Linux; this
//! is argument parsing, printing, and the order in which the library is called. See
//! `docs/18-auto-update.md`.
//!
//! ```text
//! vigil-update --version
//! vigil-update verify MANIFEST SIG_A SIG_B   what a client will do, on local files
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
        Some("verify") => verify_cmd(&args[1..]),
        Some("fetch") => fetch_cmd(&args[1..]),
        Some("--check") => check_cmd(&args[1..]),
        Some("--apply") => apply_cmd(&args[1..]),
        _ => {
            eprintln!("usage: vigil-update --version");
            eprintln!("       vigil-update verify MANIFEST SIG_A SIG_B");
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

/// Do to three local files exactly what a client does to three downloaded ones, and say so.
///
/// The decision is [`vigil_update::release::check`], which is pure and tested with real signatures;
/// this is reading three files and printing. Called by `scripts/release.sh`, which used to "verify"
/// by grepping `--version` for a compile-time constant — see that module for what that cost.
fn verify_cmd(args: &[String]) -> std::process::ExitCode {
    let [manifest, sig_a, sig_b] = args else {
        eprintln!("usage: vigil-update verify MANIFEST SIG_A SIG_B");
        return std::process::ExitCode::from(2);
    };

    let read = |path: &String| match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("verify: cannot read {path}: {e}");
            None
        }
    };
    let (Some(text), Some(a), Some(b)) = (read(manifest), read(sig_a), read(sig_b)) else {
        return std::process::ExitCode::from(3);
    };

    // The keys that ship, not a pair passed in on the command line: the point is to exercise the
    // constant the field will use.
    let r = match vigil_update::release::check(
        &vigil_update::verify::PUBLIC_KEYS,
        &text,
        &a,
        &b,
        now_secs(),
    ) {
        Ok(r) => r,
        Err(e @ vigil_update::release::Problem::NoKeysConfigured) => {
            eprintln!("verify: {e}.");
            eprintln!("        PUBLIC_KEYS in update/src/verify.rs is still the placeholder.");
            return std::process::ExitCode::from(3);
        }
        Err(e) => {
            eprintln!("verify: REFUSED — {e}");
            return std::process::ExitCode::from(1);
        }
    };

    let m = &r.manifest;
    println!("signature: ok, two distinct keys — {}", r.trusted_comment);
    println!(
        "manifest:  serial {} version {} min_version {} critical {} — {} files",
        m.serial,
        m.version,
        m.min_version,
        u8::from(m.critical),
        m.files.len()
    );
    println!("expires:   {}", vigil_core::clock::iso8601(m.expires));
    println!("base:      {}", m.base);
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

    // An apply that did not finish is answered here, **before the network and before any version
    // comparison**. Both orderings matter. The bytes are already staged and were already verified,
    // so there is nothing to fetch; and asking "is the manifest newer than me" first is exactly the
    // bug — this binary is manifest order 4 and `vigil-app.exe` is order 5, so after a crash between
    // them the updater is already the new version and would answer "current" forever, with the
    // finishing bytes sitting untouched one directory down.
    // A complete staging set that has not been started yet. Remembered rather than printed: while
    // the endpoints answer, what they say is more current than what is on disk, so this is only
    // used if the fetch below fails. **Phase B needs no network at all**, so answering
    // `unreachable` over the top of a ready folder made a fully downloaded, doubly-signed,
    // hash-checked update uninstallable — `UpdateState::Unreachable` offers no action, and the tray
    // rechecks by itself every six hours, so it needed nobody to click anything. The condition that
    // triggers it is the ordinary one: the line starts blocking `github.com` between staging and
    // installing, which is the situation this whole product exists for.
    let mut staged_offline: Option<(String, bool)> = None;
    if let Some((text, sigs)) = stage::load_inputs(&folder) {
        let refs: Vec<&str> = sigs.iter().map(String::as_str).collect();
        let verified = vigil_update::verify::verify(text.as_bytes(), &refs).is_ok();
        if let Ok(m) = vigil_update::manifest::parse(&text) {
            let required = m.files.iter().filter(|f| f.required).count();
            let left = apply::outstanding(&folder, &m).len();
            let resume = apply::resume_state(verified, required, left);
            if let apply::Resume::Finishable { outstanding } = resume {
                println!(
                    "{}",
                    status_line(
                        "interrupted",
                        &[
                            ("version", &m.version.to_string()),
                            ("outstanding", &outstanding.to_string()),
                        ]
                    )
                );
                return std::process::ExitCode::SUCCESS;
            }
            if apply::offer_staged_offline(
                verified,
                stage::ready_marker(&folder).exists(),
                vigil_update::manifest::is_newer_than(&m, vigil_update::Version::running()),
                resume,
            ) {
                staged_offline = Some((m.version.to_string(), m.critical));
            }
        }
    }

    let resolver = vigil_proxy::Resolver::default();
    let dl = Deadlines::default();

    // The manifest and both its signatures, from the first endpoint that serves a triple which
    // verifies. A partial answer is a failed endpoint, not a committed one.
    let (text, sigs) = match fetch_manifest(&resolver, dl) {
        Ok(v) => v,
        Err(why) => {
            // A ready folder outranks a dead endpoint: the bytes are here and installing them
            // needs nothing from the network.
            match &staged_offline {
                Some((version, critical)) => println!(
                    "{}",
                    status_line(
                        "staged",
                        &[
                            ("version", version),
                            ("critical", if *critical { "1" } else { "0" }),
                        ]
                    )
                ),
                None => println!("{}", status_line("unreachable", &[("why", why)])),
            }
            return std::process::ExitCode::SUCCESS;
        }
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
    // The floor is this machine's own history, not a hard-coded 0. With 0 the ceiling guarded
    // nothing and a superseded-but-genuine manifest could be replayed here forever.
    let prefs = vigil_platform::prefs::read();
    let trust = vigil_update::manifest::Trust {
        now: now_secs(),
        serial_floor: vigil_platform::prefs::serial_floor(&prefs),
        running: vigil_update::Version::running(),
    };
    if let Err(e) = vigil_update::manifest::check_trust(&m, &trust) {
        println!("{}", status_line("untrusted", &[("why", &e.to_string())]));
        return std::process::ExitCode::from(4);
    }
    // Accepted, so the floor moves up. Written here rather than after a successful install: what
    // this records is "a manifest with this serial verified against our keys and passed every trust
    // check", which is true whether or not the user goes on to install it, and recording it later
    // would leave the floor behind on every machine that checks and declines.
    if prefs.last_serial.is_none_or(|s| m.serial > s) {
        let _ = vigil_platform::prefs::write(&vigil_platform::prefs::Prefs {
            last_serial: Some(m.serial),
            ..prefs
        });
    }
    if !vigil_update::manifest::is_newer_than(&m, vigil_update::Version::running()) {
        // Unless something newer is already staged and ready. An endpoint serving a superseded
        // manifest would otherwise answer `current` over the top of a finished download and hide
        // it just as completely as an unreachable one did.
        if let Some((version, critical)) = &staged_offline {
            println!(
                "{}",
                status_line(
                    "staged",
                    &[
                        ("version", version),
                        ("critical", if *critical { "1" } else { "0" }),
                    ]
                )
            );
            return std::process::ExitCode::SUCCESS;
        }
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

/// Stop, say why, and **bring vigil back**.
///
/// Every non-success exit from `apply_cmd` goes through here. Before this existed, one of the ten
/// exits relaunched the application and nine did not — including the designed "the new repair tool
/// does not run, roll it back and stop safely" path. Their user-visible result was: tray icon gone,
/// protection off, nothing comes back, and no message anywhere, after a consent dialog that had said
/// in writing that vigil would close, update and *reopen*. The settings are already restored by then,
/// so the internet works; what is lost is the protection, silently, which on a censored line is the
/// thing the user actually came for.
///
/// `relaunch` is false for the two cases where a vigil is already running — starting a second one
/// would be worse than starting none.
fn bail(folder: &Path, code: u8, why: &str, relaunch: bool) -> std::process::ExitCode {
    println!("{why}");
    let _ = std::fs::write(folder.join(stage::LAST_ERROR), format!("{why}\n"));
    if relaunch {
        let app = folder.join(plan::APP);
        if app.exists() {
            match guard::relaunch(&app) {
                Ok(()) => println!("restarted {}", app.display()),
                Err(e) => println!("could not restart it: {e} — start it yourself"),
            }
        } else {
            println!("{} is not in the folder — nothing to restart", plan::APP);
        }
    }
    std::process::ExitCode::from(code)
}

/// Try each endpoint in turn, and take the first that yields a manifest **and both** signatures that
/// together verify.
///
/// It used to accept "at least one signature", which made the endpoint a trap: an endpoint serving a
/// manifest and one signature would be committed to, `verify` would then refuse it for having only
/// one, and the second endpoint — the whole point of having two — was never tried. On this line that
/// is not a hypothetical: GitHub Releases and raw.githubusercontent are blocked independently, and a
/// partial answer from a censored path is the ordinary case rather than the strange one.
///
/// So the unit of success is the whole verifiable triple. Verification happens here, and the caller
/// verifies again — deliberately: this decides *which endpoint*, and the caller decides *whether to
/// trust*, and collapsing the two would make a future edit to either one silently weaken the other.
fn fetch_manifest(
    resolver: &vigil_proxy::Resolver,
    dl: Deadlines,
) -> Result<(String, Vec<String>), &'static str> {
    // Which failure to report when every endpoint failed. "Nothing answered" and "something answered
    // and it did not verify" are very different situations on a censored line — one is a blocked
    // download, the other is a manifest that is not ours — and collapsing them would throw away the
    // only clue in a log a user pastes into a message.
    let mut answered = false;
    for base in MANIFEST_URLS {
        let Ok(url) = Url::parse(base) else { continue };
        let Ok(body) = fetch::get(&url, resolver, dl) else {
            continue;
        };
        let Ok(text) = String::from_utf8(body.body) else {
            continue;
        };
        answered = true;
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
        let refs: Vec<&str> = sigs.iter().map(String::as_str).collect();
        if vigil_update::verify::verify(text.as_bytes(), &refs).is_ok() {
            return Ok((text, sigs));
        }
    }
    Err(if answered {
        "no_endpoint_served_a_verifiable_manifest"
    } else {
        "no_endpoint_answered"
    })
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
    // The address vigil serves on, handed over by the application that spawned us. The guard needs it
    // to ask "does the machine point at **us**" instead of "at anything on this host" — and only the
    // application knows the answer, because it is the thing listening. The fallback is the documented
    // default rather than a guess: it is the value `sysproxy::settings_for` writes.
    let listen = args
        .iter()
        .position(|a| a == "--listen")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:1080".to_string());

    println!("folder: {}", folder.display());

    // 1. Wait for the application to be gone. Its binary is the last thing replaced, but every one
    //    of these renames wants an idle target.
    if let Some(pid) = parent {
        if !guard::wait_for_exit(pid, PARENT_WAIT) {
            return bail(
                &folder,
                3,
                &format!("parent {pid} is still running after {PARENT_WAIT:?} — changing nothing"),
                false,
            );
        }
        println!("parent {pid} has exited");
    }

    // 2. The independent check, in this process rather than the one that disengaged.
    let g = guard::check(&listen);
    println!("guard: {}", g.explain());
    if !g.may_proceed() {
        return bail(
            &folder,
            3,
            &format!("guard: {} — changing nothing", g.explain()),
            false,
        );
    }
    if g == Guard::StrandedRestoreFirst {
        // The OLD repair tool, before anything is replaced: the one that has been on this machine
        // and working, not the one that just arrived over the network.
        match guard::repair_settings(&folder.join(plan::REPAIR)) {
            Ok(()) => println!("settings repaired"),
            Err(e) => {
                return bail(
                    &folder,
                    3,
                    &format!("could not repair the settings: {e} — changing nothing"),
                    true,
                );
            }
        }
        // And **read the machine back**, rather than taking an exit status as proof. Everything else
        // in this project reads back after writing; this was the one place that did not, on the one
        // path where being wrong means somebody has no internet. `vigil-repair` prints its failures
        // to a stdout nobody reads and still exits 0, so its exit code is not the evidence it looks
        // like.
        let after = guard::check(&listen);
        if after != Guard::Clear {
            return bail(
                &folder,
                3,
                &format!(
                    "the settings still point at a vigil after repairing ({}) — changing nothing",
                    after.explain()
                ),
                true,
            );
        }
        println!("guard: confirmed clear after repair");
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
            return bail(
                &folder,
                4,
                &format!("signature: {e} — changing nothing"),
                true,
            );
        }
    }
    let m = match vigil_update::manifest::parse(&text) {
        Ok(m) => m,
        Err(e) => {
            return bail(
                &folder,
                4,
                &format!("manifest: {e} — changing nothing"),
                true,
            );
        }
    };

    // 4. Plan against what is actually on disk, so an interrupted update resumes rather than
    //    restarts.
    let on_disk = stage::hash_folder(&folder, &m);
    let staged = stage::hash_folder(&stage::staging_dir(&folder), &m);
    let p = match plan::plan(&m, &on_disk, &staged) {
        Ok(p) => p,
        Err(e) => {
            return bail(&folder, 4, &format!("plan: {e} — changing nothing"), true);
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
        Err(e) => bail(
            &folder,
            5,
            &format!(
                "FAILED {e}\noutstanding: {:?}",
                apply::outstanding(&folder, &m)
            ),
            true,
        ),
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
            // Optional files that were never staged, named. `plan()` reports them in its return
            // value exactly as its doc says, and this — the binary — dropped them on the floor, so
            // `folder matches the manifest: false` was printed with nothing to explain it. That
            // line is the one this accounts for, which is why it sits beside it.
            //
            // `AlreadyCurrent` is deliberately not printed: on a resumed apply that is every
            // finished file, and it would bury the line that matters.
            for skipped in &p.skipped {
                if let plan::Skipped::OptionalAndMissing(name) = skipped {
                    println!("  not staged, optional: {name}");
                }
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
