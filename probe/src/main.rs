//! Measurement harness — step 0 of docs/10-v6-plan.md.
//!
//! Answers one question honestly: for a given target and strategy, does the connection work,
//! `k` times out of `n`? Never one trial, always with a control, always reporting the
//! ClientHello size.
//!
//! Usage:  probe [trials] [small|default] [--via HOST:PORT]

mod attempt;
mod profile;
mod socks_client;

use std::thread::sleep;
use std::time::Duration;

use profile::Profile;
use vigil_core::{spans_multiple_segments, SplitPoint, Tally, Verdict, MIN_TRIALS, TYPICAL_MSS};

/// Targets known blocked on this line, plus controls that must stay reachable.
/// A run where the controls fail is a broken harness, not a working bypass.
const BLOCKED: &[&str] = &["discord.com", "roblox.com", "protonvpn.com", "4chan.org"];
const CONTROLS: &[&str] = &["example.com", "media.discordapp.net"];

fn strategies() -> Vec<(&'static str, SplitPoint)> {
    vec![
        ("baseline", SplitPoint::None),
        ("split@1", SplitPoint::RecordHeader),
        ("split@2", SplitPoint::At(2)),
    ]
}

fn main() {
    let trials: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(MIN_TRIALS);

    if trials < MIN_TRIALS {
        eprintln!(
            "refusing to run {trials} trials: minimum is {MIN_TRIALS}, \
             below that no conclusion is permitted (see core::verdict)"
        );
        std::process::exit(2);
    }

    // `small` is the default because only a single-segment ClientHello gives a meaningful
    // baseline on this line. `default` is selectable so the pre-split effect can be shown.
    let prof = match std::env::args().nth(2).as_deref() {
        None | Some("small") => Profile::Small,
        Some("default") => Profile::Default,
        Some(other) => {
            eprintln!("unknown profile {other:?}; expected \"small\" or \"default\"");
            std::process::exit(2);
        }
    };
    let route = match std::env::args().position(|a| a == "--via") {
        Some(i) => match std::env::args().nth(i + 1).and_then(|s| s.parse().ok()) {
            Some(a) => attempt::Route::Socks5(a),
            None => {
                eprintln!("--via needs a HOST:PORT");
                std::process::exit(2);
            }
        },
        None => attempt::Route::Direct,
    };
    let cfg = profile::config(prof);
    let timeout = Duration::from_secs(8);

    println!(
        "profile={}  trials={trials}  mss={TYPICAL_MSS}  route={}",
        prof.label(),
        match route {
            attempt::Route::Direct => "direct".to_string(),
            attempt::Route::Socks5(a) => format!("socks5://{a}"),
        }
    );
    println!(
        "{:<22} {:<10} {:>7}  {:<26} {:<11} note",
        "target", "strategy", "k/n", "outcomes", "verdict"
    );
    println!("{}", "-".repeat(104));

    // One resolver for the whole run, so its cache is shared and every cell of a host is
    // measured against the same address.
    let resolver = vigil_proxy::resolver::Resolver::default();
    let mut control_failures = 0usize;

    for (group, hosts) in [("blocked", BLOCKED), ("control", CONTROLS)] {
        for host in hosts {
            // Through vigil's own resolver, and the address is printed. Measured on this line
            // 2026-08-05: the OS answered `discord.com`, `roblox.com` and `4chan.org` with the
            // block page 195.175.254.2, and the direct arm then dutifully reported them as
            // "blocked, timeout" — a measurement of the censor's web server, not of the
            // censorship. `protonvpn.com`, which happened not to be tampered with that day,
            // showed the real answer in the same run: 0/5 rst, split@1 5/5.
            let addr = match resolver.resolve(host, 443).first().copied() {
                Some(a) => a,
                None => {
                    println!("{host:<22} {:<10} {:>7}  dns resolution failed", "-", "-");
                    continue;
                }
            };
            if vigil_proxy::resolver::is_block_page(&addr.ip()) {
                println!("{host:<22} {:<10} {:>7}  resolves to the block page {addr} — every cell below would measure the censor's web server", "-", "-");
                continue;
            }

            for (label, split) in strategies() {
                let mut tally = Tally::default();
                let mut ch_len = 0usize;
                let mut status = None;

                for _ in 0..trials {
                    let a = attempt::run_via(host, addr, &split, cfg.clone(), timeout, route);
                    if a.client_hello_len > 0 {
                        ch_len = a.client_hello_len;
                    }
                    if a.status_line.is_some() && status.is_none() {
                        status = a.status_line.clone();
                    }
                    tally.push(a.outcome);
                    sleep(Duration::from_millis(200));
                }

                let v = tally.verdict();
                if group == "control" && v != Verdict::Reliable {
                    control_failures += 1;
                }

                let breakdown = tally
                    .breakdown()
                    .iter()
                    .map(|(k, c)| format!("{k}:{c}"))
                    .collect::<Vec<_>>()
                    .join(" ");

                let mut note = format!("CH={ch_len}B");
                if spans_multiple_segments(ch_len, TYPICAL_MSS) {
                    note.push_str(" PRE-SPLIT(>MSS)");
                }
                if let Some(s) = &status {
                    note.push_str(&format!("  {}", &s[..s.len().min(28)]));
                }

                println!(
                    "{host:<22} {label:<10} {:>3}/{:<3}  {breakdown:<26} {:<11} {note}",
                    tally.successes(),
                    tally.trials(),
                    v.to_string(),
                );
            }
            println!();
        }
    }

    if control_failures > 0 {
        eprintln!(
            "HARNESS SUSPECT: {control_failures} control cell(s) did not come back RELIABLE. \
             Controls must pass or the run proves nothing — do not trust the blocked rows."
        );
        std::process::exit(1);
    }
}
