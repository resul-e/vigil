//! `vigil-update.exe` — the only binary that talks to the network to update the others.
//!
//! Nothing here decides anything. Every decision is in the library, pure and tested on Linux; this
//! is argument parsing and printing. See `docs/18-auto-update.md`.

use std::time::Instant;

use vigil_update::fetch::{self, Deadlines};
use vigil_update::http::Url;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
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
        // The gate instrument for the transport. Fetches N times and reports k/N with the resolved
        // address, the ClientHello length and the reply latency for every attempt — this project's
        // standard for a measurement, and the reason the numbers can be trusted.
        Some("fetch") => fetch_cmd(&args[1..]),
        _ => {
            eprintln!("usage: vigil-update --version");
            eprintln!("       vigil-update fetch URL [TRIALS]");
            std::process::ExitCode::from(2)
        }
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
