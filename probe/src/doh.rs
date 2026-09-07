//! The DoH reachability sweep — the measurement, not the mechanism.
//!
//! The mechanism lives in [`vigil_proxy::doh`]: one exchange with one resolver, addressed by IP
//! literal. What is here is the harness around it — the arms, the control, the verdict — and it
//! stays in `probe/` because printing a k/N table is not something a proxy does.

use std::net::{IpAddr, Ipv4Addr};

use vigil_core::strategy::Strategy;
use vigil_proxy::doh::{exchange, Answer, Budget, Endpoint, Phase};

/// One arm of the sweep: an ALPN choice and a strategy.
struct Arm {
    label: &'static str,
    alpn: bool,
    strategy: Strategy,
}

fn arms() -> Vec<Arm> {
    vec![
        Arm {
            label: "h1  none",
            alpn: true,
            strategy: Strategy::passthrough(),
        },
        Arm {
            label: "h1  default",
            alpn: true,
            strategy: Strategy::measured_default(),
        },
        Arm {
            label: "-   none",
            alpn: false,
            strategy: Strategy::passthrough(),
        },
        Arm {
            label: "-   default",
            alpn: false,
            strategy: Strategy::measured_default(),
        },
    ]
}

fn range(v: &[u128]) -> String {
    match (v.iter().min(), v.iter().max()) {
        (Some(lo), Some(hi)) if lo == hi => format!("{lo} ms"),
        (Some(lo), Some(hi)) => format!("{lo}-{hi} ms"),
        _ => "-".into(),
    }
}

/// **The one question that can kill the DoH plan before a line of resolver code is written.**
///
/// Returns `false` when the run is not a measurement — the control failed, so nothing below it
/// means anything. That is a broken harness, not a finding, and the caller exits non-zero.
///
/// The control is a resolver address **not under test**, and it passes on *any* TLS-layer response
/// at far-end latency: a ServerHello, a certificate failure, a fatal alert. All three prove the
/// line carried the flight and returned the reply, which is the only thing a control must
/// establish. Requiring a completed handshake instead would score a name-based virtual host's
/// `handshake_failure` — the server's policy — as a failure of the line.
pub fn sweep(candidates: &[IpAddr], control: IpAddr, n: usize, name: &str) -> bool {
    let os = if cfg!(windows) { "windows" } else { "linux" };
    println!("== DoH reachability  os={os}  n={n}  name={name}");
    if os != "windows" {
        println!("   REFUSED AS A MEASUREMENT: segmentation is not measurable from WSL2 — the");
        println!("   virtual switch does not preserve write boundaries. Run the Windows binary.");
    }
    println!();

    // --- the control ---
    let ctl = Endpoint::new(control);
    let mut spoke = 0usize;
    let mut ctl_ms = Vec::new();
    for _ in 0..n {
        let e = exchange(
            &ctl,
            None,
            &Strategy::passthrough(),
            true,
            Budget::default(),
        );
        if e.phase.peer_spoke() {
            spoke += 1;
            if let Some(ms) = e.reply_ms {
                ctl_ms.push(ms);
            }
        }
    }
    let control_ok = spoke == n;
    println!(
        "control {:<16} {}/{n} spoke   reply {}   {}",
        ctl.addr().to_string(),
        spoke,
        range(&ctl_ms),
        if control_ok { "PASS" } else { "FAIL" }
    );
    if !control_ok {
        println!();
        println!("*** HARNESS SUSPECT *** the control did not answer, so nothing below is a");
        println!("measurement. A dead control must never read as a pass.");
        return false;
    }
    println!();

    // --- the candidates ---
    let mut any_arm_green = false;
    let mut all_failures_are_silence = true;
    for ip in candidates {
        let ep = Endpoint::new(*ip);
        for arm in arms() {
            let mut ok = 0usize;
            let mut ms = Vec::new();
            let mut hello = 0usize;
            let mut applied: Vec<&'static str> = Vec::new();
            let mut other: Vec<String> = Vec::new();
            for _ in 0..n {
                let e = exchange(&ep, None, &arm.strategy, arm.alpn, Budget::default());
                hello = e.client_hello_len.max(hello);
                if !e.applied.is_empty() {
                    applied = e.applied.clone();
                }
                match &e.phase {
                    Phase::Answered(Answer::Handshake) => {
                        ok += 1;
                        if let Some(v) = e.reply_ms {
                            ms.push(v);
                        }
                    }
                    Phase::Hello { reset, timeout } => {
                        other.push(format!(
                            "silent({})",
                            if *reset {
                                "rst"
                            } else if *timeout {
                                "timeout"
                            } else {
                                "fin"
                            }
                        ));
                    }
                    p => {
                        // The peer spoke. Whatever it said is above the line, not on it.
                        all_failures_are_silence = false;
                        other.push(format!("{p:?}"));
                    }
                }
            }
            println!(
                "{:<16} alpn={:<12} {}/{n} handshake  hello {hello} B  applied {}  reply {}{}",
                ep.addr().to_string(),
                arm.label,
                ok,
                if applied.is_empty() {
                    "-".to_string()
                } else {
                    applied.join("+")
                },
                range(&ms),
                if other.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", other.join(" "))
                }
            );

            if ok < n {
                continue;
            }
            any_arm_green = true;
            // Only an arm that shook hands every time is worth asking a question of.
            for host in [name, "example.com"] {
                let Ok(q) = vigil_core::dnsmsg::encode_query(host, 0) else {
                    continue;
                };
                let mut good = 0usize;
                let mut addrs: Vec<Ipv4Addr> = Vec::new();
                let mut why: Vec<String> = Vec::new();
                for _ in 0..n {
                    let e = exchange(&ep, Some(&q), &arm.strategy, arm.alpn, Budget::default());
                    match e.phase {
                        Phase::Addresses(a) if !a.is_empty() => {
                            good += 1;
                            for x in a {
                                if !addrs.contains(&x) {
                                    addrs.push(x);
                                }
                            }
                        }
                        p => why.push(format!("{p:?}")),
                    }
                }
                let blocked = addrs
                    .iter()
                    .any(|a| vigil_proxy::resolver::is_block_page(&IpAddr::V4(*a)));
                println!(
                    "  {host:<24} {good}/{n}  {}{}{}",
                    addrs
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    if blocked { "  *** BLOCK PAGE ***" } else { "" },
                    if why.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", why.join(" "))
                    }
                );
            }
        }
    }

    // **The honesty check.** A DoH answer that is merely well-formed proves nothing: a sinkhole
    // answers 200 with a perfectly good DNS message. So the same names are asked of the transport
    // this is meant to replace — plain DNS on the odd port — and the two sets must **overlap**.
    // Overlap and never equality: an anycast zone hands out a rotating subset, and a correct
    // client would fail an equality test on the second trial.
    //
    // And the requirement is on the **blocked** name only. Measured 2026-09-07: `discord.com`
    // came back as the same five addresses from both transports, while `example.com` differed
    // completely — 8.47.69.0/8.6.112.0 from Yandex against 172.66.147.243/104.20.23.154 from
    // Cloudflare. Chased with `nslookup` against both resolvers on :53, which reproduced it: both
    // sets are Cloudflare edges picked from different vantage points, so it is GeoDNS and not a
    // finding. Two addresses ending in `.0` looked like a parse bug for ten minutes; it was not.
    println!();
    // `resolve_no_system`, not `resolve`: the default resolver falls back to the operating
    // system's, which on this line is the ISP's poisoner. A comparison that quietly permitted that
    // fallback would be "DoH against whatever answered first", and the first draft of this check
    // was exactly that — `example.com` came back as two addresses no other resolver had.
    let odd = vigil_proxy::resolver::Resolver::default();
    for host in [name, "example.com"] {
        let theirs: Vec<String> = odd
            .resolve_no_system(host, 443)
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        println!("odd-port {host:<24} {}", theirs.join(","));
    }
    println!("(overlap is required for the BLOCKED name and is the honesty check. A control name");
    println!(" on a CDN may legitimately differ: measured 2026-09-07, Yandex answers example.com");
    println!(" with 8.47.69.0/8.6.112.0 and Cloudflare with 172.66.147.243/104.20.23.154 — both");
    println!(" Cloudflare edges, chosen from different vantage points. Not tampering.)");

    println!();
    if any_arm_green {
        println!("At least one arm shook hands {n}/{n}: an SNI-less flight to a resolver address");
        println!("survives on this line. Read the per-name rows before concluding anything more.");
    } else if all_failures_are_silence {
        println!("*** STOP *** every arm is 0/{n} and every failure is silence — the flight went");
        println!("out and nothing came back. This line does not carry an SNI-less TLS flight to a");
        println!("resolver address on :443, and DoH is not the answer here. Record k/N and the");
        println!("date; the next candidate mechanism is DoT on :853.");
    } else {
        println!("No arm is {n}/{n}, but at least one failure was the peer speaking rather than");
        println!("silence — that is a resolver or instrument finding, not a finding about the");
        println!("line. Drop that candidate and repeat before concluding anything.");
    }
    true
}
