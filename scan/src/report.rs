//! Turning results into a conclusion and a file. Pure — no I/O, no clock.
//!
//! The report is written for someone who will read it without having run it, on a network
//! they have never seen. So it states what was measured, what the controls did, and refuses
//! to conclude anything when the controls failed.

use vigil_core::{Tally, Verdict};

use crate::dns::{integrity, selectively_blocked, Comparison, Integrity};
use crate::plan::{Cell, Phase};

#[derive(Debug, Clone)]
pub struct CellResult {
    pub cell: Cell,
    pub tally: Tally,
    /// The address actually connected to, so two ISPs can be compared against the same server.
    pub addr: String,
    pub client_hello_len: usize,
    pub reply_ms: Vec<u64>,
    pub responses: Vec<String>,
}

impl CellResult {
    pub fn reached(&self) -> bool {
        self.tally.verdict() == Verdict::Reliable
    }
}

/// How a network refuses a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// Injected TCP reset. Türk Telekom and Superonline fibre both do this.
    ResetInjection,
    /// Silent drop. Turkcell mobile does this, and it needs a different countermeasure.
    SilentDrop,
    /// The connection completed but the far end was not the far end.
    Interception,
    /// Not blocked.
    Open,
    /// Blocked in a way none of the above describes.
    Unknown,
}

impl Mechanism {
    pub fn label(self) -> &'static str {
        match self {
            Mechanism::ResetInjection => "RST injection",
            Mechanism::SilentDrop => "silent drop",
            Mechanism::Interception => "interception / block page",
            Mechanism::Open => "not blocked",
            Mechanism::Unknown => "unknown",
        }
    }
}

/// Decide the mechanism from a baseline tally and what came back.
pub fn mechanism(t: &Tally, responses: &[String]) -> Mechanism {
    if t.trials() == 0 {
        return Mechanism::Unknown;
    }
    if t.verdict() == Verdict::Reliable {
        return Mechanism::Open;
    }
    if responses.iter().any(|r| r.starts_with("not-tls")) {
        return Mechanism::Interception;
    }
    let counts = t.breakdown();
    let get = |k: &str| {
        counts
            .iter()
            .find(|(l, _)| l == k)
            .map(|(_, c)| *c)
            .unwrap_or(0)
    };
    let half = t.trials().div_ceil(2);
    if get("rst") >= half {
        Mechanism::ResetInjection
    } else if get("timeout") + get("closed") >= half {
        Mechanism::SilentDrop
    } else {
        Mechanism::Unknown
    }
}

/// The median of a sample, which is what to quote for a latency: one 300 ms outlier from a
/// retransmit should not move the number that gets compared between two ISPs.
pub fn median(xs: &[u64]) -> Option<u64> {
    if xs.is_empty() {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// How many hops away the injector is, from a TTL sweep.
///
/// Below the injector's distance the first flight expires before reaching it, so nothing
/// answers and the attempt times out. At and above it, the reset appears. The distance is
/// therefore the **smallest TTL at which resets become the majority** — and it is only
/// meaningful if some TTL produced no reset at all, otherwise the sweep never got below the
/// injector and the answer would be an artefact of where we started looking.
pub fn dpi_hop(samples: &[(u32, Tally)]) -> Option<u32> {
    let majority_reset = |t: &Tally| {
        let rst = t
            .breakdown()
            .iter()
            .find(|(l, _)| l == "rst")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        t.trials() > 0 && rst * 2 > t.trials()
    };
    let mut sorted: Vec<&(u32, Tally)> = samples.iter().collect();
    sorted.sort_by_key(|(t, _)| *t);

    let saw_a_quiet_ttl = sorted.iter().any(|(_, t)| !majority_reset(t));
    if !saw_a_quiet_ttl {
        // Every TTL we tried was already past the injector. We cannot say how far it is,
        // only that it is closer than the smallest TTL we tried.
        return None;
    }
    sorted
        .iter()
        .find(|(_, t)| majority_reset(t))
        .map(|(ttl, _)| *ttl)
}

/// Was every hostname resolved to an address that other resolvers agree on?
///
/// Separate from the controls, and checked separately, because a run can have perfect
/// controls and still be worthless: the controls are not blocked, so nobody tampers with
/// their DNS, and they resolve correctly while every measured host points at a block page.
/// That is exactly what happened on 2026-08-04.
pub fn dns_is_trustworthy(dns: &[Comparison]) -> bool {
    !dns.iter().any(|c| integrity(c) == Integrity::Tampered)
}

/// Did everything that had to succeed, succeed?
pub fn controls_passed(results: &[CellResult]) -> bool {
    let controls: Vec<&CellResult> = results
        .iter()
        .filter(|r| r.cell.phase == Phase::Control)
        .collect();
    !controls.is_empty() && controls.iter().all(|r| r.reached())
}

/// What the run was and where it ran. Supplied by the caller so this module stays pure.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub tool_version: String,
    pub timestamp: String,
    pub platform: String,
    /// ISP identity only — never the address it was learned from.
    pub network: String,
    /// A warning about the *machine* rather than the line, printed before anything is
    /// measured. Supplied by the caller so this module stays pure; today its only source is
    /// `hostdiag::warning`, for the case where Windows' proxy setting is not actually in force
    /// and every application verdict below it would therefore be misread.
    pub host_warning: String,
}

fn bar(width: usize) -> String {
    "-".repeat(width)
}

/// Render the whole report.
pub fn render(ctx: &Context, results: &[CellResult], dns: &[Comparison]) -> String {
    let mut s = String::new();
    s.push_str("vigil-scan — DPI characterisation report\n");
    s.push_str(&bar(78));
    s.push('\n');
    s.push_str(&format!("tool      : {}\n", ctx.tool_version));
    s.push_str(&format!("when      : {}\n", ctx.timestamp));
    s.push_str(&format!("platform  : {}\n", ctx.platform));
    s.push_str(&format!("network   : {}\n", ctx.network));
    s.push_str("contains  : hostnames, server addresses, timings. No personal data, and not\n");
    s.push_str("            the address of the machine this ran on.\n\n");

    // Before the DNS warning, deliberately: a machine whose proxy setting is not in force
    // cannot produce a valid application half at all, whatever the line is doing.
    if !ctx.host_warning.is_empty() {
        s.push_str(&ctx.host_warning);
    }

    if !dns_is_trustworthy(dns) {
        s.push_str("*** DNS IS BEING TAMPERED WITH ON THIS LINE ***\n");
        s.push_str("The system resolver answered with addresses no other resolver agrees on —\n");
        s.push_str(
            "see section 0. That is a finding in its own right: any application here that\n",
        );
        s.push_str(
            "trusts the system resolver is sent to the censor's address, whatever it does\n",
        );
        s.push_str("about the DPI afterwards.\n");
        s.push_str("The measurements below were taken against the addresses a clean resolver\n");
        s.push_str(
            "gave, so they characterise the DPI and not a block page, and remain valid.\n\n",
        );
    }

    let selective = selectively_blocked(dns);
    if !selective.is_empty() {
        s.push_str("*** DNS QUERIES FOR SPECIFIC NAMES ARE BEING BLOCKED ***\n");
        s.push_str("Public resolvers answered normally for some hostnames in this run and were\n");
        s.push_str("silent for these, so this is not a connectivity problem — the lookups for\n");
        s.push_str("these names are being dropped:\n");
        for h in &selective {
            s.push_str(&format!("  - {h}\n"));
        }
        s.push_str("The addresses used below for them came from the ISP's resolver alone.\n\n");
    }

    if !dns.is_empty() {
        s.push_str("0. DNS INTEGRITY\n");
        s.push_str(&bar(78));
        s.push('\n');
        s.push_str("What the system resolver said, against public resolvers asked directly.\n");
        for c in dns {
            let verdict = match integrity(c) {
                Integrity::Agrees => "ok",
                Integrity::Tampered => "TAMPERED",
                Integrity::Unknown => "unknown (no public resolver reachable)",
            };
            let sys: Vec<String> = c.system.iter().map(|a| a.to_string()).collect();
            s.push_str(&format!(
                "  {:<26} {:<10} system={}\n",
                c.host,
                verdict,
                if sys.is_empty() {
                    "-".into()
                } else {
                    sys.join(",")
                }
            ));
            for (name, r) in &c.public {
                let got = match r {
                    Ok(a) => a
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    Err(e) => format!("<{e}>"),
                };
                s.push_str(&format!("      {name:<12} {got}\n"));
            }
        }
        s.push('\n');
    }

    if !controls_passed(results) {
        s.push_str("*** RUN IS VOID ***\n");
        s.push_str("A control that must always succeed did not. That means the machine had no\n");
        s.push_str("working internet connection for part of this run, so nothing below can be\n");
        s.push_str("read as censorship. Please re-run it.\n\n");
    }

    // ---- what is blocked, and how
    s.push_str("1. WHAT IS BLOCKED\n");
    s.push_str(&bar(78));
    s.push('\n');
    s.push_str(&format!(
        "{:<28} {:>6}  {:<11} {:<20} {:>7}\n",
        "host", "k/N", "verdict", "mechanism", "reply"
    ));
    for r in results
        .iter()
        .filter(|r| matches!(r.cell.phase, Phase::Baseline | Phase::Control))
    {
        let m = mechanism(&r.tally, &r.responses);
        s.push_str(&format!(
            "{:<28} {:>3}/{:<2}  {:<11} {:<20} {:>5}ms  {}\n",
            r.cell.host,
            r.tally.successes(),
            r.tally.trials(),
            r.tally.verdict().to_string(),
            m.label(),
            median(&r.reply_ms).unwrap_or(0),
            r.addr,
        ));
    }
    s.push('\n');

    // ---- name or address
    let same: Vec<&CellResult> = results
        .iter()
        .filter(|r| r.cell.phase == Phase::SameAddress)
        .collect();
    if !same.is_empty() {
        s.push_str("2. IS IT THE NAME OR THE ADDRESS?\n");
        s.push_str(&bar(78));
        s.push('\n');
        s.push_str("The same server, asked for a permitted name. If these succeed, the block is\n");
        s.push_str("triggered by the name in the TLS handshake, not by the address.\n");
        for r in &same {
            s.push_str(&format!(
                "  {:<26} at {:<22} {:>3}/{:<2}  {}\n",
                r.cell.host,
                r.cell.via_host_addr.clone().unwrap_or_default(),
                r.tally.successes(),
                r.tally.trials(),
                r.tally.verdict()
            ));
        }
        s.push('\n');
    }

    // ---- strategies
    let strat: Vec<&CellResult> = results
        .iter()
        .filter(|r| r.cell.phase == Phase::Strategy)
        .collect();
    if !strat.is_empty() {
        s.push_str("3. WHAT DEFEATS IT\n");
        s.push_str(&bar(78));
        s.push('\n');
        let mut hosts: Vec<&str> = strat.iter().map(|r| r.cell.host.as_str()).collect();
        hosts.dedup();
        for h in hosts {
            s.push_str(&format!("  {h}\n"));
            for r in strat.iter().filter(|r| r.cell.host == h) {
                s.push_str(&format!(
                    "    {:<20} {:>3}/{:<2}  {:<11} {}\n",
                    r.cell.strategy,
                    r.tally.successes(),
                    r.tally.trials(),
                    r.tally.verdict().to_string(),
                    r.tally
                        .breakdown()
                        .iter()
                        .map(|(k, c)| format!("{k}:{c}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
        }
        s.push('\n');
    }

    // ---- size
    let sizes: Vec<&CellResult> = results
        .iter()
        .filter(|r| r.cell.phase == Phase::Size)
        .collect();
    if !sizes.is_empty() {
        s.push_str("4. DOES THE CLIENTHELLO'S LENGTH ALONE DECIDE IT?\n");
        s.push_str(&bar(78));
        s.push('\n');
        s.push_str(
            "No split applied. Above the path MSS the kernel splits the flight by itself,\n",
        );
        s.push_str("so a change here locates this network's segment boundary.\n");
        for r in &sizes {
            s.push_str(&format!(
                "  {:>5} B  {:>3}/{:<2}  {:<11} {}\n",
                r.client_hello_len,
                r.tally.successes(),
                r.tally.trials(),
                r.tally.verdict().to_string(),
                r.tally
                    .breakdown()
                    .iter()
                    .map(|(k, c)| format!("{k}:{c}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        s.push('\n');
    }

    // ---- ttl
    let ttls: Vec<&CellResult> = results
        .iter()
        .filter(|r| r.cell.phase == Phase::Ttl)
        .collect();
    if !ttls.is_empty() {
        s.push_str("5. HOW FAR AWAY IS THE INJECTOR?\n");
        s.push_str(&bar(78));
        s.push('\n');
        let samples: Vec<(u32, Tally)> = ttls
            .iter()
            .filter_map(|r| r.cell.ttl.map(|t| (t, r.tally.clone())))
            .collect();
        match dpi_hop(&samples) {
            Some(h) => {
                s.push_str(&format!(
                    "  The reset first appears at TTL {h}, so the injector is {h} hop(s) away.\n"
                ));
                s.push_str(&format!(
                    "  A v2 forged packet should use a TTL of {h} to reach it and no further.\n"
                ));
            }
            None => s.push_str(
                "  Inconclusive: no TTL was low enough to fall short of the injector, or no\n\
                 \x20 reset appeared at all.\n",
            ),
        }
        for r in &ttls {
            s.push_str(&format!(
                "    ttl {:>2}  {:>3}/{:<2}  {}\n",
                r.cell.ttl.unwrap_or(0),
                r.tally.successes(),
                r.tally.trials(),
                r.tally
                    .breakdown()
                    .iter()
                    .map(|(k, c)| format!("{k}:{c}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        s.push('\n');
    }

    s.push_str("RAW\n");
    s.push_str(&bar(78));
    s.push('\n');
    for r in results {
        s.push_str(&format!(
            "{}\t{}/{}\t{}\tch={}\taddr={}\tms={:?}\t{}\n",
            r.cell.key(),
            r.tally.successes(),
            r.tally.trials(),
            r.tally.verdict(),
            r.client_hello_len,
            r.addr,
            r.reply_ms,
            r.responses.join(","),
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::Outcome;

    fn tally(of: &[Outcome]) -> Tally {
        let mut t = Tally::default();
        for o in of {
            t.push(o.clone());
        }
        t
    }

    fn cell(phase: Phase, host: &str) -> Cell {
        Cell {
            phase,
            host: host.into(),
            via_host_addr: None,
            strategy: "none".into(),
            client_hello_len: None,
            ttl: None,
            trials: 8,
            round: 0,
        }
    }

    fn result(phase: Phase, host: &str, of: &[Outcome]) -> CellResult {
        CellResult {
            cell: cell(phase, host),
            tally: tally(of),
            addr: "1.2.3.4:443".into(),
            client_hello_len: 250,
            reply_ms: vec![2, 2, 3],
            responses: vec![],
        }
    }

    // ------------------------------------------------------------------ mechanism

    #[test]
    fn all_resets_is_reset_injection() {
        let t = tally(&vec![Outcome::Reset; 8]);
        assert_eq!(mechanism(&t, &[]), Mechanism::ResetInjection);
    }

    #[test]
    fn all_timeouts_is_a_silent_drop() {
        let t = tally(&vec![Outcome::Timeout; 8]);
        assert_eq!(mechanism(&t, &[]), Mechanism::SilentDrop);
    }

    /// Turkcell mobile closes rather than resetting; that is still a silent drop, and it needs
    /// a different countermeasure from an injector.
    #[test]
    fn closes_count_as_a_silent_drop() {
        let t = tally(&vec![Outcome::Closed; 8]);
        assert_eq!(mechanism(&t, &[]), Mechanism::SilentDrop);
    }

    #[test]
    fn everything_succeeding_is_not_blocked() {
        let t = tally(&vec![Outcome::Ok; 8]);
        assert_eq!(mechanism(&t, &[]), Mechanism::Open);
    }

    /// A plaintext answer on 443 is an interception, and must not be filed as a reset just
    /// because the tally is not all-success.
    #[test]
    fn a_plaintext_answer_is_an_interception() {
        let t = tally(&vec![Outcome::TlsError; 8]);
        assert_eq!(
            mechanism(&t, &["not-tls".to_string()]),
            Mechanism::Interception
        );
    }

    /// Partial success is never "open" — the project's rule is that flaky is failure.
    #[test]
    fn partial_success_is_not_open() {
        let mut v = vec![Outcome::Ok; 4];
        v.extend(vec![Outcome::Reset; 4]);
        assert_eq!(mechanism(&tally(&v), &[]), Mechanism::ResetInjection);
    }

    #[test]
    fn an_empty_tally_is_unknown() {
        assert_eq!(mechanism(&Tally::default(), &[]), Mechanism::Unknown);
    }

    // ------------------------------------------------------------------ ttl sweep

    #[test]
    fn the_injector_is_found_at_the_first_ttl_that_resets() {
        let quiet = tally(&vec![Outcome::Timeout; 5]);
        let loud = tally(&vec![Outcome::Reset; 5]);
        let samples = vec![
            (1, quiet.clone()),
            (2, quiet.clone()),
            (3, loud.clone()),
            (4, loud.clone()),
            (5, loud),
        ];
        assert_eq!(dpi_hop(&samples), Some(3));
    }

    /// Order must not matter: the sweep is sorted before it is read.
    #[test]
    fn the_answer_does_not_depend_on_sample_order() {
        let quiet = tally(&vec![Outcome::Timeout; 5]);
        let loud = tally(&vec![Outcome::Reset; 5]);
        let samples = vec![(4, loud.clone()), (1, quiet.clone()), (3, loud), (2, quiet)];
        assert_eq!(dpi_hop(&samples), Some(3));
    }

    /// If every TTL we tried already resets, the injector is closer than we looked and the
    /// honest answer is "do not know" — not "1".
    #[test]
    fn resets_at_every_ttl_is_inconclusive_not_hop_one() {
        let loud = tally(&vec![Outcome::Reset; 5]);
        let samples = vec![(1, loud.clone()), (2, loud.clone()), (3, loud)];
        assert_eq!(
            dpi_hop(&samples),
            None,
            "must not claim a distance it did not bracket"
        );
    }

    #[test]
    fn no_reset_anywhere_is_inconclusive() {
        let quiet = tally(&vec![Outcome::Timeout; 5]);
        let samples = vec![(1, quiet.clone()), (2, quiet.clone()), (3, quiet)];
        assert_eq!(dpi_hop(&samples), None);
    }

    #[test]
    fn an_empty_sweep_is_inconclusive() {
        assert_eq!(dpi_hop(&[]), None);
    }

    /// A single stray reset at a low TTL must not be read as the injector's distance.
    #[test]
    fn a_minority_of_resets_does_not_locate_the_injector() {
        let mut noisy = vec![Outcome::Timeout; 4];
        noisy.push(Outcome::Reset);
        let loud = tally(&vec![Outcome::Reset; 5]);
        let samples = vec![(1, tally(&noisy)), (2, loud)];
        assert_eq!(dpi_hop(&samples), Some(2));
    }

    // ------------------------------------------------------------------- median

    #[test]
    fn median_ignores_a_single_outlier() {
        assert_eq!(median(&[2, 2, 3, 2, 900]), Some(2));
        assert_eq!(median(&[5]), Some(5));
        assert_eq!(median(&[]), None);
    }

    // ------------------------------------------------------------------ controls

    #[test]
    fn a_failed_control_voids_the_run() {
        let rs = vec![
            result(Phase::Control, "example.com", &vec![Outcome::Reset; 6]),
            result(Phase::Baseline, "discord.com", &vec![Outcome::Reset; 8]),
        ];
        assert!(!controls_passed(&rs));
        let text = render(&Context::default(), &rs, &[]);
        assert!(text.contains("RUN IS VOID"), "{text}");
    }

    #[test]
    fn passing_controls_do_not_void_the_run() {
        let rs = vec![
            result(Phase::Control, "example.com", &vec![Outcome::Ok; 6]),
            result(Phase::Baseline, "discord.com", &vec![Outcome::Reset; 8]),
        ];
        assert!(controls_passed(&rs));
        assert!(!render(&Context::default(), &rs, &[]).contains("RUN IS VOID"));
    }

    /// A run with no controls at all must be treated as void, not as trivially passing.
    #[test]
    fn a_run_with_no_controls_is_void() {
        let rs = vec![result(
            Phase::Baseline,
            "discord.com",
            &vec![Outcome::Reset; 8],
        )];
        assert!(!controls_passed(&rs));
    }

    // -------------------------------------------------------------------- render

    #[test]
    fn the_report_states_what_it_contains_and_what_it_does_not() {
        let rs = vec![result(Phase::Control, "example.com", &vec![Outcome::Ok; 6])];
        let text = render(&Context::default(), &rs, &[]);
        assert!(text.contains("No personal data"));
        assert!(
            text.contains("not\n            the address of the machine this ran on"),
            "the report must say it does not carry the runner's address: {text}"
        );
    }

    #[test]
    fn every_result_appears_in_the_raw_section() {
        let rs = vec![
            result(Phase::Control, "example.com", &vec![Outcome::Ok; 6]),
            result(Phase::Baseline, "discord.com", &vec![Outcome::Reset; 8]),
            result(Phase::Baseline, "roblox.com", &vec![Outcome::Timeout; 8]),
        ];
        let text = render(&Context::default(), &rs, &[]);
        for r in &rs {
            assert!(
                text.contains(&r.cell.key()),
                "{} missing from RAW",
                r.cell.key()
            );
        }
    }

    #[test]
    fn the_same_inputs_always_render_the_same_text() {
        let rs = vec![result(
            Phase::Baseline,
            "discord.com",
            &vec![Outcome::Reset; 8],
        )];
        let ctx = Context {
            tool_version: "v".into(),
            timestamp: "t".into(),
            platform: "p".into(),
            network: "n".into(),
            host_warning: String::new(),
        };
        assert_eq!(render(&ctx, &rs, &[]), render(&ctx, &rs, &[]));

        // The host warning belongs above everything measured, because it decides whether the
        // rest can be read at all.
        let warned = Context {
            host_warning: "*** GEÇERLİ DEĞİL ***\n\n".into(),
            ..ctx.clone()
        };
        let text = render(&warned, &rs, &[]);
        let warn_at = text.find("GEÇERLİ DEĞİL").expect("warning present");
        let first_section = text.find("1. WHAT IS BLOCKED").expect("section present");
        assert!(warn_at < first_section, "{text}");
    }

    #[test]
    fn rendering_an_empty_run_does_not_panic() {
        let text = render(&Context::default(), &[], &[]);
        assert!(text.contains("RUN IS VOID"));
    }
}
