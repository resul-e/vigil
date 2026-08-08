//! What to measure, as pure data.
//!
//! The plan is built before anything touches the network, so it can be inspected and tested.
//! The rule the tests enforce is the one that keeps a report meaningful: **no phase may exist
//! without a control in the same run.** A table where everything failed is indistinguishable
//! from a broken rig unless something that must succeed did.

/// Hosts believed blocked on Turkish consumer lines. On an unknown ISP these are candidates,
/// not assumptions — the report says what the data said, and a candidate that turns out to be
/// reachable is a finding rather than an error.
pub const CANDIDATES: &[&str] = &[
    "discord.com",
    "updates.discord.com",
    "cdn.discordapp.com",
    "roblox.com",
    "protonvpn.com",
    "4chan.org",
    "nordvpn.com",
];

/// Must be reachable everywhere. If one of these fails the run is void, not interesting.
pub const CONTROLS: &[&str] = &["example.com", "media.discordapp.net", "wikipedia.org"];

/// Strategies to try against whatever turns out to be blocked. `none` is first so the table
/// always carries its own baseline.
/// `none` is first so the table always carries its own baseline. The `tlsrec` sizes are
/// there because Superonline yielded to record fragmentation and to nothing else, so where
/// its boundary lies is now a question worth an answer rather than a curiosity.
pub const STRATEGIES: &[&str] = &[
    "none",
    "split:1",
    "split:2",
    "split:1,2,3",
    "split:1@15",
    "tlsrec:8",
    "tlsrec:64",
    "tlsrec:64+split:1",
    "split:midsld",
];

/// ClientHello sizes to sweep. Chosen around the MSS boundary, which is where this line was
/// measured to change behaviour: one segment is blocked outright, two segments are a coin
/// flip, and a byte-1 split is reliable.
pub const SIZES: &[usize] = &[250, 400, 800, 1200, 1400, 1460, 1500, 1800, 2200];

/// Largest TTL worth trying when locating an on-path injector. Turkish DPI has been reported
/// at hops 2-4; beyond about a dozen we are past the ISP's own network and learning nothing.
pub const MAX_TTL: u32 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Is it blocked at all, and how does it fail?
    Baseline,
    /// The same address, asked for a permitted name: name-based or address-based?
    SameAddress,
    /// Which strategy defeats it.
    Strategy,
    /// Does the ClientHello's length alone change the answer.
    Size,
    /// How far away the injector is.
    Ttl,
    /// Must succeed, or the run is void.
    Control,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Baseline => "baseline",
            Phase::SameAddress => "same-address",
            Phase::Strategy => "strategy",
            Phase::Size => "size",
            Phase::Ttl => "ttl",
            Phase::Control => "control",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub phase: Phase,
    /// The SNI to send.
    pub host: String,
    /// Send it to this host's address instead of its own. The same-address control.
    pub via_host_addr: Option<String>,
    pub strategy: String,
    pub client_hello_len: Option<usize>,
    pub ttl: Option<u32>,
    pub trials: usize,
    /// Which pass this cell belongs to. The only thing separating the control that opens a
    /// run from the one that closes it — and without it the two share a key and the closing
    /// one silently overwrites the opening one in the report, hiding a mid-run failure.
    pub round: u8,
}

impl Cell {
    /// A stable key, so two runs on two ISPs can be lined up column by column.
    pub fn key(&self) -> String {
        let mut k = format!("{}/{}/{}", self.phase.label(), self.host, self.strategy);
        if let Some(n) = self.client_hello_len {
            k.push_str(&format!("/len{n}"));
        }
        if let Some(t) = self.ttl {
            k.push_str(&format!("/ttl{t}"));
        }
        if let Some(v) = &self.via_host_addr {
            k.push_str(&format!("/via:{v}"));
        }
        if self.round > 0 {
            k.push_str(&format!("/round{}", self.round));
        }
        k
    }
}

/// How thorough to be. The friend running this is doing us a favour; a run that takes twenty
/// minutes will be cancelled halfway and tell us nothing.
#[derive(Debug, Clone, Copy)]
pub struct Depth {
    pub baseline_trials: usize,
    pub strategy_trials: usize,
    pub size_trials: usize,
    pub ttl_trials: usize,
    pub control_trials: usize,
}

impl Default for Depth {
    fn default() -> Self {
        // Every count is at or above vigil_core::MIN_TRIALS, so no cell can produce a verdict
        // the project's own rules forbid.
        Depth {
            baseline_trials: 8,
            strategy_trials: 10,
            size_trials: 8,
            ttl_trials: 5,
            control_trials: 6,
        }
    }
}

/// Phase 1: what is blocked, and what do the controls do.
///
/// Split from the rest because the later phases only make sense against a host that phase 1
/// showed to be blocked — sweeping eight strategies against a reachable host is a waste of the
/// runner's patience.
pub fn discovery(d: Depth) -> Vec<Cell> {
    let mut cells = Vec::new();
    for h in CONTROLS {
        cells.push(Cell {
            phase: Phase::Control,
            host: (*h).to_string(),
            via_host_addr: None,
            strategy: "none".into(),
            client_hello_len: None,
            ttl: None,
            trials: d.control_trials,
            round: 0,
        });
    }
    for h in CANDIDATES {
        cells.push(Cell {
            phase: Phase::Baseline,
            host: (*h).to_string(),
            via_host_addr: None,
            strategy: "none".into(),
            client_hello_len: None,
            ttl: None,
            trials: d.baseline_trials,
            round: 0,
        });
    }
    cells
}

/// Phase 2: everything that only makes sense once we know what is blocked.
///
/// `blocked` is what discovery actually found, not what we hoped to find.
/// Whether a TTL sweep can learn anything here.
///
/// The sweep finds the smallest TTL at which an injected reset appears. A censor that
/// silently drops — which is what Superonline does — produces a timeout at every TTL,
/// indistinguishable from the packet expiring on the way. Running it anyway costs the
/// volunteer two minutes and returns "inconclusive", which is worse than not asking.
pub fn ttl_sweep_can_work(baseline_resets: bool) -> bool {
    baseline_resets
}

/// Which of [`SIZES`] can actually be built for `host`, and which cannot.
///
/// A ClientHello's floor grows with the hostname, so a long name can put the low end of the
/// sweep out of reach. Those cells used to run anyway and fail to build, which read as
/// `blocked` in the table — the network being blamed for the rig's arithmetic. They are
/// dropped here instead, and the caller says out loud which ones were dropped: a size sweep
/// that quietly measured fewer sizes than it printed would be the same lie one layer up.
pub fn sizes_for(host: &str) -> (Vec<usize>, Vec<usize>) {
    let min = vigil_core::synth::min_len(host).unwrap_or(0);
    SIZES.iter().copied().partition(|n| *n >= min)
}

pub fn investigation(blocked: &[String], ttl_useful: bool, d: Depth) -> Vec<Cell> {
    let mut cells = Vec::new();
    if blocked.is_empty() {
        return cells;
    }

    // Name or address? Ask each blocked host's own address for a permitted name.
    for h in blocked {
        cells.push(Cell {
            phase: Phase::SameAddress,
            host: CONTROLS[0].to_string(),
            via_host_addr: Some(h.clone()),
            strategy: "none".into(),
            client_hello_len: None,
            ttl: None,
            trials: d.control_trials,
            round: 0,
        });
    }

    // Which strategy works. Two blocked hosts is enough to see whether the answer generalises
    // without doubling the runtime for every extra one.
    for h in blocked.iter().take(2) {
        for s in STRATEGIES {
            cells.push(Cell {
                phase: Phase::Strategy,
                host: h.clone(),
                via_host_addr: None,
                strategy: (*s).to_string(),
                client_hello_len: None,
                ttl: None,
                trials: d.strategy_trials,
                round: 0,
            });
        }
    }

    // Does length alone decide it. One host: this is about the network, not the host.
    let first = &blocked[0];
    for n in &sizes_for(first).0 {
        cells.push(Cell {
            phase: Phase::Size,
            host: first.clone(),
            via_host_addr: None,
            strategy: "none".into(),
            client_hello_len: Some(*n),
            ttl: None,
            trials: d.size_trials,
            round: 0,
        });
    }

    // How far away the injector is — but only where there is something to find.
    for t in (1..=MAX_TTL).filter(|_| ttl_useful) {
        cells.push(Cell {
            phase: Phase::Ttl,
            host: first.clone(),
            via_host_addr: None,
            strategy: "none".into(),
            client_hello_len: None,
            ttl: Some(t),
            trials: d.ttl_trials,
            round: 0,
        });
    }

    // A control at the end, so a run that degraded halfway is visible.
    cells.push(Cell {
        phase: Phase::Control,
        host: CONTROLS[0].to_string(),
        via_host_addr: None,
        strategy: "none".into(),
        client_hello_len: None,
        ttl: None,
        trials: d.control_trials,
        round: 1,
    });
    cells
}

/// Roughly how many connections a plan will open. Used to tell the runner how long it will
/// take before it starts, which is the difference between a run that finishes and one that
/// gets cancelled.
pub fn connections(cells: &[Cell]) -> usize {
    cells.iter().map(|c| c.trials).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::strategy::Strategy;
    use vigil_core::MIN_TRIALS;

    fn blocked() -> Vec<String> {
        vec!["discord.com".to_string(), "roblox.com".to_string()]
    }

    /// The rule that keeps a report from lying: a run must contain something that has to
    /// succeed, at the start and at the end.
    #[test]
    fn every_run_carries_controls() {
        let d = Depth::default();
        let disc = discovery(d);
        assert!(
            disc.iter().any(|c| c.phase == Phase::Control),
            "discovery has no control: a fully blocked table would be unreadable"
        );
        let inv = investigation(&blocked(), true, d);
        assert!(
            inv.iter().any(|c| c.phase == Phase::Control),
            "investigation has no closing control"
        );
    }

    /// No cell may be below the project's minimum, or it would produce a verdict the rules
    /// forbid and the report would have to say "inconclusive" for it.
    #[test]
    fn no_cell_is_below_the_minimum_trial_count() {
        let d = Depth::default();
        for c in discovery(d)
            .into_iter()
            .chain(investigation(&blocked(), true, d))
        {
            assert!(
                c.trials >= MIN_TRIALS,
                "{} has {} trials, below the minimum {MIN_TRIALS}",
                c.key(),
                c.trials
            );
        }
    }

    /// Every strategy string in the plan must parse, or the run would silently fall back to
    /// passthrough and report that splitting does not help.
    #[test]
    fn every_strategy_in_the_plan_parses() {
        for s in STRATEGIES {
            Strategy::parse(s).unwrap_or_else(|e| panic!("{s:?} does not parse: {e}"));
        }
        let d = Depth::default();
        for c in discovery(d)
            .into_iter()
            .chain(investigation(&blocked(), true, d))
        {
            Strategy::parse(&c.strategy)
                .unwrap_or_else(|e| panic!("{} has bad strategy: {e}", c.key()));
        }
    }

    /// Nothing downstream should ever have to deduplicate; two cells with the same key would
    /// silently overwrite each other in the report.
    #[test]
    fn cell_keys_are_unique() {
        let d = Depth::default();
        let all: Vec<Cell> = discovery(d)
            .into_iter()
            .chain(investigation(&blocked(), true, d))
            .collect();
        let mut keys: Vec<String> = all.iter().map(|c| c.key()).collect();
        let before = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate cell keys in the plan");
    }

    /// If discovery finds nothing blocked there is nothing to investigate, and the tool must
    /// say so rather than sweeping strategies against a network that is not filtering.
    #[test]
    fn nothing_blocked_means_nothing_to_investigate() {
        assert!(investigation(&[], true, Depth::default()).is_empty());
    }

    #[test]
    fn the_strategy_sweep_always_includes_its_own_baseline() {
        let inv = investigation(&blocked(), true, Depth::default());
        for h in blocked() {
            let has_none = inv
                .iter()
                .any(|c| c.phase == Phase::Strategy && c.host == h && c.strategy == "none");
            assert!(
                has_none,
                "{h} strategy sweep has no `none` arm to compare against"
            );
        }
    }

    /// The same-address control must ask a *permitted* name, otherwise it measures nothing.
    #[test]
    fn the_same_address_control_uses_a_control_hostname() {
        for c in investigation(&blocked(), true, Depth::default())
            .iter()
            .filter(|c| c.phase == Phase::SameAddress)
        {
            assert!(
                CONTROLS.contains(&c.host.as_str()),
                "{} asks a blocked name, so it cannot separate name from address",
                c.key()
            );
            assert!(c.via_host_addr.is_some());
        }
    }

    #[test]
    fn the_ttl_sweep_starts_at_one_and_is_contiguous() {
        let ttls: Vec<u32> = investigation(&blocked(), true, Depth::default())
            .iter()
            .filter_map(|c| c.ttl)
            .collect();
        assert_eq!(ttls, (1..=MAX_TTL).collect::<Vec<_>>());
    }

    /// The size sweep must straddle the MSS boundary, which is the only place the answer was
    /// ever observed to change.
    #[test]
    fn the_size_sweep_straddles_the_mss() {
        assert!(SIZES.iter().any(|n| *n < 1460));
        assert!(SIZES.iter().any(|n| *n > 1460));
    }

    /// A size the builder cannot reach must never become a cell. It used to: the trials failed
    /// to build and the table called the host `blocked`, which is the network being blamed for
    /// the rig's arithmetic.
    #[test]
    fn the_size_sweep_drops_sizes_this_hostname_cannot_reach() {
        let long = format!("{}.example.com", "a".repeat(200));
        let (reachable, unreachable) = sizes_for(&long);
        let min = vigil_core::synth::min_len(&long).unwrap();
        assert!(
            !unreachable.is_empty(),
            "min {min} should exclude something"
        );
        assert!(unreachable.iter().all(|n| *n < min));
        assert!(reachable.iter().all(|n| *n >= min));
        assert_eq!(reachable.len() + unreachable.len(), SIZES.len());

        let cells = investigation(&[long], false, Depth::default());
        for c in cells.iter().filter(|c| c.phase == Phase::Size) {
            assert!(
                c.client_hello_len.unwrap_or(0) >= min,
                "planned an unbuildable {:?} B cell",
                c.client_hello_len
            );
        }

        // and an ordinary hostname loses nothing
        let (reachable, unreachable) = sizes_for("discord.com");
        assert!(unreachable.is_empty(), "dropped {unreachable:?}");
        assert_eq!(reachable, SIZES.to_vec());
    }

    /// A run the friend will actually sit through.
    #[test]
    fn a_full_run_is_bounded() {
        let d = Depth::default();
        let total = connections(&discovery(d)) + connections(&investigation(&blocked(), true, d));
        assert!(
            total < 500,
            "{total} connections is more than anyone will wait for"
        );
    }

    /// A silent-drop network must not be made to sit through a sweep that cannot answer.
    #[test]
    fn the_ttl_sweep_is_skipped_where_it_cannot_learn_anything() {
        let d = Depth::default();
        let with = investigation(&blocked(), true, d);
        let without = investigation(&blocked(), false, d);
        assert!(with.iter().any(|c| c.ttl.is_some()));
        assert!(
            !without.iter().any(|c| c.ttl.is_some()),
            "a silent dropper produces a timeout at every TTL; asking wastes two minutes"
        );
        assert!(
            connections(&without) < connections(&with),
            "skipping must actually save the volunteer time"
        );
        // and everything else is still there
        for phase in [
            Phase::SameAddress,
            Phase::Strategy,
            Phase::Size,
            Phase::Control,
        ] {
            assert!(without.iter().any(|c| c.phase == phase), "{phase:?} lost");
        }
    }

    #[test]
    fn candidates_and_controls_do_not_overlap() {
        for c in CANDIDATES {
            assert!(
                !CONTROLS.contains(c),
                "{c} is both a candidate and a control"
            );
        }
    }
}
