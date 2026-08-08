//! Turning k-of-N trial results into a conclusion.
//!
//! The rule exists because single observations lie on this network. An 8-trial run has
//! already inverted two conclusions that single trials got backwards, in opposite
//! directions. Published measurements put the Turkish DPI's fail-open rate at ~16.5 %
//! against a global average of 1.68 %.
//!
//! So: partial success is a **failure**, not a partial win.

use core::fmt;

/// What a single connection attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Full TLS handshake plus an HTTP status line came back.
    Ok,
    /// Connection reset — the signature of RST injection on this line.
    Reset,
    /// Nothing came back before the deadline: silent drop or throttling.
    Timeout,
    /// Peer closed cleanly without responding.
    Closed,
    /// TLS-layer failure that is not a reset (bad cert, alert, protocol error).
    TlsError,
    /// Anything else, kept as text so it shows up in reports instead of being swallowed.
    Other(String),
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Ok)
    }

    /// Short stable label for tables.
    pub fn label(&self) -> &str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Reset => "rst",
            Outcome::Timeout => "timeout",
            Outcome::Closed => "closed",
            Outcome::TlsError => "tls-err",
            Outcome::Other(_) => "other",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Other(s) => write!(f, "other({s})"),
            o => f.write_str(o.label()),
        }
    }
}

/// The conclusion drawn from `k` successes out of `n` trials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every trial succeeded. The only result that may be called "works".
    Reliable,
    /// Some succeeded, some did not. **Treat as failure** — see module docs.
    Flaky,
    /// No trial succeeded.
    Blocked,
    /// Fewer trials than the minimum, so no conclusion is permitted.
    Inconclusive,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Reliable => "RELIABLE",
            Verdict::Flaky => "flaky",
            Verdict::Blocked => "blocked",
            Verdict::Inconclusive => "inconclusive",
        })
    }
}

/// Minimum trials before any conclusion is allowed.
pub const MIN_TRIALS: usize = 5;

/// Classify `k` successes out of `n` trials.
///
/// Anything below [`MIN_TRIALS`] is [`Verdict::Inconclusive`] no matter how clean it looks —
/// the point is to make "I tried it once and it worked" unrepresentable.
pub fn verdict(k: usize, n: usize) -> Verdict {
    if n < MIN_TRIALS {
        return Verdict::Inconclusive;
    }
    match k {
        0 => Verdict::Blocked,
        k if k == n => Verdict::Reliable,
        _ => Verdict::Flaky,
    }
}

/// Tally of outcomes for one (target, strategy) cell.
#[derive(Debug, Clone, Default)]
pub struct Tally {
    pub outcomes: Vec<Outcome>,
}

impl Tally {
    pub fn push(&mut self, o: Outcome) {
        self.outcomes.push(o);
    }

    pub fn trials(&self) -> usize {
        self.outcomes.len()
    }

    pub fn successes(&self) -> usize {
        self.outcomes.iter().filter(|o| o.is_ok()).count()
    }

    /// The conclusion, with one guard the free function cannot make on its own.
    ///
    /// A cell in which **no trial ever reached the network** says nothing about the network.
    /// [`Outcome::Other`] is what the rig reports when it could not build or send a flight at
    /// all — a requested ClientHello below the smallest one the builder can make, a DNS
    /// failure — and calling that `blocked` manufactures censorship out of a typo. That is not
    /// hypothetical: asking `vigil-scan` for a 175 B hello, 46 B under the floor for that
    /// hostname, printed `0/8 blocked` for a host that answers 20/20 at every reachable size,
    /// and it printed it as the confirmation of a standing hypothesis.
    pub fn verdict(&self) -> Verdict {
        if !self.outcomes.is_empty() && self.outcomes.iter().all(|o| matches!(o, Outcome::Other(_)))
        {
            return Verdict::Inconclusive;
        }
        verdict(self.successes(), self.trials())
    }

    /// Counts per outcome label, sorted by label so output is stable across runs.
    pub fn breakdown(&self) -> Vec<(String, usize)> {
        let mut acc: Vec<(String, usize)> = Vec::new();
        for o in &self.outcomes {
            let l = o.label().to_string();
            match acc.iter_mut().find(|(k, _)| *k == l) {
                Some((_, c)) => *c += 1,
                None => acc.push((l, 1)),
            }
        }
        acc.sort_by(|a, b| a.0.cmp(&b.0));
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_success_is_reliable() {
        assert_eq!(verdict(5, 5), Verdict::Reliable);
        assert_eq!(verdict(8, 8), Verdict::Reliable);
    }

    #[test]
    fn no_success_is_blocked() {
        assert_eq!(verdict(0, 5), Verdict::Blocked);
    }

    #[test]
    fn partial_success_is_flaky_not_success() {
        for k in 1..5 {
            assert_eq!(verdict(k, 5), Verdict::Flaky, "k={k}");
        }
        // The real measurement that motivated this rule: 5/8 and 4/8 are NOT wins.
        assert_eq!(verdict(5, 8), Verdict::Flaky);
        assert_eq!(verdict(4, 8), Verdict::Flaky);
    }

    /// A single lucky trial must never be reportable as a result.
    #[test]
    fn too_few_trials_is_inconclusive_even_when_perfect() {
        assert_eq!(verdict(1, 1), Verdict::Inconclusive);
        assert_eq!(verdict(4, 4), Verdict::Inconclusive);
        assert_eq!(verdict(0, 0), Verdict::Inconclusive);
        assert_eq!(verdict(0, 3), Verdict::Inconclusive);
    }

    #[test]
    fn min_trials_boundary_is_five() {
        assert_eq!(verdict(4, 4), Verdict::Inconclusive);
        assert_eq!(verdict(5, 5), Verdict::Reliable);
    }

    #[test]
    fn tally_counts_and_concludes() {
        let mut t = Tally::default();
        for _ in 0..5 {
            t.push(Outcome::Ok);
        }
        assert_eq!(t.trials(), 5);
        assert_eq!(t.successes(), 5);
        assert_eq!(t.verdict(), Verdict::Reliable);
    }

    #[test]
    fn tally_breakdown_is_stable_and_complete() {
        let mut t = Tally::default();
        t.push(Outcome::Ok);
        t.push(Outcome::Reset);
        t.push(Outcome::Reset);
        t.push(Outcome::Timeout);
        t.push(Outcome::Ok);
        assert_eq!(t.successes(), 2);
        assert_eq!(t.verdict(), Verdict::Flaky);
        assert_eq!(
            t.breakdown(),
            vec![("ok".into(), 2), ("rst".into(), 2), ("timeout".into(), 1)]
        );
        // every trial is accounted for
        assert_eq!(
            t.breakdown().iter().map(|(_, c)| c).sum::<usize>(),
            t.trials()
        );
    }

    /// The regression this guard exists for: a cell that never reached the network must not
    /// be reportable as censorship. Measured 2026-08-05 — a below-minimum ClientHello length
    /// printed `0/8 blocked` for `updates.discord.com`, which answers 20/20 at 221 B.
    #[test]
    fn a_cell_that_never_reached_the_network_concludes_nothing() {
        let mut t = Tally::default();
        for _ in 0..8 {
            t.push(Outcome::Other("build: too small, minimum is 221".into()));
        }
        assert_eq!(t.successes(), 0);
        assert_eq!(
            t.verdict(),
            Verdict::Inconclusive,
            "0/8 that never left the rig is not a blocked host"
        );

        // and the same for a rig-side DNS failure
        let mut t = Tally::default();
        for _ in 0..5 {
            t.push(Outcome::Other("dns".into()));
        }
        assert_eq!(t.verdict(), Verdict::Inconclusive);
    }

    /// But one real network answer is enough to make the cell about the network again —
    /// otherwise the guard would start hiding genuine blocks behind rig noise.
    #[test]
    fn one_real_outcome_makes_the_cell_conclusive_again() {
        let mut t = Tally::default();
        for _ in 0..7 {
            t.push(Outcome::Other("build: too small".into()));
        }
        t.push(Outcome::Reset);
        assert_eq!(t.verdict(), Verdict::Blocked);

        let mut t = Tally::default();
        for _ in 0..7 {
            t.push(Outcome::Other("build: too small".into()));
        }
        t.push(Outcome::Ok);
        assert_eq!(t.verdict(), Verdict::Flaky);
    }

    #[test]
    fn only_ok_counts_as_success() {
        for o in [
            Outcome::Reset,
            Outcome::Timeout,
            Outcome::Closed,
            Outcome::TlsError,
            Outcome::Other("boom".into()),
        ] {
            assert!(!o.is_ok(), "{o} must not count as success");
        }
        assert!(Outcome::Ok.is_ok());
    }
}
