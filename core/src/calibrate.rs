//! Strategy selection and the per-host cache.
//!
//! Pure: this module decides *what to try next* and *what a run of results means*. It never
//! opens a socket. The caller performs the trials and feeds outcomes back in, which is what
//! makes the selection logic testable without a network.
//!
//! The rule that shapes everything here: Turkish DPI fails open on roughly 16.5 % of
//! identical probes against a global average of 1.68 %, so a single success proves nothing.
//! A strategy is accepted only after N consecutive successes, and a strategy that is
//! *sometimes* right is treated as wrong.

use core::fmt;
use std::collections::BTreeMap;

use crate::strategy::Strategy;

/// Consecutive successes required before a strategy is accepted.
pub const CONFIRM: usize = 5;
/// Consecutive failures before the current strategy is abandoned and the sweep resumes.
pub const ABANDON: usize = 3;

/// What one trial did, from the calibrator's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trial {
    Reached,
    Failed,
}

/// Where the sweep currently stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Keep testing this strategy.
    Testing {
        strategy: Strategy,
        consecutive: usize,
    },
    /// This strategy earned [`CONFIRM`] consecutive successes.
    Settled { strategy: Strategy },
    /// Every candidate was tried and none confirmed.
    Exhausted,
}

/// Sweeps candidates in order, requiring a run of consecutive successes.
#[derive(Debug, Clone)]
pub struct Calibrator {
    candidates: Vec<Strategy>,
    index: usize,
    consecutive: usize,
    settled: Option<Strategy>,
}

impl Calibrator {
    pub fn new(candidates: Vec<Strategy>) -> Self {
        Calibrator {
            candidates,
            index: 0,
            consecutive: 0,
            settled: None,
        }
    }

    pub fn with_builtin_candidates() -> Self {
        Calibrator::new(crate::strategy::candidates())
    }

    /// The strategy to use for the next trial, or `None` once the sweep is exhausted.
    pub fn current(&self) -> Option<&Strategy> {
        if let Some(s) = &self.settled {
            return Some(s);
        }
        self.candidates.get(self.index)
    }

    pub fn progress(&self) -> Progress {
        if let Some(s) = &self.settled {
            return Progress::Settled {
                strategy: s.clone(),
            };
        }
        match self.candidates.get(self.index) {
            Some(s) => Progress::Testing {
                strategy: s.clone(),
                consecutive: self.consecutive,
            },
            None => Progress::Exhausted,
        }
    }

    pub fn is_settled(&self) -> bool {
        self.settled.is_some()
    }

    /// Feed back the outcome of one trial with [`Calibrator::current`].
    ///
    /// A failure resets the run to zero rather than decrementing: five successes and a
    /// failure is not "four successes", it is a strategy that does not hold.
    pub fn record(&mut self, t: Trial) -> Progress {
        if self.settled.is_some() {
            return self.progress();
        }
        match t {
            Trial::Reached => {
                self.consecutive += 1;
                if self.consecutive >= CONFIRM {
                    if let Some(s) = self.candidates.get(self.index) {
                        self.settled = Some(s.clone());
                    }
                }
            }
            Trial::Failed => {
                self.consecutive = 0;
                self.index += 1;
            }
        }
        self.progress()
    }

    /// The settled strategy, if the sweep converged.
    pub fn result(&self) -> Option<&Strategy> {
        self.settled.as_ref()
    }
}

/// Per-host record of what worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub strategy: Strategy,
    /// Consecutive failures seen since it was confirmed. At [`ABANDON`] the entry is dropped
    /// and the host is recalibrated.
    pub recent_failures: usize,
}

/// What worked for which host, persisted as text a human can read and paste.
///
/// A cache keyed on an opaque struct is a cache nobody can diff or put in a bug report, so
/// the on-disk form is one `host strategy` pair per line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cache {
    entries: BTreeMap<String, Entry>,
}

impl Cache {
    pub fn new() -> Self {
        Cache::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, host: &str) -> Option<&Strategy> {
        self.entries.get(&normalise(host)).map(|e| &e.strategy)
    }

    pub fn insert(&mut self, host: &str, strategy: Strategy) {
        self.entries.insert(
            normalise(host),
            Entry {
                strategy,
                recent_failures: 0,
            },
        );
    }

    /// Report a success for `host`, clearing any accumulated failures.
    pub fn record_success(&mut self, host: &str) {
        if let Some(e) = self.entries.get_mut(&normalise(host)) {
            e.recent_failures = 0;
        }
    }

    /// Report a failure. Returns `true` when the entry was dropped and the host needs
    /// recalibrating.
    pub fn record_failure(&mut self, host: &str) -> bool {
        let key = normalise(host);
        let Some(e) = self.entries.get_mut(&key) else {
            return false;
        };
        e.recent_failures += 1;
        if e.recent_failures >= ABANDON {
            self.entries.remove(&key);
            return true;
        }
        false
    }

    /// Drop one host so it is calibrated again from scratch.
    pub fn forget(&mut self, host: &str) -> bool {
        self.entries.remove(&normalise(host)).is_some()
    }

    /// Drop everything learned.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    /// Serialise to the on-disk form.
    pub fn to_text(&self) -> String {
        let mut out = String::from("# vigil strategy cache — one `host strategy` per line\n");
        for (host, e) in &self.entries {
            out.push_str(host);
            out.push(' ');
            out.push_str(&e.strategy.to_string());
            out.push('\n');
        }
        out
    }

    /// Parse the on-disk form. Unparseable lines are skipped rather than fatal: a cache is a
    /// hint, and a corrupt one must never stop the tool from starting.
    pub fn from_text(s: &str) -> (Cache, Vec<String>) {
        let mut c = Cache::new();
        let mut skipped = Vec::new();
        for (n, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((host, spec)) = line.split_once(char::is_whitespace) else {
                skipped.push(format!("line {}: no strategy", n + 1));
                continue;
            };
            match Strategy::parse(spec.trim()) {
                Ok(s) => c.insert(host.trim(), s),
                Err(e) => skipped.push(format!("line {}: {e}", n + 1)),
            }
        }
        (c, skipped)
    }
}

impl fmt::Display for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// Hostnames are compared case-insensitively and without a trailing dot.
fn normalise(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strat(s: &str) -> Strategy {
        Strategy::parse(s).expect("test strategy parses")
    }

    // ------------------------------------------------------------ calibrator

    #[test]
    fn a_single_success_never_settles() {
        let mut c = Calibrator::with_builtin_candidates();
        let p = c.record(Trial::Reached);
        assert!(
            matches!(p, Progress::Testing { consecutive: 1, .. }),
            "one success must not be a conclusion, got {p:?}"
        );
        assert!(!c.is_settled());
    }

    #[test]
    fn settles_only_after_the_full_run_of_successes() {
        let mut c = Calibrator::with_builtin_candidates();
        for i in 1..CONFIRM {
            c.record(Trial::Reached);
            assert!(!c.is_settled(), "settled after only {i} successes");
        }
        c.record(Trial::Reached);
        assert!(c.is_settled(), "did not settle after {CONFIRM} successes");
    }

    /// The rule that motivated the whole module: an interrupted run is not a partial win.
    #[test]
    fn a_failure_resets_the_run_to_zero() {
        let mut c = Calibrator::new(vec![strat("split:1"), strat("split:2")]);
        for _ in 0..CONFIRM - 1 {
            c.record(Trial::Reached);
        }
        c.record(Trial::Failed);
        assert!(!c.is_settled());
        match c.progress() {
            Progress::Testing {
                consecutive,
                strategy,
            } => {
                assert_eq!(consecutive, 0, "run was not reset");
                assert_eq!(strategy, strat("split:2"), "did not advance to the next");
            }
            other => panic!("expected Testing, got {other:?}"),
        }
    }

    #[test]
    fn a_failure_advances_to_the_next_candidate() {
        let mut c = Calibrator::new(vec![strat("split:1"), strat("split:2"), strat("tlsrec:64")]);
        assert_eq!(c.current(), Some(&strat("split:1")));
        c.record(Trial::Failed);
        assert_eq!(c.current(), Some(&strat("split:2")));
        c.record(Trial::Failed);
        assert_eq!(c.current(), Some(&strat("tlsrec:64")));
    }

    #[test]
    fn exhausts_rather_than_looping_forever() {
        let mut c = Calibrator::new(vec![strat("split:1"), strat("split:2")]);
        c.record(Trial::Failed);
        c.record(Trial::Failed);
        assert_eq!(c.progress(), Progress::Exhausted);
        assert_eq!(c.current(), None);
        assert!(c.result().is_none());
        // and further failures do not panic or wrap
        c.record(Trial::Failed);
        assert_eq!(c.progress(), Progress::Exhausted);
    }

    #[test]
    fn once_settled_it_stays_settled() {
        let mut c = Calibrator::new(vec![strat("split:1"), strat("split:2")]);
        for _ in 0..CONFIRM {
            c.record(Trial::Reached);
        }
        let chosen = c.result().cloned().expect("settled");
        c.record(Trial::Failed);
        assert_eq!(c.result(), Some(&chosen), "a later failure unsettled it");
    }

    /// The sweep must open with the candidate that works on the most measured networks, not
    /// the one that works best on the developer's. `split:1` is 20/20 on the home line and
    /// **0/10** on SansürOn; `tlsrec:64+split:1` is 10/10 on both. Starting anywhere else
    /// costs half the country a burnt connection before the calibrator moves on.
    #[test]
    fn the_first_candidate_tried_is_the_one_measured_on_the_most_networks() {
        let c = Calibrator::with_builtin_candidates();
        assert_eq!(
            c.current().map(|s| s.to_string()),
            Some("tlsrec:64+split:1".to_string())
        );
    }

    /// Whatever the order, every candidate that has been measured to work somewhere must
    /// still be in the list — reordering must never quietly drop one.
    #[test]
    fn the_candidates_measured_to_work_are_all_present() {
        let all: Vec<String> = crate::candidates().iter().map(|s| s.to_string()).collect();
        for wanted in ["tlsrec:64+split:1", "tlsrec:64", "split:1", "split:2"] {
            assert!(all.contains(&wanted.to_string()), "{wanted} was dropped");
        }
    }

    /// `split:midsld` measured 2/10 on the home line and 0/10 on SansürOn. It stays in the
    /// list because it costs nothing to try last, but it must never be tried early.
    #[test]
    fn the_flakiest_candidate_is_tried_last() {
        let all: Vec<String> = crate::candidates().iter().map(|s| s.to_string()).collect();
        let mid = all.iter().position(|s| s.starts_with("split:midsld"));
        assert!(mid.is_some());
        assert!(
            mid.unwrap() >= all.len() - 2,
            "midsld is measured flaky and must not be tried early: {all:?}"
        );
    }

    #[test]
    fn an_empty_candidate_list_is_exhausted_immediately() {
        let c = Calibrator::new(vec![]);
        assert_eq!(c.progress(), Progress::Exhausted);
        assert!(c.current().is_none());
    }

    // ------------------------------------------------------------ cache

    #[test]
    fn stores_and_retrieves_per_host() {
        let mut c = Cache::new();
        c.insert("discord.com", strat("split:1"));
        c.insert("roblox.com", strat("tlsrec:64"));
        assert_eq!(c.get("discord.com"), Some(&strat("split:1")));
        assert_eq!(c.get("roblox.com"), Some(&strat("tlsrec:64")));
        assert_eq!(c.get("example.com"), None);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn hostnames_match_case_insensitively_and_ignore_a_trailing_dot() {
        let mut c = Cache::new();
        c.insert("Discord.COM.", strat("split:1"));
        for probe in [
            "discord.com",
            "DISCORD.COM",
            "discord.com.",
            " discord.com ",
        ] {
            assert_eq!(c.get(probe), Some(&strat("split:1")), "probe {probe:?}");
        }
    }

    /// The cache must survive a restart — that is its entire reason to exist.
    #[test]
    fn round_trips_through_its_text_form() {
        let mut c = Cache::new();
        c.insert("discord.com", strat("split:1"));
        c.insert("roblox.com", strat("tlsrec:64+split:1"));
        c.insert("a.example", strat("split:midsld@15"));
        let text = c.to_text();
        let (back, skipped) = Cache::from_text(&text);
        assert!(
            skipped.is_empty(),
            "clean cache reported problems: {skipped:?}"
        );
        assert_eq!(back, c, "cache did not survive a round trip");
        assert_eq!(back.to_text(), text, "serialisation is not a fixed point");
    }

    #[test]
    fn the_text_form_is_readable_and_stable() {
        let mut c = Cache::new();
        c.insert("zeta.example", strat("split:2"));
        c.insert("alpha.example", strat("split:1"));
        let t = c.to_text();
        let body: Vec<&str> = t.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            body,
            vec!["alpha.example split:1", "zeta.example split:2"],
            "entries must be sorted so the file diffs cleanly"
        );
    }

    /// A corrupt cache is a hint that went bad, never a reason to fail to start.
    #[test]
    fn a_corrupt_cache_is_skipped_line_by_line_not_fatal() {
        let text = "\
# comment
discord.com split:1
this-line-has-no-strategy
roblox.com wibble:9
bad.example tlsrec:0

good.example tlsrec:64
";
        let (c, skipped) = Cache::from_text(text);
        assert_eq!(c.get("discord.com"), Some(&strat("split:1")));
        assert_eq!(c.get("good.example"), Some(&strat("tlsrec:64")));
        assert_eq!(c.get("roblox.com"), None);
        assert_eq!(c.get("bad.example"), None);
        assert_eq!(
            skipped.len(),
            3,
            "expected three complaints, got {skipped:?}"
        );
    }

    #[test]
    fn an_empty_or_comment_only_cache_parses_to_nothing() {
        for text in ["", "\n\n", "# only a comment\n"] {
            let (c, skipped) = Cache::from_text(text);
            assert!(c.is_empty(), "{text:?}");
            assert!(skipped.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn an_entry_is_dropped_after_consecutive_failures() {
        let mut c = Cache::new();
        c.insert("discord.com", strat("split:1"));
        for i in 1..ABANDON {
            assert!(!c.record_failure("discord.com"), "dropped after {i}");
            assert!(c.get("discord.com").is_some());
        }
        assert!(c.record_failure("discord.com"), "not dropped at {ABANDON}");
        assert_eq!(c.get("discord.com"), None, "entry must be gone");
    }

    /// Intermittent failures must not evict a working strategy — only a run of them.
    #[test]
    fn a_success_clears_accumulated_failures() {
        let mut c = Cache::new();
        c.insert("discord.com", strat("split:1"));
        c.record_failure("discord.com");
        c.record_failure("discord.com");
        c.record_success("discord.com");
        assert!(
            !c.record_failure("discord.com"),
            "failures were not cleared"
        );
        assert!(c.get("discord.com").is_some());
    }

    #[test]
    fn forgetting_a_host_removes_it_and_reports_whether_it_was_there() {
        let mut c = Cache::new();
        c.insert("discord.com", strat("split:1"));
        assert!(c.forget("DISCORD.COM."), "must match case-insensitively");
        assert_eq!(c.get("discord.com"), None);
        assert!(
            !c.forget("discord.com"),
            "forgetting twice must report false"
        );
    }

    #[test]
    fn clearing_removes_everything() {
        let mut c = Cache::new();
        c.insert("a.example", strat("split:1"));
        c.insert("b.example", strat("split:2"));
        c.clear();
        assert!(c.is_empty());
    }

    #[test]
    fn reporting_on_an_unknown_host_is_harmless() {
        let mut c = Cache::new();
        assert!(!c.record_failure("nobody.example"));
        c.record_success("nobody.example");
        assert!(c.is_empty());
    }

    /// A full cycle: sweep, settle, persist, restart, reuse.
    #[test]
    fn a_settled_strategy_survives_a_simulated_restart() {
        let mut cal = Calibrator::with_builtin_candidates();
        // first candidate fails, second confirms
        cal.record(Trial::Failed);
        let second = cal.current().cloned().expect("has a second candidate");
        for _ in 0..CONFIRM {
            cal.record(Trial::Reached);
        }
        let settled = cal.result().cloned().expect("settled");
        assert_eq!(settled, second);

        let mut cache = Cache::new();
        cache.insert("discord.com", settled.clone());
        let on_disk = cache.to_text();

        // "restart"
        let (reloaded, skipped) = Cache::from_text(&on_disk);
        assert!(skipped.is_empty());
        assert_eq!(
            reloaded.get("discord.com"),
            Some(&settled),
            "the strategy did not survive the restart"
        );
    }
}
