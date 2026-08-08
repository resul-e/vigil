//! Which hosts get a strategy and which are left alone.
//!
//! The exclude list is not an optimisation, it is a safety rail. Turkish banking and
//! government sites break under desync, and "your tool broke my banking" is the single most
//! common complaint against tools in this space. `com.tr` and `gov.tr` are excluded out of
//! the box for that reason, and it takes a deliberate edit to remove them.
//!
//! Precedence is fixed: **exclude wins**. If a host matches both lists it is left alone. A
//! rule that can be overridden by another rule is a rule nobody can reason about.

use core::fmt;

/// One matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Exactly this host.
    Exact(String),
    /// This host and anything under it: `com.tr` matches `x.com.tr` and `com.tr` itself.
    Suffix(String),
}

impl Pattern {
    /// Parse one line. A leading `.` or `*.` means "and everything under it".
    ///
    /// Order matters here: the wildcard prefix is stripped **before** the trailing dot,
    /// because trimming first turns `*.` into `*`, which then looks like an ordinary
    /// hostname. Any `*` surviving the prefix step is rejected rather than taken literally —
    /// someone who types `*` or `a*b.com` means a wildcard we do not implement, and quietly
    /// matching nothing would be worse than saying so.
    pub fn parse(s: &str) -> Option<Pattern> {
        let s = s.trim().to_ascii_lowercase();
        let (wild, rest) = match s.strip_prefix("*.").or_else(|| s.strip_prefix('.')) {
            Some(r) => (true, r),
            None => (false, s.as_str()),
        };
        let rest = rest.trim_end_matches('.');
        if rest.is_empty() || rest.contains('*') {
            return None;
        }
        Some(if wild {
            Pattern::Suffix(rest.to_string())
        } else {
            Pattern::Exact(rest.to_string())
        })
    }

    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        match self {
            Pattern::Exact(p) => h == *p,
            Pattern::Suffix(p) => h == *p || h.ends_with(&format!(".{p}")),
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pattern::Exact(p) => f.write_str(p),
            Pattern::Suffix(p) => write!(f, "*.{p}"),
        }
    }
}

/// Hosts excluded by default. Removing one takes a deliberate edit.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    // Turkish banking and government break under desync. This is the number one
    // "your tool broke my internet" report for tools in this space.
    "*.com.tr",
    "*.gov.tr",
    "*.edu.tr",
    "*.org.tr",
    // Loopback and link-local never need help and must never be delayed.
    "localhost",
    "*.local",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRules {
    exclude: Vec<Pattern>,
    /// When present, only these hosts get a strategy; everything else is passed through.
    include: Option<Vec<Pattern>>,
}

impl Default for HostRules {
    fn default() -> Self {
        HostRules {
            exclude: DEFAULT_EXCLUDES
                .iter()
                .filter_map(|s| Pattern::parse(s))
                .collect(),
            include: None,
        }
    }
}

impl HostRules {
    /// No rules at all — every host gets a strategy. Only useful in tests.
    pub fn permissive() -> Self {
        HostRules {
            exclude: Vec::new(),
            include: None,
        }
    }

    pub fn with_exclude(mut self, pats: impl IntoIterator<Item = Pattern>) -> Self {
        self.exclude.extend(pats);
        self
    }

    pub fn with_include(mut self, pats: impl IntoIterator<Item = Pattern>) -> Self {
        self.include = Some(pats.into_iter().collect());
        self
    }

    pub fn excludes(&self) -> &[Pattern] {
        &self.exclude
    }

    /// Should this host get a strategy applied?
    ///
    /// Exclude always wins. An empty include list means "nothing is eligible", which is a
    /// legitimate way to turn the tool off without stopping it.
    pub fn applies_to(&self, host: &str) -> bool {
        if self.exclude.iter().any(|p| p.matches(host)) {
            return false;
        }
        match &self.include {
            Some(inc) => inc.iter().any(|p| p.matches(host)),
            None => true,
        }
    }

    /// Parse a list file: one pattern per line, `#` comments, blank lines ignored.
    pub fn parse_list(text: &str) -> (Vec<Pattern>, Vec<String>) {
        let mut pats = Vec::new();
        let mut bad = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            match Pattern::parse(line) {
                Some(p) => pats.push(p),
                None => bad.push(format!("line {}: {line:?}", n + 1)),
            }
        }
        (pats, bad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------ patterns

    #[test]
    fn an_exact_pattern_matches_only_itself() {
        let p = Pattern::parse("discord.com").unwrap();
        assert!(p.matches("discord.com"));
        assert!(p.matches("DISCORD.COM"));
        assert!(p.matches("discord.com."));
        assert!(!p.matches("cdn.discord.com"));
        assert!(!p.matches("notdiscord.com"));
    }

    #[test]
    fn a_suffix_pattern_matches_the_apex_and_everything_under_it() {
        for spelling in ["*.com.tr", ".com.tr"] {
            let p = Pattern::parse(spelling).unwrap();
            assert!(p.matches("com.tr"), "{spelling}: apex");
            assert!(p.matches("garanti.com.tr"), "{spelling}");
            assert!(p.matches("www.garanti.com.tr"), "{spelling}");
            assert!(
                !p.matches("notcom.tr"),
                "{spelling}: must not match a substring"
            );
            assert!(
                !p.matches("com.tr.evil.com"),
                "{spelling}: must not match a prefix"
            );
        }
    }

    #[test]
    fn a_suffix_never_matches_a_host_that_merely_ends_with_the_letters() {
        let p = Pattern::parse("*.example.com").unwrap();
        assert!(!p.matches("notexample.com"));
        assert!(!p.matches("myexample.com"));
        assert!(p.matches("a.example.com"));
        assert!(p.matches("example.com"));
    }

    #[test]
    fn empty_and_degenerate_patterns_are_rejected() {
        for bad in ["", "   ", ".", "*.", "*", "\t"] {
            assert!(Pattern::parse(bad).is_none(), "{bad:?} should not parse");
        }
    }

    // ------------------------------------------------------------ the safety rail

    /// The reason this module exists.
    #[test]
    fn turkish_banking_and_government_are_excluded_by_default() {
        let r = HostRules::default();
        for host in [
            "garanti.com.tr",
            "www.isbank.com.tr",
            "turkiye.gov.tr",
            "www.turkiye.gov.tr",
            "ziraatbank.com.tr",
            "odtu.edu.tr",
            "tsk.org.tr",
        ] {
            assert!(
                !r.applies_to(host),
                "{host} would be desynced; Turkish banking and government break under it"
            );
        }
    }

    #[test]
    fn the_hosts_the_tool_exists_for_are_not_excluded() {
        let r = HostRules::default();
        for host in [
            "discord.com",
            "updates.discord.com",
            "roblox.com",
            "www.roblox.com",
            "protonvpn.com",
            "4chan.org",
        ] {
            assert!(r.applies_to(host), "{host} would be skipped");
        }
    }

    #[test]
    fn loopback_and_link_local_are_left_alone() {
        let r = HostRules::default();
        assert!(!r.applies_to("localhost"));
        assert!(!r.applies_to("printer.local"));
    }

    /// Exclude beats include, always. A rule that another rule can override is a rule nobody
    /// can reason about.
    #[test]
    fn exclude_wins_over_include() {
        let r = HostRules::default().with_include([Pattern::parse("*.com.tr").unwrap()]);
        assert!(
            !r.applies_to("garanti.com.tr"),
            "an include must not resurrect an excluded host"
        );
    }

    #[test]
    fn an_include_list_makes_everything_else_ineligible() {
        let r = HostRules::permissive().with_include([
            Pattern::parse("discord.com").unwrap(),
            Pattern::parse("*.roblox.com").unwrap(),
        ]);
        assert!(r.applies_to("discord.com"));
        assert!(r.applies_to("web.roblox.com"));
        assert!(!r.applies_to("example.com"));
    }

    #[test]
    fn an_empty_include_list_turns_everything_off_without_erroring() {
        let r = HostRules::permissive().with_include([]);
        for host in ["discord.com", "example.com", "anything.at.all"] {
            assert!(!r.applies_to(host));
        }
    }

    #[test]
    fn with_no_rules_at_all_every_host_is_eligible() {
        let r = HostRules::permissive();
        assert!(r.applies_to("discord.com"));
        assert!(r.applies_to("garanti.com.tr"));
    }

    #[test]
    fn a_user_exclusion_is_honoured() {
        let r = HostRules::default().with_exclude([Pattern::parse("*.mybank.example").unwrap()]);
        assert!(!r.applies_to("login.mybank.example"));
        assert!(r.applies_to("discord.com"));
    }

    // ------------------------------------------------------------ list files

    #[test]
    fn parses_a_list_file_with_comments_and_blanks() {
        let text = "\
# hosts to leave alone
*.com.tr        # banking
discord.com

  .gov.tr
";
        let (pats, bad) = HostRules::parse_list(text);
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(pats.len(), 3);
        assert!(pats.contains(&Pattern::Suffix("com.tr".into())));
        assert!(pats.contains(&Pattern::Exact("discord.com".into())));
        assert!(pats.contains(&Pattern::Suffix("gov.tr".into())));
    }

    #[test]
    fn a_bad_line_is_reported_and_the_rest_still_load() {
        let (pats, bad) = HostRules::parse_list("discord.com\n*.\nroblox.com\n");
        assert_eq!(pats.len(), 2, "good lines must survive a bad one");
        assert_eq!(bad.len(), 1);
    }

    #[test]
    fn patterns_round_trip_through_their_text_form() {
        for text in ["discord.com", "*.com.tr", "*.gov.tr"] {
            let p = Pattern::parse(text).unwrap();
            let back = Pattern::parse(&p.to_string()).unwrap();
            assert_eq!(back, p, "{text}");
        }
    }

    #[test]
    fn arbitrary_hostnames_never_panic() {
        let r = HostRules::default();
        let mut seed = 0x9E3779B9u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let n = (next() % 40) as usize;
            let s: String = (0..n)
                .map(|_| char::from(b'\x20' + (next() % 90) as u8))
                .collect();
            let _ = r.applies_to(&s);
            let _ = Pattern::parse(&s);
        }
    }
}
