//! `major.minor.patch`, and nothing else.
//!
//! Used for two comparisons that decide whether an update happens: is the offered version newer
//! than the running one, and is the running one at least the manifest's `min_version`. Both are
//! trust decisions, so the parser refuses anything it is not certain about rather than guessing —
//! a pre-release suffix or a fourth component would have to be *ordered*, and inventing an order
//! for something the release process never emits is how a client ends up refusing a real update
//! or accepting a stale one.

/// A release version. Ordered the obvious way, which is what `derive(Ord)` gives for a tuple of
/// three numbers in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    /// Exactly three dot-separated decimal numbers. No `v` prefix, no suffix, no leading zeros
    /// beyond a bare `0`, no whitespace.
    pub fn parse(s: &str) -> Option<Version> {
        let mut parts = s.split('.');
        let mut next = || -> Option<u32> {
            let p = parts.next()?;
            if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            // `01` is not a version component. Allowing it would mean two spellings of the same
            // version, and the manifest is signed — two spellings is two things to compare.
            if p.len() > 1 && p.starts_with('0') {
                return None;
            }
            p.parse().ok()
        };
        let v = Version {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        // A fourth component means this is not the shape we understand.
        if parts.next().is_some() {
            return None;
        }
        Some(v)
    }

    /// The version of the binary doing the asking, from `CARGO_PKG_VERSION`.
    ///
    /// Panics only if the workspace version stops being three numbers, which would be a build
    /// mistake rather than a runtime one — and failing loudly at startup beats a client that
    /// silently believes it is version 0.0.0 and accepts any `min_version`.
    pub fn running() -> Version {
        Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("the workspace version must be major.minor.patch")
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ordinary_shape_parses_and_round_trips() {
        let v = Version::parse("0.7.0").expect("parses");
        assert_eq!(v, Version::new(0, 7, 0));
        assert_eq!(v.to_string(), "0.7.0");
        assert_eq!(Version::parse("10.20.30"), Some(Version::new(10, 20, 30)));
        assert_eq!(Version::parse("0.0.0"), Some(Version::new(0, 0, 0)));
    }

    /// Ordering is the whole point: it decides whether an update is offered.
    #[test]
    fn versions_order_by_component() {
        let v = |s: &str| Version::parse(s).expect(s);
        assert!(v("0.7.0") > v("0.6.3"));
        assert!(v("0.6.10") > v("0.6.9"), "not string ordering");
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("0.6.3") == v("0.6.3"));
        assert!(v("0.6.3") < v("0.6.4"));
    }

    #[test]
    fn everything_that_is_not_three_numbers_is_refused() {
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "1.2.3-rc1",
            "1.2.3+build",
            " 1.2.3",
            "1.2.3 ",
            "1..3",
            ".1.2",
            "1.2.",
            "a.b.c",
            "1.2.x",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "-1.2.3",
            "1.2.-3",
            "999999999999.0.0",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?} should not parse");
        }
    }

    /// The workspace version has to be readable, or the client cannot tell whether it satisfies
    /// a `min_version` and would have to guess.
    #[test]
    fn the_running_version_is_readable() {
        let v = Version::running();
        assert_eq!(v.to_string(), env!("CARGO_PKG_VERSION"));
        assert!(v > Version::new(0, 0, 0));
    }
}
