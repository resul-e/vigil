//! Turning a Unix timestamp into something a person can read. Pure.
//!
//! Fifteen lines rather than a dependency, because this binary is handed to someone else and
//! the shorter its dependency list, the easier it is to believe it does what it says.

/// Civil date from days since the Unix epoch. Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD HH:MM:SS UTC` from seconds since the Unix epoch.
pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_itself() {
        assert_eq!(iso8601(0), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn known_timestamps() {
        assert_eq!(iso8601(1_000_000_000), "2001-09-09 01:46:40 UTC");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    /// Leap years are exactly the sort of thing a hand-rolled date routine gets wrong, and a
    /// report stamped with the wrong day is a report that cannot be lined up with another.
    #[test]
    fn leap_days_land_correctly() {
        // 2024-02-29T00:00:00Z
        assert_eq!(iso8601(1_709_164_800), "2024-02-29 00:00:00 UTC");
        // 2000-02-29T00:00:00Z — a century that IS a leap year
        assert_eq!(iso8601(951_782_400), "2000-02-29 00:00:00 UTC");
        // 2100 is not a leap year: 2100-03-01T00:00:00Z
        assert_eq!(iso8601(4_107_542_400), "2100-03-01 00:00:00 UTC");
    }

    #[test]
    fn end_of_day_does_not_roll_over_early() {
        assert_eq!(iso8601(86_399), "1970-01-01 23:59:59 UTC");
        assert_eq!(iso8601(86_400), "1970-01-02 00:00:00 UTC");
    }

    #[test]
    fn month_boundaries() {
        assert_eq!(iso8601(1_704_067_199), "2023-12-31 23:59:59 UTC");
        assert_eq!(iso8601(1_704_067_200), "2024-01-01 00:00:00 UTC");
    }

    /// It must never panic, whatever it is handed.
    #[test]
    fn extremes_do_not_panic() {
        for s in [0u64, 1, u32::MAX as u64, u64::MAX / 2, 253_402_300_799] {
            let out = iso8601(s);
            assert!(out.contains("UTC"), "{s} -> {out}");
        }
    }
}
