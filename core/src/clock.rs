//! Civil dates, both directions, pure and dependency-free.
//!
//! Lived in `scan/` while only one direction was needed — a Unix timestamp printed into a report
//! header. The update manifest needs the other direction, because it carries an expiry date and
//! a client has to decide whether it has passed. Two implementations of a calendar in one
//! workspace is how two parts of a program come to disagree about what day it is, so it moved
//! here, where the rest of the dependency-free logic is.
//!
//! Howard Hinnant's `civil_from_days` / `days_from_civil`, which are exact for the whole proleptic
//! Gregorian calendar and short enough to read.
//!
//! **No clock.** Nothing here asks the operating system what time it is; the caller passes `now`
//! in. That is what lets the expiry check be tested at all — a trust decision that reads the
//! clock itself can only be tested on the day the test was written.

/// Civil date from days since the Unix epoch.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
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

/// Days since the Unix epoch from a civil date. The exact inverse of [`civil_from_days`].
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
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

/// Parse exactly `YYYY-MM-DDTHH:MM:SSZ` into seconds since the Unix epoch.
///
/// **Exactly** that. No offsets, no fractional seconds, no lowercase `t` or `z`, no missing
/// seconds, no leap second. This reads a *signed* manifest, and every liberty a parser takes is
/// a way for the thing that was signed and the thing that was understood to differ. RFC 3339 in
/// full is a large grammar; the manifest writer is a script in this repository, and it can emit
/// one shape.
pub fn parse_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = s.get(from..to)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);

    // Range-check before converting, so an impossible date is rejected rather than normalised.
    // `days_from_civil` will happily accept month 13 and hand back a plausible number, which is
    // how "2026-13-01" would silently become February.
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    // And check the round trip, which is what catches 31 February.
    if civil_from_days(days) != (y, mo as u32, d as u32) {
        return None;
    }
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + (h as u64) * 3600 + (mi as u64) * 60 + sec as u64)
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
        assert_eq!(iso8601(1_709_164_800), "2024-02-29 00:00:00 UTC");
        // A century that IS a leap year.
        assert_eq!(iso8601(951_782_400), "2000-02-29 00:00:00 UTC");
        // 2100 is not.
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

    #[test]
    fn extremes_do_not_panic() {
        for s in [0u64, 1, u32::MAX as u64, u64::MAX / 2, 253_402_300_799] {
            assert!(iso8601(s).contains("UTC"), "{s}");
        }
    }

    /// The two directions are each other's inverse, across four centuries and every leap rule.
    #[test]
    fn the_two_directions_are_inverses() {
        for days in -100_000i64..100_000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
    }

    #[test]
    fn parsing_a_timestamp_agrees_with_printing_one() {
        for secs in [
            0u64,
            86_399,
            86_400,
            1_000_000_000,
            1_700_000_000,
            1_709_164_800,
            951_782_400,
            4_107_542_400,
        ] {
            let printed = iso8601(secs);
            // Rebuild the strict form the manifest uses from the readable one.
            let rfc = format!("{}T{}Z", &printed[..10], &printed[11..19]);
            assert_eq!(parse_utc(&rfc), Some(secs), "{rfc}");
        }
    }

    /// Every shape this refuses, and why refusing matters: it reads a signed file, so a parser
    /// that guesses is a parser that can disagree with the signer.
    #[test]
    fn the_parser_refuses_everything_that_is_not_the_exact_shape() {
        // Cross-checked with `date -u -d "2026-11-12T00:00:00Z" +%s`, not with this module.
        assert_eq!(parse_utc("2026-11-12T00:00:00Z"), Some(1_794_441_600));
        for bad in [
            "",
            "2026-11-12",
            "2026-11-12T00:00:00",       // no Z
            "2026-11-12T00:00:00+03:00", // an offset
            "2026-11-12t00:00:00z",      // lowercase
            "2026-11-12T00:00:00.5Z",    // fractional
            "2026-11-12T00:00Z",         // no seconds
            "2026-1-12T00:00:00Z",       // unpadded
            " 2026-11-12T00:00:00Z",
            "2026-11-12T00:00:00Z ",
            "2026-13-01T00:00:00Z", // month 13
            "2026-00-01T00:00:00Z", // month 0
            "2026-02-30T00:00:00Z", // no such day
            "2026-02-31T00:00:00Z",
            "2025-02-29T00:00:00Z", // not a leap year
            "2026-11-32T00:00:00Z",
            "2026-11-12T24:00:00Z", // hour 24
            "2026-11-12T00:60:00Z",
            "2026-11-12T00:00:60Z", // leap second
            "1969-12-31T23:59:59Z", // before the epoch
            "abcd-11-12T00:00:00Z",
            "2026-11-12T00:00:0AZ",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad:?} should not parse");
        }
        // The one leap day that is real.
        assert!(parse_utc("2024-02-29T00:00:00Z").is_some());
    }

    /// It must never panic on arbitrary input, because the input arrives over a network.
    #[test]
    fn the_parser_never_panics() {
        let base = "2026-11-12T00:00:00Z";
        for i in 0..base.len() {
            for b in [0u8, 1, b'-', b'/', 0x7f, 0xff, b'9', b'a'] {
                let mut bytes = base.as_bytes().to_vec();
                bytes[i] = b;
                if let Ok(s) = core::str::from_utf8(&bytes) {
                    let _ = parse_utc(s);
                }
            }
        }
        for s in ["\u{0}", "🕐", &"9".repeat(1000), &"-".repeat(20)] {
            let _ = parse_utc(s);
        }
    }
}
