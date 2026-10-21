//! Calendar arithmetic for certificate times, so the crate needs no date library.
//!
//! Howard Hinnant's civil-date algorithms, proleptic Gregorian, UTC only.

/// Days since 1970-01-01 of the given civil date.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day, hour, minute, second)` of a Unix time.
pub fn civil(unix: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, secs / 3600, secs % 3600 / 60, secs % 60)
}

/// The current Unix time.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// `2026-10-21 12:34:56 UTC`.
pub fn format(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil(1_792_586_096), (2026, 10, 21, 12, 34, 56));
        assert_eq!(civil(-1), (1969, 12, 31, 23, 59, 59));
        assert_eq!(format(1_792_586_096), "2026-10-21 12:34:56 UTC");
    }

    #[test]
    fn leap_years() {
        // 1900 was not a leap year, 2000 was, 2100 will not be.
        for (y, leap) in [(1900, false), (2000, true), (2024, true), (2100, false), (2026, false)] {
            let march1 = days_from_civil(y, 3, 1);
            let feb28 = days_from_civil(y, 2, 28);
            assert_eq!(march1 - feb28, if leap { 2 } else { 1 }, "{y}");
        }
    }

    #[test]
    fn round_trip_over_a_wide_range() {
        let mut t = -4_000_000_000i64;
        while t < 8_000_000_000 {
            let (y, mo, d, h, mi, s) = civil(t);
            assert_eq!(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s, t);
            t += 86_399 * 7 + 13;
        }
    }
}
