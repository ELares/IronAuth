// SPDX-License-Identifier: MIT OR Apache-2.0

//! `xsd:dateTime` as SAML uses it, parsed to epoch seconds (issue #139).
//!
//! # Why this crate parses its own timestamps
//!
//! Every value here arrives inside a document an attacker composed, and this crate's whole
//! discipline is to refuse what it does not implement rather than to accept broadly and hope. A
//! general date library accepts a very large grammar -- offsets, week dates, ordinal dates,
//! two-digit years, locale quirks -- and every one of those is a shape two implementations can
//! disagree about. What SAML actually requires is one narrow form.
//!
//! # The form, and what is refused
//!
//! `YYYY-MM-DDThh:mm:ss[.fraction]Z`. SAML 2.0 Core section 1.3.3 requires UTC with no offset,
//! spelled `Z`, and this refuses everything else:
//!
//! - AN OFFSET LIKE `+01:00` IS REFUSED, not converted. Converting is where two implementations
//!   drift, and an assertion whose validity depends on which side did the arithmetic is one
//!   nobody can reason about. The specification says `Z`, so `Z` is what is accepted.
//! - A FRACTION IS PARSED AND DISCARDED. Sub-second precision cannot matter to a window measured
//!   in minutes, and the alternative -- refusing it -- would reject identity providers that emit
//!   it, which many do.
//! - NO LEAP SECONDS. A `:60` is refused rather than clamped: clamping would make two distinct
//!   instants compare equal.
//! - NEGATIVE AND EXPANDED YEARS ARE REFUSED. `-0001` and `12345` are legal `xsd:dateTime` and
//!   are not something an identity provider means.

/// Seconds in a minute, an hour and a day.
const MINUTE: i64 = 60;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;

/// Days before the start of each month in a non-leap year.
const MONTH_START: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// Whether `year` has a 29th of February.
const fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in `month` (1-based) of `year`.
const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from the epoch to the first of `year`.
fn days_to_year(year: i64) -> i64 {
    // COUNTED FROM 1970 IN BOTH DIRECTIONS rather than with a closed form, because the closed
    // forms for this are exactly the kind of thing that is subtly wrong for one century in four
    // hundred and is never noticed. The bounded year range below keeps the loop short.
    let mut days = 0;
    if year >= 1970 {
        for y in 1970..year {
            days += if is_leap(y) { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            days -= if is_leap(y) { 366 } else { 365 };
        }
    }
    days
}

/// The years this accepts. Wide enough for any certificate or assertion, narrow enough that the
/// day count above is a short loop and that a nonsense year is refused rather than computed.
const MIN_YEAR: i64 = 1900;
const MAX_YEAR: i64 = 2200;

/// Parse `xsd:dateTime` in the one form SAML requires, to seconds since the Unix epoch.
///
/// # Errors
///
/// `None` for anything outside `YYYY-MM-DDThh:mm:ssZ` with an optional fraction: an offset, a
/// missing `Z`, a leap second, a day that does not exist in that month, a year outside
/// [`MIN_YEAR`]..=[`MAX_YEAR`], or any character where a digit belongs.
#[must_use]
pub fn parse_utc(raw: &str) -> Option<i64> {
    let bytes = raw.as_bytes();
    // The shortest legal form is exactly 20 bytes: `1970-01-01T00:00:00Z`.
    if bytes.len() < 20 {
        return None;
    }
    // POSITIONAL, not split-based. A split on `-` would accept `1970-1-1T...`, which is not the
    // format and which two parsers pad differently.
    let digits = |from: usize, len: usize| -> Option<i64> {
        let slice = bytes.get(from..from + len)?;
        if !slice.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut value: i64 = 0;
        for byte in slice {
            value = value * 10 + i64::from(byte - b'0');
        }
        Some(value)
    };
    let literal = |at: usize, expected: u8| -> Option<()> {
        (bytes.get(at).copied() == Some(expected)).then_some(())
    };

    let year = digits(0, 4)?;
    literal(4, b'-')?;
    let month = digits(5, 2)?;
    literal(7, b'-')?;
    let day = digits(8, 2)?;
    literal(10, b'T')?;
    let hour = digits(11, 2)?;
    literal(13, b':')?;
    let minute = digits(14, 2)?;
    literal(16, b':')?;
    let second = digits(17, 2)?;

    // THE TAIL IS EITHER `Z` OR A FRACTION THEN `Z`. Anything else -- an offset, trailing text,
    // a second fraction -- is refused rather than ignored: trailing bytes a parser ignores are
    // bytes another parser might read.
    let tail = &bytes[19..];
    match tail {
        [b'Z'] => {}
        [b'.', rest @ ..] => {
            let [fraction @ .., b'Z'] = rest else {
                return None;
            };
            if fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit) {
                return None;
            }
        }
        _ => return None,
    }

    if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
        return None;
    }
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // `24:00:00` is legal `xsd:dateTime` and means the next midnight. REFUSED rather than
    // normalised, because it is one instant with two spellings and no identity provider emits it.
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut days = days_to_year(year) + MONTH_START[usize::try_from(month).ok()? - 1] + (day - 1);
    if month > 2 && is_leap(year) {
        days += 1;
    }
    Some(days * DAY + hour * HOUR + minute * MINUTE + second)
}
