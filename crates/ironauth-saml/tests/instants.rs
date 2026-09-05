// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `xsd:dateTime` parser, driven against values rather than against itself (issue #139).
//!
//! # Why a hand-written parser gets its own suite
//!
//! It decides whether an assertion is inside its validity window, so every way it can be wrong is
//! a way a captured assertion stays usable or a genuine one is refused. And it parses bytes an
//! attacker composed, so the interesting cases are the malformed ones.
//!
//! The epoch values here are DERIVED FROM ARITHMETIC STATED IN THE TEST, not from running the
//! parser and writing down what it said. A suite whose expectations came from the code under test
//! would agree with any bug it had.
//!
//! Needs no database.

use ironauth_saml::parse_utc;

/// Seconds in a day.
const DAY: i64 = 86_400;

#[test]
fn the_epoch_and_the_days_around_it() {
    // The one value everything else is measured from.
    assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_utc("1970-01-02T00:00:00Z"), Some(DAY));
    assert_eq!(parse_utc("1969-12-31T00:00:00Z"), Some(-DAY));
    // Time of day is seconds, minutes and hours, added.
    assert_eq!(parse_utc("1970-01-01T01:02:03Z"), Some(3600 + 2 * 60 + 3));
}

#[test]
fn a_leap_day_is_a_day_and_a_skipped_one_is_not() {
    // 2000 is a leap year (divisible by 400), 1900 is not (divisible by 100 and not 400), and
    // getting that backwards is the classic calendar bug -- worth a test because the rule is
    // stated in one place and read in two.
    assert!(parse_utc("2000-02-29T00:00:00Z").is_some());
    assert!(
        parse_utc("1900-02-29T00:00:00Z").is_none(),
        "1900 is not a leap year"
    );
    assert!(
        parse_utc("2026-02-29T00:00:00Z").is_none(),
        "2026 is not a leap year"
    );
    assert!(parse_utc("2024-02-29T00:00:00Z").is_some());

    // AND THE LEAP DAY SHIFTS EVERYTHING AFTER IT. A parser that accepted the 29th and then did
    // not count it would put every later date in that year one day early.
    let feb28 = parse_utc("2024-02-28T00:00:00Z").expect("valid");
    let mar01 = parse_utc("2024-03-01T00:00:00Z").expect("valid");
    assert_eq!(mar01 - feb28, 2 * DAY, "the leap day was not counted");
    let feb28 = parse_utc("2026-02-28T00:00:00Z").expect("valid");
    let mar01 = parse_utc("2026-03-01T00:00:00Z").expect("valid");
    assert_eq!(mar01 - feb28, DAY, "a day was counted that does not exist");
}

#[test]
fn a_month_ends_where_the_calendar_says() {
    assert!(
        parse_utc("2026-04-31T00:00:00Z").is_none(),
        "April has 30 days"
    );
    assert!(parse_utc("2026-04-30T00:00:00Z").is_some());
    assert!(parse_utc("2026-01-32T00:00:00Z").is_none());
    assert!(parse_utc("2026-13-01T00:00:00Z").is_none());
    assert!(parse_utc("2026-00-01T00:00:00Z").is_none());
    assert!(parse_utc("2026-01-00T00:00:00Z").is_none());
}

#[test]
fn an_offset_is_refused_rather_than_converted() {
    // SAML 2.0 Core section 1.3.3 requires UTC spelled `Z`. Converting an offset is where two
    // implementations drift, and an assertion whose validity depends on which side did the
    // arithmetic is one nobody can reason about.
    assert!(parse_utc("2026-01-01T00:00:00+01:00").is_none());
    assert!(parse_utc("2026-01-01T00:00:00-05:00").is_none());
    assert!(
        parse_utc("2026-01-01T00:00:00").is_none(),
        "a timestamp with no zone at all is not UTC, it is unstated"
    );
}

#[test]
fn a_fraction_is_accepted_and_ignored() {
    // Many identity providers emit one, and sub-second precision cannot matter to a window
    // measured in minutes. Refusing it would reject them; reading it would imply a precision the
    // comparison does not have.
    let plain = parse_utc("2026-01-01T00:00:00Z").expect("valid");
    assert_eq!(parse_utc("2026-01-01T00:00:00.000Z"), Some(plain));
    assert_eq!(parse_utc("2026-01-01T00:00:00.123456789Z"), Some(plain));
    // But a fraction has to have digits, and has to end in `Z`.
    assert!(parse_utc("2026-01-01T00:00:00.Z").is_none());
    assert!(parse_utc("2026-01-01T00:00:00.123").is_none());
    assert!(parse_utc("2026-01-01T00:00:00.12.3Z").is_none());
}

#[test]
fn a_leap_second_and_a_midnight_of_twenty_four_are_refused() {
    // Both are legal in some readings and neither is something an identity provider emits.
    // Clamping `:60` would make two distinct instants compare equal; normalising `24:00:00` would
    // give one instant two spellings.
    assert!(parse_utc("2026-06-30T23:59:60Z").is_none());
    assert!(parse_utc("2026-01-01T24:00:00Z").is_none());
    assert!(parse_utc("2026-01-01T00:60:00Z").is_none());
}

#[test]
fn a_year_outside_the_accepted_range_is_refused() {
    assert!(parse_utc("1899-12-31T00:00:00Z").is_none());
    assert!(parse_utc("2201-01-01T00:00:00Z").is_none());
    assert!(parse_utc("1900-01-01T00:00:00Z").is_some());
    assert!(parse_utc("2200-01-01T00:00:00Z").is_some());
}

#[test]
fn anything_that_is_not_the_one_form_is_refused() {
    // A SPLIT-BASED PARSER WOULD ACCEPT MOST OF THESE. Unpadded fields, the wrong separators,
    // trailing bytes: each is a shape two parsers read differently, which is the whole reason
    // this one is positional.
    for malformed in [
        "",
        "Z",
        "2026-1-1T00:00:00Z",
        "2026/01/01T00:00:00Z",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:00Z ",
        "2026-01-01T00:00:00ZZ",
        "2026-01-01T00:00:00Zjunk",
        "20260101T000000Z",
        "not-a-date-at-all!!!!",
        "2026-01-01T0a:00:00Z",
        "+2026-01-01T00:00:00Z",
        "-2026-01-01T00:00:00Z",
    ] {
        assert!(
            parse_utc(malformed).is_none(),
            "{malformed:?} was parsed as a timestamp"
        );
    }
}

#[test]
fn a_known_instant_matches_arithmetic_stated_here() {
    // 2026-01-01T00:00:00Z, derived here rather than copied from the parser -- and the LEAP
    // COUNT is derived too. Writing `let leaps = 14;` would be the same defect one level down: a
    // number this test asserts against, hand-computed by the same person who wrote the parser,
    // agreeing with it for whatever reason they both got it wrong.
    let years: i64 = 2026 - 1970;
    let leaps: i64 = (1970..2026)
        .filter(|year| (year % 4 == 0 && year % 100 != 0) || year % 400 == 0)
        .count()
        .try_into()
        .expect("fifty-six years hold fewer leap days than an i64");
    assert_eq!(
        leaps, 14,
        "the Gregorian rule as spelled here counts a different number"
    );
    let expected = (years * 365 + leaps) * DAY;
    assert_eq!(
        parse_utc("2026-01-01T00:00:00Z"),
        Some(expected),
        "the epoch arithmetic and the parser disagree"
    );
}
