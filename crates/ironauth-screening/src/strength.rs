// SPDX-License-Identifier: MIT OR Apache-2.0

//! A COARSE, in-tree password-strength estimator (issue #66).
//!
//! # Coarseness: what this is BLIND to (read this first)
//!
//! This is a COARSE length/charset/pattern floor, NOT a zxcvbn-equivalent guard. It is
//! BLIND to dictionary words and l33t substitution: it has no large word list and no
//! substitution model, so a word-plus-digits password like `summer2024`, `hello123`,
//! `test1234`, `company1`, or `P@ssw0rd` scores the MAXIMUM `4` here and would clear ANY
//! threshold, including a `min_password_strength_score = 4`. Do NOT set the floor
//! believing it rejects such passwords: it does not.
//!
//! The mandatory HIBP/offline breach screen that runs RIGHT AFTER this is the PRIMARY
//! defense; every one of those example passwords is in the breach corpus and is caught
//! there. This score is only a complementary length/charset floor layered in front of the
//! (network/hash-spending) screen. The config key is deliberately named
//! `min_password_strength_score` (NOT `min_zxcvbn_score`) so the name does not imply full
//! zxcvbn semantics. The real `zxcvbn` crate can be swapped in behind
//! [`PasswordPolicy::evaluate_strength`] / [`score`] once its dependency tree passes
//! cargo-deny (see below).
//!
//! # Why in-tree, not zxcvbn
//!
//! The plan proposed the `zxcvbn` crate (v3, MIT). Its cargo-deny gate FAILS under this
//! repository's constraints: zxcvbn transitively depends on `time`, and every `time`
//! version that fixes RUSTSEC-2026-0009 (a stack-exhaustion denial of service, fixed in `time >=
//! 0.3.47`) requires rustc 1.88, which breaks the MSRV 1.85 floor, while every `time <
//! 0.3.47` still carries the advisory. There is no `time` version that satisfies BOTH
//! "advisories are build failures" AND MSRV 1.85 at once, so the crate cannot be
//! admitted. Per the gate protocol, the crate is NOT forced; this is the documented
//! fallback, exposing the SAME 0-4 score contract behind the same
//! [`PasswordPolicy::evaluate_strength`] seam, so zxcvbn (or another estimator) can be
//! swapped back in later behind one function the day its tree passes the gate.
//!
//! # What it estimates
//!
//! A guessability score in `0..=4`, aligned with zxcvbn's guesses-to-score boundaries
//! (score `s` when the estimated guess count is below `10^(3), 10^6, 10^8, 10^10`, else
//! `4`). It combines:
//!
//! - A Shannon-style entropy bound `length * log2(charset)`, where `charset` is the size
//!   of the union of character classes present (lowercase, uppercase, digits, symbols,
//!   and a coarse bucket for other Unicode). `guesses = 2^entropy`.
//! - A compiled-in check for the most common passwords and simple keyboard / repeat /
//!   sequence patterns; a hit forces the score to `0` regardless of length, because such
//!   a password is trivially guessed however long it is (`password1234567` is not
//!   strong).
//!
//! It is COARSE: unlike zxcvbn it has no large dictionary and no l33t/substitution model,
//! so it OVER-credits a word-plus-digits string (e.g. `summer2024` scores the maximum `4`)
//! relative to zxcvbn. That is why it is a COMPLEMENTARY floor, not the primary defense:
//! the mandatory HIBP/offline breach screen catches actually-common passwords, and the
//! compiled-in pattern list catches the top trivially-guessed shapes. The scoring knob
//! (`min_password_strength_score`) defaults OFF, and raising it only ever TIGHTENS
//! admission.
//!
//! It is a PURE, deterministic function: no clock read, no RNG, no allocation of an
//! estimator model, so it needs no `ironauth-env` seam and is cheap enough to run inline
//! before the (network/hash-spending) breach screen.

/// The estimated password-strength score in `0..=4` (issue #66), the same contract the
/// `min_password_strength_score` policy compares against. Higher is stronger. COARSE and
/// BLIND to dictionary words / l33t substitution (a word-plus-digits password scores the
/// maximum), so the breach screen is the primary defense; see the module docs. NFKC
/// normalization is applied by the caller before this runs (like every other password
/// step).
#[must_use]
pub fn score(password: &str) -> u8 {
    // A known-weak password or an obvious pattern is score 0 no matter how long it is.
    if is_obviously_weak(password) {
        return 0;
    }
    let bits = entropy_bits(password);
    // guesses ~= 2^bits; zxcvbn's score boundaries are at 10^3 / 10^6 / 10^8 / 10^10
    // guesses. log2(10^k) = k * log2(10) = k * 3.321928..., so the bit thresholds are:
    //   score 1 at 10^3  ->  9.97 bits
    //   score 2 at 10^6  -> 19.93 bits
    //   score 3 at 10^8  -> 26.58 bits
    //   score 4 at 10^10 -> 33.22 bits
    if bits < 9.97 {
        0
    } else if bits < 19.93 {
        1
    } else if bits < 26.58 {
        2
    } else if bits < 33.22 {
        3
    } else {
        4
    }
}

/// The Shannon-style entropy upper bound in bits: `length * log2(charset)`, where the
/// charset size is the union of the character classes the password draws from. A longer
/// password over a larger alphabet is credited more, but a repeated single character is
/// discounted (its effective length is the count of DISTINCT characters), so `aaaaaaaa`
/// scores as one character's worth, not eight.
fn entropy_bits(password: &str) -> f64 {
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    let mut other = false;
    for &c in &chars {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if c.is_ascii() {
            symbol = true;
        } else {
            other = true;
        }
    }
    let mut charset = 0u32;
    if lower {
        charset += 26;
    }
    if upper {
        charset += 26;
    }
    if digit {
        charset += 10;
    }
    if symbol {
        // The printable ASCII punctuation set (a conservative ~32).
        charset += 32;
    }
    if other {
        // A coarse bucket for non-ASCII: credited modestly so a Unicode password is not
        // over-credited by assuming the whole code space.
        charset += 128;
    }
    let charset = f64::from(charset.max(1));
    // Discount trivial repetition: the effective length is the number of DISTINCT
    // characters (so `aaaaaaaaaaaaaa` is not credited as fourteen independent draws),
    // clamped to the real length.
    let distinct = distinct_count(&chars);
    let effective_len = distinct.min(chars.len());
    // f64::from is lossless for these small counts.
    let len = f64::from(u32::try_from(effective_len).unwrap_or(u32::MAX));
    len * charset.log2()
}

/// The number of DISTINCT characters in `chars` (order-independent), used to discount a
/// password that is mostly one repeated character. Uses a `HashSet` so it is O(n) in the
/// password length regardless of alphabet size: a `Vec::contains` scan would be O(n^2),
/// which an operator setting a pathological `max_length` plus a non-zero strength floor
/// could turn into CPU pressure (issue #66 INFO).
fn distinct_count(chars: &[char]) -> usize {
    let seen: std::collections::HashSet<char> = chars.iter().copied().collect();
    seen.len()
}

/// Whether `password` is OBVIOUSLY weak: a compiled-in most-common password, a common
/// password with trailing digits/symbols stripped, or an all-one-run / keyboard /
/// sequential pattern. Case-insensitive on the ASCII letters. Such a password is score 0
/// no matter its length.
fn is_obviously_weak(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    // A short password is weak by construction (too few guesses); catch it here too so a
    // tiny high-entropy-looking string does not slip a threshold.
    if lower.chars().count() < 4 {
        return true;
    }
    // A single repeated character (aaaaaa, 111111) is trivially guessed.
    if is_single_run(&lower) {
        return true;
    }
    // A monotonic keyboard/number sequence (abcdef, 123456, qwerty run).
    if is_sequential(&lower) {
        return true;
    }
    // The compiled-in common set, matched against the whole value and against the value
    // with trailing digits/symbols stripped (so `password1`, `letmein!!` are caught).
    let stripped: String = lower
        .trim_end_matches(|c: char| c.is_ascii_digit() || c.is_ascii_punctuation())
        .to_owned();
    COMMON_PASSWORDS
        .iter()
        .any(|&common| lower == common || stripped == common)
        || COMMON_PASSWORDS
            .iter()
            .any(|&common| common.len() >= 4 && lower.contains(common))
}

/// Whether the string is a single repeated character (`aaaa`, `0000`).
fn is_single_run(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first),
        None => false,
    }
}

/// Whether the string is a monotonic ASCII sequence up or down (`abcdef`, `654321`),
/// which is trivially enumerated. Requires length >= 4 (checked by the caller).
fn is_sequential(s: &str) -> bool {
    let bytes: Vec<u8> = s.bytes().collect();
    if bytes.len() < 4 {
        return false;
    }
    let ascending = bytes.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    let descending = bytes.windows(2).all(|w| w[0] == w[1].wrapping_add(1));
    ascending || descending
}

/// A small compiled-in set of the most common passwords and keyboard walks (the head of
/// the public breach top-lists). This is NOT the breach screen (that is the HIBP /
/// offline corpus with millions of entries); it is only the pattern floor the strength
/// estimator forces to score 0, so a trivially guessable password never clears a
/// `min_password_strength_score` floor on length alone.
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwertyuiop",
    "abc123",
    "letmein",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "master",
    "shadow",
    "superman",
    "trustno1",
    "asdfgh",
    "asdfghjkl",
    "zxcvbn",
    "zxcvbnm",
    "qazwsx",
    "1q2w3e4r",
    "1qaz2wsx",
    "password1",
    "changeme",
    "starwars",
    "whatever",
    "hunter2",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_passwords_score_zero_however_long() {
        // A common password with trailing digits is still trivially guessable.
        assert_eq!(score("password1234567"), 0);
        assert_eq!(score("qwertyuiop"), 0);
        assert_eq!(score("letmein!!"), 0);
        // A password CONTAINING a common walk is forced to zero.
        assert_eq!(score("myqwertypassword"), 0);
    }

    #[test]
    fn patterns_score_zero() {
        assert_eq!(score("aaaaaaaaaaaa"), 0, "single run");
        assert_eq!(score("123456789"), 0, "ascending sequence");
        assert_eq!(score("abcdefgh"), 0, "ascending letters");
    }

    #[test]
    fn a_short_password_is_weak() {
        assert_eq!(score("aB3"), 0);
    }

    #[test]
    fn length_and_variety_raise_the_score() {
        // A long, mixed, non-patterned password reaches the top of the ladder.
        assert_eq!(
            score("7xQ!v9mLp2#wZr8Kt4"),
            4,
            "a long mixed password is strong"
        );
        // A very short (but non-pattern) mixed string is below the top: the Shannon
        // bound credits few characters modestly. NOTE (coarse fallback): unlike zxcvbn
        // this estimator has no large dictionary, so it credits entropy from
        // length/charset and can OVER-credit a non-random string relative to zxcvbn; the
        // HIBP/offline breach screen and the compiled-in common-pattern floor are the
        // primary defenses, with this score as a coarse complementary floor.
        assert!(score("k7Q") < 4, "a 3-char string is not top-of-ladder");
        // Adding length and variety never LOWERS the score (monotone in the safe
        // direction), so raising the `min_password_strength_score` floor is a strictly
        // tightening knob.
        assert!(score("k7mQ9pLx2R8v") >= score("k7mQ"));
    }

    #[test]
    fn a_repeated_character_is_discounted() {
        // Fourteen 'a's is credited as one character's worth, so it stays weak even at
        // length fourteen (also caught by the single-run pattern).
        assert_eq!(score(&"a".repeat(14)), 0);
    }

    #[test]
    fn the_dictionary_l33t_blind_spot_is_documented_by_test() {
        // HONESTY (issue #66 MEDIUM): this estimator is BLIND to dictionary words and
        // l33t substitution. A word-plus-digits or leetspeak password scores the MAXIMUM
        // 4 here and would clear EVERY threshold, including min_password_strength_score=4.
        // This test pins that blind spot so the limitation is never mistaken for a
        // zxcvbn-grade guard: the mandatory HIBP/offline breach screen (which every one of
        // these is caught by) is the PRIMARY defense, not this score. If a real dictionary
        // model is ever swapped in behind `score`, this test flips and must be revisited.
        for weak in ["summer2024", "hello123", "test1234", "company1", "P@ssw0rd"] {
            assert_eq!(
                score(weak),
                4,
                "coarse estimator is blind to dictionary/l33t and over-credits {weak:?}; \
                 the breach screen is the primary defense"
            );
        }
    }

    #[test]
    fn distinct_count_is_linear_and_correct_on_a_large_input() {
        // The O(n) HashSet path (issue #66 INFO) returns the same distinct count a scan
        // would, even for a pathologically long input, without O(n^2) blowup.
        let chars: Vec<char> = "abcabcabc".chars().collect();
        assert_eq!(distinct_count(&chars), 3);
        let many: Vec<char> = "a".repeat(100_000).chars().collect();
        assert_eq!(distinct_count(&many), 1);
    }
}
