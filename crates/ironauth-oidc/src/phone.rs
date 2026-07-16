// SPDX-License-Identifier: MIT OR Apache-2.0

//! E.164 phone parsing, country-calling-code extraction, and the pre-send phone
//! SCORING heuristics for the guarded SMS-OTP factor (issue #70).
//!
//! # Scoring is a DOCUMENTED, self-contained heuristic
//!
//! Every judgment here is derived from the number ITSELF against a documented table,
//! with NO external data dependency (no HLR lookup, no carrier API). The table is
//! deliberately conservative: it blocks ranges that are UNMISTAKABLY not a personal
//! mobile that would receive a login code (toll-free, premium-rate, and known virtual /
//! personal-number ranges), because those are the ranges SMS-pumping fraud rides. A
//! number the table cannot classify is treated as [`NumberType::Unknown`] and allowed
//! through: the velocity caps and the send-to-verify conversion auto-throttle (the real
//! pumping defense) catch abuse the static table cannot see.
//!
//! Geographic-clustering and burst detection are NOT per-number properties, so they are
//! NOT decided here; they are enforced by the per-route velocity cap and the per-route
//! conversion counters in the send handler (a burst of sends to one country/route trips
//! the route cap; a burst with near-zero verification trips the conversion alarm).

/// A parsed E.164 phone number (issue #70): the country calling code and the national
/// significant number, both digits only. Produced ONLY by [`E164::parse`] from the
/// canonical `+<digits>` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E164 {
    country_code: String,
    national: String,
}

/// The number-type classification of a destination (issue #70): the documented
/// heuristic verdict used by [`score`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberType {
    /// A plausible personal mobile / fixed line: allowed through.
    Allowed,
    /// A toll-free range (for example NANP 800/888/.../833): not a device that receives
    /// a personal login code. Refused.
    TollFree,
    /// A premium-rate range (for example NANP 900, UK 09): a classic SMS-pumping target.
    /// Refused.
    Premium,
    /// A known virtual / personal-number range (for example UK 070): frequently abused.
    /// Refused.
    Virtual,
    /// A structurally invalid number (wrong length, an invalid NANP area/exchange).
    /// Refused.
    Invalid,
}

impl NumberType {
    /// Whether this classification permits a send.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, NumberType::Allowed)
    }

    /// The stable wire tag, for tracing and audit detail (never attacker-controlled).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            NumberType::Allowed => "allowed",
            NumberType::TollFree => "toll_free",
            NumberType::Premium => "premium",
            NumberType::Virtual => "virtual",
            NumberType::Invalid => "invalid",
        }
    }
}

/// The set of E.164 country calling codes the extractor knows, longest first so a
/// longest-prefix match picks the right one (issue #70). Deliberately a curated,
/// documented table (no external dependency). A number whose prefix is not in the table
/// falls back to its leading digit as the route bucket, which is stable (the same number
/// always buckets the same way) even when it is not the true calling code.
const KNOWN_CALLING_CODES: &[&str] = &[
    // 3-digit codes (a representative, documented subset).
    "212", "213", "216", "218", "220", "221", "234", "254", "255", "256", "263", "351", "352",
    "353", "354", "355", "358", "359", "370", "371", "372", "380", "381", "385", "386", "420",
    "421", "852", "853", "855", "856", "880", "886", "960", "961", "962", "963", "964", "965",
    "966", "971", "972", "973", "974", "975", "976", "977", "992", "993", "994", "995", "996",
    "998", // 2-digit codes.
    "20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45", "46", "47",
    "48", "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65",
    "66", "81", "82", "84", "86", "90", "91", "92", "93", "94", "95", "98",
    // 1-digit codes.
    "1", "7",
];

impl E164 {
    /// Parse a canonical `+<digits>` phone number (issue #70) into its country calling
    /// code and national number. Returns [`None`] for anything that is not a `+` followed
    /// by an all-digit string of a plausible E.164 length (a country code plus at least a
    /// few national digits, and no more than 15 digits total).
    #[must_use]
    pub fn parse(canonical: &str) -> Option<Self> {
        let digits = canonical.strip_prefix('+')?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // E.164 caps the whole number (country + national) at 15 digits.
        if digits.len() > 15 {
            return None;
        }
        let country_code = extract_calling_code(digits);
        let national = digits[country_code.len()..].to_owned();
        // A usable destination has at least four national digits behind its code.
        if national.len() < 4 {
            return None;
        }
        Some(Self {
            country_code,
            national,
        })
    }

    /// The extracted country calling code (digits only).
    #[must_use]
    pub fn country_code(&self) -> &str {
        &self.country_code
    }

    /// The national significant number (digits only).
    #[must_use]
    pub fn national(&self) -> &str {
        &self.national
    }

    /// The route bucket this number is accounted to (issue #70): its country calling
    /// code. The velocity caps and the conversion auto-throttle are keyed on this.
    #[must_use]
    pub fn route_key(&self) -> &str {
        &self.country_code
    }

    /// The documented number-type classification (issue #70).
    #[must_use]
    pub fn number_type(&self) -> NumberType {
        classify(self.country_code(), self.national())
    }
}

/// Extract the country calling code from an all-digit E.164 body by longest-prefix
/// match against [`KNOWN_CALLING_CODES`] (issue #70). Falls back to the leading digit
/// when no known code matches (a stable, documented bucket).
fn extract_calling_code(digits: &str) -> String {
    for len in [3_usize, 2, 1] {
        if digits.len() > len {
            let prefix = &digits[..len];
            if KNOWN_CALLING_CODES.contains(&prefix) {
                return prefix.to_owned();
            }
        }
    }
    // Fallback: the leading digit is a stable route bucket even for an unknown code.
    digits[..1.min(digits.len())].to_owned()
}

/// The documented number-type heuristic (issue #70): classify `(country_code,
/// national)` against the conservative table. Anything the table cannot place is
/// [`NumberType::Allowed`] (the velocity caps and conversion auto-throttle are the
/// dynamic defense).
#[must_use]
fn classify(country_code: &str, national: &str) -> NumberType {
    // Structural sanity: an E.164 national number is between 4 and 14 digits.
    if !(4..=14).contains(&national.len()) {
        return NumberType::Invalid;
    }
    match country_code {
        // North American Numbering Plan: a 10-digit NPA-NXX-XXXX.
        "1" => classify_nanp(national),
        // United Kingdom.
        "44" => classify_uk(national),
        _ => NumberType::Allowed,
    }
}

/// NANP (country code 1) number-type heuristic (issue #70). The national number is a
/// 10-digit NPA (area) + NXX (exchange) + XXXX.
fn classify_nanp(national: &str) -> NumberType {
    if national.len() != 10 {
        return NumberType::Invalid;
    }
    let bytes = national.as_bytes();
    let npa = &national[0..3];
    // A valid NANP area code and exchange both start with 2-9 (N).
    if !(b'2'..=b'9').contains(&bytes[0]) || !(b'2'..=b'9').contains(&bytes[3]) {
        return NumberType::Invalid;
    }
    // Toll-free area codes (not a personal device that receives a login code).
    if matches!(
        npa,
        "800" | "888" | "877" | "866" | "855" | "844" | "833" | "822"
    ) {
        return NumberType::TollFree;
    }
    // Premium / special services.
    if npa == "900" {
        return NumberType::Premium;
    }
    NumberType::Allowed
}

/// UK (country code 44) number-type heuristic (issue #70). The national number drops the
/// trunk `0`, so a UK mobile is `7xxxxxxxxx`.
fn classify_uk(national: &str) -> NumberType {
    // 070 personal numbers: a known virtual / follow-me range abused for fraud. In the
    // national (no trunk 0) form these begin `70`.
    if national.starts_with("70") {
        return NumberType::Virtual;
    }
    // 09 premium-rate services (national form `9...`).
    if national.starts_with('9') {
        return NumberType::Premium;
    }
    // 084 / 087 revenue-share ranges (national form `84` / `87`).
    if national.starts_with("84") || national.starts_with("87") {
        return NumberType::Premium;
    }
    NumberType::Allowed
}

/// The outcome of pre-send phone scoring (issue #70).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoreOutcome {
    /// The destination passes: a send may proceed.
    Pass,
    /// The destination is refused; the reason (the number-type tag) is operator-safe
    /// audit detail, never surfaced to the client (the response is uniform).
    Refused(NumberType),
}

/// Score a parsed destination BEFORE any send (issue #70). When `scoring_enabled` is
/// false the check is a no-op ([`ScoreOutcome::Pass`]); otherwise a non-[`Allowed`]
/// number type is refused. This is a PURE function of the number and the toggle, so the
/// heuristics are unit-testable in isolation.
#[must_use]
pub fn score(number: &E164, scoring_enabled: bool) -> ScoreOutcome {
    if !scoring_enabled {
        return ScoreOutcome::Pass;
    }
    let number_type = number.number_type();
    if number_type.is_allowed() {
        ScoreOutcome::Pass
    } else {
        ScoreOutcome::Refused(number_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_nanp_number_and_extracts_the_calling_code() {
        let number = E164::parse("+14155550100").expect("parses");
        assert_eq!(number.country_code(), "1");
        assert_eq!(number.national(), "4155550100");
        assert_eq!(number.route_key(), "1");
    }

    #[test]
    fn parses_a_uk_number_with_a_two_digit_code() {
        let number = E164::parse("+447700900123").expect("parses");
        assert_eq!(number.country_code(), "44");
        assert_eq!(number.national(), "7700900123");
    }

    #[test]
    fn parses_a_three_digit_code() {
        let number = E164::parse("+351912345678").expect("parses");
        assert_eq!(number.country_code(), "351");
    }

    #[test]
    fn rejects_non_e164_shapes() {
        assert!(E164::parse("4155550100").is_none(), "no leading +");
        assert!(E164::parse("+").is_none(), "empty");
        assert!(E164::parse("+1abc").is_none(), "non-digit");
        assert!(E164::parse("+1234567890123456").is_none(), "too long");
        assert!(E164::parse("+123").is_none(), "too short national part");
    }

    #[test]
    fn nanp_toll_free_and_premium_are_refused() {
        for (raw, expected) in [
            ("+18005550100", NumberType::TollFree),
            ("+18885550100", NumberType::TollFree),
            ("+19005550100", NumberType::Premium),
        ] {
            let number = E164::parse(raw).expect("parses");
            assert_eq!(number.number_type(), expected, "{raw}");
            assert_eq!(
                score(&number, true),
                ScoreOutcome::Refused(expected),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_plausible_mobile_passes() {
        let number = E164::parse("+14155550100").expect("parses");
        assert_eq!(number.number_type(), NumberType::Allowed);
        assert_eq!(score(&number, true), ScoreOutcome::Pass);
    }

    #[test]
    fn uk_virtual_and_premium_ranges_are_refused() {
        let virtual_number = E164::parse("+447050900123").expect("parses");
        assert_eq!(virtual_number.number_type(), NumberType::Virtual);
        let premium = E164::parse("+449012345678").expect("parses");
        assert_eq!(premium.number_type(), NumberType::Premium);
    }

    #[test]
    fn an_invalid_nanp_area_code_is_refused() {
        // A NANP area code starting with 1 is invalid.
        let number = E164::parse("+11155550100").expect("parses digits");
        assert_eq!(number.number_type(), NumberType::Invalid);
        assert_ne!(score(&number, true), ScoreOutcome::Pass);
    }

    #[test]
    fn disabled_scoring_passes_everything() {
        let premium = E164::parse("+19005550100").expect("parses");
        assert_eq!(
            score(&premium, false),
            ScoreOutcome::Pass,
            "scoring off is a no-op"
        );
    }

    #[test]
    fn an_unknown_calling_code_buckets_by_leading_digit_and_passes() {
        // 999 is not a known code; the route falls back to the leading digit, and an
        // unclassifiable number is allowed (the dynamic defenses catch abuse).
        let number = E164::parse("+9995550100").expect("parses");
        assert_eq!(number.route_key(), "9");
        assert_eq!(number.number_type(), NumberType::Allowed);
    }
}
