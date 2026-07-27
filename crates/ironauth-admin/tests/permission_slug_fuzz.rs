// SPDX-License-Identifier: MIT OR Apache-2.0

//! A stable-toolchain fuzz harness for the permission-slug grammar (issue #98).
//!
//! Follows the register `crates/ironauth-webauthn/tests/parse_fuzz.rs` established:
//! a file-local generator seeded from hard-coded constants so a failure in CI is
//! reproducible from the log alone, driving a large volume of adversarial inputs
//! through the one byte-facing validator. NO property-testing crate is added; the
//! workspace deliberately has none (`scripts/invariant-lints.sh` bans the `rand`
//! family outright so randomness in tests is always seeded and replayable), and
//! `crates/ironauth-store/tests/org_assignments.rs` sets the `SplitMix64` precedent
//! this file reuses.
//!
//! Four properties, in ascending strength:
//!
//!   1. TOTALITY. The validator never panics on any input. The classic fuzz
//!      property and the weakest one here.
//!   2. NO CANONICALIZATION. Acceptance implies BYTE IDENTITY: for every accepted
//!      `s`, the result is exactly `s`. A mutation that adds a `.trim()` or a
//!      `to_lowercase()` dies here.
//!   3. JOIN SAFETY. No accepted slug contains `:` `/` `,` tab, newline, carriage
//!      return, or space. This is what makes a permission set safe to join on any
//!      of those characters, which is what an OAuth `scope` string does with a
//!      space. A mutation that widens the charset dies here.
//!   4. STRUCTURE. Every accepted slug has at least two segments, no leading or
//!      trailing `.`, and no `..`. A mutation that drops the `+` from the grammar
//!      (making a single segment legal) dies here.
//!
//! The agreement between this validator and the Postgres CHECK is a different
//! property with a different oracle: `permission_slug_parity.rs`, which needs a real
//! database and therefore cannot live in this DB-free file.
//!
//! REACH COUNTERS. A generator that stopped producing interesting inputs would make
//! every property above vacuously true while staying green. The counters below are
//! asserted against floors, so a future change to the alphabet or the shape mix
//! fails loudly instead of quietly testing nothing.

use ironauth_admin::require_permission_slug;

/// A deterministic `SplitMix64` stream, seeded from a hard-coded constant so a
/// failure in CI is reproducible from the log alone.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`. `bound` must be nonzero.
    fn below(&mut self, bound: usize) -> usize {
        let bound_u64 = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.next_u64() % bound_u64).expect("modulus fits usize")
    }
}

/// The adversarial alphabet the UNSTRUCTURED half of the corpus draws from, biased
/// hard toward the interesting characters: the delimiter, the two in-segment
/// punctuation marks, the boundary of the accepted charset, and every character the
/// grammar must refuse, including the four whose exclusion the join-safety argument
/// rests on.
const ALPHABET: &[char] = &[
    // Accepted, and the reason any slug is ever accepted at all.
    'a',
    'b',
    'z',
    '0',
    '9',
    '_',
    '-', //
    // The delimiter, weighted heavily so leading, trailing, and doubled dots occur.
    '.',
    '.',
    '.', //
    // Refused: the four join delimiters the safety argument names.
    ':',
    '/',
    ',',
    ' ', //
    // Refused: the remaining whitespace forms and the punctuation the role charset
    // already excludes.
    '\t',
    '\n',
    '\r',
    '@',
    '+',
    '~',
    '#',
    '?',
    '*',
    '%',
    '\\',
    '"',
    '\'',
    '(',
    '$',
    // Refused: uppercase, and non-ASCII in one-, two-, three-, and four-byte forms.
    'A',
    'Z',
    '\u{00e9}',
    '\u{4e2d}',
    '\u{1F600}',
];

/// The characters a well-formed segment may carry after its first.
const SEGMENT_TAIL: &[char] = &['a', 'b', 'c', 'x', 'y', 'z', '0', '5', '9', '_', '-'];

/// The characters a well-formed segment may LEAD with (no punctuation).
const SEGMENT_HEAD: &[char] = &['a', 'b', 'c', 'x', 'y', 'z', '0', '5', '9'];

/// The characters no accepted slug may ever contain, used by the mutator to turn a
/// well-formed candidate into a refusable one at a precise position.
const FORBIDDEN: &[char] = &[
    ':',
    '/',
    ',',
    ' ',
    '\t',
    '\n',
    '\r',
    '@',
    '+',
    '~',
    '#',
    '?',
    '*',
    'A',
    'Z',
    '\u{00e9}',
    '\u{4e2d}',
    '\u{1F600}',
];

/// Build a WELL-FORMED candidate of `segments` segments. One segment is deliberately
/// reachable: it is the single-segment refusal, and it must be reached by an
/// otherwise-perfect value or that rule is only ever exercised by noise.
fn structured(rng: &mut Rng, segments: usize) -> String {
    let mut out = String::new();
    for index in 0..segments {
        if index > 0 {
            out.push('.');
        }
        out.push(SEGMENT_HEAD[rng.below(SEGMENT_HEAD.len())]);
        for _ in 0..rng.below(8) {
            out.push(SEGMENT_TAIL[rng.below(SEGMENT_TAIL.len())]);
        }
    }
    out
}

/// Apply exactly one targeted mutation, each of which reaches a named rule of the
/// grammar. A purely uniform generator over the adversarial alphabet reaches the
/// ACCEPT side about once in twenty thousand draws, which would make every property
/// in this file vacuous; this is the half that fixes that.
fn mutate(rng: &mut Rng, candidate: &str) -> String {
    match rng.below(13) {
        0 => format!(".{candidate}"),
        1 => format!("{candidate}."),
        2 => candidate.replacen('.', "..", 1),
        3 => candidate.replace('.', ""),
        4 => {
            // A forbidden character at a random position.
            let forbidden = FORBIDDEN[rng.below(FORBIDDEN.len())];
            let chars: Vec<char> = candidate.chars().collect();
            let at = if chars.is_empty() {
                0
            } else {
                rng.below(chars.len())
            };
            let mut out: String = chars[..at].iter().collect();
            out.push(forbidden);
            out.extend(chars[at..].iter());
            out
        }
        5 => candidate.to_uppercase(),
        6 => format!("{candidate}{}", "x".repeat(64)),
        7 => {
            // Exactly at the 63-byte bound, still well formed.
            let base = "a.";
            format!("{base}{}", "x".repeat(63 - base.len()))
        }
        8 => {
            // Exactly one past it, still well formed but for the length.
            let base = "a.";
            format!("{base}{}", "x".repeat(64 - base.len()))
        }
        9 => format!(" {candidate}"),
        10 => format!("{candidate} "),
        11 => {
            // Uppercase exactly ONE character, never a segment head. A DISTINCT rule
            // from case 5: the head rule refuses an all-uppercase value regardless of
            // what the tail charset allows, so a corpus carrying only head-position
            // uppercase asserts nothing at all about the tail charset.
            uppercase_a_tail_character(candidate)
        }
        _ => {
            // A segment leading with punctuation, which the head rule refuses.
            let lead = if rng.below(2) == 0 { '_' } else { '-' };
            match candidate.split_once('.') {
                Some((head, tail)) => format!("{head}.{lead}{tail}"),
                None => format!("{lead}{candidate}"),
            }
        }
    }
}

/// Uppercase the LAST character, which is a segment TAIL position unless that
/// segment is a single character. Returns the input unchanged when there is no such
/// position, so the caller still gets a well-formed candidate.
fn uppercase_a_tail_character(base: &str) -> String {
    let Some((head, last)) = base.split_at_checked(base.len().saturating_sub(1)) else {
        return base.to_owned();
    };
    if head.is_empty() || head.ends_with('.') {
        return base.to_owned();
    }
    format!("{head}{}", last.to_uppercase())
}

/// One generated candidate: a third unstructured noise, a third well formed, a third
/// well formed and then mutated at one precise point.
fn candidate(rng: &mut Rng) -> String {
    match rng.below(3) {
        0 => {
            // Lengths span the empty string, the ordinary case, the 63-byte
            // boundary, and well past it.
            let len = rng.below(70);
            (0..len)
                .map(|_| ALPHABET[rng.below(ALPHABET.len())])
                .collect()
        }
        1 => {
            let segments = 1 + rng.below(4);
            structured(rng, segments)
        }
        _ => {
            let segments = 1 + rng.below(4);
            let base = structured(rng, segments);
            mutate(rng, &base)
        }
    }
}

/// What the corpus reached, so a generator change that stops reaching a rule fails
/// loudly instead of going vacuous.
#[derive(Default)]
struct Reach {
    accepted: usize,
    refused: usize,
    leading_dot: usize,
    trailing_dot: usize,
    doubled_dot: usize,
    single_segment: usize,
    over_the_bound: usize,
    at_the_bound: usize,
    uppercase: usize,
    uppercase_in_a_tail: usize,
    join_delimiter: usize,
    non_ascii: usize,
    empty: usize,
}

impl Reach {
    fn observe(&mut self, candidate: &str, accepted: bool) {
        if accepted {
            self.accepted += 1;
        } else {
            self.refused += 1;
        }
        if candidate.is_empty() {
            self.empty += 1;
            return;
        }
        if candidate.starts_with('.') {
            self.leading_dot += 1;
        }
        if candidate.ends_with('.') {
            self.trailing_dot += 1;
        }
        if candidate.contains("..") {
            self.doubled_dot += 1;
        }
        if !candidate.contains('.') {
            self.single_segment += 1;
        }
        if candidate.len() > 63 {
            self.over_the_bound += 1;
        }
        if candidate.len() == 63 {
            self.at_the_bound += 1;
        }
        if candidate.chars().any(char::is_uppercase) {
            self.uppercase += 1;
        }
        // The FINER counter: uppercase in a segment TAIL, with that segment's own
        // head still lowercase. A corpus whose uppercase cases all sit at a head is
        // refused by the head rule no matter what the tail charset allows, which is
        // exactly the gap a surviving mutant exposed while this PR was written.
        if candidate.split('.').any(|segment| {
            segment
                .chars()
                .next()
                .is_some_and(|head| !head.is_uppercase())
                && segment.chars().skip(1).any(char::is_uppercase)
        }) {
            self.uppercase_in_a_tail += 1;
        }
        if candidate.contains([':', '/', ',', ' ']) {
            self.join_delimiter += 1;
        }
        if !candidate.is_ascii() {
            self.non_ascii += 1;
        }
    }

    /// Every rule the grammar states must be REACHED by the corpus. The floors are
    /// deliberately far below the observed counts: they exist to catch a generator
    /// that stops producing a shape entirely, not to pin a distribution.
    fn assert_every_rule_was_reached(&self) {
        for (label, count, floor) in [
            ("accepted at all", self.accepted, 200),
            ("refused at all", self.refused, 1_000),
            ("a leading dot", self.leading_dot, 50),
            ("a trailing dot", self.trailing_dot, 50),
            ("a doubled dot", self.doubled_dot, 50),
            ("a single segment", self.single_segment, 50),
            ("over the 63-byte bound", self.over_the_bound, 50),
            ("exactly at the 63-byte bound", self.at_the_bound, 5),
            ("an uppercase character", self.uppercase, 50),
            (
                "an uppercase character in a segment TAIL",
                self.uppercase_in_a_tail,
                50,
            ),
            ("a join delimiter", self.join_delimiter, 50),
            ("a non-ASCII character", self.non_ascii, 50),
            ("the empty string", self.empty, 1),
        ] {
            assert!(
                count >= floor,
                "the corpus reached {label} only {count} times (floor {floor}); a generator \
                 that no longer reaches a rule makes the properties in this file vacuous"
            );
        }
    }
}

/// Drive `iterations` generated candidates through the validator, asserting all four
/// properties on each, and return what the corpus reached.
fn sweep(seed: u64, iterations: usize) -> Reach {
    let mut rng = Rng(seed);
    let mut reach = Reach::default();
    for _ in 0..iterations {
        let candidate = candidate(&mut rng);

        // Property 1: totality. A panic anywhere in the validator fails the test by
        // unwinding out of it; there is no other way to state "never panics".
        let verdict = require_permission_slug(&candidate, "slug");
        reach.observe(&candidate, verdict.is_ok());

        let Ok(accepted) = verdict else {
            continue;
        };

        // Property 2: no canonicalization. Acceptance implies byte identity.
        assert_eq!(
            accepted, candidate,
            "an accepted slug must be returned byte identical, never trimmed or folded"
        );

        // Property 3: join safety. None of the four characters a consumer might
        // join on can appear, and neither can the other whitespace forms.
        for forbidden in [':', '/', ',', ' ', '\t', '\n', '\r'] {
            assert!(
                !accepted.contains(forbidden),
                "accepted slug {accepted:?} contains {forbidden:?}, which would make a \
                 delimiter-joined permission set smuggleable"
            );
        }

        // Property 4: structure. Namespacing is by construction.
        let segments: Vec<&str> = accepted.split('.').collect();
        assert!(
            segments.len() >= 2,
            "accepted slug {accepted:?} is not namespaced"
        );
        assert!(
            segments.iter().all(|segment| !segment.is_empty()),
            "accepted slug {accepted:?} has an empty segment (a leading, trailing, or \
             doubled dot)"
        );
        assert!(
            !accepted.starts_with('.') && !accepted.ends_with('.') && !accepted.contains(".."),
            "accepted slug {accepted:?} violates the structural refusals"
        );

        // The bound, and the charset, restated positively so a widened validator
        // cannot pass by refusing everything interesting. The LOWERCASE assertion is
        // separate from every structural one above and is load-bearing on its own:
        // the grammar has a HEAD rule and a TAIL rule, and a validator that widened
        // only the tail to `is_ascii_alphabetic` satisfies every structural property
        // in this file.
        assert!(
            accepted.len() <= 63,
            "accepted slug {accepted:?} is too long"
        );
        assert!(
            accepted.is_ascii(),
            "accepted slug {accepted:?} is not ASCII"
        );
        assert!(
            !accepted.chars().any(char::is_uppercase),
            "accepted slug {accepted:?} carries an uppercase character; slug comparison \
             is byte exact, so two permissions must never differ only by case"
        );
    }
    reach
}

#[test]
fn the_permission_slug_grammar_holds_over_a_generated_corpus() {
    // Two independent seeds, so a property that happens to hold on one stream is
    // not mistaken for one that holds generally.
    let first = sweep(0x5052_4D5F_5345_4544, 20_000);
    let second = sweep(0x9E37_79B9_7F4A_7C15, 20_000);
    first.assert_every_rule_was_reached();
    second.assert_every_rule_was_reached();
}

#[test]
fn the_generator_reaches_the_accepted_shapes_it_is_meant_to() {
    // A sharper reach assertion than the floors above: the generator must produce
    // slugs of MORE than two segments and slugs carrying each of the two in-segment
    // punctuation marks, or the accepted half of the corpus is a single shape.
    let mut rng = Rng(0xA5A5_5A5A_C3C3_3C3C);
    let mut deep = 0_usize;
    let mut with_underscore = 0_usize;
    let mut with_hyphen = 0_usize;
    for _ in 0..40_000 {
        let generated = candidate(&mut rng);
        if require_permission_slug(&generated, "slug").is_err() {
            continue;
        }
        if generated.split('.').count() >= 3 {
            deep += 1;
        }
        if generated.contains('_') {
            with_underscore += 1;
        }
        if generated.contains('-') {
            with_hyphen += 1;
        }
    }
    for (label, count) in [
        ("three or more segments", deep),
        ("an underscore inside a segment", with_underscore),
        ("a hyphen inside a segment", with_hyphen),
    ] {
        assert!(
            count > 0,
            "no accepted slug carried {label}; the accepted half of the corpus has \
             collapsed to one shape"
        );
    }
}
