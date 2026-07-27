// SPDX-License-Identifier: MIT OR Apache-2.0

//! The permission-slug PARITY oracle (issue #98), over a real database
//! (`DATABASE_URL`).
//!
//! The grammar has TWO enforcement points and they must never drift:
//!
//!   1. `permissions_slug_valid`, the CHECK constraint migration 0091 ships. The
//!      real guarantee.
//!   2. `ironauth_admin::require_permission_slug`, the pure validator at the
//!      management edge, which exists so a bad slug is a caller-facing 400 naming
//!      the field and the rule instead of an opaque 500 from the CHECK.
//!
//! Issue #97 shipped the same two-point arrangement for role and group slugs with
//! NOTHING pinning the two halves equal; the regex appears in several places with no
//! shared source of truth. This file is the improvement: one seeded corpus is fed to
//! both halves and their verdicts are asserted equal CASE BY CASE, in both
//! directions. A validator that grew stricter than the CHECK would start refusing
//! values the database accepts (a caller-visible regression), and one that grew
//! laxer would start passing values the CHECK rejects (the opaque 500 the validator
//! exists to prevent). Both are caught here and nowhere else.
//!
//! The Postgres half is deliberately NOT a re-statement of the regex in this file.
//! Restating it would test a copy of the rule against another copy of the rule. Each
//! case is instead INSERTED into the real `permissions` table inside a transaction
//! that is rolled back, so the oracle is the constraint as deployed, length conjunct
//! included. A refusal counts only when it is SQLSTATE 23514 naming
//! `permissions_slug_valid`; any other failure fails the test loudly rather than
//! being read as "the CHECK refused it".
//!
//! REACH COUNTERS. A corpus that stopped reaching a rule would make this file agree
//! vacuously. The #95 review found exactly that shape: a corpus structurally blind
//! to three CHECKs because its generator could not reach the relevant values. Every
//! rule the grammar states therefore has a counter asserted against a floor, and the
//! counters answer the two questions a plain "did this rule appear" cannot:
//!
//!   * WHERE it appeared. The regex spells its charset as FOUR separate literal
//!     classes (the first segment's head and tail, and a later segment's head and
//!     tail), each of which can be widened on its own. A forbidden character reached
//!     in one position says nothing about the other three, so every forbidden
//!     character is counted PER POSITION and floored in each.
//!   * WHICH HALF reached it. The hand-written and generated halves are counted
//!     apart, because a floor met entirely by the hand-written cases is no assertion
//!     at all about the generator, and this file's promise that a generator change
//!     failing to reach a rule fails loudly depends on exactly that separation.

use std::collections::BTreeMap;

use ironauth_admin::require_permission_slug;
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, OrgRoleId, OrganizationId, PermissionId, Scope, ServiceId,
};
use sqlx::{PgPool, Row};

/// The Postgres "check violation" SQLSTATE. The ONLY refusal this file accepts as a
/// verdict from the storage half.
const CHECK_VIOLATION: &str = "23514";

/// The constraint whose verdict is being compared. Naming it (rather than accepting
/// any 23514) is what stops a refusal by the display-name or kind CHECK from being
/// miscounted as a slug refusal.
const SLUG_CONSTRAINT: &str = "permissions_slug_valid";

/// The shipped ROLE slug CHECK (migration 0086), which the permission grammar claims
/// to be a STRICT SUBSET of.
const ROLE_SLUG_CONSTRAINT: &str = "org_roles_slug_valid";

/// The corpus seed, hard-coded so a failure in CI is reproducible from the log alone.
const SEED: u64 = 0x9851_5055_5F50_5254;

/// How many generated cases the corpus carries.
const GENERATED: usize = 220;

/// A deterministic `SplitMix64` stream, seeded from a hard-coded constant so a
/// failure in CI is reproducible from the log alone. A file-local generator rather
/// than a crate: the workspace has no property-testing dependency and
/// `scripts/invariant-lints.sh` bans the `rand` family, so randomness in tests is
/// always seeded and replayable.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound_u64 = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.next_u64() % bound_u64).expect("modulus fits usize")
    }
}

/// Every character an accepted slug must never contain. Each one is reached by the
/// corpus and counted individually, because "some forbidden character appeared" is
/// exactly the aggregate that hides a rule the corpus never touched.
const FORBIDDEN: &[char] = &[
    ':', '/', ',', ' ', '\t', '\n', '\r', '@', '+', '~', '#', '?', '*', '%', '\\', '"', '\'', '(',
    '$', '=', ';', '|', '<', '&', '!', '[', '{',
];

/// The hand-written half of the corpus: the cases a reader would ask about by name.
fn explicit_corpus() -> Vec<String> {
    let mut cases: Vec<String> = Vec::new();

    // ACCEPT side. Ordinary shapes, the entitlement shapes issue #103 needs, and
    // both edges of the in-segment charset.
    for accepted in [
        "billing.invoice.read",
        "a.b",
        "0.9",
        "z.0",
        "feature.sso",
        "plan.enterprise",
        "feature.audit_log_export",
        "billing.invoice_export",
        "team-eu.west-1.read",
        "a.b.c.d.e.f.g",
        "9deep.9deep.9deep",
        "a_b.c-d",
        "a-.b",
        "a_.b",
    ] {
        cases.push(accepted.to_owned());
    }
    // Exactly 63 characters: the accepted value AT the bound.
    cases.push(format!("a.{}", "x".repeat(61)));
    // Exactly 64: one past it, identical in every other respect.
    cases.push(format!("a.{}", "x".repeat(62)));
    // 63 characters made of many segments, so the bound is reached by a shape the
    // padding case does not cover.
    cases.push(vec!["abc"; 16].join(".")[..63].to_owned());

    // REFUSE side: the three structural refusals the permission grammar ADDS on top
    // of the #97 role charset.
    for refused in [
        "billing",     // a single segment
        "a",           //
        "0",           //
        ".leading",    // a leading dot
        ".a.b",        //
        "trailing.",   // a trailing dot
        "a.b.",        //
        "double..dot", // a doubled dot
        "a..b",        //
        "...",         // all three at once
        ".",           //
        "..",          //
    ] {
        cases.push(refused.to_owned());
    }

    // REFUSE side: the exclusions inherited from the role charset.
    for refused in [
        "",             // empty
        "Billing.Read", // uppercase at a segment HEAD
        "BILLING.READ", //
        "billing.Read", //
        // Uppercase in a segment TAIL, every head still lowercase. A DISTINCT rule
        // from the three above: the head rule refuses those regardless of what the
        // tail charset allows, so a corpus carrying only head-position uppercase
        // asserts nothing about the tail charset at all. A validator that admitted
        // `is_ascii_alphabetic` in the tail passes every head-position case.
        "billing.reaD",
        "billinG.read",
        "a.bC",
        "billing.invoice.reaD",
        "read:orders",          // the Auth0 spelling; `:` is not the delimiter
        "billing:invoice.read", //
        "billing.invoice/read", // slash
        "billing,invoice",      // comma
        "has space.read",       // space
        "billing.read ",        // trailing space (never trimmed)
        " billing.read",        // leading space (never trimmed)
        "billing.\tread",       // tab
        "billing.\nread",       // newline
        "billing.\rread",       // carriage return
        "billing.read@v1",      // at
        "billing.read+extra",   // plus
        "billing.read~1",       // tilde
        "billing.read#1",       // hash
        "billing.read?",        // question mark
        "billing.*",            // star
        "_leading.read",        // a segment leading with punctuation
        "-leading.read",        //
        "billing._read",        //
        "billing.-read",        //
        "billing.rea\u{00e9}d", // non-ASCII, two-byte
        "billing.\u{4e2d}wen",  // non-ASCII, three-byte
        "billing.\u{1F600}",    // non-ASCII, four-byte
        "billing.re\u{0301}ad", // a combining mark, which no fold may absorb
    ] {
        cases.push(refused.to_owned());
    }

    // Every forbidden character at ALL FOUR positions the grammar spells as separate
    // literal character classes: the first segment's HEAD and TAIL, and a later
    // segment's HEAD and TAIL. One placement per character is NOT enough, and the
    // reason is structural rather than stylistic: the regex is
    // `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$`, four classes that can drift
    // independently. A corpus placing every forbidden character only in the first
    // segment's tail lets a widened LATER-SEGMENT TAIL class produce zero
    // disagreements: `(\.[a-z0-9][:a-z0-9_-]*)+` accepts `billing.read:orders` while
    // the Rust validator still refuses it, and the parity assertion stays green.
    // That matters because the join-safety covenant rests on exactly these
    // exclusions: `:` is excluded so a slug can never be confused with an RFC 8707
    // resource indicator or an OAuth scope token.
    for forbidden in FORBIDDEN {
        cases.push(format!("{forbidden}x.read"));
        cases.push(format!("billing{forbidden}x.read"));
        cases.push(format!("billing.{forbidden}read"));
        cases.push(format!("billing.rea{forbidden}d"));
    }

    // A value whose CHARACTER count is inside the bound while its BYTE count is not.
    // The Rust validator bounds bytes and the CHECK bounds characters; the regex
    // conjunct confines an accepted value to ASCII, so the two measures can only
    // ever disagree on a value both halves refuse anyway. This case is what proves
    // that claim rather than asserting it.
    cases.push(format!("a.{}", "\u{4e2d}".repeat(30)));

    cases
}

/// The generated half of the corpus: well-formed shapes, and well-formed shapes with
/// one precise mutation. The explicit half above states the cases a reader asks for
/// by name; this half is what keeps the two implementations honest on shapes nobody
/// thought to write down.
fn generated_corpus(seed: u64, count: usize) -> Vec<String> {
    const HEAD: &[char] = &['a', 'b', 'z', '0', '9'];
    const TAIL: &[char] = &['a', 'q', 'z', '0', '7', '_', '-'];
    let mut rng = Rng(seed);
    let mut cases = Vec::with_capacity(count);
    for _ in 0..count {
        let segments = 1 + rng.below(4);
        let mut base = String::new();
        for index in 0..segments {
            if index > 0 {
                base.push('.');
            }
            base.push(HEAD[rng.below(HEAD.len())]);
            for _ in 0..rng.below(6) {
                base.push(TAIL[rng.below(TAIL.len())]);
            }
        }
        let mutated = match rng.below(10) {
            0 | 1 => base.clone(),
            2 => format!(".{base}"),
            3 => format!("{base}."),
            4 => base.replacen('.', "..", 1),
            5 => base.replace('.', ""),
            6 => base.to_uppercase(),
            // Uppercase exactly ONE character, and never a segment head, so the
            // generated half reaches the TAIL charset rule too. A DISTINCT rule from
            // the arm above: the head rule refuses an all-uppercase value regardless
            // of what the tail charset allows.
            7 => uppercase_a_tail_character(&base),
            8 => format!("{base}{}", "y".repeat(64)),
            _ => {
                let forbidden = FORBIDDEN[rng.below(FORBIDDEN.len())];
                format!("{base}{forbidden}")
            }
        };
        cases.push(mutated);
    }
    cases
}

/// Uppercase the LAST character of the last segment, which is never a segment head
/// unless that segment is a single character. Returns the input unchanged when there
/// is no such position, so the caller still gets a well-formed candidate.
fn uppercase_a_tail_character(base: &str) -> String {
    let Some((head, last)) = base.split_at_checked(base.len().saturating_sub(1)) else {
        return base.to_owned();
    };
    if head.ends_with('.') || head.is_empty() {
        return base.to_owned();
    }
    format!("{head}{}", last.to_uppercase())
}

/// Where in a slug a character sits.
///
/// The grammar spells its charset as FOUR separate literal classes (the first
/// segment's head and tail, and a later segment's head and tail), and each can be
/// widened independently. A counter that only asks "did this character appear
/// somewhere" is satisfied by a single placement and says nothing about the other
/// three classes, which is the position blindness this enum exists to remove.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Position {
    FirstHead,
    FirstTail,
    LaterHead,
    LaterTail,
}

impl Position {
    /// Every position, so a floor can be asserted for each one individually.
    const ALL: [Self; 4] = [
        Self::FirstHead,
        Self::FirstTail,
        Self::LaterHead,
        Self::LaterTail,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::FirstHead => "the FIRST segment's head",
            Self::FirstTail => "the FIRST segment's tail",
            Self::LaterHead => "a LATER segment's head",
            Self::LaterTail => "a LATER segment's tail",
        }
    }
}

/// Every distinct [`Position`] at which `needle` occurs in `case`.
fn positions_of(case: &str, needle: char) -> Vec<Position> {
    let mut found: Vec<Position> = Vec::new();
    for (segment_index, segment) in case.split('.').enumerate() {
        for (offset, character) in segment.chars().enumerate() {
            if character != needle {
                continue;
            }
            let position = match (segment_index == 0, offset == 0) {
                (true, true) => Position::FirstHead,
                (true, false) => Position::FirstTail,
                (false, true) => Position::LaterHead,
                (false, false) => Position::LaterTail,
            };
            if !found.contains(&position) {
                found.push(position);
            }
        }
    }
    found
}

/// What one HALF of the corpus reached. Every rule the grammar states gets a
/// counter, so a generator change that stops reaching one fails loudly instead of
/// leaving this file agreeing about nothing.
///
/// The two halves are counted SEPARATELY, and the reason is the same shape this file
/// exists to catch: several floors were met exactly by the hand-written half, so the
/// documented promise that a generator change failing to reach a rule fails loudly
/// was FALSE for those rules. Disabling a generator arm moved a shared counter by a
/// number no floor could see. Separate counters make each floor bind on the half it
/// is a claim about.
#[derive(Default, Debug)]
struct Reach {
    accepted: usize,
    refused: usize,
    leading_dot: usize,
    trailing_dot: usize,
    doubled_dot: usize,
    single_segment: usize,
    exactly_63: usize,
    exactly_64: usize,
    over_63: usize,
    uppercase: usize,
    uppercase_at_a_head: usize,
    uppercase_in_a_tail: usize,
    non_ascii: usize,
    empty: usize,
    segment_leading_punctuation: usize,
    forbidden: BTreeMap<(char, Position), usize>,
    forbidden_anywhere: usize,
}

impl Reach {
    fn observe(&mut self, case: &str, accepted: bool) {
        if accepted {
            self.accepted += 1;
        } else {
            self.refused += 1;
        }
        let mut carries_a_forbidden_character = false;
        for forbidden in FORBIDDEN {
            for position in positions_of(case, *forbidden) {
                carries_a_forbidden_character = true;
                *self.forbidden.entry((*forbidden, position)).or_default() += 1;
            }
        }
        if carries_a_forbidden_character {
            self.forbidden_anywhere += 1;
        }
        if case.is_empty() {
            self.empty += 1;
            return;
        }
        if case.starts_with('.') {
            self.leading_dot += 1;
        }
        if case.ends_with('.') {
            self.trailing_dot += 1;
        }
        if case.contains("..") {
            self.doubled_dot += 1;
        }
        if !case.contains('.') {
            self.single_segment += 1;
        }
        match case.len() {
            63 => self.exactly_63 += 1,
            64 => self.exactly_64 += 1,
            _ => {}
        }
        if case.len() > 63 {
            self.over_63 += 1;
        }
        if case.chars().any(char::is_uppercase) {
            self.uppercase += 1;
        }
        // The head-position counter, which binds the generator arm that uppercases
        // the WHOLE value. Without it, `uppercase` alone cannot tell that arm from
        // the tail-only one below: disabling either leaves the other still counting.
        if case
            .split('.')
            .any(|segment| segment.chars().next().is_some_and(char::is_uppercase))
        {
            self.uppercase_at_a_head += 1;
        }
        // The FINER counter, and the reason it exists: a corpus whose uppercase cases
        // all sit at a segment HEAD is refused by the head rule no matter what the
        // TAIL charset allows, so it asserts nothing about the tail. A mutation
        // widening the tail to `is_ascii_alphabetic` survived exactly that gap during
        // this PR's own mutation testing.
        if case.split('.').any(|segment| {
            segment
                .chars()
                .next()
                .is_some_and(|head| !head.is_uppercase())
                && segment.chars().skip(1).any(char::is_uppercase)
        }) {
            self.uppercase_in_a_tail += 1;
        }
        if !case.is_ascii() {
            self.non_ascii += 1;
        }
        if case
            .split('.')
            .any(|segment| segment.starts_with('_') || segment.starts_with('-'))
        {
            self.segment_leading_punctuation += 1;
        }
    }

    /// The floors the HAND-WRITTEN half must meet: every rule a reader would ask
    /// about by name, plus every forbidden character AT EVERY POSITION.
    fn assert_the_named_cases_reached_every_rule(&self) {
        for (label, count, floor) in [
            ("an accepted case", self.accepted, 15),
            ("a refused case", self.refused, 80),
            ("a leading dot", self.leading_dot, 4),
            ("a trailing dot", self.trailing_dot, 2),
            ("a doubled dot", self.doubled_dot, 3),
            ("a single segment", self.single_segment, 3),
            ("exactly 63 bytes", self.exactly_63, 2),
            ("exactly 64 bytes", self.exactly_64, 1),
            ("more than 63 bytes", self.over_63, 2),
            ("an uppercase character", self.uppercase, 5),
            (
                "an uppercase character at a segment HEAD",
                self.uppercase_at_a_head,
                3,
            ),
            (
                "an uppercase character in a segment TAIL",
                self.uppercase_in_a_tail,
                4,
            ),
            ("a non-ASCII character", self.non_ascii, 4),
            ("the empty string", self.empty, 1),
            (
                "a segment leading with punctuation",
                self.segment_leading_punctuation,
                4,
            ),
        ] {
            assert!(
                count >= floor,
                "the hand-written corpus reached {label} only {count} times (floor \
                 {floor}); a corpus that cannot reach a rule makes this parity assertion \
                 vacuous for it"
            );
        }
        // EVERY forbidden character at EVERY POSITION, not merely "some forbidden
        // character appeared somewhere". The four positions are four separate literal
        // classes in the deployed regex, and widening any one of them is a real
        // weakening that a single placement cannot see.
        for forbidden in FORBIDDEN {
            for position in Position::ALL {
                let count = self
                    .forbidden
                    .get(&(*forbidden, position))
                    .copied()
                    .unwrap_or_default();
                assert!(
                    count >= 1,
                    "the corpus never reached the forbidden character {forbidden:?} at \
                     {}; its exclusion THERE is asserted by nothing, and that class of \
                     the regex could be widened with this file still green",
                    position.label()
                );
            }
        }
    }

    /// The floors the GENERATED half must meet.
    ///
    /// Each floor is calibrated against the count that SURVIVES disabling the arm
    /// that feeds it, measured arm by arm, so the floor genuinely fires rather than
    /// being satisfied by whatever else happens to reach the rule. Six of these bind
    /// ONE arm exactly (the survivors are 0), and the tail-uppercase floor is set
    /// above its survivor of 8 for the same reason: that arm is the one added to kill
    /// the tail-uppercase mutant, and a floor it could not detect the loss of would be
    /// the very shape this file exists to prevent.
    ///
    /// `a single segment` is the ONE floor here that binds the RULE rather than one
    /// arm: a quarter of the generated bases are single-segment before any mutation,
    /// so 44 of the 56 survive the delimiter-stripping arm. It is kept honest by
    /// saying so rather than by a floor that pretends otherwise.
    ///
    /// The per-position forbidden floors deliberately are NOT asserted here: this
    /// generator only ever APPENDS a forbidden character, so by construction it
    /// reaches a tail and never a head. The aggregate is what binds that arm, and the
    /// four positions are covered by the hand-written half.
    fn assert_every_generator_arm_is_live(&self) {
        for (label, count, floor) in [
            ("an accepted case", self.accepted, 8),
            ("a refused case", self.refused, 80),
            ("a leading dot (arm 2, survivor 0)", self.leading_dot, 8),
            ("a trailing dot (arm 3, survivor 0)", self.trailing_dot, 8),
            ("a doubled dot (arm 4, survivor 0)", self.doubled_dot, 8),
            (
                "a single segment (arms 0, 1, and 5)",
                self.single_segment,
                8,
            ),
            ("more than 63 bytes (arm 8, survivor 0)", self.over_63, 12),
            (
                "an uppercase character at a segment HEAD (arm 6, survivor 0)",
                self.uppercase_at_a_head,
                12,
            ),
            (
                "an uppercase character in a segment TAIL (arm 7, survivor 8)",
                self.uppercase_in_a_tail,
                12,
            ),
            (
                "a forbidden character (arm 9, survivor 0)",
                self.forbidden_anywhere,
                12,
            ),
        ] {
            assert!(
                count >= floor,
                "the GENERATED corpus reached {label} only {count} times (floor {floor}); \
                 a generator that stopped reaching this rule would leave this file \
                 agreeing about nothing for it, and the hand-written half cannot cover \
                 for it because the two are counted apart"
            );
        }
    }
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does, so the probe row satisfies the isolation policy's WITH CHECK and
/// the CHECK constraint is the only thing that can refuse it.
async fn bind_scope(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, scope: Scope) {
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut **tx)
        .await
        .expect("bind tenant scope");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut **tx)
        .await
        .expect("bind environment scope");
}

/// The STORAGE half's verdict on one slug: attempt the real insert, then roll it
/// back. `true` means the deployed CHECK accepted the value.
///
/// Anything other than a clean success or a 23514 naming `permissions_slug_valid`
/// panics: a refusal by the display-name CHECK, by the uniqueness index, by the
/// isolation policy, or by a missing grant is NOT a verdict about the slug, and
/// silently counting one as a refusal is how a parity test agrees for the wrong
/// reason.
async fn postgres_accepts(pool: &PgPool, env: &Env, scope: Scope, slug: &str) -> bool {
    let id = PermissionId::generate(env, &scope).to_string();
    let mut tx = pool.begin().await.expect("begin parity probe");
    bind_scope(&mut tx, scope).await;
    let result = sqlx::query(
        "INSERT INTO permissions (id, tenant_id, environment_id, slug, display_name) \
         VALUES ($1, $2, $3, $4, 'parity probe')",
    )
    .bind(&id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(slug)
    .execute(&mut *tx)
    .await;
    let _ = tx.rollback().await;

    match result {
        Ok(_) => true,
        Err(error) => {
            let database_error = error
                .as_database_error()
                .unwrap_or_else(|| panic!("slug {slug:?} failed outside the database: {error}"));
            let code = database_error.code().unwrap_or_default().into_owned();
            let constraint = database_error.constraint().unwrap_or_default().to_owned();
            assert_eq!(
                (code.as_str(), constraint.as_str()),
                (CHECK_VIOLATION, SLUG_CONSTRAINT),
                "slug {slug:?} was refused by something other than the slug CHECK: {error}"
            );
            false
        }
    }
}

#[tokio::test]
async fn the_rust_validator_and_the_postgres_check_agree_case_by_case() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.control_pool();

    let explicit = explicit_corpus();
    let generated = generated_corpus(SEED, GENERATED);
    let corpus: Vec<String> = explicit.iter().chain(generated.iter()).cloned().collect();

    // The two halves are counted SEPARATELY: a floor met by the hand-written cases
    // says nothing about whether the generator still reaches the rule, and several
    // floors in this file were met exactly that way before.
    let mut explicit_reach = Reach::default();
    let mut generated_reach = Reach::default();
    let mut disagreements: Vec<String> = Vec::new();
    for (index, case) in corpus.iter().enumerate() {
        let rust = require_permission_slug(case, "slug").is_ok();
        let postgres = postgres_accepts(pool, &env, scope, case).await;
        if index < explicit.len() {
            explicit_reach.observe(case, rust);
        } else {
            generated_reach.observe(case, rust);
        }
        if rust != postgres {
            disagreements.push(format!(
                "{case:?}: the Rust validator says {rust}, the CHECK says {postgres}"
            ));
        }
        // The validator never canonicalizes, so an accepted value comes back byte
        // identical. Asserted here as well as in the fuzz target because a
        // canonicalizing validator would ALSO break parity, in a way that only
        // shows up once the transformed value reaches the CHECK.
        if rust {
            assert_eq!(
                require_permission_slug(case, "slug").expect("accepted"),
                *case,
                "an accepted slug must be stored byte identical"
            );
        }
    }
    assert!(
        disagreements.is_empty(),
        "the management edge and the storage engine disagree about {} of {} cases:\n{}",
        disagreements.len(),
        corpus.len(),
        disagreements.join("\n")
    );
    explicit_reach.assert_the_named_cases_reached_every_rule();
    generated_reach.assert_every_generator_arm_is_live();
}

/// The STORAGE half's verdict on one slug used as a ROLE name: attempt the real
/// insert into `org_roles`, then roll it back. `true` means the deployed
/// `org_roles_slug_valid` CHECK accepted the value.
///
/// Anything other than a clean success or a 23514 naming that constraint panics, for
/// the same reason the permission probe does: a refusal by the display-name CHECK, by
/// the live-uniqueness index, by the isolation policy, or by a foreign key is NOT a
/// verdict about the slug.
async fn org_roles_accepts(
    pool: &PgPool,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    slug: &str,
) -> bool {
    let id = OrgRoleId::generate(env, &scope).to_string();
    let mut tx = pool.begin().await.expect("begin role probe");
    bind_scope(&mut tx, scope).await;
    let result = sqlx::query(
        "INSERT INTO org_roles \
         (id, tenant_id, environment_id, organization_id, slug, display_name) \
         VALUES ($1, $2, $3, $4, $5, 'strict subset probe')",
    )
    .bind(&id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(organization.to_string())
    .bind(slug)
    .execute(&mut *tx)
    .await;
    let _ = tx.rollback().await;

    match result {
        Ok(_) => true,
        Err(error) => {
            let database_error = error.as_database_error().unwrap_or_else(|| {
                panic!("role slug {slug:?} failed outside the database: {error}")
            });
            let code = database_error.code().unwrap_or_default().into_owned();
            let constraint = database_error.constraint().unwrap_or_default().to_owned();
            assert_eq!(
                (code.as_str(), constraint.as_str()),
                (CHECK_VIOLATION, ROLE_SLUG_CONSTRAINT),
                "role slug {slug:?} was refused by something other than the role slug \
                 CHECK: {error}"
            );
            false
        }
    }
}

/// The text of one deployed CHECK constraint.
async fn constraint_definition(pool: &PgPool, table: &str, constraint: &str) -> String {
    sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = $1::regclass AND conname = $2",
    )
    .bind(table)
    .bind(constraint)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|error| panic!("{constraint} on {table} must exist: {error}"))
    .get("def")
}

#[tokio::test]
async fn every_slug_the_deployed_permission_check_accepts_is_a_valid_role_slug() {
    // The STRICT SUBSET claim, against the DEPLOYED role CHECK.
    //
    // That claim is what avoids a second slug grammar and a migration on 0086 and
    // 0087: every valid permission slug must also be a valid role slug. It was
    // asserted in exactly one place, `ironauth_admin::input`'s unit test, against the
    // Rust `require_slug` COPY of the role charset over seven hard-coded slugs. The
    // shipped `org_roles_slug_valid` CHECK was never consulted, so the claim rested on
    // a copy agreeing with a copy: a role CHECK that drifted from its Rust twin, or a
    // permission grammar widened past the role charset, would leave the claim standing
    // and false. This file already has a database; the claim is asserted on it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.control_pool();

    // A role needs an organization to belong to (the 0086 foreign key), so one is
    // created through the ordinary audited management path.
    let organization = OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .organizations(scope)
        .create(&env, &organization, 1_000_000, "strict subset probe", None)
        .await
        .expect("create the probe organization");

    let mut corpus = explicit_corpus();
    corpus.extend(generated_corpus(SEED, GENERATED));

    let mut checked = 0_usize;
    for case in &corpus {
        // The Rust validator is only the cheap PREFILTER here; the assertion below is
        // what makes the selected case a DEPLOYED permission verdict, and the parity
        // test above is what guarantees the prefilter selects exactly the set the
        // permission CHECK accepts.
        if require_permission_slug(case, "slug").is_err() {
            continue;
        }
        assert!(
            postgres_accepts(pool, &env, scope, case).await,
            "the prefilter and the deployed permission CHECK disagree about {case:?}"
        );
        assert!(
            org_roles_accepts(pool, &env, scope, &organization, case).await,
            "{case:?} is accepted as a permission slug but REFUSED by the deployed role \
             CHECK; the permission grammar has stopped being a strict subset of the role \
             charset, and the claim that migrations 0086 and 0087 need no change is false"
        );
        checked += 1;
    }
    assert!(
        checked >= 15,
        "only {checked} accepted permission slugs reached the role CHECK; a corpus that \
         accepts almost nothing would make this subset claim vacuous"
    );

    // `org_groups` carries the SAME charset in a CHECK of its own (0087), and the
    // subset claim is made about both. Rather than repeat the insert sweep against a
    // second table, the two deployed texts are pinned EQUAL: whichever one a later
    // migration edits, they stop matching and this fails.
    let owner = db.owner_pool();
    assert_eq!(
        constraint_definition(owner, "org_roles", ROLE_SLUG_CONSTRAINT).await,
        constraint_definition(owner, "org_groups", "org_groups_slug_valid").await,
        "the role and group slug CHECKs must stay the SAME charset; the permission \
         grammar is claimed to be a strict subset of one alphabet, not of two"
    );
}

#[tokio::test]
async fn the_deployed_check_is_the_grammar_this_issue_specified() {
    // The parity test above proves the two halves AGREE. It cannot prove they agree
    // on the RIGHT grammar: two halves widened together would still agree. This pins
    // the deployed constraint text, so a migration edit that changed the rule has to
    // change this line too and say so out loud.
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    let definition: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'permissions'::regclass AND conname = $1",
    )
    .bind(SLUG_CONSTRAINT)
    .fetch_one(pool)
    .await
    .expect("the slug CHECK exists")
    .get("def");

    assert!(
        definition.contains(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$"),
        "the deployed slug CHECK must carry the specified regex, got: {definition}"
    );
    assert!(
        definition.contains("length(slug) <= 63"),
        "the length bound must be a SEPARATE conjunct, not folded into the regex, got: \
         {definition}"
    );
    // The grammar is a STRICT SUBSET of the shipped role charset, which is what keeps
    // this tree on one slug alphabet and is why migrations 0086 and 0087 need no
    // change. A permission regex that admitted a dot inside the character class would
    // silently re-admit the doubled dot and the trailing dot.
    assert!(
        !definition.contains("[a-z0-9._-]"),
        "the permission charset must NOT be the flat role charset: the delimiter is \
         structural here, got: {definition}"
    );
}

#[tokio::test]
async fn the_kind_and_display_name_checks_are_deployed_and_independent() {
    // The parity probe reads any 23514 that does NOT name the slug constraint as a
    // hard failure, which only works if the other two CHECKs are genuinely separate
    // named constraints. This proves they are, and that each refuses on its own.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.control_pool();

    for (column, value, constraint) in [
        ("kind", "capability", "permissions_kind_known"),
        ("display_name", "", "permissions_display_name_nonempty"),
    ] {
        let id = PermissionId::generate(&env, &scope).to_string();
        let mut tx = pool.begin().await.expect("begin");
        bind_scope(&mut tx, scope).await;
        let statement = format!(
            "INSERT INTO permissions (id, tenant_id, environment_id, slug, display_name, kind) \
             VALUES ($1, $2, $3, 'billing.read', {}, {})",
            if column == "display_name" {
                "$4"
            } else {
                "'ok'"
            },
            if column == "kind" {
                "$4"
            } else {
                "'permission'"
            }
        );
        let result = sqlx::query(&statement)
            .bind(&id)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(value)
            .execute(&mut *tx)
            .await;
        let _ = tx.rollback().await;
        let error = result.expect_err("the CHECK must refuse");
        let database_error = error.as_database_error().expect("a database error");
        assert_eq!(database_error.code().as_deref(), Some(CHECK_VIOLATION));
        assert_eq!(
            database_error.constraint(),
            Some(constraint),
            "{column} must be refused by its OWN named constraint, so a slug parity probe \
             can never mistake one for the other"
        );
    }
}
