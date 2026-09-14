// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every declared use of the hot-state interface, in one place.
//!
//! # Why they live together rather than beside their callers
//!
//! #146 asks that "every trait use must declare its class in code; CI rejects unclassified
//! uses". A declaration beside its caller satisfies the first half and makes the second
//! impossible: a gate would have to decide whether some `HotUse::declare` it found in a handler
//! was a real declaration or a way around the registry, and it cannot.
//!
//! Here, the rule is simple: a declaration appears in this file and nowhere else, and [`ALL`]
//! names every one. Three things hold it, in decreasing order of strength:
//!
//! 1. `HotUse::declare` is `pub(crate)`, so NO OTHER CRATE CAN DECLARE ONE AT ALL. Every call
//!    site the matrix is about lives in another crate, so for all of them this is the compiler's
//!    rule rather than a convention.
//! 2. `scripts/hotstate-classification.sh` covers what privacy cannot say -- "within this crate,
//!    registry.rs only" -- by matching the method NAME with any receiver, so an aliased import
//!    or a UFCS spelling does not walk past it.
//! 3. The same script, and `tests::every_declared_use_is_listed`, check [`ALL`] BY NAME in both
//!    directions. Comparing the two counts (which is what both did at first) passes a registry
//!    that declares `A` and `B` and lists `A` twice.
//!
//! # It also makes the classification READABLE
//!
//! The point of a classification matrix is that somebody can look at it. Spread across twenty
//! call sites it is a property of the codebase that nobody has ever seen at once; here it is a
//! page, and a reviewer asking "what does this deployment do when the cache is gone" has one
//! place to read.

use crate::{Class, HotUse, OnLoss, Reach};

/// The JSON Web Key Set an environment publishes.
///
/// AN ACCELERATOR, unambiguously: the keys are in the store, the document is derived from them,
/// and a miss costs one read and a render. Nothing about a missing entry weakens anything.
pub static JWKS: HotUse = HotUse::declare(
    "jwks",
    Class::Accelerator,
    None,
    // One document per environment, derived from the signing keys. An anonymous caller READS
    // it (the JWKS endpoint is public) but cannot cause an entry: only a key rotation does.
    Reach::Authenticated,
);

/// A tenant's resolved configuration, as the request path reads it.
///
/// ALSO AN ACCELERATOR. It is read on nearly every request and changes rarely, which is the
/// shape a cache is for; and every reader can resolve it from the store.
pub static TENANT_CONFIG: HotUse = HotUse::declare(
    "tenant_config",
    Class::Accelerator,
    None,
    // One entry per environment, written when the configuration changes, which is a management
    // operation.
    Reach::Authenticated,
);

/// The result of an introspection call, for the seconds until it could change.
///
/// AN ACCELERATOR, and the reasoning that put it here is worth keeping because it first put it
/// somewhere else. This was declared `LossyDegradesSecurity { FailOpen }` under the heading
/// "security sensitive", and the paragraph justifying that said: with no cache at all, every
/// introspection reaches the store and answers correctly. THAT IS THE DEFINITION OF
/// [`Class::Accelerator`] -- "the caller must already be able to answer from the store" -- so the
/// doc was arguing for a class the declaration did not use.
///
/// The confusion is worth naming because it is easy to repeat: `Class` is about WHAT HAPPENS
/// WHEN THE ACCELERATOR IS GONE, and the risk here is the opposite case. A STALE HIT tells a
/// caller a revoked token is still active for as long as the entry lives -- a real weakening,
/// but one that exists only while the cache IS available, and one the class system cannot act
/// on. It is bounded by the two things that can: a TTL in seconds rather than minutes, and
/// revocation DELETING the entry rather than waiting for it to lapse.
///
/// Classifying it fail-open to mark it "sensitive" would have been a label with no consequence,
/// since fail-open and accelerator behave identically when the cache is down. A class whose
/// members do not differ in behaviour is a comment.
pub static INTROSPECTION: HotUse = HotUse::declare(
    "introspection",
    Class::Accelerator,
    None,
    // Keyed by a token that was ISSUED, so the number of entries is bounded by the number of
    // live tokens, which the grant paths already bound. An anonymous caller cannot mint one.
    Reach::Authenticated,
);

/// Per-subject counters the rate limiter spends.
///
/// FAIL OPEN, and this is the one where the choice is genuinely contested. A counter that fails
/// closed turns an accelerator outage into a total outage -- every request refused because the
/// limiter cannot confirm it is under budget -- and that is a worse failure than the burst it
/// prevents, for a control whose job is fairness rather than authentication.
///
/// AN OPERATOR MAY INVERT IT. The class records the default; the config surface that overrides
/// it lands with the limiter itself (#150), which is the caller that spends these.
pub static RATE_COUNTER: HotUse = HotUse::declare(
    "rate_counter",
    Class::LossyDegradesSecurity {
        on_loss: OnLoss::FailOpen,
    },
    None,
    // ANONYMOUS, and this is the use that most obviously is: a rate counter exists precisely to
    // count what unauthenticated traffic does, and it is keyed by a subject or an address the
    // caller chooses. Without a ceiling, minting counters IS the flood -- an attacker rotating
    // the key writes one row per request and never trips the limit those rows exist to enforce.
    //
    // 50_000 counters per scope, between the other two because this one is keyed per SUBJECT:
    // more than the pre-auth counters (one per artifact class) and fewer than the single-use
    // markers (one per outstanding artifact, of which a subject may have several).
    //
    // A tenant with more than fifty thousand distinct subjects active inside one counter window
    // is past what this number is sized for, and the right answer then is a deployment-specific
    // one. That belongs with the limiter that spends these counters (issue #150), where an
    // operator already configures the limits; until it lands this is a ceiling rather than a
    // tuning, and it is set where a healthy deployment does not meet it.
    Reach::Anonymous {
        per_scope_entries: 50_000,
    },
);

/// The count of unauthenticated artifacts a tenant or an address has outstanding.
///
/// FAIL CLOSED, and it is the only use here that does. The counter exists to bound what an
/// ANONYMOUS caller can make this deployment store -- flow blobs, device codes, pending markers
/// -- which is the shape of Dex #1292, a pre-auth storage exhaustion open since 2018. Failing
/// open would remove the bound exactly when the deployment is least able to absorb it: an
/// accelerator under enough load to stop answering is one a flood is already hitting.
///
/// THE COST OF BEING WRONG IS ASYMMETRIC and that is the whole argument. Failing closed refuses
/// some unauthenticated requests during a cache outage, which is visible, bounded, and
/// recoverable. Failing open lets an unauthenticated flood write until the disk is full, which
/// takes the deployment down for everybody including the callers who were authenticated.
pub static PRE_AUTH_QUOTA: HotUse = HotUse::declare(
    "pre_auth_quota",
    Class::LossyDegradesSecurity {
        on_loss: OnLoss::FailClosed,
    },
    None,
    // THE USE NAMED FOR THE PROBLEM. It counts pre-authentication artifacts, so every entry is
    // caused by an anonymous request by definition, and a use that bounds a flood while being
    // unbounded itself would be the flood.
    //
    // 10_000, the smallest ceiling here, because this use is keyed per ARTIFACT CLASS rather
    // than per subject: the number of distinct pre-auth counters a tenant needs is the number of
    // kinds of pre-authentication artifact it issues, which is a property of the product and is
    // two orders of magnitude below this. A scope holding ten thousand distinct ones is already
    // the anomaly, so refusing there costs a healthy deployment nothing.
    //
    // Note this is a ceiling on the COUNTERS, not on what they count. A tenant under a flood
    // holds a handful of counters with large values, which is the shape this is sized for; an
    // attacker rotating the counter KEY to mint rows is the shape it refuses.
    Reach::Anonymous {
        per_scope_entries: 10_000,
    },
);

/// The marker that says a single-use artifact has been redeemed.
///
/// CORRECTNESS. An authorization code, a device code, a magic link: each may be spent once, and
/// "was it spent" is a question only an atomic answer settles. A best-effort cache answering
/// "no" to two callers at once is the double redemption the marker exists to prevent.
///
/// ITS FALLBACK IS THE ROW, which is where single-use has always been decided: the conditional
/// UPDATE that spends the artifact is the authority, and this marker only ever saves that write
/// from being attempted twice. With no accelerator the caller does exactly what it does today.
pub static SINGLE_USE_MARKER: HotUse = HotUse::declare(
    "single_use_marker",
    Class::Correctness,
    Some("the artifact's own conditional UPDATE, which is the authority either way"),
    // ANONYMOUS. A device code, an authorization code and a magic-link token are all redeemed by
    // a caller that has not authenticated yet, and each redemption can mint a marker.
    //
    // AND THE QUOTA CAN REFUSE A CLAIM, which needs saying because an earlier version of this
    // comment asserted the opposite. `put_if_absent` on a NEW key, for a scope at this ceiling,
    // returns `HotError::QuotaExceeded`. It does not lie about who won -- that distinction is
    // the whole reason the ceiling gets its own statement -- but it does decline to answer.
    //
    // WHY THAT IS SAFE HERE, AND ONLY HERE. This use is Correctness, so an unanswered claim is
    // not a degraded answer; it is no answer. The class system's response to no answer is the
    // FALLBACK, and this use's fallback is the artifact's own conditional UPDATE, named above --
    // which was always the authority. A caller that gets `QuotaExceeded` does exactly what it
    // does when the accelerator is down: it spends the artifact against the row, and the row
    // settles it. So the ceiling costs a round trip and never a decision.
    //
    // That argument does NOT transfer to a Correctness use with no fallback, and
    // `HotUse::declare` refuses to construct one.
    //
    // 100_000, the largest ceiling here, because a marker lives only as long as its artifact's
    // redemption window and an environment can legitimately have very many codes outstanding at
    // once -- far more than it has pre-auth counters, which are per artifact CLASS. The number
    // is a ceiling and not a capacity plan: at it, every claim still gets a correct answer from
    // Postgres, which is why it can be set high enough to never be reached in normal operation.
    Reach::Anonymous {
        per_scope_entries: 100_000,
    },
);

/// The lock a rotation or migration holds while it moves something that must move once.
///
/// CORRECTNESS, and the fallback is not "proceed": it is the advisory lock in Postgres that this
/// entry accelerates. A lock a caller believes it holds and does not is worse than no lock.
pub static ROTATION_LOCK: HotUse = HotUse::declare(
    "rotation_lock",
    Class::Correctness,
    Some("the Postgres advisory lock, which is the authority either way"),
    // A rotation is an operator action or a scheduled job, never an anonymous request, and the
    // number of locks is the number of things that can be rotated -- a fixed, small set.
    Reach::Authenticated,
);

/// Every declared use.
///
/// THE GATE READS THIS. A use declared above and missing here is one the classification matrix
/// does not show, which is the same defect as not declaring it at all.
pub static ALL: &[&HotUse] = &[
    &JWKS,
    &TENANT_CONFIG,
    &INTROSPECTION,
    &RATE_COUNTER,
    &PRE_AUTH_QUOTA,
    &SINGLE_USE_MARKER,
    &ROTATION_LOCK,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_use_is_listed() {
        // THE DIRECTION THAT CAN FAIL. Comparing `ALL` to itself proves nothing; this reads the
        // source of this very file and asserts each declaration appears in the list, which is
        // what catches a use added above and not below.
        //
        // BY NAME, NOT BY COUNT. An earlier version compared `declared.len()` to `ALL.len()`
        // while its comment claimed it "asserts each declaration appears in the list" -- two
        // different assertions, and the weaker one. A registry that declared `A` and `B` and
        // listed `A` twice had equal lengths and passed, with `B` -- the use missing from the
        // matrix, which is the entire defect this test is named for -- unmentioned.
        let source = include_str!("registry.rs");
        let mut declared: Vec<&str> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub static "))
            .filter_map(|rest| rest.split(':').next())
            .filter(|name| *name != "ALL")
            .collect();
        declared.sort_unstable();
        assert!(
            declared.len() >= 7,
            "the parse found {} declarations, which is too few to be reading this file",
            declared.len()
        );

        // `ALL` holds values, and the static's IDENTIFIER is what the parse above collected, so
        // the two are joined on the name each declaration passes to `declare`. That the two
        // spellings agree is itself worth pinning: `no_declarations_name_disagrees_with_its_ident`
        // below is the reason this join is sound.
        let mut listed: Vec<&str> = ALL.iter().map(|r#use| r#use.name()).collect();
        listed.sort_unstable();
        let idents: Vec<String> = listed.iter().map(|name| name.to_uppercase()).collect();
        let mut idents: Vec<&str> = idents.iter().map(String::as_str).collect();
        idents.sort_unstable();

        for name in &declared {
            assert!(
                idents.contains(name),
                "{name} is declared in this file and does not appear in ALL, so the \
                 classification matrix does not show it"
            );
        }
        for name in &idents {
            assert!(
                declared.contains(name),
                "ALL lists {name}, which is not declared in this file"
            );
        }
    }

    #[test]
    fn no_declarations_name_disagrees_with_its_ident() {
        // WHAT THE TEST ABOVE JOINS ON. A use declared as `pub static ROTATION_LOCK` whose name
        // string said "rotation-lock" would make that join silently vacuous in one direction --
        // every `contains` would fail, which is loud, or worse, a near-miss would pass. Pinning
        // the correspondence here means the membership check is checking membership.
        let source = include_str!("registry.rs");
        let idents: Vec<&str> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub static "))
            .filter_map(|rest| rest.split(':').next())
            .filter(|name| *name != "ALL")
            .collect();
        for r#use in ALL {
            assert!(
                idents.contains(&r#use.name().to_uppercase().as_str()),
                "the use named {:?} has no `pub static` whose identifier is its name in \
                 upper case; the registry's two spellings have drifted",
                r#use.name()
            );
        }
    }

    #[test]
    fn every_use_states_whether_an_anonymous_request_can_cause_an_entry() {
        // BOTH ANSWERS MUST OCCUR. Every quota test in `ironauth-store` fills a use to its
        // declared ceiling and asserts the next write is refused; a registry where nothing were
        // `Anonymous` would make all of them vacuous, and one where EVERYTHING were would cap
        // three uses no anonymous caller can reach -- including JWKS, whose entry count is the
        // number of environments.
        let mut anonymous = Vec::new();
        let mut authenticated = Vec::new();
        for r#use in ALL {
            match r#use.reach() {
                Reach::Anonymous { per_scope_entries } => {
                    assert!(
                        per_scope_entries > 0,
                        "{}'s ceiling is zero, which is a use nothing can write",
                        r#use.name()
                    );
                    assert_eq!(
                        r#use.per_scope_entry_quota(),
                        Some(per_scope_entries),
                        "{}'s accessor must report the ceiling its declaration carries",
                        r#use.name()
                    );
                    anonymous.push(r#use.name());
                }
                Reach::Authenticated => {
                    assert_eq!(
                        r#use.per_scope_entry_quota(),
                        None,
                        "{} is only reachable authenticated, so it must report no ceiling -- a \
                         number here would be enforced against a count nothing bounds",
                        r#use.name()
                    );
                    authenticated.push(r#use.name());
                }
            }
        }
        assert!(
            !anonymous.is_empty() && !authenticated.is_empty(),
            "both reaches must occur: {anonymous:?} are anonymous and {authenticated:?} are \
             not, and a registry where either list is empty makes the other's tests vacuous"
        );

        // A CONSTRAINT NOTHING ELSE ENFORCES. The two assertions above are close to what the
        // enum and the const assertion already give; this one is not. Every ceiling is converted
        // to a signed integer to reach SQL, and the integration tests seed up to a ceiling
        // through a bind that is `i32`. A ceiling past `i32::MAX` would compile, declare
        // cleanly, and then fail at the point of use rather than here.
        for r#use in ALL {
            if let Some(ceiling) = r#use.per_scope_entry_quota() {
                assert!(
                    i32::try_from(ceiling).is_ok(),
                    "{}'s ceiling of {ceiling} does not fit the signed integer it is bound as",
                    r#use.name()
                );
            }
        }
    }

    #[test]
    fn no_use_name_can_confuse_a_key() {
        // WHAT THE IRONCACHE KEY ENCODING RESTS ON, and nothing else enforces.
        //
        // A RESP keyspace is flat, so `IronCacheHotState` isolates tenants by building
        // `ira:{tenant}:{environment}:{use}:{key}` and relying on that being INJECTIVE: two
        // different tuples must not produce one string. Tenant and environment cannot contain a
        // colon (they render as a prefix plus url-safe base64, alphabet `A-Za-z0-9-_`), and the
        // caller's key is LAST so it may contain anything. The use name is the one component
        // whose alphabet is a convention rather than a type -- `HotUse::declare` takes any
        // `&'static str`.
        //
        // So a use named "a:b" would make `ira:t:e:a:b:k` ambiguous with a use "a" and a key
        // "b:k", and one tenant's entry could answer another use's read. This is the check that
        // stops that being possible to write.
        for r#use in ALL {
            let name = r#use.name();
            assert!(
                !name.is_empty(),
                "a use name may not be empty: the key would have an empty component"
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{name:?} is not lowercase ASCII, digits and underscore, so it may not be safe \
                 as a key component; see IronCacheHotState's key encoding"
            );
        }
    }

    #[test]
    fn no_two_uses_share_a_name() {
        // THE NAME IS THE KEY PREFIX and the label a report is read under. Two uses sharing one
        // would let a miss on either be attributed to the other, and would let one use's entries
        // answer the other's reads.
        let mut names: Vec<&str> = ALL.iter().map(|r#use| r#use.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "two uses share a name: {names:?}");
    }

    #[test]
    fn every_correctness_use_names_where_it_goes_instead() {
        // THE PAIRING IS ENFORCED AT COMPILE TIME by `HotUse::declare`, and this is the runtime
        // half: it reads what the fallback SAYS, because a `Some("")` would satisfy the const
        // assertion and tell a reader nothing.
        for r#use in ALL {
            match r#use.class() {
                Class::Correctness => {
                    let fallback = r#use.fallback().unwrap_or("");
                    // WHAT IT SAYS, not how long it is. The comment above used to promise the
                    // former while the code did only the latter, and `Some("aaaaaaaaaaaaaaaaaaaaaa")`
                    // passed it. A fallback is a sentence a person acts on when the accelerator
                    // is down, so it must name a destination: the store is where every one of
                    // these goes, and saying so is the minimum that is worth reading.
                    assert!(
                        fallback.len() > 20,
                        "{} is correctness-relevant and its fallback says only {fallback:?}",
                        r#use.name()
                    );
                    assert!(
                        fallback.split_whitespace().count() >= 5,
                        "{}'s fallback is {fallback:?}, which is a phrase rather than an \
                         instruction",
                        r#use.name()
                    );
                    // NOT A KEYWORD SCAN. The first attempt here required the word "store" or
                    // "database", and it failed against `single_use_marker` -- whose fallback
                    // names the artifact's own conditional UPDATE, which is a BETTER answer than
                    // the word it was looking for. A vocabulary check measures vocabulary; what
                    // a fallback owes a reader is that it is about this use and not another,
                    // which is what the distinctness assertion after this loop can actually
                    // hold.
                    assert!(
                        !fallback
                            .to_lowercase()
                            .contains(&r#use.name().to_lowercase()),
                        "{}'s fallback only repeats its own name: {fallback:?}",
                        r#use.name()
                    );
                }
                _ => assert!(
                    r#use.fallback().is_none(),
                    "{} is not correctness-relevant and names a fallback",
                    r#use.name()
                ),
            }
        }

        // DISTINCT, because one sentence pasted under every correctness use is the shape this
        // whole test is trying to prevent: it would satisfy every assertion above while telling
        // a reader nothing about which use they are looking at.
        let mut fallbacks: Vec<&str> = ALL.iter().filter_map(|r#use| r#use.fallback()).collect();
        let before = fallbacks.len();
        fallbacks.sort_unstable();
        fallbacks.dedup();
        assert_eq!(
            before,
            fallbacks.len(),
            "two correctness uses name the same fallback, so at least one of them is describing \
             somewhere it does not actually go"
        );
    }
}
