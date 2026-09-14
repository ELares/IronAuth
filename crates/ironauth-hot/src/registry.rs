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
//! Here, the rule a script can check is simple: `HotUse::declare` appears in this file and
//! nowhere else, and [`ALL`] names every one. `scripts/hotstate-classification.sh` enforces
//! both directions, so a use added without a class does not compile past review, and one added
//! without being listed does not pass the gate.
//!
//! # It also makes the classification READABLE
//!
//! The point of a classification matrix is that somebody can look at it. Spread across twenty
//! call sites it is a property of the codebase that nobody has ever seen at once; here it is a
//! page, and a reviewer asking "what does this deployment do when the cache is gone" has one
//! place to read.

use crate::{Class, HotUse, OnLoss};

/// The JSON Web Key Set an environment publishes.
///
/// AN ACCELERATOR, unambiguously: the keys are in the store, the document is derived from them,
/// and a miss costs one read and a render. Nothing about a missing entry weakens anything.
pub static JWKS: HotUse = HotUse::declare("jwks", Class::Accelerator, None);

/// A tenant's resolved configuration, as the request path reads it.
///
/// ALSO AN ACCELERATOR. It is read on nearly every request and changes rarely, which is the
/// shape a cache is for; and every reader can resolve it from the store.
pub static TENANT_CONFIG: HotUse = HotUse::declare("tenant_config", Class::Accelerator, None);

/// The result of an introspection call, for the seconds until it could change.
///
/// SECURITY SENSITIVE AND FAIL OPEN BY DEFAULT, which needs saying rather than assuming. A miss
/// costs a read; a STALE HIT tells a caller a revoked token is still active for as long as the
/// entry lives, which is why the TTL is seconds rather than minutes and why revocation deletes
/// the entry rather than waiting for it to lapse.
///
/// Failing open is right for the UNAVAILABLE case specifically: with no cache at all, every
/// introspection reaches the store and answers correctly. The weakening is the stale window,
/// and that exists only when the cache IS available.
pub static INTROSPECTION: HotUse = HotUse::declare(
    "introspection",
    Class::LossyDegradesSecurity {
        on_loss: OnLoss::FailOpen,
    },
    None,
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
);

/// The lock a rotation or migration holds while it moves something that must move once.
///
/// CORRECTNESS, and the fallback is not "proceed": it is the advisory lock in Postgres that this
/// entry accelerates. A lock a caller believes it holds and does not is worse than no lock.
pub static ROTATION_LOCK: HotUse = HotUse::declare(
    "rotation_lock",
    Class::Correctness,
    Some("the Postgres advisory lock, which is the authority either way"),
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
        let source = include_str!("registry.rs");
        let declared: Vec<&str> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub static "))
            .filter_map(|rest| rest.split(':').next())
            .filter(|name| *name != "ALL")
            .collect();
        assert!(
            declared.len() >= 7,
            "the parse found {} declarations, which is too few to be reading this file",
            declared.len()
        );
        assert_eq!(
            declared.len(),
            ALL.len(),
            "declared {declared:?} but ALL lists {} of them",
            ALL.len()
        );
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
                    assert!(
                        fallback.len() > 20,
                        "{} is correctness-relevant and its fallback says only {fallback:?}",
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
    }
}
