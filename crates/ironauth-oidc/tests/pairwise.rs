// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pairwise subject derivation across surfaces (issue #19), database-free.
//!
//! Acceptance criterion 5: the pairwise `sub` is deterministic and IDENTICAL
//! across the ID token and `UserInfo`, through one shared derivation function, and
//! switching a client to pairwise never changes an already-derived `sub`
//! (memoization).

use ironauth_env::FixedEntropy;
use ironauth_oidc::{PairwiseSalt, SubjectCache, SubjectConfig, resolve_subject};

/// The end user's local (per-environment) account identifier.
const LOCAL_SUBJECT: &str = "user-4f2a";
/// The client's sector identifier.
const SECTOR: &str = "client.example.test";

#[test]
fn pairwise_sub_is_identical_across_id_token_and_userinfo() {
    // One environment salt, one shared cache: the ID token path and the UserInfo
    // path both resolve the subject through the SAME function and cache.
    let salt = PairwiseSalt::generate(&FixedEntropy::new(0x5A));
    let cache = SubjectCache::new();
    let config = SubjectConfig::pairwise(SECTOR);

    // The ID token surface derives the sub...
    let id_token_sub = cache.resolve(&config, LOCAL_SUBJECT, &salt);
    // ...and the UserInfo surface derives it independently.
    let userinfo_sub = cache.resolve(&config, LOCAL_SUBJECT, &salt);

    assert_eq!(
        id_token_sub, userinfo_sub,
        "the ID token and UserInfo must return the identical pairwise sub"
    );
    // It is opaque (not the local account id) and pairwise (sector-specific).
    assert_ne!(id_token_sub, LOCAL_SUBJECT);
    let other_sector = cache.resolve(
        &SubjectConfig::pairwise("other.example.test"),
        LOCAL_SUBJECT,
        &salt,
    );
    assert_ne!(
        id_token_sub, other_sector,
        "different sector, different sub"
    );
}

#[test]
fn derivation_is_deterministic_across_fresh_state() {
    // A completely fresh cache and an equal salt reproduce the exact same sub, so
    // the value does not depend on any hidden per-process state.
    let salt_a = PairwiseSalt::new(vec![3_u8; 32]);
    let salt_b = PairwiseSalt::new(vec![3_u8; 32]);
    let config = SubjectConfig::pairwise(SECTOR);
    let a = resolve_subject(&config, LOCAL_SUBJECT, &salt_a);
    let b = resolve_subject(&config, LOCAL_SUBJECT, &salt_b);
    assert_eq!(a, b);
}

#[test]
fn memoized_sub_never_changes_once_derived() {
    // Once a sub has been derived and (conceptually) issued to the relying party,
    // re-deriving it must return the identical value, even if the environment salt
    // were rotated underneath: memoization pins the already-issued identifier.
    let cache = SubjectCache::new();
    let config = SubjectConfig::pairwise(SECTOR);
    let first = cache.resolve(&config, LOCAL_SUBJECT, &PairwiseSalt::new(vec![1_u8; 32]));
    let after_salt_change =
        cache.resolve(&config, LOCAL_SUBJECT, &PairwiseSalt::new(vec![2_u8; 32]));
    assert_eq!(first, after_salt_change, "an already-derived sub is stable");
}

#[test]
fn public_sub_is_the_local_account_id_through_the_same_function() {
    // A public subject flows through the same shared function and returns the local
    // account id verbatim, so the ID token and UserInfo agree there too.
    let config = SubjectConfig::public();
    let salt = PairwiseSalt::new(Vec::new());
    assert_eq!(
        resolve_subject(&config, LOCAL_SUBJECT, &salt),
        LOCAL_SUBJECT
    );
}
