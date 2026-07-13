// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pairwise subject derivation (issue #19), database-free.
//!
//! Acceptance criterion 5 requires the pairwise `sub` to be deterministic and
//! IDENTICAL across the ID token and `UserInfo` through one shared derivation
//! function, and stable once derived. There is no `UserInfo` surface yet (it lands
//! with issue #15), so what these tests prove is the property that MAKES the
//! cross-surface guarantee hold: the single shared derivation is deterministic and
//! memoized per environment, so any two surfaces that call it necessarily agree.
//! The cross-surface parity itself is exercised end to end once `UserInfo` exists.

use ironauth_env::FixedEntropy;
use ironauth_oidc::{PairwiseSalt, SubjectCache, SubjectConfig, resolve_subject};

/// The end user's local (per-environment) account identifier.
const LOCAL_SUBJECT: &str = "user-4f2a";
/// The client's sector identifier.
const SECTOR: &str = "client.example.test";

#[test]
fn one_shared_derivation_gives_every_surface_the_same_sub() {
    // Any two call sites that resolve through the SAME shared function and cache
    // (with the same environment salt) get the identical sub. This is the property
    // that guarantees the ID token and a future UserInfo (#15) cannot diverge: they
    // are not two independent derivations, they are two calls to one function.
    let salt = PairwiseSalt::generate(&FixedEntropy::new(0x5A));
    let cache = SubjectCache::new();
    let config = SubjectConfig::pairwise(SECTOR);

    let first_call = cache.resolve(&config, LOCAL_SUBJECT, &salt);
    let second_call = cache.resolve(&config, LOCAL_SUBJECT, &salt);

    assert_eq!(
        first_call, second_call,
        "two resolutions of the same subject return the identical pairwise sub"
    );
    // It is opaque (not the local account id) and pairwise (sector-specific).
    assert_ne!(first_call, LOCAL_SUBJECT);
    let other_sector = cache.resolve(
        &SubjectConfig::pairwise("other.example.test"),
        LOCAL_SUBJECT,
        &salt,
    );
    assert_ne!(first_call, other_sector, "different sector, different sub");
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
fn memoized_sub_is_stable_within_an_environment_and_isolated_across_them() {
    // Within one environment (one salt) a re-derivation returns the identical,
    // already-issued value: memoization pins it for the process. A DIFFERENT
    // environment salt is a distinct partition and correctly yields a different
    // sub, so the two environments cannot correlate the user by comparing subs.
    let cache = SubjectCache::new();
    let config = SubjectConfig::pairwise(SECTOR);
    let env_a = PairwiseSalt::new(vec![1_u8; 32]);
    let first = cache.resolve(&config, LOCAL_SUBJECT, &env_a);
    let again = cache.resolve(&config, LOCAL_SUBJECT, &env_a);
    assert_eq!(
        first, again,
        "an already-derived sub is stable within its environment"
    );
    let env_b = PairwiseSalt::new(vec![2_u8; 32]);
    let other_env = cache.resolve(&config, LOCAL_SUBJECT, &env_b);
    assert_ne!(
        first, other_env,
        "a different environment salt derives a different, isolated sub"
    );
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
