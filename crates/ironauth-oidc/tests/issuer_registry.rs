// SPDX-License-Identifier: MIT OR Apache-2.0

//! The live issuer registry hardening (issue #204), against a real Postgres.
//!
//! Three properties, all resolved through [`IssuerRegistry::entry_for`] with an
//! explicit `now` (the determinism seam threads the instant in, so these tests
//! advance time by passing later instants, never by sleeping):
//!
//! - The positive keyset cache carries a bounded TTL: a rotation on a serving scope
//!   is invisible within the TTL (the cached entry is served) and picked up once the
//!   entry goes stale, with no restart. A loader-less registry never expires. The
//!   suspension fence still wins over a fresh cached entry.
//! - A single malformed key row degrades to the loadable subset instead of failing
//!   the whole environment; an all-bad environment still fails closed (404).
//! - A well-formed nonexistent scope is negatively cached (bounded, TTL'd): a repeat
//!   lookup short-circuits the `signing_keys` load, the negative expires on the TTL,
//!   and it is per-scope (never shadows a different scope).

mod common;

use std::time::{Duration, SystemTime};

use common::{Harness, es256_pkcs8};
use ironauth_jose::JwsAlgorithm;
use ironauth_oidc::{IssuerRegistry, JwksCacheWindow};
use ironauth_store::SigningKeyMaterialKind;

/// The deployment base URL the test registries advertise. The registry's issuer
/// string is not under test here, so any well-formed base serves.
const BASE: &str = "https://issuer.test";

/// A short, explicit cache staleness ceiling, so a test can step just under and just
/// over it deterministically.
const TTL: Duration = Duration::from_secs(100);

/// A store-backed registry over the harness store, with the short test TTL.
fn store_backed(harness: &Harness) -> IssuerRegistry {
    IssuerRegistry::store_backed(BASE, JwksCacheWindow::clamped(300), harness.store().clone())
        .with_entry_ttl(TTL)
}

/// `now` at `secs` past the Unix epoch (the harness clock's origin).
fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

#[tokio::test]
async fn positive_cache_is_fresh_within_ttl_then_reloads_after() {
    // The harness provisions ONE EdDSA key on its primary scope.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness);

    // Cold load: the single EdDSA key, policy EdDSA only.
    let entry = registry
        .entry_for(&scope, at(0))
        .await
        .expect("entry loads");
    assert_eq!(entry.keyset().published_signing_keys(at(0)).len(), 1);
    assert!(entry.policy().permits(JwsAlgorithm::EdDsa));
    assert!(!entry.policy().permits(JwsAlgorithm::Es256));

    // Rotate in a second key of a DIFFERENT algorithm directly in the store.
    harness
        .provision_signing_key(
            scope,
            "ES256",
            SigningKeyMaterialKind::EcdsaPkcs8,
            es256_pkcs8(),
        )
        .await;

    // Within the TTL: the cached entry is served, so the rotated-in key is NOT yet
    // visible (the staleness ceiling has not lapsed).
    let within = registry
        .entry_for(&scope, at(50))
        .await
        .expect("cached entry served");
    assert_eq!(
        within.keyset().published_signing_keys(at(50)).len(),
        1,
        "a fresh cache serves the pre-rotation key set"
    );
    assert!(!within.policy().permits(JwsAlgorithm::Es256));

    // Past the TTL: the entry is stale, reloaded, and the rotated-in key appears.
    let after = registry
        .entry_for(&scope, at(101))
        .await
        .expect("stale entry reloads");
    assert_eq!(
        after.keyset().published_signing_keys(at(101)).len(),
        2,
        "a stale entry reloads and picks up the rotated-in key"
    );
    assert!(
        after.policy().permits(JwsAlgorithm::Es256),
        "the reloaded policy now permits the added algorithm"
    );
}

#[tokio::test]
async fn loader_less_registry_never_expires() {
    // A pre-populated (loader-less) registry has no store to reload from, so its
    // inserted entry is served indefinitely, well past the TTL, and never 404s.
    use ironauth_jose::{KeySet, SigningKey, SigningPolicy};
    use ironauth_oidc::{IssuerEntry, PairwiseSalt};
    use ironauth_store::{EnvironmentType, GuardrailSet, Scope};

    let harness = Harness::start_store_backed().await;
    let scope = Scope::new(harness.scope().tenant(), harness.scope().environment());
    let registry = IssuerRegistry::new(BASE, JwksCacheWindow::clamped(300)).with_entry_ttl(TTL);

    let key =
        SigningKey::ed25519_from_seed(Some("prepop-kid".to_owned()), &[0x22; 32]).expect("key");
    registry.insert(
        scope,
        IssuerEntry::new(
            KeySet::bootstrap(key, SystemTime::UNIX_EPOCH),
            SigningPolicy::eddsa_default(),
            PairwiseSalt::new(Vec::new()),
            GuardrailSet::for_kind(EnvironmentType::Dev),
        ),
    );

    assert!(
        registry.entry_for(&scope, at(0)).await.is_some(),
        "the inserted entry serves at load time"
    );
    assert!(
        registry.entry_for(&scope, at(10 * 100)).await.is_some(),
        "a loader-less registry never expires its inserted entry"
    );
}

#[tokio::test]
async fn the_fence_wins_over_a_fresh_cached_entry() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness);

    // Warm the cache with a fresh entry.
    assert!(registry.entry_for(&scope, at(0)).await.is_some());

    // Suspend the scope (a control-plane fence). The very next resolution fails
    // closed even though the cached entry is still fresh (fence consulted FIRST).
    harness
        .db()
        .set_environment_serving_state(scope, "suspended")
        .await;
    assert!(
        registry.entry_for(&scope, at(1)).await.is_none(),
        "a fenced scope returns None despite a fresh cached entry"
    );
}

#[tokio::test]
async fn one_malformed_row_degrades_to_the_loadable_subset() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.second_scope().await;
    let registry = store_backed(&harness);

    // One healthy EdDSA key and one row whose algorithm name is not a known JOSE
    // algorithm (unreconstructable). The bad row is 32 bytes of valid Ed25519 seed
    // material, so ONLY the algorithm makes it unloadable.
    let seed = harness.fresh_ed25519_seed();
    harness
        .provision_signing_key(scope, "EdDSA", SigningKeyMaterialKind::Ed25519Seed, &seed)
        .await;
    harness
        .provision_signing_key(scope, "BOGUS", SigningKeyMaterialKind::Ed25519Seed, &seed)
        .await;

    let entry = registry
        .entry_for(&scope, at(0))
        .await
        .expect("the healthy subset still serves");
    assert_eq!(
        entry.keyset().published_signing_keys(at(0)).len(),
        1,
        "only the loadable key is published"
    );
    assert!(entry.policy().permits(JwsAlgorithm::EdDsa));
}

#[tokio::test]
async fn an_all_bad_environment_fails_closed() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.second_scope().await;
    let registry = store_backed(&harness);

    // The ONLY provisioned row is unreconstructable (unknown algorithm), so no key
    // loads and the environment fails closed exactly like an unprovisioned one.
    let seed = harness.fresh_ed25519_seed();
    harness
        .provision_signing_key(scope, "BOGUS", SigningKeyMaterialKind::Ed25519Seed, &seed)
        .await;

    assert!(
        registry.entry_for(&scope, at(0)).await.is_none(),
        "an all-bad environment 404s (fail closed)"
    );
}

#[tokio::test]
async fn negative_cache_short_circuits_then_expires() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.second_scope().await; // an environment with NO signing keys yet
    let registry = store_backed(&harness);

    // A genuine post-fence miss records a negative at t0.
    assert!(registry.entry_for(&scope, at(0)).await.is_none());

    // Provision the scope AFTER the negative was recorded. Within the TTL the
    // negative short-circuits the signing_keys load, so the freshly provisioned key
    // is NOT observed: the lookup still returns None (proving the store SELECT was
    // skipped).
    let seed = harness.fresh_ed25519_seed();
    harness
        .provision_signing_key(scope, "EdDSA", SigningKeyMaterialKind::Ed25519Seed, &seed)
        .await;
    assert!(
        registry.entry_for(&scope, at(50)).await.is_none(),
        "a fresh negative short-circuits the store load"
    );

    // Past the TTL the negative is stale, the store is re-queried, and the now
    // provisioned scope resolves.
    assert!(
        registry.entry_for(&scope, at(101)).await.is_some(),
        "the negative expires on the TTL and the scope resolves"
    );
}

#[tokio::test]
async fn the_negative_cache_is_per_scope() {
    let harness = Harness::start_store_backed().await;
    let registry = store_backed(&harness);

    // The primary scope resolves (provisioned); a DIFFERENT, unprovisioned scope is
    // negatively cached. Neither serves the other: a negative for one never shadows
    // a real entry, and a real entry never satisfies a different scope's lookup.
    let resolved = harness.scope();
    let missing = harness.second_scope().await;

    assert!(registry.entry_for(&resolved, at(0)).await.is_some());
    assert!(registry.entry_for(&missing, at(0)).await.is_none());

    // Re-check within the TTL: still isolated (the negative did not poison the real
    // scope, and the cached real entry did not answer the missing scope).
    assert!(registry.entry_for(&resolved, at(10)).await.is_some());
    assert!(registry.entry_for(&missing, at(10)).await.is_none());
}
