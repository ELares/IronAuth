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

#[tokio::test]
async fn a_transient_store_error_does_not_negative_cache_a_real_scope() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope(); // a healthy, active, fully provisioned scope
    let registry = store_backed(&harness);

    // Induce a TRANSIENT store error on the guardrails SELECT (which fires AFTER the
    // keys SELECT already succeeded) by renaming the environment_guardrails view out
    // from under the load. The fence read (environment_states) and the keys list still
    // succeed, so this isolates a post-keys read blip on an otherwise healthy scope.
    // Rename (not drop) preserves the view's OID, so restoring it does not invalidate
    // any cached statement plan.
    harness
        .db()
        .execute_owner_sql(
            "ALTER VIEW environment_guardrails RENAME TO environment_guardrails_hidden",
        )
        .await;

    // During the blip the load fails closed for THIS request, exactly as pre-#204.
    assert!(
        registry.entry_for(&scope, at(0)).await.is_none(),
        "a transient store error fails closed for that one request"
    );

    // The blip clears: restore the view.
    harness
        .db()
        .execute_owner_sql(
            "ALTER VIEW environment_guardrails_hidden RENAME TO environment_guardrails",
        )
        .await;

    // The VERY NEXT request (SAME `now`, no TTL advance) must resolve. Had the error
    // been negative-cached, this would 404 until a full TTL elapsed; it resolves,
    // proving no negative was recorded for a real scope over a transient error.
    assert!(
        registry.entry_for(&scope, at(0)).await.is_some(),
        "the healthy scope self-heals on the next request (no negative was cached)"
    );
}

// ---------------------------------------------------------------------------
// Issue #149 criterion 2: a database outage must not stop discovery or JWKS.
//
// The fence read (`environment_states`) runs ahead of every cache, so renaming that
// table away is what a Postgres outage looks like to this seam: the entry stays warm
// in memory and the fence simply cannot be read. Each test below renames it back
// before asserting, so a failure cannot leave the harness schema broken for the next.
// ---------------------------------------------------------------------------

/// Run `body` with the fence read broken, restoring the table before returning.
async fn with_unreadable_fence<F, Fut, T>(harness: &Harness, body: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    harness
        .db()
        .execute_owner_sql("ALTER TABLE environment_states RENAME TO environment_states_hidden")
        .await;
    let out = body().await;
    harness
        .db()
        .execute_owner_sql("ALTER TABLE environment_states_hidden RENAME TO environment_states")
        .await;
    out
}

/// THE CRITERION: with the store unable to answer, a FRESH cached JWKS entry serves.
///
/// Before the publication split this returned `None` on the first request after the
/// outage, with the warm entry sitting unused, because the fence failed closed ahead
/// of the cache.
#[tokio::test]
async fn jwks_serves_a_fresh_cached_entry_when_the_fence_cannot_be_read() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness);

    let warm = registry.jwks_json(&scope, at(0)).await;
    assert!(
        warm.is_some(),
        "precondition: JWKS serves while the store is healthy"
    );

    let during = with_unreadable_fence(&harness, || registry.jwks_json(&scope, at(0))).await;
    assert!(
        during.is_some(),
        "a fresh cached JWKS must still publish while the database is unreadable"
    );
    assert_eq!(
        during.expect("served").expect("well-formed"),
        warm.expect("warm").expect("well-formed"),
        "and it must be the same document, not a degraded one"
    );
}

/// THE ASYMMETRY, and the reason this change is not a fence relaxation: the same
/// registry, the same warm entry, the same outage -- and the MINTING seam still
/// refuses. If this ever passes, a scope whose serving state is unknown can mint.
#[tokio::test]
async fn the_minting_seam_still_fails_closed_while_publication_serves() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness);

    assert!(
        registry.entry_for(&scope, at(0)).await.is_some(),
        "precondition"
    );

    with_unreadable_fence(&harness, || async {
        assert!(
            registry.jwks_json(&scope, at(0)).await.is_some(),
            "publication serves"
        );
        assert!(
            registry.entry_for(&scope, at(0)).await.is_none(),
            "MINTING must still fail closed when the serving state cannot be read"
        );
    })
    .await;
}

/// A STALE entry is still never published. The #204 argument is untouched: serving a
/// stale key set would extend the staleness window of a compromise rotation, and an
/// outage is exactly when that window matters most.
#[tokio::test]
async fn a_stale_entry_is_not_published_even_during_an_outage() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness);

    assert!(
        registry.jwks_json(&scope, at(0)).await.is_some(),
        "precondition"
    );

    // One second PAST the TTL, so the cached entry is unambiguously stale.
    let stale_at = at(TTL.as_secs() + 1);
    let during = with_unreadable_fence(&harness, || registry.jwks_json(&scope, stale_at)).await;
    assert!(
        during.is_none(),
        "a stale entry must not be published, outage or not"
    );
}

/// A FENCED scope still refuses on the publication surface. Only UNKNOWN state is
/// softened; known operator intent is honoured everywhere.
#[tokio::test]
async fn a_fenced_scope_still_refuses_to_publish() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness);

    assert!(
        registry.jwks_json(&scope, at(0)).await.is_some(),
        "precondition"
    );

    // The fence read SUCCEEDS here and reports a suspension. No outage involved.
    harness
        .db()
        .set_environment_serving_state(scope, "suspended")
        .await;
    assert!(
        registry.jwks_json(&scope, at(0)).await.is_none(),
        "an operator suspension must still stop publication, cached entry or not"
    );
}

/// With nothing cached there is nothing public to serve AND no way to establish the
/// scope is unfenced, so an unreadable fence refuses. The fix must not turn a cold
/// registry into one that serves during an outage.
#[tokio::test]
async fn a_cold_registry_refuses_to_publish_during_an_outage() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness); // never warmed

    let during = with_unreadable_fence(&harness, || registry.jwks_json(&scope, at(0))).await;
    assert!(
        during.is_none(),
        "a cold registry has nothing to publish and cannot clear the fence"
    );
}

/// THE COST OF THE SPLIT, stated as a measurement rather than a caveat.
///
/// A scope suspended while the database is UP is refused immediately, because the
/// fence read succeeds (see `a_fenced_scope_still_refuses_to_publish`). But a scope
/// suspended shortly BEFORE an outage keeps publishing until its cached entry goes
/// stale, because during the outage there is no way to learn about the suspension.
///
/// The window is therefore bounded by the entry TTL, and this test pins that bound
/// from both sides: still publishing just inside it, refused just outside. What
/// leaks is public key material for at most one TTL, and minting is refused
/// throughout; that is the trade the publication split makes, and it is bounded
/// rather than open-ended.
#[tokio::test]
async fn a_suspension_landing_just_before_an_outage_is_invisible_for_at_most_one_ttl() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let registry = store_backed(&harness);

    // Warm at t=0, then suspend. The suspension is real in the database.
    assert!(
        registry.jwks_json(&scope, at(0)).await.is_some(),
        "precondition"
    );
    harness
        .db()
        .set_environment_serving_state(scope, "suspended")
        .await;

    // Inside the TTL, with the fence unreadable: the suspension is invisible.
    let inside = with_unreadable_fence(&harness, || {
        registry.jwks_json(&scope, at(TTL.as_secs() - 1))
    })
    .await;
    assert!(
        inside.is_some(),
        "inside the TTL an outage hides the suspension: this is the cost being bounded"
    );

    // Past the TTL the entry is stale, so there is nothing fresh to publish and the
    // window closes on its own, with the database still unreachable.
    let outside = with_unreadable_fence(&harness, || {
        registry.jwks_json(&scope, at(TTL.as_secs() + 1))
    })
    .await;
    assert!(
        outside.is_none(),
        "past the TTL the window closes without the database coming back"
    );
}
