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
// Issue #149 criterion 2: JWKS, and now DISCOVERY TOO (issue #1262).
//
// This block used to say discovery was deliberately NOT relaxed, because its document
// was rendered with a SECOND store read (`supported_ui_locales`) that failed open to
// `["en"]` during an outage, so relaxing it would have published a DEGRADED document
// under the full `Cache-Control` max-age and outlived the incident in every
// relying-party cache. That read now happens on the cold load, on the entry, where a
// failure is a retry rather than a guess, so the objection is gone and discovery
// resolves for publication exactly as JWKS does.
//
// The fence read (`environment_states`) runs ahead of every cache, so renaming that
// table away is what a Postgres outage looks like to this seam: the entry stays warm
// in memory and the fence simply cannot be read. Each test below renames it back
// before asserting, so a failure cannot leave the harness schema broken for the next.
// ---------------------------------------------------------------------------

/// Run `body` with the fence read AND the locale-bundle read broken, restoring both
/// before returning (issue #1262).
///
/// Renaming ONE table is narrower than the criterion: "Postgres is unreachable" is the fault
/// this stands in for, and discovery depends on two reads, so a document that survives one
/// broken table has not been shown to survive the outage.
///
/// BOTH RENAMES ARE LOAD-BEARING NOW, and a review showed they were not before. With only the
/// fence broken, `resolve_with` returns the fresh cached entry and performs no further store
/// reads, so the `locale_bundles` rename could not affect the path under test and the claim
/// that breaking both proved something was decoration. Discovery now reads the bundles LIVE
/// first and falls back to the entry's cached set, so with both tables broken the live read is
/// the one that fails and the fallback is the one that answers. Neutralize either and the
/// byte-identical assertion below goes red.
async fn with_unreadable_store<F, Fut, T>(harness: &Harness, body: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    for statement in [
        "ALTER TABLE environment_states RENAME TO environment_states_hidden",
        "ALTER TABLE locale_bundles RENAME TO locale_bundles_hidden",
    ] {
        harness.db().execute_owner_sql(statement).await;
    }
    let out = body().await;
    for statement in [
        "ALTER TABLE environment_states_hidden RENAME TO environment_states",
        "ALTER TABLE locale_bundles_hidden RENAME TO locale_bundles",
    ] {
        harness.db().execute_owner_sql(statement).await;
    }
    out
}

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
    let served = during.expect("served").expect("well-formed");

    // An expectation derived from the STORE rather than from the same registry call.
    // Comparing `during` to `warm` alone is a check whose expected value comes from the
    // thing it checks: both are rendered from one `Arc<IssuerEntry>` at one instant, so
    // it cannot fail unless the renderer is nondeterministic. Pin the content against
    // what the harness actually provisioned.
    let provisioned = harness
        .store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("keys listed while healthy");
    let document: serde_json::Value = serde_json::from_str(&served).expect("valid JSON");
    let keys = document["keys"].as_array().expect("a keys array");
    assert!(!keys.is_empty(), "the published set must not be empty");
    assert_eq!(
        keys.len(),
        provisioned.len(),
        "every provisioned key must still publish during the outage"
    );
    assert!(
        keys.iter().all(|key| key["kid"].is_string()),
        "every published key carries a kid, so a relying party can select one"
    );

    assert_eq!(
        served,
        warm.expect("warm").expect("well-formed"),
        "and it is byte-identical to the healthy document, not a degraded one"
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

    // Values are collected inside the outage and asserted AFTER the restore. Asserting
    // inside the closure would skip the restore on a panic, since there is no unwind
    // guard -- harmless here because each test owns a throwaway database, but the PR
    // claimed the restore always runs and that claim should be true rather than
    // incidentally survivable.
    let (published, minted) = with_unreadable_fence(&harness, || async {
        (
            registry.jwks_json(&scope, at(0)).await.is_some(),
            registry.entry_for(&scope, at(0)).await.is_some(),
        )
    })
    .await;

    assert!(published, "publication serves");
    assert!(
        !minted,
        "MINTING must still fail closed when the serving state cannot be read"
    );
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

// ---------------------------------------------------------------------------
// Issue #1262: the DISCOVERY half of #149 criterion 2.
// ---------------------------------------------------------------------------

/// The discovery URL for `scope` on the appended-form route.
fn discovery_url(scope: &ironauth_store::Scope) -> String {
    format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    )
}

/// A discovery router over the store-backed registry, and the URL to drive it with.
fn store_backed_discovery(harness: &Harness) -> (axum::Router, String) {
    let registry = std::sync::Arc::new(store_backed(harness));
    let router = ironauth_oidc::discovery_router(ironauth_oidc::DiscoveryState::new(
        BASE,
        JwksCacheWindow::clamped(300),
        ironauth_oidc::DiscoveryCapabilities::default(),
        registry,
        harness.env().clone(),
    ));
    (router, discovery_url(&harness.scope()))
}

/// `GET url` on `router`, returning the status and the body.
async fn get(router: &axum::Router, url: &str) -> (axum::http::StatusCode, String) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let response = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(url)
                .body(axum::body::Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router infallible");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

/// Install a locale bundle for `scope`, so the environment has a locale set worth
/// advertising and worth losing.
async fn install_locale(harness: &Harness, locale: &str) {
    let scope = harness.scope();
    harness
        .db()
        .execute_owner_sql(&format!(
            "INSERT INTO locale_bundles (id, tenant_id, environment_id, locale, entries) \
             VALUES ('lcb_{locale}test', '{}', '{}', '{locale}', '{{}}'::jsonb)",
            scope.tenant(),
            scope.environment()
        ))
        .await;
}

/// THE CRITERION, DISCOVERY HALF: with the store unable to answer, the discovery
/// document served during the outage is BYTE-IDENTICAL to the healthy one.
///
/// Byte-identical rather than merely present is the whole point. Before issue #1262
/// discovery resolved through `entry_for`, so an unreadable fence 404'd it; relaxing
/// that alone would have been worse, because the document is rendered with a
/// `ui_locales_supported` set that came from a SECOND store read ending in
/// `unwrap_or_default()`. With `fr` installed, that read failing turned
/// `["en", "fr"]` into `["en"]`, and the degraded answer went out with the full
/// `Cache-Control: max-age`, so it outlived the outage in every relying-party cache.
#[tokio::test]
async fn discovery_serves_a_byte_identical_document_when_the_store_cannot_be_read() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    install_locale(&harness, "fr").await;
    let (router, url) = store_backed_discovery(&harness);

    // AN EXPECTATION DERIVED FROM THE STORE, not from the document under test.
    // Asserting `during == warm` alone would be a check whose expected value comes from
    // the thing it checks: both render from one `Arc<IssuerEntry>`, so it cannot fail
    // unless the renderer is nondeterministic. This pins the CONTENT to what the store
    // actually holds, which is the fact the outage is supposed to preserve.
    let installed = harness
        .store()
        .scoped(scope)
        .locale_bundles()
        .installed_locales()
        .await
        .expect("bundles list while healthy");
    let mut expected: Vec<String> = installed;
    expected.push("en".to_owned());
    expected.sort();
    expected.dedup();
    assert_eq!(
        expected,
        vec!["en".to_owned(), "fr".to_owned()],
        "precondition: the environment really has two renderable locales"
    );

    let (warm_status, warm) = get(&router, &url).await;
    assert_eq!(
        warm_status,
        axum::http::StatusCode::OK,
        "precondition: discovery serves while the store is healthy"
    );
    let warm_locales = ui_locales(&warm);
    assert_eq!(
        warm_locales, expected,
        "the healthy document advertises exactly what the store holds"
    );

    let (status, during) = with_unreadable_store(&harness, || get(&router, &url)).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "a fresh cached entry must still publish discovery while the database is unreadable"
    );
    assert_eq!(
        ui_locales(&during),
        expected,
        "and it advertises the REAL locale set, not the ['en'] fallback a failed read \
         used to collapse to"
    );
    assert_eq!(
        during, warm,
        "and the whole document is byte-identical to the healthy one, not a degraded \
         variant cached at every relying party for the full max-age"
    );
}

/// `ui_locales_supported` out of a discovery document body.
fn ui_locales(body: &str) -> Vec<String> {
    let document: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
    document["ui_locales_supported"]
        .as_array()
        .expect("ui_locales_supported is an array")
        .iter()
        .map(|value| value.as_str().expect("a tag").to_owned())
        .collect()
}

/// THE LINE THIS DOES NOT CROSS: a FENCED scope, where the state read SUCCEEDED and
/// reports an operator suspension, still 404s on discovery.
///
/// Only UNKNOWN state is softened. If this ever passes, an operator's suspension stops
/// reaching the discovery surface, and a scope the operator took out of service keeps
/// advertising itself.
#[tokio::test]
async fn discovery_still_refuses_a_fenced_scope() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let (router, url) = store_backed_discovery(&harness);

    let (status, _) = get(&router, &url).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "precondition: it serves before the suspension"
    );

    // THE TYPED HARNESS HELPER, which upserts with bound parameters and carries the
    // query-audit-allow marker. This hand-rolled a format!-interpolated INSERT ... ON CONFLICT
    // that was byte-for-byte what `set_environment_serving_state` already does, and which the
    // three neighbouring fenced tests in this file already call.
    //
    // It got there by a worse route than duplication: the first version was a bare UPDATE, and
    // `environment_state()` returns `Active` when the row is ABSENT, which it was for the
    // harness scope. The UPDATE matched zero rows, suspended nothing, and the test drove a
    // perfectly healthy scope while asserting it was refused. The first run caught it (200
    // where 404 was asserted); had the arms been the other way round it would have passed
    // forever. The assertion below stays for the same reason.
    harness
        .db()
        .set_environment_serving_state(scope, "suspended")
        .await;
    assert!(
        harness
            .store()
            .scoped(scope)
            .environment_state()
            .await
            .expect("the state reads")
            .is_fenced(),
        "fixture precondition: the scope really is suspended now"
    );

    let (status, _) = get(&router, &url).await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "a suspended scope is refused, warm entry or not: known operator intent is \
         honoured, only unknown state is softened"
    );
}

/// THE COSMETIC TABLE MUST NOT BE LOAD-BEARING FOR THE MINT.
///
/// This test asserted the opposite until a review caught it. The first version of issue #1262
/// returned `LoadOutcome::Error` when the `locale_bundles` read failed, and this test asserted
/// that the entry did NOT load, as though that were the requirement. It is the defect:
/// `load_issuer_entry` is the cold load behind `entry_for`, which is the TOKEN MINT seam, the
/// JWKS load, the back-channel-logout and SSF push SET signers, and the admin console
/// credential bridge. None of them render a locale. A review broke only `locale_bundles`,
/// left the fence and the keys healthy, and measured `/token` returning 500, JWKS 404 and the
/// console unable to log in: a fault confined to translations took down authentication.
///
/// So the entry LOADS, and carries the failed read as `None` rather than as a default. The one
/// caller that cannot proceed without knowing refuses on its own behalf, which
/// `discovery_refuses_rather_than_advertising_a_guessed_locale_set` pins.
#[tokio::test]
async fn a_failed_bundle_read_does_not_fail_the_entry_the_mint_depends_on() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    install_locale(&harness, "fr").await;
    // A REGISTRY WITH NO WARM ENTRY, so this exercises the cold load.
    let registry = store_backed(&harness);

    harness
        .db()
        .execute_owner_sql("ALTER TABLE locale_bundles RENAME TO locale_bundles_hidden")
        .await;
    let during = registry.entry_for(&scope, at(0)).await;
    harness
        .db()
        .execute_owner_sql("ALTER TABLE locale_bundles_hidden RENAME TO locale_bundles")
        .await;

    let during = during.expect(
        "the entry must still load: the mint, JWKS, the SET signers and the admin bridge all \
         resolve through here and none of them render a locale",
    );
    assert!(
        !during.keyset().published_signing_keys(at(0)).is_empty(),
        "and it carries the keys, so the mint can actually work during the fault"
    );
    assert_eq!(
        during.ui_locales(),
        None,
        "the failed read is CARRIED as not-known, not defaulted to ['en']: defaulting is \
         what let an outage publish a degraded document under the full max-age"
    );

    // AND IT IS NOT NEGATIVE-CACHED: the very next request, at the SAME instant, reloads and
    // now knows the locales. A transient read error that got negative-cached would turn a
    // blip into a TTL-long fault for a real scope.
    let entry = registry
        .entry_for(&scope, at(TTL.as_secs() + 1))
        .await
        .expect("the scope reloads once the entry goes stale");
    assert_eq!(
        entry.ui_locales(),
        Some(["en".to_owned(), "fr".to_owned()].as_slice()),
        "and the reloaded entry carries the real locale set"
    );
}

/// DISCOVERY REFUSES RATHER THAN ADVERTISING A GUESSED LOCALE SET.
///
/// The other half of the test above: the entry survives a failed bundle read, so SOMETHING has
/// to refuse, or the degraded document this whole issue is about ships anyway. Discovery is
/// that something, and a 404 is the right refusal: it is what an unreadable store gave before
/// this change, and it is transient in a way a cached wrong answer is not.
///
/// The fault here breaks ONLY `locale_bundles`, leaving the fence readable, so what this
/// measures is that read's failure direction rather than the fence's.
#[tokio::test]
async fn discovery_refuses_rather_than_advertising_a_guessed_locale_set() {
    let harness = Harness::start_store_backed().await;
    install_locale(&harness, "fr").await;
    let (router, url) = store_backed_discovery(&harness);

    let (status, body) = get(&router, &url).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "precondition: it serves while the bundles are readable"
    );
    assert_eq!(ui_locales(&body), vec!["en".to_owned(), "fr".to_owned()]);

    harness
        .db()
        .execute_owner_sql("ALTER TABLE locale_bundles RENAME TO locale_bundles_hidden")
        .await;
    // A COLD registry, so there is no cached entry to fall back to and the refusal is the
    // only answer left. With a warm entry the cached set answers instead, which is the
    // outage-safety half and is pinned by the byte-identical test above.
    let (cold_router, cold_url) = store_backed_discovery(&harness);
    let (status, body) = get(&cold_router, &cold_url).await;
    harness
        .db()
        .execute_owner_sql("ALTER TABLE locale_bundles_hidden RENAME TO locale_bundles")
        .await;

    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "with no live read and no cached set, discovery must refuse rather than advertise \
         the ['en'] fallback as though it were the environment's real capability: {body}"
    );
}

/// A REMOVED BUNDLE STOPS BEING ADVERTISED AT ONCE, NOT AFTER A TTL.
///
/// The regression the live-first ordering exists to prevent, and the one the first revision of
/// this change introduced. `locale_bundles` is a MUTABLE config table with live set and delete
/// routes, and the hosted pages resolve it per render, so a cached-only discovery would keep
/// advertising a locale the pages had already stopped rendering, for the rest of the entry TTL
/// plus another `max-age` at whichever relying party fetched last.
#[tokio::test]
async fn a_removed_locale_bundle_stops_being_advertised_immediately() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    install_locale(&harness, "fr").await;
    let (router, url) = store_backed_discovery(&harness);

    let (status, body) = get(&router, &url).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        ui_locales(&body),
        vec!["en".to_owned(), "fr".to_owned()],
        "precondition: the removable locale is advertised"
    );

    harness
        .db()
        .execute_owner_sql(&format!(
            "DELETE FROM locale_bundles WHERE tenant_id = '{}' AND environment_id = '{}'",
            scope.tenant(),
            scope.environment()
        ))
        .await;

    // THE SAME ROUTER, the same warm entry, the SAME instant: no TTL has elapsed.
    let (status, body) = get(&router, &url).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        ui_locales(&body),
        vec!["en".to_owned()],
        "a removed bundle must disappear from the advertised set on the NEXT request, \
         because the pages stop rendering it on the next request too"
    );
}

/// THE SUSPENSION WINDOW DISCOVERY OPENS IS BOUNDED BY THE ENTRY TTL, from both sides.
///
/// `a_suspension_landing_just_before_an_outage_is_invisible_for_at_most_one_ttl` pins this for
/// JWKS and drives `jwks_json` only, so routing discovery through the same seam inherited the
/// argument without inheriting the test. A review pointed that out, and the gap matters: the
/// publication relaxation is defensible only because the window CLOSES on its own.
///
/// THREE WRONG VERSIONS PRECEDED THIS ONE, each caught by running it.
///
/// The first asserted that a fenced scope refuses during an outage. That is not what
/// `resolve_for_publication` provides and not what it claims: with the fence unreadable there
/// is no way to learn of a suspension, so a fresh cached entry keeps publishing. It returned
/// 200 where it asserted 404, and the test was wrong rather than the code.
///
/// The second built a short-TTL registry but never warmed it, so its closing 404 came from
/// having NO cached entry rather than from one expiring. It passed for a reason unrelated to
/// the TTL, and a review's mutation freezing the discovery clock at the epoch left it green.
///
/// The third warmed the registry but relied on WALL TIME to age the entry out. The harness
/// clock is a `ManualClock` frozen at a fixed instant, so no amount of real time advances what
/// `DiscoveryState::now()` returns: the entry was permanently fresh and the closing assertion
/// got 200. The clock is ADVANCED explicitly here, which is both what the seam exists for and
/// the only thing that makes the frozen-clock mutation fail.
#[tokio::test]
async fn a_discovery_suspension_landing_just_before_an_outage_is_bounded_by_one_ttl() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let (router, url) = store_backed_discovery(&harness);

    let (status, _) = get(&router, &url).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "precondition: it serves while healthy and unsuspended, and this WARMS the entry"
    );

    harness
        .db()
        .set_environment_serving_state(scope, "suspended")
        .await;
    let (status, _) = get(&router, &url).await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "precondition: the suspension takes effect at once while the store is readable"
    );

    // WITHIN THE TTL, the suspension is invisible: the fence cannot be read, the entry is
    // fresh, and publication serves it. This is the documented cost, not a defect, and it is
    // asserted so that anyone who widens it has to come here and change this line.
    let (status, _) = with_unreadable_store(&harness, || get(&router, &url)).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "a suspension learned only after the outage began cannot be enforced during it"
    );

    // PAST THE TTL, the window closes ON ITS OWN, with the database still unreachable. Only
    // the clock moved.
    harness.clock().advance(TTL + Duration::from_secs(1));
    let (status, body) = with_unreadable_store(&harness, || get(&router, &url)).await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "with no FRESH cached entry there is nothing to publish and no way to establish the \
         scope is unfenced, so the window closes without the database returning: {body}"
    );
}

// ---------------------------------------------------------------------------
// Issue #146: the JWKS accelerator, the hot-state seam's first data-plane caller.
//
// An audit found the seam complete and unreached: the trait, the classification, the stall
// bounds, the tiering and the IronCache backend all built and tested, with `PgHotState::new`
// constructed only in test files and no production path reading through any of the seven
// declared uses. Criterion 2, "with IronCache unreachable, all flows complete correctly on
// Postgres alone", was true by construction and would have stayed true with the crate deleted.
//
// These tests are about the two halves that makes real: that an attached accelerator is
// actually consulted, and that an absent or broken one changes no answer.
// ---------------------------------------------------------------------------

/// A hot state that records every call and can be told to fail.
#[derive(Debug, Default)]
struct RecordingHot {
    calls: std::sync::Mutex<Vec<String>>,
    entries: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    /// When set, every operation answers `Unavailable`, which is what a down accelerator does.
    broken: bool,
}

impl RecordingHot {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("not poisoned").clone()
    }
}

impl ironauth_hot::HotState for RecordingHot {
    fn get<'a>(
        &'a self,
        r#use: &'static ironauth_hot::HotUse,
        key: &'a str,
    ) -> ironauth_hot::Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            self.calls
                .lock()
                .expect("not poisoned")
                .push(format!("get {} {key}", r#use.name()));
            if self.broken {
                return Err(ironauth_hot::HotError::Unavailable);
            }
            Ok(self.entries.lock().expect("not poisoned").get(key).cloned())
        })
    }

    fn put<'a>(
        &'a self,
        r#use: &'static ironauth_hot::HotUse,
        key: &'a str,
        value: &'a [u8],
        _ttl: ironauth_hot::Ttl,
    ) -> ironauth_hot::Answer<'a, ()> {
        Box::pin(async move {
            self.calls
                .lock()
                .expect("not poisoned")
                .push(format!("put {} {key}", r#use.name()));
            if self.broken {
                return Err(ironauth_hot::HotError::Unavailable);
            }
            self.entries
                .lock()
                .expect("not poisoned")
                .insert(key.to_owned(), value.to_vec());
            Ok(())
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        _use: &'static ironauth_hot::HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: ironauth_hot::Ttl,
    ) -> ironauth_hot::Answer<'a, bool> {
        Box::pin(async move { Err(ironauth_hot::HotError::Unavailable) })
    }

    fn delete<'a>(
        &'a self,
        _use: &'static ironauth_hot::HotUse,
        _key: &'a str,
    ) -> ironauth_hot::Answer<'a, ()> {
        Box::pin(async move { Ok(()) })
    }
}

/// THE SEAM HAS A CALLER: an attached accelerator is read, populated, and then served from.
///
/// The assertion that matters is the THIRD one. A test that only checked the document came back
/// would pass against a registry that ignored the accelerator entirely, which is exactly the
/// state the audit found: the whole crate was reachable only from its own tests.
#[tokio::test]
async fn an_attached_accelerator_is_consulted_and_then_serves_the_jwks() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let hot = std::sync::Arc::new(RecordingHot::default());
    let registry = store_backed(&harness).with_jwks_hot_state(hot.clone());

    let first = registry
        .jwks_json(&scope, at(0))
        .await
        .expect("resolves")
        .expect("renders");

    // A MISS THEN A POPULATE, in that order: the accelerator was asked before the render and
    // written after it.
    let calls = hot.calls();
    assert_eq!(calls.len(), 2, "one get and one put: {calls:?}");
    assert!(calls[0].starts_with("get jwks "), "{calls:?}");
    assert!(calls[1].starts_with("put jwks "), "{calls:?}");

    let second = registry
        .jwks_json(&scope, at(0))
        .await
        .expect("resolves")
        .expect("renders");
    assert_eq!(second, first, "the served document is the same document");

    // AND THE SECOND READ WAS A HIT, so it did not render again. Without this the test passes
    // against a registry that writes to the accelerator and never reads it.
    let calls = hot.calls();
    assert_eq!(
        calls.len(),
        3,
        "the second request must be answered by the accelerator, not re-rendered: {calls:?}"
    );
    assert!(calls[2].starts_with("get jwks "), "{calls:?}");
}

/// A BROKEN ACCELERATOR CHANGES NO ANSWER, which is the class's whole contract.
///
/// `Accelerator` means "the caller must already be able to answer from the store", so a miss, a
/// stall, an error and an undecodable value are all the same thing: render. This drives the
/// error arm against the SAME scope a healthy registry serves, and compares the two documents.
#[tokio::test]
async fn a_broken_accelerator_changes_no_answer() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    let without = store_backed(&harness)
        .jwks_json(&scope, at(0))
        .await
        .expect("resolves")
        .expect("renders");

    let hot = std::sync::Arc::new(RecordingHot {
        broken: true,
        ..RecordingHot::default()
    });
    let with_broken = store_backed(&harness)
        .with_jwks_hot_state(hot.clone())
        .jwks_json(&scope, at(0))
        .await
        .expect("a broken accelerator must not stop a publication")
        .expect("renders");

    assert_eq!(
        with_broken, without,
        "an unavailable accelerator must produce the byte-identical document a registry with \
         none produces"
    );
    // AND IT WAS ACTUALLY ASKED, so the equality above is not the equality of two paths that
    // both ignored it.
    assert!(
        hot.calls().iter().any(|call| call.starts_with("get jwks ")),
        "the broken accelerator must have been consulted: {:?}",
        hot.calls()
    );
}

/// THE KEY CARRIES THE PUBLISHED KID SET, so a rotation cannot be served a pre-rotation document.
///
/// This is the property that lets the cache be populated without an invalidation racing the
/// read: the kids that produced a document are IN its key, so a document rendered from a
/// different set is stored under a different key and the old one simply goes unread.
#[tokio::test]
async fn the_accelerator_key_changes_when_the_published_key_set_does() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let hot = std::sync::Arc::new(RecordingHot::default());
    let registry = store_backed(&harness).with_jwks_hot_state(hot.clone());

    let _ = registry.jwks_json(&scope, at(0)).await.expect("resolves");
    let before: Vec<String> = hot
        .calls()
        .into_iter()
        .filter(|call| call.starts_with("get jwks "))
        .collect();
    assert_eq!(before.len(), 1);

    // Provision a SECOND key and let the entry go stale so the registry reloads it.
    harness
        .provision_signing_key(
            scope,
            "ES256",
            SigningKeyMaterialKind::EcdsaPkcs8,
            es256_pkcs8(),
        )
        .await;
    let fresh = store_backed(&harness).with_jwks_hot_state(hot.clone());
    let _ = fresh
        .jwks_json(&scope, at(TTL.as_secs() + 1))
        .await
        .expect("resolves");

    let after: Vec<String> = hot
        .calls()
        .into_iter()
        .filter(|call| call.starts_with("get jwks "))
        .collect();
    assert_eq!(after.len(), 2, "{after:?}");
    assert_ne!(
        after[0], after[1],
        "a changed published key set must change the accelerator key, or a rotation would be \
         served the document it replaced"
    );
}
