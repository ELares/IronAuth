// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tenant-lifecycle DATA-PLANE fence (issue #46), against a real Postgres.
//!
//! A suspended (or offboarded) tenant must stop serving its data plane. The
//! control plane records the serving decision in the scoped, data-plane-readable
//! `environment_states` table; the store-backed issuer registry consults it on
//! EVERY resolution and fails closed for a fenced scope.
//!
//! The load-bearing property this proves is IMMEDIACY WITHOUT A RESTART: the scope
//! is served at least once first (so its issuer entry is CACHED in the live
//! registry), and only then suspended. A correct fence stops serving on the very
//! NEXT request against the SAME running node; a fence that only re-checks on a cold
//! cache load (the defect this test guards) would keep serving the cached entry
//! until the process restarts. The suite drives the JWKS and discovery surfaces
//! (both funnel through `IssuerRegistry::entry_for`, as does the token mint) and
//! shows: an active scope serves (200); once suspended it is fenced on the next
//! request with no restart (404); once resumed it serves again (200), the signing
//! key never touched (no data loss).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use ironauth_store::Scope;

/// Fetch the mounted JWKS for `scope` and return the HTTP status.
async fn jwks_status(harness: &Harness, scope: &Scope) -> StatusCode {
    let uri = format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment());
    status_of(harness, &uri).await
}

/// Fetch the appended-form discovery document for `scope` and return the status.
async fn discovery_status(harness: &Harness, scope: &Scope) -> StatusCode {
    let uri = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    status_of(harness, &uri).await
}

/// `GET uri` through the router and return only the status.
async fn status_of(harness: &Harness, uri: &str) -> StatusCode {
    let (status, _headers, _body) = harness
        .send(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    status
}

/// Set the data-plane serving state of `scope`, exactly as a control-plane
/// suspend/resume/delete cascade writes it. The control-plane transition logic
/// itself is proven in the store crate's tenant-lifecycle tests; here we only need
/// the precondition set.
async fn set_serving(harness: &Harness, scope: &Scope, status: &str) {
    harness
        .db()
        .set_environment_serving_state(*scope, status)
        .await;
}

#[tokio::test]
async fn a_suspended_scope_is_fenced_on_the_next_request_without_a_restart() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // Serve the scope FIRST, so its issuer entry is now cached in the live registry.
    // Both surfaces are 200 for an active, provisioned environment.
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::OK,
        "an active environment serves its JWKS"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::OK,
        "an active environment serves its discovery document"
    );

    // Suspend the scope (a control-plane suspend cascade). NO restart: the SAME
    // running node, with the entry still cached, must stop serving on the next
    // request. This is the assertion the cached-fast-path defect fails: without the
    // per-resolution fence the cached entry keeps serving JWKS/discovery/token.
    set_serving(&harness, &scope, "suspended").await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a suspended scope is fenced off the JWKS surface on the very next request"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a suspended scope is fenced off the discovery surface on the very next request"
    );

    // Resume the scope: it serves again on the next request, still no restart, and
    // the signing key was never touched (no data loss).
    set_serving(&harness, &scope, "active").await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::OK,
        "a resumed scope serves its JWKS again with no data loss"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::OK,
        "a resumed scope serves its discovery document again"
    );
}

#[tokio::test]
async fn a_deleted_scope_stops_serving_immediately() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // Warm the cache with a served request.
    assert_eq!(jwks_status(&harness, &scope).await, StatusCode::OK);

    // A tenant delete (offboard) fences every environment by writing the suspended
    // serving state, exactly as suspend does. The fenced scope stops serving at once,
    // no restart, on both surfaces.
    set_serving(&harness, &scope, "suspended").await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a deleted (fenced) scope stops serving its JWKS immediately"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a deleted (fenced) scope stops serving its discovery immediately"
    );
}
