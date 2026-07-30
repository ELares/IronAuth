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
//! until the process restarts. The suite drives the JWKS and discovery surfaces and
//! shows: an active scope serves (200); once suspended it is fenced on the next
//! request with no restart (404); once resumed it serves again (200), the signing
//! key never touched (no data loss).
//!
//! It ALSO drives the TOKEN MINT (issue #406), which is the surface the fence exists
//! for and the one this doc used to assert rode along with the other two ("both funnel
//! through `IssuerRegistry::entry_for`, as does the token mint") while no test here
//! touched it. It does ride the same fence, and it now says so on the strength of
//! `a_suspended_scope_mints_no_token_from_an_outstanding_code` rather than on the
//! strength of a sentence. Its refusal is a `server_error` rather than a 404, because
//! the token endpoint answers in OAuth error shape, and it does not burn the code (the
//! same code mints again once the scope resumes).
//!
//! It also drives the FAIL-CLOSED arm (`a_fence_read_error_fences_rather_than_serving`),
//! which was the other sentence this file was cited for and did not carry: flipping
//! `scope_is_fenced`'s `Err(_) => true` to `false` survived the whole `ironauth-oidc`
//! suite until that test existed.
//!
//! One test here drives the CONTROL PLANE ITSELF rather than seeding a serving state:
//! `a_restored_tenant_that_is_still_suspended_serves_nothing` runs the real suspend ->
//! grace delete -> restore sequence through the audited tenant repository and then asks
//! the data plane what it will serve (issue #432). The others deliberately set the
//! serving state directly, which is why the defect that test pins (a restore writing a
//! literal `active` over a suspended tenant's fence) was invisible to every one of them:
//! they never let a control-plane transition choose the state they assert on.
//!
//! Every test here MUST use `Harness::start_store_backed()`. The default
//! `Harness::start()` installs a static issuer registry that never reads
//! `environment_states`, so a suspended scope keeps serving on it and a lifecycle test
//! written against it passes while exercising nothing.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_store::{ActingTenantRepo, CorrelationId, OperatorId, Scope};
use sqlx::Row;

/// The offboarding retention window these tests restore inside. The harness clock is
/// frozen, so any window longer than zero keeps the restore on offer.
const RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Fetch the mounted JWKS for `scope` and return the HTTP status.
async fn jwks_status(harness: &Harness, scope: &Scope) -> StatusCode {
    jwks(harness, scope).await.0
}

/// Fetch the mounted JWKS for `scope` and return its status AND body, so a test that
/// claims a lifecycle round trip left the signing key alone can compare the published
/// key set itself rather than infer it from a 200.
async fn jwks(harness: &Harness, scope: &Scope) -> (StatusCode, String) {
    let uri = format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment());
    let (status, _headers, body) = harness
        .send(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    (status, body)
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

/// Drive authorize to an OUTSTANDING authorization code for a fresh consenting
/// subject of the harness client, and return it unredeemed.
async fn outstanding_code(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect: {body}"
    );
    location_param(&headers, "code").expect("code in redirect")
}

/// Exchange `code` at the token endpoint as the harness public client.
async fn exchange(harness: &Harness, code: &str) -> (StatusCode, String) {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &harness.client_id().to_string()),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, response) = harness.token(&body).await;
    (status, response)
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

/// The operator that owns `scope`'s tenant, read as the owner: the harness seeds the
/// operator -> tenant -> environment chain directly and keeps the operator id to
/// itself, and the control-plane tenant repository is addressed per operator.
async fn operator_of(harness: &Harness, scope: &Scope) -> OperatorId {
    let raw: String = sqlx::query("SELECT operator_id FROM tenants WHERE id = $1")
        .bind(scope.tenant().to_string())
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("the harness tenant row is present")
        .get("operator_id");
    OperatorId::parse(&raw).expect("operator id parses")
}

/// The acting, audited control-plane tenant repository for `operator`, over the
/// CONTROL-plane store, exactly as the management API reaches it.
fn tenants(harness: &Harness, operator: OperatorId) -> ActingTenantRepo<'_> {
    harness
        .db()
        .control_store()
        .management()
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .tenants(operator)
}

#[tokio::test]
async fn a_restored_tenant_that_is_still_suspended_serves_nothing() {
    // Issue #432, at the surface the fence exists for. The other tests here set the
    // serving state directly; this one drives the REAL control-plane lifecycle calls
    // (suspend -> grace delete -> restore) and then asks the data plane what it will
    // serve. The defect: `restore` wrote a literal `active` serving state for every
    // environment, so a tenant whose `tenants.status` still read `suspended` came back
    // serving JWKS and discovery with nobody having lifted the suspension.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let operator = operator_of(&harness, &scope).await;

    // The control: active and serving, which also WARMS the registry cache. The
    // published key set is kept, so the claim that the round trip below never touches
    // the signing key is carried by a comparison rather than by a 200.
    let (status, published_keys) = jwks(&harness, &scope).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an active environment serves its JWKS"
    );

    // Suspend through the control plane: fenced on the next request.
    tenants(&harness, operator)
        .suspend(harness.env(), &scope.tenant(), None)
        .await
        .expect("suspend");
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a suspended tenant is fenced off the JWKS surface"
    );

    // Grace-delete and then RESTORE inside the retention window. The restore undoes
    // the delete; it must not undo the suspension too.
    tenants(&harness, operator)
        .delete(harness.env(), &scope.tenant())
        .await
        .expect("grace delete");
    tenants(&harness, operator)
        .restore(harness.env(), &scope.tenant(), RETENTION, None)
        .await
        .expect("restore in window");

    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a restored tenant whose status is still suspended serves no JWKS"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "and no discovery document: the restore did not lift the suspension"
    );

    // The explicit RESUME is what lifts it, and it still does after a restore: the
    // fence a restore preserves is not a permanent one.
    tenants(&harness, operator)
        .resume(harness.env(), &scope.tenant(), None)
        .await
        .expect("resume");
    let (status, keys_after) = jwks(&harness, &scope).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a resumed tenant serves its JWKS again"
    );
    assert_eq!(
        keys_after, published_keys,
        "and serves the SAME key set: suspend, delete, restore, and resume never \
         touched the signing key"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::OK,
        "and serves discovery again"
    );
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
async fn a_suspended_scope_mints_no_token_from_an_outstanding_code() {
    // The TOKEN MINT, which this file's own module doc has always named as riding the
    // same fence while the file drove only JWKS and discovery (issue #406). It is the
    // surface that matters most and it was the one not measured, so it is measured
    // here. This is also the ENVIRONMENT and TENANT half of the effective-resolution
    // liveness question: those two dimensions are deliberately NOT fenced in the
    // organization closure, on the grounds that a deactivated scope must not issue a
    // token at all rather than issue a role-less one. That grounds is only sound if
    // this passes.
    //
    // # THE HARNESS TRAP, which is the reason to read this comment before writing a
    // # lifecycle test of your own
    //
    // This MUST use `Harness::start_store_backed()`. The default `Harness::start()`
    // installs a STATIC issuer registry that never consults `environment_states`, so a
    // suspended scope on that harness serves a full 200 with a signed, claim-bearing
    // access token and every assertion below passes in reverse. A lifecycle test
    // written on the default harness is green, silent, and worthless: it reports that
    // the fence works while exercising no fence at all. That was measured on this
    // exact scenario before this test was written, which is why it is written down.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // The control: an active scope mints from an outstanding code, so a refusal below
    // is attributable to the fence rather than to the fixture or the store-backed
    // wiring.
    let code = outstanding_code(&harness).await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "active scope exchange: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "an active scope mints an access token"
    );

    // Suspend, with the issuer entry now warm in the registry from the exchange above.
    // The next exchange must refuse on the SAME running node, no restart, exactly as
    // the JWKS and discovery surfaces do.
    let code = outstanding_code(&harness).await;
    set_serving(&harness, &scope, "suspended").await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a suspended scope refuses the exchange: {body}"
    );
    // NOTE, and it is a decision this test FREEZES rather than one it endorses: the
    // refusal shape is `500 server_error`, because the issuer-entry lookup cannot tell
    // "fenced" from "no signing key" and the latter really is a fault. An administrative
    // suspension is not, and the JWKS and discovery surfaces answer `404` for the very
    // same scope. That disagreement is pre-existing and is tracked in issue #433; what
    // this test is FOR is that nothing is minted, which holds under either shape.
    assert_eq!(json(&body)["error"], "server_error");
    assert!(
        json(&body).get("access_token").is_none(),
        "a suspended scope mints no access token"
    );
    assert!(
        json(&body).get("id_token").is_none(),
        "and no id token: the fence is upstream of the signing, not a claim filter"
    );

    // Resumed. The refused exchange did NOT consume the code: this fence sits at the
    // issuer-entry lookup inside `mint_tokens`, and the whole mint runs BEFORE the
    // atomic redeem precisely so a signing failure never burns a code. So the SAME
    // code, unredeemed, is presented again here rather than a fresh one, which turns
    // that claim from a comment into an assertion.
    set_serving(&harness, &scope, "active").await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "resumed scope exchange: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "a resumed scope mints again from the very code the fence refused, its signing \
         key never touched and that code never burned"
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

#[tokio::test]
async fn a_fence_read_error_fences_rather_than_serving() {
    // The FAIL-CLOSED half of the fence (issue #406). `scope_is_fenced` maps a store
    // read error on `environment_states` to `true`, and that arm was previously
    // claimed by the census and pinned by NOTHING: flipping `Err(_) => true` to
    // `Err(_) => false` survived the entire `ironauth-oidc` suite, measured. It is the
    // arm that matters most operationally, because a suspension enforced only while
    // the database is healthy is not a suspension: a pool timeout on the fence read
    // would let a suspended or offboarded tenant serve for as long as the blip lasts.
    //
    // The blip is induced the same way
    // `a_transient_store_error_does_not_negative_cache_a_real_scope` induces one in
    // `crates/ironauth-oidc/tests/issuer_registry.rs`: RENAME the table out from under
    // the read, so the SELECT errors while everything else stays healthy. Rename
    // rather than drop, so the relation's OID survives and restoring it invalidates no
    // cached plan.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // The controls, both taken while the scope is healthy and ACTIVE, so a refusal
    // below is attributable to the read error and not to a fence state or a fixture.
    // Taking them first also WARMS the registry cache, which is what makes the
    // assertion sharp: the fence has to beat a fresh cached entry, not merely a cold
    // load that would fail anyway.
    let code = outstanding_code(&harness).await;
    assert_eq!(jwks_status(&harness, &scope).await, StatusCode::OK);
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "healthy active scope: {body}");

    // The blip: the fence read now errors. Everything else (the signing keys, the
    // guardrails, the codes) is untouched and healthy.
    let code = outstanding_code(&harness).await;
    harness
        .db()
        .execute_owner_sql("ALTER TABLE environment_states RENAME TO environment_states_hidden")
        .await;

    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a fence read error denies serving rather than permitting it"
    );
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "and the token mint refuses too: {body}"
    );
    assert_eq!(json(&body)["error"], "server_error");
    assert!(
        json(&body).get("access_token").is_none(),
        "no access token is minted while the fence cannot be read"
    );

    // The blip clears. The scope serves again on the VERY NEXT request, so failing
    // closed here is a refusal for the duration of the fault and not a self-inflicted
    // outage that outlives it.
    harness
        .db()
        .execute_owner_sql("ALTER TABLE environment_states_hidden RENAME TO environment_states")
        .await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::OK,
        "the healthy scope serves again on the next request"
    );
    let code = outstanding_code(&harness).await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "and mints again: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "the fence read error cost the scope nothing beyond the blip"
    );
}
