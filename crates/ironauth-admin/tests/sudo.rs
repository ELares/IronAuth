// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin session privilege separation (sudo mode) over HTTP (issue #73).
//!
//! The lifecycle (elevate, act, expire, challenge, re-elevate), the acceptance-critical
//! STOLEN-COOKIE adversarial case (a valid credential whose recorded elevation is stale
//! or absent cannot mutate, and no client-supplied header can forge freshness, while
//! reads still work), the inert-when-off posture, and the elevation/expiry audit trail.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, bearer};
use ironauth_store::{EnvironmentId, Scope, TenantId};

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn revoke_path(tenant: &str, environment: &str, session: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/sessions/{session}/revoke")
}

fn elevate_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/admin/sudo/elevate")
}

async fn audit_actions(harness: &Harness, scope: Scope) -> Vec<String> {
    harness
        .control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .collect()
}

/// The full sudo lifecycle: a mutation is challenged until a fresh elevation is
/// recorded, succeeds while the window holds, is challenged again once it lapses, and
/// succeeds after a re-elevation.
#[tokio::test]
async fn sudo_lifecycle_elevate_act_expire_challenge_reelevate() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let elevate = elevate_path(&tenant, &env);

    // A seeded session, and a mutation attempted WITHOUT a fresh elevation: the RFC 9470
    // challenge, and the session is untouched (nothing executed).
    let s1 = harness.seed_session(scope, &subject).await;
    let (status, headers, body) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "stale mutation is challenged: {body}"
    );
    assert!(
        body.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {body}"
    );
    let www = headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        www.contains("insufficient_user_authentication") && www.contains("max_age=600"),
        "the WWW-Authenticate header carries the challenge and max_age: {www}"
    );
    assert!(
        harness.session_resolves(scope, &s1).await,
        "the challenged revoke executed nothing"
    );

    // Elevate, then the same class of mutation succeeds.
    let (status, _, body) = harness.post(&elevate, "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    assert!(body.contains("\"elevated\":true"), "elevate body: {body}");

    let (status, _, body) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r2", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "elevated revoke succeeds: {body}");
    assert!(
        !harness.session_resolves(scope, &s1).await,
        "the elevated revoke executed"
    );

    // Advance the clock past the window: the elevation lapses.
    clock.advance(Duration::from_secs(601));

    let s2 = harness.seed_session(scope, &subject).await;
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s2.to_string()), "r3", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the lapsed window challenges again"
    );
    assert!(
        harness.session_resolves(scope, &s2).await,
        "the challenged revoke executed nothing after expiry"
    );

    // Re-elevate: the mutation succeeds again.
    let (status, _, _) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s2.to_string()), "r4", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "the re-elevated revoke succeeds");
    assert!(!harness.session_resolves(scope, &s2).await);
}

/// The acceptance-critical adversarial case: a valid credential whose recorded elevation
/// is stale or absent CANNOT mutate once the window lapses, and NO client-supplied
/// header can forge the elevation (it derives only from a server-recorded event), while
/// reads are unaffected.
#[tokio::test]
async fn a_stale_credential_cannot_mutate_but_can_read_and_no_header_forges_elevation() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let s1 = harness.seed_session(scope, &subject).await;

    // Reads are unaffected by the flag: the operator can list sessions.
    let (status, _, _) = harness
        .get(&format!("/v1/tenants/{tenant}/environments/{env}/sessions"))
        .await;
    assert_eq!(status, StatusCode::OK, "reads work without an elevation");

    // A mutation with a valid credential but no recorded elevation: challenged.
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no elevation, no mutation"
    );
    assert!(harness.session_resolves(scope, &s1).await);

    // A forged freshness claim in the request (a client-asserted header AND body field)
    // does NOTHING: the elevation is server-side only, so the mutation is still refused
    // and the session is untouched.
    let forged = Request::builder()
        .method("POST")
        .uri(revoke_path(&tenant, &env, &s1.to_string()))
        .header(header::AUTHORIZATION, bearer(common::OPERATOR_TOKEN))
        .header("idempotency-key", "r2")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-privileged", "true")
        .header("x-auth-time", "9999999999999999")
        .header("x-sudo", "1")
        .body(Body::from(
            "{\"elevated\":true,\"acr\":\"urn:ironauth:acr:mfa\"}",
        ))
        .expect("request builds");
    let (status, _, body) = harness.send(forged).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a client-asserted elevation is ignored: {body}"
    );
    assert!(
        harness.session_resolves(scope, &s1).await,
        "the forged-header mutation executed nothing"
    );
}

/// With the flag off (the default), the admin surface behaves exactly as before: a
/// mutation succeeds with no elevation, and the elevate endpoint is a uniform not-found.
#[tokio::test]
async fn sudo_mode_off_by_default_is_fully_inert() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let s1 = harness.seed_session(scope, &subject).await;

    // A mutation succeeds with no elevation (no freshness gate).
    let (status, _, body) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "no gate when the flag is off: {body}"
    );
    assert!(!harness.session_resolves(scope, &s1).await);

    // The elevate endpoint is a uniform not-found when sudo mode is disabled.
    let (status, _, _) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "elevate is inert when off");
}

/// Elevation and expiry (challenge) events are audited (issue #73).
#[tokio::test]
async fn elevation_and_expiry_are_audited() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let s1 = harness.seed_session(scope, &subject).await;

    // A challenged mutation writes the expiry/challenge audit event.
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // An elevation writes the elevation audit event.
    let (status, _, _) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK);

    let actions = audit_actions(&harness, scope).await;
    assert!(
        actions.iter().any(|a| a == "admin.privilege.challenged"),
        "the challenge (expiry) event is audited: {actions:?}"
    );
    assert!(
        actions.iter().any(|a| a == "admin.privilege.elevated"),
        "the elevation event is audited: {actions:?}"
    );
}
