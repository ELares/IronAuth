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

fn snapshot_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/config/snapshot")
}

fn plan_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/config/promotion/plan")
}

fn apply_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/config/promotion/apply")
}

fn invitations_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/invitations")
}

fn dcr_policies_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/dcr/policies")
}

fn locale_path(tenant: &str, environment: &str, locale: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/locales/{locale}")
}

fn signup_form_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/signup-form")
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

/// A locale bundle write rewrites the plain text of the auth pages (login, recovery, error
/// copy), a social engineering surface, so it is sudo gated exactly like the other environment
/// scoped management mutations (issue #86 PR 2): challenged without a fresh elevation, and it
/// succeeds after one.
#[tokio::test]
async fn a_locale_write_is_sudo_gated() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = locale_path(&tenant, &env, "fr");
    let body = format!(
        "{{\"entries\":{{\"{}\":\"Se connecter\"}}}}",
        ironauth_oidc::flow::message::LOGIN_TITLE.0
    );

    // Without a fresh elevation the write is challenged and nothing is stored.
    let (status, _, challenge) = harness.put(&path, &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale locale write is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );

    // After elevation the same write succeeds.
    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, stored) = harness.put(&path, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated locale write succeeds: {stored}"
    );
    assert!(
        stored.contains("Se connecter"),
        "the write persisted: {stored}"
    );
}

/// A signup form write is sudo-gated exactly like the other environment-scoped config writes
/// (issue #87): a stale write is challenged and stored nothing; the same write succeeds after a
/// fresh elevation.
#[tokio::test]
async fn a_signup_form_write_is_sudo_gated() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = signup_form_path(&tenant, &env, &client);
    // An empty form needs no active trait schema, so this isolates the sudo gate.
    let body = "{\"fields\":[]}";

    // Without a fresh elevation the write is challenged and nothing is stored.
    let (status, _, challenge) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale signup form write is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );

    // After elevation the same write succeeds.
    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, stored) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated signup form write succeeds: {stored}"
    );
    assert!(stored.contains(&client), "the write persisted: {stored}");
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

/// Count the items in a management list response body.
fn item_count(body: &str) -> usize {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("list json");
    parsed["items"].as_array().map_or(0, Vec::len)
}

/// Build a valid, no-op config-promotion apply body for `(tenant, env)`: export the
/// current snapshot, plan it (a dry run, ungated) to capture the `base_revision`, and
/// pair the two. Applying it is a genuine no-op the sudo gate must still guard.
async fn noop_apply_body(harness: &Harness, tenant: &str, env: &str) -> String {
    let (status, _, snapshot) = harness.get(&snapshot_path(tenant, env)).await;
    assert_eq!(status, StatusCode::OK, "export snapshot: {snapshot}");
    let (status, _, plan) = harness
        .post(&plan_path(tenant, env), "plan-1", &snapshot)
        .await;
    assert_eq!(status, StatusCode::OK, "plan (dry run, ungated): {plan}");
    let plan_json: serde_json::Value = serde_json::from_str(&plan).expect("plan json");
    let base_revision = plan_json["base_revision"]
        .as_str()
        .expect("base_revision")
        .to_owned();
    let source: serde_json::Value = serde_json::from_str(&snapshot).expect("snapshot json");
    serde_json::json!({ "source": source, "base_revision": base_revision }).to_string()
}

/// The sudo gate covers the WHOLE environment-scoped mutation surface, not just the
/// sessions example: the config-promotion apply flagship, invitation creation, and DCR
/// policy creation are all challenged without a fresh elevation (writing nothing) and
/// succeed after one. This is the MEDIUM-1 coverage guarantee (issue #73): the gate is
/// on every environment-scoped audited mutator, including the highest-risk apply.
#[tokio::test]
async fn sudo_gate_covers_apply_promotion_invitations_and_dcr() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);

    let apply_body = noop_apply_body(&harness, &tenant, &env).await;
    let invitation_body = serde_json::json!({ "identifier": "ada@example.test" }).to_string();
    let policy_body = serde_json::json!({
        "name": "force-private-key-jwt",
        "primitives": [{
            "kind": "force",
            "property": "token_endpoint_auth_method",
            "value": "private_key_jwt"
        }]
    })
    .to_string();

    // --- Without a fresh elevation, every one of these environment-scoped mutators is
    // challenged with the RFC 9470 401 and writes NOTHING. ---
    for (label, path, key, body) in [
        (
            "apply_config_promotion",
            apply_path(&tenant, &env),
            "apply-1",
            apply_body.clone(),
        ),
        (
            "create_invitation",
            invitations_path(&tenant, &env),
            "inv-1",
            invitation_body.clone(),
        ),
        (
            "create_dcr_policy",
            dcr_policies_path(&tenant, &env),
            "pol-1",
            policy_body.clone(),
        ),
    ] {
        let (status, _, resp) = harness.post(&path, key, &body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} is challenged without an elevation: {resp}"
        );
        assert!(
            resp.contains("insufficient_user_authentication"),
            "{label} carries the RFC 9470 challenge: {resp}"
        );
    }

    // Nothing was written: no invitation, no policy exists.
    let (_, _, invitations) = harness.get(&invitations_path(&tenant, &env)).await;
    assert_eq!(
        item_count(&invitations),
        0,
        "the challenged create_invitation wrote nothing: {invitations}"
    );
    let (_, _, policies) = harness.get(&dcr_policies_path(&tenant, &env)).await;
    assert_eq!(
        item_count(&policies),
        0,
        "the challenged create_dcr_policy wrote nothing: {policies}"
    );
    // The challenge (expiry) event is audited for these attempts.
    let actions = audit_actions(&harness, scope).await;
    assert!(
        actions.iter().any(|a| a == "admin.privilege.challenged"),
        "a challenged env-scoped mutator is audited: {actions:?}"
    );

    // --- After a fresh elevation, each mutator succeeds. ---
    let (status, _, body) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");

    let (status, _, resp) = harness
        .post(&apply_path(&tenant, &env), "apply-2", &apply_body)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "elevated apply_config_promotion succeeds (no-op): {resp}"
    );
    assert!(
        resp.contains("no_op"),
        "the elevated apply is the expected no-op: {resp}"
    );

    let (status, _, resp) = harness
        .post(&invitations_path(&tenant, &env), "inv-2", &invitation_body)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "elevated create_invitation succeeds: {resp}"
    );

    let (status, _, resp) = harness
        .post(&dcr_policies_path(&tenant, &env), "pol-2", &policy_body)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "elevated create_dcr_policy succeeds: {resp}"
    );
}
