// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public invitation-accept endpoint (issue #60), against a real Postgres.
//!
//! The store tests pin the data model and atomicity; these pin what an INVITEE
//! actually experiences through the public HTTP surface, and the properties that
//! make it safe:
//!
//! - a valid password token activates the pending-verification user
//!   (`pending_verification` -> active) and sets the credential; a passkey token
//!   activates WITHOUT any password;
//! - the token is SINGLE USE: a second accept of the same token is the uniform
//!   not-found;
//! - a forged, expired, or revoked token is the SAME uniform not-found (no
//!   token-guessing or existence oracle);
//! - a token minted in one tenant can NEVER be accepted at another tenant's path.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_store::{
    CorrelationId, InvitationCredentialType, MintedInvitationToken, NewAdminUser, NewInvitation,
    Scope, UserId, UserState, mint_invitation_token,
};
use serde_json::Value;

/// The current clock-seam time in microseconds since the Unix epoch.
fn now_micros(harness: &Harness) -> i64 {
    i64::try_from(
        harness
            .env()
            .clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Create a pending-verification user and an invitation for it in `scope` (through
/// the CONTROL plane, as the admin API does), returning the user id and the raw
/// one-time token.
async fn create_invitation(
    harness: &Harness,
    scope: Scope,
    identifier: &str,
    credential_type: InvitationCredentialType,
    ttl_micros: i64,
) -> (UserId, String) {
    let env = harness.env();
    let db = harness.db();
    let created = now_micros(harness);
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(env, &scope);
    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            created,
            None,
        )
        .await
        .expect("create pending user");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .invitations()
        .create(
            env,
            NewInvitation {
                id: &id,
                user_id: &user_id,
                target_identifier: identifier,
                token_digest: &digest,
                credential_type,
                org_context: None,
                expires_at_unix_micros: created.saturating_add(ttl_micros),
            },
            created,
            None,
        )
        .await
        .expect("create invitation");
    (user_id, token)
}

/// The accept path for `scope`.
fn accept_path(scope: Scope) -> String {
    format!(
        "/t/{}/e/{}/invitations/accept",
        scope.tenant(),
        scope.environment()
    )
}

/// POST a JSON body to `path`; return the status and parsed JSON body.
async fn accept(harness: &Harness, path: &str, body: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds");
    let (status, _headers, response) = harness.send(request).await;
    let parsed = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).expect("json")
    };
    (status, parsed)
}

/// The user's current lifecycle state, read through the app store.
async fn user_state(harness: &Harness, scope: Scope, id: &UserId) -> UserState {
    harness
        .store()
        .scoped(scope)
        .users()
        .get(id)
        .await
        .expect("user get")
        .state
}

#[tokio::test]
async fn a_password_token_activates_the_user_and_is_single_use() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "ada@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": "correct horse battery staple" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "accept: {body}");
    assert_eq!(body["accepted"], true);
    assert_eq!(body["user_id"], user_id.to_string());
    assert_eq!(body["credential_type"], "password");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::Active
    );

    // A SECOND accept of the same token is the uniform not-found.
    let (again_status, again_body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": "correct horse battery staple" }),
    )
    .await;
    assert_eq!(
        again_status,
        StatusCode::NOT_FOUND,
        "second accept: {again_body}"
    );
    assert_eq!(again_body["error"], "invalid_invitation");
}

#[tokio::test]
async fn a_passkey_token_activates_without_a_password() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "grace@example.test",
        InvitationCredentialType::Passkey,
        1_000_000_000,
    )
    .await;

    // No password field at all: a passkey invitation provisions none.
    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "passkey accept: {body}");
    assert_eq!(body["credential_type"], "passkey");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::Active
    );
}

#[tokio::test]
async fn a_password_token_without_a_password_is_refused_without_activating() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "nopass@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no-password: {body}");
    assert_eq!(body["error"], "password_required");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::PendingVerification,
        "a refused accept never activates the user"
    );
}

#[tokio::test]
async fn a_forged_token_is_the_uniform_not_found() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let (_user_id, _real) = create_invitation(
        &harness,
        scope,
        "real@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    for forged in ["ira_inv_deadbeef~not-a-real-secret", "", "garbage"] {
        let (status, body) = accept(
            &harness,
            &accept_path(scope),
            &serde_json::json!({ "token": forged, "password": "x" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "forged {forged:?}: {body}");
        assert_eq!(body["error"], "invalid_invitation");
    }
}

#[tokio::test]
async fn an_expired_token_is_the_uniform_not_found() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "stale@example.test",
        InvitationCredentialType::Password,
        100_000_000,
    )
    .await;

    // Advance the harness clock past the expiry.
    harness.clock().advance(Duration::from_secs(200));

    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expired: {body}");
    assert_eq!(body["error"], "invalid_invitation");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::PendingVerification
    );
}

#[tokio::test]
async fn a_revoked_token_is_the_uniform_not_found() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "revoked@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // Revoke through the control plane (as the admin API does).
    let env = harness.env();
    let db = harness.db();
    let id = db
        .control_store()
        .scoped(scope)
        .invitations()
        .resolve_pending(&token, now_micros(&harness))
        .await
        .expect("resolve")
        .expect("pending")
        .id;
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .invitations()
        .revoke(env, &id, None)
        .await
        .expect("revoke");

    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "revoked: {body}");
    assert_eq!(body["error"], "invalid_invitation");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::PendingVerification
    );
}

#[tokio::test]
async fn a_token_cannot_be_accepted_at_another_tenants_path() {
    let harness = Harness::start().await;
    let scope_a = harness.scope();
    let scope_b = harness.second_scope().await;
    let (user_a, token_a) = create_invitation(
        &harness,
        scope_a,
        "tenant-a@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // Present A's token at B's accept path: the uniform not-found, and A's user is
    // untouched.
    let (status, body) = accept(
        &harness,
        &accept_path(scope_b),
        &serde_json::json!({ "token": token_a, "password": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-tenant accept: {body}");
    assert_eq!(body["error"], "invalid_invitation");
    assert_eq!(
        user_state(&harness, scope_a, &user_a).await,
        UserState::PendingVerification,
        "A's user is untouched by the cross-tenant accept attempt"
    );

    // A's token still works at A's own path (isolation is directional).
    let (ok_status, ok_body) = accept(
        &harness,
        &accept_path(scope_a),
        &serde_json::json!({ "token": token_a, "password": "x" }),
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "own-path accept: {ok_body}");
}
