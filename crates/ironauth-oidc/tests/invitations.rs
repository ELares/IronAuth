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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, ScreeningSetup};
use ironauth_config::{QuotaConfig, ScopeQuotaConfig};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_quota::QuotaEnforcer;
use ironauth_screening::{
    BreachRange, BreachRangeProvider, FailurePolicy, PasswordPolicy, ProviderError, Sha1Digest,
    Sha1Prefix, digest_password,
};
use ironauth_store::{
    CorrelationId, InvitationCredentialType, MintedInvitationToken, NewAdminUser, NewInvitation,
    Scope, UserId, UserState, mint_invitation_token,
};
use serde_json::Value;

/// A stub k-anonymity screening provider (never the real HIBP API): it reports a fixed set
/// of passwords as breached, driving the invitation-accept screening wiring faithfully.
struct StubProvider {
    breached: Vec<Sha1Digest>,
}

impl StubProvider {
    fn corpus(passwords: &[&str]) -> Self {
        Self {
            breached: passwords.iter().map(|p| digest_password(p)).collect(),
        }
    }
}

impl BreachRangeProvider for StubProvider {
    fn range(
        &self,
        prefix: Sha1Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<BreachRange, ProviderError>> + Send + '_>> {
        let suffixes = self
            .breached
            .iter()
            .filter(|digest| digest.prefix() == prefix)
            .map(Sha1Digest::suffix)
            .collect();
        Box::pin(async move { Ok(BreachRange::new(suffixes)) })
    }

    fn label(&self) -> &'static str {
        "stub"
    }
}

/// The default 800-63B-4 policy plus an injected screening provider, fail-open.
fn screening(provider: StubProvider) -> ScreeningSetup {
    ScreeningSetup {
        policy: PasswordPolicy::default(),
        failure: FailurePolicy::FailOpen,
        screen_on_login: false,
        provider: Some(Arc::new(provider) as Arc<dyn BreachRangeProvider>),
    }
}

// A >= 15-code-point password used as a "breached" fixture (long enough to clear the length
// floor, so a rejection is attributable to SCREENING, not to policy).
const BREACHED_PW: &str = "Breached-Passphrase-2026";
// A clean >= 15-code-point passphrase absent from the stub corpus.
const CLEAN_PW: &str = "a-fresh-unbreached-passphrase-2026";

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

    // A's token still works at A's own path (isolation is directional). A compliant,
    // non-breached 800-63B-4 password (>= 15 code points), since the accept path now
    // evaluates policy and screens before hashing (issue #63).
    let (ok_status, ok_body) = accept(
        &harness,
        &accept_path(scope_a),
        &serde_json::json!({ "token": token_a, "password": "correct horse battery staple" }),
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "own-path accept: {ok_body}");
}

/// A quota whose `PasswordHashing` environment bucket admits exactly ONE hash
/// (`burst = 1`, no refill) before shedding, so a second admitted hash is
/// over-share. A `burst` of 0 would mean UNLIMITED (the self-hoster posture), so
/// the smallest genuine bound is 1. Other dimensions are unused by the pool.
fn one_hash_quota() -> QuotaConfig {
    let base = ScopeQuotaConfig {
        requests_per_second: 0,
        requests_burst: 0,
        token_issuance_per_second: 0,
        token_issuance_burst: 0,
        hook_seconds_per_second: 0,
        hook_seconds_burst: 0,
        password_hashing_per_second: 0, // no refill: an exact budget.
        password_hashing_burst: 1,
    };
    QuotaConfig {
        // A generous tenant envelope so the ENVIRONMENT bucket is the limiter.
        tenant: ScopeQuotaConfig {
            password_hashing_burst: 1_000_000,
            ..base.clone()
        },
        environment: base,
        usage_thresholds_percent: vec![100],
        idle_bucket_ttl_secs: 0,
    }
}

#[tokio::test]
async fn invitation_accept_hashing_is_admission_controlled() {
    // Issue #62 HIGH-1 regression: the public invitation-accept endpoint must hash
    // THROUGH the admission-controlled pool, not inline on the I/O thread. With a
    // pool that admits exactly ONE hash per tenant before shedding, a first accept
    // succeeds (consuming the admission) and a second is SHED with a retryable 429.
    // If the endpoint reverted to the raw inline hasher, it would charge no
    // admission and BOTH accepts would succeed, failing this test.
    let mut harness = Harness::start().await;
    let scope = harness.scope();

    // Share the harness clock so the single admission does not refill mid-test.
    let quota = Arc::new(QuotaEnforcer::from_config(
        &one_hash_quota(),
        harness.env().clock_arc(),
    ));
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1), // cheap: cost is irrelevant to admission.
        1,
        64,
        Some(quota),
    ));
    harness.install_hashing_pool(pool);

    let (_id_a, token_a) = create_invitation(
        &harness,
        scope,
        "grace@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;
    let (_id_b, token_b) = create_invitation(
        &harness,
        scope,
        "hopper@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // The first accept hashes through the pool, consuming the single admission.
    let (first_status, first_body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token_a, "password": "correct horse battery staple" }),
    )
    .await;
    assert_eq!(
        first_status,
        StatusCode::OK,
        "the first accept is admitted: {first_body}"
    );

    // The second accept's hash is over the tenant's fair share and is SHED with a
    // retryable 429, proving the accept hash routes through admission control.
    let (second_status, second_body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token_b, "password": "correct horse battery staple" }),
    )
    .await;
    assert_eq!(
        second_status,
        StatusCode::TOO_MANY_REQUESTS,
        "the second accept is admission-shed (429), proving it is not an inline hash: {second_body}"
    );
    assert_eq!(second_body["error"], "rate_limited");
}

#[tokio::test]
async fn a_breached_password_invitation_is_refused_without_activating() {
    // Issue #63 MEDIUM-1 regression: the invitation-accept password path is a credential SET
    // path and MUST screen. An invitee who chooses a breached password is REFUSED and the
    // pending user is NOT activated (a breach on a real credential-set path is a bypass of
    // the mandatory-screening covenant).
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        screening(StubProvider::corpus(&[BREACHED_PW])),
    )
    .await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "breach-inv@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": BREACHED_PW }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a breached invitation password is refused: {body}"
    );
    assert_eq!(body["error"], "breached_password");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::PendingVerification,
        "a refused accept never activates the user"
    );

    // The token was NOT consumed by the refused attempt: a CLEAN password now accepts and
    // activates (proving the refusal is pre-hash, not a spent-token failure).
    let (ok_status, ok_body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": CLEAN_PW }),
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "clean retry accepts: {ok_body}");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::Active
    );
}

#[tokio::test]
async fn a_too_short_password_invitation_is_refused_by_the_63b4_floor() {
    // Issue #63 MEDIUM-1 regression: the invitation-accept path enforces the 800-63B-4
    // sole-factor length floor (15 code points) before any hash. A trivially short password
    // (e.g. 1 char) is refused by policy and the user stays pending.
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        screening(StubProvider::corpus(&[])),
    )
    .await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "short-inv@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": "x" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a too-short invitation password is refused: {body}"
    );
    assert_eq!(body["error"], "weak_password");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("at least 15"),
        "the 15 code-point floor message is shown: {body}"
    );
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::PendingVerification,
        "a policy-refused accept never activates the user"
    );
}

#[tokio::test]
async fn a_compliant_non_breached_password_invitation_activates_the_user() {
    // Issue #63 MEDIUM-1 regression: a policy-compliant, non-breached password passes the
    // evaluate-then-screen gate and activates the invited user (the happy path still works
    // once screening/policy are wired into the accept flow).
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        screening(StubProvider::corpus(&[BREACHED_PW])),
    )
    .await;
    let scope = harness.scope();
    let (user_id, token) = create_invitation(
        &harness,
        scope,
        "clean-inv@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    let (status, body) = accept(
        &harness,
        &accept_path(scope),
        &serde_json::json!({ "token": token, "password": CLEAN_PW }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "compliant accept: {body}");
    assert_eq!(body["accepted"], true);
    assert_eq!(body["credential_type"], "password");
    assert_eq!(
        user_state(&harness, scope, &user_id).await,
        UserState::Active
    );
}
