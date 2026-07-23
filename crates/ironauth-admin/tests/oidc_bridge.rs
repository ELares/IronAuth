// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OIDC-session to management-Principal credential bridge (issue #90, PR 2).
//!
//! The admin console signs in through IronAuth's OWN OIDC and receives a
//! short-lived `at+jwt` bound to the management audience; the management API's
//! third resolution arm verifies that bearer and maps its subject to the operator
//! plane via a fail-closed allowlist, with NO backdoor. These tests self-provision
//! a throwaway environment as the admin issuer (a signing key held in the SAME
//! shared issuer registry the OIDC data plane serves its JWKS from, plus a
//! management audience the console token is bound to), mint tokens through the SAME
//! JOSE signing core the OIDC `/token` endpoint uses (`sign_jws_with_policy` with
//! `typ = at+jwt`, standing in for the browser Authorization Code + PKCE exchange),
//! and drive the management router with them.
//!
//! They map the issue's PR2 verification:
//!
//! - **sign-in via own flows**: a listed operator subject reaches the management
//!   plane (200) and gets exactly operator reach, no more.
//! - **no-backdoor**: an audience-mismatched token (cross-RP replay), an
//!   admin-issuer token WITHOUT `ironauth.manage`, an expired token, a token signed
//!   by a foreign key, a wrong `typ`, and a wrong issuer are each rejected (401),
//!   and the bridge is inert (rejects everything) when disarmed.
//! - **authz-cannot-exceed-session**: an unlisted subject authenticates at OIDC but
//!   is rejected by the management API (fail closed).
//! - **sudo via OIDC**: a sudo-gated write with the OIDC human principal is
//!   challenged and then succeeds after `elevate_sudo`, the human actor keying the
//!   elevation.

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ironauth_admin::{AdminOidcBridge, AdminState, management_router};
use ironauth_config::{AdminConfig, Secret, SecretString};
use ironauth_env::Env;
use ironauth_jose::{EmissionOptions, KeySet, SigningKey, SigningPolicy, sign_jws_with_policy};
use ironauth_oidc::{IssuerEntry, IssuerRegistry, JwksCacheWindow, PairwiseSalt};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{EnvironmentId, EnvironmentType, GuardrailSet, Scope, TenantId};
use serde_json::Value;
use tower::ServiceExt;

const OPERATOR_TOKEN: &str = "test-bootstrap-operator-token";
const ISSUER_BASE: &str = "https://admin.ironauth.test";
const MGMT_AUDIENCE: &str = "https://mgmt.ironauth.test/api";
/// A subject on the operator allowlist: it maps to the operator plane.
const LISTED_SUB: &str = "op-alice";
/// A subject NOT on the allowlist: it authenticates at OIDC but is rejected here.
const UNLISTED_SUB: &str = "intruder-mallory";

/// A management router whose third arm is armed with the OIDC bridge, plus the
/// registry and signing material needed to mint tokens for it.
struct BridgeHarness {
    // Held so the database and its pools outlive the router.
    _db: TestDatabase,
    router: Router,
    registry: Arc<IssuerRegistry>,
    admin_scope: Scope,
    env: Env,
    issuer: String,
}

impl BridgeHarness {
    async fn start() -> Self {
        Self::start_inner(false).await
    }

    /// The same harness with admin sudo mode enabled, for the sudo-via-OIDC path.
    async fn start_with_sudo() -> Self {
        Self::start_inner(true).await
    }

    async fn start_inner(sudo: bool) -> Self {
        let db = TestDatabase::start().await;
        let env = Env::system();
        // A throwaway system environment as the admin issuer. Its signing key lives
        // in a PRE-POPULATED registry (the database-free key path), which is exactly
        // the shared registry the management arm reads: the token's `iss` and the
        // verification keys both derive from THIS scope, one source of truth.
        let admin_scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let signing_key =
            SigningKey::generate_ed25519(Some("k1".to_owned()), env.entropy()).expect("gen key");
        let registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(300));
        registry.insert(
            admin_scope,
            IssuerEntry::new(
                KeySet::bootstrap(signing_key, SystemTime::UNIX_EPOCH),
                SigningPolicy::eddsa_default(),
                PairwiseSalt::new(Vec::new()),
                GuardrailSet::for_kind(EnvironmentType::Dev),
            ),
        );
        let registry = Arc::new(registry);
        let issuer = registry.issuer_for(&admin_scope);

        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size: 50,
            sudo_mode_enabled: sudo,
            sudo_mode_window_secs: 600,
            ..AdminConfig::default()
        };
        let bridge = AdminOidcBridge::new(
            Arc::clone(&registry),
            admin_scope,
            MGMT_AUDIENCE,
            vec![LISTED_SUB.to_owned()],
        );
        let state = AdminState::new(db.control_store().clone(), env.clone(), &config)
            .expect("admin state builds")
            .with_admin_oidc_bridge(bridge);
        let router = management_router(state);
        Self {
            _db: db,
            router,
            registry,
            admin_scope,
            env,
            issuer,
        }
    }

    fn now_secs(&self) -> i64 {
        let secs = self
            .env
            .clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs();
        i64::try_from(secs).expect("fits i64")
    }

    /// The claim set of a well-formed console access token: a listed operator, the
    /// admin issuer, the management audience, and the `ironauth.manage` scope.
    fn good_claims(&self) -> Value {
        let now = self.now_secs();
        serde_json::json!({
            "iss": self.issuer,
            "sub": LISTED_SUB,
            "aud": MGMT_AUDIENCE,
            "scope": "openid ironauth.manage",
            "iat": now,
            "exp": now + 3600,
            "jti": "jti-console-1",
            "client_id": "console",
        })
    }

    /// Sign `claims` into an `at+jwt` with the admin issuer's live signing key and
    /// policy (the SAME core the `/token` endpoint mints with). `typ` overrides the
    /// media type so a wrong-`typ` case can be exercised.
    async fn sign_with_typ(&self, claims: &Value, typ: &str) -> String {
        let entry = self
            .registry
            .entry_for(&self.admin_scope, self.env.clock().now_utc())
            .await
            .expect("issuer entry");
        let signer = entry
            .signer(self.env.clock().now_utc())
            .expect("active signer");
        let bytes = serde_json::to_vec(claims).expect("claims serialize");
        sign_jws_with_policy(
            entry.policy(),
            signer,
            &bytes,
            &EmissionOptions::new().with_typ(typ),
        )
        .expect("sign at+jwt")
    }

    async fn sign(&self, claims: &Value) -> String {
        self.sign_with_typ(claims, "at+jwt").await
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, String) {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn get_as(&self, path: &str, token: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    async fn put_as(&self, path: &str, token: &str, body: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    async fn post_as(
        &self,
        path: &str,
        token: &str,
        idempotency_key: &str,
        body: &str,
    ) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("idempotency-key", idempotency_key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// Create a tenant with the BOOTSTRAP operator token (setup), returning
    /// `(tenant_id, environment_id)`. The OIDC operator then acts on it.
    async fn create_tenant(&self, key: &str) -> (String, String) {
        let body = serde_json::json!({ "display_name": "Acme" }).to_string();
        let (status, response) = self
            .post_as("/v1/tenants", OPERATOR_TOKEN, key, &body)
            .await;
        assert_eq!(status, StatusCode::CREATED, "create tenant: {response}");
        let value: Value = serde_json::from_str(&response).expect("json");
        (
            value["tenant"]["id"]
                .as_str()
                .expect("tenant id")
                .to_owned(),
            value["environment"]["id"]
                .as_str()
                .expect("environment id")
                .to_owned(),
        )
    }
}

// --- sign-in via own flows --------------------------------------------------

#[tokio::test]
async fn a_listed_operator_subject_reaches_the_management_plane() {
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let token = harness.sign(&harness.good_claims()).await;

    // The console token authenticates and, mapped to the operator plane, reads the
    // environment exactly as the bootstrap operator would.
    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::OK, "listed operator reads env: {body}");
}

#[tokio::test]
async fn a_listed_subject_gets_exactly_operator_reach_and_no_more() {
    // The OIDC operator has EXACTLY the bootstrap operator's reach: the same read
    // succeeds, and a probe for a resource that does not exist is the SAME uniform
    // not-found for both (never a self-consistent bogus 200), so mapping to the
    // operator plane confers operator reach and nothing beyond it.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let token = harness.sign(&harness.good_claims()).await;

    let real = format!("/v1/tenants/{tenant}/environments/{env}");
    let (oidc_status, _) = harness.get_as(&real, &token).await;
    let (op_status, _) = harness.get_as(&real, OPERATOR_TOKEN).await;
    assert_eq!(oidc_status, StatusCode::OK);
    assert_eq!(op_status, StatusCode::OK, "operator parity on the real env");

    // A well-formed but absent environment id under the same tenant: uniform 404
    // for both principals (the anti-oracle discipline, same as tests/idor.rs).
    let absent = EnvironmentId::generate(&harness.env);
    let probe = format!("/v1/tenants/{tenant}/environments/{absent}");
    let (oidc_probe, _) = harness.get_as(&probe, &token).await;
    let (op_probe, _) = harness.get_as(&probe, OPERATOR_TOKEN).await;
    assert_eq!(oidc_probe, StatusCode::NOT_FOUND);
    assert_eq!(
        op_probe,
        StatusCode::NOT_FOUND,
        "operator parity on a probe"
    );
}

// --- no-backdoor ------------------------------------------------------------

#[tokio::test]
async fn a_token_for_another_audience_is_rejected() {
    // Cross-RP replay: a token minted for any other client or resource, even by the
    // same issuer, has the wrong `aud` and MUST be rejected.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let mut claims = harness.good_claims();
    claims["aud"] = Value::String("https://some-other-rp.test/api".to_owned());
    let token = harness.sign(&claims).await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "aud mismatch: {body}");
}

#[tokio::test]
async fn an_admin_issuer_token_without_the_manage_scope_is_rejected() {
    // An ordinary end-user login token for the SAME issuer, lacking the
    // `ironauth.manage` scope, must NOT reach the management plane.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let mut claims = harness.good_claims();
    claims["scope"] = Value::String("openid profile email".to_owned());
    let token = harness.sign(&claims).await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing scope: {body}");
}

#[tokio::test]
async fn an_expired_token_leaves_no_residual_access() {
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let now = harness.now_secs();
    let mut claims = harness.good_claims();
    // Well past the default 60s skew.
    claims["exp"] = Value::from(now - 3600);
    claims["iat"] = Value::from(now - 7200);
    let token = harness.sign(&claims).await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired: {body}");
}

#[tokio::test]
async fn a_not_yet_valid_token_is_rejected() {
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let now = harness.now_secs();
    let mut claims = harness.good_claims();
    claims["nbf"] = Value::from(now + 3600);
    let token = harness.sign(&claims).await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "not yet valid: {body}");
}

#[tokio::test]
async fn a_token_signed_by_a_foreign_key_is_rejected() {
    // A token whose signature is over a key NOT in the admin issuer's published
    // JWKS fails the signature check: no ambient trust anchor, only the issuer's
    // own keys.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let claims = harness.good_claims();
    let bytes = serde_json::to_vec(&claims).expect("serialize");
    let foreign = SigningKey::generate_ed25519(Some("foreign".to_owned()), harness.env.entropy())
        .expect("foreign key");
    let token = sign_jws_with_policy(
        &SigningPolicy::eddsa_default(),
        &foreign,
        &bytes,
        &EmissionOptions::new().with_typ("at+jwt"),
    )
    .expect("sign with foreign key");

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "foreign signature: {body}"
    );
}

#[tokio::test]
async fn a_wrong_issuer_token_is_rejected() {
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let mut claims = harness.good_claims();
    claims["iss"] = Value::String("https://evil.issuer.test/t/x/e/y".to_owned());
    let token = harness.sign(&claims).await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong issuer: {body}");
}

#[tokio::test]
async fn a_token_with_the_wrong_typ_is_rejected() {
    // A valid-looking JWS for the same issuer/audience/scope but with a non
    // `at+jwt` media type (an id token, a logout token) is not a console access
    // token and is rejected.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let token = harness.sign_with_typ(&harness.good_claims(), "JWT").await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong typ: {body}");
}

#[tokio::test]
async fn an_opaque_non_jws_credential_is_rejected() {
    // A non-JWS bearer never reaches the verify path (the shape gate), and with no
    // matching service credential it is the uniform unauthorized.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let (status, body) = harness
        .get_as(
            &format!("/v1/tenants/{tenant}/environments/{env}"),
            "not-a-jws-opaque-token",
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "opaque token: {body}");
}

// --- authz-cannot-exceed-session --------------------------------------------

#[tokio::test]
async fn an_unlisted_subject_authenticates_at_oidc_but_is_rejected_by_management() {
    // The token is otherwise perfectly valid (correct issuer, audience, scope,
    // signature, and `typ`): ONLY the subject is not on the operator allowlist. It
    // must be rejected (fail closed), so an OIDC login that is not an operator can
    // never reach the management plane.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let mut claims = harness.good_claims();
    claims["sub"] = Value::String(UNLISTED_SUB.to_owned());
    let token = harness.sign(&claims).await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unlisted subject: {body}");
}

#[tokio::test]
async fn a_whitespace_padded_subject_does_not_alias_a_listed_operator() {
    // The verified subject is matched BYTE EXACT: a token whose `sub` is a listed
    // operator surrounded by whitespace is a DIFFERENT subject and must be rejected,
    // so no padding variant can alias a real operator.
    let harness = BridgeHarness::start().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let mut claims = harness.good_claims();
    claims["sub"] = Value::String(format!("  {LISTED_SUB}\t\n"));
    let token = harness.sign(&claims).await;

    let (status, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), &token)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a padded subject must not alias a listed operator: {body}"
    );
}

#[tokio::test]
async fn the_bridge_rejects_everything_when_disarmed() {
    // With no bridge installed (an operator who never armed [admin_spa]), a
    // perfectly valid-looking console token is rejected: no `at+jwt` is accepted at
    // all. This proves the surface is inert by default (fail closed).
    let db = TestDatabase::start().await;
    let env = Env::system();
    let admin_scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let signing_key =
        SigningKey::generate_ed25519(Some("k1".to_owned()), env.entropy()).expect("gen key");
    let registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(300));
    registry.insert(
        admin_scope,
        IssuerEntry::new(
            KeySet::bootstrap(signing_key, SystemTime::UNIX_EPOCH),
            SigningPolicy::eddsa_default(),
            PairwiseSalt::new(Vec::new()),
            GuardrailSet::for_kind(EnvironmentType::Dev),
        ),
    );
    let registry = Arc::new(registry);
    let issuer = registry.issuer_for(&admin_scope);
    let config = AdminConfig {
        bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
        ..AdminConfig::default()
    };
    // NOTE: no `.with_admin_oidc_bridge(...)`.
    let state =
        AdminState::new(db.control_store().clone(), env.clone(), &config).expect("state builds");
    let router = management_router(state);

    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs(),
    )
    .expect("fits");
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": LISTED_SUB,
        "aud": MGMT_AUDIENCE,
        "scope": "openid ironauth.manage",
        "iat": now,
        "exp": now + 3600,
    });
    let entry = registry
        .entry_for(&admin_scope, env.clock().now_utc())
        .await
        .expect("entry");
    let signer = entry.signer(env.clock().now_utc()).expect("signer");
    let token = sign_jws_with_policy(
        entry.policy(),
        signer,
        &serde_json::to_vec(&claims).expect("ser"),
        &EmissionOptions::new().with_typ("at+jwt"),
    )
    .expect("sign");

    let request = Request::builder()
        .method("GET")
        .uri("/v1/tenants")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request builds");
    let response = router.oneshot(request).await.expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a disarmed bridge accepts no at+jwt"
    );
}

// --- sudo via OIDC ----------------------------------------------------------

#[tokio::test]
async fn a_sudo_gated_write_is_challenged_then_succeeds_after_elevation() {
    // The OIDC human principal participates in sudo unchanged: a sudo-gated write
    // is challenged (RFC 9470) without a fresh elevation, and succeeds after
    // POST .../admin/sudo/elevate records one keyed on the human actor.
    let harness = BridgeHarness::start_with_sudo().await;
    let (tenant, env) = harness.create_tenant("k1").await;
    let token = harness.sign(&harness.good_claims()).await;

    let locale_path = format!("/v1/tenants/{tenant}/environments/{env}/locales/fr");
    let body = format!(
        "{{\"entries\":{{\"{}\":\"Se connecter\"}}}}",
        ironauth_oidc::flow::message::LOGIN_TITLE.0
    );

    // Without an elevation, the write is the RFC 9470 challenge.
    let (status, challenge) = harness.put_as(&locale_path, &token, &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "stale OIDC write challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge carries the RFC 9470 error: {challenge}"
    );

    // Elevate with the SAME OIDC bearer: the elevation is keyed on the human actor.
    let elevate_path = format!("/v1/tenants/{tenant}/environments/{env}/admin/sudo/elevate");
    let (status, elevated) = harness.post_as(&elevate_path, &token, "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "OIDC operator elevates: {elevated}");

    // The same write now succeeds.
    let (status, stored) = harness.put_as(&locale_path, &token, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated OIDC write succeeds: {stored}"
    );
    assert!(stored.contains("Se connecter"), "persisted: {stored}");
}
