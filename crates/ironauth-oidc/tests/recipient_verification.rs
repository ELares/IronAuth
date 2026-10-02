// SPDX-License-Identifier: MIT OR Apache-2.0

//! The gated recipient ceremony through real HTTP handlers and isolated Postgres.
//! Delivery is an owned in-memory adapter, not an email or a claimed inbox receipt.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{
    Harness, ISSUER_BASE, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form,
    location_param, send_through,
};
use ironauth_oidc::recipient_verification::{
    RecipientDeliveryFailure, RecipientVerificationMessage, RecipientVerificationTransport,
};
use ironauth_store::UserId;
use serde_json::{Value, json};

const EMAIL: &str = "Owner@Example.test";
const NONCE: &str = "owned_invitation_nonce_00000000000000001";

#[derive(Default)]
struct OwnedTransport {
    messages: Mutex<Vec<(String, String)>>,
    outcome: Option<RecipientDeliveryFailure>,
}

#[async_trait::async_trait]
impl RecipientVerificationTransport for OwnedTransport {
    async fn deliver(
        &self,
        message: RecipientVerificationMessage<'_>,
    ) -> Result<(), RecipientDeliveryFailure> {
        self.messages
            .lock()
            .expect("fixture mailbox")
            .push((message.recipient.to_owned(), message.code.to_owned()));
        self.outcome.map_or(Ok(()), Err)
    }
}

fn route(harness: &Harness, operation: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/account/{operation}",
        scope.tenant(),
        scope.environment()
    )
}

fn now(harness: &Harness) -> i64 {
    i64::try_from(
        harness
            .env()
            .clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits")
}

fn enabled_router(harness: &Harness, transport: Arc<OwnedTransport>) -> Router {
    ironauth_oidc::oidc_router(
        harness
            .state()
            .clone()
            .with_recipient_verification_test_transport(transport),
    )
}

async fn post(
    router: &Router,
    path: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    origin: Option<&str>,
    body: &Value,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(token) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    let (status, headers, raw) = send_through(
        router.clone(),
        request.body(Body::from(body.to_string())).expect("request"),
    )
    .await;
    (
        status,
        headers,
        serde_json::from_str(&raw).unwrap_or(Value::Null),
    )
}

async fn start(h: &Harness, router: &Router, cookie: &str) -> Value {
    let (status, headers, body) = post(
        router,
        &route(h, "email-verification/start"),
        Some(cookie),
        None,
        Some(ISSUER_BASE),
        &json!({"email": "owner@example.test"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "start: {body}");
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(body["delivery"], "accepted");
    assert!(body.get("code").is_none());
    assert!(body.get("email").is_none());
    body
}

async fn finish(h: &Harness, router: &Router, transport: &OwnedTransport, cookie: &str) -> String {
    let started = start(h, router, cookie).await;
    let delivered = transport
        .messages
        .lock()
        .expect("fixture")
        .last()
        .cloned()
        .expect("accepted local handoff");
    assert_eq!(delivered.0, EMAIL);
    assert_eq!(delivered.1.len(), 8);
    let (status, headers, body) = post(
        router,
        &route(h, "email-verification/verify"),
        Some(cookie),
        None,
        Some(ISSUER_BASE),
        &json!({"challenge_id": started["challenge_id"], "code": delivered.1}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "verify: {body}");
    assert_eq!(body["verified"], true);
    assert!(
        !headers.contains_key(header::SET_COOKIE),
        "no authentication strength/session upgrade"
    );
    body["verification_revision"]
        .as_str()
        .expect("revision")
        .to_owned()
}

async fn token_for(h: &Harness, subject: &str) -> String {
    token_for_with_proof(h, subject, None).await
}

async fn token_for_with_proof(h: &Harness, subject: &str, dpop: Option<&str>) -> String {
    let client = h.client_id().to_string();
    h.grant_consent(subject, &client).await;
    let cookie = h.session_cookie_at(subject, "pwd", now(h)).await;
    let query = format!(
        "response_type=code&client_id={client}&redirect_uri={}&scope=openid%20email&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = h.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("authorization code");
    let form_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(proof) = dpop {
        builder = builder.header("DPoP", proof);
    }
    let (status, _, raw) = h
        .send(builder.body(Body::from(form_body)).expect("token request"))
        .await;
    assert_eq!(status, StatusCode::OK, "token issuance should succeed");
    serde_json::from_str::<Value>(&raw).expect("token response")["access_token"]
        .as_str()
        .expect("access token")
        .to_owned()
}

async fn recipient_rows(h: &Harness) -> (i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM recipient_verification_challenges), (SELECT count(*) FROM recipient_email_verifications)")
        .fetch_one(h.db().owner_pool()).await.expect("recipient rows")
}

#[tokio::test]
async fn production_default_and_existing_otp_sender_cannot_enable_recipient_verification() {
    let h = Harness::start().await;
    for operation in [
        "email-verification/start",
        "email-verification/verify",
        "recipient-proof",
    ] {
        let (status, headers, body) = post(
            &h.router(),
            &route(&h, operation),
            None,
            None,
            None,
            &json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "recipient_verification_unavailable");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
    assert_eq!(recipient_rows(&h).await, (0, 0));
}

#[tokio::test]
async fn password_signup_can_verify_without_new_session_and_get_fresh_client_subject_nonce_bound_proof()
 {
    let h = Harness::start().await;
    // This intentionally untrustworthy claim bag used to be all UserInfo knew.
    // It must not prove mailbox ownership before the real ceremony.
    let user = h
        .seed_user_with_claims(
            EMAIL,
            SEED_PASSWORD,
            r#"{"email":"owner@example.test","email_verified":true}"#,
        )
        .await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let access = token_for(&h, &user).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    let request = json!({"email": "owner@example.test", "nonce": NONCE});
    let (status, _, _) = post(
        &router,
        &route(&h, "recipient-proof"),
        None,
        Some(&access),
        None,
        &request,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "stored email_verified is not ownership"
    );
    let before: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(s)::text FROM sessions s ORDER BY id")
            .fetch_all(h.db().owner_pool())
            .await
            .expect("sessions before");
    let revision = finish(&h, &router, &transport, &cookie).await;
    let after: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(s)::text FROM sessions s ORDER BY id")
            .fetch_all(h.db().owner_pool())
            .await
            .expect("sessions after");
    // A session lookup may touch last_seen, but the fixed environment clock makes
    // the before and after identical; no session row or authority is added.
    assert_eq!(before, after);
    let (status, headers, proof) = post(
        &router,
        &route(&h, "recipient-proof"),
        None,
        Some(&access),
        None,
        &request,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "proof: {proof}");
    assert_eq!(proof["purpose"], "invitation_recipient");
    assert_eq!(proof["iss"], h.issuer());
    assert_eq!(proof["aud"], h.client_id().to_string());
    assert_eq!(proof["sub"], user);
    assert_eq!(proof["nonce"], NONCE);
    assert_eq!(proof["verification_revision"], revision);
    assert_eq!(proof["recipient_matches"], true);
    assert_eq!(proof["checked_at_unix_micros"], now(&h));
    assert!(proof["expires_at_unix_micros"].as_i64().expect("expiry") <= now(&h) + 30_000_000);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(recipient_rows(&h).await, (1, 1));
}

#[tokio::test]
async fn cookie_origin_freshness_subject_and_json_contract_deny_before_challenge_write() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let wrong = h.seed_user("wrong@example.test", SEED_PASSWORD).await;
    let wrong_cookie = h.session_cookie_at(&wrong, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    let path = route(&h, "email-verification/start");
    for (auth, origin, body, expected) in [
        (
            None,
            Some(ISSUER_BASE),
            json!({"email": EMAIL}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some(cookie.as_str()),
            None,
            json!({"email": EMAIL}),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(cookie.as_str()),
            Some("https://evil.test"),
            json!({"email": EMAIL}),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(wrong_cookie.as_str()),
            Some(ISSUER_BASE),
            json!({"email": EMAIL}),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(cookie.as_str()),
            Some(ISSUER_BASE),
            json!({"email": EMAIL, "subject": wrong}),
            StatusCode::BAD_REQUEST,
        ),
        (
            Some(cookie.as_str()),
            Some(ISSUER_BASE),
            json!({"email": "owner@example.test\r\nBcc:elsewhere@test"}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, _, _) = post(&router, &path, auth, None, origin, &body).await;
        assert_eq!(status, expected);
    }
    h.clock().advance(Duration::from_secs(301));
    let (status, _, body) = post(
        &router,
        &path,
        Some(&cookie),
        None,
        Some(ISSUER_BASE),
        &json!({"email": EMAIL}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "reauthentication_required");
    assert_eq!(recipient_rows(&h).await, (0, 0));
    assert!(transport.messages.lock().expect("fixture").is_empty());
}

#[tokio::test]
async fn one_subject_cannot_consume_another_subjects_challenge_and_replay_never_succeeds() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let wrong = h.seed_user("wrong@example.test", SEED_PASSWORD).await;
    let wrong_cookie = h.session_cookie_at(&wrong, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    let started = start(&h, &router, &cookie).await;
    let code = transport.messages.lock().expect("fixture")[0].1.clone();
    let body = json!({"challenge_id": started["challenge_id"], "code": code});
    let path = route(&h, "email-verification/verify");
    let (status, _, _) = post(
        &router,
        &path,
        Some(&wrong_cookie),
        None,
        Some(ISSUER_BASE),
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(recipient_rows(&h).await, (1, 0));
    let (status, _, _) = post(
        &router,
        &path,
        Some(&cookie),
        None,
        Some(ISSUER_BASE),
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = post(
        &router,
        &path,
        Some(&cookie),
        None,
        Some(ISSUER_BASE),
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(recipient_rows(&h).await, (1, 1));
}

#[tokio::test]
async fn transport_refusal_or_uncertainty_is_truthful_and_never_verifies_ownership() {
    for (outcome, label) in [
        (RecipientDeliveryFailure::Refused, "refused"),
        (RecipientDeliveryFailure::Uncertain, "uncertain"),
    ] {
        let h = Harness::start().await;
        let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
        let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
        let transport = Arc::new(OwnedTransport {
            outcome: Some(outcome),
            ..OwnedTransport::default()
        });
        let router = enabled_router(&h, transport);
        let (status, _, body) = post(
            &router,
            &route(&h, "email-verification/start"),
            Some(&cookie),
            None,
            Some(ISSUER_BASE),
            &json!({"email": EMAIL}),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["delivery"], label);
        assert!(body["challenge_id"].is_string());
        assert!(body.get("code").is_none());
        assert_eq!(recipient_rows(&h).await, (1, 0));
    }
}

#[tokio::test]
async fn proof_requires_current_direct_access_and_expected_recipient_without_cookie_fallback() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    finish(&h, &router, &transport, &cookie).await;
    let access = token_for(&h, &user).await;
    let path = route(&h, "recipient-proof");
    let body = json!({"email": EMAIL, "nonce": NONCE});
    for (token, request, expected) in [
        (None, body.clone(), StatusCode::UNAUTHORIZED),
        (Some("not-a-token"), body.clone(), StatusCode::UNAUTHORIZED),
        (
            Some("ira_at_opaque"),
            body.clone(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some(access.as_str()),
            json!({"email": "other@example.test", "nonce": NONCE}),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(access.as_str()),
            json!({"email": EMAIL, "nonce": "short"}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, _, _) = post(&router, &path, Some(&cookie), token, None, &request).await;
        assert_eq!(status, expected);
    }
    let (status, _, _) = post(
        &router,
        &format!("{path}?access_token=never-accepted"),
        None,
        Some(&access),
        None,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let foreign = h.db().seed_scope(h.env()).await;
    let foreign_path = format!(
        "/t/{}/e/{}/account/recipient-proof",
        foreign.tenant(),
        foreign.environment()
    );
    let (status, _, _) = post(&router, &foreign_path, None, Some(&access), None, &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Current identifier state is consulted on every proof; no cached UserInfo or
    // successful earlier response can substitute for the removed identifier.
    let typed = UserId::parse_in_scope(&user, &h.scope()).expect("subject");
    let identifier = h
        .store()
        .scoped(h.scope())
        .user_identifiers()
        .list_for_user(&typed)
        .await
        .expect("identifiers")[0]
        .id;
    let (actor, correlation) = h.seeding_actor();
    h.db()
        .control_store()
        .scoped(h.scope())
        .acting(actor, correlation)
        .user_identifiers()
        .remove(h.env(), &typed, &identifier)
        .await
        .expect("remove identifier");
    let (status, _, _) = post(&router, &path, None, Some(&access), None, &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    h.revoke_every_session_for(&user).await;
    let (status, _, _) = post(&router, &path, None, Some(&access), None, &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "direct session/grant no longer live"
    );
}

#[tokio::test]
async fn dpop_uses_the_scoped_proof_url_and_rejects_bearer_wrong_url_and_replay() {
    use ironauth_jose::SigningKey;
    use ironauth_jose::dpop_test_util::{sign_proof, sign_proof_with_ath};
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    finish(&h, &router, &transport, &cookie).await;
    let key = SigningKey::ed25519_from_seed(Some("owned-dpop".to_owned()), &[9_u8; 32])
        .expect("fixture key");
    let seconds = u64::try_from(now(&h) / 1_000_000).expect("seconds");
    let issue = sign_proof(
        &key,
        "POST",
        &format!("{ISSUER_BASE}/token"),
        seconds,
        "recipient-issue",
    );
    let access = token_for_with_proof(&h, &user, Some(&issue)).await;
    let path = route(&h, "recipient-proof");
    let body = json!({"email": EMAIL, "nonce": NONCE});
    let (status, _, _) = post(&router, &path, None, Some(&access), None, &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "bound credential cannot become bearer"
    );
    let ath = ironauth_jose::access_token_hash(&access);
    let mut replay = None;
    for (url, jti, expected) in [
        (
            format!("{ISSUER_BASE}/userinfo"),
            "recipient-wrong-url",
            StatusCode::UNAUTHORIZED,
        ),
        (
            format!("{ISSUER_BASE}{path}"),
            "recipient-right-url",
            StatusCode::OK,
        ),
    ] {
        let proof = sign_proof_with_ath(&key, "POST", &url, seconds, jti, &ath);
        let request = Request::builder()
            .method("POST")
            .uri(&path)
            .header(header::AUTHORIZATION, format!("DPoP {access}"))
            .header("DPoP", &proof)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("proof request");
        let (status, _, _) = send_through(router.clone(), request).await;
        assert_eq!(status, expected);
        replay = Some(proof);
    }
    let request = Request::builder()
        .method("POST")
        .uri(&path)
        .header(header::AUTHORIZATION, format!("DPoP {access}"))
        .header("DPoP", replay.expect("accepted proof"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("replayed proof");
    let (status, _, _) = send_through(router, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signed_access_without_direct_session_provenance_cannot_prove_a_recipient() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    finish(&h, &router, &transport, &cookie).await;
    let access = token_for(&h, &user).await;
    // A valid signed token whose store provenance is no longer a direct session
    // models the distinguishing property of exchange/machine grants. No signature
    // tampering shadows this check: ordinary UserInfo still resolves the token.
    sqlx::query("UPDATE grants SET session_ref = NULL WHERE subject = $1")
        .bind(&user)
        .execute(h.db().owner_pool())
        .await
        .expect("isolated provenance fixture");
    let request = Request::builder()
        .uri("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {access}"))
        .body(Body::empty())
        .expect("userinfo request");
    let (status, _, _) = h.send(request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary UserInfo policy remains unchanged"
    );
    let (status, _, _) = post(
        &router,
        &route(&h, "recipient-proof"),
        None,
        Some(&access),
        None,
        &json!({"email": EMAIL, "nonce": NONCE}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_anonymous_routes_refuse_live_and_absent_scopes_without_effects() {
    let h = Harness::start().await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, Arc::clone(&transport));
    let absent = ironauth_store::Scope::new(
        ironauth_store::TenantId::generate(h.env()),
        ironauth_store::EnvironmentId::generate(h.env()),
    );
    let before = recipient_rows(&h).await;
    for (operation, body) in [
        (
            "email-verification/start",
            json!({"email": "owner@example.test"}),
        ),
        (
            "email-verification/verify",
            json!({"challenge_id": ironauth_store::RecipientChallengeId::generate(h.env(), &h.scope()).to_string(), "code": "12345678"}),
        ),
        (
            "recipient-proof",
            json!({"email": "owner@example.test", "nonce": NONCE}),
        ),
    ] {
        let live = post(
            &router,
            &route(&h, operation),
            None,
            None,
            Some(ISSUER_BASE),
            &body,
        )
        .await;
        let ghost = post(
            &router,
            &format!(
                "/t/{}/e/{}/account/{operation}",
                absent.tenant(),
                absent.environment()
            ),
            None,
            None,
            Some(ISSUER_BASE),
            &body,
        )
        .await;
        assert_eq!(live.0, StatusCode::UNAUTHORIZED, "{operation}: {}", live.2);
        assert_eq!(
            live, ghost,
            "{operation} cannot distinguish scope existence"
        );
        assert!(!live.1.contains_key(header::SET_COOKIE));
    }
    assert_eq!(before, recipient_rows(&h).await);
    assert!(
        transport
            .messages
            .lock()
            .expect("fixture mailbox")
            .is_empty()
    );
}

fn hosted_resume(h: &Harness) -> String {
    format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        h.client_id(),
        enc(REDIRECT_URI)
    )
}

async fn hosted_page(
    h: &Harness,
    router: &Router,
    cookie: Option<&str>,
    resume: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut request = Request::builder().uri(format!(
        "{}?return_to={}",
        route(h, "email-verification"),
        enc(resume)
    ));
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send_through(router.clone(), request.body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn hosted_verification_requires_a_recent_account_and_registered_in_scope_continuation() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    let resume = hosted_resume(&h);
    let (status, headers, body) = hosted_page(&h, &router, Some(&cookie), &resume).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("value=\"Owner@Example.test\" readonly"));
    assert!(body.contains("data-verified=\"false\""));
    assert!(body.contains("autocomplete=\"one-time-code\""));
    // Optional render artifact for actual Chrome UI qualification. It contains
    // only this synthetic fixture page, never a cookie, code or token.
    if let Some(path) = std::env::var_os("IRONAUTH_RECIPIENT_PAGE_FIXTURE") {
        let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        std::fs::write(
            path,
            serde_json::to_vec(&json!({"html":body, "csp":csp})).unwrap(),
        )
        .unwrap();
    }
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("script-src 'nonce-"));
    assert!(csp.contains("connect-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(recipient_rows(&h).await, (0, 0));
    assert!(transport.messages.lock().unwrap().is_empty());
    assert_eq!(
        hosted_page(&h, &router, None, &resume).await.0,
        StatusCode::UNAUTHORIZED
    );
    for bad in [
        "https://evil.test/".to_owned(),
        "//evil.test/".to_owned(),
        resume.replace(&enc(REDIRECT_URI), &enc("https://evil.test/callback")),
        format!("{resume}&client_id=duplicate"),
    ] {
        let (status, _, body) = hosted_page(&h, &router, Some(&cookie), &bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(!body.contains("href=\"https://evil.test"));
    }
    h.clock().advance(Duration::from_secs(301));
    assert_eq!(
        hosted_page(&h, &router, Some(&cookie), &resume).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn hosted_reload_observes_current_verified_ownership() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    finish(&h, &router, &transport, &cookie).await;
    let (status, _, body) = hosted_page(&h, &router, Some(&cookie), &hosted_resume(&h)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("data-verified=\"true\""));
    assert_eq!(recipient_rows(&h).await, (1, 1));
}

#[tokio::test]
async fn cancellation_is_subject_bound_repeatable_and_invalidates_the_pending_code() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let other = h.seed_user("other@example.test", SEED_PASSWORD).await;
    let other_cookie = h.session_cookie_at(&other, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    let pending = start(&h, &router, &cookie).await;
    let code = transport.messages.lock().unwrap()[0].1.clone();
    let cancel = route(&h, "email-verification/cancel");
    for origin in [None, Some("https://evil.test")] {
        assert_eq!(
            post(&router, &cancel, Some(&cookie), None, origin, &json!({}))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    // Other accounts can cancel their own state, never the requested subject's.
    assert_eq!(
        post(
            &router,
            &cancel,
            Some(&other_cookie),
            None,
            Some(ISSUER_BASE),
            &json!({"subject":user})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(
            &router,
            &cancel,
            Some(&other_cookie),
            None,
            Some(ISSUER_BASE),
            &json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    let subject = UserId::parse_in_scope(&user, &h.scope()).unwrap();
    let id = ironauth_store::RecipientChallengeId::parse_in_scope(
        pending["challenge_id"].as_str().unwrap(),
        &h.scope(),
    )
    .unwrap();
    assert!(
        h.store()
            .scoped(h.scope())
            .recipient_verification()
            .challenge(h.env(), &subject, &id)
            .await
            .unwrap()
            .is_some()
    );
    for _ in 0..2 {
        let (status, headers, body) = post(
            &router,
            &cancel,
            Some(&cookie),
            None,
            Some(ISSUER_BASE),
            &json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cancelled"], true);
        assert!(!headers.contains_key(header::SET_COOKIE));
    }
    assert!(
        h.store()
            .scoped(h.scope())
            .recipient_verification()
            .challenge(h.env(), &subject, &id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        post(
            &router,
            &route(&h, "email-verification/verify"),
            Some(&cookie),
            None,
            Some(ISSUER_BASE),
            &json!({"challenge_id":id.to_string(),"code":code})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(recipient_rows(&h).await, (1, 0));
}

#[tokio::test]
async fn cancellation_does_not_revoke_a_completed_mailbox_proof() {
    let h = Harness::start().await;
    let user = h.seed_user(EMAIL, SEED_PASSWORD).await;
    let cookie = h.session_cookie_at(&user, "pwd", now(&h)).await;
    let transport = Arc::new(OwnedTransport::default());
    let router = enabled_router(&h, transport.clone());
    finish(&h, &router, &transport, &cookie).await;
    assert_eq!(
        post(
            &router,
            &route(&h, "email-verification/cancel"),
            Some(&cookie),
            None,
            Some(ISSUER_BASE),
            &json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(recipient_rows(&h).await, (1, 1));
    assert!(
        hosted_page(&h, &router, Some(&cookie), &hosted_resume(&h))
            .await
            .2
            .contains("data-verified=\"true\"")
    );
}
