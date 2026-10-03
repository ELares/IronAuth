// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hosted request through real TLS mail and PostgreSQL. Registration/mailbox
//! verification and an empty screening corpus are explicit test fixtures.

use super::*;
use crate::password_reset_browser::ResetBrowserBinding;
use crate::{IssuerEntry, IssuerRegistry, JwksCacheWindow, OidcState, PairwiseSalt};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientId, CorrelationId, NewRecipientChallenge, RecipientAttempt, RecipientChallengeId, UserId,
};
use sqlx::Row;
use std::sync::Arc;
use tower::ServiceExt;

const OWNER: &str = "owner@example.test";
const OLD: &str = "The previous test password 1496";
const NEW: &str = "A different recovery password 1496";

struct EmptyCorpus;
impl ironauth_screening::BreachRangeProvider for EmptyCorpus {
    fn range(
        &self,
        _: ironauth_screening::Sha1Prefix,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        ironauth_screening::BreachRange,
                        ironauth_screening::ProviderError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { Ok(ironauth_screening::BreachRange::default()) })
    }
    fn label(&self) -> &'static str {
        "reset_test_empty_corpus"
    }
}

fn state(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    transport: Option<PasswordResetSmtpTransport>,
) -> OidcState {
    let key = ironauth_jose::SigningKey::generate_ed25519(Some("reset-test".into()), env.entropy())
        .unwrap();
    let registry = IssuerRegistry::new("https://auth.example.test", JwksCacheWindow::clamped(60));
    registry.insert(
        scope,
        IssuerEntry::new(
            ironauth_jose::KeySet::bootstrap(key, env.clock().now_utc()),
            ironauth_jose::SigningPolicy::eddsa_default(),
            PairwiseSalt::new(Vec::new()),
            ironauth_store::GuardrailSet::for_kind(ironauth_store::EnvironmentType::Dev),
        ),
    );
    let state = OidcState::new(
        db.store().clone(),
        env.clone(),
        Arc::new(registry),
        &ironauth_config::OidcConfig::default(),
        "https://auth.example.test",
    )
    .with_breach_provider(Arc::new(EmptyCorpus));
    transport.map_or(state.clone(), |transport| {
        state.with_password_reset_smtp(transport)
    })
}

async fn seed(db: &TestDatabase, state: &OidcState, scope: Scope) -> (UserId, ClientId) {
    let env = state.env();
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let hash = state.hash_password(&scope, OLD).await.unwrap();
    let subject = acting
        .users()
        .register(env, OWNER, &hash, None)
        .await
        .unwrap();
    let proof = RecipientChallengeId::generate(env, &scope);
    acting
        .recipient_verification()
        .start(
            env,
            NewRecipientChallenge {
                id: &proof,
                subject: &subject,
                email: OWNER,
                code_hash: &hash,
                expires_at_unix_micros: crate::util::epoch_micros(state.now()) + 300_000_000,
            },
        )
        .await
        .unwrap();
    let challenge = db
        .store()
        .scoped(scope)
        .recipient_verification()
        .challenge(env, &subject, &proof)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        acting
            .recipient_verification()
            .attempt(env, &subject, &challenge, true)
            .await
            .unwrap(),
        RecipientAttempt::Verified
    );
    acting
        .users()
        .register(env, "unverified@example.test", &hash, None)
        .await
        .unwrap();
    let client = acting
        .clients()
        .create(env, "recovery test application")
        .await
        .unwrap();
    acting
        .clients()
        .register_redirect_uris(env, &client, &["https://client.example.test/cb"])
        .await
        .unwrap();
    (subject, client)
}

fn resume(client: &ClientId) -> String {
    format!(
        "/authorize?client_id={client}&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcb&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    )
}

async fn call(
    state: &OidcState,
    method: &str,
    path: &str,
    body: String,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, "https://auth.example.test")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let response = crate::password_reset_request::routes()
        .with_state(state.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, headers, body)
}

async fn request(
    state: &OidcState,
    target: &str,
    identifier: &str,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    call(
        state,
        "POST",
        "/recover",
        serde_urlencoded::to_string([("return_to", target), ("identifier", identifier)]).unwrap(),
        cookie,
    )
    .await
}

fn cookie(headers: &HeaderMap) -> String {
    let value = headers[header::SET_COOKIE].to_str().unwrap();
    assert!(value.starts_with("__Host-ironauth_reset="));
    assert!(
        value.contains("Secure") && value.contains("HttpOnly") && value.contains("SameSite=Lax")
    );
    value.split(';').next().unwrap().to_owned()
}

async fn uniform_and_repeat(state: &OidcState, target: &str, real_cookie: &str) {
    let (_, _, original) = call(
        state,
        "GET",
        "/recover/reset",
        String::new(),
        Some(real_cookie),
    )
    .await;
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, real_cookie.parse().unwrap());
    let binding = ResetBrowserBinding::from_headers(&headers).unwrap();
    let original = original.replace(&binding.csrf_token(), "[csrf]");
    for identifier in ["unknown@example.test", "unverified@example.test"] {
        let (status, headers, _) = request(state, target, identifier, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(headers[header::LOCATION], "/recover/reset");
        let current = cookie(&headers);
        let mut parsed = HeaderMap::new();
        parsed.insert(header::COOKIE, current.parse().unwrap());
        let binding = ResetBrowserBinding::from_headers(&parsed).unwrap();
        let (status, _, body) = call(
            state,
            "GET",
            "/recover/reset",
            String::new(),
            Some(&current),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.replace(&binding.csrf_token(), "[csrf]"), original);
        let (status, headers, body) = request(state, target, identifier, Some(&current)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(!headers.contains_key(header::SET_COOKIE));
        assert!(body.contains("Enter your current code"));
    }
    let (status, headers, _) = request(state, target, OWNER, Some(real_cookie)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!headers.contains_key(header::SET_COOKIE));
}

async fn complete_from_mail(
    state: &OidcState,
    db: &TestDatabase,
    subject: &UserId,
    browser: &str,
    mail: &str,
) {
    let code = mail
        .split("Your IronAuth password reset code is ")
        .nth(1)
        .unwrap()
        .get(..8)
        .unwrap();
    assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, browser.parse().unwrap());
    let binding = ResetBrowserBinding::from_headers(&headers).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let row =
                sqlx::query("SELECT delivery_state FROM password_reset_challenges WHERE id=$1")
                    .bind(binding.challenge().to_string())
                    .fetch_one(db.owner_pool())
                    .await
                    .unwrap();
            if row.get::<String, _>("delivery_state") == "accepted" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let body = serde_urlencoded::to_string([
        ("csrf", binding.csrf_token()),
        ("code", code.to_owned()),
        ("new_password", NEW.to_owned()),
        ("confirm_password", NEW.to_owned()),
    ])
    .unwrap();
    let (status, headers, page) = call(state, "POST", "/recover/reset", body, Some(browser)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Your password has been reset"));
    assert!(!page.contains(NEW) && !page.contains(code));
    assert!(!headers.contains_key(header::SET_COOKIE));
    let hash = db
        .store()
        .scoped(subject.scope())
        .users()
        .password_hash_for_subject(subject)
        .await
        .unwrap()
        .unwrap();
    assert!(
        state
            .verify_password(&subject.scope(), NEW, &hash)
            .await
            .unwrap()
    );
    assert!(
        !state
            .verify_password(&subject.scope(), OLD, &hash)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn hosted_request_delivers_real_code_and_completes_without_enumerating_ineligible_accounts() {
    let db = TestDatabase::start().await;
    let env = env();
    let scope = db.seed_scope(&env).await;
    let (smtp, mail) = fixture(Reply::Accepted, true).await;
    let transport = PasswordResetSmtpTransport {
        smtp,
        issuer: Url::parse("https://auth.example.test").unwrap(),
        env: env.clone(),
    };
    let state = state(&db, &env, scope, Some(transport));
    let (subject, client) = seed(&db, &state, scope).await;
    let target = resume(&client);
    let query = serde_urlencoded::to_string([("return_to", target.as_str())]).unwrap();
    let (status, headers, _) = call(
        &state,
        "GET",
        &format!("/recover?{query}"),
        String::new(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::SET_COOKIE));
    for bad in [
        target.replace("client.example.test", "evil.example.test"),
        format!("{target}&client_id={client}"),
        target.replace("S256", "plain"),
        format!("{target}#fragment"),
        format!("{target}&resource=https%3A%2F%2Funregistered.example.test"),
    ] {
        let (status, headers, _) = request(&state, &bad, OWNER, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!headers.contains_key(header::SET_COOKIE));
    }
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM password_reset_challenges")
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(before, 0);
    let (status, headers, _) = request(&state, &target, OWNER, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let browser = cookie(&headers);
    uniform_and_repeat(&state, &target, &browser).await;
    let raw = tokio::time::timeout(Duration::from_secs(5), mail)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    complete_from_mail(&state, &db, &subject, &browser, &raw).await;
}

#[tokio::test]
async fn disabled_recovery_and_invalid_origin_never_issue_challenges() {
    let db = TestDatabase::start().await;
    let env = env();
    let scope = db.seed_scope(&env).await;
    let state = state(&db, &env, scope, None);
    let (_, client) = seed(&db, &state, scope).await;
    let target = resume(&client);
    let mut previous = None;
    for identifier in [OWNER, "unknown@example.test"] {
        let (status, headers, body) = request(&state, &target, identifier, None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!headers.contains_key(header::SET_COOKIE));
        assert!(body.contains("Password recovery is unavailable"));
        if let Some(previous) = previous {
            assert_eq!(body, previous);
        }
        previous = Some(body);
    }
    let query = serde_urlencoded::to_string([("return_to", target.as_str())]).unwrap();
    let (status, headers, _) = call(
        &state,
        "GET",
        &format!("/recover?{query}"),
        String::new(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!headers.contains_key(header::SET_COOKIE));
    for (origin, body, expected) in [
        ("https://evil.example.test", query, StatusCode::FORBIDDEN),
        (
            "https://auth.example.test",
            format!("identifier={}", "a".repeat(65536)),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let response = crate::password_reset_request::routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/recover")
                    .header(header::ORIGIN, origin)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM password_reset_challenges")
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}
