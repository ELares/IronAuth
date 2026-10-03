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
        .route(
            "/recover/cancel",
            axum::routing::get(crate::recover::recover_cancel_get)
                .post(crate::recover::recover_cancel_post),
        )
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
    deliver_completion_from_queue(
        &state,
        &db,
        scope,
        &browser,
        Reply::Accepted,
        ironauth_store::PasswordResetDelivery::Accepted,
    )
    .await;
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

async fn deliver_completion_from_queue(
    state: &OidcState,
    db: &TestDatabase,
    scope: Scope,
    browser: &str,
    reply: Reply,
    expected: ironauth_store::PasswordResetDelivery,
) {
    use crate::password_reset_delivery::PasswordResetCompletionConsumer;
    use ironauth_store::outbox::{OutboxWorker, WorkerSettings};
    let (smtp, mail) = fixture(reply, true).await;
    let delivery_state = state
        .clone()
        .with_password_reset_smtp(PasswordResetSmtpTransport {
            smtp,
            issuer: Url::parse("https://auth.example.test").unwrap(),
            env: state.env().clone(),
        });
    let worker = OutboxWorker::new(
        db.store().clone(),
        state.env().clone(),
        Arc::new(PasswordResetCompletionConsumer::new(delivery_state)),
        WorkerSettings::default(),
    );
    let drained = worker.run_once(scope).await.unwrap();
    assert_eq!(drained.claimed, 1);
    assert_eq!(
        drained.completed,
        u64::from(expected == ironauth_store::PasswordResetDelivery::Accepted)
    );
    assert_eq!(
        drained.dead_lettered,
        u64::from(expected != ironauth_store::PasswordResetDelivery::Accepted)
    );
    let raw = tokio::time::timeout(Duration::from_secs(5), mail)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(raw.contains("Your IronAuth password was reset"));
    assert!(!raw.contains(OLD) && !raw.contains(NEW));
    assert!(!raw.contains("reset code is") && !raw.contains("ira_rcv_"));
    assert_eq!(worker.run_once(scope).await.unwrap().claimed, 0);
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, browser.parse().unwrap());
    let binding = ResetBrowserBinding::from_headers(&headers).unwrap();
    let result = db
        .store()
        .scoped(scope)
        .password_reset()
        .completion_notice_status(binding.challenge())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.result, Some(expected));
}

#[tokio::test]
async fn completion_mail_failure_keeps_reset_committed_and_does_not_resend() {
    for (reply, expected) in [
        (
            Reply::Refused,
            ironauth_store::PasswordResetDelivery::Refused,
        ),
        (
            Reply::Disconnect,
            ironauth_store::PasswordResetDelivery::Uncertain,
        ),
    ] {
        let db = TestDatabase::start().await;
        let env = env();
        let scope = db.seed_scope(&env).await;
        let (smtp, mail) = fixture(Reply::Accepted, true).await;
        let state = state(
            &db,
            &env,
            scope,
            Some(PasswordResetSmtpTransport {
                smtp,
                issuer: Url::parse("https://auth.example.test").unwrap(),
                env: env.clone(),
            }),
        );
        let (subject, client) = seed(&db, &state, scope).await;
        let (status, headers, _) = request(&state, &resume(&client), OWNER, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let browser = cookie(&headers);
        let raw = tokio::time::timeout(Duration::from_secs(5), mail)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        complete_from_mail(&state, &db, &subject, &browser, &raw).await;
        deliver_completion_from_queue(&state, &db, scope, &browser, reply, expected).await;
        // Exact receipt replay stays successful after refused or uncertain notice delivery.
        complete_from_mail(&state, &db, &subject, &browser, &raw).await;
    }
}

#[tokio::test]
async fn restarted_completion_worker_classifies_stale_claim_without_sending_again() {
    use crate::password_reset_delivery::PasswordResetCompletionConsumer;
    use ironauth_store::outbox::{OutboxWorker, WorkerSettings};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        1499,
    );
    let scope = db.seed_scope(&env).await;
    let (smtp, mail) = fixture(Reply::Accepted, true).await;
    let state = state(
        &db,
        &env,
        scope,
        Some(PasswordResetSmtpTransport {
            smtp,
            issuer: Url::parse("https://auth.example.test").unwrap(),
            env: env.clone(),
        }),
    );
    let (subject, client) = seed(&db, &state, scope).await;
    let (_, headers, _) = request(&state, &resume(&client), OWNER, None).await;
    let browser = cookie(&headers);
    let raw = tokio::time::timeout(Duration::from_secs(5), mail)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    complete_from_mail(&state, &db, &subject, &browser, &raw).await;
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, browser.parse().unwrap());
    let binding = ResetBrowserBinding::from_headers(&headers).unwrap();
    // Persist the claim that would survive a crash before recording SMTP outcome.
    assert!(
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .password_reset()
            .claim_completion_notice(&env, binding.challenge())
            .await
            .unwrap()
            .is_some()
    );
    let (smtp, unexpected_mail) = fixture(Reply::Accepted, true).await;
    let state = state.with_password_reset_smtp(PasswordResetSmtpTransport {
        smtp,
        issuer: Url::parse("https://auth.example.test").unwrap(),
        env: env.clone(),
    });
    let worker = || {
        OutboxWorker::new(
            db.store().clone(),
            env.clone(),
            Arc::new(PasswordResetCompletionConsumer::new(state.clone())),
            WorkerSettings::default(),
        )
    };
    let first = worker().run_once(scope).await.unwrap();
    assert_eq!(first.retried, 1);
    assert_eq!(first.completed, 0);
    // The retry schedule includes up to thirty seconds of jitter.
    clock.advance(Duration::from_secs(61));
    let restarted = worker();
    let second = restarted.run_once(scope).await.unwrap();
    assert_eq!(second.dead_lettered, 1);
    assert_eq!(second.completed, 0);
    assert_eq!(restarted.run_once(scope).await.unwrap().claimed, 0);
    assert!(!unexpected_mail.is_finished());
    unexpected_mail.abort();
    let result = db
        .store()
        .scoped(scope)
        .password_reset()
        .completion_notice_status(binding.challenge())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.result,
        Some(ironauth_store::PasswordResetDelivery::Uncertain)
    );
    complete_from_mail(&state, &db, &subject, &browser, &raw).await;
}

#[tokio::test]
async fn cancellation_link_is_scanner_safe_and_delivers_one_code_free_warning() {
    let db = TestDatabase::start().await;
    let env = env();
    let scope = db.seed_scope(&env).await;
    let (smtp, mail) = fixture(Reply::Accepted, true).await;
    let state = state(
        &db,
        &env,
        scope,
        Some(PasswordResetSmtpTransport {
            smtp,
            issuer: Url::parse("https://auth.example.test").unwrap(),
            env: env.clone(),
        }),
    );
    let (subject, client) = seed(&db, &state, scope).await;
    let (status, _, _) = request(&state, &resume(&client), OWNER, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let raw = tokio::time::timeout(Duration::from_secs(5), mail)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let link = raw
        .split("cancel it: ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let url = Url::parse(link).unwrap();
    let token = url
        .query_pairs()
        .find(|(key, _)| key == "token")
        .unwrap()
        .1
        .into_owned();
    let path = format!("{}?{}", url.path(), url.query().unwrap());
    let (status, _, _) = call(&state, "GET", &path, String::new(), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(crate::recovery::cancel_token_is_live(&state, &token).await);
    let body = serde_urlencoded::to_string([("token", token.as_str())]).unwrap();
    cancel_queue_fault_is_retryable(&state, &db, &body).await;
    assert!(crate::recovery::cancel_token_is_live(&state, &token).await);
    for _ in 0..2 {
        let (status, headers, page) =
            call(&state, "POST", "/recover/cancel", body.clone(), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!headers.contains_key(header::SET_COOKIE));
        assert!(!page.contains("alerted your"));
    }
    assert!(!crate::recovery::cancel_token_is_live(&state, &token).await);
    drain_cancel_notice(&state, &db, scope).await;
    let hash = db
        .store()
        .scoped(scope)
        .users()
        .password_hash_for_subject(&subject)
        .await
        .unwrap()
        .unwrap();
    assert!(state.verify_password(&scope, OLD, &hash).await.unwrap());
    assert!(!state.verify_password(&scope, NEW, &hash).await.unwrap());
}

async fn drain_cancel_notice(state: &OidcState, db: &TestDatabase, scope: Scope) {
    use crate::password_reset_delivery::PasswordResetCompletionConsumer;
    use ironauth_store::outbox::{OutboxWorker, WorkerSettings};
    let (smtp, mail) = fixture(Reply::Accepted, true).await;
    let delivery_state = state
        .clone()
        .with_password_reset_smtp(PasswordResetSmtpTransport {
            smtp,
            issuer: Url::parse("https://auth.example.test").unwrap(),
            env: state.env().clone(),
        });
    let worker = OutboxWorker::new(
        db.store().clone(),
        state.env().clone(),
        Arc::new(PasswordResetCompletionConsumer::new(delivery_state)),
        WorkerSettings::default(),
    );
    let drained = worker.run_once(scope).await.unwrap();
    assert_eq!(drained.completed, 1);
    let raw = tokio::time::timeout(Duration::from_secs(5), mail)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(raw.contains("Your IronAuth password reset was cancelled"));
    assert!(!raw.contains("reset code is") && !raw.contains("ira_rcv_") && !raw.contains(OLD));
    assert_eq!(worker.run_once(scope).await.unwrap().claimed, 0);
}

async fn cancel_queue_fault_is_retryable(state: &OidcState, db: &TestDatabase, body: &str) {
    sqlx::raw_sql("CREATE FUNCTION reject_cancel_mail_queue() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.consumer='password-reset-completion' THEN RAISE EXCEPTION 'fixture queue fault'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_cancel_mail_queue BEFORE INSERT ON outbox_messages FOR EACH ROW EXECUTE FUNCTION reject_cancel_mail_queue();")
        .execute(db.owner_pool()).await.unwrap();
    let (status, _, page) = call(state, "POST", "/recover/cancel", body.to_owned(), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(page.contains("Unable to confirm cancellation"));
    sqlx::raw_sql("DROP TRIGGER reject_cancel_mail_queue ON outbox_messages; DROP FUNCTION reject_cancel_mail_queue();")
        .execute(db.owner_pool()).await.unwrap();
}
