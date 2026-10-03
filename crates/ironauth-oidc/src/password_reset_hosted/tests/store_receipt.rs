// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP receipt recovery from real-store fixtures; this does not simulate a
//! successful initial hosted reset or actual mail delivery.

use super::*;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientId, NewPasswordReset, NewRecipientChallenge, NewRecoveryFlow, PasswordResetAccount,
    PasswordResetChallengeId, PasswordResetDelivery, RecipientAttempt, RecipientChallengeId,
    RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod,
};
use std::sync::Arc;
use tower::ServiceExt;

const EMAIL: &str = "receipt@example.test";
const CODE: &str = "12345678";
const CHOSEN: &str = "A distinct recovery password 1493";

async fn post(state: OidcState, binding: &ResetBrowserBinding) -> (StatusCode, String, bool) {
    let csrf = binding.csrf_token();
    let body = serde_urlencoded::to_string([
        ("csrf", csrf.as_str()),
        ("code", CODE),
        ("new_password", CHOSEN),
        ("confirm_password", CHOSEN),
    ])
    .unwrap();
    let cookie = binding.cookie();
    let cookie = cookie.to_str().unwrap().split(';').next().unwrap();
    let response = routes()
        .with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/recover/reset")
                .header(header::ORIGIN, "https://auth.example.test")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let session_cookie = response.headers().contains_key(header::SET_COOKIE);
    let text = String::from_utf8(
        to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, text, session_cookie)
}

fn outage_state(db: &TestDatabase, env: &Env) -> OidcState {
    let registry = crate::issuer::IssuerRegistry::new(
        "https://auth.example.test",
        crate::issuer::JwksCacheWindow::clamped(60),
    );
    let smtp = crate::password_reset_smtp::PasswordResetSmtpTransport::new(
        crate::recipient_smtp::RecipientSmtpConfig {
            host: "localhost".into(),
            port: 465,
            tls: crate::recipient_smtp::RecipientSmtpTls::Implicit,
            sender: "sender@example.test".into(),
            message_id_domain: "auth.example.test".into(),
            credentials: None,
            max_in_flight: 1,
        },
        "https://auth.example.test",
        env.clone(),
    )
    .unwrap();
    OidcState::new(
        db.store().clone(),
        env.clone(),
        Arc::new(registry),
        &ironauth_config::OidcConfig::default(),
        "https://auth.example.test",
    )
    .with_password_reset_smtp(smtp)
    .with_password_policy(
        ironauth_screening::PasswordPolicy::default(),
        ironauth_screening::FailurePolicy::FailClosed,
        false,
    )
}

async fn verified_subject(
    db: &TestDatabase,
    env: &Env,
    scope: ironauth_store::Scope,
    code_hash: &str,
) -> ironauth_store::UserId {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let subject = acting
        .users()
        .register(env, EMAIL, code_hash, None)
        .await
        .unwrap();
    let expiry = crate::util::epoch_micros(env.clock().now_utc()) + 300_000_000;
    let verification = RecipientChallengeId::generate(env, &scope);
    acting
        .recipient_verification()
        .start(
            env,
            NewRecipientChallenge {
                id: &verification,
                subject: &subject,
                email: EMAIL,
                code_hash,
                expires_at_unix_micros: expiry,
            },
        )
        .await
        .unwrap();
    let proof = db
        .store()
        .scoped(scope)
        .recipient_verification()
        .challenge(env, &subject, &verification)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        acting
            .recipient_verification()
            .attempt(env, &subject, &proof, true)
            .await
            .unwrap(),
        RecipientAttempt::Verified
    );
    subject
}

async fn pending_reset(
    db: &TestDatabase,
    env: &Env,
    scope: ironauth_store::Scope,
    subject: &ironauth_store::UserId,
    code_hash: &str,
) -> ResetBrowserBinding {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let expiry = crate::util::epoch_micros(env.clock().now_utc()) + 300_000_000;
    let recovery = RecoveryFlowId::generate(env, &scope);
    acting
        .recovery_flows()
        .initiate(
            env,
            NewRecoveryFlow {
                id: &recovery,
                subject,
                entry_point: RecoveryEntryPoint::LostPassword,
                recover_acr: "urn:ironauth:acr:pwd",
                cancel_token_digest: &[7; 32],
                recipient: EMAIL,
                hold_until_unix_micros: None,
                method: RecoveryMethod::Standard,
            },
            0,
        )
        .await
        .unwrap();
    let id = PasswordResetChallengeId::generate(env, &scope);
    let binding = ResetBrowserBinding::generate(env, id);
    let client = ClientId::generate(env, &scope);
    let return_to = format!("/authorize?client_id={client}");
    acting
        .password_reset()
        .start(
            env,
            NewPasswordReset {
                id: &id,
                client: &client,
                browser_binding_hash: &binding.binding_hash(),
                authorization_return_to: &return_to,
                account: Some(PasswordResetAccount {
                    subject,
                    recovery: &recovery,
                }),
                cancellation_token_digest: Some(&[8; 32]),
                code_hash,
                expires_at_unix_micros: expiry,
            },
        )
        .await
        .unwrap();
    // Store acceptance fixture only; no SMTP request is made in this test.
    acting
        .password_reset()
        .record_delivery(env, &id, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    binding
}

#[tokio::test]
async fn committed_http_receipt_survives_screening_outage_and_stricter_policy_without_new_mutation()
{
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let state = outage_state(&db, &env);
    assert!(matches!(
        state.screen_password(&scope, CHOSEN).await,
        crate::state::ScreenDecision::RefusedUnavailable
    ));
    let code_hash = state.hash_password(&scope, CODE).await.unwrap();
    let chosen_hash = state.hash_password(&scope, CHOSEN).await.unwrap();
    let subject = verified_subject(&db, &env, scope, &code_hash).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let binding = pending_reset(&db, &env, scope, &subject, &code_hash).await;
    let id = *binding.challenge();
    let challenge = db
        .store()
        .scoped(scope)
        .password_reset()
        .challenge(&env, &id, &binding.binding_hash())
        .await
        .unwrap()
        .unwrap();
    let (status, _, cookie) = post(state.clone(), &binding).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "pending reset still requires screening"
    );
    assert!(!cookie);
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(code_hash.as_str())
    );
    // Seed the committed result to model a successful earlier transaction whose
    // HTTP response was lost before the screening provider became unavailable.
    assert!(matches!(
        acting
            .password_reset()
            .complete(
                &env,
                CompletePasswordReset {
                    challenge: &challenge,
                    browser_binding_hash: &binding.binding_hash(),
                    code_matched: true,
                    new_password_hash: &chosen_hash,
                    request_hash: &binding.completion_request_hash(CODE, CHOSEN)
                }
            )
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    let before = db.store().scoped(scope).audit().list().await.unwrap().len();
    let strict = state.clone().with_password_policy(
        ironauth_screening::PasswordPolicy::new(64, 8, 128, false, false, false, false, 0, true, 0),
        ironauth_screening::FailurePolicy::FailClosed,
        false,
    );
    for current in [state, strict] {
        let (status, body, cookie) = post(current, &binding).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Your password has been reset"));
        assert!(!body.contains(CHOSEN) && !body.contains(CODE));
        assert!(!cookie);
    }
    assert_eq!(
        db.store().scoped(scope).audit().list().await.unwrap().len(),
        before
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(chosen_hash.as_str())
    );
}
