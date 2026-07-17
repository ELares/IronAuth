// SPDX-License-Identifier: MIT OR Apache-2.0

//! The account-recovery subsystem (issue #81), against a real Postgres with an injected
//! clock.
//!
//! These pin the acceptance-critical recovery behaviors:
//!
//! - THE DOWNGRADE INVARIANT (the crux): an attacker-initiated recovery via email OTP
//!   against a passkey-protected account can NEVER yield passkey removal without either a
//!   fresh equal-or-stronger re-verification OR the configured delay window elapsing
//!   (with notifications), enforced by the issue #66 factor-strength ordering;
//! - initiating recovery notifies EVERY registered channel (all verified emails and
//!   phone numbers);
//! - a held recovery is cancellable from its notification-link token, and cancellation
//!   REVOKES the pending recovery;
//! - the per-account cooldown rate-limits repeated initiations;
//! - every recovery step appears in the audit log with enough context to reconstruct the
//!   flow;
//! - the risk seam can block a recovery (the #79 integration point).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, base32_decode, code_at};
use ironauth_oidc::recovery::{
    RecoveryInitiation, cancel_from_token, decoy_recovery_work, evaluate_factor_change,
    initiate_recovery,
};
use ironauth_oidc::{
    FactorChangeDecision, RecoveryFactor, RiskDirective, RiskEvaluator, RiskEvent,
    VerificationPurpose, VerificationSender,
};
use ironauth_store::{
    IdentifierType, NewUserIdentifier, RecoveryEntryPoint, RecoveryState, UniquenessMode, UserId,
};
use serde_json::{Value, json};
use sqlx::Row;

/// A recording verification sender: captures every channel a recovery notification was
/// dispatched to, so a test can assert EVERY registered channel was alerted.
#[derive(Debug, Default)]
struct RecordingSender {
    notified: Mutex<Vec<String>>,
}

impl RecordingSender {
    fn recipients(&self) -> Vec<String> {
        let mut out = self.notified.lock().expect("lock").clone();
        out.sort();
        out
    }
}

impl VerificationSender for RecordingSender {
    fn send(&self, _scope: ironauth_store::Scope, purpose: VerificationPurpose, recipient: &str) {
        if purpose == VerificationPurpose::Recovery {
            self.notified
                .lock()
                .expect("lock")
                .push(recipient.to_owned());
        }
    }
}

/// A risk evaluator that returns a fixed directive, to drive the #79 seam.
#[derive(Debug)]
struct FixedRisk(RiskDirective);

impl RiskEvaluator for FixedRisk {
    fn evaluate_recovery(&self, _event: &RiskEvent<'_>) -> RiskDirective {
        self.0
    }
}

/// Parse a seeded subject string into a `UserId` under the harness scope.
fn subject_id(harness: &Harness, subject: &str) -> UserId {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .parse_id(subject)
        .expect("parse subject")
}

/// Add a verified flexible identifier (issue #54) to a user, so the recovery
/// notification fan-out has a registered channel to alert.
async fn add_verified_identifier(
    harness: &Harness,
    subject: &UserId,
    kind: IdentifierType,
    raw: &str,
) {
    let actor = harness.db().test_actor(harness.env());
    let corr = ironauth_store::CorrelationId::generate(harness.env());
    harness
        .store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .user_identifiers()
        .add(
            harness.env(),
            NewUserIdentifier {
                user_id: subject,
                identifier_type: kind,
                raw,
                verified: true,
                mode: UniquenessMode::EnvironmentWide,
                org: None,
            },
        )
        .await
        .expect("add verified identifier");
}

/// The recovery.* audit actions recorded for the harness scope, via the owner pool
/// (bypassing RLS to see every row).
async fn recovery_audit(harness: &Harness) -> Vec<(String, String)> {
    let scope = harness.scope();
    sqlx::query(
        "SELECT action, target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action LIKE 'recovery.%' \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read audit")
    .into_iter()
    .map(|row| {
        (
            row.get::<String, _>("action"),
            row.get::<String, _>("target_id"),
        )
    })
    .collect()
}

// ===========================================================================
// THE DOWNGRADE INVARIANT (the acceptance-critical crux).
// ===========================================================================

#[tokio::test]
async fn email_recovery_against_a_passkey_account_cannot_remove_the_passkey_without_delay_or_reverify()
 {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject = harness
        .seed_user("ada@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);
    // The account is protected by a (synced) passkey: the strongest factor.
    harness.seed_passkey(&subject.to_string(), true).await;

    // An attacker files a recovery via the WEAKER email-OTP channel.
    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "ada@example.test",
        Some("203.0.113.7"),
    )
    .await;
    let flow_id = match outcome {
        RecoveryInitiation::Created { flow_id, held, .. } => {
            // Recovery via email against a passkey account REDUCES security, so it is HELD.
            assert!(
                held,
                "an email recovery against a passkey account must be held"
            );
            flow_id
        }
        RecoveryInitiation::Suppressed => panic!("recovery should have been created"),
    };

    // Recovery restored access, but the passkey is INTACT and its removal is BLOCKED:
    // no fresh reverify, and the delay window has not elapsed.
    let blocked = evaluate_factor_change(
        harness.state(),
        harness.scope(),
        &flow_id,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(
        blocked,
        FactorChangeDecision::Blocked,
        "email-OTP recovery must NOT remove a passkey without delay or reverify"
    );

    // A FRESH equal-or-stronger re-verification (a passkey ceremony) unblocks it.
    let reverified = evaluate_factor_change(
        harness.state(),
        harness.scope(),
        &flow_id,
        RecoveryFactor::Passkey,
        Some(RecoveryFactor::Passkey.strength_acr()),
    )
    .await;
    assert_eq!(reverified, FactorChangeDecision::AllowedByReverify);

    // OR, without any reverify, once the configured delay window has elapsed (clock
    // advanced past the hold horizon): allowed, with notifications.
    harness.clock().advance(Duration::from_secs(
        harness.state().recovery_settings().delay_secs + 1,
    ));
    let after_delay = evaluate_factor_change(
        harness.state(),
        harness.scope(),
        &flow_id,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(after_delay, FactorChangeDecision::AllowedByDelay);
}

#[tokio::test]
async fn email_recovery_can_remove_an_equal_or_weaker_factor_outright() {
    // The other side of the invariant: recovery via email OTP (pwd) can immediately
    // remove a password (pwd) or another primary factor, because that is NOT a downgrade.
    let harness = Harness::start_store_backed().await;
    let subject = harness
        .seed_user("bob@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);
    // No stronger factor enrolled, so the recovery is NOT held.
    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "bob@example.test",
        None,
    )
    .await;
    let RecoveryInitiation::Created { flow_id, held, .. } = outcome else {
        panic!("recovery should have been created");
    };
    assert!(
        !held,
        "a recovery with no stronger factor to protect is not held"
    );
    let decision = evaluate_factor_change(
        harness.state(),
        harness.scope(),
        &flow_id,
        RecoveryFactor::Password,
        None,
    )
    .await;
    assert_eq!(decision, FactorChangeDecision::NotADowngrade);
}

// ===========================================================================
// Notification everywhere.
// ===========================================================================

#[tokio::test]
async fn initiating_recovery_notifies_every_verified_channel() {
    let mut harness = Harness::start_store_backed().await;
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    let subject = harness
        .seed_user("carol@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);
    // Three registered, verified channels: two emails and a phone.
    add_verified_identifier(
        &harness,
        &subject,
        IdentifierType::Email,
        "carol@example.test",
    )
    .await;
    add_verified_identifier(
        &harness,
        &subject,
        IdentifierType::Email,
        "carol.alt@example.test",
    )
    .await;
    add_verified_identifier(&harness, &subject, IdentifierType::Phone, "+14155550100").await;

    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostAllFactors,
        RecoveryFactor::EmailOtp,
        "carol@example.test",
        None,
    )
    .await;
    let RecoveryInitiation::Created {
        channels_notified, ..
    } = outcome
    else {
        panic!("recovery should have been created");
    };
    assert_eq!(channels_notified, 3, "every verified channel is notified");
    assert_eq!(
        sender.recipients(),
        vec![
            "+14155550100".to_owned(),
            "carol.alt@example.test".to_owned(),
            "carol@example.test".to_owned(),
        ],
        "the send seam alerted every verified email and phone"
    );
}

// ===========================================================================
// Delay window: cancellation revokes the pending recovery.
// ===========================================================================

#[tokio::test]
async fn a_held_recovery_is_cancellable_from_its_notification_token_and_cancellation_revokes_it() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject = harness
        .seed_user("dave@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);
    harness.seed_passkey(&subject.to_string(), true).await;

    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "dave@example.test",
        None,
    )
    .await;
    let (flow_id, cancel_token) = match outcome {
        RecoveryInitiation::Created {
            flow_id,
            held,
            cancel_token,
            ..
        } => {
            assert!(held);
            (flow_id, cancel_token)
        }
        RecoveryInitiation::Suppressed => panic!("recovery should have been created"),
    };

    // The flow is HELD before cancellation.
    let record = harness
        .store()
        .scoped(harness.scope())
        .recovery_flows()
        .get(&flow_id)
        .await
        .expect("read flow")
        .expect("flow exists");
    assert_eq!(record.state, RecoveryState::Held);

    // Cancel from the notification-link token: the pending recovery is REVOKED.
    let cancelled = cancel_from_token(harness.state(), &cancel_token).await;
    assert!(cancelled, "a held recovery is cancellable from its token");

    let record = harness
        .store()
        .scoped(harness.scope())
        .recovery_flows()
        .get(&flow_id)
        .await
        .expect("read flow")
        .expect("flow exists");
    assert_eq!(
        record.state,
        RecoveryState::Cancelled,
        "cancellation revokes the flow"
    );

    // A cancelled flow can no longer complete, and a downgrade is no longer gated by it
    // (there is no pending recovery to protect against).
    let recompleted = cancel_from_token(harness.state(), &cancel_token).await;
    assert!(!recompleted, "an already-cancelled flow is a no-op");
    let decision = evaluate_factor_change(
        harness.state(),
        harness.scope(),
        &flow_id,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(
        decision,
        FactorChangeDecision::NotADowngrade,
        "a cancelled recovery imposes no downgrade gate"
    );
}

// ===========================================================================
// Cooldown.
// ===========================================================================

#[tokio::test]
async fn cooldown_rate_limits_repeated_recovery_initiations() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject = harness
        .seed_user("erin@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);

    let first = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "erin@example.test",
        None,
    )
    .await;
    assert!(matches!(first, RecoveryInitiation::Created { .. }));

    // A repeat inside the cooldown window is SUPPRESSED (no second flow).
    let second = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "erin@example.test",
        None,
    )
    .await;
    assert!(
        matches!(second, RecoveryInitiation::Suppressed),
        "a repeat inside the cooldown window is suppressed"
    );

    // After the cooldown elapses, a fresh initiation is allowed again.
    harness.clock().advance(Duration::from_secs(
        harness.state().recovery_settings().cooldown_secs + 1,
    ));
    let third = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "erin@example.test",
        None,
    )
    .await;
    assert!(
        matches!(third, RecoveryInitiation::Created { .. }),
        "a fresh initiation past the cooldown is allowed"
    );
}

// ===========================================================================
// Audit completeness.
// ===========================================================================

#[tokio::test]
async fn every_recovery_step_appears_in_the_audit_log() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject = harness
        .seed_user("frank@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);
    harness.seed_passkey(&subject.to_string(), true).await;

    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostSecondFactor,
        RecoveryFactor::EmailOtp,
        "frank@example.test",
        Some("203.0.113.9"),
    )
    .await;
    let (flow_id, cancel_token) = match outcome {
        RecoveryInitiation::Created {
            flow_id,
            cancel_token,
            ..
        } => (flow_id, cancel_token),
        RecoveryInitiation::Suppressed => panic!("recovery should have been created"),
    };

    // A blocked factor-change attempt is recorded, then a cancellation.
    let _ = evaluate_factor_change(
        harness.state(),
        harness.scope(),
        &flow_id,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert!(cancel_from_token(harness.state(), &cancel_token).await);

    let rows = recovery_audit(&harness).await;
    let actions: Vec<&str> = rows.iter().map(|(action, _)| action.as_str()).collect();
    for expected in [
        "recovery.initiate",
        "recovery.factor_change",
        "recovery.cancel",
    ] {
        assert!(
            actions.contains(&expected),
            "the audit log must record {expected}; got {actions:?}"
        );
    }
    // Every recovery audit row targets THIS flow, so the whole flow reconstructs from the
    // log by its `rcv_` id.
    let flow_text = flow_id.to_string();
    for (action, target) in &rows {
        assert_eq!(target, &flow_text, "{action} must target the recovery flow");
    }
}

// ===========================================================================
// Risk seam (the #79 integration point).
// ===========================================================================

#[tokio::test]
async fn a_risk_block_suppresses_recovery() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let state = harness
        .state()
        .clone()
        .with_risk_evaluator(Arc::new(FixedRisk(RiskDirective::Block)));
    let subject = harness
        .seed_user("grace@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);

    let outcome = initiate_recovery(
        &state,
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "grace@example.test",
        None,
    )
    .await;
    assert!(
        matches!(outcome, RecoveryInitiation::Suppressed),
        "a risk BLOCK suppresses the recovery"
    );
}

#[tokio::test]
async fn a_risk_forced_delay_holds_an_otherwise_immediate_recovery() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let state = harness
        .state()
        .clone()
        .with_risk_evaluator(Arc::new(FixedRisk(RiskDirective::ForceDelay)));
    // No stronger factor, so it would normally be immediate; risk forces the delay path.
    let subject = harness
        .seed_user("heidi@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject);

    let outcome = initiate_recovery(
        &state,
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "heidi@example.test",
        None,
    )
    .await;
    let RecoveryInitiation::Created { held, .. } = outcome else {
        panic!("recovery should have been created");
    };
    assert!(
        held,
        "a risk-forced delay holds an otherwise-immediate recovery"
    );
}

// ===========================================================================
// HIGH-1: the downgrade invariant is enforced on the LIVE factor-removal HTTP
// surface (the acceptance-critical crux). These drive the ACTUAL endpoints on
// real Postgres, not `evaluate_factor_change` directly.
// ===========================================================================

/// POST a JSON body to `path` with a session cookie; return the status and parsed body.
async fn post_json(
    harness: &Harness,
    path: &str,
    cookie: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let (status, _headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// The `/t/{tenant}/e/{env}/account` base path for the harness scope.
fn account_base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/account", scope.tenant(), scope.environment())
}

/// The live WebAuthn credential-removal endpoint path.
fn webauthn_remove_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/webauthn/credentials/remove",
        scope.tenant(),
        scope.environment()
    )
}

/// The `pky_` ids of `subject`'s registered passkeys (for the removal endpoint).
async fn passkey_ids(harness: &Harness, subject: &UserId) -> Vec<String> {
    harness
        .store()
        .scoped(harness.scope())
        .webauthn_credentials()
        .list(subject, 10, None)
        .await
        .expect("list passkeys")
        .into_iter()
        .map(|record| record.id)
        .collect()
}

/// The `detail` strings of every `recovery.factor_change` audit row in the harness scope,
/// so a test can prove the transition fired LIVE with the expected decision.
async fn factor_change_details(harness: &Harness) -> Vec<String> {
    let scope = harness.scope();
    sqlx::query(
        "SELECT detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'recovery.factor_change' \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read factor_change audit")
    .into_iter()
    .filter_map(|row| row.get::<Option<String>, _>("detail"))
    .collect()
}

/// Drive a TOTP enrollment to ACTIVE through the live HTTP endpoints and return the
/// (pwd) session cookie it was enrolled from.
async fn enroll_active_totp(harness: &Harness, subject: &str) -> String {
    let base = account_base(harness);
    let cookie = harness.session_cookie(subject).await;
    let (status, begun) = post_json(
        harness,
        &format!("{base}/mfa/totp/enroll"),
        &cookie,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "enroll begin: {begun:?}");
    let credential_id = begun["credential_id"].as_str().expect("credential_id");
    let secret = begun["secret"].as_str().expect("secret");
    let seed = base32_decode(secret).expect("decode secret");
    let now_secs = harness
        .clock()
        .now_utc()
        .duration_since(UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();
    let code = code_at(&seed, TotpParams::authenticator_default(), now_secs);
    let (status, activated) = post_json(
        harness,
        &format!("{base}/mfa/totp/verify-enrollment"),
        &cookie,
        &json!({ "credential_id": credential_id, "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate: {activated:?}");
    assert_eq!(activated["activated"], json!(true));
    cookie
}

#[tokio::test]
async fn live_endpoint_a_held_recovery_blocks_passkey_removal_until_a_fresh_reverify() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject_str = harness
        .seed_user("ada@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject_str);
    harness.seed_passkey(&subject_str, true).await; // a synced passkey (phr).
    let pky = passkey_ids(&harness, &subject).await;
    let pky = pky.first().expect("a seeded passkey").clone();

    // A pending email-OTP recovery against a passkey account is HELD (security-reducing).
    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "ada@example.test",
        None,
    )
    .await;
    assert!(matches!(
        outcome,
        RecoveryInitiation::Created { held: true, .. }
    ));

    let remove = webauthn_remove_path(&harness);
    // (a) The ordinary (pwd) recovered session CANNOT remove the passkey: 409, and the
    // recovery.factor_change transition fires LIVE with a blocked decision.
    let pwd_cookie = harness.session_cookie(&subject_str).await;
    let (status, body) = post_json(
        &harness,
        &remove,
        &pwd_cookie,
        &json!({ "credentialId": pky }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body:?}");
    assert_eq!(body["error"], json!("recovery_downgrade_blocked"));
    let details = factor_change_details(&harness).await;
    assert!(
        details.iter().any(|d| d.contains("decision=blocked")),
        "a blocked recovery.factor_change audit row must be written live: {details:?}"
    );
    // The passkey is intact.
    assert_eq!(
        passkey_ids(&harness, &subject).await.len(),
        1,
        "the passkey must not have been removed while blocked"
    );

    // (c) A FRESH equal-or-stronger passkey re-verification unblocks it immediately.
    let phr_cookie = harness
        .session_cookie_at(&subject_str, "passkey_uv", 0)
        .await;
    let (status, body) = post_json(
        &harness,
        &remove,
        &phr_cookie,
        &json!({ "credentialId": pky }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["removed"], json!(true));
    assert!(
        passkey_ids(&harness, &subject).await.is_empty(),
        "a fresh equal-or-stronger re-verify permits the removal"
    );
}

#[tokio::test]
async fn live_endpoint_a_held_recovery_blocks_passkey_removal_until_the_delay_elapses() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject_str = harness
        .seed_user("bob@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject_str);
    harness.seed_passkey(&subject_str, true).await;
    let pky = passkey_ids(&harness, &subject).await;
    let pky = pky.first().expect("a seeded passkey").clone();

    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "bob@example.test",
        None,
    )
    .await;
    assert!(matches!(
        outcome,
        RecoveryInitiation::Created { held: true, .. }
    ));

    let remove = webauthn_remove_path(&harness);
    let cookie = harness.session_cookie(&subject_str).await;
    // Before the delay elapses: BLOCKED.
    let (status, _) = post_json(&harness, &remove, &cookie, &json!({ "credentialId": pky })).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Advance past the delay horizon: the removal is now permitted (AllowedByDelay).
    harness.clock().advance(Duration::from_secs(
        harness.state().recovery_settings().delay_secs + 1,
    ));
    let (status, body) =
        post_json(&harness, &remove, &cookie, &json!({ "credentialId": pky })).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["removed"], json!(true));
}

#[tokio::test]
async fn live_endpoint_passkey_removal_with_no_pending_recovery_still_works() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject_str = harness
        .seed_user("carol@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject_str);
    harness.seed_passkey(&subject_str, true).await;
    let pky = passkey_ids(&harness, &subject).await;
    let pky = pky.first().expect("a seeded passkey").clone();

    // No recovery is pending, so the removal is not recovery-gated.
    let remove = webauthn_remove_path(&harness);
    let cookie = harness.session_cookie(&subject_str).await;
    let (status, body) =
        post_json(&harness, &remove, &cookie, &json!({ "credentialId": pky })).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["removed"], json!(true));
    // No factor_change audit row was written (no recovery to protect against).
    assert!(
        factor_change_details(&harness).await.is_empty(),
        "an un-gated removal writes no recovery.factor_change row"
    );
}

#[tokio::test]
async fn live_endpoint_a_held_recovery_blocks_totp_removal_until_the_delay_elapses() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject_str = harness
        .seed_user("dave@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject_str);
    // An active TOTP makes `mfa` the account's strongest factor.
    let cookie = enroll_active_totp(&harness, &subject_str).await;

    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostSecondFactor,
        RecoveryFactor::EmailOtp,
        "dave@example.test",
        None,
    )
    .await;
    assert!(
        matches!(outcome, RecoveryInitiation::Created { held: true, .. }),
        "an email-OTP recovery against a TOTP account is held"
    );

    let remove = format!("{}/mfa/totp/remove", account_base(&harness));
    let totp_id = harness
        .store()
        .scoped(harness.scope())
        .totp_credentials()
        .list(&subject)
        .await
        .expect("list totp")
        .first()
        .expect("an active totp")
        .id
        .clone();

    // Before the delay elapses: BLOCKED, with the live factor_change audit row.
    let (status, body) = post_json(
        &harness,
        &remove,
        &cookie,
        &json!({ "credential_id": totp_id }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body:?}");
    assert_eq!(body["error"], json!("recovery_downgrade_blocked"));
    assert!(
        factor_change_details(&harness)
            .await
            .iter()
            .any(|d| d.contains("decision=blocked")),
        "the TOTP removal must write a blocked recovery.factor_change row"
    );

    // Advance past the delay: the removal is now permitted.
    harness.clock().advance(Duration::from_secs(
        harness.state().recovery_settings().delay_secs + 1,
    ));
    let (status, body) = post_json(
        &harness,
        &remove,
        &cookie,
        &json!({ "credential_id": totp_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["removed"], json!(true));
}

#[tokio::test]
async fn live_endpoint_password_removal_still_works_via_fresh_passkey_reauth() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject_str = harness
        .seed_user("erin@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject_str);
    harness.seed_passkey(&subject_str, true).await; // a surviving passkey.

    // A pending recovery is HELD, but removing the PASSWORD is not a downgrade and a fresh
    // passkey re-auth proves an equal-or-stronger factor, so the conversion still succeeds.
    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "erin@example.test",
        None,
    )
    .await;
    assert!(matches!(
        outcome,
        RecoveryInitiation::Created { held: true, .. }
    ));

    let remove_password = format!("{}/password/remove", account_base(&harness));
    let phr_cookie = harness
        .session_cookie_at(&subject_str, "passkey_uv", 0)
        .await;
    let (status, _headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(&remove_password)
                .header(header::COOKIE, phr_cookie)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let body: Value = serde_json::from_str(&response).unwrap_or(Value::Null);
    assert_eq!(body["converted"], json!(true));
}

// ===========================================================================
// MEDIUM-1: recovery initiation is not a TIMING enumeration oracle -- the
// unknown-identifier path does the same risk-scored, store-read work.
// ===========================================================================

/// A risk evaluator that COUNTS how many recovery events it scored, so a test can assert
/// the unknown-identifier decoy runs the SAME risk-scored pipeline as the known path
/// (not a bare tracing log).
#[derive(Debug, Default)]
struct CountingRisk {
    scored: AtomicUsize,
}

impl RiskEvaluator for CountingRisk {
    fn evaluate_recovery(&self, _event: &RiskEvent<'_>) -> RiskDirective {
        self.scored.fetch_add(1, Ordering::SeqCst);
        RiskDirective::Allow
    }
}

#[tokio::test]
async fn the_known_and_unknown_init_paths_do_comparable_work() {
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let counter = Arc::new(CountingRisk::default());
    let state = harness.state().clone().with_risk_evaluator(counter.clone());
    let subject_str = harness
        .seed_user("frank@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject_str);

    // The KNOWN path scores exactly one recovery event through the risk seam.
    let _ = initiate_recovery(
        &state,
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "frank@example.test",
        None,
    )
    .await;
    let after_known = counter.scored.load(Ordering::SeqCst);
    assert_eq!(after_known, 1, "the known path scores one risk event");

    // The UNKNOWN path (the decoy) must run the SAME risk-scored, store-read pipeline: it
    // scores one risk event too, rather than collapsing to a bare tracing log (which would
    // make the response latency an existence oracle).
    decoy_recovery_work(
        &state,
        harness.scope(),
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::EmailOtp,
        "nobody@example.test",
        None,
    )
    .await;
    let after_unknown = counter.scored.load(Ordering::SeqCst);
    assert_eq!(
        after_unknown - after_known,
        1,
        "the unknown-identifier decoy runs the same risk-scored pipeline"
    );
}

// ===========================================================================
// MEDIUM-2: the hold decision fails CLOSED and projects the TRUE strongest rung.
// ===========================================================================

#[tokio::test]
async fn a_device_bound_passkey_holder_is_held_at_its_true_rung() {
    // The account's strongest factor is a DEVICE-BOUND passkey (`phrh`), stronger than a
    // synced passkey (`phr`). A recovery performed at the synced-passkey rung therefore
    // REDUCES security and must be HELD. Before the fix, `account_strength_acr` projected
    // ANY passkey to `phr`, so a `phr` recovery matched and was NOT held (the under-hold
    // bug this pins).
    let mut harness = Harness::start_store_backed().await;
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let subject_str = harness
        .seed_user("grace@example.test", "correct horse battery staple")
        .await;
    let subject = subject_id(&harness, &subject_str);
    harness.seed_passkey(&subject_str, false).await; // device-bound (phrh).

    let outcome = initiate_recovery(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryEntryPoint::LostPassword,
        RecoveryFactor::Passkey, // recover at the synced-passkey rung (phr).
        "grace@example.test",
        None,
    )
    .await;
    let RecoveryInitiation::Created { held, .. } = outcome else {
        panic!("recovery should have been created");
    };
    assert!(
        held,
        "a phr recovery against a device-bound (phrh) passkey holder must be held"
    );
}
