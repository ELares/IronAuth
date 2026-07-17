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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Harness;
use ironauth_oidc::recovery::{
    RecoveryInitiation, cancel_from_token, evaluate_factor_change, initiate_recovery,
};
use ironauth_oidc::{
    FactorChangeDecision, RecoveryFactor, RiskDirective, RiskEvaluator, RiskEvent,
    VerificationPurpose, VerificationSender,
};
use ironauth_store::{
    IdentifierType, NewUserIdentifier, RecoveryEntryPoint, RecoveryState, UniquenessMode, UserId,
};
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
