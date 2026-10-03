// SPDX-License-Identifier: MIT OR Apache-2.0

//! Actual TLS relay outcomes through the delivery coordinator into isolated
//! PostgreSQL. Verification/hash setup is a store fixture, not a hosted ceremony.

use super::*;
use crate::issuer::{IssuerRegistry, JwksCacheWindow};
use crate::password_reset_delivery::{ResetRequestDelivery, send_reset_request};
use crate::state::OidcState;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientId, CorrelationId, NewPasswordReset, NewRecipientChallenge, NewRecoveryFlow,
    PasswordResetAccount, PasswordResetDelivery, RecipientAttempt, RecipientChallengeId,
    RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod, StoreError, UserId,
};
use sqlx::Row;
use std::sync::Arc;

const OWNER: &str = "owner@example.test";
// Only store-fixture verifiers. This test neither verifies a reset code nor changes
// a credential; the real TLS send and durable delivery outcome are its boundary.
const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

async fn issued(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
) -> (UserId, PasswordResetChallengeId, String) {
    let store = db.store();
    let scoped = store.scoped(scope);
    let acting = scoped.acting(db.test_actor(env), CorrelationId::generate(env));
    let subject = acting
        .users()
        .register(env, OWNER, HASH, None)
        .await
        .unwrap();
    let proof_id = RecipientChallengeId::generate(env, &scope);
    let expiry = crate::util::epoch_micros(env.clock().now_utc()) + 300_000_000;
    acting
        .recipient_verification()
        .start(
            env,
            NewRecipientChallenge {
                id: &proof_id,
                subject: &subject,
                email: OWNER,
                code_hash: HASH,
                expires_at_unix_micros: expiry,
            },
        )
        .await
        .unwrap();
    let proof = scoped
        .recipient_verification()
        .challenge(env, &subject, &proof_id)
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
    let recovery = RecoveryFlowId::generate(env, &scope);
    acting
        .recovery_flows()
        .initiate(
            env,
            NewRecoveryFlow {
                id: &recovery,
                subject: &subject,
                entry_point: RecoveryEntryPoint::LostPassword,
                recover_acr: "urn:ironauth:acr:pwd",
                cancel_token_digest: &[7; 32],
                recipient: OWNER,
                hold_until_unix_micros: None,
                method: RecoveryMethod::Standard,
            },
            0,
        )
        .await
        .unwrap();
    let challenge = PasswordResetChallengeId::generate(env, &scope);
    let primary = acting
        .password_reset()
        .start(
            env,
            NewPasswordReset {
                id: &challenge,
                client: &ClientId::generate(env, &scope),
                browser_binding_hash: &[3; 32],
                authorization_return_to: "/authorize?client_id=fixture",
                account: Some(PasswordResetAccount {
                    subject: &subject,
                    recovery: &recovery,
                }),
                cancellation_token_digest: Some(&[8; 32]),
                code_hash: HASH,
                expires_at_unix_micros: expiry,
            },
        )
        .await
        .unwrap()
        .unwrap();
    (subject, challenge, primary)
}

#[tokio::test]
async fn real_tls_outcomes_are_claimed_once_and_persisted_without_credential_mutation() {
    let db = TestDatabase::start().await;
    let env = env();
    for (reply, expected, expected_count) in [
        (Reply::Accepted, PasswordResetDelivery::Accepted, 1),
        (Reply::Refused, PasswordResetDelivery::Refused, 0),
        (Reply::Disconnect, PasswordResetDelivery::Uncertain, 0),
    ] {
        let scope = db.seed_scope(&env).await;
        let (subject, challenge, primary) = issued(&db, &env, scope).await;
        let (smtp, task) = fixture(reply, true).await;
        let transport = PasswordResetSmtpTransport {
            smtp,
            issuer: Url::parse("https://auth.example.test").unwrap(),
            env: env.clone(),
        };
        let registry =
            IssuerRegistry::new("https://auth.example.test", JwksCacheWindow::clamped(60));
        let state = OidcState::new(
            db.store().clone(),
            env.clone(),
            Arc::new(registry),
            &ironauth_config::OidcConfig::default(),
            "https://auth.example.test",
        )
        .with_password_reset_smtp(transport);
        let request = ResetRequestDelivery {
            subject: &subject,
            challenge: &challenge,
            primary_recipient: &primary,
            code: "12345678",
            expires_at_unix_micros: 1_800_000_300_000_000,
            cancel_url: "https://auth.example.test/recover/cancel?token=fixture-capability",
        };
        assert_eq!(
            send_reset_request(&state, &request).await.unwrap(),
            expected
        );
        let raw = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        if expected != PasswordResetDelivery::Refused {
            let raw = raw.unwrap();
            assert!(raw.contains("12345678"));
            assert!(raw.contains(&format!("Message-ID: <{challenge}-code@auth.example.test>")));
        }
        let row = sqlx::query("SELECT state,delivery_state,notified_channels,delivery_started_at IS NOT NULL AS started,delivery_finished_at IS NOT NULL AS finished FROM password_reset_challenges WHERE id=$1")
            .bind(challenge.to_string()).fetch_one(db.owner_pool()).await.unwrap();
        assert_eq!(row.get::<String, _>("state"), "pending");
        assert_eq!(row.get::<String, _>("delivery_state"), expected.as_str());
        assert_eq!(row.get::<i32, _>("notified_channels"), expected_count);
        assert!(row.get::<bool, _>("started") && row.get::<bool, _>("finished"));
        assert!(matches!(
            send_reset_request(&state, &request).await,
            Err(StoreError::Conflict)
        ));
        let audit = db.store().scoped(scope).audit().list().await.unwrap();
        for action in ["password_reset.delivery_started", "password_reset.delivery"] {
            assert_eq!(audit.iter().filter(|row| row.action == action).count(), 1);
        }
        assert_eq!(
            db.store()
                .scoped(scope)
                .users()
                .password_hash_for_subject(&subject)
                .await
                .unwrap()
                .as_deref(),
            Some(HASH)
        );
    }
}
