// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drive the actual boot helper and its registered consumer against scoped Postgres.
//! Malformed internal work must be drained without opening an SMTP connection.

use super::*;
use ironauth_oidc::password_reset_smtp::PasswordResetSmtpTransport;
use ironauth_oidc::recipient_smtp::{RecipientSmtpConfig, RecipientSmtpTls};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{NewOutboxMessage, PASSWORD_RESET_COMPLETION_CONSUMER};
use std::time::Duration;

fn configured_state(db: &TestDatabase, env: &Env) -> OidcState {
    let registry = Arc::new(IssuerRegistry::new(
        "https://auth.example.test",
        JwksCacheWindow::clamped(60),
    ));
    let state = OidcState::new(
        db.store().clone(),
        env.clone(),
        registry,
        &OidcConfig::default(),
        "https://auth.example.test",
    );
    let transport = PasswordResetSmtpTransport::new(
        RecipientSmtpConfig {
            host: "localhost".into(),
            port: 1,
            tls: RecipientSmtpTls::Implicit,
            sender: "auth@example.test".into(),
            message_id_domain: "example.test".into(),
            credentials: None,
            max_in_flight: 1,
        },
        "https://auth.example.test",
        env.clone(),
    )
    .unwrap();
    state.with_password_reset_smtp(transport)
}

#[tokio::test]
async fn password_reset_worker_boot_requires_delivery_and_control_scope_access() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mut config = Config::from_toml_str("", "<test>").unwrap().config;
    assert!(
        start_password_reset_completion_pools(&config, None)
            .await
            .unwrap()
            .is_empty()
    );
    config.oidc.password_recovery.enabled = true;
    assert!(
        start_password_reset_completion_pools(&config, None)
            .await
            .is_err()
    );
    let state = configured_state(&db, &env);
    config.dev_mode = false;
    assert!(
        start_password_reset_completion_pools(&config, Some(&state))
            .await
            .is_err()
    );
    config.admin.control_database_url = Some(Secret::Literal(ironauth_config::SecretString::new(
        db.app_url(),
    )));
    assert!(
        start_password_reset_completion_pools(&config, Some(&state))
            .await
            .is_err()
    );
    config.admin.control_database_url = Some(Secret::Literal(ironauth_config::SecretString::new(
        db.control_url(),
    )));
    let id = db
        .store()
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &NewOutboxMessage {
                consumer: PASSWORD_RESET_COMPLETION_CONSUMER,
                idempotency_key: "malformed-completion-test",
                ordering_key: "malformed-completion-test",
                payload: serde_json::json!({"invalid": true}),
            },
        )
        .await
        .unwrap();
    let pools = start_password_reset_completion_pools(&config, Some(&state))
        .await
        .unwrap();
    assert_eq!(pools.len(), 1);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let terminal = db
                .store()
                .scoped(scope)
                .outbox()
                .dead_lettered(PASSWORD_RESET_COMPLETION_CONSUMER, None, 10)
                .await
                .unwrap()
                .iter()
                .any(|message| message.id == id);
            if terminal {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for pool in pools {
        pool.shutdown().await;
    }
}
