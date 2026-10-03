// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::recipient_smtp::RecipientSmtpTls;
use crate::recipient_smtp::tests::{Reply, fixture};
use ironauth_store::{EnvironmentId, TenantId};
use std::time::{Duration, SystemTime};

fn env() -> Env {
    Env::deterministic(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        1479,
    )
    .0
}

fn scope(env: &Env) -> Scope {
    Scope::new(TenantId::generate(env), EnvironmentId::generate(env))
}

fn config() -> RecipientSmtpConfig {
    RecipientSmtpConfig {
        host: "localhost".into(),
        port: 465,
        tls: RecipientSmtpTls::Implicit,
        sender: "recovery@example.test".into(),
        message_id_domain: "auth.example.test".into(),
        credentials: None,
        max_in_flight: 1,
    }
}

fn code(id: &PasswordResetChallengeId, scope: Scope) -> PasswordResetMessage<'_> {
    PasswordResetMessage {
        challenge_id: id,
        scope,
        recipient: "owner@example.test",
        notice: PasswordResetNotice::Code {
            code: "12345678",
            expires_at_unix_micros: 1_800_000_300_000_000,
            cancel_url: "https://auth.example.test/recover/cancel?token=fixture-capability",
        },
    }
}

#[test]
fn reset_mail_has_distinct_purpose_expiry_and_cancellation_and_completion_identity() {
    let env = env();
    let scope = scope(&env);
    let id = PasswordResetChallengeId::generate(&env, &scope);
    let smtp = PasswordResetSmtpTransport::new(config(), "https://auth.example.test", env).unwrap();
    let (_, raw) = smtp.render(&code(&id, scope)).unwrap();
    assert!(raw.contains("Subject: Reset your IronAuth password"));
    assert!(raw.contains(&format!("Message-ID: <{id}-code@auth.example.test>")));
    assert!(raw.contains("Fri, 15 Jan 2027 08:05:00 GMT"));
    assert!(raw.contains("recover/cancel?token=fixture-capability"));
    assert_eq!(raw.matches("12345678").count(), 2);
    assert!(!raw.contains("email verification code"));
    let (_, done) = smtp
        .render(&PasswordResetMessage {
            notice: PasswordResetNotice::Completed,
            ..code(&id, scope)
        })
        .unwrap();
    assert!(done.contains(&format!("Message-ID: <{id}-completed@auth.example.test>")));
    assert!(!done.contains("12345678"));
    assert!(!done.contains("fixture-capability"));
    assert_eq!(
        format!("{smtp:?}"),
        "PasswordResetSmtpTransport { redacted }"
    );
}

#[test]
fn reset_mail_refuses_foreign_scope_and_untrusted_cancellation_destinations() {
    let env = env();
    let current = scope(&env);
    let id = PasswordResetChallengeId::generate(&env, &current);
    let smtp = PasswordResetSmtpTransport::new(config(), "https://auth.example.test", env.clone())
        .unwrap();
    assert!(smtp.render(&code(&id, scope(&env))).is_err());
    for cancel_url in [
        "https://evil.test/recover/cancel?token=x",
        "http://auth.example.test/recover/cancel?token=x",
        "https://auth.example.test/authorize?token=x",
        "https://auth.example.test/recover/cancel?token=x&redirect_uri=https://evil.test",
        "https://user:secret@auth.example.test/recover/cancel?token=x",
        "https://auth.example.test/recover/cancel?token=x#fragment",
    ] {
        let mut message = code(&id, current);
        message.notice = PasswordResetNotice::Code {
            code: "12345678",
            expires_at_unix_micros: 1_800_000_300_000_000,
            cancel_url,
        };
        assert!(smtp.render(&message).is_err());
    }
}

async fn attempt(
    reply: Reply,
    trust: bool,
) -> (Result<(), PasswordResetDeliveryFailure>, Option<String>) {
    let (smtp, task) = fixture(reply, trust).await;
    let env = env();
    let current = scope(&env);
    let id = PasswordResetChallengeId::generate(&env, &current);
    let transport = PasswordResetSmtpTransport {
        smtp,
        issuer: Url::parse("https://auth.example.test").unwrap(),
        env,
    };
    let outcome = transport.deliver(code(&id, current)).await;
    let raw = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    (outcome, raw)
}

#[tokio::test]
async fn reset_mail_uses_verified_tls_and_preserves_refused_vs_uncertain() {
    let (outcome, raw) = attempt(Reply::Accepted, true).await;
    assert_eq!(outcome, Ok(()));
    assert!(raw.unwrap().contains("Reset your IronAuth password"));
    assert_eq!(
        attempt(Reply::Refused, true).await.0,
        Err(PasswordResetDeliveryFailure::Refused)
    );
    for reply in [Reply::Disconnect, Reply::Stall] {
        let (outcome, raw) = attempt(reply, true).await;
        assert_eq!(outcome, Err(PasswordResetDeliveryFailure::Uncertain));
        assert!(raw.unwrap().contains("12345678"));
    }
    let (outcome, raw) = attempt(Reply::Accepted, false).await;
    assert_eq!(outcome, Err(PasswordResetDeliveryFailure::Uncertain));
    assert!(raw.is_none());
}

#[test]
fn reset_mail_refuses_expired_or_overlong_lifetimes_and_non_numeric_codes() {
    let env = env();
    let current = scope(&env);
    let id = PasswordResetChallengeId::generate(&env, &current);
    let smtp = PasswordResetSmtpTransport::new(config(), "https://auth.example.test", env).unwrap();
    for expiry in [
        1_799_999_999_000_000,
        1_800_000_000_000_000,
        1_800_000_600_000_001,
    ] {
        let message = PasswordResetMessage {
            notice: PasswordResetNotice::Code {
                code: "12345678",
                expires_at_unix_micros: expiry,
                cancel_url: "https://auth.example.test/recover/cancel?token=fixture-capability",
            },
            ..code(&id, current)
        };
        assert!(smtp.render(&message).is_err());
    }
    for value in ["", "1234567", "123456789", "1234567x", "1234567\n"] {
        let message = PasswordResetMessage {
            notice: PasswordResetNotice::Code {
                code: value,
                expires_at_unix_micros: 1_800_000_300_000_000,
                cancel_url: "https://auth.example.test/recover/cancel?token=fixture-capability",
            },
            ..code(&id, current)
        };
        assert!(smtp.render(&message).is_err());
    }
    for issuer in [
        "http://auth.example.test",
        "https://user:secret@auth.example.test",
        "https://auth.example.test/?query=x",
        "https://auth.example.test/#fragment",
    ] {
        assert!(PasswordResetSmtpTransport::new(config(), issuer, super::tests::env()).is_err());
    }
}

#[test]
fn disabled_recovery_never_resolves_secrets_and_enabled_failures_are_value_free() {
    use ironauth_config::{
        PasswordRecoveryConfig, RecipientSmtpSecurity, RecipientSmtpSettings, Secret, SecretString,
    };
    let mut config = PasswordRecoveryConfig {
        enabled: false,
        smtp: Some(RecipientSmtpSettings {
            host: "localhost".into(),
            port: 465,
            security: RecipientSmtpSecurity::Implicit,
            sender: "recovery@example.test".into(),
            message_id_domain: "auth.example.test".into(),
            username: Some(Secret::Literal(SecretString::new("fixture-user"))),
            password: Some(Secret::File(
                "/nonexistent/ironauth-reset-1479/password".into(),
            )),
            max_in_flight: 1,
        }),
    };
    assert!(
        PasswordResetSmtpTransport::configured(&config, None, env())
            .unwrap()
            .is_none()
    );
    config.enabled = true;
    let error =
        PasswordResetSmtpTransport::configured(&config, Some("https://auth.example.test"), env())
            .unwrap_err();
    assert_eq!(error.to_string(), "invalid recipient SMTP configuration");
    config.smtp.as_mut().unwrap().password =
        Some(Secret::Literal(SecretString::new("fixture-password")));
    assert!(
        PasswordResetSmtpTransport::configured(&config, Some("https://auth.example.test"), env())
            .unwrap()
            .is_some()
    );
    assert!(PasswordResetSmtpTransport::configured(&config, None, env()).is_err());
}

#[tokio::test]
async fn reset_owner_notice_delivers_cancellation_without_sharing_the_code() {
    let (smtp, task) = fixture(Reply::Accepted, true).await;
    let env = env();
    let current = scope(&env);
    let id = PasswordResetChallengeId::generate(&env, &current);
    let transport = PasswordResetSmtpTransport {
        smtp,
        issuer: Url::parse("https://auth.example.test").unwrap(),
        env,
    };
    let message = PasswordResetMessage {
        notice: PasswordResetNotice::Requested {
            cancel_url: "https://auth.example.test/recover/cancel?token=fixture-owner-cancel",
        },
        ..code(&id, current)
    };
    assert_eq!(transport.deliver(message).await, Ok(()));
    let raw = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(raw.contains(&format!("Message-ID: <{id}-requested@auth.example.test>")));
    assert!(raw.contains("recover/cancel?token=fixture-owner-cancel"));
    assert!(!raw.contains("12345678"));
    let bad = PasswordResetMessage {
        notice: PasswordResetNotice::Requested {
            cancel_url: "https://foreign.test/recover/cancel?token=x",
        },
        ..code(&id, current)
    };
    assert!(transport.render(&bad).is_err());
}

#[cfg(feature = "testing")]
mod delivery_store;

#[cfg(feature = "testing")]
mod request_store;
