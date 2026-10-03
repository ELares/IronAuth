// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;
use std::time::SystemTime;

use ironauth_store::{EnvironmentId, RecipientChallengeId, Scope, TenantId};
use lettre::transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};

use super::*;

fn env() -> Env {
    Env::deterministic(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        1475,
    )
    .0
}

fn config(port: u16) -> RecipientSmtpConfig {
    RecipientSmtpConfig {
        host: "localhost".into(),
        port,
        tls: RecipientSmtpTls::Implicit,
        sender: "verify@example.test".into(),
        message_id_domain: "auth.example.test".into(),
        credentials: None,
        max_in_flight: 1,
    }
}

fn test_scope(env: &Env) -> Scope {
    Scope::new(TenantId::generate(env), EnvironmentId::generate(env))
}

#[test]
fn message_is_scoped_multipart_and_uses_environment_time() {
    let env = env();
    let scope = test_scope(&env);
    let id = RecipientChallengeId::generate(&env, &scope);
    let smtp = RecipientSmtpTransport::new(config(465), env).unwrap();
    let message = RecipientVerificationMessage {
        scope,
        challenge_id: &id,
        recipient: "owner@example.test",
        code: "12345678",
    };
    let (_, raw) = smtp.render(&message).unwrap();
    assert!(raw.contains(&format!("Message-ID: <{id}@auth.example.test>\r\n")));
    assert!(raw.contains("Date: Fri, 15 Jan 2027 08:00:00 GMT\r\n"));
    assert!(raw.contains("Content-Type: text/plain"));
    assert!(raw.contains("Content-Type: text/html"));
    assert_eq!(raw.matches("12345678").count(), 2);
    assert_eq!(format!("{smtp:?}"), "RecipientSmtpTransport { redacted }");
    let foreign = test_scope(&super::tests::env());
    // Advance the fixture entropy to produce a distinct scope.
    let foreign = Scope::new(TenantId::generate(&smtp.env), foreign.environment());
    assert!(
        smtp.render(&RecipientVerificationMessage {
            scope: foreign,
            ..message
        })
        .is_err()
    );
}

#[test]
fn malformed_addresses_and_configuration_are_refused_without_network() {
    for value in [
        "a@example.test\r\nBcc: other@example.test",
        "A <a@example.test>",
        "a@example.test,b@example.test",
        "a\0@example.test",
        "é@example.test",
    ] {
        assert!(mailbox(value).is_err());
    }
    for max in [0, 33] {
        let mut cfg = config(465);
        cfg.max_in_flight = max;
        assert!(RecipientSmtpTransport::new(cfg, env()).is_err());
    }
    let mut cfg = config(465);
    cfg.host = "smtp://user:password@example.test".into();
    assert!(RecipientSmtpTransport::new(cfg, env()).is_err());
}

#[derive(Clone, Copy)]
pub(crate) enum Reply {
    Accepted,
    Refused,
    Disconnect,
    Stall,
}

pub(crate) async fn fixture(
    reply: Reply,
    trust: bool,
) -> (
    RecipientSmtpTransport,
    tokio::task::JoinHandle<Option<String>>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut smtp = RecipientSmtpTransport::new(config(port), env()).unwrap();
    if trust {
        // Only the fixture injects this root. Hostname verification stays enabled.
        let tls = TlsParameters::builder("localhost".into())
            .certificate_store(CertificateStore::None)
            .add_root_certificate(Certificate::from_der(cert.cert.der().to_vec()).unwrap())
            .build()
            .unwrap();
        smtp.client = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
            .port(port)
            .tls(Tls::Wrapper(tls))
            .timeout(Some(Duration::from_millis(150)))
            .build();
    }
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let Ok(socket) = acceptor.accept(socket).await else {
            return None;
        };
        let mut io = BufReader::new(socket);
        io.get_mut()
            .write_all(b"220 localhost SMTP fixture\r\n")
            .await
            .unwrap();
        let mut body = String::new();
        loop {
            let mut line = String::new();
            if io.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            let response: &[u8] = if line.starts_with("EHLO ") {
                b"250-localhost\r\n250 8BITMIME\r\n"
            } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                b"250 OK\r\n"
            } else if line == "DATA\r\n" {
                io.get_mut()
                    .write_all(b"354 send content\r\n")
                    .await
                    .unwrap();
                loop {
                    let mut content = String::new();
                    if io.read_line(&mut content).await.unwrap_or(0) == 0 {
                        return Some(body);
                    }
                    if content == ".\r\n" {
                        break;
                    }
                    body.push_str(&content);
                }
                match reply {
                    Reply::Accepted => b"250 accepted\r\n",
                    Reply::Refused => b"550 refused\r\n",
                    Reply::Disconnect => break,
                    Reply::Stall => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        break;
                    }
                }
            } else if line == "QUIT\r\n" {
                let _ = io.get_mut().write_all(b"221 bye\r\n").await;
                break;
            } else {
                panic!("unexpected SMTP command");
            };
            if io.get_mut().write_all(response).await.is_err() {
                break;
            }
        }
        Some(body)
    });
    (smtp, task)
}

async fn attempt(
    reply: Reply,
    trust: bool,
) -> (Result<(), RecipientDeliveryFailure>, Option<String>) {
    let (smtp, task) = fixture(reply, trust).await;
    let scope = test_scope(&smtp.env);
    let id = RecipientChallengeId::generate(&smtp.env, &scope);
    let outcome = smtp
        .deliver(RecipientVerificationMessage {
            scope,
            challenge_id: &id,
            recipient: "owner@example.test",
            code: "12345678",
        })
        .await;
    let body = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    (outcome, body)
}

#[tokio::test]
async fn verified_tls_acceptance_and_explicit_refusal() {
    let (outcome, body) = attempt(Reply::Accepted, true).await;
    assert_eq!(outcome, Ok(()));
    assert!(body.unwrap().contains("12345678"));
    assert_eq!(
        attempt(Reply::Refused, true).await.0,
        Err(RecipientDeliveryFailure::Refused)
    );
}

#[tokio::test]
async fn disconnect_or_timeout_after_data_is_uncertain_without_retry() {
    for reply in [Reply::Disconnect, Reply::Stall] {
        let (outcome, body) = attempt(reply, true).await;
        assert_eq!(outcome, Err(RecipientDeliveryFailure::Uncertain));
        assert!(body.unwrap().contains("12345678"));
    }
}

#[tokio::test]
async fn untrusted_tls_sends_no_code() {
    let (outcome, body) = attempt(Reply::Accepted, false).await;
    assert_eq!(outcome, Err(RecipientDeliveryFailure::Uncertain));
    assert!(body.is_none());
}

#[tokio::test]
async fn saturation_refuses_before_connecting() {
    let smtp = RecipientSmtpTransport::new(config(1), env()).unwrap();
    let _held = smtp.permits.acquire().await.unwrap();
    let scope = test_scope(&smtp.env);
    let id = RecipientChallengeId::generate(&smtp.env, &scope);
    assert_eq!(
        smtp.deliver(RecipientVerificationMessage {
            scope,
            challenge_id: &id,
            recipient: "owner@example.test",
            code: "12345678",
        })
        .await,
        Err(RecipientDeliveryFailure::Refused)
    );
}

#[tokio::test]
async fn starttls_never_falls_back_to_plaintext() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = config(listener.local_addr().unwrap().port());
    cfg.tls = RecipientSmtpTls::StartTls;
    cfg.credentials = Some(("fixture-user".into(), "fixture-password".into()));
    let smtp = RecipientSmtpTransport::new(cfg, env()).unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut io = BufReader::new(socket);
        io.get_mut()
            .write_all(b"220 plaintext fixture\r\n")
            .await
            .unwrap();
        let mut line = String::new();
        io.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("EHLO "));
        // Offer authentication but not STARTTLS. Neither AUTH nor MAIL is allowed.
        io.get_mut()
            .write_all(b"250-fixture\r\n250 AUTH PLAIN LOGIN\r\n")
            .await
            .unwrap();
        loop {
            line.clear();
            if io.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            assert_eq!(line, "QUIT\r\n");
            let _ = io.get_mut().write_all(b"221 bye\r\n").await;
        }
    });
    let scope = test_scope(&smtp.env);
    let id = RecipientChallengeId::generate(&smtp.env, &scope);
    assert!(
        smtp.deliver(RecipientVerificationMessage {
            scope,
            challenge_id: &id,
            recipient: "owner@example.test",
            code: "12345678",
        })
        .await
        .is_err()
    );
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn operator_configuration_resolves_secrets_only_when_enabled_and_redacts_failures() {
    use ironauth_config::{
        RecipientSmtpSecurity, RecipientSmtpSettings, RecipientVerificationConfig, Secret,
        SecretString,
    };
    let settings = RecipientSmtpSettings {
        host: "localhost".into(),
        port: 465,
        security: RecipientSmtpSecurity::Implicit,
        sender: "verify@example.test".into(),
        message_id_domain: "auth.example.test".into(),
        username: Some(Secret::Literal(SecretString::new("fixture-user"))),
        password: Some(Secret::File(
            "/nonexistent/ironauth-recipient-1475/password".into(),
        )),
        max_in_flight: 2,
    };
    let mut config = RecipientVerificationConfig {
        enabled: false,
        smtp: Some(settings),
    };
    assert!(
        RecipientSmtpTransport::configured(&config, env())
            .unwrap()
            .is_none()
    );
    config.enabled = true;
    let error = RecipientSmtpTransport::configured(&config, env()).unwrap_err();
    assert_eq!(error.to_string(), "invalid recipient SMTP configuration");
    config.smtp.as_mut().unwrap().password =
        Some(Secret::Literal(SecretString::new("fixture-password")));
    assert!(
        RecipientSmtpTransport::configured(&config, env())
            .unwrap()
            .is_some()
    );
    config.smtp = None;
    assert!(RecipientSmtpTransport::configured(&config, env()).is_err());
}
