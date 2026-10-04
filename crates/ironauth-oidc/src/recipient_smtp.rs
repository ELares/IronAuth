// SPDX-License-Identifier: MIT OR Apache-2.0

//! SMTP delivery for subject-bound verification (issue #1475).
//!
//! One bounded attempt, without pooling or automatic retry. A missing final SMTP
//! reply is uncertain, not a refusal and not permission to send a second code.
//! This adapter does not enable the gated hosted ceremony on its own.

use std::time::Duration;

use base64::Engine as _;
use ironauth_env::Env;
use ironauth_store::message_mime;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::recipient_verification::{
    RecipientDeliveryFailure, RecipientVerificationMessage, RecipientVerificationTransport,
};

/// Only authenticated, certificate-verified TLS modes are supported.
#[derive(Debug, Clone, Copy)]
pub enum RecipientSmtpTls {
    /// TLS from connection establishment, normally port 465.
    Implicit,
    /// Mandatory STARTTLS, normally port 587. No plaintext fallback.
    StartTls,
}

/// A value-free configuration failure. Never return library errors containing
/// credentials, addresses, server replies or message material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientSmtpConfigError;

impl std::fmt::Display for RecipientSmtpConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid recipient SMTP configuration")
    }
}

impl std::error::Error for RecipientSmtpConfigError {}

/// Deployment-owned configuration, never derived from a verification request.
/// Deliberately has no Debug or serialization implementation.
pub struct RecipientSmtpConfig {
    /// Fixed relay hostname, verified against its TLS certificate.
    pub host: String,
    /// Explicit TCP port.
    pub port: u16,
    /// Required TLS policy.
    pub tls: RecipientSmtpTls,
    /// Bare ASCII sender mailbox, without display names or header syntax.
    pub sender: String,
    /// Domain used in the challenge-bound Message-ID.
    pub message_id_domain: String,
    /// Optional relay authentication, resolved through operator secret references.
    pub credentials: Option<(String, String)>,
    /// Maximum simultaneous attempts; 1 through 32, with no waiting queue.
    pub max_in_flight: usize,
}

impl RecipientSmtpConfig {
    pub(crate) fn resolve(
        smtp: &ironauth_config::RecipientSmtpSettings,
    ) -> Result<Self, RecipientSmtpConfigError> {
        let credentials = match (&smtp.username, &smtp.password) {
            (Some(user), Some(password)) => Some((
                user.resolve()
                    .map_err(|_| RecipientSmtpConfigError)?
                    .expose()
                    .to_owned(),
                password
                    .resolve()
                    .map_err(|_| RecipientSmtpConfigError)?
                    .expose()
                    .to_owned(),
            )),
            (None, None) => None,
            _ => return Err(RecipientSmtpConfigError),
        };
        Ok(RecipientSmtpConfig {
            host: smtp.host.clone(),
            port: smtp.port,
            tls: match smtp.security {
                ironauth_config::RecipientSmtpSecurity::Implicit => RecipientSmtpTls::Implicit,
                ironauth_config::RecipientSmtpSecurity::StartTls => RecipientSmtpTls::StartTls,
            },
            sender: smtp.sender.clone(),
            message_id_domain: smtp.message_id_domain.clone(),
            credentials,
            max_in_flight: smtp.max_in_flight,
        })
    }
}

/// SMTP adapter whose Debug representation contains no configuration or secrets.
pub struct RecipientSmtpTransport {
    client: AsyncSmtpTransport<Tokio1Executor>,
    sender: Address,
    message_id_domain: String,
    permits: Semaphore,
    env: Env,
}

impl std::fmt::Debug for RecipientSmtpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecipientSmtpTransport { redacted }")
    }
}

fn mailbox(value: &str) -> Result<Address, RecipientSmtpConfigError> {
    if value.is_empty()
        || value.len() > 254
        || !value.is_ascii()
        || value.bytes().any(|byte| byte <= 32 || byte == 127)
        || value.contains(['<', '>', ',', ';', '"', '\\'])
    {
        return Err(RecipientSmtpConfigError);
    }
    value.parse().map_err(|_| RecipientSmtpConfigError)
}

impl RecipientSmtpTransport {
    /// Resolve the operator's secret references and construct the configured
    /// transport. Disabled settings never read secrets or create a client.
    ///
    /// # Errors
    /// A value-free error for missing, unreadable or invalid relay configuration.
    pub fn configured(
        config: &ironauth_config::RecipientVerificationConfig,
        env: Env,
    ) -> Result<Option<Self>, RecipientSmtpConfigError> {
        if !config.enabled {
            return Ok(None);
        }
        let smtp = config.smtp.as_ref().ok_or(RecipientSmtpConfigError)?;
        Self::new(RecipientSmtpConfig::resolve(smtp)?, env).map(Some)
    }

    /// Construct a relay with verified TLS and bounded command deadlines.
    ///
    /// # Errors
    /// Returns a value-free error for invalid configuration or TLS setup.
    pub fn new(config: RecipientSmtpConfig, env: Env) -> Result<Self, RecipientSmtpConfigError> {
        let sender = mailbox(&config.sender)?;
        if config.host.is_empty()
            || config.host.len() > 253
            || !config
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            || config.port == 0
            || !(1..=32).contains(&config.max_in_flight)
            || !message_mime::is_usable_message_id_domain(&config.message_id_domain)
        {
            return Err(RecipientSmtpConfigError);
        }
        let builder = match config.tls {
            RecipientSmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host),
            RecipientSmtpTls::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            }
        }
        .map_err(|_| RecipientSmtpConfigError)?
        .port(config.port)
        .timeout(Some(Duration::from_secs(3)));
        let builder = match config.credentials {
            Some((user, password)) => {
                if user.is_empty()
                    || password.is_empty()
                    || user.len() > 1024
                    || password.len() > 4096
                {
                    return Err(RecipientSmtpConfigError);
                }
                builder.credentials(Credentials::new(user, password))
            }
            None => builder,
        };
        Ok(Self {
            client: builder.build(),
            sender,
            message_id_domain: config.message_id_domain,
            permits: Semaphore::new(config.max_in_flight),
            env,
        })
    }

    fn render(
        &self,
        message: &RecipientVerificationMessage<'_>,
    ) -> Result<(lettre::address::Envelope, String), RecipientDeliveryFailure> {
        let refused = RecipientDeliveryFailure::Refused;
        if message.code.len() != 8 || !message.code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(refused);
        }
        // A typed handle must still belong to the caller's scope. Message-ID is
        // correlation, not an idempotency promise from an SMTP server.
        let id = message.challenge_id.to_string();
        ironauth_store::RecipientChallengeId::parse_in_scope(&id, &message.scope)
            .map_err(|_| refused)?;
        let text = format!(
            "Your IronAuth email verification code is {}.\r\n\
             Enter it in the verification page you opened. It expires in five minutes.\r\n\
             If you did not request this code, ignore this message.",
            message.code
        );
        let html = format!(
            "<p>Your IronAuth email verification code is <strong>{}</strong>.</p>\
             <p>Enter it in the verification page you opened. It expires in five minutes.</p>\
             <p>If you did not request this code, ignore this message.</p>",
            message.code
        );
        self.render_parts(
            &id,
            message.recipient,
            "Verify your IronAuth email address",
            &text,
            &html,
        )
    }

    pub(crate) fn render_parts(
        &self,
        id: &str,
        recipient: &str,
        subject: &str,
        text: &str,
        html: &str,
    ) -> Result<(lettre::address::Envelope, String), RecipientDeliveryFailure> {
        let refused = RecipientDeliveryFailure::Refused;
        let recipient = mailbox(recipient).map_err(|_| refused)?;
        if subject.len() > 200 || subject.chars().any(char::is_control) {
            return Err(refused);
        }
        let message_id =
            message_mime::message_id(id, &self.message_id_domain).map_err(|_| refused)?;
        let boundary = format!(
            "ironauth-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(id.as_bytes()))
        );
        let body =
            message_mime::multipart_alternative(text, html, &boundary).map_err(|_| refused)?;
        let date = httpdate::fmt_http_date(self.env.clock().now_utc());
        let raw = format!(
            "From: {}\r\nTo: {recipient}\r\nDate: {date}\r\n\
             Message-ID: {message_id}\r\nSubject: {subject}\r\n\
             MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n{body}",
            self.sender
        );
        let envelope = lettre::address::Envelope::new(Some(self.sender.clone()), vec![recipient])
            .map_err(|_| refused)?;
        Ok((envelope, raw))
    }
}

#[async_trait::async_trait]
impl RecipientVerificationTransport for RecipientSmtpTransport {
    async fn deliver(
        &self,
        message: RecipientVerificationMessage<'_>,
    ) -> Result<(), RecipientDeliveryFailure> {
        let (envelope, raw) = self.render(&message)?;
        self.send_rendered(envelope, raw).await
    }
}

impl RecipientSmtpTransport {
    pub(crate) async fn send_rendered(
        &self,
        envelope: lettre::address::Envelope,
        raw: String,
    ) -> Result<(), RecipientDeliveryFailure> {
        // Saturation is a known refusal before any network action. No unbounded
        // queue can retain secret material or outlive challenge expiry.
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| RecipientDeliveryFailure::Refused)?;
        match tokio::time::timeout(
            Duration::from_secs(4),
            self.client.send_raw(&envelope, raw.as_bytes()),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            // Only an explicit negative SMTP response establishes refusal.
            // An I/O error can follow DATA acceptance, so never retry here.
            Ok(Err(error)) if error.is_permanent() || error.is_transient() => {
                Err(RecipientDeliveryFailure::Refused)
            }
            Ok(Err(_)) | Err(_) => Err(RecipientDeliveryFailure::Uncertain),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
