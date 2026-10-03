// SPDX-License-Identifier: MIT OR Apache-2.0

//! Purpose-specific password recovery mail. No logging/no-op fallback and no
//! plaintext outbox. Construction alone never enables a hosted recovery route.

use ironauth_env::Env;
use ironauth_store::{PasswordResetChallengeId, Scope};
use url::Url;

use crate::pages::escape_html;
use crate::recipient_smtp::{
    RecipientSmtpConfig, RecipientSmtpConfigError, RecipientSmtpTransport,
};
use crate::recipient_verification::RecipientDeliveryFailure;

/// Transient recovery content; never Debug, serialized or persisted in plaintext.
pub enum PasswordResetNotice<'a> {
    /// A code and a usable same-provider cancellation action.
    Code {
        /// Purpose-specific eight-digit code.
        code: &'a str,
        /// Exact expiry from the environment clock and persisted challenge.
        expires_at_unix_micros: i64,
        /// Validated provider cancellation URL, never an application redirect.
        cancel_url: &'a str,
    },
    /// Owner warning for another required verified channel, without reset proof.
    Requested {
        /// Usable cancellation action for the same recovery case.
        cancel_url: &'a str,
    },
    /// Notification after the credential transaction committed.
    Completed,
}

/// A reset message is deliberately not a mailbox-verification or login message.
pub struct PasswordResetMessage<'a> {
    /// Scope-bound reset identity, used only for delivery correlation.
    pub challenge_id: &'a PasswordResetChallengeId,
    /// Exact provider scope.
    pub scope: Scope,
    /// Current store-owned verified address, not a browser-supplied alias.
    pub recipient: &'a str,
    /// Secret-bearing request or non-secret completion content.
    pub notice: PasswordResetNotice<'a>,
}

/// Value-free transport outcome; a missing SMTP acknowledgement is not a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordResetDeliveryFailure {
    /// No acceptance; an explicit refusal or a local validation/admission failure.
    Refused,
    /// Acceptance is unknown. No automatic retry is permitted.
    Uncertain,
}

impl From<RecipientDeliveryFailure> for PasswordResetDeliveryFailure {
    fn from(value: RecipientDeliveryFailure) -> Self {
        match value {
            RecipientDeliveryFailure::Refused => Self::Refused,
            RecipientDeliveryFailure::Uncertain => Self::Uncertain,
        }
    }
}

/// Explicit recovery transport; installing an unrelated sender cannot enable it.
#[async_trait::async_trait]
pub trait PasswordResetTransport: Send + Sync {
    /// One bounded delivery attempt. Never log codes or cancellation capabilities.
    async fn deliver(
        &self,
        message: PasswordResetMessage<'_>,
    ) -> Result<(), PasswordResetDeliveryFailure>;
}

/// Shares TLS/SMTP mechanics, never the verification-code purpose or enable flag.
pub struct PasswordResetSmtpTransport {
    smtp: RecipientSmtpTransport,
    issuer: Url,
    env: Env,
}

impl std::fmt::Debug for PasswordResetSmtpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordResetSmtpTransport { redacted }")
    }
}

impl PasswordResetSmtpTransport {
    /// Resolve relay secrets only for explicitly enabled recovery delivery.
    ///
    /// # Errors
    /// A value-free error for invalid or unreadable enabled configuration.
    pub fn configured(
        config: &ironauth_config::PasswordRecoveryConfig,
        public_url: Option<&str>,
        env: Env,
    ) -> Result<Option<Self>, RecipientSmtpConfigError> {
        if !config.enabled {
            return Ok(None);
        }
        let settings = config.smtp.as_ref().ok_or(RecipientSmtpConfigError)?;
        Self::new(
            RecipientSmtpConfig::resolve(settings)?,
            public_url.ok_or(RecipientSmtpConfigError)?,
            env,
        )
        .map(Some)
    }

    /// Construct explicit TLS delivery for a root HTTPS provider origin.
    ///
    /// # Errors
    /// Value-free invalid issuer or SMTP configuration. No secret is logged.
    pub fn new(
        config: RecipientSmtpConfig,
        issuer: &str,
        env: Env,
    ) -> Result<Self, RecipientSmtpConfigError> {
        let issuer = Url::parse(issuer).map_err(|_| RecipientSmtpConfigError)?;
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || issuer.path() != "/"
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return Err(RecipientSmtpConfigError);
        }
        Ok(Self {
            smtp: RecipientSmtpTransport::new(config, env.clone())?,
            issuer,
            env,
        })
    }

    fn cancel_url(&self, raw: &str) -> Result<String, PasswordResetDeliveryFailure> {
        let refused = PasswordResetDeliveryFailure::Refused;
        if raw.len() > 2048 || raw.chars().any(char::is_control) {
            return Err(refused);
        }
        let url = Url::parse(raw).map_err(|_| refused)?;
        let params: Vec<_> = url.query_pairs().collect();
        if url.origin() != self.issuer.origin()
            || url.path() != "/recover/cancel"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || params.len() != 1
            || params[0].0 != "token"
            || params[0].1.is_empty()
        {
            return Err(refused);
        }
        Ok(url.to_string())
    }

    fn render(
        &self,
        message: &PasswordResetMessage<'_>,
    ) -> Result<(lettre::address::Envelope, String), PasswordResetDeliveryFailure> {
        let refused = PasswordResetDeliveryFailure::Refused;
        if message.challenge_id.scope() != message.scope {
            return Err(refused);
        }
        let (suffix, subject, text, html) = match &message.notice {
            PasswordResetNotice::Code {
                code,
                expires_at_unix_micros,
                cancel_url,
            } => {
                if code.len() != 8 || !code.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(refused);
                }
                let now = crate::util::epoch_micros(self.env.clock().now_utc());
                if *expires_at_unix_micros <= now
                    || *expires_at_unix_micros > now.saturating_add(600_000_000)
                {
                    return Err(refused);
                }
                let expiry = std::time::SystemTime::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_micros(
                        u64::try_from(*expires_at_unix_micros).map_err(|_| refused)?,
                    ))
                    .ok_or(refused)?;
                let expiry = httpdate::fmt_http_date(expiry);
                let cancel = self.cancel_url(cancel_url)?;
                let text = format!(
                    "Your IronAuth password reset code is {code}.\r\nEnter it on the recovery page you opened. It expires at {expiry}.\r\nThis code does not sign you in or remove your other authentication factors.\r\nIf you did not request this reset, cancel it: {cancel}"
                );
                let html = format!(
                    "<p>Your IronAuth password reset code is <strong>{code}</strong>.</p><p>Enter it on the recovery page you opened. It expires at {expiry}.</p><p>This code does not sign you in or remove your other authentication factors.</p><p>If you did not request this reset, <a href=\"{}\">cancel it</a>.</p>",
                    escape_html(&cancel)
                );
                ("code", "Reset your IronAuth password", text, html)
            }
            PasswordResetNotice::Requested { cancel_url } => {
                let cancel = self.cancel_url(cancel_url)?;
                let text = format!(
                    "A password reset was requested for your IronAuth account. If you did not request it, cancel the recovery: {cancel}\r\nThis notification does not contain a reset code and does not sign you in."
                );
                let html = format!(
                    "<p>A password reset was requested for your IronAuth account.</p><p>If you did not request it, <a href=\"{}\">cancel the recovery</a>.</p><p>This notification does not contain a reset code and does not sign you in.</p>",
                    escape_html(&cancel)
                );
                (
                    "requested",
                    "Password reset requested for your IronAuth account",
                    text,
                    html,
                )
            }
            PasswordResetNotice::Completed => {
                let text = "Your IronAuth password was reset. You have been signed out on your devices. Sign in with your new password and your usual authentication factors. If you did not make this change, contact your administrator immediately.".to_owned();
                let html = format!("<p>{}</p>", escape_html(&text));
                ("completed", "Your IronAuth password was reset", text, html)
            }
        };
        // Different notices have different identities even for the same challenge.
        let id = format!("{}-{suffix}", message.challenge_id);
        self.smtp
            .render_parts(&id, message.recipient, subject, &text, &html)
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl PasswordResetTransport for PasswordResetSmtpTransport {
    async fn deliver(
        &self,
        message: PasswordResetMessage<'_>,
    ) -> Result<(), PasswordResetDeliveryFailure> {
        let (envelope, raw) = self.render(&message)?;
        self.smtp
            .send_rendered(envelope, raw)
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
