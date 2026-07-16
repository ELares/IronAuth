// SPDX-License-Identifier: MIT OR Apache-2.0

//! The verification / OTP SEND seam and its closed-registration suppression (issue #64).
//!
//! The actual email / OTP transport is a later factor milestone (email OTP is issue
//! #68). This module lands only the SEAM the abuse defenses need: a [`VerificationSender`]
//! trait and the suppression rule that makes closed-registration and recovery
//! non-oracular. When registration is CLOSED (or a recovery is requested for an unknown
//! address), a send to an UNKNOWN recipient is silently SUPPRESSED while the user-visible
//! acknowledgment is IDENTICAL to a real send (the Logto v1.41 pattern), so a probe
//! cannot distinguish an existing account from an unknown one.

use ironauth_store::{EmailFactorPurpose, Scope};

/// Why a verification message would be sent (issue #64). Bound into the send so a future
/// transport (#68) can render the right template and a test can assert what was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPurpose {
    /// A registration verification (confirm a newly claimed identifier).
    Registration,
    /// An account-recovery message (a reset link / OTP).
    Recovery,
}

/// An email-OTP delivery (issue #68): the numeric code to deliver to `recipient`, with
/// the flow it authorizes and its lifetime. The concrete transport is a documented seam
/// (M11 messaging); the code is a live secret, so an implementation MUST NOT log it at a
/// level that reaches production sinks.
#[derive(Debug, Clone, Copy)]
pub struct EmailOtpMessage<'a> {
    /// The tenant/environment scope.
    pub scope: Scope,
    /// The flow the code authorizes.
    pub purpose: EmailFactorPurpose,
    /// The recipient email address.
    pub recipient: &'a str,
    /// The numeric one-time code (a live secret).
    pub code: &'a str,
    /// The code lifetime in seconds (for the message copy).
    pub ttl_secs: u64,
}

/// A scanner-safe magic-link delivery (issue #68): the confirmation-page link AND the
/// cross-device short code, both printed in the same email so a broken-link client still
/// completes login. Both the link (it carries the single-use token) and the short code
/// are live secrets.
#[derive(Debug, Clone, Copy)]
pub struct MagicLinkMessage<'a> {
    /// The tenant/environment scope.
    pub scope: Scope,
    /// The flow the link authorizes.
    pub purpose: EmailFactorPurpose,
    /// The recipient email address.
    pub recipient: &'a str,
    /// The full confirmation-page URL the user opens (carries the single-use token).
    pub link: &'a str,
    /// The cross-device short code, entered on the originating device when the link is
    /// opened elsewhere or the email client breaks the link.
    pub short_code: &'a str,
    /// The link lifetime in seconds (for the message copy).
    pub ttl_secs: u64,
}

/// An SMS-OTP delivery (issue #70): the numeric code to text to `recipient`, with the
/// flow it authorizes and its lifetime. The concrete transport is a documented seam
/// (M11 messaging: Twilio Verify, Vonage, SNS); the code is a live secret, so an
/// implementation MUST NOT log it at a level that reaches production sinks.
#[derive(Debug, Clone, Copy)]
pub struct SmsOtpMessage<'a> {
    /// The tenant/environment scope.
    pub scope: Scope,
    /// The flow the code authorizes.
    pub purpose: EmailFactorPurpose,
    /// The recipient phone number (canonical E.164).
    pub recipient: &'a str,
    /// The route bucket the send is accounted to (the country calling code).
    pub route_key: &'a str,
    /// The numeric one-time code (a live secret).
    pub code: &'a str,
    /// The code lifetime in seconds (for the message copy).
    pub ttl_secs: u64,
}

impl VerificationPurpose {
    /// The stable wire tag, for tracing and a future template selection.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            VerificationPurpose::Registration => "registration",
            VerificationPurpose::Recovery => "recovery",
        }
    }
}

/// The SMS delivery seam (issue #70): the provider boundary the guarded SMS-OTP factor
/// delivers through. The concrete transport (Twilio Verify, Vonage, SNS) is M11 and out
/// of scope here; this issue ships and tests against a local STUB, exactly like the
/// email [`VerificationSender`] shipped [`NullVerificationSender`] /
/// [`LoggingVerificationSender`]. An implementation MUST perform an actual delivery ONLY
/// when [`send`](Self::send) is called; the caller decides whether to call it, applying
/// the country-allowlist, velocity-cap, phone-scoring, and pumping-defense guards first,
/// so a refused / suppressed destination never reaches a provider.
pub trait SmsSender: Send + Sync + std::fmt::Debug {
    /// Deliver an SMS-OTP code (issue #70). Called ONLY for a destination the guard
    /// layer has permitted (never a refused / throttled / suppressed one).
    fn send(&self, message: &SmsOtpMessage<'_>);
}

/// The default SMS sender: it performs NO delivery (issue #70). The real SMS transport
/// is M11 messaging; until it is wired, a permitted send is a no-op, so the user-visible
/// acknowledgment is identical whether or not a text actually goes out.
#[derive(Debug, Default)]
pub struct NullSmsSender;

impl SmsSender for NullSmsSender {
    fn send(&self, _message: &SmsOtpMessage<'_>) {
        // No transport yet (issue #70). Intentionally does nothing.
    }
}

/// A development / diagnostic SMS transport (issue #70): it records that a delivery
/// HAPPENED on the observability plane and emits the live code ONLY at the `debug` trace
/// level (never `info`), mirroring [`LoggingVerificationSender`]. The concrete provider
/// adapters (M11) replace this stub; it ships so the guarded SMS-OTP logic is
/// exercisable end to end without an SMS gateway.
#[derive(Debug, Default)]
pub struct LoggingSmsSender;

impl SmsSender for LoggingSmsSender {
    fn send(&self, message: &SmsOtpMessage<'_>) {
        tracing::info!(
            target: "ironauth.verification",
            purpose = message.purpose.as_str(),
            tenant = %message.scope.tenant(),
            environment = %message.scope.environment(),
            route = message.route_key,
            ttl_secs = message.ttl_secs,
            "SMS OTP delivered (dev transport)"
        );
        // The code is a live secret: only at debug, never at info.
        tracing::debug!(
            target: "ironauth.verification",
            code = message.code,
            "SMS OTP code (dev transport, debug only)"
        );
    }
}

/// The verification / OTP delivery seam (issue #64).
///
/// The concrete transport (SMTP, an email provider, an SMS gateway) is issue #68; this
/// trait is the boundary the abuse defenses govern. An implementation MUST perform an
/// actual delivery ONLY when [`send`](Self::send) is called; the caller decides whether to
/// call it, applying the closed-registration suppression via
/// [`OidcState::dispatch_verification`](crate::state::OidcState). The default
/// [`NullVerificationSender`] performs no delivery (no transport is wired yet), so a
/// deployment without #68 behaves exactly as today.
pub trait VerificationSender: Send + Sync + std::fmt::Debug {
    /// Deliver a verification message of `purpose` to `recipient` in `scope`. Called ONLY
    /// for a recipient a send is permitted to (never a suppressed one).
    fn send(&self, scope: Scope, purpose: VerificationPurpose, recipient: &str);

    /// Deliver an email-OTP code (issue #68). Called ONLY for a recipient a send is
    /// permitted to (never a suppressed one). The default is a no-op, so a deployment
    /// with no transport wired behaves as before; a real transport (M11) overrides it.
    fn deliver_email_otp(&self, message: &EmailOtpMessage<'_>) {
        let _ = message;
    }

    /// Deliver a scanner-safe magic link and its cross-device short code (issue #68).
    /// Called ONLY for a permitted recipient. The default is a no-op.
    fn deliver_magic_link(&self, message: &MagicLinkMessage<'_>) {
        let _ = message;
    }
}

/// The default sender: it performs NO delivery (issue #64). The verification/OTP
/// transport is issue #68; until it is wired, a permitted send is a no-op, so the
/// user-visible acknowledgment is identical whether or not a message actually goes out.
#[derive(Debug, Default)]
pub struct NullVerificationSender;

impl VerificationSender for NullVerificationSender {
    fn send(&self, _scope: Scope, _purpose: VerificationPurpose, _recipient: &str) {
        // No transport yet (issue #64). Intentionally does nothing.
    }
}

/// A development / diagnostic transport (issue #68): it records that a delivery HAPPENED
/// on the observability plane, and emits the live secret (the code, the link, the short
/// code) ONLY at the `debug` trace level so it is available to a developer running a dev
/// build but is NOT emitted at the `info` level a production sink typically ingests. The
/// concrete production email provider (SMTP or an API) is a documented seam (M11
/// messaging) that replaces this sender; this ships so the OTP / magic-link logic is
/// exercisable end to end without a mail server.
#[derive(Debug, Default)]
pub struct LoggingVerificationSender;

impl VerificationSender for LoggingVerificationSender {
    fn send(&self, scope: Scope, purpose: VerificationPurpose, _recipient: &str) {
        tracing::info!(
            target: "ironauth.verification",
            purpose = purpose.as_str(),
            tenant = %scope.tenant(),
            environment = %scope.environment(),
            "verification message delivered (dev transport)"
        );
    }

    fn deliver_email_otp(&self, message: &EmailOtpMessage<'_>) {
        tracing::info!(
            target: "ironauth.verification",
            purpose = message.purpose.as_str(),
            tenant = %message.scope.tenant(),
            environment = %message.scope.environment(),
            ttl_secs = message.ttl_secs,
            "email OTP delivered (dev transport)"
        );
        // The code is a live secret: only at debug, never at info.
        tracing::debug!(
            target: "ironauth.verification",
            code = message.code,
            "email OTP code (dev transport, debug only)"
        );
    }

    fn deliver_magic_link(&self, message: &MagicLinkMessage<'_>) {
        tracing::info!(
            target: "ironauth.verification",
            purpose = message.purpose.as_str(),
            tenant = %message.scope.tenant(),
            environment = %message.scope.environment(),
            ttl_secs = message.ttl_secs,
            "magic link delivered (dev transport)"
        );
        tracing::debug!(
            target: "ironauth.verification",
            link = message.link,
            short_code = message.short_code,
            "magic link and short code (dev transport, debug only)"
        );
    }
}
