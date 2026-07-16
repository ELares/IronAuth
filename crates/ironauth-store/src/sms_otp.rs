// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public value types of the guarded SMS-OTP factor (issue #70): the issue spec,
//! the resolve outcome, the per-tenant SMS configuration, and the per-route
//! send-to-verify conversion counters that drive the pumping defense.
//!
//! The OTP semantics are IDENTICAL to the email OTP (issue #68), so the flow purpose
//! is reused from [`crate::email_otp::EmailFactorPurpose`]; only the recipient
//! (a phone number instead of an email) and the SMS-specific guard state differ.
//!
//! The SQL that reads and writes these lives on the repositories in `repository.rs`
//! (the single scoped-table SQL module, enforced by `scripts/query-audit.sh`); this
//! module carries only the types the store's callers name.

use crate::id::SmsOtpCodeId;
use crate::id::UserId;

/// The specification for issuing an SMS-OTP code (issue #70): the freshly minted
/// `sot_` id, the subject and purpose it binds, the one-way code hash, the recipient
/// phone number (sealed and blind-indexed on write, never stored plaintext), the
/// wrong-guess budget, and the TTL horizon. Mirrors
/// [`crate::email_otp::NewEmailOtpCode`].
#[derive(Debug)]
pub struct NewSmsOtpCode<'a> {
    /// The freshly minted `sot_` id (the row's primary key and audit target).
    pub id: &'a SmsOtpCodeId,
    /// The subject (a `usr_` id) the code belongs to.
    pub subject: &'a UserId,
    /// The flow the code authorizes.
    pub purpose: crate::email_otp::EmailFactorPurpose,
    /// The Argon2id PHC verifier of the numeric code (issue #62). Never plaintext.
    pub code_hash: &'a str,
    /// The recipient phone number (canonical E.164); sealed and blind-indexed on
    /// write (issue #48).
    pub recipient_phone: &'a str,
    /// The per-code wrong-guess budget; the code dies once it reaches this count.
    pub max_attempts: i32,
    /// The TTL horizon in Unix microseconds (the clock seam drives it).
    pub expires_at_unix_micros: i64,
}

/// An active (unconsumed, unexpired) SMS-OTP code resolved for a verify (issue #70):
/// the id to consume, the one-way code hash the caller verifies through the hashing
/// pool, and the attempt budget. Mirrors [`crate::email_otp::ActiveEmailOtpCode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSmsOtpCode {
    /// The `sot_` id to consume on a correct code or advance on a wrong one.
    pub id: SmsOtpCodeId,
    /// The Argon2id PHC verifier to compare the presented code against.
    pub code_hash: String,
    /// The wrong guesses recorded so far.
    pub attempt_count: i32,
    /// The wrong-guess budget; the code dies once `attempt_count` reaches this.
    pub max_attempts: i32,
}

/// The per (tenant, environment) SMS configuration (issue #70): whether SMS OTP is
/// enabled at all, and whether an explicit factor-downgrade path is opted in. Off by
/// default: a scope with NO row resolves to [`SmsTenantConfig::disabled`], so SMS OTP
/// is unusable until a tenant explicitly turns it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmsTenantConfig {
    /// Whether SMS OTP is enabled for this scope. False by default (no row).
    pub enabled: bool,
    /// Whether SMS may satisfy a step-up / downgrade a stronger factor requirement
    /// (issue #70 no-silent-downgrade invariant). False by default.
    pub allow_factor_downgrade: bool,
}

impl SmsTenantConfig {
    /// The default posture for a scope with no configuration row: SMS OTP off, no
    /// downgrade path. The safe default that makes SMS off by default everywhere.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            allow_factor_downgrade: false,
        }
    }
}

/// The per (tenant, environment, route) send-to-verify conversion counters and the
/// auto-throttle state (issue #70): the pumping-defense signal. A route is a
/// country/carrier bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsRouteStat {
    /// The route bucket (a country calling code).
    pub route_key: String,
    /// Sends recorded in the current window.
    pub send_count: i64,
    /// Successful verifications recorded in the current window.
    pub verify_count: i64,
    /// The instant (Unix micros) the route is throttled until, or [`None`] when it is
    /// not throttled. A send to a throttled route is refused uniformly.
    pub throttled_until_unix_micros: Option<i64>,
    /// Whether the low-conversion alarm is currently latched for this route.
    pub alarm_active: bool,
}

impl SmsRouteStat {
    /// Whether the route is throttled at `now_micros` (a throttle instant in the
    /// future).
    #[must_use]
    pub fn is_throttled(&self, now_micros: i64) -> bool {
        matches!(self.throttled_until_unix_micros, Some(until) if until > now_micros)
    }
}
