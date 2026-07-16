// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public value types of the email-OTP and scanner-safe magic-link factors
//! (issue #68): the flow purpose a code or link is bound to, the issue specs, and the
//! resolve/consume outcomes.
//!
//! The SQL that reads and writes these lives on the repositories in `repository.rs`
//! (the single scoped-table SQL module, enforced by `scripts/query-audit.sh`); this
//! module carries only the types the store's callers name.

use crate::id::{EmailOtpCodeId, MagicLinkTokenId, UserId};

/// The flow an email-OTP code or a magic link is bound to (issue #68).
///
/// The purpose is stored on the row and re-checked at verify/consume, so a code minted
/// for one flow (say address verification) can never satisfy another (say a login),
/// closing a purpose-confusion attack. It also selects the message template a future
/// transport renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailFactorPurpose {
    /// Passwordless login (the code or link IS the primary authenticator).
    Login,
    /// Self-service registration (confirm a newly claimed identifier and sign in).
    Register,
    /// A second factor / MFA challenge.
    Mfa,
    /// Account recovery (a last-resort factor).
    Recovery,
    /// Address verification (prove control of a claimed email).
    VerifyAddress,
}

impl EmailFactorPurpose {
    /// The stable wire tag stored in the `purpose` column and bound into the audit
    /// detail.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EmailFactorPurpose::Login => "login",
            EmailFactorPurpose::Register => "register",
            EmailFactorPurpose::Mfa => "mfa",
            EmailFactorPurpose::Recovery => "recovery",
            EmailFactorPurpose::VerifyAddress => "verify_address",
        }
    }

    /// Parse a stored wire tag back to the typed purpose. Returns [`None`] for any
    /// unknown value (the caller treats it as a uniform not-found / skip).
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "login" => Some(EmailFactorPurpose::Login),
            "register" => Some(EmailFactorPurpose::Register),
            "mfa" => Some(EmailFactorPurpose::Mfa),
            "recovery" => Some(EmailFactorPurpose::Recovery),
            "verify_address" => Some(EmailFactorPurpose::VerifyAddress),
            _ => None,
        }
    }
}

/// The specification for issuing an email-OTP code (issue #68): the freshly minted
/// `eot_` id, the subject and purpose it binds, the one-way code hash, the recipient
/// address (sealed and blind-indexed on write, never stored plaintext), the wrong-guess
/// budget, and the TTL horizon.
#[derive(Debug)]
pub struct NewEmailOtpCode<'a> {
    /// The freshly minted `eot_` id (the row's primary key and audit target).
    pub id: &'a EmailOtpCodeId,
    /// The subject (a `usr_` id) the code belongs to.
    pub subject: &'a UserId,
    /// The flow the code authorizes.
    pub purpose: EmailFactorPurpose,
    /// The Argon2id PHC verifier of the numeric code (issue #62). Never plaintext.
    pub code_hash: &'a str,
    /// The recipient email; sealed and blind-indexed on write (issue #48).
    pub recipient_email: &'a str,
    /// The per-code wrong-guess budget; the code dies once it reaches this count.
    pub max_attempts: i32,
    /// The TTL horizon in Unix microseconds (the clock seam drives it).
    pub expires_at_unix_micros: i64,
}

/// An active (unconsumed, unexpired) email-OTP code resolved for a verify (issue #68):
/// the id to consume, the one-way code hash the caller verifies through the hashing
/// pool, and the attempt budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveEmailOtpCode {
    /// The `eot_` id to consume on a correct code or advance on a wrong one.
    pub id: EmailOtpCodeId,
    /// The Argon2id PHC verifier to compare the presented code against.
    pub code_hash: String,
    /// The wrong guesses recorded so far.
    pub attempt_count: i32,
    /// The wrong-guess budget; the code dies once `attempt_count` reaches this.
    pub max_attempts: i32,
}

/// The result of recording a wrong email-OTP guess (issue #68).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAttemptOutcome {
    /// The code survives; more attempts remain.
    Survived,
    /// The code died (the budget is spent) and was invalidated.
    Died,
    /// The code was already gone (a race consumed or expired it).
    Gone,
}

/// The specification for issuing a scanner-safe magic link (issue #68): the freshly
/// minted `mlk_` id, the subject and purpose it binds, the one-way token digest, the
/// one-way short-code hash, the same-device binding digest, the recipient address, and
/// the TTL horizon.
#[derive(Debug)]
pub struct NewMagicLink<'a> {
    /// The freshly minted `mlk_` id (the row's primary key, audit target, and the
    /// routing handle embedded in the token wire form).
    pub id: &'a MagicLinkTokenId,
    /// The subject (a `usr_` id) the link belongs to.
    pub subject: &'a UserId,
    /// The flow the link authorizes.
    pub purpose: EmailFactorPurpose,
    /// The SHA-256 digest of the emitted bearer token (issue #29). Never plaintext.
    pub token_digest: &'a str,
    /// The Argon2id PHC verifier of the printed cross-device short code (issue #62).
    pub short_code_hash: &'a str,
    /// The SHA-256 digest of the same-device binding secret (set as a cookie).
    pub binding_digest: &'a str,
    /// The recipient email; sealed and blind-indexed on write (issue #48).
    pub recipient_email: &'a str,
    /// The TTL horizon in Unix microseconds (the clock seam drives it).
    pub expires_at_unix_micros: i64,
}

/// An active (unconsumed, unexpired) magic-link challenge resolved for the cross-device
/// short-code path (issue #68): the id to consume and the one-way short-code hash the
/// caller verifies through the hashing pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicLinkChallenge {
    /// The `mlk_` id to consume once the short code verifies.
    pub id: MagicLinkTokenId,
    /// The subject (a `usr_` id string) the link belongs to.
    pub subject: String,
    /// The flow the link authorizes.
    pub purpose: EmailFactorPurpose,
    /// The Argon2id PHC verifier to compare the presented short code against.
    pub short_code_hash: String,
}

/// The result of consuming a magic link single-use (issue #68).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicLinkConsumeOutcome {
    /// The link was consumed; a session should be established for this subject.
    Consumed {
        /// The subject (a `usr_` id string) to establish a session for.
        subject: String,
        /// The flow the link authorized.
        purpose: EmailFactorPurpose,
    },
    /// No active link matched (forged, expired, already consumed, or the same-device
    /// binding did not match): the uniform, non-enumerating not-found.
    NotFound,
}
