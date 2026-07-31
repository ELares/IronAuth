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

    /// Every purpose, in declaration order: the STRUCTURAL registry a caller (or a
    /// test sweep) enumerates so a purpose can never be silently skipped.
    ///
    /// A new variant added to [`EmailFactorPurpose`] makes [`Self::as_str`],
    /// [`Self::from_wire`], and [`Self::establishes_session`] fail to compile (each is
    /// an exhaustive match), and the length assertion in this module's tests fails
    /// until it is listed here too. A fixed-size array is the one thing the compiler
    /// does NOT check, so the test is the belt to that suspenders.
    pub const ALL: [EmailFactorPurpose; 5] = [
        EmailFactorPurpose::Login,
        EmailFactorPurpose::Register,
        EmailFactorPurpose::Mfa,
        EmailFactorPurpose::Recovery,
        EmailFactorPurpose::VerifyAddress,
    ];

    /// Whether a successful verify for this purpose establishes a PRIMARY login
    /// session (issue #70, generalized to every email-family factor by issue #267).
    ///
    /// `Login`, `Recovery`, and self-service `Register` mint a session: the one-time
    /// proof IS the primary authenticator for those flows, so each must additionally
    /// pass the no-silent-downgrade gate.
    ///
    /// `Mfa` and `VerifyAddress` are possession PROOFS that never mint a primary
    /// session. A second factor elevating an EXISTING session is the step-up flow
    /// (issue #72), and address verification proves control of an identifier without
    /// signing anyone in. Minting a primary session from an `mfa` code alone would
    /// silently claim a first factor that was never proven, so those purposes are
    /// never session-establishing on any factor.
    ///
    /// This lives on the shared purpose type deliberately: the SMS factor (issue #70)
    /// and the email family (issue #267) drive the SAME enum, and a second, private
    /// copy of this predicate per factor is exactly how they diverged in the first
    /// place.
    #[must_use]
    pub fn establishes_session(self) -> bool {
        match self {
            EmailFactorPurpose::Login
            | EmailFactorPurpose::Register
            | EmailFactorPurpose::Recovery => true,
            EmailFactorPurpose::Mfa | EmailFactorPurpose::VerifyAddress => false,
        }
    }
}

/// The per (tenant, environment) EMAIL-FACTOR configuration (issue #267): whether an
/// explicit factor-downgrade path is opted in for the email possession family (the
/// email OTP, the magic link, and the headless recovery journey that reuses the same
/// verify core).
///
/// Safe by default: a scope with NO row resolves to [`EmailFactorConfig::default`],
/// which refuses the downgrade, exactly as a scope with no `sms_config` row does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmailFactorConfig {
    /// Whether an email possession proof may mint a PRIMARY session for an account
    /// that already holds a stronger factor (a passkey or an active TOTP). False by
    /// default, including for every scope that has no row.
    pub allow_factor_downgrade: bool,
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
    /// The per-link cross-device SHORT-CODE wrong-guess budget; the link dies once its
    /// `attempt_count` reaches this. The high-entropy same-device token path is unbounded.
    pub max_attempts: i32,
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

#[cfg(test)]
mod tests {
    use super::EmailFactorPurpose;

    /// The [`EmailFactorPurpose::ALL`] registry must list EVERY variant. The compiler
    /// already forces the exhaustive matches (`as_str`, `from_wire`,
    /// `establishes_session`) to cover a new variant; it does NOT force a fixed-size
    /// array to grow, so a purpose added without being listed here would silently drop
    /// out of every sweep that iterates `ALL` (including the issue #267
    /// no-purpose-mints-a-session regression). The round trip through `from_wire`
    /// proves each listed entry is a distinct, wire-addressable purpose, so a
    /// duplicated placeholder cannot pad the array to the right length.
    #[test]
    fn the_purpose_registry_lists_every_variant_exactly_once() {
        let mut seen: Vec<&'static str> = EmailFactorPurpose::ALL
            .iter()
            .map(|purpose| purpose.as_str())
            .collect();
        let listed = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            listed,
            "EmailFactorPurpose::ALL must not repeat a purpose"
        );
        for purpose in EmailFactorPurpose::ALL {
            assert_eq!(
                EmailFactorPurpose::from_wire(purpose.as_str()),
                Some(purpose),
                "{} must round trip through the wire tag",
                purpose.as_str()
            );
        }
        // The count is asserted LAST so a missing variant reports as a count mismatch
        // rather than being masked by an earlier failure.
        assert_eq!(
            listed, 5,
            "EmailFactorPurpose::ALL must list every variant; update it and the \
             issue #267 sweep when a purpose is added"
        );
    }

    /// The session-establishing split (issue #70, generalized by issue #267). Pinned
    /// per purpose so a future edit that flips `mfa` or `verify_address` into a
    /// session-establishing purpose (the pre-#267 email-OTP behaviour, which let an
    /// `mfa` code alone mint a primary login) fails here rather than in production.
    #[test]
    fn only_the_primary_authenticator_purposes_establish_a_session() {
        assert!(EmailFactorPurpose::Login.establishes_session());
        assert!(EmailFactorPurpose::Recovery.establishes_session());
        assert!(EmailFactorPurpose::Register.establishes_session());
        assert!(
            !EmailFactorPurpose::Mfa.establishes_session(),
            "an mfa code is a possession proof, never a primary session"
        );
        assert!(
            !EmailFactorPurpose::VerifyAddress.establishes_session(),
            "address verification proves control without signing anyone in"
        );
    }
}
