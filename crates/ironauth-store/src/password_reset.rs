// SPDX-License-Identifier: MIT OR Apache-2.0

//! Purpose-specific hosted password reset storage inputs, never login authority.

use crate::{ClientId, PasswordResetChallengeId, RecoveryFlowId, UserId};

/// Account and recovery case selected by the recovery subsystem. The store derives
/// the verified ownership revision and credential generation itself.
pub struct PasswordResetAccount<'a> {
    /// Resolved account, not a browser-supplied subject.
    pub subject: &'a UserId,
    /// Pending standard lost-password case for that same account.
    pub recovery: &'a RecoveryFlowId,
}

/// Server-derived policy for preparing or reusing a lost-password recovery case.
/// No Debug/serialization; cancellation input is only a high-entropy token digest.
pub struct PreparePasswordResetCase<'a> {
    /// Proposed fresh case ID, used only when no pending case can be reused.
    pub id: &'a RecoveryFlowId,
    /// Resolved subject, whose current eligibility is checked transactionally.
    pub subject: &'a UserId,
    /// Digest of a fresh cancellation token naming the proposed case ID.
    pub cancellation_token_digest: &'a [u8; 32],
    /// Required notified waiting period from current risk/factor policy; zero
    /// means no new delay. A previously required delay is never shortened.
    pub delay_micros: i64,
    /// Minimum interval between new recovery cases; resend has its own cooldown.
    pub cooldown_micros: i64,
}

/// A new browser-bound ceremony. No plaintext password, code or binding secret.
pub struct NewPasswordReset<'a> {
    /// Fresh scoped handle.
    pub id: &'a PasswordResetChallengeId,
    /// Client from the validated hosted authorization interaction.
    pub client: &'a ClientId,
    /// SHA-256 of a fresh high-entropy browser secret.
    pub browser_binding_hash: &'a [u8; 32],
    /// Validated local authorization continuation, retained only server-side.
    pub authorization_return_to: &'a str,
    /// None for the existence-uniform unknown/ineligible ceremony.
    pub account: Option<PasswordResetAccount<'a>>,
    /// Digest of a fresh high-entropy cancellation token for this account case.
    /// Required for a real account, absent for a decoy. Earlier links stay usable
    /// after code reissue or expiry while the recovery case remains pending.
    pub cancellation_token_digest: Option<&'a [u8; 32]>,
    /// Argon2id verifier computed through the admitted hashing pool.
    pub code_hash: &'a str,
    /// Expiry from Env, at most ten minutes after issuance.
    pub expires_at_unix_micros: i64,
}

/// Internal hashing input. Deliberately has no Debug or serialization support.
/// Reading this does not consume an attempt or authorize a credential mutation.
pub struct PasswordResetChallenge {
    /// Scoped handle checked again by the completion transaction.
    pub id: PasswordResetChallengeId,
    /// One-way verifier checked outside the database transaction.
    pub code_hash: String,
}

/// Internal presentation/audit context for the browser that started a reset.
/// No Debug or serialization: subject presence must never change the public
/// existence-uniform form. This metadata is not credential or session authority.
pub struct PasswordResetContext {
    /// Client retained at issuance, never recovered from a posted redirect.
    pub client: ClientId,
    /// Server-owned local authorization continuation.
    pub authorization_return_to: String,
    /// Original issuance time, for an existence-independent browser resend delay.
    pub created_at_unix_micros: i64,
    /// Exact expiry of the code; context may outlive it within the browser window.
    pub expires_at_unix_micros: i64,
    /// Store-bound subject for internal audit attribution, absent on decoys.
    pub subject: Option<UserId>,
}

/// One admitted code verification and policy-checked new password. The caller
/// verifies the code against `challenge.code_hash` through the hashing pool.
pub struct CompletePasswordReset<'a> {
    /// Immutable verifier snapshot used for the code comparison.
    pub challenge: &'a PasswordResetChallenge,
    /// Browser secret digest, never recovered from a posted account identifier.
    pub browser_binding_hash: &'a [u8; 32],
    /// Result of verifying the presented code against the exact snapshot.
    pub code_matched: bool,
    /// New normalized, screened and policy-checked Argon2id password verifier.
    pub new_password_hash: &'a str,
    /// Keyed digest of the exact normalized completion request, not a plain
    /// password digest. Stable across a retry even when Argon2 salts change.
    pub request_hash: &'a [u8; 32],
}

/// Already-verified browser/code proof for a read-only completion receipt check.
/// No password verifier or policy result is needed: this can only confirm an
/// earlier exact request, never perform or authorize a new password change.
pub struct PasswordResetReceipt<'a> {
    /// Exact verifier snapshot used by the admitted code check.
    pub challenge: &'a PasswordResetChallenge,
    /// Original browser-secret digest.
    pub browser_binding_hash: &'a [u8; 32],
    /// Result of verifying the presented code against the exact snapshot.
    pub code_matched: bool,
    /// Keyed digest of the exact normalized original completion request.
    pub request_hash: &'a [u8; 32],
}

/// Store completion outcome. No outcome creates an authentication session.
#[derive(Debug, PartialEq, Eq)]
pub enum PasswordResetOutcome {
    /// Uniform invalid, stale, exhausted, cancelled or expired authority.
    Refused,
    /// Correct proof cannot bypass the existing recovery delay.
    Held {
        /// Earliest eligible instant. A fresh code may be needed after the delay.
        until_unix_micros: i64,
    },
    /// Credential, proof, receipt, recovery state and invalidation committed.
    Completed {
        /// Validated server-owned continuation to ordinary authentication.
        authorization_return_to: String,
    },
    /// Same request already committed and its resulting credential is still current.
    Replayed {
        /// Same server-owned continuation; no new mutation or audit was emitted.
        authorization_return_to: String,
    },
}

/// Terminal result of one actual reset-mail attempt. Only acceptance of the code
/// and every required owner notice permits completion; uncertain mail is distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordResetDelivery {
    /// Code and all required notices were accepted by the configured transport.
    Accepted,
    /// At least one required send was refused before acceptance.
    Refused,
    /// At least one required acceptance could not be established.
    Uncertain,
}

impl PasswordResetDelivery {
    /// Stable storage tag, never a raw transport response.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Refused => "refused",
            Self::Uncertain => "uncertain",
        }
    }
}

/// Durable outbox consumer for code-free completed or cancelled reset warnings.
pub const PASSWORD_RESET_COMPLETION_CONSUMER: &str = "password-reset-completion";

/// The committed terminal recovery transition, with no recipient or secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordResetNoticeKind {
    /// The credential change committed.
    Completed,
    /// The recovery case was cancelled without changing the password.
    Cancelled,
}

/// A verified target for a terminal recovery owner warning.
/// No Debug/serialization; a missing recipient requires a recorded refusal.
pub struct PasswordResetCompletionNotice {
    /// The committed transition, never selected by an outbox payload.
    pub kind: PasswordResetNoticeKind,
    /// Account bound to the committed reset.
    pub subject: UserId,
    /// Still-current verified primary, absent if ownership is no longer eligible.
    pub recipient: Option<String>,
}

/// Metadata only, for resolving an interrupted terminal owner-notice attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordResetNoticeStatus {
    /// An external attempt may already have started; it cannot be repeated.
    pub started_at_unix_micros: Option<i64>,
    /// A terminal result, or None for work not yet durably confirmed.
    pub result: Option<PasswordResetDelivery>,
}
