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
