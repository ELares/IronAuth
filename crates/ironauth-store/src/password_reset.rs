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
