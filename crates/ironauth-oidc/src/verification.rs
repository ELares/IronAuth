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

use ironauth_store::Scope;

/// Why a verification message would be sent (issue #64). Bound into the send so a future
/// transport (#68) can render the right template and a test can assert what was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPurpose {
    /// A registration verification (confirm a newly claimed identifier).
    Registration,
    /// An account-recovery message (a reset link / OTP).
    Recovery,
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
}

/// The default sender: it performs NO delivery (issue #64). The verification/OTP
/// transport is issue #68; until it is wired, a permitted send is a no-op, so the
/// user-visible acknowledgment is identical whether or not a message actually goes out.
#[derive(Debug, Default)]
pub struct NullVerificationSender;

impl VerificationSender for NullVerificationSender {
    fn send(&self, _scope: Scope, _purpose: VerificationPurpose, _recipient: &str) {
        // No transport yet (issue #68). Intentionally does nothing.
    }
}
