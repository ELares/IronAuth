// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public value types of the account-recovery state machine (issue #81): the
//! entry point a recovery started from, the state-machine position, the cancellation
//! reason, and the issue/resolve specs.
//!
//! Recovery is a DISTINCT, first-class flow, not a branch of password reset. The
//! three design pillars it encodes are DELAY as a security feature (a recovery that
//! would REDUCE account security is HELD for a configured delay before completing),
//! NOTIFICATION on every registered channel, and the invariant that recovery can
//! NEVER silently remove a factor STRONGER than the one used to recover. "Stronger"
//! is the issue #66 credential-ladder strength carried on `recover_acr`.
//!
//! The SQL that reads and writes these lives on the repositories in `repository.rs`
//! (the single scoped-table SQL module, enforced by `scripts/query-audit.sh`); this
//! module carries only the types the store's callers name.

use crate::id::{RecoveryFlowId, UserId};

/// What the user lost, the recovery entry point (issue #81). A closed set pinned by
/// the `recovery_flows.entry_point` CHECK and re-checked here on read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryEntryPoint {
    /// The user lost their password (but may still hold stronger factors).
    LostPassword,
    /// The user lost their second factor (an authenticator or its recovery codes).
    LostSecondFactor,
    /// The user lost every factor: the last-resort recovery.
    LostAllFactors,
}

impl RecoveryEntryPoint {
    /// The stable wire tag stored in the `entry_point` column and bound into the
    /// audit detail.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryEntryPoint::LostPassword => "lost_password",
            RecoveryEntryPoint::LostSecondFactor => "lost_second_factor",
            RecoveryEntryPoint::LostAllFactors => "lost_all_factors",
        }
    }

    /// Parse a stored wire tag back to the typed entry point. Returns [`None`] for
    /// any unknown value (a foreign or corrupted row is treated as a uniform skip).
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "lost_password" => Some(RecoveryEntryPoint::LostPassword),
            "lost_second_factor" => Some(RecoveryEntryPoint::LostSecondFactor),
            "lost_all_factors" => Some(RecoveryEntryPoint::LostAllFactors),
            _ => None,
        }
    }
}

/// The recovery state-machine position (issue #81). A closed set pinned by the
/// `recovery_flows.state` CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryState {
    /// The recovery began and can complete immediately (no security downgrade).
    Initiated,
    /// The recovery would REDUCE account security, so it is HELD for the configured
    /// delay before it can complete, cancellable throughout the window.
    Held,
    /// The recovery was cancelled (from a notification link or superseded); it can
    /// never complete.
    Cancelled,
    /// The recovery completed and restored access.
    Completed,
}

impl RecoveryState {
    /// The stable wire tag stored in the `state` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryState::Initiated => "initiated",
            RecoveryState::Held => "held",
            RecoveryState::Cancelled => "cancelled",
            RecoveryState::Completed => "completed",
        }
    }

    /// Parse a stored wire tag back to the typed state. Returns [`None`] for any
    /// unknown value.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "initiated" => Some(RecoveryState::Initiated),
            "held" => Some(RecoveryState::Held),
            "cancelled" => Some(RecoveryState::Cancelled),
            "completed" => Some(RecoveryState::Completed),
            _ => None,
        }
    }

    /// Whether a flow in this state is still PENDING (can be cancelled or completed):
    /// `initiated` or `held`. A cancelled or completed flow is terminal.
    #[must_use]
    pub fn is_pending(self) -> bool {
        matches!(self, RecoveryState::Initiated | RecoveryState::Held)
    }
}

/// Why a recovery flow was cancelled (issue #81). A closed set pinned by the
/// `recovery_flows.cancel_reason` CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryCancelReason {
    /// The user (or the account owner) cancelled it from a notification link: the
    /// "this was not me" path that stops an attacker-initiated recovery in its
    /// delay window.
    UserNotification,
    /// A newer recovery request superseded this one.
    Superseded,
}

impl RecoveryCancelReason {
    /// The stable wire tag stored in the `cancel_reason` column and audit detail.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryCancelReason::UserNotification => "user_notification",
            RecoveryCancelReason::Superseded => "superseded",
        }
    }
}

/// The specification for initiating a recovery flow (issue #81): the freshly minted
/// `rcv_` id, the subject it targets, the entry point, the recover-factor strength
/// (`acr`), the one-way cancellation-token digest, the recipient to seal, and the
/// optional delay-window horizon.
#[derive(Debug)]
pub struct NewRecoveryFlow<'a> {
    /// The freshly minted `rcv_` id (the row's primary key and audit target).
    pub id: &'a RecoveryFlowId,
    /// The subject (a `usr_` id) the recovery targets.
    pub subject: &'a UserId,
    /// The entry point the recovery started from.
    pub entry_point: RecoveryEntryPoint,
    /// The achieved `acr` (issue #66 credential-ladder strength) of the factor the
    /// recovery was performed with. The downgrade invariant compares a later factor
    /// removal against this.
    pub recover_acr: &'a str,
    /// The SHA-256 digest of the high-entropy cancellation token carried in the
    /// notification link. Never the token itself.
    pub cancel_token_digest: &'a [u8],
    /// The recipient/channel that initiated recovery; sealed under the scope DEK on
    /// write (issue #48).
    pub recipient: &'a str,
    /// The delay-window horizon in Unix microseconds, when a delay applies (the flow
    /// is `held` until this instant). [`None`] when the recovery can complete
    /// immediately (no security downgrade).
    pub hold_until_unix_micros: Option<i64>,
}

/// A recovery flow resolved for a status, cancellation, or downgrade-invariant check
/// (issue #81): the id, the subject it targets, the state-machine position, the entry
/// point, the recover-factor strength, and the delay/lifecycle timestamps (Unix
/// microseconds, so a caller compares them against the env clock seam).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryFlowRecord {
    /// The `rcv_` id of this flow.
    pub id: RecoveryFlowId,
    /// The subject (a `usr_` id string) the recovery targets.
    pub subject: String,
    /// The state-machine position.
    pub state: RecoveryState,
    /// The entry point the recovery started from.
    pub entry_point: RecoveryEntryPoint,
    /// The recover-factor strength (`acr`).
    pub recover_acr: String,
    /// When the recovery began, in Unix microseconds.
    pub initiated_at_unix_micros: i64,
    /// The delay-window horizon in Unix microseconds, when the flow is held. [`None`]
    /// when no delay applies.
    pub hold_until_unix_micros: Option<i64>,
}
