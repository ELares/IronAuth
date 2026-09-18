// SPDX-License-Identifier: MIT OR Apache-2.0

//! Apply stored per-scope quota overrides to the running enforcer (issue #150 criterion 4).
//!
//! # The layer that had no consumer
//!
//! The overrides table has existed since migration 0229, with `QuotaLimitsRepo` reading and
//! writing it and a suite covering both. Nothing outside that suite ever called it, and
//! `QuotaEnforcer::set_environment_override` had no production caller either: its own doc
//! comment says "overriding is how the management plane (wired in M15) adjusts a tenant's
//! quota". So a row could be written and would change nothing, on any node, for ever.
//!
//! This is the reader that closes the gap. It runs on a tick rather than on a notification,
//! which is the SLO the criterion asks about: an override takes effect on every node within one
//! refresh interval of the write committing.
//!
//! # Why a poll, stated rather than apologised for
//!
//! Issue #147's own criteria treat polling as the baseline that a bus must beat ("IronBus mode
//! measurably reduces propagation latency versus polling"), and Postgres-only mode is a
//! supported deployment there. A poll needs no bus, no cross-node connection and no delivery
//! guarantee: every node reaches the same rows and converges, and a node that was down for an
//! hour is correct one interval after it comes back rather than having missed a notification.
//!
//! # An absent row is an instruction, not silence
//!
//! The pass clears the override for a scope with no rows. That asymmetry is the whole
//! correctness argument: if a refresh only applied what it found, a DELETE through the
//! management API would change the table and leave every node enforcing the old limit until it
//! restarted, which is precisely the "without restart" the criterion names.

use std::sync::Arc;

use ironauth_quota::{EnvironmentId, Limit, QuotaDimension, QuotaEnforcer, ScopeLimits, TenantId};
use ironauth_store::outbox::ScopeSource;
use ironauth_store::{Scope, Store, StoreError};

/// What one refresh pass did, for the caller's log line and for a test to assert on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Refreshed {
    /// Scopes whose stored overrides were applied.
    pub applied: usize,
    /// Scopes with no stored override, whose runtime override was cleared.
    pub cleared: usize,
    /// Rows naming a dimension this build does not have.
    ///
    /// NOT AN ERROR, and reported rather than swallowed for the same reason the store reads the
    /// label as text: during a rolling upgrade a newer node writes a dimension an older one
    /// cannot name, and the older one must keep applying the rest. A count that stays non-zero
    /// outside an upgrade means the two ends have diverged.
    pub unknown_dimensions: usize,
}

/// Apply every scope's stored overrides to `enforcer`, and clear the ones with no rows.
///
/// # Errors
///
/// [`StoreError`] if a scope's overrides cannot be read. The pass stops at the first failure and
/// the enforcer keeps the limits it already had, which is the safe direction: a database blip
/// must not widen or narrow anyone's quota as a side effect.
pub async fn refresh(
    store: &Store,
    scopes: &[Scope],
    enforcer: &Arc<QuotaEnforcer>,
) -> Result<Refreshed, StoreError> {
    let mut summary = Refreshed::default();
    for scope in scopes {
        let rows = store.scoped(*scope).quota_limits().all().await?;
        let tenant = TenantId::new(scope.tenant().to_string());
        let environment = EnvironmentId::new(scope.environment().to_string());
        if rows.is_empty() {
            enforcer.clear_environment_override(&tenant, &environment);
            summary.cleared += 1;
            continue;
        }
        let mut limits = ScopeLimits::default();
        for (label, stored) in rows {
            let Some(dimension) = QuotaDimension::parse(&label) else {
                summary.unknown_dimensions += 1;
                continue;
            };
            let limit = Limit::new(stored.refill_per_sec, stored.burst);
            match dimension {
                QuotaDimension::Requests => limits.requests = Some(limit),
                QuotaDimension::TokenIssuance => limits.token_issuance = Some(limit),
                QuotaDimension::HookSeconds => limits.hook_seconds = Some(limit),
                QuotaDimension::PasswordHashing => limits.password_hashing = Some(limit),
            }
        }
        enforcer.set_environment_override(&tenant, &environment, limits);
        summary.applied += 1;
    }
    Ok(summary)
}

/// Read the scopes to refresh from `scopes`, then refresh them.
///
/// Split from [`refresh`] so a test can drive an exact scope list, and so the caller's loop can
/// hold one source of scopes rather than re-deriving it. The source is the same
/// [`ScopeSource`] the outbox pools take, so a deployment enumerates its scopes once and every
/// per-scope sweep agrees about what exists.
///
/// # Errors
///
/// [`StoreError`] if the scope list or any scope's overrides cannot be read.
pub async fn refresh_all(
    store: &Store,
    scopes: &Arc<dyn ScopeSource>,
    enforcer: &Arc<QuotaEnforcer>,
) -> Result<Refreshed, StoreError> {
    let scopes = scopes.scopes().await?;
    refresh(store, &scopes, enforcer).await
}
