// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-stream audit retention (issue #109).
//!
//! Two windows, one per stream, swept independently. That independence is the reason the
//! streams were separated at all: the admin trail answers "who changed this configuration"
//! and is usually kept for years, while the authentication trail answers "who signed in"
//! and is high volume and usually kept for months. A single window forces the short
//! requirement onto the long one or the long storage bill onto the short one.
//!
//! # The connection this runs on is not incidental
//!
//! [`AuditReaper`] must be built on a [`Store`] authenticated as `ironauth_audit_retention`.
//! It is the only role granted DELETE on the audit tables, and specifically it is the only
//! one that is NOT also granted INSERT: a role that can write an audit row and remove one
//! could erase a row and put another in its place, which is the tampering the log exists to
//! make evident. Migration 0136 carries the full argument. Passing a data-plane or
//! control-plane store here does not silently sweep less; it fails on the first DELETE.
//!
//! # A zero window means FOREVER
//!
//! Not "immediately". A zero that deleted everything would let an operator who enables the
//! sweeper before choosing a window destroy the trail with one line of configuration. The
//! failure mode of retention being off is a larger table; the failure mode of it being on
//! by accident is unrecoverable.

use std::time::Duration;

use ironauth_env::Env;

use crate::error::StoreError;
use crate::repository::epoch_micros_public;
use crate::scope::Scope;
use crate::store::Store;

/// The admin-action stream's wire name.
pub const ADMIN_ACTION_STREAM: &str = "admin_action";
/// The authentication stream's wire name.
pub const AUTHENTICATION_STREAM: &str = "authentication";

/// The windows this reaper runs to.
#[derive(Debug, Clone, Copy)]
pub struct AuditRetentionSettings {
    /// How long an admin-action row is kept. [`None`] is forever.
    pub admin_action: Option<Duration>,
    /// How long an authentication row is kept. [`None`] is forever.
    pub authentication: Option<Duration>,
    /// The most rows one pass removes from one stream in one scope.
    pub batch: i64,
}

/// What one pass removed, per stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditReapStats {
    /// Admin-action rows removed.
    pub admin_action_removed: u64,
    /// Authentication rows removed.
    pub authentication_removed: u64,
    /// Whether either stream hit the batch limit, meaning there is more to do and the
    /// next pass should not wait for the full interval to make progress.
    pub saturated: bool,
}

/// Sweeps expired audit rows to their per-stream windows.
pub struct AuditReaper {
    store: Store,
    env: Env,
    settings: AuditRetentionSettings,
}

impl AuditReaper {
    /// Build a reaper over `store`, which MUST authenticate as the retention role.
    #[must_use]
    pub fn new(store: Store, env: Env, settings: AuditRetentionSettings) -> Self {
        Self {
            store,
            env,
            settings,
        }
    }

    /// The windows this reaper runs to.
    #[must_use]
    pub fn settings(&self) -> AuditRetentionSettings {
        self.settings
    }

    /// Run ONE bounded pass over both streams in `scope`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a persistence fault, including the permission failure a caller
    /// gets for building this on any role but the retention one.
    pub async fn reap_once(&self, scope: Scope) -> Result<AuditReapStats, StoreError> {
        let now_micros = epoch_micros_public(self.env.clock().now_utc());
        let scoped = self.store.scoped(scope);
        let chain = scoped.audit_chain();
        let batch = self.settings.batch;

        let mut stats = AuditReapStats::default();
        for (stream, window) in [
            (ADMIN_ACTION_STREAM, self.settings.admin_action),
            (AUTHENTICATION_STREAM, self.settings.authentication),
        ] {
            // `None` is forever, so the stream is skipped entirely rather than swept to
            // a cutoff of now.
            let Some(window) = window else {
                continue;
            };
            let cutoff = cutoff_micros(now_micros, window);
            let report = chain.prune_before(stream, cutoff, batch).await?;
            if stream == ADMIN_ACTION_STREAM {
                stats.admin_action_removed = report.rows_removed;
            } else {
                stats.authentication_removed = report.rows_removed;
            }
            if u64::try_from(batch).is_ok_and(|batch| report.rows_removed >= batch) {
                stats.saturated = true;
            }
        }
        Ok(stats)
    }
}

/// `now` less `window`, in epoch microseconds, saturating rather than wrapping.
///
/// Saturating matters: a window longer than the current epoch offset would otherwise wrap
/// to a cutoff in the far future and sweep the whole table.
fn cutoff_micros(now_micros: i64, window: Duration) -> i64 {
    let micros = i64::try_from(window.as_micros()).unwrap_or(i64::MAX);
    now_micros.saturating_sub(micros)
}

/// Told what each retention pass did.
///
/// An observer rather than direct logging, matching the outbox reaper: this crate takes
/// no logging dependency, and a sweep that fails silently is the worst available outcome.
/// A permission failure here means the configured DSN is not the retention role, and an
/// operator has to be able to see that said.
pub trait AuditRetentionObserver: Send + Sync {
    /// A pass finished for `scope`.
    fn pass_completed(&self, scope: Scope, stats: AuditReapStats);
    /// A pass failed for `scope`.
    fn pass_failed(&self, scope: Scope, error: &StoreError);
    /// The scope enumeration itself failed, so no scope was swept this round.
    fn enumeration_failed(&self, error: &StoreError);
}

/// An observer that says nothing, for tests.
pub struct SilentAuditRetentionObserver;

impl AuditRetentionObserver for SilentAuditRetentionObserver {
    fn pass_completed(&self, _scope: Scope, _stats: AuditReapStats) {}
    fn pass_failed(&self, _scope: Scope, _error: &StoreError) {}
    fn enumeration_failed(&self, _error: &StoreError) {}
}

/// The background task that runs [`AuditReaper`] on an interval.
///
/// # Two roles, deliberately
///
/// Scope enumeration and deletion run on DIFFERENT connections here, which is the opposite
/// of the outbox sweeper's arrangement and for a reason that does not apply there. Listing
/// scopes reads `environments`, which only `ironauth_control` may read; deleting an audit
/// row needs `ironauth_audit_retention`, which is the only role granted DELETE and is
/// deliberately granted no INSERT. No single role can do both, and giving one role both
/// would dissolve exactly the separation migration 0136 exists to create.
pub struct AuditRetentionSweeper {
    handle: Option<tokio::task::JoinHandle<()>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl AuditRetentionSweeper {
    /// Spawn the sweeper. Returns immediately; it runs until
    /// [`shutdown`](AuditRetentionSweeper::shutdown) is awaited or it is dropped.
    #[must_use]
    pub fn spawn(
        reaper: AuditReaper,
        scopes: std::sync::Arc<dyn crate::outbox::ScopeSource>,
        observer: std::sync::Arc<dyn AuditRetentionObserver>,
        interval: Duration,
    ) -> Self {
        use std::sync::atomic::Ordering;

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_stop = std::sync::Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            while !task_stop.load(Ordering::Relaxed) {
                match scopes.scopes().await {
                    Ok(resolved) => {
                        for scope in resolved {
                            // Checked BETWEEN scopes, so a shutdown is bounded by one
                            // scope's bounded delete rather than by the whole pass.
                            if task_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            match reaper.reap_once(scope).await {
                                Ok(stats) => observer.pass_completed(scope, stats),
                                // Reported rather than fatal: one scope failing must not
                                // stop the others being swept.
                                Err(error) => observer.pass_failed(scope, &error),
                            }
                        }
                    }
                    Err(error) => observer.enumeration_failed(&error),
                }
                // Slept in short slices so shutdown does not wait out a whole interval.
                let mut slept = Duration::ZERO;
                while slept < interval && !task_stop.load(Ordering::Relaxed) {
                    let slice = Duration::from_millis(200).min(interval.saturating_sub(slept));
                    tokio::time::sleep(slice).await;
                    slept += slice;
                }
            }
        });
        Self {
            handle: Some(handle),
            stop,
        }
    }

    /// Stop the sweeper and wait for the in-flight pass to finish.
    pub async fn shutdown(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for AuditRetentionSweeper {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_longer_than_the_epoch_does_not_wrap_into_the_future() {
        let now = 1_700_000_000_000_000_i64;
        let cutoff = cutoff_micros(now, Duration::from_secs(u64::MAX / 2));
        assert!(
            cutoff < now,
            "an absurd window must saturate backwards, never ahead of now: {cutoff}"
        );
    }

    #[test]
    fn an_ordinary_window_subtracts_exactly() {
        let now = 1_700_000_000_000_000_i64;
        assert_eq!(
            cutoff_micros(now, Duration::from_secs(60)),
            now - 60_000_000
        );
    }
}
