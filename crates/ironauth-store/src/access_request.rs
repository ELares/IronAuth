// SPDX-License-Identifier: MIT OR Apache-2.0

//! Time-boxed access requests with enforced requester/approver separation
//! (issue #145 criterion 4, EXPLORATORY).
//!
//! The types behind `access_grant_requests`. The table's own comments carry the reasoning;
//! what matters here is that the two invariants an auditor cares about are not this
//! module's to keep. Self-approval is refused by a CHECK constraint on every connection,
//! and an approved row without a deadline is refused by another, so a bug in this file
//! cannot produce a self-approved request or a grant that never ends.
//!
//! What this file IS responsible for is the read side: [`AccessGrantRequest::grants_now`]
//! decides whether a row confers access at an instant, and it answers no for a row past
//! its deadline whether or not the sweeper has got to it yet.

use serde::{Deserialize, Serialize};

/// Where a request is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestState {
    /// Raised, and nobody has decided.
    Pending,
    /// Approved, and granting until its deadline.
    Approved,
    /// Refused. Grants nothing and never did.
    Denied,
    /// Approved once, and its deadline has passed.
    Expired,
}

impl AccessRequestState {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Parse the stored spelling, or [`None`] for one this build does not know.
    ///
    /// [`None`] rather than a default: a state a NEWER binary wrote is one this one cannot
    /// classify, and guessing `approved` would grant access on a rollback while guessing
    /// `denied` would revoke it. The callers treat an unreadable row as absent.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// One request for time-boxed access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantRequest {
    /// The `agr_` identifier.
    pub id: String,
    /// Whose roles are at stake.
    pub organization_id: String,
    /// Who would receive the access. Not necessarily the requester.
    pub subject_id: String,
    /// Which role.
    pub role_slug: String,
    /// Who asked.
    pub requested_by: String,
    /// Why, in the requester's words.
    pub reason: String,
    /// Where it is in its life.
    pub state: AccessRequestState,
    /// Who decided, or [`None`] while pending.
    pub decided_by: Option<String>,
    /// When it was decided, in epoch micros.
    pub decided_at_micros: Option<i64>,
    /// When the granted access ends, in epoch micros.
    ///
    /// Present on an APPROVED row and kept on an EXPIRED one; absent on pending and
    /// denied, neither of which ever granted. The `granted_until_iff_granted` CHECK is what
    /// enforces that, not this sentence.
    pub granted_until_micros: Option<i64>,
    /// When it was raised, in epoch micros.
    pub created_at_micros: i64,
}

impl AccessGrantRequest {
    /// Whether this row confers access AT `now` (epoch micros).
    ///
    /// # Why the deadline is re-checked here
    ///
    /// A sweeper moves an elapsed approval to `expired`, and the listing reads better for
    /// it. But a sweeper is a process, and processes do not run: it may be stopped, its
    /// deployment may never have configured it, it may be mid-restart, or the row may have
    /// elapsed one second ago and the next pass is thirty seconds out. In every one of
    /// those the row still says `approved`.
    ///
    /// So the deadline decides, and the state only narrows it. A caller asking "may this
    /// person act" gets no for an elapsed grant whether or not anything has relabelled it,
    /// which means a sweeper that is not running cannot leak access. It can only leave the
    /// listing stale.
    #[must_use]
    pub fn grants_now(&self, now_micros: i64) -> bool {
        if self.state != AccessRequestState::Approved {
            return false;
        }
        // A missing deadline on an approved row is refused by the database, so this arm is
        // unreachable for a row this build wrote. Answering NO rather than unwrapping is
        // the safe reading of a row it did not: no access is the recoverable mistake.
        self.granted_until_micros
            .is_some_and(|until| now_micros < until)
    }
}

/// What a sweep pass reports.
///
/// A trait rather than a `tracing` call, because this crate takes no logging dependency and
/// the sibling `AuditRetentionObserver` made the same choice for the same reason: a store
/// that logged would decide the shape of an operator's logs from inside the data layer.
pub trait AccessRequestObserver: Send + Sync {
    /// A scope was swept. `swept` may be zero, which is the ordinary case.
    fn pass_completed(&self, scope: crate::Scope, swept: u64);
    /// One scope's pass failed. The others still run: the access in every scope has
    /// already ended on its own deadline, so a failed pass is a stale listing.
    fn pass_failed(&self, scope: crate::Scope, error: &crate::StoreError);
    /// The scope enumeration itself failed, so no scope was swept this pass.
    fn enumeration_failed(&self, error: &crate::StoreError);
}

/// The background pass that relabels elapsed grants (issue #145 criterion 4).
///
/// # What it is for, and what it is NOT for
///
/// It does not end access. [`AccessGrantRequest::grants_now`] already does, at the deadline,
/// with no process involved. What this keeps current is the RECORD: the listing stops
/// showing a grant that looks live, and an `access_request.expire` audit row marks when the
/// system noticed.
///
/// So a deployment that never starts it is not insecure, it is only out of date, and a
/// deployment whose pass is late is late about bookkeeping. That is the whole reason the
/// deadline check lives in the read path rather than here.
pub struct AccessRequestSweeper {
    handle: Option<tokio::task::JoinHandle<()>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// How many grants one pass relabels per scope.
///
/// Bounded so a backlog cannot hold one scope's transaction open across an unbounded number
/// of audited writes; the next pass takes the rest.
const SWEEP_BATCH: i64 = 200;

impl AccessRequestSweeper {
    /// Spawn the sweeper. Returns immediately; it runs until
    /// [`shutdown`](AccessRequestSweeper::shutdown) is awaited or it is dropped.
    #[must_use]
    pub fn spawn(
        store: crate::Store,
        env: ironauth_env::Env,
        actor: crate::ActorRef,
        scopes: std::sync::Arc<dyn crate::outbox::ScopeSource>,
        observer: std::sync::Arc<dyn AccessRequestObserver>,
        interval: std::time::Duration,
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
                            // scope's bounded pass rather than by the whole sweep.
                            if task_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let now = crate::repository::epoch_micros(env.clock().now_utc());
                            let outcome = store
                                .management()
                                .acting(actor, crate::CorrelationId::generate(&env))
                                .access_requests(scope)
                                .expire_elapsed(&env, now, SWEEP_BATCH)
                                .await;
                            match outcome {
                                Ok(swept) => observer.pass_completed(scope, swept),
                                // Reported rather than fatal: one scope failing must not
                                // stop the others being swept, and the access in every
                                // scope has already ended on its own deadline.
                                Err(error) => observer.pass_failed(scope, &error),
                            }
                        }
                    }
                    Err(error) => observer.enumeration_failed(&error),
                }
                // Slept in short slices so shutdown does not wait out a whole interval.
                let mut slept = std::time::Duration::ZERO;
                while slept < interval && !task_stop.load(Ordering::Relaxed) {
                    let slice =
                        std::time::Duration::from_millis(200).min(interval.saturating_sub(slept));
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

impl Drop for AccessRequestSweeper {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessGrantRequest, AccessRequestState};

    fn request(state: AccessRequestState, until: Option<i64>) -> AccessGrantRequest {
        AccessGrantRequest {
            id: "agr_1".to_owned(),
            organization_id: "org_1".to_owned(),
            subject_id: "usr_1".to_owned(),
            role_slug: "billing-admin".to_owned(),
            requested_by: "prn_asker".to_owned(),
            reason: "quarter close".to_owned(),
            state,
            decided_by: Some("prn_decider".to_owned()),
            decided_at_micros: Some(1_000),
            granted_until_micros: until,
            created_at_micros: 0,
        }
    }

    #[test]
    fn an_approved_grant_holds_until_its_deadline_and_not_at_it() {
        let row = request(AccessRequestState::Approved, Some(5_000));
        assert!(row.grants_now(4_999), "before the deadline it grants");
        // AT the instant, not after it: a half-open window is the only one where "granted
        // until T" and "expired at T" cannot both be true of the same instant.
        assert!(!row.grants_now(5_000), "at the deadline it has ended");
        assert!(!row.grants_now(5_001));
    }

    #[test]
    fn an_elapsed_grant_the_sweeper_has_not_reached_grants_nothing() {
        // THE POINT OF THE DOUBLE CHECK. The row still says `approved` because nothing has
        // relabelled it, and a reader trusting the state alone would let the holder act.
        let stale = request(AccessRequestState::Approved, Some(5_000));
        assert_eq!(stale.state, AccessRequestState::Approved);
        assert!(
            !stale.grants_now(9_999),
            "a stopped sweeper must leave the LISTING stale, never the ACCESS"
        );
    }

    #[test]
    fn no_other_state_grants_anything() {
        for state in [
            AccessRequestState::Pending,
            AccessRequestState::Denied,
            AccessRequestState::Expired,
        ] {
            let row = request(state, None);
            assert!(!row.grants_now(0), "{state:?} must grant nothing");
            // And not even with a live deadline attached, which the database refuses but a
            // rollback could present: the state is a necessary condition, not a hint.
            let row = request(state, Some(i64::MAX));
            assert!(
                !row.grants_now(0),
                "{state:?} with a deadline still grants nothing"
            );
        }
    }

    #[test]
    fn an_approved_row_with_no_deadline_grants_nothing() {
        // Refused by `access_grant_requests_granted_until_iff_granted`, so unreachable for
        // a row this build wrote. Asserted because the alternative reading of a row it did
        // not write -- treating a missing deadline as unbounded -- is the standing access
        // this whole primitive exists to replace.
        let row = request(AccessRequestState::Approved, None);
        assert!(!row.grants_now(0));
    }

    #[test]
    fn every_state_round_trips_through_the_wire() {
        for state in [
            AccessRequestState::Pending,
            AccessRequestState::Approved,
            AccessRequestState::Denied,
            AccessRequestState::Expired,
        ] {
            assert_eq!(AccessRequestState::from_wire(state.as_str()), Some(state));
        }
        assert_eq!(AccessRequestState::from_wire("revoked"), None);
    }
}
