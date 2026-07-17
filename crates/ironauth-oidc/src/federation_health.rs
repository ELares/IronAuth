// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-connector health tracking and health-driven backoff for the federation
//! runtime (issue #76).
//!
//! The failure-isolation contract: a broken upstream degrades EXACTLY its own
//! connector while every other connector and the core OP surface keep serving. This
//! module is the small in-memory health record that makes that true and diagnosable.
//! It records, per connector id:
//!
//! - the coarse [`HealthState`] (never exercised, healthy, config-broken, or upstream
//!   unavailable);
//! - the recent upstream error rate over the configured probe window, and the last
//!   success / last failure instants (all via the injected clock seam, never the process
//!   wall clock directly);
//! - a health-driven backoff so a DEAD upstream is not hammered (probe again only after
//!   an exponentially growing, capped window) while a TRANSIENTLY-down one is retried and
//!   recovers, and a CONFIG-broken connector stays failed until it is RECONFIGURED.
//!
//! The classification comes straight from the #75 [`ConnectorError`] taxonomy:
//! [`ConnectorError::Config`] is PERMANENT (until the definition changes),
//! [`ConnectorError::UpstreamUnavailable`] is TRANSIENT (retried with backoff), and
//! [`ConnectorError::UpstreamProtocol`] is a per-request fault that feeds the error rate
//! but never trips the connector into a hard-down state.
//!
//! A connector RECONFIGURATION is detected by a FINGERPRINT (the store row's
//! `updated_at` micros): a changed fingerprint RESETS that connector's record, so a
//! reconfigured connector is retried immediately and, crucially, so a reconfig of one
//! connector never touches another's record. The whole registry is keyed by connector
//! id, so no connector's health can disturb a sibling's.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use ironauth_connector::ConnectorError;

/// The connector-labeled gauge that is `1` while a connector is healthy and `0`
/// otherwise (never exercised, config-broken, or upstream-unavailable). The `kind`
/// of a non-healthy state is carried by [`CONNECTOR_UPSTREAM_ERROR_TOTAL`].
pub const CONNECTOR_HEALTHY: &str = "ironauth_connector_healthy";

/// The connector-labeled count of upstream operations that SUCCEEDED (a resolved
/// discovery / JWKS and a validated login leg).
pub const CONNECTOR_UPSTREAM_SUCCESS_TOTAL: &str = "ironauth_connector_upstream_success_total";

/// The connector-labeled, kind-labeled count of upstream operation FAILURES. `kind`
/// is the stable [`ConnectorError::kind`] label (`config` / `upstream_protocol` /
/// `upstream_unavailable`), so an operator can tell a permanent misconfiguration from a
/// transient outage from the series alone.
pub const CONNECTOR_UPSTREAM_ERROR_TOTAL: &str = "ironauth_connector_upstream_error_total";

/// Register the per-connector health metric descriptions (issue #76), mirroring the
/// platform's other `describe_*_metrics` seams. Safe to call after the recorder is
/// installed; a no-op with no recorder.
pub fn describe_connector_health_metrics() {
    metrics::describe_gauge!(
        CONNECTOR_HEALTHY,
        "1 while a federation connector is healthy, 0 while it is unexercised, \
         config-broken, or its upstream is unavailable (labeled by connector)"
    );
    metrics::describe_counter!(
        CONNECTOR_UPSTREAM_SUCCESS_TOTAL,
        "Successful federation upstream operations, labeled by connector"
    );
    metrics::describe_counter!(
        CONNECTOR_UPSTREAM_ERROR_TOTAL,
        "Failed federation upstream operations, labeled by connector and error kind \
         (config/upstream_protocol/upstream_unavailable)"
    );
}

/// The coarse health state of a single connector (issue #76).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// No upstream operation has been attempted yet: the connector is admitted (it is
    /// not KNOWN broken), but nothing is asserted about its upstream.
    Unknown,
    /// The last upstream operation succeeded.
    Healthy,
    /// The connector DEFINITION is broken ([`ConnectorError::Config`]): permanent until
    /// the connector is reconfigured (a fingerprint change resets it).
    ConfigError,
    /// The upstream is unavailable ([`ConnectorError::UpstreamUnavailable`]): transient,
    /// retried after the health-driven backoff window.
    Unavailable,
}

impl HealthState {
    /// The stable wire string for the management-API health read and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HealthState::Unknown => "unknown",
            HealthState::Healthy => "healthy",
            HealthState::ConfigError => "config_error",
            HealthState::Unavailable => "unavailable",
        }
    }

    /// The `ironauth_connector_healthy` gauge value: `1.0` only when healthy.
    fn gauge_value(self) -> f64 {
        f64::from(u8::from(self == HealthState::Healthy))
    }
}

/// Whether a connector operation is admitted, or denied by the health layer without
/// touching the upstream (issue #76).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Attempt the upstream operation. Either the connector is healthy / unknown, or a backoff
    /// window has elapsed so the first request(s) after it may probe. The probe is NOT serialized:
    /// concurrent authorizes crossing the backoff boundary are all admitted (a small, self-limiting
    /// thundering herd against a recovering upstream), not gated to exactly one in-flight probe.
    Allow,
    /// Do NOT touch the upstream; surface a typed connector-unavailable error. The
    /// reason distinguishes a permanent config fault from a transient backoff.
    Deny(DenyReason),
}

/// Why the health layer denied a connector operation (issue #76). Both map to a typed
/// connector-unavailable response, but the reason is diagnosable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The connector definition is broken; it stays failed until reconfigured.
    Config,
    /// The upstream is unavailable and still inside its backoff window.
    Backoff,
}

impl DenyReason {
    /// The stable label surfaced on the typed connector-unavailable response.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::Config => "config",
            DenyReason::Backoff => "upstream_unavailable",
        }
    }
}

/// The maximum number of consecutive failures the exponential backoff shift honors, so
/// the window is `probe_window * 2^min(failures-1, SHIFT_CAP)` and can never overflow.
const BACKOFF_SHIFT_CAP: u32 = 6;

/// The hard cap on distinct connectors tracked in the registry MAP, bounding its memory
/// (connectors are operator-provisioned store rows, already bounded, but this fails safe against a
/// runaway). Beyond the cap a new connector is admitted UNTRACKED (folded onto a reserved overflow
/// slot), never blocked -- so the failure-isolation layer FAILS OPEN past the cap.
///
/// Note this bounds the MAP, not the exported metric-label cardinality: [`emit_metrics`] always
/// labels with the connector's REAL id, so the `connector` label set is bounded by how many
/// connectors an operator actually provisions and exercises, independent of this cap.
const MAX_TRACKED_CONNECTORS: usize = 4096;

/// One connector's mutable health record.
#[derive(Debug, Clone)]
struct Record {
    /// The connector-definition fingerprint (the store row `updated_at` micros); a
    /// change means a RECONFIGURATION, which resets the record.
    fingerprint: i64,
    state: HealthState,
    consecutive_failures: u32,
    last_error_kind: Option<&'static str>,
    last_success_at: Option<SystemTime>,
    last_failure_at: Option<SystemTime>,
    /// When a backoff-denied connector may be probed again (only in [`HealthState::Unavailable`]).
    next_retry_at: Option<SystemTime>,
    success_total: u64,
    error_total: u64,
    /// The rolling error-rate window: its start instant and the attempt / error counts
    /// within it. Reset when the probe window elapses.
    window_start: SystemTime,
    window_attempts: u32,
    window_errors: u32,
}

impl Record {
    fn fresh(now: SystemTime, fingerprint: i64) -> Self {
        Self {
            fingerprint,
            state: HealthState::Unknown,
            consecutive_failures: 0,
            last_error_kind: None,
            last_success_at: None,
            last_failure_at: None,
            next_retry_at: None,
            success_total: 0,
            error_total: 0,
            window_start: now,
            window_attempts: 0,
            window_errors: 0,
        }
    }

    /// Advance the rolling error-rate window, resetting it when the probe window elapsed.
    fn roll_window(&mut self, now: SystemTime, probe_window: Duration) {
        let elapsed = now
            .duration_since(self.window_start)
            .unwrap_or(Duration::ZERO);
        if elapsed >= probe_window {
            self.window_start = now;
            self.window_attempts = 0;
            self.window_errors = 0;
        }
    }
}

/// A read-only snapshot of one connector's health, for the management-API diagnostics
/// read and tests (issue #76).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorHealthSnapshot {
    /// The coarse health state.
    pub state: HealthState,
    /// The stable kind of the last error, if any (`config` / `upstream_protocol` /
    /// `upstream_unavailable`).
    pub last_error_kind: Option<&'static str>,
    /// The number of consecutive upstream failures (0 while healthy).
    pub consecutive_failures: u32,
    /// The last successful upstream operation instant, if any.
    pub last_success_at: Option<SystemTime>,
    /// The last upstream failure instant, if any.
    pub last_failure_at: Option<SystemTime>,
    /// When a backed-off connector may be probed again, if it is in backoff.
    pub next_retry_at: Option<SystemTime>,
    /// The recent upstream error rate over the probe window, in `0.0..=1.0`.
    pub recent_error_rate: f64,
    /// The lifetime count of successful upstream operations.
    pub success_total: u64,
    /// The lifetime count of failed upstream operations.
    pub error_total: u64,
}

/// The per-connector health registry (issue #76): a bounded, in-memory, clock-driven
/// map keyed by connector id. Shared (behind an [`std::sync::Arc`]) between the
/// federation runtime that records into it and the management-API read that snapshots it.
#[derive(Debug)]
pub struct ConnectorHealthRegistry {
    probe_window: Duration,
    records: Mutex<HashMap<String, Record>>,
}

impl ConnectorHealthRegistry {
    /// A registry whose backoff / error-rate window base is `probe_window`.
    #[must_use]
    pub fn new(probe_window: Duration) -> Self {
        Self {
            probe_window: probe_window.max(Duration::from_secs(1)),
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Decide whether a connector operation may touch the upstream, WITHOUT recording
    /// anything (issue #76). A config-broken connector is denied permanently (until its
    /// fingerprint changes); an unavailable one is denied until its backoff window
    /// elapses, then admitted as a probe (the first request(s) after the window; the probe is
    /// not serialized to exactly one in-flight request).
    ///
    /// `fingerprint` is the connector-definition version (the store row `updated_at`
    /// micros): a change resets the record so a RECONFIGURED connector is retried at once.
    #[must_use]
    pub fn admit(&self, now: SystemTime, connector_id: &str, fingerprint: i64) -> Admission {
        let records = self.lock();
        let Some(record) = records.get(connector_id) else {
            return Admission::Allow;
        };
        // A reconfiguration (changed fingerprint) clears any prior verdict.
        if record.fingerprint != fingerprint {
            return Admission::Allow;
        }
        match record.state {
            HealthState::Unknown | HealthState::Healthy => Admission::Allow,
            HealthState::ConfigError => Admission::Deny(DenyReason::Config),
            HealthState::Unavailable => match record.next_retry_at {
                Some(retry_at) if now < retry_at => Admission::Deny(DenyReason::Backoff),
                _ => Admission::Allow,
            },
        }
    }

    /// Record a successful upstream operation for `connector_id`, clearing any prior
    /// failure state (issue #76).
    pub fn record_success(&self, now: SystemTime, connector_id: &str, fingerprint: i64) {
        let mut records = self.lock();
        let record = Self::entry(&mut records, now, connector_id, fingerprint);
        record.roll_window(now, self.probe_window);
        record.window_attempts = record.window_attempts.saturating_add(1);
        record.state = HealthState::Healthy;
        record.consecutive_failures = 0;
        record.next_retry_at = None;
        record.last_success_at = Some(now);
        record.success_total = record.success_total.saturating_add(1);
        let state = record.state;
        drop(records);
        emit_metrics(connector_id, state, None);
    }

    /// Record a failed upstream operation for `connector_id`, classified by the #75
    /// error taxonomy (issue #76): a [`ConnectorError::Config`] fault trips the connector
    /// into the PERMANENT config-broken state; a [`ConnectorError::UpstreamUnavailable`]
    /// fault trips it UNAVAILABLE and arms the exponential backoff; a
    /// [`ConnectorError::UpstreamProtocol`] fault feeds the error rate and counters but
    /// leaves admission unchanged (a per-request fault, not a connector-down signal).
    pub fn record_failure(
        &self,
        now: SystemTime,
        connector_id: &str,
        fingerprint: i64,
        error: &ConnectorError,
    ) {
        let kind = error.kind();
        let mut records = self.lock();
        let probe_window = self.probe_window;
        let record = Self::entry(&mut records, now, connector_id, fingerprint);
        record.roll_window(now, probe_window);
        record.window_attempts = record.window_attempts.saturating_add(1);
        record.window_errors = record.window_errors.saturating_add(1);
        record.last_error_kind = Some(kind);
        record.last_failure_at = Some(now);
        record.error_total = record.error_total.saturating_add(1);

        match error {
            ConnectorError::Config(_) => {
                record.state = HealthState::ConfigError;
                record.consecutive_failures = record.consecutive_failures.saturating_add(1);
                record.next_retry_at = None;
            }
            ConnectorError::UpstreamUnavailable(_) => {
                record.state = HealthState::Unavailable;
                record.consecutive_failures = record.consecutive_failures.saturating_add(1);
                let shift = (record.consecutive_failures.saturating_sub(1)).min(BACKOFF_SHIFT_CAP);
                let backoff = probe_window.saturating_mul(1_u32 << shift);
                record.next_retry_at = Some(now.checked_add(backoff).unwrap_or(now));
            }
            // A per-request upstream-protocol fault (a bad token, a mix-up-checked issuer
            // mismatch): it feeds the error rate and counters above, but does not trip the
            // connector into a hard-down state (do not blacklist a connector for one bad
            // token). It also never clears a healthy state to "down".
            _ => {}
        }
        let state = record.state;
        drop(records);
        emit_metrics(connector_id, state, Some(kind));
    }

    /// A read-only snapshot of one connector's health for the management-API read, or [`None`]
    /// when the connector has never been exercised OR its record predates the current
    /// `fingerprint` (issue #76).
    ///
    /// `fingerprint` is the connector-definition version (the store row `updated_at` micros), the
    /// SAME value the record- and admit- paths key on. A record whose fingerprint differs is
    /// STALE: it describes the connector BEFORE a reconfiguration, so reporting it would surface a
    /// stale `config_error` (or a stale backoff) for a definition that has since changed. Treating
    /// a fingerprint mismatch as never-exercised makes the health read reflect the reconfiguration
    /// promptly (the handler renders it as `unknown` until the new definition is next exercised),
    /// exactly mirroring how [`ConnectorHealthRegistry::admit`] resets a reconfigured connector.
    #[must_use]
    pub fn snapshot(
        &self,
        now: SystemTime,
        connector_id: &str,
        fingerprint: i64,
    ) -> Option<ConnectorHealthSnapshot> {
        let records = self.lock();
        let record = records.get(connector_id)?;
        // A reconfiguration (changed fingerprint) voids the stale record for the read.
        if record.fingerprint != fingerprint {
            return None;
        }
        // The error rate reflects the CURRENT window: an elapsed window reads as zero
        // recent errors without mutating the record on a read.
        let window_fresh = now
            .duration_since(record.window_start)
            .unwrap_or(Duration::ZERO)
            < self.probe_window;
        let recent_error_rate = if window_fresh && record.window_attempts > 0 {
            f64::from(record.window_errors) / f64::from(record.window_attempts)
        } else {
            0.0
        };
        Some(ConnectorHealthSnapshot {
            state: record.state,
            last_error_kind: record.last_error_kind,
            consecutive_failures: record.consecutive_failures,
            last_success_at: record.last_success_at,
            last_failure_at: record.last_failure_at,
            next_retry_at: record.next_retry_at,
            recent_error_rate,
            success_total: record.success_total,
            error_total: record.error_total,
        })
    }

    /// Get or insert the record for `connector_id`, resetting it on a fingerprint change
    /// (a reconfiguration) and enforcing the cardinality bound. Returns the existing
    /// record when the map is full and the connector is new (untracked, admitted).
    fn entry<'a>(
        records: &'a mut HashMap<String, Record>,
        now: SystemTime,
        connector_id: &str,
        fingerprint: i64,
    ) -> &'a mut Record {
        if let Some(existing) = records.get(connector_id) {
            if existing.fingerprint != fingerprint {
                records.insert(connector_id.to_owned(), Record::fresh(now, fingerprint));
            }
        } else if records.len() < MAX_TRACKED_CONNECTORS {
            records.insert(connector_id.to_owned(), Record::fresh(now, fingerprint));
        } else {
            // The map is full: reuse an arbitrary slot's identity is unsafe, so instead
            // return a transient record kept under a reserved key. We never block on the
            // cap; the connector is simply admitted without long-lived tracking.
            records
                .entry(String::new())
                .or_insert_with(|| Record::fresh(now, fingerprint));
            return records.get_mut("").expect("reserved overflow record");
        }
        records
            .get_mut(connector_id)
            .expect("record present after insert")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Record>> {
        self.records
            .lock()
            .expect("connector health registry lock poisoned")
    }
}

/// Emit the connector-labeled health metrics for a state transition (issue #76). The
/// connector id is an operator-provisioned, bounded label value (one per environment),
/// exactly the bounded-cardinality shape the exposition plane requires.
fn emit_metrics(connector_id: &str, state: HealthState, error_kind: Option<&'static str>) {
    let connector = connector_id.to_owned();
    metrics::gauge!(CONNECTOR_HEALTHY, "connector" => connector.clone()).set(state.gauge_value());
    match error_kind {
        Some(kind) => {
            metrics::counter!(
                CONNECTOR_UPSTREAM_ERROR_TOTAL,
                "connector" => connector,
                "kind" => kind,
            )
            .increment(1);
        }
        None => {
            metrics::counter!(CONNECTOR_UPSTREAM_SUCCESS_TOTAL, "connector" => connector)
                .increment(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: &str = "cnr_test";
    const FP: i64 = 1_000;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn registry() -> ConnectorHealthRegistry {
        ConnectorHealthRegistry::new(Duration::from_secs(30))
    }

    #[test]
    fn an_unexercised_connector_is_admitted_and_has_no_snapshot() {
        let reg = registry();
        assert_eq!(reg.admit(at(0), CID, FP), Admission::Allow);
        assert!(reg.snapshot(at(0), CID, FP).is_none());
    }

    #[test]
    fn a_success_marks_the_connector_healthy_and_admitted() {
        let reg = registry();
        reg.record_success(at(0), CID, FP);
        assert_eq!(reg.admit(at(0), CID, FP), Admission::Allow);
        let snap = reg.snapshot(at(0), CID, FP).expect("snapshot");
        assert_eq!(snap.state, HealthState::Healthy);
        assert_eq!(snap.success_total, 1);
        assert_eq!(snap.consecutive_failures, 0);
        assert_eq!(snap.last_success_at, Some(at(0)));
    }

    #[test]
    fn a_config_error_stays_failed_until_reconfigured() {
        // A config-broken connector is denied PERMANENTLY: no elapsed time re-admits it.
        let reg = registry();
        reg.record_failure(
            at(0),
            CID,
            FP,
            &ConnectorError::Config("bad url".to_owned()),
        );
        assert_eq!(
            reg.admit(at(0), CID, FP),
            Admission::Deny(DenyReason::Config)
        );
        assert_eq!(
            reg.admit(at(1_000_000), CID, FP),
            Admission::Deny(DenyReason::Config),
            "no backoff elapses a config fault"
        );
        let snap = reg.snapshot(at(0), CID, FP).expect("snapshot");
        assert_eq!(snap.state, HealthState::ConfigError);
        assert_eq!(snap.last_error_kind, Some("config"));

        // A RECONFIGURATION (new fingerprint) resets the verdict: the connector is retried.
        let reconfigured = FP + 1;
        assert_eq!(reg.admit(at(0), CID, reconfigured), Admission::Allow);
    }

    #[test]
    fn an_unavailable_upstream_is_retried_with_growing_backoff() {
        // The clock is injected: an unavailable upstream is denied inside the backoff
        // window and re-admitted once it elapses (do not hammer a dead upstream; do not
        // permanently blacklist a transiently-down one).
        let reg = registry(); // probe window = 30s
        reg.record_failure(
            at(0),
            CID,
            FP,
            &ConnectorError::UpstreamUnavailable("timeout".to_owned()),
        );
        // First failure: base window (30s). Denied at t=10s, admitted at t=30s.
        assert_eq!(
            reg.admit(at(10), CID, FP),
            Admission::Deny(DenyReason::Backoff)
        );
        assert_eq!(reg.admit(at(30), CID, FP), Admission::Allow);

        // A second consecutive failure at t=30 doubles the window to 60s: denied at t=60,
        // admitted at t=90.
        reg.record_failure(
            at(30),
            CID,
            FP,
            &ConnectorError::UpstreamUnavailable("timeout".to_owned()),
        );
        assert_eq!(
            reg.admit(at(60), CID, FP),
            Admission::Deny(DenyReason::Backoff)
        );
        assert_eq!(reg.admit(at(90), CID, FP), Admission::Allow);

        // A success clears the backoff and marks it healthy again.
        reg.record_success(at(90), CID, FP);
        assert_eq!(reg.admit(at(90), CID, FP), Admission::Allow);
        let snap = reg.snapshot(at(90), CID, FP).expect("snapshot");
        assert_eq!(snap.state, HealthState::Healthy);
        assert_eq!(snap.consecutive_failures, 0);
    }

    #[test]
    fn an_upstream_protocol_fault_feeds_the_error_rate_but_does_not_blacklist() {
        // A per-request protocol fault (a bad token) counts toward the error rate but never
        // trips the connector into a hard-down / denied state.
        let reg = registry();
        reg.record_success(at(0), CID, FP);
        reg.record_failure(
            at(1),
            CID,
            FP,
            &ConnectorError::UpstreamProtocol("bad nonce".to_owned()),
        );
        assert_eq!(
            reg.admit(at(1), CID, FP),
            Admission::Allow,
            "a protocol fault never denies the connector"
        );
        let snap = reg.snapshot(at(1), CID, FP).expect("snapshot");
        assert_eq!(snap.error_total, 1);
        assert_eq!(snap.last_error_kind, Some("upstream_protocol"));
        // One error out of two attempts in the window.
        assert!((snap.recent_error_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn the_error_rate_window_resets_after_the_probe_window() {
        let reg = registry(); // 30s window
        reg.record_failure(
            at(0),
            CID,
            FP,
            &ConnectorError::UpstreamProtocol("x".to_owned()),
        );
        let snap = reg.snapshot(at(0), CID, FP).expect("snapshot");
        assert!((snap.recent_error_rate - 1.0).abs() < f64::EPSILON);
        // Past the probe window with no new activity, the recent rate reads as zero.
        let snap = reg.snapshot(at(31), CID, FP).expect("snapshot");
        assert!(snap.recent_error_rate.abs() < f64::EPSILON);
    }

    #[test]
    fn a_snapshot_under_a_new_fingerprint_reads_as_never_exercised() {
        // The health READ accounts for the fingerprint (issue #76 review LOW): a record left by
        // the OLD definition is voided for a read under a NEW fingerprint, so a reconfigured
        // connector does not report a stale config_error until its next login.
        let reg = registry();
        reg.record_failure(
            at(0),
            CID,
            FP,
            &ConnectorError::Config("bad url".to_owned()),
        );
        assert_eq!(
            reg.snapshot(at(0), CID, FP).expect("snapshot").state,
            HealthState::ConfigError,
            "the current-fingerprint read still reports the recorded state"
        );
        assert!(
            reg.snapshot(at(0), CID, FP + 1).is_none(),
            "a reconfiguration (new fingerprint) voids the stale record for the read"
        );
    }

    #[test]
    fn a_reconfiguration_resets_health_and_never_touches_a_sibling() {
        let reg = registry();
        // Connector A goes config-broken; connector B is healthy.
        reg.record_failure(at(0), "cnr_a", 1, &ConnectorError::Config("bad".to_owned()));
        reg.record_success(at(0), "cnr_b", 9);
        assert_eq!(
            reg.admit(at(0), "cnr_a", 1),
            Admission::Deny(DenyReason::Config)
        );
        // Reconfiguring A (new fingerprint) resets ONLY A; B is untouched.
        assert_eq!(reg.admit(at(0), "cnr_a", 2), Admission::Allow);
        assert_eq!(reg.admit(at(0), "cnr_b", 9), Admission::Allow);
        assert_eq!(
            reg.snapshot(at(0), "cnr_b", 9).expect("b snapshot").state,
            HealthState::Healthy,
            "a sibling's health is never disturbed by another's reconfiguration"
        );
    }
}
