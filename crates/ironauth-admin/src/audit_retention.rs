// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reporting the audit-retention policy this deployment enforces (issue #145 criterion 3).
//!
//! # Why a customer needs this from the API
//!
//! "How long do you keep our audit trail" is a question a SOC2 or ISO auditor asks the
//! customer, and the customer can only answer it by asking their vendor. The policy is real
//! and enforced -- `AuditReaper` deletes past each stream's window on a timer -- but it lived
//! only in the vendor's config file, so the answer travelled by email.
//!
//! # The two ways a naive report would lie
//!
//! Both are in the deployment's own configuration and neither is obvious from the numbers:
//!
//! * A WINDOW OF ZERO MEANS FOREVER, not "delete immediately". `main.rs` says so where the
//!   sweeper starts ("a window of 0 means that stream is kept FOREVER"), and `AuditReaper`
//!   maps it to `None` and skips the stream. A report emitting `0` would tell an auditor the
//!   opposite of the truth, and the sign of the error is the dangerous one: it claims data is
//!   destroyed that is in fact retained.
//! * A DISABLED REAPER ENFORCES NOTHING. With `[audit_retention] enabled = false` the sweeper
//!   never starts, so both windows are inert and everything is kept whatever the numbers say.
//!   Reporting the windows without that flag would publish a policy nothing applies.
//!
//! So `enforced` comes first and the per-stream entries say `retained_forever` explicitly
//! rather than leaving a reader to infer it from a zero.
//!
//! # The delivery attestation, in the same module for the same reason
//!
//! Criterion 3's other half is "log-stream delivery attestations (what was delivered where,
//! gaps flagged)". Both answers go to the same reader for the same purpose: an auditor asking
//! what happened to this deployment's audit trail, and whether any of it went missing.
//!
//! WHERE A GAP CAN BE COUNTED IT IS COUNTED, and where it cannot it is still reported. An
//! undelivered batch is a `log_stream_dead_letters` row carrying the number of events in it
//! and the audit-id range it spans, so the attestation says how many events were missed and
//! from when rather than leaving a reader a boolean to interpret.
//!
//! But a dead letter is written only after a bounded run of REFUSED deliveries, and most
//! ways a stream stops delivering never reach that: `log_streams.shipping_enabled` is off
//! by default, the shipper may not have started, the stream may be deactivated, its sink
//! type may have no implementation in this build, or a failure run may be under way and
//! below the threshold. In every one of those nothing is attempted, so nothing is refused,
//! so the table is empty -- and a report reading only the table would tell an auditor the
//! whole trail arrived while none of it had.
//!
//! So `gap` is the disjunction of every state in which events are not reaching the sink,
//! and the counts stand beside it describing the part that left a record. `gap: false`
//! means all of them are clear at once, which is the answer an auditor needs on a good day;
//! `gap: true` with zero counts is the bad day that used to be invisible.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::resolve_scope;
use crate::response::json;
use crate::state::AdminState;

/// One audit stream's retention.
#[derive(Debug, Serialize, ToSchema)]
pub struct StreamRetentionView {
    /// The stream the window applies to: `admin_action` or `authentication`.
    pub stream: String,
    /// Whether this stream is kept indefinitely. A configured window of zero means this.
    pub retained_forever: bool,
    /// How long rows are kept, in seconds, or absent when the stream is kept forever.
    pub retention_secs: Option<u64>,
}

/// The deployment's audit-retention policy.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditRetentionView {
    /// Whether the reaper started, AS OBSERVED AT BOOT. When false, NOTHING is deleted and
    /// the per-stream windows below are inert.
    ///
    /// A snapshot, not a liveness probe. The boot path is the only place that can see
    /// whether the sweeper started, and it speaks once; a reaper that starts and later
    /// stops deleting -- its connection dropped, its role revoked -- is not reported here.
    /// Narrowing that window would take a health signal the sweeper writes on each pass,
    /// which this does not have. The snapshot still closes the case it was added for, an
    /// operator who sets the flag and never wires the retention role, which is a permanent
    /// state rather than a drifting one.
    pub enforced: bool,
    /// How often the sweep runs, in seconds, or absent when it does not run.
    pub sweep_interval_secs: Option<u64>,
    /// One entry per audit stream.
    pub streams: Vec<StreamRetentionView>,
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/audit-retention",
    operation_id = "readAuditRetention",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The retention this deployment enforces. `enforced: false` means nothing is deleted whatever the windows say, and a stream with `retained_forever` is kept indefinitely", body = AuditRetentionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such tenant and environment pair under this operator. A soft-deleted environment still answers: the report describes the deployment, which outlives it", body = ErrorBody)
    )
)]
pub async fn read_audit_retention(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (_scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;

    let view = retention_view(state.audit_retention());
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// What one log stream failed to deliver.
///
/// # Why this is more than a dead-letter count
///
/// A dead letter is written only after a bounded run of REFUSED deliveries. Every other
/// way a stream fails to deliver writes no row at all: shipping is off for the deployment
/// (the default), the shipper could not start, the stream is deactivated, its sink type
/// has no implementation in this build, or a failure run is under way and has not reached
/// the threshold. In all of those the dead-letter table is empty and none of the trail has
/// arrived, so a report reading only that table would answer an auditor "no gap" for a
/// deployment exporting nothing. The counts below are exact for what was dead-lettered;
/// `gap` additionally covers the states where there is nothing to count.
///
/// # What it still cannot see
///
/// Every signal here is per stream or per process. A pass that dies BEFORE the per-stream
/// loop -- `list_active` itself erroring, say -- records nothing against any stream, so
/// every disjunct stays clear while no stream advances. Narrowing that needs a per-pass
/// health row, which the shipper does not write. The states this does cover are the
/// standing ones an auditor is asking about; the uncovered one is a process failing
/// loudly in its own logs.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryAttestationView {
    /// The stream this attests to.
    pub stream_id: String,
    /// Whether anything is known to be undelivered, by any of the routes above.
    pub gap: bool,
    /// Whether the shipper was running in THIS PROCESS when it booted. When false nothing
    /// is being delivered for this stream, whatever the counts say.
    ///
    /// A snapshot and a per-process one, with the same two bounds as `enforced` on the
    /// retention report. The boot path speaks once, so a shipper that starts and later
    /// dies is not reported here; and in a split deployment where the management API and
    /// the workers run as separate processes, this is the answer for the process serving
    /// the request. Both would need a health signal each pass writes, which the shipper
    /// does not have. What the snapshot does close is the state it was added for, a
    /// deployment that never starts a shipper at all, which is the shipped default and is
    /// permanent rather than drifting.
    pub shipping: bool,
    /// Whether the stream itself is active. A deactivated stream delivers nothing.
    pub active: bool,
    /// Delivery failures since the last success. Non-zero means a batch is being retried
    /// and the cursor has not moved past it.
    pub consecutive_failures: i32,
    /// When this stream last completed a pass WITHOUT a delivery failure, in epoch
    /// milliseconds, or absent when it never has.
    ///
    /// Not "last delivered": `record_success` is also called for a pass whose window was
    /// entirely filtered out, and on the pass that sets a batch aside. Both advance the
    /// cursor without anything reaching the sink. It is a liveness signal for the pass,
    /// and the counts beside it are the delivery signal.
    pub last_success_at_unix_ms: Option<i64>,
    /// How many batches were set aside after refusal and are still awaiting replay.
    pub undelivered_batches: u32,
    /// How many audit events those batches hold.
    pub undelivered_events: u64,
    /// How many set-aside batches lost events to audit retention before a replay could
    /// reach them. A batch counts here whether retention took the WHOLE range (nothing was
    /// delivered) or only part of it (the survivors were).
    pub permanently_lost_batches: u32,
    /// How many audit events are permanently lost: removed from the audit log without ever
    /// reaching the sink. Not the size of the batches above, which may have delivered some
    /// of what they held.
    pub permanently_lost_events: u64,
    /// When the earliest undelivered or lost RANGE begins, in epoch milliseconds, or
    /// absent when there is neither.
    ///
    /// The start of the range a failed pass read, which is a bound rather than the
    /// timestamp of a particular delivered-or-not event: a stream carrying an event-type
    /// filter may have skipped the first row in that range. It is the honest answer to
    /// "from when is this trail incomplete", and it errs early, which is the safe
    /// direction for the question.
    pub earliest_undelivered_at_unix_ms: Option<i64>,
    /// The most recent delivery error known for this stream: the LIVE failure reason while
    /// a run is under way, and otherwise the error recorded against the most recently
    /// set-aside batch. Absent only when neither exists.
    pub last_error: Option<String>,
}

/// Sum the OUTSTANDING batches into (batches, events, earliest occurrence).
fn batch_totals(batches: &[ironauth_store::log_stream::DeadLetter]) -> (u32, u64, Option<i64>) {
    (
        u32::try_from(batches.len()).unwrap_or(u32::MAX),
        batches
            .iter()
            .map(|batch| u64::from(batch.event_count.unsigned_abs()))
            .sum(),
        batches.iter().map(|batch| batch.from.0).min(),
    )
}

/// Sum the LOST batches the same way.
///
/// A separate function over a separate type rather than a generic one, because the field
/// each sums means something different: a dead letter's `event_count` is how many events
/// the failed pass held, and a lost batch's `lost_event_count` is how many of them nobody
/// will ever receive. They are equal only when the whole range was deleted.
fn lost_totals(batches: &[ironauth_store::log_stream::LostBatch]) -> (u32, u64, Option<i64>) {
    (
        u32::try_from(batches.len()).unwrap_or(u32::MAX),
        batches
            .iter()
            .map(|batch| u64::from(batch.lost_event_count.unsigned_abs()))
            .sum(),
        batches.iter().map(|batch| batch.from.0).min(),
    )
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}/attestation",
    operation_id = "readLogStreamAttestation",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("stream_id" = String, Path, description = "The log stream identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "What this stream failed to deliver. `gap: false` means nothing is known to be undelivered BY ANY ROUTE: no batch is outstanding or lost, no failure run is under way, the stream is active and this deployment is shipping", body = DeliveryAttestationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such log stream in this scope, or one confined out of this credential's reach", body = ErrorBody)
    )
)]
pub async fn read_log_stream_attestation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, stream_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;
    // THE SAME FENCE THE DELETE AND REPLAY TAKE. A stream is addressed by id alone here and
    // this answers with how much of a sibling organization's audit trail went undelivered
    // and what its SIEM said about it.
    crate::log_streams::require_stream_in_reach(&state, &principal, scope, &stream_id).await?;

    let streams = state.store().scoped(scope).log_streams();
    let map_error = |error| match error {
        ironauth_store::StoreError::NotFound => ApiError::NotFound,
        _ => ApiError::Internal,
    };
    // THE RECORD, not the listing: a DEACTIVATED stream delivers nothing, which is exactly
    // what this must report, and `list_active` would hide it behind a not-found.
    let record = streams.record(&stream_id).await.map_err(map_error)?;
    let outstanding = streams
        .outstanding_dead_letters(&stream_id)
        .await
        .map_err(map_error)?;
    let lost = streams.lost_batches(&stream_id).await.map_err(map_error)?;

    let view = attestation_view(
        stream_id,
        &record,
        &outstanding,
        &lost,
        state.log_shipper().running(),
    );
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Render the attestation, with every not-delivering rule applied once.
///
/// A free function so each disjunct of `gap` is reachable from a unit test. Over HTTP only
/// some are: the test harness builds its `AdminState` directly and never runs the boot
/// path, so `shipping` is false for every test server and the branches it dominates would
/// ship unexercised.
fn attestation_view(
    stream_id: String,
    record: &ironauth_store::log_stream::LogStreamRecord,
    outstanding: &[ironauth_store::log_stream::DeadLetter],
    lost: &[ironauth_store::log_stream::LostBatch],
    shipping: bool,
) -> DeliveryAttestationView {
    let (undelivered_batches, undelivered_events, earliest_outstanding) = batch_totals(outstanding);
    let (permanently_lost_batches, permanently_lost_events, earliest_lost) = lost_totals(lost);
    let failures = record.health.consecutive_failures;
    // EVERY ROUTE, not just the counted one. Each disjunct is a state in which events this
    // stream is meant to carry are not reaching the sink, and only the first two of them
    // leave a row behind to count.
    let gap =
        !outstanding.is_empty() || !lost.is_empty() || failures > 0 || !shipping || !record.active;
    DeliveryAttestationView {
        stream_id,
        gap,
        shipping,
        active: record.active,
        consecutive_failures: failures,
        last_success_at_unix_ms: record
            .health
            .last_success_micros
            .map(|micros| micros / 1000),
        undelivered_batches,
        undelivered_events,
        permanently_lost_batches,
        permanently_lost_events,
        // THE EARLIER OF THE TWO. Both kinds are undelivered, and an auditor asking from
        // when the trail is incomplete wants the earliest of either.
        earliest_undelivered_at_unix_ms: match (earliest_outstanding, earliest_lost) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
        .map(|micros| micros / 1000),
        // THE LIVE REASON FIRST, THE SET-ASIDE BATCH SECOND, and neither alone is right.
        //
        // Dead-lettering ADVANCES the cursor and records a success, so the moment a batch
        // is set aside the stream's own `last_error` is cleared: reading only the stream
        // reports no error at all while a batch sits undelivered. Reading only the batch
        // is wrong the other way, because a dead letter freezes the error that was current
        // when it was written, so a fresh failure or a refused replay afterwards updates
        // the stream and not the row.
        //
        // The most recently set-aside batch is the LAST of the list: both queries order by
        // `dead_lettered_at`. Outstanding before lost, because an outstanding batch is the
        // one an operator can still act on.
        last_error: record.health.last_error.clone().or_else(|| {
            outstanding
                .last()
                .map(|batch| batch.last_error.clone())
                .or_else(|| lost.last().map(|batch| batch.last_error.clone()))
        }),
    }
}

/// What the admin plane knows about retention: the ANSWER, not the credential.
///
/// # Why the plane does not hold `AuditRetentionConfig`
///
/// That struct carries `database_url`, the retention-role DSN, and `PLANE_LOCAL_KEYS`
/// records why no plane state may hold it: the retention role is the one role granted
/// DELETE on the audit tables and INSERT on nothing, so handing the section to a plane
/// widens exactly the credential migration 0136 exists to keep narrow. The boot path
/// therefore reduces the section to the numbers this report publishes and passes those.
///
/// # Why `enforced` is not the config flag
///
/// `enabled = true` is the first of several conditions, not the whole of them. Without a
/// retention DSN, without a control-plane DSN, or with either connection refused, the boot
/// path logs "audit retention NOT running" and starts nothing, and in every one of those
/// states the flag is still true. Publishing the flag would tell an auditor the trail is
/// pruned on a fixed window while it is in fact retained forever, which is the error
/// direction this module goes out of its way to avoid for the zero window. So this field
/// is set from the sweeper the boot path ACTUALLY STARTED.
#[derive(Clone, Debug, Default)]
pub struct AuditRetentionPolicy {
    // SHARED WITH THE BOOT PATH, because the plane is assembled before the sweeper is
    // attempted. `assemble_planes` runs at boot step one and `start_audit_retention_sweeper`
    // several steps later, so the plane cannot be handed a verdict that does not exist yet.
    // The boot path keeps this handle and stores the verdict once it has one, which happens
    // before `server.run`, so no request can observe the interim `false`.
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// How often the reaper sweeps.
    pub sweep_interval_secs: u64,
    /// The admin-action window, zero meaning forever.
    pub admin_action_retention_secs: u64,
    /// The authentication window, zero meaning forever.
    pub authentication_retention_secs: u64,
}

impl AuditRetentionPolicy {
    /// The windows and interval this deployment is configured with.
    ///
    /// Starts NOT enforcing. Whether it does is not knowable from the config: see
    /// [`AuditRetentionPolicy::running_handle`].
    #[must_use]
    pub fn from_config(config: &ironauth_config::AuditRetentionConfig) -> Self {
        Self {
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            sweep_interval_secs: config.interval_secs,
            admin_action_retention_secs: config.admin_action_retention_secs,
            authentication_retention_secs: config.authentication_retention_secs,
        }
    }

    /// The handle the boot path stores the sweeper verdict into.
    ///
    /// # Why this is not derived from the config flag
    ///
    /// `enabled = true` is the first of several conditions, not the whole of them. Without
    /// a retention DSN, without a control-plane DSN, or with either connection refused, the
    /// boot path logs "audit retention NOT running" and starts nothing, and the flag stays
    /// true through all of it. A handler checking `enabled && database_url.is_some()` would
    /// still answer `enforced: true` for a DSN that exists and is refused. Only the boot
    /// path sees the connection attempts, so only the boot path can answer, and it answers
    /// with whether `start_audit_retention_sweeper` returned a sweeper.
    ///
    /// Reporting the flag instead would tell an auditor the trail is pruned on a fixed
    /// window while it is in fact retained forever, which is the error direction this
    /// module goes out of its way to avoid for the zero window.
    #[must_use]
    pub fn running_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.running)
    }

    /// Whether the reaper is running, as the boot path observed it.
    #[must_use]
    pub fn enforced(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Whether this deployment's LOG SHIPPER is running, as the boot path observed it.
///
/// # Why the attestation cannot answer without this
///
/// `log_streams.shipping_enabled` is FALSE by default, and even when it is on the shipper
/// does not start without a data-plane DSN and a control-plane DSN it can reach. In every
/// one of those states a configured stream delivers nothing and dead-letters nothing,
/// because a dead letter is written only after a run of FAILED deliveries and no delivery
/// is ever attempted. An attestation reading only `log_stream_dead_letters` would answer
/// "no gap" for a deployment where none of the audit trail has arrived.
///
/// Same shape and same reason as [`AuditRetentionPolicy`]: the plane is assembled before
/// the worker is attempted, so the boot path stores the verdict into a handle the plane
/// holds.
#[derive(Clone, Debug, Default)]
pub struct LogShipperStatus {
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LogShipperStatus {
    /// The handle the boot path stores the verdict into.
    #[must_use]
    pub fn running_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.running)
    }

    /// Whether the shipper is running.
    #[must_use]
    pub fn running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Render the policy, with both "nothing is enforced" rules applied once.
///
/// A free function so both branches of `enforced` are reachable from a unit test. Over HTTP
/// only the false branch is: the test harness builds its `AdminState` directly and never
/// runs the boot path, so no test server can have a sweeper running, and the true branch
/// would ship unexercised.
fn retention_view(policy: &AuditRetentionPolicy) -> AuditRetentionView {
    let enforced = policy.enforced();
    AuditRetentionView {
        enforced,
        // WITHHELD WHEN NOTHING SWEEPS. An interval published beside `enforced: false`
        // reads as a schedule, and there is none.
        sweep_interval_secs: enforced.then_some(policy.sweep_interval_secs),
        streams: vec![
            stream_view(
                ironauth_store::audit_retention::ADMIN_ACTION_STREAM,
                policy.admin_action_retention_secs,
            ),
            stream_view(
                ironauth_store::audit_retention::AUTHENTICATION_STREAM,
                policy.authentication_retention_secs,
            ),
        ],
    }
}

/// One stream's entry, with the zero-means-forever rule applied once.
fn stream_view(stream: &str, secs: u64) -> StreamRetentionView {
    StreamRetentionView {
        stream: stream.to_owned(),
        retained_forever: secs == 0,
        retention_secs: (secs != 0).then_some(secs),
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditRetentionPolicy, attestation_view, retention_view, stream_view};
    use ironauth_store::log_stream::{DeadLetter, LogStreamRecord, StreamHealth};

    #[test]
    fn a_zero_window_reports_forever_and_never_a_zero() {
        // The dangerous direction. `AuditReaper` maps 0 to `None` and skips the stream, and
        // the config's own default is 0 for both -- so a report that emitted `0` would tell
        // an auditor the default deployment destroys its audit trail immediately, when it
        // keeps everything.
        let view = stream_view("admin_action", 0);
        assert!(view.retained_forever, "zero means forever");
        assert_eq!(
            view.retention_secs, None,
            "a forever stream must carry no number at all, not a zero a reader could take \
             literally"
        );
    }

    #[test]
    fn a_configured_window_reports_its_seconds() {
        // The control: without it, "no zeros" is equally satisfied by a report that never
        // carries a number.
        let view = stream_view("authentication", 7_776_000);
        assert!(!view.retained_forever);
        assert_eq!(view.retention_secs, Some(7_776_000));
        assert_eq!(view.stream, "authentication");
    }

    /// A policy configured with windows but whose sweeper never started.
    fn configured(running: bool) -> AuditRetentionPolicy {
        let policy = AuditRetentionPolicy {
            sweep_interval_secs: 900,
            admin_action_retention_secs: 2_592_000,
            authentication_retention_secs: 604_800,
            ..AuditRetentionPolicy::default()
        };
        policy
            .running_handle()
            .store(running, std::sync::atomic::Ordering::Relaxed);
        policy
    }

    #[test]
    fn a_configured_deployment_whose_sweeper_never_started_enforces_nothing() {
        // THE CANONICAL OPERATOR MISTAKE: the windows are set, the flag is on, and the
        // retention DSN was never wired, so the boot path logged "audit retention NOT
        // running" and nothing is ever deleted. Publishing the windows with
        // `enforced: true` would tell an auditor the trail is pruned on a fixed schedule
        // while it grows without bound.
        let view = retention_view(&configured(false));
        assert!(!view.enforced, "no sweeper started");
        assert_eq!(
            view.sweep_interval_secs, None,
            "an interval is meaningless when nothing sweeps"
        );
        // AND THE WINDOWS ARE STILL PUBLISHED, because they are what the deployment is
        // configured with and an auditor comparing intent against reality needs both.
        let admin = &view.streams[0];
        assert_eq!(admin.retention_secs, Some(2_592_000));
        assert!(!admin.retained_forever);
    }

    #[test]
    fn a_running_sweeper_is_reported_as_enforcing_and_publishes_its_interval() {
        // The control. Without it, "never claims enforcement" is equally satisfied by a
        // report hard-coding `false`, which would understate every deployment that IS
        // deleting -- the other direction of the same lie.
        let view = retention_view(&configured(true));
        assert!(view.enforced, "the sweeper is running");
        assert_eq!(view.sweep_interval_secs, Some(900));
        assert_eq!(view.streams[1].retention_secs, Some(604_800));
    }

    /// A healthy, active stream on a shipping deployment.
    fn healthy() -> LogStreamRecord {
        LogStreamRecord {
            id: "lsm_1".to_owned(),
            description: String::new(),
            source: ironauth_store::log_stream::StreamSource::Both,
            sink_type: ironauth_store::log_stream::SinkType::Http,
            sink_config: serde_json::Value::Null,
            credential_secret_name: None,
            signing_secret_name: None,
            event_type_filter: None,
            organization_id: None,
            active: true,
            cursor: None,
            health: StreamHealth {
                last_success_micros: Some(9_000_000),
                last_error_micros: None,
                last_error: None,
                consecutive_failures: 0,
            },
        }
    }

    fn lost(id: &str, from_micros: i64, lost_events: i32) -> ironauth_store::log_stream::LostBatch {
        ironauth_store::log_stream::LostBatch {
            id: id.to_owned(),
            from: (from_micros, format!("aud_{id}_from")),
            lost_event_count: lost_events,
            last_error: format!("{id} refused"),
        }
    }

    fn batch(id: &str, from_micros: i64, events: i32) -> DeadLetter {
        DeadLetter {
            id: id.to_owned(),
            from: (from_micros, format!("aud_{id}_from")),
            to: (from_micros + 1_000_000, format!("aud_{id}_to")),
            event_count: events,
            last_error: format!("{id} refused"),
        }
    }

    #[test]
    fn the_handle_the_boot_path_writes_is_the_one_the_report_reads() {
        // THE SEAM BETWEEN THEM, which nothing else observes. `serve` stores the verdict
        // into `running_handle()` and logs the value it reads back out of the SAME local
        // binding, so that log line proves the store happened and says nothing about where
        // it landed. Were `running_handle` to hand back a fresh `Arc` -- a plausible
        // slip, since every other accessor on this type returns a value -- the boot log
        // would still print the right answer and the endpoint would report `enforced:
        // false` on every deployment forever.
        let policy = AuditRetentionPolicy::default();
        assert!(!policy.enforced(), "the default is not enforcing");
        policy
            .running_handle()
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            policy.enforced(),
            "the boot path wrote through the handle and the report did not see it: the \
             two are not the same atomic"
        );

        // AND A CLONE OF THE POLICY SHARES IT, which is how the plane holds it: the
        // builder installs a policy into `AdminState` and the boot path takes its handle
        // from the assembled plane, so a `Clone` that deep-copied the atomic would break
        // the same seam one layer up.
        let clone = policy.clone();
        policy
            .running_handle()
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(
            !clone.enforced(),
            "a cloned policy must observe the same verdict, not a snapshot of it"
        );
    }

    #[test]
    fn the_shipper_status_handle_is_shared_the_same_way() {
        // Same seam, same slip, different type.
        let status = super::LogShipperStatus::default();
        assert!(!status.running());
        status
            .running_handle()
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(status.running(), "the handle and the reader must agree");
        let clone = status.clone();
        status
            .running_handle()
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!clone.running(), "a clone must share, not snapshot");
    }

    #[test]
    fn a_delivering_stream_reports_no_gap() {
        // THE CONTROL, and the only input combination that may report none. Without it
        // every assertion below is satisfied by a report hard-coding `gap: true`.
        let view = attestation_view("lsm_1".to_owned(), &healthy(), &[], &[], true);
        assert!(!view.gap);
        assert!(view.shipping && view.active);
        assert_eq!(view.undelivered_batches, 0);
        assert_eq!(view.undelivered_events, 0);
        assert_eq!(view.permanently_lost_batches, 0);
        assert_eq!(view.permanently_lost_events, 0);
        assert_eq!(view.earliest_undelivered_at_unix_ms, None);
        assert_eq!(view.last_success_at_unix_ms, Some(9_000));
    }

    #[test]
    fn a_deployment_that_ships_nothing_reports_a_gap_with_nothing_to_count() {
        // THE DEFECT THIS FUNCTION EXISTS FOR. `log_streams.shipping_enabled` is off by
        // default, so no delivery is attempted, so nothing is refused, so nothing is
        // dead-lettered. A report reading only the dead-letter table answers "no gap"
        // while NONE of the audit trail has arrived, which is the strongest possible lie
        // to an auditor asking whether any of it went missing.
        let view = attestation_view("lsm_1".to_owned(), &healthy(), &[], &[], false);
        assert!(
            view.gap,
            "a deployment shipping nothing must not report a complete trail"
        );
        assert!(!view.shipping);
        assert_eq!(
            view.undelivered_batches, 0,
            "there is genuinely nothing set aside; the gap is not a count"
        );
    }

    #[test]
    fn a_deactivated_stream_reports_a_gap() {
        // Same shape, different cause: a stream nobody ships FOR and a stream nothing
        // ships are both delivering nothing, and neither leaves a row.
        let mut record = healthy();
        record.active = false;
        let view = attestation_view("lsm_1".to_owned(), &record, &[], &[], true);
        assert!(view.gap, "a deactivated stream delivers nothing");
        assert!(!view.active);
    }

    #[test]
    fn a_failure_run_below_the_dead_letter_threshold_reports_a_gap() {
        // The window this report used to be blind to. A batch is retried from the same
        // position for DEAD_LETTER_AFTER passes before a row is written, and throughout it
        // the cursor has not moved and the events have not arrived.
        let mut record = healthy();
        record.health.consecutive_failures = 3;
        record.health.last_error = Some("connection refused".to_owned());
        let view = attestation_view("lsm_1".to_owned(), &record, &[], &[], true);
        assert!(view.gap, "a batch is being retried and has not landed");
        assert_eq!(view.consecutive_failures, 3);
        assert_eq!(
            view.last_error.as_deref(),
            Some("connection refused"),
            "the CURRENT reason, read off the stream rather than frozen in a batch"
        );
    }

    #[test]
    fn batches_are_summed_and_the_earliest_of_either_kind_is_dated() {
        // TWO OF EACH, with different sizes and different instants, so `sum` is
        // distinguishable from `max` and from the batch count, and `min` from `first` and
        // from `max`. One of each would satisfy all of them at once.
        let outstanding = [batch("a", 50_000_000, 7), batch("b", 30_000_000, 5)];
        let lost = [lost("c", 20_000_000, 2), lost("d", 40_000_000, 3)];
        let view = attestation_view("lsm_1".to_owned(), &healthy(), &outstanding, &lost, true);

        assert_eq!(view.undelivered_batches, 2);
        assert_eq!(view.undelivered_events, 12, "7 + 5, not 7 and not 2");
        assert_eq!(view.permanently_lost_batches, 2);
        assert_eq!(view.permanently_lost_events, 5, "2 + 3");
        // THE EARLIEST OF EITHER KIND, and it is a LOST one: taking the minimum over only
        // the outstanding list would answer 30s, and taking the first element of either
        // would answer 50s or 20s depending on order.
        assert_eq!(
            view.earliest_undelivered_at_unix_ms,
            Some(20_000),
            "the earliest of both lists, converted from micros to millis"
        );
        assert!(view.gap);
    }

    #[test]
    fn the_live_failure_reason_wins_over_a_frozen_one_and_a_frozen_one_beats_nothing() {
        // BOTH DIRECTIONS, because each alone is wrong. Dead-lettering advances the cursor
        // and records a success, so a stream with an outstanding batch usually carries NO
        // error of its own: reading only the stream reports none while a batch sits
        // undelivered. And a dead letter freezes the reason it was written with, so a
        // fresh failure afterwards makes the row stale.
        let outstanding = [batch("a", 10_000_000, 1), batch("b", 20_000_000, 1)];

        let frozen = attestation_view("lsm_1".to_owned(), &healthy(), &outstanding, &[], true);
        assert_eq!(
            frozen.last_error.as_deref(),
            Some("b refused"),
            "with no live reason, the MOST RECENTLY set-aside batch's error is the answer, \
             and both queries order by dead_lettered_at so that is the last element"
        );

        let mut failing = healthy();
        failing.health.consecutive_failures = 2;
        failing.health.last_error = Some("connection refused".to_owned());
        let live = attestation_view("lsm_1".to_owned(), &failing, &outstanding, &[], true);
        assert_eq!(
            live.last_error.as_deref(),
            Some("connection refused"),
            "a live failure run is the current reason; the frozen batch error is older"
        );
    }

    #[test]
    fn an_outstanding_batch_alone_is_still_a_gap() {
        // EACH DISJUNCT ALONE, because a test exercising two at once cannot tell which one
        // carries it. Dropping `!outstanding.is_empty()` from the expression survived every
        // other test in this module: the only case with outstanding batches also had lost
        // ones, so `!lost.is_empty()` kept the answer right for the wrong reason.
        //
        // This is the ordinary case as well: a healthy, active stream on a shipping
        // deployment whose sink refused one batch hard enough to set it aside.
        let outstanding = [batch("a", 10_000_000, 3)];
        let view = attestation_view("lsm_1".to_owned(), &healthy(), &outstanding, &[], true);
        assert!(view.gap, "a batch is set aside and undelivered");
        assert!(
            view.shipping && view.active && view.consecutive_failures == 0,
            "every OTHER route to a gap is clear, so the flag can only come from the \
             outstanding batch"
        );
        assert_eq!(view.undelivered_batches, 1);
        assert_eq!(view.undelivered_events, 3);
        assert_eq!(view.permanently_lost_batches, 0);
    }

    #[test]
    fn a_permanently_lost_batch_alone_is_still_a_gap() {
        // A stream whose outstanding queue is EMPTY because every set-aside batch was
        // abandoned has delivered none of them, and `outstanding_dead_letters` excludes
        // abandoned rows precisely so they stop blocking. Reading only that list would
        // report the permanently lost events as no gap at all.
        let lost = [lost("c", 20_000_000, 4)];
        let view = attestation_view("lsm_1".to_owned(), &healthy(), &[], &lost, true);
        assert!(view.gap, "these events can never be delivered");
        assert!(
            view.shipping && view.active && view.consecutive_failures == 0,
            "every other route to a gap is clear, so the flag can only come from the lost \
             batch"
        );
        assert_eq!(view.undelivered_batches, 0);
        assert_eq!(view.permanently_lost_events, 4);
        assert_eq!(view.earliest_undelivered_at_unix_ms, Some(20_000));
    }
}
