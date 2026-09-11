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
//! A GAP IS NOT INFERRED, it is counted. An undelivered batch is a `log_stream_dead_letters`
//! row, and each one carries the number of events in it and the audit-id range it spans, so
//! the attestation reports how many events were missed and from when -- not a boolean a
//! reader has to interpret. A stream with no outstanding batches reports `gap: false` and
//! zero, which is the answer an auditor needs on a good day and the one that makes the bad
//! day legible.

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
    /// Whether the reaper runs at all. When false, NOTHING is deleted and the per-stream
    /// windows below are inert.
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
#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryAttestationView {
    /// The stream this attests to.
    pub stream_id: String,
    /// Whether anything is known to be undelivered.
    pub gap: bool,
    /// How many batches are outstanding.
    pub undelivered_batches: u32,
    /// How many audit events those batches hold.
    pub undelivered_events: u64,
    /// When the earliest undelivered event occurred, in epoch milliseconds, or absent when
    /// there is no gap.
    pub earliest_undelivered_at_unix_ms: Option<i64>,
    /// The error the most recent failure reported, or absent when there is no gap.
    pub last_error: Option<String>,
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
        (status = 200, description = "What this stream failed to deliver. `gap: false` with zero counts means nothing is outstanding", body = DeliveryAttestationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such log stream in this scope", body = ErrorBody)
    )
)]
pub async fn read_log_stream_attestation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, stream_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;
    // THE SAME FENCE THE DELETE AND REPLAY TAKE. A stream is addressed by id alone here, the
    // listing hands out every id in the environment, and this answers with how much of a
    // sibling organization's audit trail went undelivered and what its SIEM said about it.
    crate::log_streams::require_stream_in_reach(&state, &principal, scope, &stream_id).await?;

    let outstanding = state
        .store()
        .scoped(scope)
        .log_streams()
        .outstanding_dead_letters(&stream_id)
        .await
        .map_err(|error| match error {
            ironauth_store::StoreError::NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        })?;

    // COUNTED, NOT INFERRED. Each outstanding batch carries the number of events in it and
    // the instant the earliest one occurred, so the attestation can say how much went
    // missing and from when rather than only that something did.
    let undelivered_events: u64 = outstanding
        .iter()
        .map(|batch| u64::from(batch.event_count.unsigned_abs()))
        .sum();
    let earliest = outstanding.iter().map(|batch| batch.from.0).min();
    let view = DeliveryAttestationView {
        stream_id,
        gap: !outstanding.is_empty(),
        undelivered_batches: u32::try_from(outstanding.len()).unwrap_or(u32::MAX),
        undelivered_events,
        earliest_undelivered_at_unix_ms: earliest.map(|micros| micros / 1000),
        last_error: outstanding.last().map(|batch| batch.last_error.clone()),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
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
    use super::{AuditRetentionPolicy, retention_view, stream_view};

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
}
