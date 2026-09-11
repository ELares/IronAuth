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
        (status = 404, description = "The environment is not a live row of this deployment", body = ErrorBody)
    )
)]
pub async fn read_audit_retention(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (_scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;

    let config = state.audit_retention();
    let view = AuditRetentionView {
        enforced: config.enabled,
        sweep_interval_secs: config.enabled.then_some(config.interval_secs),
        streams: vec![
            stream_view(
                ironauth_store::audit_retention::ADMIN_ACTION_STREAM,
                config.admin_action_retention_secs,
            ),
            stream_view(
                ironauth_store::audit_retention::AUTHENTICATION_STREAM,
                config.authentication_retention_secs,
            ),
        ],
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
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
    use super::stream_view;

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
}
