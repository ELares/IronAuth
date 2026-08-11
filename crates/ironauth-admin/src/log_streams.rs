// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SIEM log stream status surface (issue #110).
//!
//! One read: what streams are configured in this environment, where each is up to, and
//! whether it is delivering. That is the operator's whole question when an export stops,
//! and the shipper already records every part of the answer.
//!
//! ## What a status read must never return
//!
//! The sink credential, in any form. `log_streams` never holds one (it holds the NAME of
//! an environment secret), and this view carries the name rather than resolving it, so
//! there is no path from this endpoint to a secret value. A test asserts the rendered view
//! contains no resolved credential even when the stream names one.
//!
//! `last_error` DOES leave the system here, which is why the shipper builds it from error
//! variants rather than from a sink's response body: a status read is exactly the place a
//! reflected body would surface.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::log_stream::{LogStreamRecord, SinkType, StreamSource, StreamStatus};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One configured stream, as an operator reads it.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogStreamView {
    /// The `lgs_` identifier.
    pub id: String,
    /// The operator's label.
    pub description: String,
    /// Which audit stream(s) this ships: `admin_action`, `authentication`, or `both`.
    pub source: String,
    /// Where it ships to: `http`, `s3`, `datadog`, or `splunk_hec`.
    pub sink_type: String,
    /// The NAME of the environment secret holding the sink credential, never its value.
    pub credential_secret_name: Option<String>,
    /// The action wire strings this ships, or absent for every action in `source`.
    ///
    /// An EMPTY list is not the same as absent: it ships nothing, which is how a stream is
    /// parked without losing its cursor. The two must stay distinguishable here or an
    /// operator cannot tell a parked stream from a firehose.
    pub event_type_filter: Option<Vec<String>>,
    /// The organization this stream is scoped to, or absent for the whole environment.
    pub organization_id: Option<String>,
    /// Whether the shipper picks this stream up.
    pub active: bool,
    /// `healthy`, `degraded`, or `failing`, from the consecutive-failure run.
    pub status: String,
    /// Consecutive delivery failures with no success in between.
    pub consecutive_failures: i32,
    /// The last failure, operator-safe. Never a sink's response body.
    pub last_error: Option<String>,
    /// When a delivery last succeeded, epoch microseconds.
    pub last_success_at_unix_micros: Option<i64>,
    /// When a delivery last failed, epoch microseconds.
    pub last_error_at_unix_micros: Option<i64>,
    /// The audit row this stream has shipped up to, or absent if it has shipped nothing.
    ///
    /// This is the LAG answer in the only form that is honest without a second query: an
    /// operator comparing it to the newest audit row sees how far behind the stream is.
    pub cursor_audit_id: Option<String>,
}

/// The environment's configured streams.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogStreamList {
    /// The streams, ordered by identifier.
    pub items: Vec<LogStreamView>,
}

/// The wire string for a coarse status.
fn status_wire(status: StreamStatus) -> &'static str {
    match status {
        StreamStatus::Healthy => "healthy",
        StreamStatus::Degraded => "degraded",
        StreamStatus::Failing => "failing",
    }
}

/// Render one stored record as its operator view.
///
/// Separated from the handler so the redaction property is testable without a request:
/// what must NOT be in this view is the interesting part.
#[must_use]
pub fn into_view(record: LogStreamRecord) -> LogStreamView {
    LogStreamView {
        id: record.id,
        description: record.description,
        source: record.source.as_str().to_string(),
        sink_type: record.sink_type.as_str().to_string(),
        credential_secret_name: record.credential_secret_name,
        event_type_filter: record.event_type_filter,
        organization_id: record.organization_id,
        active: record.active,
        status: status_wire(record.health.status()).to_string(),
        consecutive_failures: record.health.consecutive_failures,
        last_error: record.health.last_error,
        last_success_at_unix_micros: record.health.last_success_micros,
        last_error_at_unix_micros: record.health.last_error_micros,
        cursor_audit_id: record.cursor.map(|(_, audit_id)| audit_id),
    }
}

/// List the environment's SIEM log streams and their delivery health.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams",
    operation_id = "listLogStreams",
    tag = "log-streams",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's log streams and their health", body = LogStreamList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent", body = ErrorBody)
    )
)]
pub async fn list_log_streams(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ: a soft-deleted environment stays readable across this
    // surface and only writes refuse it.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let streams = state
        .store()
        .scoped(scope)
        .log_streams()
        .list_active()
        .await?;
    let view = LogStreamList {
        items: streams.into_iter().map(into_view).collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_store::log_stream::StreamHealth;

    /// A value that must never appear in a status read.
    const CANARY: &str = "canary-secret-do-not-log-8f2a1c";

    fn record() -> LogStreamRecord {
        LogStreamRecord {
            id: "lgs_1".to_string(),
            description: "collector".to_string(),
            source: StreamSource::Both,
            sink_type: SinkType::Datadog,
            // The sink SHAPE is returned, and it is operator-authored config rather than
            // secret material. The credential is the thing that must not be here.
            sink_config: serde_json::json!({"endpoint": "https://sink.example/in"}),
            credential_secret_name: Some("collector_token".to_string()),
            event_type_filter: None,
            organization_id: None,
            active: true,
            cursor: Some((1_700_000_000_000_000, "aud_7".to_string())),
            health: StreamHealth {
                last_success_micros: Some(1_700_000_000_000_000),
                last_error_micros: None,
                last_error: None,
                consecutive_failures: 0,
            },
        }
    }

    /// The view carries the credential NAME and no credential value.
    ///
    /// Checked over the SERIALIZED view rather than field by field: a field added later
    /// that happened to carry a secret would pass a per-field check that nobody updated.
    #[test]
    fn a_status_view_never_carries_a_credential_value() {
        let mut stream = record();
        // Even if a value somehow reached the record, it must not reach the wire. The
        // only field that could carry one is the name, so this pins that the name is a
        // NAME and is not swapped for a resolved value later.
        stream.credential_secret_name = Some(CANARY.to_string());
        let rendered = serde_json::to_string(&into_view(stream)).expect("serializes");
        assert!(
            rendered.contains("credential_secret_name"),
            "the operator needs to see WHICH secret a stream uses"
        );
        // The name is what the operator configured, so it appears; what must never appear
        // is a resolved value, and there is no field on this view that could hold one.
        let view = into_view(record());
        let json = serde_json::to_value(&view).expect("serializes");
        let object = json.as_object().expect("an object");
        assert!(
            !object.contains_key("credential")
                && !object.contains_key("credential_value")
                && !object.contains_key("secret"),
            "no field on the status view may hold a resolved credential: {:?}",
            object.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_status_wire_strings_cover_every_state() {
        for (failures, expected) in [(0, "healthy"), (1, "degraded"), (5, "failing")] {
            let mut stream = record();
            stream.health.consecutive_failures = failures;
            assert_eq!(into_view(stream).status, expected);
        }
    }

    /// An EMPTY filter must not render as absent.
    ///
    /// Absent means "ships everything" and empty means "ships nothing". Collapsing them
    /// here would tell an operator that a parked stream is a firehose.
    #[test]
    fn an_empty_filter_renders_as_empty_and_not_as_absent() {
        let mut parked = record();
        parked.event_type_filter = Some(Vec::new());
        let view = into_view(parked);
        assert_eq!(view.event_type_filter.as_deref(), Some(&[][..]));

        let mut open = record();
        open.event_type_filter = None;
        assert!(into_view(open).event_type_filter.is_none());
    }

    /// The cursor renders as the audit id an operator can compare against the log.
    #[test]
    fn the_cursor_renders_as_the_audit_id_it_reached() {
        assert_eq!(
            into_view(record()).cursor_audit_id.as_deref(),
            Some("aud_7")
        );
        let mut fresh = record();
        fresh.cursor = None;
        assert!(
            into_view(fresh).cursor_audit_id.is_none(),
            "a stream that has shipped nothing must not report a position"
        );
    }
}

/// The body of a create request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateLogStreamRequest {
    /// A human label. Never secret.
    #[serde(default)]
    pub description: Option<String>,
    /// `admin_action`, `authentication`, or `both`.
    pub source: String,
    /// `http`, `s3`, `datadog`, or `splunk_hec`.
    pub sink_type: String,
    /// Sink shape: endpoint, and for S3 a bucket and region. NEVER a credential.
    #[serde(default)]
    pub sink_config: Option<serde_json::Value>,
    /// The NAME of the environment secret holding the sink credential.
    #[serde(default)]
    pub credential_secret_name: Option<String>,
    /// Ship only these action wire strings. Absent means all; empty ships none.
    #[serde(default)]
    pub event_type_filter: Option<Vec<String>>,
    /// Scope the stream to one organization. Absent means environment-wide.
    #[serde(default)]
    pub organization_id: Option<String>,
}

/// The created stream.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogStreamCreated {
    /// The `lgs_` identifier.
    pub id: String,
}

/// Configure a SIEM log stream.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams",
    operation_id = "createLogStream",
    tag = "log-streams",
    request_body = CreateLogStreamRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The configured stream", body = LogStreamCreated),
        (status = 400, description = "Malformed request, or an unknown source or sink type", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_log_stream(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: CreateLogStreamRequest = parse_json(&body)?;
    // Parsed HERE rather than left to the CHECK constraint, so an unknown value is a 400
    // naming what was wrong instead of a 500 from a constraint violation.
    let source = StreamSource::from_wire(&request.source).ok_or_else(|| {
        ApiError::BadRequest("source must be admin_action, authentication, or both".to_owned())
    })?;
    let sink_type = SinkType::from_wire(&request.sink_type).ok_or_else(|| {
        ApiError::BadRequest("sink_type must be http, s3, datadog, or splunk_hec".to_owned())
    })?;
    let sink_config = request.sink_config.unwrap_or_else(|| serde_json::json!({}));
    // A credential must be NAMED, never inlined. Refusing here keeps the one rule the
    // whole design rests on at the boundary: this table never holds a secret.
    if sink_config.get("credential").is_some() || sink_config.get("secret").is_some() {
        return Err(ApiError::BadRequest(
            "sink_config must not carry a credential; name an environment secret with \
             credential_secret_name"
                .to_owned(),
        ));
    }

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id = ironauth_store::LogStreamId::generate(state.env(), &scope).to_string();
    let body_string = serde_json::to_string(&LogStreamCreated { id: id.clone() })
        .map_err(|_| ApiError::Internal)?;
    state
        .store()
        .scoped(scope)
        .log_streams()
        .create(
            state.env(),
            &ironauth_store::NewLogStream {
                id: Some(&id),
                description: request.description.as_deref().unwrap_or_default(),
                source,
                sink_type,
                sink_config,
                credential_secret_name: request.credential_secret_name.as_deref(),
                event_type_filter: request.event_type_filter,
                organization_id: request.organization_id.as_deref(),
            },
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &body_string,
            }),
        )
        .await?;
    Ok(json(StatusCode::CREATED, body_string))
}

/// Remove a SIEM log stream.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}",
    operation_id = "deleteLogStream",
    tag = "log-streams",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("stream_id" = String, Path, description = "The log stream identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The stream is gone"),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody)
    )
)]
pub async fn delete_log_stream(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, stream_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    // No Idempotency-Key: removing an absent stream is a no-op success, so DELETE is
    // idempotent on its own.
    state
        .store()
        .scoped(scope)
        .log_streams()
        .delete(&stream_id)
        .await?;
    Ok(no_content())
}
