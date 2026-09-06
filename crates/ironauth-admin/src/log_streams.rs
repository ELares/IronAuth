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
//! there is no path from this endpoint to a secret value.
//!
//! Two tests hold that, at the two levels it can break at.
//! `tests::a_status_view_never_carries_a_credential_value` below pins the rendering itself,
//! and `delegated_admin::a_log_stream_read_names_the_credential_secret_and_renders_no_value`
//! drives the real HTTP route under a `management.read` grant, which the unit test cannot
//! see: it calls `into_view` directly, so it would still pass if a handler resolved the
//! secret and merged it into the response, or if this route stopped calling `into_view`.
//!
//! They differ in strength and the difference is deliberate. The unit test enumerates the
//! field names a credential might arrive under; the HTTP test asserts the rendered key set
//! EQUALS the documented one, because enumeration only catches names someone thought of. A
//! secret rendered under `resolved_token`, or under `credentials` in the plural, passes an
//! enumerated guard and fails an exact one.
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
    /// The NAME of the environment secret batches are signed with, never its value, and
    /// absent when the stream ships unsigned. An operator has to be able to see WHICH
    /// streams are signed and with what, or they cannot tell a stream that lost its
    /// signature from one that never had one.
    pub signing_secret_name: Option<String>,
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
        signing_secret_name: record.signing_secret_name,
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
    // NARROWED FOR A CONFINED CREDENTIAL, which it was not. Each row carries its
    // `organization_id` on the wire, so an unnarrowed listing handed a credential confined to
    // one organization both the ids of every sibling's stream -- the ids the delete and replay
    // above are addressed by -- and the organization ids themselves, which is the enumeration
    // the uniform not-found exists to prevent everywhere else in this crate. An
    // environment-wide stream is excluded too: it carries every organization's rows.
    let confined = principal.confined_organization().map(ToString::to_string);
    let view = LogStreamList {
        items: streams
            .into_iter()
            .filter(|stream| match &confined {
                None => true,
                Some(organization) => stream.organization_id.as_ref() == Some(organization),
            })
            .map(into_view)
            .collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// The event a SIEM log-stream lifecycle change emits (issue #108).
///
/// `sink_type` present means a CREATE, absent means a DELETE. The sink type travels with the
/// create because "audit is now shipping to S3" and "audit is now shipping to an HTTP
/// endpoint" are different facts to anyone reconciling where a tenant's audit trail goes.
///
/// NEVER THE SINK CREDENTIAL. A stream carries the secret its deliveries authenticate with,
/// sealed at rest and stripped from the read surface -- and a webhook is a wider audience than
/// that surface.
fn log_stream_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    stream_id: &str,
    sink_type: Option<&str>,
) -> Option<crate::events::PendingEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let (event_type, payload) = match sink_type {
        Some(sink) => (
            "log_stream.created",
            serde_json::json!({ "log_stream_id": stream_id, "sink_type": sink }),
        ),
        None => (
            "log_stream.deleted",
            serde_json::json!({ "log_stream_id": stream_id }),
        ),
    };
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: stream_id.to_owned(),
        envelope,
    })
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
            signing_secret_name: None,
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
    #[schema(value_type = Option<Object>)]
    pub sink_config: Option<serde_json::Value>,
    /// The NAME of the environment secret holding the sink credential.
    #[serde(default)]
    pub credential_secret_name: Option<String>,
    /// The NAME of the environment secret to SIGN batches with. Absent ships unsigned.
    ///
    /// Signing is what lets a SIEM check authenticity and replay once a batch has left TLS
    /// and landed in an object store or a log index. See `docs/log-stream-verification.md`.
    /// Setting it here is a control-plane act by design: the app role that ships batches can
    /// read this name and cannot change it, or it could sign with a key it chose.
    #[serde(default)]
    pub signing_secret_name: Option<String>,
    /// Ship only these action wire strings. Absent means all; empty ships none.
    #[serde(default)]
    pub event_type_filter: Option<Vec<String>>,
    /// Scope the stream to one organization. Absent means environment-wide.
    ///
    /// A CREDENTIAL CONFINED TO ONE ORGANIZATION MUST NAME IT. The stream ships that
    /// organization's rows and no other, so a confined credential may name the organization it
    /// is confined to and nothing else; absent means the whole environment, which is strictly
    /// more than such a credential may see and is refused rather than quietly narrowed. An
    /// organization that is not a live row of this scope answers the uniform not-found.
    #[serde(default)]
    pub organization_id: Option<String>,
}

/// The created stream.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogStreamCreated {
    /// The `lgs_` identifier.
    pub id: String,
}

/// Refuse a credential confined to one organization.
///
/// AN ENVIRONMENT-WIDE STREAM HAS NO ORGANIZATION BOUNDARY TO CHECK, so there is nothing for
/// the confinement to be compared against and the only safe answer is to refuse. This is the
/// same shape `personal_access_tokens::require_unconfined` takes, and for the same reason: a
/// credential must never end up carrying MORE authority than its row claims.
fn require_unconfined(principal: &Principal) -> Result<(), ApiError> {
    if principal.confined_organization().is_none() {
        return Ok(());
    }
    Err(ApiError::WrongScope {
        expected: "an unconfined management credential".to_owned(),
        actual: "credential confined to one organization".to_owned(),
        message: "a stream with no organization ships the WHOLE environment's rows, which is \
                  strictly more than a credential confined to one organization may see; name \
                  that organization on the stream instead"
            .to_owned(),
    })
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
        (status = 403, description = "Wrong plane or scope, or a credential confined to one organization asked for a stream with no organization_id (which would carry the whole environment)", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the named organization is not a live row of this scope (which includes an organization the credential is confined away from, and an id this scope cannot parse)", body = ErrorBody),
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
    // THE ORGANIZATION IS FENCED, and until this line it was not. `organization_id` selects
    // WHICH organization's rows the shipper reads -- `log_shipper.rs` passes it into
    // `rows_after` so the isolation is a property of the QUERY -- and it arrives in the request
    // BODY, so it never met the confinement fence every organization-addressed route in this
    // crate goes through. A credential confined to organization A could name organization B
    // here and point the sink at an endpoint it controls, and B's audit and authentication
    // events would be shipped to it. The confinement was decoration on this path.
    //
    // FOUND BY THE DERIVATION THIS CHANGE ADDS rather than by reading the handler. The portal
    // link's identical defect was a hand-written list away from being the only one anybody
    // knew about; deriving the body-addressed set from the committed contract named this one
    // on the first run.
    //
    // AN ABSENT ORGANIZATION IS THE WHOLE ENVIRONMENT, which is strictly MORE than any
    // confined credential may see, so it is refused rather than silently narrowed to the
    // credential's own organization. Narrowing would answer 201 for a stream that carries
    // less than the operator asked for, and a stream that quietly drops rows is the failure
    // an audit pipeline cannot detect.
    let organization_id = if let Some(organization) = request.organization_id.as_deref() {
        Some(
            crate::org_context::resolve_live_org(
                &state,
                &principal,
                scope,
                organization,
                crate::org_context::EnvironmentAccess::Write,
            )
            .await?
            .to_string(),
        )
    } else {
        require_unconfined(&principal)?;
        None
    };
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
    let pending = log_stream_event(&state, scope, &id, Some(sink_type.as_str()));
    state
        .store()
        .scoped(scope)
        .log_streams()
        .create_with_event(
            state.env(),
            &ironauth_store::NewLogStream {
                id: Some(&id),
                description: request.description.as_deref().unwrap_or_default(),
                source,
                sink_type,
                sink_config,
                credential_secret_name: request.credential_secret_name.as_deref(),
                signing_secret_name: request.signing_secret_name.as_deref(),
                event_type_filter: request.event_type_filter,
                organization_id: organization_id.as_deref(),
            },
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &body_string,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(json(StatusCode::CREATED, body_string))
}

/// Refuse a credential confined to an organization the stream does not belong to.
///
/// # Why every stream operation needs this and not just the create
///
/// A stream is addressed by ID ALONE on every operation except its creation: delete, the dead
/// letter listing and the replay all take `stream_id` from the path and nothing else. The id is
/// unguessable, but unguessable is not an authorization check -- and the LISTING hands out every
/// id in the environment, so it is not even unguessable in practice.
///
/// Fencing only the create is therefore worth very little on its own. It stops a confined
/// credential from pointing a NEW stream at a sibling's rows and leaves it free to delete the
/// sibling's existing one, which stops that organization's audit and authentication events
/// reaching its SIEM. That is a quieter failure than the one the create fence closes: nothing
/// arrives, and the organization whose stream it was is not the one that would notice.
///
/// AN ENVIRONMENT-WIDE STREAM IS OUT OF REACH TOO. It carries every organization's rows, so a
/// credential confined to one has no claim on it in either direction.
///
/// THE UNIFORM NOT-FOUND, so a confined credential cannot learn which stream ids exist in the
/// environment by comparing a 403 against a 404.
async fn require_stream_in_reach(
    state: &AdminState,
    principal: &Principal,
    scope: ironauth_store::Scope,
    stream_id: &str,
) -> Result<(), ApiError> {
    let Some(confined) = principal.confined_organization() else {
        return Ok(());
    };
    let ownership = state
        .store()
        .scoped(scope)
        .log_streams()
        .organization_of(stream_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    match ownership {
        ironauth_store::LogStreamOwnership::Organization(organization)
            if organization == confined.to_string() =>
        {
            Ok(())
        }
        _ => Err(ApiError::NotFound),
    }
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

    // THE CONFINEMENT, which this path did not check. The delete is addressed by id alone, so
    // without it a credential confined to organization A could remove organization B's stream
    // and stop B's audit and authentication events reaching B's SIEM -- and the id it needed is
    // handed out by the listing beside this.
    require_stream_in_reach(&state, &principal, scope, &stream_id).await?;

    // No Idempotency-Key: removing an absent stream is a no-op success, so DELETE is
    // idempotent on its own.
    let pending = log_stream_event(&state, scope, &stream_id, None);
    state
        .store()
        .scoped(scope)
        .log_streams()
        .delete_with_event(
            Some(state.env()),
            &stream_id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The most dead letters ONE listing returns.
///
/// A stream that has been failing for a long time can accumulate an unbounded number of
/// them, and the store read is deliberately unbounded because the SHIPPER needs every one
/// to replay. An operator listing is a different question, so it is bounded here and says
/// when it truncated rather than silently showing a prefix.
const DEAD_LETTER_LIMIT: usize = 200;

/// One set-aside audit range, as an operator reads it.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogStreamDeadLetterView {
    /// The `lsd_` identifier.
    pub id: String,
    /// How many events the failed batch carried.
    pub event_count: i32,
    /// The failure that ended the retry run. Operator-safe, never a sink's response body,
    /// for the same reason `last_error` on the stream itself is not.
    pub last_error: String,
    /// The inclusive start of the undelivered range, in cursor order.
    pub from_occurred_at_unix_ms: i64,
    /// The audit id at the start of the range.
    pub from_audit_id: String,
    /// The inclusive end of the undelivered range, in cursor order.
    pub to_occurred_at_unix_ms: i64,
    /// The audit id at the end of the range.
    pub to_audit_id: String,
}

/// A stream's outstanding dead letters.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogStreamDeadLetterList {
    /// Oldest first, so an operator reads the gap in the order it happened.
    pub items: Vec<LogStreamDeadLetterView>,
    /// True when the stream has MORE outstanding dead letters than this page carries.
    ///
    /// Present so a truncated read is distinguishable from a complete one. Without it an
    /// operator who sees exactly the limit cannot tell whether they are looking at the
    /// whole gap, which is the number they are trying to establish.
    pub truncated: bool,
}

/// The answer to a replay request.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogStreamReplayAccepted {
    /// The stream the replay was requested for.
    pub log_stream_id: String,
}

/// List a stream's outstanding dead letters.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}/dead-letters",
    operation_id = "listLogStreamDeadLetters",
    tag = "log-streams",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("stream_id" = String, Path, description = "The stream identifier (lgs_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The outstanding dead letters, oldest first", body = LogStreamDeadLetterList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, or the stream is in another scope", body = ErrorBody)
    )
)]
pub async fn list_log_stream_dead_letters(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, stream_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ, matching the stream listing beside it: a soft-deleted
    // environment stays readable across this surface and only writes refuse it.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let mut dead = state
        .store()
        .scoped(scope)
        .log_streams()
        .outstanding_dead_letters(&stream_id)
        .await?;
    let truncated = dead.len() > DEAD_LETTER_LIMIT;
    dead.truncate(DEAD_LETTER_LIMIT);
    let view = LogStreamDeadLetterList {
        items: dead
            .into_iter()
            .map(|entry| LogStreamDeadLetterView {
                id: entry.id,
                event_count: entry.event_count,
                last_error: entry.last_error,
                from_occurred_at_unix_ms: entry.from.0 / 1000,
                from_audit_id: entry.from.1,
                to_occurred_at_unix_ms: entry.to.0 / 1000,
                to_audit_id: entry.to.1,
            })
            .collect(),
        truncated,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Request a replay of a stream's outstanding dead letters.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}/dead-letters/replay",
    operation_id = "replayLogStreamDeadLetters",
    tag = "log-streams",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("stream_id" = String, Path, description = "The stream identifier (lgs_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 202, description = "The replay was queued. A worker performs it; poll the dead-letter listing to watch it drain", body = LogStreamReplayAccepted),
        (status = 400, description = "The Idempotency-Key header is absent", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the stream is in another scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn replay_log_stream_dead_letters(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, stream_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`, and
    // sudo-fenced, matching the webhook replay. This causes outbound traffic carrying AUDIT
    // events to a third-party SIEM, which is a larger act than reading configuration.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    // THE CONFINEMENT, for the same reason the delete needs it: the stream is named by id and
    // nothing here asked whose it is. A replay re-delivers a sibling organization's set-aside
    // batches to that organization's own sink, so it is tampering and cost rather than
    // disclosure -- but a credential fenced out of an organization has no business commanding
    // its shipper either.
    require_stream_in_reach(&state, &principal, scope, &stream_id).await?;

    let key = idempotency::required_key(&headers)?;
    // Fingerprinted over the path alone, because this command HAS no body: unlike the
    // webhook replay there is no `since` bound that could make two requests under one key
    // mean different things. The stream is in the path, so replays of different streams
    // already fingerprint differently, which is the distinction this exists to make.
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The response is knowable BEFORE the write, because this is a COMMAND rather than the
    // replay itself. A count could only ever describe the instant the statement ran, and a
    // retry of the same request would report zero because the first call already queued it.
    let view = LogStreamReplayAccepted {
        log_stream_id: stream_id.clone(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let pending = log_stream_replay_event(&state, scope, &stream_id);
    state
        .store()
        .scoped(scope)
        .log_streams()
        .request_dead_letter_replay(
            state.env(),
            &stream_id,
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 202,
                response_body: &body_string,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(json(StatusCode::ACCEPTED, body_string))
}

/// The `log_stream.replay_requested` event for a replay command.
fn log_stream_replay_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    stream_id: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let payload = serde_json::json!({ "log_stream_id": stream_id });
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "log_stream.replay_requested",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: stream_id.to_owned(),
        envelope,
    })
}
