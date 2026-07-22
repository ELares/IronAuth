// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment custom-journey version management (issue #92, PR 5).
//!
//! The management surface for the declarative-journey version registry: create a new immutable
//! version of a journey, get and list a journey's versions, and PIN the active version a fresh
//! custom flow is created against. A custom-journey version is a DATA-plane scoped resource
//! (`flow_versions` / `flow_version_pins`), reachable by the operator OR by a management key
//! scoped to exactly this environment (the same authorization as environment reads), exactly like
//! locales and signup forms.
//!
//! Every create is validated LOAD-VALID against the journey engine before it is stored: the
//! artifact must parse and COMPILE (known step kinds and node groups, no dangling or ambiguous
//! transition, no unreachable step or dead end, and a reachable completion). A load-invalid
//! artifact is a loud 400 naming the offending RFC 6901 location and reason, never a caller value,
//! so a rejection carries no secret and nothing is stored. A version is IMMUTABLE once written (a
//! change is a new version), so there is no overwrite and no delete: the registry is append-only.
//! Pinning is the only mutation of the active pointer, and a live flow keeps the version stamped
//! on its row regardless of where the pin moves.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_journey::Journey;
use ironauth_store::{
    CorrelationId, FlowVersionId, FlowVersionRecord, IdempotencyWrite, NewFlowVersion, Scope,
    StoreError, validate_journey_artifact,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::response::json;
use crate::state::AdminState;
use crate::views::{CreateFlowVersionRequest, FlowVersionView};

/// The largest a journey id path segment may be. An author-facing journey id is a short slug; this
/// bound (generous for any real journey) keeps a management key holder from keying a version on a
/// huge string.
const MAX_JOURNEY_ID_BYTES: usize = 128;

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #92). The operator
/// passes; a management key must be scoped to exactly this environment (otherwise the LOUD
/// wrong-scope error). A malformed tenant or environment id is the uniform not-found.
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Normalize the `{journey_id}` path parameter to a validated author-facing journey id, or the
/// uniform not-found for a malformed id (a malformed journey id names no journey, so it is
/// indistinguishable from an absent one). A journey id is a bounded slug of ASCII alphanumerics,
/// `_`, `-`, or `.`, so it can never smuggle SQL wildcards or path separators.
fn parse_journey_id(raw: &str) -> Result<String, ApiError> {
    let ok = !raw.is_empty()
        && raw.len() <= MAX_JOURNEY_ID_BYTES
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
    if ok {
        Ok(raw.to_owned())
    } else {
        Err(ApiError::NotFound)
    }
}

/// Normalize the `{version}` path parameter to a positive version number, or the uniform not-found
/// for a malformed or non-positive value (it names no version).
fn parse_version(raw: &str) -> Result<i32, ApiError> {
    match raw.parse::<i32>() {
        Ok(version) if version >= 1 => Ok(version),
        _ => Err(ApiError::NotFound),
    }
}

/// Parse and LOAD-VALID validate the submitted artifact (issue #92, PR 5): it must be a
/// well-formed journey document that COMPILES. Returns the canonical artifact JSON the store
/// persists on success; on failure a loud 400 naming the offending location and reason (never a
/// caller value). This is the SAME load-time gate the store applies on write, run here first so
/// the operator gets the precise reason.
fn validated_artifact(request: &CreateFlowVersionRequest) -> Result<String, ApiError> {
    let journey: Journey = serde_json::from_value(request.artifact.clone()).map_err(|error| {
        ApiError::BadRequest(format!(
            "journey artifact is not a well-formed journey document: {error}"
        ))
    })?;
    validate_journey_artifact(&journey).map_err(|errors| {
        let detail = errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        ApiError::BadRequest(format!("journey artifact is not load-valid: {detail}"))
    })?;
    serde_json::to_string(&request.artifact).map_err(|_| ApiError::Internal)
}

/// Build the API view of a stored version.
fn view_of(record: FlowVersionRecord) -> Result<FlowVersionView, ApiError> {
    let artifact: serde_json::Value =
        serde_json::from_str(&record.artifact_json).map_err(|_| ApiError::Internal)?;
    Ok(FlowVersionView {
        id: record.id,
        journey_id: record.journey_id,
        version: record.version,
        artifact,
        pinned: record.pinned,
    })
}

/// Create a new version of a custom journey.
///
/// This is a POST, not a PUT: it APPENDS a new immutable version (a server-assigned monotonic
/// version number), so it is NOT a PUT-to-a-fixed-resource upsert. Per the codebase convention it
/// REQUIRES an `Idempotency-Key`, wired through the shared idempotency path: a retry with the same
/// key REPLAYS the stored response (the SAME version number), so a client or network retry never
/// silently appends a duplicate version. A key reused with a different body is a 422.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions",
    operation_id = "createFlowVersion",
    tag = "flow-versions",
    request_body = CreateFlowVersionRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("journey_id" = String, Path, description = "The author-facing journey identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response (the same version) without appending a \
         duplicate.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The created version", body = FlowVersionView),
        (status = 400, description = "A load-invalid journey artifact", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed journey id", body = ErrorBody),
        (status = 409, description = "A concurrent create took the next version; retry", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_flow_version(
    State(state): State<AdminState>,
    principal: Principal,
    uri: Uri,
    headers: HeaderMap,
    Path((tenant_id, environment_id, journey_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Authoring a journey version changes WHICH orchestration a custom flow runs, a
    // security-relevant config surface, so it demands fresh privilege exactly like the other
    // environment-scoped management writes (locales, signup forms).
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let journey_id = parse_journey_id(&journey_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The environment must exist (a clean 404 rather than a foreign-key error).
    state
        .store()
        .management()
        .environments(scope.tenant())
        .get(&scope.environment())
        .await?;

    let request: CreateFlowVersionRequest = parse_json(&body)?;
    // Store ONLY the validated result: a load-invalid artifact is a loud 400 and nothing is
    // written.
    let artifact_json = validated_artifact(&request)?;

    // Resolve the id and the next version BEFORE the write so the response is fully known, then
    // store it under the idempotency key IN THE SAME transaction as the version and its audit row
    // (exactly like the other server-minted creates). The append-only unique index makes a
    // concurrent create of the same version fail (surfaced as a retriable 409), never a duplicate.
    let id = FlowVersionId::generate(state.env(), &scope);
    let version = state
        .store()
        .scoped(scope)
        .flow_versions()
        .next_version(&journey_id)
        .await?;
    let view = view_of(FlowVersionRecord {
        id: id.to_string(),
        journey_id: journey_id.clone(),
        version,
        artifact_json: artifact_json.clone(),
        pinned: false,
    })?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let created_at_micros = state.now_unix_micros();
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .flow_versions()
        .create_version(
            state.env(),
            &id,
            NewFlowVersion {
                journey_id: &journey_id,
                artifact_json: &artifact_json,
            },
            version,
            created_at_micros,
            Some(write),
        )
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // A concurrent create took the next version: retriable, not a duplicate or overwrite.
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a concurrent create took the next version of this journey; retry".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// List every version of a custom journey (ascending by version).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions",
    operation_id = "listFlowVersions",
    tag = "flow-versions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("journey_id" = String, Path, description = "The author-facing journey identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The journey's versions", body = [FlowVersionView]),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Malformed journey id", body = ErrorBody)
    )
)]
pub async fn list_flow_versions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, journey_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let journey_id = parse_journey_id(&journey_id)?;
    let records = state
        .store()
        .scoped(scope)
        .flow_versions()
        .list_for_journey(&journey_id)
        .await?;
    let views = records
        .into_iter()
        .map(view_of)
        .collect::<Result<Vec<_>, _>>()?;
    let body_string = serde_json::to_string(&views).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get one version of a custom journey by its version number.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions/{version}",
    operation_id = "getFlowVersion",
    tag = "flow-versions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("journey_id" = String, Path, description = "The author-facing journey identifier"),
        ("version" = i32, Path, description = "The version number")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The version", body = FlowVersionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_flow_version(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, journey_id, version)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let journey_id = parse_journey_id(&journey_id)?;
    let version = parse_version(&version)?;
    let record = state
        .store()
        .scoped(scope)
        .flow_versions()
        .get_version(&journey_id, version)
        .await?
        .ok_or(ApiError::NotFound)?;
    let view = view_of(record)?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Pin a version of a custom journey as the active version (the version a fresh custom flow is
/// created against).
///
/// A mutating POST, so per the codebase convention it REQUIRES an `Idempotency-Key`: a retry with
/// the same key REPLAYS the stored response without re-writing the pin (and pinning is naturally
/// idempotent on the target version anyway).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions/{version}/pin",
    operation_id = "pinFlowVersion",
    tag = "flow-versions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("journey_id" = String, Path, description = "The author-facing journey identifier"),
        ("version" = i32, Path, description = "The version number to pin"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The now-pinned version", body = FlowVersionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The version does not exist in this scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn pin_flow_version(
    State(state): State<AdminState>,
    principal: Principal,
    uri: Uri,
    headers: HeaderMap,
    Path((tenant_id, environment_id, journey_id, version)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Moving the active pin changes which version a fresh custom flow runs, a security-relevant
    // config surface, so it demands fresh privilege exactly like a version create.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let journey_id = parse_journey_id(&journey_id)?;
    let version = parse_version(&version)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Resolve the target version BEFORE the pin so the response (the now-pinned version) is fully
    // known and can be stored under the idempotency key in the SAME transaction as the pin. A
    // version's artifact is immutable, so reading it before the pin gives the correct body.
    let record = state
        .store()
        .scoped(scope)
        .flow_versions()
        .get_version(&journey_id, version)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut view = view_of(record)?;
    view.pinned = true;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let now_micros = state.now_unix_micros();
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .flow_versions()
        .pin(state.env(), &journey_id, version, now_micros, Some(write))
        .await;
    match result {
        Ok(_) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

// A version is immutable and never deleted (a change is a new version), so the append-only
// registry deliberately exposes no delete surface.

#[cfg(test)]
mod tests {
    use super::{parse_journey_id, parse_version};
    use crate::error::ApiError;

    #[test]
    fn a_well_formed_journey_id_parses_and_a_malformed_one_is_a_uniform_not_found() {
        assert_eq!(
            parse_journey_id("login_basic").expect("valid"),
            "login_basic"
        );
        assert_eq!(
            parse_journey_id("my-journey.v2").expect("valid"),
            "my-journey.v2"
        );
        // An empty id, an oversize id, or one carrying an unsafe character is the uniform not-found.
        assert!(matches!(parse_journey_id(""), Err(ApiError::NotFound)));
        assert!(matches!(
            parse_journey_id("has spaces"),
            Err(ApiError::NotFound)
        ));
        assert!(matches!(
            parse_journey_id("wild%card"),
            Err(ApiError::NotFound)
        ));
        assert!(matches!(
            parse_journey_id(&"x".repeat(super::MAX_JOURNEY_ID_BYTES + 1)),
            Err(ApiError::NotFound)
        ));
    }

    #[test]
    fn a_positive_version_parses_and_a_non_positive_or_malformed_one_is_a_uniform_not_found() {
        assert_eq!(parse_version("1").expect("valid"), 1);
        assert_eq!(parse_version("42").expect("valid"), 42);
        assert!(matches!(parse_version("0"), Err(ApiError::NotFound)));
        assert!(matches!(parse_version("-3"), Err(ApiError::NotFound)));
        assert!(matches!(parse_version("nope"), Err(ApiError::NotFound)));
    }
}
