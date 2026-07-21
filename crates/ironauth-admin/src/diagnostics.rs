// SPDX-License-Identifier: MIT OR Apache-2.0

//! The client authentication diagnostics read (issue #91, M9 flow inspector).
//!
//! `GET .../diagnostics/client-auth` surfaces the rich, structured record of WHY a
//! client authentication failed, kept OFF the wire. On the token endpoint every
//! client authentication failure returns the uniform, opaque `invalid_client` with
//! no oracle (issue #25); the specific reason, the assertion header key id and
//! algorithm, the derived clock skew bucket, and the bounded expectation hint are
//! recorded out of band into `client_auth_diagnostics` instead. This endpoint is the
//! admin read of that sink, so an operator can see the SPECIFIC failure (a bad
//! signature, an expired assertion, a clock skew, an audience mismatch, an unknown
//! kid, a disallowed algorithm) the wire response deliberately hides.
//!
//! Authorization is environment scoped, exactly like the other per environment
//! reads: the operator plane, or the environment's own management key, may read it
//! (the same `require_environment` gate). The read is IDOR safe by construction: the
//! scope comes from the path, `require_environment` fails LOUD on a wrong scope
//! management key, and the store read runs under forced row level security, so a
//! cross tenant or cross environment read resolves to no rows.
//!
//! The response exposes ONLY the safe, non secret diagnostic fields. That guarantee
//! is STRUCTURAL, not a filter here: the store record type
//! ([`ironauth_store::ClientAuthDiagnosticRecord`]) has no field capable of holding
//! an assertion body, a client secret, or a token, so a secret is not scrubbed on
//! the way out, it is unrepresentable. This view carries the same bounded fields
//! forward, never widening them.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{
    ClientAuthDiagnosticQuery, ClientAuthDiagnosticRecord, ClientAuthDiagnosticsRepo, Scope,
    TenantId,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;

/// One recorded client authentication failure diagnostic (issue #91).
///
/// Every field is a bounded, non secret datum the store record already holds: the
/// `client_id`, `key_id`, and `signing_alg` are attacker influenced but non secret
/// identifiers the failed attempt itself presented, and `reason`, `skew_seconds`,
/// and `expected` are derived, bounded cardinality values. There is deliberately NO
/// field for an assertion body, a secret, or a token: the wire response stayed the
/// opaque `invalid_client`, and this record is the ONLY additional detail.
#[derive(Serialize, ToSchema)]
pub struct ClientAuthDiagnosticView {
    /// The client identifier the failed attempt claimed.
    pub client_id: String,
    /// The token endpoint authentication method the attempt used.
    pub auth_method: String,
    /// The bounded cardinality failure reason (for example `assertion_bad_signature`,
    /// `assertion_expired`, `assertion_clock_skew`, `assertion_audience_mismatch`,
    /// `assertion_kid_unknown`, `assertion_algorithm_disallowed`, `bad_secret`).
    pub reason: String,
    /// The assertion header `kid`, if the attempt presented a JWT assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The assertion header `alg`, if the attempt presented a JWT assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_alg: Option<String>,
    /// The derived, bounded clock skew bucket in seconds, if recorded: how far the
    /// presented `exp`/`nbf` fell outside the tolerance window (positive = expired
    /// past the window, negative = not yet valid). Never the assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skew_seconds: Option<i64>,
    /// The derived, bounded expectation hint, if recorded (for example
    /// `kid_not_in_registered_jwks`). Never the JWKS and never a key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// When the failed attempt happened, unix microseconds from the application clock.
    pub occurred_at_unix_micros: i64,
}

impl From<ClientAuthDiagnosticRecord> for ClientAuthDiagnosticView {
    fn from(record: ClientAuthDiagnosticRecord) -> Self {
        Self {
            client_id: record.client_id,
            auth_method: record.auth_method,
            reason: record.failure_reason,
            key_id: record.key_id,
            signing_alg: record.signing_alg,
            skew_seconds: record.skew_seconds,
            expected: record.expected,
            occurred_at_unix_micros: record.occurred_at_micros,
        }
    }
}

/// A page of recorded client authentication diagnostics (issue #91).
#[derive(Serialize, ToSchema)]
pub struct ClientAuthDiagnosticsList {
    /// The diagnostics matching the query, oldest first, bounded by the limit.
    pub items: Vec<ClientAuthDiagnosticView>,
}

/// The filter parameters of the diagnostics read (issue #91).
///
/// Every filter NARROWS within the caller's scope; none can widen past it. The three
/// integer params are deserialized as raw strings and parsed below (not as typed
/// `i64`) so a malformed value surfaces as the structured [`ApiError::BadRequest`]
/// JSON body rather than axum's plain text query rejection, exactly as the shared
/// pagination `limit` does. The OpenAPI schema still documents them as integers via
/// `#[param(value_type = ...)]`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ClientAuthDiagnosticsQuery {
    /// Restrict to one client identifier, or absent for every client in scope.
    pub client_id: Option<String>,
    /// Only failures at or after this instant, unix microseconds. Absent for no lower
    /// bound.
    #[param(value_type = Option<i64>)]
    pub since: Option<String>,
    /// Only failures strictly before this instant, unix microseconds. Absent for no
    /// upper bound.
    #[param(value_type = Option<i64>)]
    pub until: Option<String>,
    /// The maximum number of rows to return, a positive integer. Clamped to the
    /// repository's hard ceiling ([`ClientAuthDiagnosticsRepo::MAX_QUERY_LIMIT`]), so
    /// a caller can never request an unbounded scan. Defaults to that ceiling.
    #[param(value_type = Option<i64>)]
    pub limit: Option<String>,
}

/// Parse an optional integer query value, mapping a malformed value to a structured
/// bad request naming the offending field (never axum's plain text rejection).
fn parse_optional_i64(raw: Option<&str>, field: &str) -> Result<Option<i64>, ApiError> {
    match raw {
        None => Ok(None),
        Some(value) => value
            .parse::<i64>()
            .map(Some)
            .map_err(|_| ApiError::BadRequest(format!("{field} must be an integer"))),
    }
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids through
/// the management repositories (a malformed id is the uniform not found).
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(TenantId, Scope), ApiError> {
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
    Ok((tenant, Scope::new(tenant, environment)))
}

/// Read the environment's recorded client authentication failure diagnostics.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/client-auth",
    operation_id = "getClientAuthDiagnostics",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ClientAuthDiagnosticsQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's recorded client authentication failure \
         diagnostics, oldest first, filtered by client and time window and bounded to at most 500 \
         rows. Each carries only the safe, non secret fields the store record holds: the specific \
         failure reason, the assertion key id and algorithm, the derived clock skew bucket, and the \
         expectation hint. The token endpoint's wire response for every one of these failures stays \
         the uniform, opaque invalid_client.", body = ClientAuthDiagnosticsList),
        (status = 400, description = "A malformed filter value", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn get_client_auth_diagnostics(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ClientAuthDiagnosticsQuery>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Environment scoped read: the operator plane, or the environment's own management
    // key, may read its client authentication diagnostics. A wrong scope key fails LOUD
    // here; the forced row level security on the store read is the IDOR backstop.
    principal.require_environment(tenant, scope.environment())?;

    let since = parse_optional_i64(query.since.as_deref(), "since")?;
    let until = parse_optional_i64(query.until.as_deref(), "until")?;
    let limit = parse_optional_i64(query.limit.as_deref(), "limit")?;

    let records = state
        .store()
        .scoped(scope)
        .client_auth_diagnostics()
        .query(ClientAuthDiagnosticQuery {
            client_id: query.client_id.as_deref(),
            occurred_at_or_after_micros: since,
            occurred_before_micros: until,
            // The repository clamps this to MAX_QUERY_LIMIT (referenced so the ceiling
            // stays a single source of truth), so even an out of range request is bounded.
            limit: limit.or(Some(ClientAuthDiagnosticsRepo::MAX_QUERY_LIMIT)),
        })
        .await?;

    let list = ClientAuthDiagnosticsList {
        items: records
            .into_iter()
            .map(ClientAuthDiagnosticView::from)
            .collect(),
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
