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
    ClientAuthDiagnosticQuery, ClientAuthDiagnosticRecord, ClientAuthDiagnosticsRepo,
    PolicyDecisionTraceQuery, PolicyDecisionTraceRecord, PolicyDecisionTracesRepo, Scope, TenantId,
    TokenSizeEventsRepo,
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
    /// The diagnostics matching the query, NEWEST first, bounded by the limit, so a
    /// capped result keeps the most recent failures (what a live incident is about).
    pub items: Vec<ClientAuthDiagnosticView>,
    /// True when the result hit the limit and older matching failures were left out;
    /// the operator should narrow the client or time window (never a silent truncation).
    pub truncated: bool,
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

    // The effective limit the repository will apply (the request value clamped to the
    // ceiling, or the ceiling by default). The result is truncated when it fills it.
    let effective_limit = limit
        .unwrap_or(ClientAuthDiagnosticsRepo::MAX_QUERY_LIMIT)
        .clamp(0, ClientAuthDiagnosticsRepo::MAX_QUERY_LIMIT);
    let records = state
        .store()
        .scoped(scope)
        .client_auth_diagnostics()
        .query(ClientAuthDiagnosticQuery {
            client_id: query.client_id.as_deref(),
            occurred_at_or_after_micros: since,
            occurred_before_micros: until,
            limit: Some(effective_limit),
            // Newest first so a capped result keeps the most recent failures, not the
            // oldest: an operator debugging a live failure wants what just happened.
            newest_first: true,
        })
        .await?;

    let truncated =
        i64::try_from(records.len()).unwrap_or(i64::MAX) >= effective_limit && effective_limit > 0;
    let list = ClientAuthDiagnosticsList {
        items: records
            .into_iter()
            .map(ClientAuthDiagnosticView::from)
            .collect(),
        truncated,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

// ===========================================================================
// Policy decision traces (issue #91): the step up, risk, and claim mapping traces.
// ===========================================================================

/// One recorded policy decision trace (issue #91).
///
/// Every field is a bounded, non secret datum the store record already holds: `policy`
/// and `outcome` are closed sets, `subject` is an internal usr_ handle (a blind
/// reference, never raw PII), `reason` is a bounded hint, and `decision_inputs` is the
/// STRUCTURALLY REDACTED safe field projection (the acr floor and achieved acr, the auth
/// age, the risk signal names and levels, the connector slug and the mapped trait count),
/// serialized as a JSON string. There is deliberately NO field capable of holding a claim
/// value, a token, or a secret: those are unrepresentable in the record this view carries.
#[derive(Serialize, ToSchema)]
pub struct PolicyTraceView {
    /// The traced policy (`step_up`, `risk`, or `claim_mapping`).
    pub policy: String,
    /// The bounded verdict (`satisfied`, `step_up_required`, or `deny`).
    pub outcome: String,
    /// The internal usr_ handle the decision was for, if any (a blind reference).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The bounded, non secret reason hint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The redacted, allowlisted safe field projection of the decision inputs, as a JSON
    /// string (rendered inertly by the console, never a claim value).
    pub decision_inputs: String,
    /// When the decision happened, unix microseconds from the application clock.
    pub occurred_at_unix_micros: i64,
}

impl From<PolicyDecisionTraceRecord> for PolicyTraceView {
    fn from(record: PolicyDecisionTraceRecord) -> Self {
        Self {
            policy: record.policy,
            outcome: record.outcome,
            subject: record.subject,
            reason: record.reason,
            decision_inputs: record.decision_inputs_json,
            occurred_at_unix_micros: record.occurred_at_micros,
        }
    }
}

/// A page of recorded policy decision traces (issue #91), newest first, truncation flagged.
#[derive(Serialize, ToSchema)]
pub struct PolicyTracesList {
    /// The traces matching the query, NEWEST first, bounded by the limit.
    pub items: Vec<PolicyTraceView>,
    /// True when the result hit the limit and older matching traces were left out.
    pub truncated: bool,
}

/// The filter parameters of the policy traces read (issue #91). Every filter NARROWS
/// within the caller's scope; none can widen past it.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PolicyTracesQuery {
    /// Restrict to one policy (`step_up`, `risk`, or `claim_mapping`), or absent for all.
    pub policy: Option<String>,
    /// Restrict to one subject (a usr_ handle), or absent for every subject in scope.
    pub subject: Option<String>,
    /// Only traces at or after this instant, unix microseconds. Absent for no lower bound.
    #[param(value_type = Option<i64>)]
    pub since: Option<String>,
    /// Only traces strictly before this instant, unix microseconds. Absent for no bound.
    #[param(value_type = Option<i64>)]
    pub until: Option<String>,
    /// The maximum number of rows to return, clamped to the repository ceiling.
    #[param(value_type = Option<i64>)]
    pub limit: Option<String>,
}

/// Read the environment's recorded policy decision traces (issue #91).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/policy-traces",
    operation_id = "getPolicyDecisionTraces",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        PolicyTracesQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's recorded policy decision traces (the step \
         up, risk, and claim mapping decisions), NEWEST first, filtered by policy and subject and \
         time window and bounded to at most 500 rows. Each carries only the safe, non secret \
         fields the store record holds: the closed policy and outcome, the blind subject handle, \
         the bounded reason, and the redacted safe field projection of the decision inputs.",
         body = PolicyTracesList),
        (status = 400, description = "A malformed filter value", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn get_policy_traces(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<PolicyTracesQuery>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Environment scoped read: the operator plane, or the environment's own management key,
    // may read its policy traces. A wrong scope key fails LOUD here; the forced row level
    // security on the store read is the IDOR backstop.
    principal.require_environment(tenant, scope.environment())?;

    let since = parse_optional_i64(query.since.as_deref(), "since")?;
    let until = parse_optional_i64(query.until.as_deref(), "until")?;
    let limit = parse_optional_i64(query.limit.as_deref(), "limit")?;

    let effective_limit = limit
        .unwrap_or(PolicyDecisionTracesRepo::MAX_QUERY_LIMIT)
        .clamp(0, PolicyDecisionTracesRepo::MAX_QUERY_LIMIT);
    let records = state
        .store()
        .scoped(scope)
        .policy_decision_traces()
        .query(PolicyDecisionTraceQuery {
            policy: query.policy.as_deref(),
            subject: query.subject.as_deref(),
            occurred_at_or_after_micros: since,
            occurred_before_micros: until,
            limit: Some(effective_limit),
            // Newest first so a capped result keeps the most recent decisions.
            newest_first: true,
        })
        .await?;

    let truncated =
        i64::try_from(records.len()).unwrap_or(i64::MAX) >= effective_limit && effective_limit > 0;
    let list = PolicyTracesList {
        items: records.into_iter().map(PolicyTraceView::from).collect(),
        truncated,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

// ===========================================================================
// Operational warnings (issue #91): COMPUTED LIVE from the existing seams.
// ===========================================================================

/// The recent upstream error rate at or above which a connector is warned as degraded.
const DEGRADED_ERROR_RATE: f64 = 0.5;

/// One operational warning item (issue #91): a bounded `kind`, the `subject` it is about
/// (a connector slug or a client id, non secret), and a safe `detail`. Every field is a
/// bounded, non secret datum; the detail never carries a claim value, a token, or a secret.
#[derive(Serialize, ToSchema)]
pub struct WarningItemView {
    /// The bounded warning kind (for example `connector_config_error`,
    /// `connector_unavailable`, `connector_degraded`, `token_size`).
    pub kind: String,
    /// The subject the warning is about (a connector slug or a client id), non secret.
    pub subject: String,
    /// A safe, bounded detail (a health counter, an error rate, a size summary). Never a
    /// claim value, a token, or a secret.
    pub detail: String,
}

/// The environment's operational warnings (issue #91), COMPUTED LIVE from the existing
/// seams (the connector health registry and the token size event sink). Nothing here is a
/// stored, staleness prone materialization except the token size events, which are already
/// bounded and retention pruned.
#[derive(Serialize, ToSchema)]
pub struct DiagnosticsWarningsList {
    /// The computed warnings, connector warnings first, then token size warnings.
    pub items: Vec<WarningItemView>,
}

/// Read the environment's operational warnings, computed live (issue #91).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/warnings",
    operation_id = "getDiagnosticsWarnings",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's operational warnings, computed live from \
         the connector health registry (a misconfigured, unreachable, or degraded upstream, which \
         is how a stale or expired connector cert or metadata manifests through the live probe) \
         and the token size (claim bloat) event sink. Each is a bounded kind, the non secret \
         subject, and a safe detail.", body = DiagnosticsWarningsList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn get_diagnostics_warnings(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    principal.require_environment(tenant, scope.environment())?;

    let mut items: Vec<WarningItemView> = Vec::new();

    // Connector health warnings: the live per connector health this node records (issue #76).
    // A misconfigured, unreachable, or degraded connector is where a stale or expired upstream
    // cert or metadata surfaces through the live probe, so this is the live computed source for
    // the connector health, reachability, staleness, and misconfiguration warning families.
    let connectors = state.store().scoped(scope).connectors().list_all().await?;
    for connector in &connectors {
        // Only warn about ACTIVE connectors; a disabled connector is not serving.
        if !connector.enabled {
            continue;
        }
        let Some(snapshot) =
            state.connector_health(&connector.id.to_string(), connector.updated_at_unix_micros)
        else {
            continue;
        };
        match snapshot.state {
            ironauth_oidc::HealthState::ConfigError => items.push(WarningItemView {
                kind: "connector_config_error".to_owned(),
                subject: connector.slug.clone(),
                detail: format!(
                    "the connector is failing a configuration check ({} consecutive failures)",
                    snapshot.consecutive_failures
                ),
            }),
            ironauth_oidc::HealthState::Unavailable => items.push(WarningItemView {
                kind: "connector_unavailable".to_owned(),
                subject: connector.slug.clone(),
                detail: format!(
                    "the upstream is unreachable ({} consecutive failures)",
                    snapshot.consecutive_failures
                ),
            }),
            ironauth_oidc::HealthState::Healthy | ironauth_oidc::HealthState::Unknown => {
                if snapshot.recent_error_rate >= DEGRADED_ERROR_RATE {
                    items.push(WarningItemView {
                        kind: "connector_degraded".to_owned(),
                        subject: connector.slug.clone(),
                        detail: format!(
                            "an elevated recent upstream error rate ({:.0}%)",
                            snapshot.recent_error_rate * 100.0
                        ),
                    });
                }
            }
        }
    }

    // Token size (claim bloat) warnings: the one materialized warning. Aggregate the recent
    // oversized mints per client into one warning, so a flood of large tokens for one client
    // is a single, legible item rather than hundreds.
    let events = state
        .store()
        .scoped(scope)
        .token_size_events()
        .recent(TokenSizeEventsRepo::MAX_QUERY_LIMIT)
        .await?;
    let mut per_client: std::collections::BTreeMap<String, (usize, i64)> =
        std::collections::BTreeMap::new();
    for event in &events {
        let entry = per_client.entry(event.client_id.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = entry.1.max(event.byte_size);
    }
    for (client_id, (count, max_bytes)) in per_client {
        items.push(WarningItemView {
            kind: "token_size".to_owned(),
            subject: client_id,
            detail: format!(
                "{count} recent ID token(s) exceeded the claim bloat threshold (largest \
                 {max_bytes} bytes)"
            ),
        });
    }

    let list = DiagnosticsWarningsList { items };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
