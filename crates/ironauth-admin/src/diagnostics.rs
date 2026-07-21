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

use axum::extract::{Json, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_oidc::RiskLevel;
use ironauth_oidc::flow::inspect::{
    self, DryRunInput, DryRunProjection, ObserveProjection, RiskInput, RiskSignalInput,
};
use ironauth_oidc::flow::model::{Journey, NodeAttributes};
use ironauth_store::{
    ClientAuthDiagnosticQuery, ClientAuthDiagnosticRecord, ClientAuthDiagnosticsRepo, FlowId,
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

// ===========================================================================
// The flow inspector (issue #91, PR4): the read only OBSERVE projection over an
// existing flow, and the zero side effect DRY REPLAY policy dry run.
//
// Neither endpoint mutates a flow: OBSERVE does ONE scoped, RLS forced read of the
// flow row and projects it read only (never calling the mutating flow engine), and the
// DRY REPLAY carries a supplied context, evaluates the REAL step up and risk evaluators
// with every write disabled (the pure `ironauth_oidc::flow::inspect` module holds no
// store handle), and writes NO row anywhere. Both are environment scoped and IDOR safe
// exactly like the reads above: the scope comes from the path, `require_environment`
// fails LOUD on a wrong scope key, and the store read runs under forced row level
// security, so a foreign flow id resolves to a uniform not found.
// ===========================================================================

/// Serialize a bounded enum value (a journey, a transport, a state tag, a node group)
/// to its stable wire string through serde, so the admin projection never re encodes the
/// engine's vocabulary by hand (no drift from the flow contract).
fn wire_str<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The redacted flow context projection surfaced by the inspector (issue #91): only safe
/// fields. The recovery identifier (a PII contact) is reduced to `has_identifier`, and the
/// flow submit token is not representable here at all.
#[derive(Serialize, ToSchema)]
pub struct FlowContextResponse {
    /// The current state machine step.
    pub step: String,
    /// The proven auth method tokens so far (for example `["pwd"]`), the honest amr source.
    pub methods: Vec<String>,
    /// The blind internal `usr_` subject handle, or absent before a primary factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Whether a recovery identifier is held server side (never its PII value).
    pub has_identifier: bool,
    /// Whether a second factor enrollment is pending (never its credential id or secret).
    pub enrolling: bool,
    /// The federation connector slug (non secret), or absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector: Option<String>,
}

impl From<inspect::FlowContextView> for FlowContextResponse {
    fn from(context: inspect::FlowContextView) -> Self {
        Self {
            step: wire_str(context.step),
            methods: context.methods,
            subject: context.subject,
            has_identifier: context.has_identifier,
            enrolling: context.enrolling,
            connector: context.connector,
        }
    }
}

/// One node of the current node render (issue #91): its group, its typed kind, and the form
/// field name for an input. A compact projection of the flow object's `ui.nodes`, never a
/// secret (no prefilled value is carried).
#[derive(Serialize, ToSchema)]
pub struct FlowNodeView {
    /// The node group (for example `default`, `password`, `totp`).
    pub group: String,
    /// The node kind (`input` or `text`).
    pub kind: String,
    /// The form field name, for an input node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The OBSERVE projection of an existing flow (issue #91): its current position, the plan it
/// sits within, the redacted context, the current node render, and any recorded policy
/// traces for its subject (from PR3).
#[derive(Serialize, ToSchema)]
pub struct FlowObserveResponse {
    /// The flow id (a scope embedded `flw_` id, non secret).
    pub flow_id: String,
    /// The journey this flow drives.
    pub journey: String,
    /// The transport it was created on.
    pub transport: String,
    /// The journey plan (the ordered state sequence, from the ONE transition table the
    /// engine shares).
    pub plan: Vec<String>,
    /// The current state machine position.
    pub current: String,
    /// Whether the single use completion latch has tripped.
    pub completed: bool,
    /// Whether the flow has expired at the observation instant.
    pub expired: bool,
    /// The redacted flow context.
    pub context: FlowContextResponse,
    /// The current node render (a compact projection of the flow object's nodes).
    pub nodes: Vec<FlowNodeView>,
    /// The recorded policy decision traces for this flow's subject (from PR3), newest first.
    pub traces: Vec<PolicyTraceView>,
}

impl FlowObserveResponse {
    /// Build the response from the read only projection plus the subject's recorded traces.
    fn build(projection: ObserveProjection, traces: Vec<PolicyTraceView>) -> Self {
        let nodes = projection
            .node_render
            .ui
            .nodes
            .iter()
            .map(|node| {
                let (kind, name) = match &node.attributes {
                    NodeAttributes::Input { name, .. } => ("input", Some(name.clone())),
                    NodeAttributes::Text { .. } => ("text", None),
                };
                FlowNodeView {
                    group: wire_str(node.group),
                    kind: kind.to_owned(),
                    name,
                }
            })
            .collect();
        Self {
            flow_id: projection.flow_id,
            journey: wire_str(projection.journey),
            transport: wire_str(projection.transport),
            plan: projection.plan.steps.iter().map(|s| wire_str(*s)).collect(),
            current: wire_str(projection.current),
            completed: projection.completed,
            expired: projection.expired,
            context: projection.context.into(),
            nodes,
            traces,
        }
    }
}

/// OBSERVE an existing flow read only (issue #91): the flow's current position, plan,
/// redacted context, node render, and recorded policy traces. NEVER mutates the flow.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/{flow_id}",
    operation_id = "getFlowObservation",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("flow_id" = String, Path, description = "The flow identifier to observe")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The read only observation of the flow: its current state, \
         the journey plan (the ordered state sequence from the one transition table the engine \
         shares), a structurally redacted projection of its persisted context (the step, the \
         proven method tokens, the blind subject handle; never a submit token or the recovery \
         identifier PII), the current node render, and the recorded policy decision traces for \
         its subject. This read never calls the mutating flow engine.", body = FlowObserveResponse),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment or flow not found", body = ErrorBody)
    )
)]
pub async fn get_flow_observation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, flow_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Environment scoped read: the operator plane, or the environment's own management key,
    // may observe its flows. A wrong scope key fails LOUD here; the forced row level security
    // on the store read is the IDOR backstop.
    principal.require_environment(tenant, scope.environment())?;

    // A malformed or cross scope flow id is the UNIFORM not found (never an oracle): the id
    // carries its own scope, and `parse_in_scope` rejects one that does not match the path.
    let parsed = FlowId::parse_in_scope(&flow_id, &scope).map_err(|_| ApiError::NotFound)?;
    let record = state
        .store()
        .scoped(scope)
        .flows()
        .load(&parsed)
        .await?
        .ok_or(ApiError::NotFound)?;

    let now = state.now_unix_micros();
    // A malformed stored row is a uniform not found too (never a 500, never an oracle).
    let projection = inspect::observe(&record, scope, now).map_err(|_| ApiError::NotFound)?;

    // The recorded policy decision traces for this flow's subject (from PR3), newest first,
    // for the "why did the policy decide this" context alongside the plan. Absent a subject
    // (a pre primary factor flow) there is nothing to key on, so the traces are empty.
    let traces = match projection.context.subject.as_deref() {
        Some(subject) => state
            .store()
            .scoped(scope)
            .policy_decision_traces()
            .query(PolicyDecisionTraceQuery {
                policy: None,
                subject: Some(subject),
                occurred_at_or_after_micros: None,
                occurred_before_micros: None,
                limit: Some(PolicyDecisionTracesRepo::MAX_QUERY_LIMIT),
                newest_first: true,
            })
            .await?
            .into_iter()
            .map(PolicyTraceView::from)
            .collect(),
        None => Vec::new(),
    };

    let response = FlowObserveResponse::build(projection, traces);
    let body = serde_json::to_string(&response).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// A supplied risk signal for a flow dry run (issue #91): the operator's what if scenario.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RiskSignalRequest {
    /// The signal name (mapped to the engine's bounded vocabulary; an unknown name folds to
    /// `external_signal`).
    pub name: String,
    /// The signal's contribution level (`low` / `med` / `high`).
    pub level: String,
    /// Whether this signal alone justifies a block (a hard deny). Defaults to false.
    #[serde(default)]
    pub hard_deny: bool,
}

/// The risk scenario a flow dry run evaluates (issue #91): the supplied signals plus the
/// deployment posture switches. Every field is optional; the defaults mirror the shipped
/// risk config (`block_on_high` on, `notify_on_new_device` on, no forced threshold).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct RiskScenarioRequest {
    /// The supplied signals (the what if scenario).
    #[serde(default)]
    pub signals: Vec<RiskSignalRequest>,
    /// Whether a new device fired.
    #[serde(default)]
    pub new_device: bool,
    /// The step up threshold the score is compared against (`off` / `low` / `med` / `high`),
    /// or absent for "never force".
    #[serde(default)]
    pub require_mfa_at: Option<String>,
    /// Whether a hard deny blocks (defaults to true).
    #[serde(default)]
    pub block_on_high: Option<bool>,
    /// Whether a new device notifies (defaults to true).
    #[serde(default)]
    pub notify_on_new_device: Option<bool>,
}

/// The flow dry run request (issue #91): a supplied context to replay through a journey's
/// plan. It is evaluated with EVERY write disabled and MUST write nothing.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct FlowDryRunRequest {
    /// The journey whose plan to walk (`login`, `registration`, `recovery`, `federation`).
    pub journey: String,
    /// The subject the context carries (a blind `usr_` handle), or absent.
    #[serde(default)]
    pub subject: Option<String>,
    /// The required acr floor (an alias like `mfa` or a full canonical acr), or absent.
    #[serde(default)]
    pub required_acr: Option<String>,
    /// The achieved acr the supplied authentication reached.
    pub achieved_acr: String,
    /// The maximum authentication age in seconds the requirement imposes, or absent.
    #[serde(default)]
    pub max_auth_age_secs: Option<u64>,
    /// The recorded authentication instant in unix microseconds, or absent (which fails an
    /// age bound closed).
    #[serde(default)]
    pub auth_time_unix_micros: Option<i64>,
    /// The clock instant to evaluate against, or absent for the current server clock.
    #[serde(default)]
    pub now_unix_micros: Option<i64>,
    /// The acr order to compare under, or absent for the canonical deployment ladder.
    #[serde(default)]
    pub acr_order: Option<Vec<String>>,
    /// The risk scenario, or absent to skip the risk evaluator.
    #[serde(default)]
    pub risk: Option<RiskScenarioRequest>,
}

/// The step up requirement evaluation projection (issue #91), from the REAL evaluator.
#[derive(Serialize, ToSchema)]
pub struct StepUpDecisionResponse {
    /// The bounded outcome (`satisfied` or `step_up_required`).
    pub outcome: String,
    /// Whether the achieved acr did not satisfy the floor.
    pub acr_unmet: bool,
    /// Whether the authentication age window lapsed.
    pub age_lapsed: bool,
    /// The required acr floor, or absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_acr: Option<String>,
    /// The achieved acr the evaluation compared.
    pub achieved_acr: String,
}

/// A contributing risk signal projection (issue #91): the name and level only (redacted).
#[derive(Serialize, ToSchema)]
pub struct RiskSignalResponse {
    /// The signal name.
    pub name: String,
    /// The signal's contribution level.
    pub level: String,
}

/// The risk decision projection (issue #91), from the REAL compute core.
#[derive(Serialize, ToSchema)]
pub struct RiskDecisionResponse {
    /// The combined level (`low` / `med` / `high`).
    pub level: String,
    /// The dispatched action (`allow` / `block` / `challenge` / `notify`).
    pub action: String,
    /// Whether the new device signal fired.
    pub new_device_fired: bool,
    /// The contributing signals, name and level only.
    pub signals: Vec<RiskSignalResponse>,
}

/// One evaluated step of the dry replay (issue #91).
#[derive(Serialize, ToSchema)]
pub struct FlowDryRunStep {
    /// The plan state this step is.
    pub step: String,
    /// Whether the supplied scenario reaches this state.
    pub reached: bool,
    /// The policy that governs the transition out of this step, or absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// The step up requirement evaluation at this step, when it governs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUpDecisionResponse>,
    /// The risk decision at this step, when it governs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskDecisionResponse>,
    /// The redacted context at this step.
    pub context: FlowContextResponse,
}

/// The flow dry run response (issue #91): the plan, the per step evaluations, and the
/// terminal state the supplied scenario reaches. ZERO rows were written to produce it.
#[derive(Serialize, ToSchema)]
pub struct FlowDryRunResponse {
    /// The journey walked.
    pub journey: String,
    /// The journey plan (the ordered state sequence).
    pub plan: Vec<String>,
    /// The terminal state the supplied scenario reaches.
    pub terminal: String,
    /// The per step evaluations.
    pub steps: Vec<FlowDryRunStep>,
}

impl From<DryRunProjection> for FlowDryRunResponse {
    fn from(projection: DryRunProjection) -> Self {
        let steps = projection
            .steps
            .into_iter()
            .map(|step| FlowDryRunStep {
                step: wire_str(step.step),
                reached: step.reached,
                policy: step.policy,
                step_up: step.step_up.map(|view| StepUpDecisionResponse {
                    outcome: view.outcome,
                    acr_unmet: view.acr_unmet,
                    age_lapsed: view.age_lapsed,
                    required_acr: view.required_acr,
                    achieved_acr: view.achieved_acr,
                }),
                risk: step.risk.map(|view| RiskDecisionResponse {
                    level: view.level,
                    action: view.action,
                    new_device_fired: view.new_device_fired,
                    signals: view
                        .signals
                        .into_iter()
                        .map(|signal| RiskSignalResponse {
                            name: signal.name,
                            level: signal.level,
                        })
                        .collect(),
                }),
                context: step.context.into(),
            })
            .collect();
        Self {
            journey: wire_str(projection.journey),
            plan: projection.plan.steps.iter().map(|s| wire_str(*s)).collect(),
            terminal: wire_str(projection.terminal),
            steps,
        }
    }
}

/// DRY REPLAY a supplied context through a journey's plan (issue #91): evaluate the REAL step
/// up and risk evaluators with EVERY write disabled and project the reachable path. Despite
/// the POST verb this is READ ONLY / SIDE EFFECT FREE: it carries a context body but writes
/// NO row anywhere (no flow, session, risk, jti, or trace row). The `POST` is only because
/// the supplied context does not fit a URL.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/dry-run",
    operation_id = "postFlowDryRun",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    request_body = FlowDryRunRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The dry replay of the supplied context: the journey plan, \
         the per step evaluations of the REAL step up and risk evaluators (with every write \
         disabled), and the terminal state the scenario reaches. This is SIDE EFFECT FREE / read \
         only despite the POST verb: it writes no flow, session, risk, jti, or trace row \
         anywhere. The evaluators are the SAME ones the live path runs, so the decisions match \
         the live path for the same inputs.", body = FlowDryRunResponse),
        (status = 400, description = "A malformed request body or journey", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn post_flow_dry_run(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Json(request): Json<FlowDryRunRequest>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    principal.require_environment(tenant, scope.environment())?;

    let journey = Journey::parse(&request.journey).ok_or_else(|| {
        ApiError::BadRequest(
            "journey must be one of login, registration, recovery, federation, mfa".to_owned(),
        )
    })?;
    // The clock instant: the supplied value, or the current server clock.
    let now = request
        .now_unix_micros
        .unwrap_or_else(|| state.now_unix_micros());

    let risk = request.risk.map(|scenario| RiskInput {
        signals: scenario
            .signals
            .into_iter()
            .map(|signal| RiskSignalInput {
                name: signal.name,
                level: RiskLevel::parse_threshold(&signal.level).unwrap_or(RiskLevel::Low),
                hard_deny: signal.hard_deny,
            })
            .collect(),
        new_device_fired: scenario.new_device,
        threshold: scenario
            .require_mfa_at
            .as_deref()
            .and_then(RiskLevel::parse_threshold),
        block_on_high: scenario.block_on_high.unwrap_or(true),
        notify_on_new_device: scenario.notify_on_new_device.unwrap_or(true),
    });

    let input = DryRunInput {
        journey,
        subject: request.subject,
        required_acr: request.required_acr,
        achieved_acr: request.achieved_acr,
        max_auth_age_secs: request.max_auth_age_secs,
        auth_time_micros: request.auth_time_unix_micros,
        now_micros: now,
        order: request.acr_order,
        risk,
    };

    // The dry replay is pure: it holds no store handle and writes nothing.
    let projection = inspect::dry_run(&input);
    let response = FlowDryRunResponse::from(projection);
    let body = serde_json::to_string(&response).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
