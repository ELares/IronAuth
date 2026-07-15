// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data-plane quota enforcement (issue #50).
//!
//! This is the request-path wiring for the [`ironauth_quota`] engine: it turns
//! the resolved persistence [`Scope`] into a quota spend and, when a scope is over
//! quota, produces the RFC 6585 `429 Too Many Requests` short-circuit carrying the
//! structured `RateLimit` headers, the legacy `X-RateLimit-*` triplet, the
//! machine-readable block signal, and (for a WAF that gates on a cookie) the
//! block-signal `Set-Cookie`.
//!
//! The nested tenant/environment fairness, the atomic check-and-charge, and the
//! fail-closed decision all live in the engine; this module only maps the store
//! scope onto the engine's scope, records the decision as a metric, surfaces any
//! usage-threshold event, and renders the denied response. A scope UNDER quota is
//! passed through untouched (no headers stamped on the success path).

use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use ironauth_quota::{
    EnvironmentId as QuotaEnvironmentId, QuotaDimension, QuotaEnforcer, QuotaOutcome,
    Scope as QuotaScope, TenantId as QuotaTenantId,
};
use ironauth_store::Scope;

/// Map the resolved persistence scope onto the quota engine's scope. Every OIDC
/// data-plane request runs in a `(tenant, environment)`, so it is always an
/// environment scope: the spend draws from BOTH the environment bucket and, by
/// nesting, its tenant bucket, which is what gives an environment its bounded
/// share of its tenant and keeps one tenant from starving another.
fn to_quota_scope(scope: &Scope) -> QuotaScope {
    QuotaScope::Environment(
        QuotaTenantId::new(scope.tenant().to_string()),
        QuotaEnvironmentId::new(scope.environment().to_string()),
    )
}

/// Charge one request against the request-rate dimension for `scope`.
///
/// Returns [`Some`] `429` response when the scope is over quota (the caller must
/// short-circuit with it, spending nothing further), or [`None`] when the request
/// is admitted and should proceed. The decision is atomic and fail-closed in the
/// engine; a denied spend charges nothing, so a rejected request never erodes the
/// scope's own budget.
pub(crate) fn enforce_request(enforcer: &QuotaEnforcer, scope: &Scope) -> Option<Response> {
    let quota_scope = to_quota_scope(scope);
    let outcome = enforcer.admit_request(&quota_scope);
    record(QuotaDimension::Requests, &outcome);
    if outcome.decision.is_denied() {
        Some(too_many_requests(&outcome))
    } else {
        None
    }
}

/// Record the decision as an aggregate metric and surface any usage-threshold
/// crossing. The engine also keeps per-scope, per-dimension counters that
/// [`QuotaEnforcer::metrics`] exports; wiring those into the Prometheus recorder
/// as labelled series is a follow-up (it needs a bounded-cardinality scrape hook),
/// so the request path emits a low-cardinality decision counter here and logs the
/// saturation events, keeping denials and pressure observable without an unbounded
/// per-tenant label set.
fn record(dimension: QuotaDimension, outcome: &QuotaOutcome) {
    let decision = if outcome.decision.is_denied() {
        "denied"
    } else {
        "admitted"
    };
    metrics::counter!(
        "ironauth_quota_decisions_total",
        "dimension" => dimension.as_str(),
        "decision" => decision,
    )
    .increment(1);
    for event in &outcome.events {
        tracing::info!(
            dimension = event.dimension.as_str(),
            threshold_percent = event.threshold_percent,
            utilization_percent = event.utilization_percent,
            "quota saturation threshold crossed"
        );
    }
}

/// Build the `429 Too Many Requests` short-circuit from a denied outcome: the
/// structured and legacy rate-limit headers, the block-signal header, the
/// `Retry-After`, and the optional block-signal cookie, with a small
/// machine-readable JSON body.
fn too_many_requests(outcome: &QuotaOutcome) -> Response {
    let body = "{\"error\":\"rate_limited\",\"error_description\":\"the tenant or environment \
                quota for this request was exceeded\"}";
    let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (name, value) in outcome.snapshot.headers() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
    }
    if let Some(cookie) = outcome.snapshot.block_set_cookie() {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            headers.append(axum::http::header::SET_COOKIE, value);
        }
    }
    response
}
