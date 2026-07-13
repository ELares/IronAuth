// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-request observability: the tracing span, the HTTP metrics, and the
//! effective-client-IP decision, as one middleware.
//!
//! What is logged is deliberately narrow: the request method, the route
//! TEMPLATE (never the raw path), the config-derived scheme, the effective
//! client IP, and the response status. Query strings, `Authorization`,
//! `Cookie`, other headers, and bodies are never touched by this layer, so a
//! secret in any of them cannot reach a log line through request logging.
//! Metric labels use the same route template, so URL contents can neither
//! explode series cardinality nor smuggle PII into a time series.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts, MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

use crate::AppState;
use crate::metrics::{
    HTTP_REQUEST_DURATION_SECONDS, HTTP_REQUESTS_TOTAL, PROXY_FORWARDING_REJECTED_TOTAL,
};
use crate::proxy::{ClientContext, FailClosedReason, ForwardDecision};

/// Route-template placeholder for requests that matched no route (a 404). Using
/// a constant instead of the raw path keeps metric cardinality bounded.
const UNMATCHED_ROUTE: &str = "<unmatched>";

/// The tower middleware that spans, times, and meters every request and
/// resolves the effective client context under the trusted-proxy policy.
pub async fn observe(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.ip());

    let resolution = state.policy.resolve_client_ip(peer, req.headers());
    if let ForwardDecision::FailedClosed(reason) = &resolution.decision {
        metrics::counter!(PROXY_FORWARDING_REJECTED_TOTAL, "reason" => reason_label(reason))
            .increment(1);
    }
    let client_ip = resolution.client_ip;

    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED_ROUTE.to_owned(), |m| m.as_str().to_owned());

    // Make the resolved context available to downstream handlers. Scheme and
    // host come from config, never from the request headers.
    req.extensions_mut().insert(ClientContext {
        client_ip,
        scheme: state.site.scheme().to_owned(),
        host: state.site.authority().to_owned(),
        forward_decision: resolution.decision,
    });

    let span = tracing::info_span!(
        "http_request",
        "http.request.method" = %method,
        "http.route" = %route,
        "url.scheme" = %state.site.scheme(),
        "client.ip" = %client_ip,
        "http.response.status_code" = tracing::field::Empty,
    );

    let start = state.env.clock().monotonic();
    async move {
        let response = next.run(req).await;
        let status = response.status();
        let elapsed = state.env.clock().monotonic().duration_since(start);

        tracing::Span::current().record("http.response.status_code", status.as_u16());

        let method_label = method.as_str().to_owned();
        let status_label = status.as_u16().to_string();
        metrics::counter!(
            HTTP_REQUESTS_TOTAL,
            "method" => method_label.clone(),
            "route" => route.clone(),
            "status" => status_label.clone(),
        )
        .increment(1);
        metrics::histogram!(
            HTTP_REQUEST_DURATION_SECONDS,
            "method" => method_label,
            "route" => route,
            "status" => status_label,
        )
        .record(elapsed.as_secs_f64());

        tracing::info!(
            duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            "request completed"
        );
        response
    }
    .instrument(span)
    .await
}

/// Stable metric label for a fail-closed reason.
fn reason_label(reason: &FailClosedReason) -> &'static str {
    match reason {
        FailClosedReason::HopCountMismatch { .. } => "hop_count_mismatch",
        FailClosedReason::ConflictingHeaders => "conflicting_headers",
        FailClosedReason::MalformedEntry => "malformed_entry",
    }
}

impl<S> FromRequestParts<S> for ClientContext
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, StatusCode> {
        // Present whenever the observe middleware ran (it always does on both
        // planes). Absence is a wiring bug, not a client error.
        parts
            .extensions
            .get::<ClientContext>()
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
