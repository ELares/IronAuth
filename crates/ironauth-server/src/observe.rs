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
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use ironauth_config::PEER_IP_HEADER;
use tracing::Instrument;

use crate::AppState;
use crate::metrics::{
    HTTP_REQUEST_DURATION_SECONDS, HTTP_REQUESTS_TOTAL, PROXY_FORWARDING_REJECTED_TOTAL,
};
use crate::proxy::{ClientContext, FailClosedReason, ForwardDecision};

/// Route-template placeholder for requests that matched no route (a 404). Using
/// a constant instead of the raw path keeps metric cardinality bounded.
const UNMATCHED_ROUTE: &str = "<unmatched>";

/// Catch-all method label for any request method outside the fixed set.
const OTHER_METHOD: &str = "<other>";

/// Bucket an HTTP method into a fixed, closed label set.
///
/// HTTP permits arbitrary extension-method tokens, and the observe middleware
/// runs before routing, so an unauthenticated caller controls `method`. Using
/// the raw token as a metric label (or log field) would let sustained distinct
/// methods grow the never-evicted Prometheus series set without bound, an
/// unauthenticated memory-exhaustion vector on the public plane. Only the nine
/// registered methods pass through; everything else collapses to `<other>`.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::PATCH => "PATCH",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => OTHER_METHOD,
    }
}

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
    let method_label = method_label(&method);
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

    // Stamp the POLICY-RESOLVED client IP for the OFF-BY-DEFAULT peer-IP session
    // binding (issue #32). `insert` REPLACES every value already on the request, so
    // a client that tried to supply this header cannot spoof its own peer IP: what
    // downstream reads is always what the trusted-proxy policy resolved.
    if let Ok(value) = HeaderValue::from_str(&client_ip.to_string()) {
        req.headers_mut().insert(PEER_IP_HEADER, value);
    } else {
        req.headers_mut().remove(PEER_IP_HEADER);
    }

    let span = tracing::info_span!(
        "http_request",
        "http.request.method" = method_label,
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

        let status_label = status.as_u16().to_string();
        metrics::counter!(
            HTTP_REQUESTS_TOTAL,
            "method" => method_label,
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

#[cfg(test)]
mod tests {
    use super::{OTHER_METHOD, method_label};
    use axum::http::Method;

    #[test]
    fn registered_methods_pass_through() {
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::POST), "POST");
        assert_eq!(method_label(&Method::DELETE), "DELETE");
        assert_eq!(method_label(&Method::OPTIONS), "OPTIONS");
    }

    #[test]
    fn extension_methods_collapse_to_other() {
        // An attacker-chosen extension-method token must never become its own
        // metric label; unbounded distinct tokens would grow the series set
        // without eviction (memory-exhaustion vector on the public plane).
        for raw in ["EVILMETHOD", "FROBNICATE", "aaaaaaaaaaaaaaaa", "PROPFIND"] {
            let method = Method::from_bytes(raw.as_bytes()).expect("valid token");
            assert_eq!(method_label(&method), OTHER_METHOD, "{raw} must bucket");
        }
    }
}
