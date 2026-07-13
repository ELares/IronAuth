// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prometheus metrics: the recorder, the metric names, and text rendering.
//!
//! The recorder is installed process-once (a global, as the `metrics` facade
//! requires) and its handle is cloned into server state; `/metrics` on the
//! management plane renders it. Only route TEMPLATES appear as labels, never
//! raw request paths, so an attacker cannot explode cardinality or smuggle PII
//! into a time series through the URL.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Total HTTP requests, labeled by method, route template, and status.
pub const HTTP_REQUESTS_TOTAL: &str = "ironauth_http_requests_total";
/// HTTP request duration in seconds, labeled by method, route template, and
/// status.
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "ironauth_http_request_duration_seconds";
/// Liveness gauge: 1 while the process is serving.
pub const UP: &str = "ironauth_up";
/// Count of requests whose forwarding headers were rejected and failed closed,
/// labeled by reason.
pub const PROXY_FORWARDING_REJECTED_TOTAL: &str = "ironauth_proxy_forwarding_rejected_total";

/// Latency histogram buckets in seconds, from sub-millisecond to ten seconds.
const DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// The process-wide Prometheus handle, installing the recorder on first call.
///
/// Idempotent: later calls clone the handle installed by the first, so several
/// [`crate::Server`] instances in one process (as in tests) share one recorder.
///
/// # Panics
///
/// Panics if a different global metrics recorder was already installed by
/// other code; in this binary this function is the sole installer.
#[must_use]
pub fn recorder_handle() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .set_buckets(&DURATION_BUCKETS)
                .expect("static bucket list is non-empty")
                .install_recorder()
                .expect("no global metrics recorder is installed yet");
            describe();
            handle
        })
        .clone()
}

/// Register metric descriptions and units once, right after install.
fn describe() {
    metrics::describe_counter!(
        HTTP_REQUESTS_TOTAL,
        "Total HTTP requests by method, route template, and status"
    );
    metrics::describe_histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "HTTP request duration by method, route template, and status"
    );
    metrics::describe_gauge!(UP, "1 while the process is serving");
    metrics::describe_counter!(
        PROXY_FORWARDING_REJECTED_TOTAL,
        "Requests whose forwarding headers were ambiguous and failed closed"
    );
}

/// Render the current metrics in the Prometheus text exposition format.
#[must_use]
pub fn render(handle: &PrometheusHandle) -> String {
    handle.render()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_installable_and_renders() {
        let handle = recorder_handle();
        metrics::gauge!(UP).set(1.0);
        metrics::counter!(HTTP_REQUESTS_TOTAL, "method" => "GET", "route" => "/", "status" => "200")
            .increment(1);
        let text = render(&handle);
        assert!(text.contains(HTTP_REQUESTS_TOTAL), "{text}");
        assert!(text.contains(UP), "{text}");
    }
}
