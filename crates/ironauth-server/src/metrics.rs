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

/// Outbox messages leased by a worker, labeled by `consumer` (issue #104).
///
/// This and every other `ironauth_outbox_*` series is labeled by CONSUMER ONLY, never by
/// tenant or environment. A per-tenant label on a multi-tenant deployment is an unbounded
/// cardinality time series, which is the standard way to bring down a Prometheus instance;
/// bounded by the consumer registry, these stay at a handful of series no matter how many
/// tenants exist. The per-scope numbers are not lost: they are already available,
/// authenticated, on the queues management API, which is the surface that can afford them.
pub const OUTBOX_MESSAGES_CLAIMED_TOTAL: &str = "ironauth_outbox_messages_claimed_total";
/// Outbox messages that reached an outcome, labeled by `consumer` and `outcome`
/// (`completed`, `retried`, `dead_lettered`, `lease_lost`).
pub const OUTBOX_MESSAGES_TOTAL: &str = "ironauth_outbox_messages_total";
/// Outbox drain passes that could not run, labeled by `consumer` and `kind` (`drain` for a
/// persistence fault draining one scope, `scopes` for a sweep that could not enumerate its
/// scopes at all and therefore drained NOTHING).
pub const OUTBOX_PASS_FAILURES_TOTAL: &str = "ironauth_outbox_pass_failures_total";
/// Outbox queue depth, labeled by `consumer` and `state` (`ready`, `in_flight`, `scheduled`,
/// `dead_lettered`), summed across every scope the sampler swept.
pub const OUTBOX_DEPTH: &str = "ironauth_outbox_depth";
/// Consumer lag in seconds: how long the OLDEST ready message has been waiting past the
/// moment it became due, labeled by `consumer`, taken as the worst case across scopes.
///
/// Zero means nothing is overdue. A message still waiting out its retry backoff is not lag
/// and is not counted here, because it is waiting by design rather than for want of a worker.
pub const OUTBOX_OLDEST_READY_AGE_SECONDS: &str = "ironauth_outbox_oldest_ready_age_seconds";

/// Configured SIEM log streams, labeled by `sink_type` and `status` (`healthy`,
/// `degraded`, `failing`), summed across every scope the shipper swept (issue #110).
///
/// Labeled by SINK TYPE and STATUS only, never by stream id, tenant or environment, for
/// the reason spelled out on the outbox series above: an operator-created stream id is
/// unbounded, and an unbounded label on a multi-tenant deployment is how a Prometheus
/// instance falls over. Four sink types by three statuses is twelve series no matter how
/// many streams exist. The per-stream detail is not lost; it is on the authenticated
/// `GET .../log-streams` surface, which can afford it.
pub const LOG_STREAMS: &str = "ironauth_log_streams";
/// Outstanding dead-lettered batches, labeled by `sink_type`, summed across scopes.
///
/// Outstanding means set aside and not yet replayed, so this is the size of the export
/// gap an operator has not yet closed. It falls when a replay succeeds.
pub const LOG_STREAM_DEAD_LETTERS: &str = "ironauth_log_stream_dead_letters";

/// The `outcome` label values of [`OUTBOX_MESSAGES_TOTAL`], which together partition every
/// message a drain pass finished with.
pub const OUTBOX_OUTCOMES: [&str; 4] = ["completed", "retried", "dead_lettered", "lease_lost"];
/// The `state` label values of [`OUTBOX_DEPTH`], which together partition every non-terminal
/// message plus the dead-lettered tail.
pub const OUTBOX_DEPTH_STATES: [&str; 4] = ["ready", "in_flight", "scheduled", "dead_lettered"];

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
    metrics::describe_counter!(
        OUTBOX_MESSAGES_CLAIMED_TOTAL,
        "Outbox messages leased by a worker, by consumer"
    );
    metrics::describe_counter!(
        OUTBOX_MESSAGES_TOTAL,
        "Outbox messages that reached an outcome, by consumer and outcome"
    );
    metrics::describe_counter!(
        OUTBOX_PASS_FAILURES_TOTAL,
        "Outbox drain passes that could not run, by consumer and kind"
    );
    metrics::describe_gauge!(
        OUTBOX_DEPTH,
        "Outbox queue depth summed across scopes, by consumer and state"
    );
    metrics::describe_gauge!(
        OUTBOX_OLDEST_READY_AGE_SECONDS,
        metrics::Unit::Seconds,
        "How long the oldest ready outbox message has been overdue, by consumer"
    );
    metrics::describe_gauge!(
        LOG_STREAMS,
        "Configured SIEM log streams summed across scopes, by sink type and status"
    );
    metrics::describe_gauge!(
        LOG_STREAM_DEAD_LETTERS,
        "Outstanding dead-lettered log stream batches summed across scopes, by sink type"
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
