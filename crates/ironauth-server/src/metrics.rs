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

/// What kind of series a metric is, which is what a scrape's `# TYPE` line states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// Monotonic count.
    Counter,
    /// Instantaneous value.
    Gauge,
    /// Distribution.
    Histogram,
}

impl MetricKind {
    /// The word a Prometheus `# TYPE` line uses.
    #[must_use]
    pub const fn type_word(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// One metric this build promises to export.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    /// The series name.
    pub name: &'static str,
    /// Counter, gauge or histogram.
    pub kind: MetricKind,
    /// The labels every sample carries, in no particular order.
    ///
    /// THE LABELS ARE THE PART THAT WAS ONLY PROSE. Every constant above already said what it
    /// is "labeled by", in a doc comment, and nothing checked it: a metric emitted with a label
    /// the comment did not mention, or missing one it promised, was invisible until a dashboard
    /// broke. A dashboard or an alert is written against the label set, so drift in either
    /// direction breaks somebody's query.
    pub labels: &'static [&'static str],
    /// The one-line HELP a scrape carries.
    pub help: &'static str,
}

/// EVERY METRIC THIS BUILD EXPORTS (issue #152 criterion 1).
///
/// # What this is for
///
/// The criterion asks that "every metric in the documented contract is exported and carries the
/// documented labels; a CI contract test fails on drift in either direction". This is the
/// documented contract as a VALUE rather than a document, so the test and the published doc read
/// the same thing and cannot disagree.
///
/// # Both directions, and why each has a different failure
///
/// A metric in the contract that is NOT exported is a promise to a dashboard that will render
/// empty, and an alert that will never fire -- the failure that looks like quiet. A metric
/// exported that is NOT in the contract is a series nobody documented, which is how cardinality
/// arrives unreviewed.
///
/// `tests/metric_contract.rs` has ONE TEST PER DIRECTION, which is worth stating as a structure
/// rather than as an assurance: this sentence previously said it "fails on both" while only one
/// direction had an assertion behind it, because both tests iterated a collection other than
/// this one. A bidirectional check has a loop per direction, and counting them is how that is
/// seen without running anything.
///
/// # Scope: the workspace, not this crate
///
/// This constant LIVES in the server crate and is not limited to it. Most of what it lists is
/// emitted from `ironauth-oidc`, the rest from the binary crate, `ironauth-fetch` and this one.
///
/// NO COUNTS IN THIS PARAGRAPH, deliberately. It first said "the server's own metrics. Other
/// crates export their own (`ironauth-fetch` has two), and they are NOT here yet" while those
/// two sat in the list below it. The repair stated a measured split, 4/28/7/2 over 41 entries,
/// and the very next change to add an entry falsified all five numbers in the same commit that
/// edited the list twenty lines further down. A hand-written count beside a list that grows is
/// a retraction waiting for its next author, so the shape is stated and the arithmetic is left
/// to the reader who can count the entries.
///
/// Two boundaries hold it, and they are different claims:
/// `the_contract_covers_every_metric_this_module_declares` refuses a constant declared HERE with
/// no entry, and `the_contract_covers_every_metric_the_workspace_emits` refuses a metric emitted
/// ANYWHERE with no entry.
pub const CONTRACT: &[MetricSpec] = &[
    MetricSpec {
        name: HTTP_REQUESTS_TOTAL,
        kind: MetricKind::Counter,
        labels: &["method", "route", "status"],
        help: "Total HTTP requests",
    },
    MetricSpec {
        name: HTTP_REQUEST_DURATION_SECONDS,
        kind: MetricKind::Histogram,
        labels: &["method", "route", "status"],
        help: "HTTP request duration in seconds",
    },
    MetricSpec {
        name: UP,
        kind: MetricKind::Gauge,
        labels: &[],
        help: "1 while the process is serving",
    },
    MetricSpec {
        name: PROXY_FORWARDING_REJECTED_TOTAL,
        kind: MetricKind::Counter,
        labels: &["reason"],
        help: "Requests whose forwarding headers were rejected and failed closed",
    },
    MetricSpec {
        name: OUTBOX_MESSAGES_CLAIMED_TOTAL,
        kind: MetricKind::Counter,
        labels: &["consumer"],
        help: "Outbox messages leased by a worker",
    },
    MetricSpec {
        name: OUTBOX_MESSAGES_TOTAL,
        kind: MetricKind::Counter,
        labels: &["consumer", "outcome"],
        help: "Outbox messages that reached an outcome",
    },
    MetricSpec {
        name: OUTBOX_PASS_FAILURES_TOTAL,
        kind: MetricKind::Counter,
        labels: &["consumer", "kind"],
        help: "Outbox drain passes that could not run",
    },
    MetricSpec {
        name: OUTBOX_DEPTH,
        kind: MetricKind::Gauge,
        labels: &["consumer", "state"],
        help: "Outbox messages by state",
    },
    MetricSpec {
        name: OUTBOX_OLDEST_READY_AGE_SECONDS,
        kind: MetricKind::Gauge,
        labels: &["consumer"],
        help: "Age of the oldest ready outbox message in seconds",
    },
    MetricSpec {
        name: LOG_STREAMS,
        kind: MetricKind::Gauge,
        // `sink_type` and `status`, not `state`. The first version of this entry said `state`,
        // invented from the constant's doc comment rather than read from the call site, and the
        // contract test caught it -- which is the entire argument for comparing the contract
        // against the emit sites instead of against a scrape generated from the contract.
        labels: &["sink_type", "status"],
        help: "Configured log streams by sink type and status",
    },
    MetricSpec {
        name: LOG_STREAM_DEAD_LETTERS,
        kind: MetricKind::Gauge,
        labels: &["sink_type"],
        help: "Log stream dead letters awaiting replay, by sink type",
    },
    // ---------------------------------------------------------------------------------
    // METRICS DECLARED OUTSIDE THIS MODULE (issue #152 criterion 1).
    //
    // The contract covered only what this module declares, so twenty-seven metrics emitted
    // from other crates were promised to nobody and checked by nothing. They are named by
    // literal here rather than by constant because the constants live in their own crates,
    // and `ironauth-server` does not depend on all of them.
    //
    // `the_contract_covers_every_metric_the_workspace_emits` is what keeps this list
    // honest in the other direction: a metric added anywhere in the workspace fails until
    // it has a row here.
    // ---------------------------------------------------------------------------------
    MetricSpec {
        name: "ironauth_connector_healthy",
        kind: MetricKind::Gauge,
        labels: &["connector"],
        help: "Whether an upstream connector's last probe succeeded",
    },
    MetricSpec {
        name: "ironauth_connector_upstream_error_total",
        kind: MetricKind::Counter,
        labels: &["connector", "kind"],
        help: "Upstream connector calls that failed, by failure kind",
    },
    MetricSpec {
        name: "ironauth_connector_upstream_success_total",
        kind: MetricKind::Counter,
        labels: &["connector"],
        help: "Upstream connector calls that succeeded",
    },
    MetricSpec {
        name: "ironauth_passkey_funnel_total",
        kind: MetricKind::Counter,
        labels: &["stage", "result"],
        help: "Passkey ceremony outcomes by funnel stage",
    },
    MetricSpec {
        name: "ironauth_otp_funnel_total",
        kind: MetricKind::Counter,
        labels: &["channel", "stage", "result"],
        help: "One-time-code outcomes by channel and funnel stage",
    },
    MetricSpec {
        name: "ironauth_factor_downgrade_recovery_permitted_total",
        kind: MetricKind::Counter,
        labels: &["factor", "surface"],
        help: "Recovery flows permitted to use a weaker factor",
    },
    MetricSpec {
        name: "ironauth_factor_downgrade_refused_total",
        kind: MetricKind::Counter,
        labels: &["factor", "path"],
        help: "Authentications refused for attempting a weaker factor than the policy allows",
    },
    MetricSpec {
        name: "ironauth_backup_success_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Scheduled encrypted-backup passes that pushed and (when configured) pruned successfully",
    },
    MetricSpec {
        name: "ironauth_backup_failure_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Scheduled encrypted-backup passes that failed",
    },
    MetricSpec {
        name: "ironauth_backup_last_success_timestamp_seconds",
        kind: MetricKind::Gauge,
        labels: &[],
        help: "Unix seconds of the last successful scheduled backup push; a dashboard derives age",
    },
    MetricSpec {
        name: "ironauth_lazy_migration_breaker_state",
        kind: MetricKind::Gauge,
        labels: &[],
        help: "Lazy password-migration breaker state, as a number a dashboard can threshold",
    },
    MetricSpec {
        name: "ironauth_lazy_migration_breaker_transitions_total",
        kind: MetricKind::Counter,
        labels: &["to"],
        help: "Lazy-migration breaker transitions, by the state entered",
    },
    MetricSpec {
        name: "ironauth_lazy_migration_hook_latency_seconds",
        kind: MetricKind::Histogram,
        labels: &[],
        help: "Wall time of a lazy-migration verification hook",
    },
    MetricSpec {
        name: "ironauth_lazy_migration_hook_total",
        kind: MetricKind::Counter,
        labels: &["outcome"],
        help: "Lazy-migration hook invocations, by outcome",
    },
    MetricSpec {
        name: "ironauth_lazy_migration_migrated_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Credentials rehashed into the current scheme by a lazy migration",
    },
    MetricSpec {
        name: "ironauth_oidc_code_reuse_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Authorization codes presented more than once, which is a replay signal",
    },
    MetricSpec {
        name: "ironauth_oidc_redeem_error_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Token redemptions that failed",
    },
    MetricSpec {
        name: "ironauth_oidc_refresh_reuse_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Refresh tokens presented after rotation, which is a theft signal",
    },
    MetricSpec {
        name: "ironauth_token_requests_total",
        kind: MetricKind::Counter,
        labels: &["grant_type", "outcome"],
        help: "Token endpoint requests by grant type and outcome",
    },
    MetricSpec {
        name: "ironauth_token_request_duration_seconds",
        kind: MetricKind::Histogram,
        labels: &["grant_type"],
        help: "Token endpoint request duration in seconds, by grant type",
    },
    MetricSpec {
        name: "ironauth_outbound_fetch_blocked_total",
        kind: MetricKind::Counter,
        labels: &["purpose", "reason"],
        help: "Outbound fetches refused by the destination policy",
    },
    MetricSpec {
        name: "ironauth_outbound_fetch_requests_total",
        kind: MetricKind::Counter,
        labels: &["outcome", "purpose"],
        help: "Outbound fetches attempted, by purpose and outcome",
    },
    MetricSpec {
        name: "ironauth_password_breached_at_login_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Logins where the presented password matched a breach corpus",
    },
    // Issue #150 criterion 1: "the limiting layer identified in headers and metrics". The
    // layer label carries the same stable string the `x-ratelimit-layer` header does, so a
    // dashboard and a response cannot disagree about what a layer is called.
    MetricSpec {
        name: "ironauth_forward_auth_throttled_total",
        kind: MetricKind::Counter,
        labels: &["layer"],
        help: "Forward-auth checks refused by the request-plane limiter, by refusing layer",
    },
    // Issue #150 criterion 1: the same limiting layer, on the OIDC request paths (authorize,
    // challenge, OTP, magic-link, invitation surfaces). The `layer` label is the same stable
    // string the `x-ratelimit-layer` header carries on the 429.
    // Issue #150 criterion 5: the shared (L2) bucket tier's fail-open class, counted so a
    // deployment that configured the accelerator can see when a node stops sharing budgets.
    MetricSpec {
        name: "ironauth_shared_rate_fallbacks_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "Admits enforced by the local bucket because the shared rate tier could not answer",
    },
    MetricSpec {
        name: "ironauth_request_throttled_total",
        kind: MetricKind::Counter,
        labels: &["layer"],
        help: "Request-path refusals by the layered limiter, by refusing layer",
    },
    MetricSpec {
        name: "ironauth_password_hash_admission_rejected_total",
        kind: MetricKind::Counter,
        labels: &["reason"],
        help: "Hash requests refused before reaching the pool, by reason",
    },
    MetricSpec {
        name: "ironauth_password_hash_duration_seconds",
        kind: MetricKind::Histogram,
        labels: &["op"],
        help: "Wall time of a password hash or verify",
    },
    MetricSpec {
        name: "ironauth_password_hash_pool_active_workers",
        kind: MetricKind::Gauge,
        labels: &[],
        help: "Hash pool workers currently running a job",
    },
    MetricSpec {
        name: "ironauth_password_hash_pool_queue_depth",
        kind: MetricKind::Gauge,
        labels: &[],
        help: "Hash requests waiting for a pool worker",
    },
    MetricSpec {
        name: "ironauth_password_hash_pool_threads",
        kind: MetricKind::Gauge,
        labels: &[],
        help: "Hash pool worker threads configured",
    },
    MetricSpec {
        name: "ironauth_password_screen_total",
        kind: MetricKind::Counter,
        labels: &["outcome"],
        help: "Password screening checks, by outcome",
    },
    MetricSpec {
        name: "ironauth_quota_decisions_total",
        kind: MetricKind::Counter,
        labels: &["decision", "dimension"],
        help: "Quota decisions, by dimension and admitted or denied",
    },
    MetricSpec {
        name: "ironauth_sms_route_throttled_total",
        kind: MetricKind::Counter,
        labels: &["route"],
        help: "SMS sends refused by a per-route throttle",
    },
    MetricSpec {
        name: "ironauth_sms_send_hash_rejected_total",
        kind: MetricKind::Counter,
        labels: &[],
        help: "SMS sends refused because the recipient hash was rejected",
    },
    MetricSpec {
        name: "ironauth_sms_send_refused_total",
        kind: MetricKind::Counter,
        labels: &["reason"],
        help: "SMS sends refused, by reason",
    },
    MetricSpec {
        name: "ironauth_verification_send_suppressed_total",
        kind: MetricKind::Counter,
        labels: &["purpose"],
        help: "Verification sends suppressed, by purpose",
    },
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

/// Register every contract entry's description and unit once, right after install.
///
/// DRIVEN FROM `CONTRACT`, not hand written beside it. This was a hand-maintained list of
/// eleven `describe_*` calls whose strings had already drifted from the contract's own `help`
/// (`PROXY_FORWARDING_REJECTED_TOTAL` was described as "ambiguous" here and "rejected and failed
/// closed" there), and the thirty-odd metrics emitted from other crates had no description at
/// all: their `# HELP` line on a scrape was the metric name repeated back. The contract already
/// carries the one-line semantics, and `tests/metric_contract.rs` already holds it against the
/// emit sites, so reading it here makes the published page, the scrape's HELP text and the
/// checked value the same string.
///
/// The unit is derived from the name rather than declared: `metrics::Unit::Seconds` for a
/// histogram whose name ends in `_seconds`, which is the Prometheus naming convention the
/// contract already follows and the only unit this build exports.
fn describe() {
    for spec in CONTRACT {
        match spec.kind {
            MetricKind::Counter => metrics::describe_counter!(spec.name, spec.help),
            MetricKind::Gauge => {
                if spec.name.ends_with("_seconds") {
                    metrics::describe_gauge!(spec.name, metrics::Unit::Seconds, spec.help);
                } else {
                    metrics::describe_gauge!(spec.name, spec.help);
                }
            }
            MetricKind::Histogram => {
                if spec.name.ends_with("_seconds") {
                    metrics::describe_histogram!(spec.name, metrics::Unit::Seconds, spec.help);
                } else {
                    metrics::describe_histogram!(spec.name, spec.help);
                }
            }
        }
    }
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
