// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-purpose observability for the outbound fetcher.
//!
//! Every fetch, allowed or blocked, is metered by its caller-declared purpose
//! and its outcome, and every block additionally records the internal reason.
//! The labels are drawn from fixed, closed sets (the purpose enum, the outcome
//! enum, and the block-class labels), so an attacker who controls the target URL
//! can neither explode metric cardinality nor smuggle content into a label, the
//! same discipline the server's request metrics use.
//!
//! Structured logs for a block carry only those bounded fields (purpose and
//! reason), never the raw host or URL: the target is attacker-influenced
//! free-form text, and keeping it out of the log stream matches the server's
//! log-scrubbing stance (route templates, never raw paths). Aggregate visibility
//! (which purpose is being pointed at internal addresses, and how) comes from
//! the metrics, not from logging the attacker's string.

use crate::FetchPurpose;
use crate::policy::BlockClass;

/// Total outbound fetches, labeled by purpose and outcome.
pub const FETCH_REQUESTS_TOTAL: &str = "ironauth_outbound_fetch_requests_total";
/// Outbound fetches refused before or at connect time, labeled by purpose and
/// the internal block reason.
pub const FETCH_BLOCKED_TOTAL: &str = "ironauth_outbound_fetch_blocked_total";

/// The terminal outcome of a fetch, as a bounded metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A response was returned to the caller.
    Ok,
    /// The destination policy refused the fetch (see [`BlockReason`]).
    Blocked,
    /// The scheme was not permitted (plaintext http without opt-in).
    SchemeNotAllowed,
    /// A redirect was surfaced as an error and not followed.
    Redirect,
    /// The body exceeded the size cap.
    TooLarge,
    /// The deadline was exceeded.
    Timeout,
    /// The connection or exchange failed.
    UpstreamError,
    /// The request was malformed by the caller.
    InvalidRequest,
}

impl Outcome {
    /// A stable, bounded label.
    const fn label(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Blocked => "blocked",
            Outcome::SchemeNotAllowed => "scheme_not_allowed",
            Outcome::Redirect => "redirect",
            Outcome::TooLarge => "too_large",
            Outcome::Timeout => "timeout",
            Outcome::UpstreamError => "upstream_error",
            Outcome::InvalidRequest => "invalid_request",
        }
    }
}

/// Why a fetch was blocked, as a bounded metric/log reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockReason {
    /// A resolved address fell in a denied range.
    Address(BlockClass),
    /// The host could not be resolved (folded into the uniform block so it is no
    /// oracle for whether a name exists).
    ResolutionFailed,
    /// The host resolved to no addresses at all.
    NoAddresses,
}

impl BlockReason {
    /// A stable, bounded label. Address blocks reuse the [`BlockClass`] labels;
    /// the resolution reasons are their own fixed tokens.
    const fn label(self) -> &'static str {
        match self {
            BlockReason::Address(class) => class.label(),
            BlockReason::ResolutionFailed => "resolution_failed",
            BlockReason::NoAddresses => "no_addresses",
        }
    }
}

/// Register the metric descriptions once, after a recorder is installed.
///
/// Optional: the counters record without it, but calling it (from the binary,
/// right after installing the Prometheus recorder) attaches help text. It is
/// idempotent enough to call once at startup.
pub fn describe_metrics() {
    metrics::describe_counter!(
        FETCH_REQUESTS_TOTAL,
        "Total outbound fetches by purpose and outcome"
    );
    metrics::describe_counter!(
        FETCH_BLOCKED_TOTAL,
        "Outbound fetches refused by the destination policy, by purpose and reason"
    );
}

/// Record a completed (non-blocked) outcome.
pub(crate) fn record_outcome(purpose: FetchPurpose, outcome: Outcome) {
    metrics::counter!(
        FETCH_REQUESTS_TOTAL,
        "purpose" => purpose.label(),
        "outcome" => outcome.label(),
    )
    .increment(1);
}

/// Record a blocked fetch: the uniform `blocked` outcome plus the internal
/// reason, and a structured warning carrying only the bounded fields.
pub(crate) fn record_block(purpose: FetchPurpose, reason: BlockReason) {
    record_outcome(purpose, Outcome::Blocked);
    metrics::counter!(
        FETCH_BLOCKED_TOTAL,
        "purpose" => purpose.label(),
        "reason" => reason.label(),
    )
    .increment(1);
    // Bounded fields only: never the raw target host or URL (attacker-influenced
    // free-form text stays out of the log stream, per the scrubbing stance).
    tracing::warn!(
        "outbound.fetch.purpose" = purpose.label(),
        "outbound.fetch.block_reason" = reason.label(),
        "outbound fetch blocked by destination policy"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_labels_are_distinct() {
        let outcomes = [
            Outcome::Ok,
            Outcome::Blocked,
            Outcome::SchemeNotAllowed,
            Outcome::Redirect,
            Outcome::TooLarge,
            Outcome::Timeout,
            Outcome::UpstreamError,
            Outcome::InvalidRequest,
        ];
        let mut labels: Vec<&str> = outcomes.iter().map(|o| o.label()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count);
    }

    #[test]
    fn block_reason_reuses_class_labels() {
        assert_eq!(
            BlockReason::Address(BlockClass::LinkLocal).label(),
            "link_local"
        );
        assert_eq!(BlockReason::ResolutionFailed.label(), "resolution_failed");
        assert_eq!(BlockReason::NoAddresses.label(), "no_addresses");
    }
}
