// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIEM log stream configuration and selection (issue #110).
//!
//! A stream is a standing instruction to ship one or both audit streams to one sink. This
//! module owns the CONFIGURATION and the question every shipper has to answer correctly:
//! given a stream and an audit row, does this row belong in this stream?
//!
//! That question is pure and it is where a leak would live, so it is answered by
//! [`LogStreamRecord::accepts`] with no database and no sink in sight. A shipper that got
//! the selection wrong would deliver another operator's events to a third party, and that
//! is not a failure a delivery test would notice: the delivery would succeed.
//!
//! # Two filters, and the difference between empty and absent
//!
//! `source` selects by audit stream (`admin_action`, `authentication`, or both).
//! `event_type_filter` narrows further by action wire string. [`None`] means every action
//! in `source`, and an EMPTY list means none of them. Those are deliberately different:
//! an empty list is how an operator parks a stream without deleting it and losing its
//! cursor, and reading empty as "everything" would turn parking a stream into firehosing
//! it.

use serde_json::Value;

/// Which audit stream(s) a log stream ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSource {
    /// Only the admin-action stream.
    AdminAction,
    /// Only the authentication stream.
    Authentication,
    /// Both.
    Both,
}

impl StreamSource {
    /// Every variant, so a test can sweep them rather than list them.
    pub const ALL: [StreamSource; 3] = [
        StreamSource::AdminAction,
        StreamSource::Authentication,
        StreamSource::Both,
    ];

    /// The stable wire string stored in `log_streams.source`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StreamSource::AdminAction => "admin_action",
            StreamSource::Authentication => "authentication",
            StreamSource::Both => "both",
        }
    }

    /// Parse a stored wire string.
    #[must_use]
    pub fn from_wire(wire: &str) -> Option<Self> {
        match wire {
            "admin_action" => Some(StreamSource::AdminAction),
            "authentication" => Some(StreamSource::Authentication),
            "both" => Some(StreamSource::Both),
            _ => None,
        }
    }

    /// Whether this source carries rows of the audit `stream` wire string.
    #[must_use]
    pub fn carries(self, stream: &str) -> bool {
        match self {
            StreamSource::Both => stream == "admin_action" || stream == "authentication",
            other => other.as_str() == stream,
        }
    }
}

/// Where a log stream ships to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkType {
    /// A plain HTTPS POST of a batch.
    Http,
    /// An S3-compatible object store.
    S3,
    /// Datadog logs intake.
    Datadog,
    /// Splunk HTTP Event Collector.
    SplunkHec,
}

impl SinkType {
    /// Every variant.
    pub const ALL: [SinkType; 4] = [
        SinkType::Http,
        SinkType::S3,
        SinkType::Datadog,
        SinkType::SplunkHec,
    ];

    /// The stable wire string stored in `log_streams.sink_type`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SinkType::Http => "http",
            SinkType::S3 => "s3",
            SinkType::Datadog => "datadog",
            SinkType::SplunkHec => "splunk_hec",
        }
    }

    /// Parse a stored wire string.
    #[must_use]
    pub fn from_wire(wire: &str) -> Option<Self> {
        match wire {
            "http" => Some(SinkType::Http),
            "s3" => Some(SinkType::S3),
            "datadog" => Some(SinkType::Datadog),
            "splunk_hec" => Some(SinkType::SplunkHec),
            _ => None,
        }
    }
}

/// A batch a stream could not deliver, recorded as a RANGE rather than as a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetter {
    /// The `lsd_` identifier.
    pub id: String,
    /// The inclusive start, in cursor order.
    pub from: (i64, String),
    /// The inclusive end, in cursor order.
    pub to: (i64, String),
    /// How many events the failed batch carried.
    pub event_count: i32,
    /// The failure that ended the retry run. Operator-safe.
    pub last_error: String,
}

/// One configured stream.
#[derive(Debug, Clone)]
pub struct LogStreamRecord {
    /// The `lgs_` identifier.
    pub id: String,
    /// The operator's label. Never secret.
    pub description: String,
    /// Which audit stream(s) this ships.
    pub source: StreamSource,
    /// Where it ships to.
    pub sink_type: SinkType,
    /// Sink shape: endpoint, region, bucket, index. Never a credential.
    pub sink_config: Value,
    /// The environment-scoped secret holding the sink credential, by NAME.
    pub credential_secret_name: Option<String>,
    /// The environment-scoped secret this stream's batches are SIGNED with, by NAME
    /// (issue #110 criterion 5).
    ///
    /// Separate from `credential_secret_name` because it points the other way: the
    /// credential authenticates IronAuth TO the sink, and this lets a CONSUMER establish
    /// that a batch came from this deployment and arrived in order. One secret for both
    /// would hand every party that can receive a batch the key that proves batches genuine.
    ///
    /// [`None`] ships UNSIGNED, which is what every stream does today.
    pub signing_secret_name: Option<String>,
    /// Ship only these action wire strings. [`None`] is every action in `source`;
    /// `Some(empty)` is none of them.
    pub event_type_filter: Option<Vec<String>>,
    /// Ship only this organization's events, or [`None`] for the whole environment.
    ///
    /// Matched by EQUALITY against the audit row's organization. A row with no
    /// organization is not an organization's event, so a per-org stream never matches it,
    /// which falls out of equality rather than needing a special case.
    pub organization_id: Option<String>,
    /// Whether the shipper picks this stream up.
    pub active: bool,
    /// The cursor: everything at or before this `(occurred_micros, audit_id)` has
    /// shipped. [`None`] means nothing has.
    pub cursor: Option<(i64, String)>,
    /// Delivery health.
    pub health: StreamHealth,
}

/// A stream's delivery health, as the status surface reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamHealth {
    /// When a delivery last succeeded, epoch microseconds.
    pub last_success_micros: Option<i64>,
    /// When a delivery last failed, epoch microseconds.
    pub last_error_micros: Option<i64>,
    /// The last failure, operator-safe: a status and a reason, never a response body.
    pub last_error: Option<String>,
    /// Consecutive failures with no success in between.
    pub consecutive_failures: i32,
}

/// The coarse state an operator reads off a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStatus {
    /// Delivering, or configured and not yet tried.
    Healthy,
    /// Failing, but not for long enough to call it down.
    Degraded,
    /// Failing persistently.
    Failing,
}

/// Consecutive failures at which a stream is called DEGRADED.
pub const DEGRADED_AFTER: i32 = 1;
/// Consecutive failures at which a stream is called FAILING.
///
/// A run rather than a rate, for the reason the webhook auto-disable uses one: a busy
/// sink that fails a fraction of the time is working, and only an unbroken run ending
/// now says it has stopped answering.
pub const FAILING_AFTER: i32 = 5;

impl StreamHealth {
    /// The coarse status, from the consecutive-failure run.
    #[must_use]
    pub fn status(&self) -> StreamStatus {
        if self.consecutive_failures >= FAILING_AFTER {
            StreamStatus::Failing
        } else if self.consecutive_failures >= DEGRADED_AFTER {
            StreamStatus::Degraded
        } else {
            StreamStatus::Healthy
        }
    }
}

impl LogStreamRecord {
    /// Whether an audit row in `stream` with action `action` belongs in this log stream.
    ///
    /// The one place selection is decided. A shipper must not re-derive any part of this:
    /// a delivery to the wrong sink SUCCEEDS, so nothing downstream notices, and the
    /// operator finds out from whoever received the events.
    #[must_use]
    pub fn accepts(&self, stream: &str, action: &str) -> bool {
        if !self.active {
            return false;
        }
        if !self.source.carries(stream) {
            return false;
        }
        match &self.event_type_filter {
            // Absent means every action in `source`.
            None => true,
            // Present means exactly these, and an empty list therefore means none.
            Some(allowed) => allowed.iter().any(|entry| entry == action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(source: StreamSource) -> LogStreamRecord {
        LogStreamRecord {
            id: "lgs_1".to_string(),
            description: String::new(),
            source,
            sink_type: SinkType::Http,
            sink_config: serde_json::json!({}),
            credential_secret_name: None,
            signing_secret_name: None,
            event_type_filter: None,
            organization_id: None,
            active: true,
            cursor: None,
            health: StreamHealth::default(),
        }
    }

    #[test]
    fn a_source_carries_only_its_own_stream() {
        assert!(stream(StreamSource::AdminAction).accepts("admin_action", "client.create"));
        assert!(!stream(StreamSource::AdminAction).accepts("authentication", "login.succeeded"));
        assert!(stream(StreamSource::Authentication).accepts("authentication", "login.succeeded"));
        assert!(!stream(StreamSource::Authentication).accepts("admin_action", "client.create"));
        assert!(stream(StreamSource::Both).accepts("admin_action", "client.create"));
        assert!(stream(StreamSource::Both).accepts("authentication", "login.succeeded"));
    }

    /// An unknown stream name is carried by NOTHING, including `both`.
    ///
    /// `both` is the arm that would plausibly be written as "anything that is not
    /// `admin_action`", which would make a typo or a future third stream ship into every
    /// `both` sink in the deployment.
    #[test]
    fn no_source_carries_an_unknown_stream_name() {
        for source in StreamSource::ALL {
            assert!(
                !stream(source).accepts("authentification", "client.create"),
                "{} must not carry an unknown stream name",
                source.as_str()
            );
        }
    }

    #[test]
    fn an_inactive_stream_accepts_nothing() {
        let mut parked = stream(StreamSource::Both);
        parked.active = false;
        assert!(!parked.accepts("admin_action", "client.create"));
        assert!(!parked.accepts("authentication", "login.succeeded"));
    }

    /// An EMPTY filter ships nothing; an ABSENT filter ships everything.
    ///
    /// Reading empty as "everything" is the plausible bug, and it turns parking a stream
    /// into firehosing it, which is the worst direction for the mistake to go.
    #[test]
    fn an_empty_filter_is_not_the_same_as_an_absent_one() {
        let mut absent = stream(StreamSource::Both);
        absent.event_type_filter = None;
        assert!(absent.accepts("admin_action", "client.create"));

        let mut empty = stream(StreamSource::Both);
        empty.event_type_filter = Some(Vec::new());
        assert!(
            !empty.accepts("admin_action", "client.create"),
            "an empty filter must ship nothing, never everything"
        );
    }

    #[test]
    fn a_filter_admits_exactly_its_listed_actions() {
        let mut filtered = stream(StreamSource::Both);
        filtered.event_type_filter = Some(vec!["client.create".to_string()]);
        assert!(filtered.accepts("admin_action", "client.create"));
        assert!(!filtered.accepts("admin_action", "client.delete"));
        // A prefix of a listed action is not a listed action.
        assert!(!filtered.accepts("admin_action", "client.creat"));
        assert!(!filtered.accepts("admin_action", "client.created"));
    }

    #[test]
    fn the_wire_strings_round_trip() {
        for source in StreamSource::ALL {
            assert_eq!(StreamSource::from_wire(source.as_str()), Some(source));
        }
        for sink in SinkType::ALL {
            assert_eq!(SinkType::from_wire(sink.as_str()), Some(sink));
        }
        assert_eq!(StreamSource::from_wire("nonsense"), None);
        assert_eq!(SinkType::from_wire("nonsense"), None);
    }

    /// The wire strings must match the CHECK constraints in migration 0137, which is
    /// where a mismatch would surface as an insert failure at runtime rather than here.
    #[test]
    fn the_wire_strings_match_the_migration_check_constraints() {
        let sql = include_str!("../migrations/0137_log_streams.sql");
        for source in StreamSource::ALL {
            assert!(
                sql.contains(&format!("'{}'", source.as_str())),
                "migration 0137 does not permit source `{}`",
                source.as_str()
            );
        }
        for sink in SinkType::ALL {
            assert!(
                sql.contains(&format!("'{}'", sink.as_str())),
                "migration 0137 does not permit sink_type `{}`",
                sink.as_str()
            );
        }
    }

    #[test]
    fn health_reports_a_run_of_failures_as_degraded_then_failing() {
        let mut health = StreamHealth::default();
        assert_eq!(health.status(), StreamStatus::Healthy);
        health.consecutive_failures = DEGRADED_AFTER;
        assert_eq!(health.status(), StreamStatus::Degraded);
        health.consecutive_failures = FAILING_AFTER;
        assert_eq!(health.status(), StreamStatus::Failing);
        // One success resets the run, so a sink that recovers is healthy again rather
        // than carrying its history forever.
        health.consecutive_failures = 0;
        assert_eq!(health.status(), StreamStatus::Healthy);
    }
}
