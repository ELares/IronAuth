// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIEM log stream delivery (issue #110).
//!
//! Reads audit rows forward from each stream's cursor, renders them as OCSF events, hands
//! the batch to that stream's sink, and advances the cursor only on success.
//!
//! # Why the cursor advances only on success, and only to what was accepted
//!
//! A batch that fails is retried from the same position, so an unreachable sink costs
//! duplicate delivery attempts rather than lost events. Delivery is therefore
//! AT LEAST ONCE, which is the right direction for an audit export: a SIEM that sees an
//! event twice deduplicates on the event id, and one that never sees it cannot.
//!
//! # Isolation between streams
//!
//! One stream's failure must not delay or block another's. Each stream is shipped
//! independently and its failure is recorded against its own row, so a dead sink
//! accumulates its own consecutive-failure run while its healthy neighbours keep
//! advancing. This is the isolation the issue asks for, and it is a property of shipping
//! per stream rather than per batch across streams.

use std::sync::Arc;

use ironauth_env::Env;
use ironauth_store::log_stream::{LogStreamRecord, SinkType};
use ironauth_store::{ChainedAuditRow, Scope, Store, StoreError, ocsf};
use serde_json::{Value, json};

/// The most rows one stream ships in one pass.
///
/// Bounded so a stream that has fallen far behind cannot hold a connection or a sink's
/// patience for an unbounded time; it simply catches up over several passes.
pub const SHIP_BATCH: i64 = 500;

/// What ONE delivery attempt to a sink produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkOutcome {
    /// The sink accepted the batch.
    Accepted,
    /// The sink refused or could not be reached. Carries an OPERATOR-SAFE reason.
    ///
    /// Never a response body: a sink can echo arbitrary bytes, and this string is stored
    /// on the stream row and shown in a status read.
    Rejected(String),
}

/// A destination a batch of OCSF events can be shipped to.
///
/// One trait for every sink so a peer (Sentinel, GCS, `EventBridge`) is a new implementation
/// and no change to the shipper.
pub trait LogSink: Send + Sync {
    /// Which configured `sink_type` this implementation serves.
    fn sink_type(&self) -> SinkType;

    /// Ship `events` for `stream`, returning what the destination said.
    fn deliver<'a>(
        &'a self,
        stream: &'a LogStreamRecord,
        events: &'a [Value],
    ) -> std::pin::Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>>;
}

/// Render one audit row as the OCSF event a sink receives.
///
/// Returns [`None`] for an action that classifies as nothing, which cannot happen for a
/// row this build wrote (the classifier is exhaustive and the writer refuses an
/// unclassified action) but can for a row a NEWER build wrote and this one is reading
/// after a rollback. Skipping it is the only safe answer: shipping it under a guessed
/// class would file it under the wrong dashboard in someone's SIEM.
#[must_use]
pub fn render(row: &ChainedAuditRow, scope: Scope) -> Option<Value> {
    let mut event = ocsf::ocsf_event_from_wire(
        &row.action,
        &row.actor_kind,
        &row.actor_id,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        row.occurred_micros / 1000,
        Some(&row.target_id),
    )?;
    // The audit id is the sink's deduplication key. Delivery is at least once, so a
    // consumer needs a stable identity to collapse a repeat on, and without one a retried
    // batch looks like new events.
    if let Some(object) = event.as_object_mut() {
        object.insert("uid".to_string(), json!(row.audit_id));
        object.insert("correlation_uid".to_string(), json!(row.correlation_id));
    }
    Some(event)
}

/// Ship every active stream in `scope` once.
///
/// Returns how many events were accepted across all streams. A stream that fails is
/// recorded and SKIPPED rather than aborting the pass, so one dead sink cannot stop the
/// others: that isolation is an acceptance criterion, not a nicety.
///
/// # Errors
///
/// [`StoreError`] only when the stream LIST itself cannot be read. A per-stream delivery
/// failure is recorded on that stream, not returned, because it is not the caller's fault
/// and not the caller's to retry.
pub async fn ship_once(
    store: &Store,
    env: &Env,
    scope: Scope,
    sinks: &[Arc<dyn LogSink>],
) -> Result<u64, StoreError> {
    let scoped = store.scoped(scope);
    let streams = scoped.log_streams().list_active().await?;
    let mut shipped = 0_u64;
    for stream in streams {
        match ship_stream(store, env, scope, &stream, sinks).await {
            Ok(count) => shipped += count,
            Err(error) => {
                // Recorded against THIS stream and then stepped over. Returning here
                // would let the first dead sink in a scope stop every stream behind it.
                let _ = scoped
                    .log_streams()
                    .record_failure(env, &stream.id, &error.operator_safe())
                    .await;
            }
        }
    }
    Ok(shipped)
}

/// Ship ONE stream once, returning how many events the sink accepted.
async fn ship_stream(
    store: &Store,
    env: &Env,
    scope: Scope,
    stream: &LogStreamRecord,
    sinks: &[Arc<dyn LogSink>],
) -> Result<u64, ShipError> {
    let Some(sink) = sinks
        .iter()
        .find(|sink| sink.sink_type() == stream.sink_type)
    else {
        // Configured for a sink this build does not implement. REPORTED rather than
        // recorded here: every per-stream problem is written down in ONE place, by the
        // caller, so there is a single answer to "what happens when one stream fails"
        // rather than one answer per failure kind.
        return Err(ShipError::NoSink(stream.sink_type.as_str()));
    };

    let scoped = store.scoped(scope);
    let chain = scoped.audit_chain();
    let cursor = stream
        .cursor
        .as_ref()
        .map(|(micros, id)| (*micros, id.as_str()));

    // Both audit streams are read when the source is `both`, and each is read from the
    // SAME cursor position. The cursor is over (occurred_at, id), which is a total order
    // across both, so one position is enough for both reads.
    let mut candidates: Vec<ChainedAuditRow> = Vec::new();
    for audit_stream in ["admin_action", "authentication"] {
        if !stream.source.carries(audit_stream) {
            continue;
        }
        candidates.extend(chain.rows_after(audit_stream, cursor, SHIP_BATCH).await?);
    }
    // Reading two streams separately means the union is not ordered. It has to be, or
    // the cursor would advance past rows of the other stream that were never shipped.
    candidates.sort_by(|left, right| {
        (left.occurred_micros, &left.audit_id).cmp(&(right.occurred_micros, &right.audit_id))
    });
    candidates
        .truncate(usize::try_from(SHIP_BATCH).expect("SHIP_BATCH is a small positive constant"));

    let mut events = Vec::new();
    let mut last_position: Option<(i64, String)> = None;
    for row in &candidates {
        // The cursor advances over every row CONSIDERED, including one whose action this
        // build cannot classify and one the filter excludes. Advancing only over shipped
        // rows would stall the cursor forever behind the first excluded row.
        last_position = Some((row.occurred_micros, row.audit_id.clone()));
        let audit_stream = ocsf::class_for_wire(&row.action).map(|class| class.stream().as_str());
        let Some(audit_stream) = audit_stream else {
            continue;
        };
        if !stream.accepts(audit_stream, &row.action) {
            continue;
        }
        if let Some(event) = render(row, scope) {
            events.push(event);
        }
    }

    let Some(position) = last_position else {
        // Nothing new. Not a success and not a failure: an idle stream must not have its
        // health rewritten, or a healthy idle stream and a freshly recovered one become
        // indistinguishable.
        return Ok(0);
    };

    if events.is_empty() {
        // Everything in the window was filtered out. The cursor still advances, because
        // those rows will never become shippable, but no delivery happened so the health
        // is left alone.
        scoped
            .log_streams()
            .record_success(env, &stream.id, (position.0, &position.1))
            .await?;
        return Ok(0);
    }

    match sink.deliver(stream, &events).await {
        SinkOutcome::Accepted => {
            let accepted = u64::try_from(events.len()).unwrap_or(u64::MAX);
            scoped
                .log_streams()
                .record_success(env, &stream.id, (position.0, &position.1))
                .await?;
            Ok(accepted)
        }
        SinkOutcome::Rejected(reason) => {
            // The cursor is NOT advanced, so the batch is retried from the same place.
            scoped
                .log_streams()
                .record_failure(env, &stream.id, &reason)
                .await?;
            Ok(0)
        }
    }
}

/// Why one stream could not be shipped.
///
/// Every variant renders to an OPERATOR-SAFE reason, deliberately coarse: the reason is
/// stored on the stream row and read back through a status API, and a database error's
/// `Display` can carry a query fragment.
#[derive(Debug)]
enum ShipError {
    /// The stream names a sink type this build does not implement.
    NoSink(&'static str),
    /// A persistence fault.
    Store(StoreError),
}

impl From<StoreError> for ShipError {
    fn from(error: StoreError) -> Self {
        ShipError::Store(error)
    }
}

impl ShipError {
    /// The reason as it is written to the stream row.
    fn operator_safe(&self) -> String {
        match self {
            ShipError::NoSink(sink_type) => format!("no sink implementation for `{sink_type}`"),
            // A DATABASE error is rendered coarsely on purpose: its `Display` can carry
            // a query fragment, and this string is read back through a status API. The
            // other store errors are closed vocabulary and safe to name, and naming them
            // is the difference between an operator seeing "a persistence fault" forever
            // and seeing which one.
            ShipError::Store(StoreError::Database(_)) => {
                "a persistence fault interrupted the pass".to_string()
            }
            ShipError::Store(other) => format!("the pass could not run: {other}"),
        }
    }
}

/// The plain HTTPS sink: one POST of a JSON array of OCSF events.
///
/// Routed through [`ironauth_fetch::Fetcher`], so an operator-configured endpoint is
/// subject to the same SSRF policy every other outbound path is. A log stream is an
/// operator-controlled URL that the server will POST the environment's entire audit trail
/// to, which makes it exactly the shape that policy exists for.
pub struct HttpLogSink {
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl HttpLogSink {
    /// Ship through `fetcher`.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self { fetcher }
    }

    /// The configured endpoint, or `None` when the stream's `sink_config` does not carry
    /// a usable one.
    fn endpoint(stream: &LogStreamRecord) -> Option<&str> {
        stream.sink_config.get("endpoint")?.as_str()
    }
}

impl LogSink for HttpLogSink {
    fn sink_type(&self) -> SinkType {
        SinkType::Http
    }

    fn deliver<'a>(
        &'a self,
        stream: &'a LogStreamRecord,
        events: &'a [Value],
    ) -> std::pin::Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>> {
        let fetcher = Arc::clone(&self.fetcher);
        let endpoint = Self::endpoint(stream).map(str::to_owned);
        let body = serde_json::to_string(events).unwrap_or_else(|_| "[]".to_string());
        Box::pin(async move {
            let Some(endpoint) = endpoint else {
                return SinkOutcome::Rejected(
                    "sink_config carries no `endpoint` string".to_string(),
                );
            };
            let request = ironauth_fetch::FetchRequest::new(
                ironauth_fetch::FetchPurpose::LogStreamDelivery,
                http::Method::POST,
                endpoint,
            )
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            )
            .body(body);
            // Matched by VARIANT rather than rendered with `Display`, so the reason
            // stored on the stream row is operator-safe by construction. This string is
            // read back through a status API, and a rendering that ever grew to include a
            // response body would carry whatever the sink chose to echo straight out.
            match fetcher.fetch(request).await {
                Ok(response) if response.status().is_success() => SinkOutcome::Accepted,
                Ok(response) => {
                    SinkOutcome::Rejected(format!("sink answered {}", response.status().as_u16()))
                }
                Err(ironauth_fetch::FetchError::Blocked) => SinkOutcome::Rejected(
                    "the outbound policy refused the configured endpoint".to_string(),
                ),
                Err(ironauth_fetch::FetchError::Timeout) => {
                    SinkOutcome::Rejected("the sink timed out".to_string())
                }
                Err(_) => SinkOutcome::Rejected("the sink could not be reached".to_string()),
            }
        })
    }
}
