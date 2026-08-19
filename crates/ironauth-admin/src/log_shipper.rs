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
use ironauth_store::{ChainedAuditRow, CursorOrigin, Scope, Store, StoreError, ocsf};
use serde_json::{Value, json};

/// The most rows one stream ships in one pass.
///
/// Bounded so a stream that has fallen far behind cannot hold a connection or a sink's
/// patience for an unbounded time; it simply catches up over several passes.
pub const SHIP_BATCH: i64 = 500;

/// Consecutive failures after which a batch is DEAD-LETTERED and the cursor advances past
/// it.
///
/// A cursor pipeline has no other way out of head-of-line blocking: a batch the sink
/// refuses forever is otherwise retried forever from the same position, and every later
/// event stops reaching the SIEM. The threshold matches the `FAILING` health boundary, so
/// a stream is reported as failing before anything is set aside, and an operator who is
/// watching has the same warning the number gives them.
pub const DEAD_LETTER_AFTER: i32 = ironauth_store::log_stream::FAILING_AFTER;

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
    ///
    /// `credential` is the RESOLVED secret value the stream named, opened by the shipper.
    /// Sinks never resolve it themselves: one resolution path means one place that can
    /// leak it, and a sink that took a secret NAME would have to hold the master key.
    /// `signature` is the batch signature when the stream carries a signing secret, and
    /// [`None`] when it ships unsigned. Computed by the shipper, never by the sink: it must be
    /// identical whatever carried it, and a per-sink signature would be four chances to get
    /// the canonical form subtly different.
    ///
    /// `position` is the cursor position that signature covers, and a sink MUST transmit it
    /// alongside the signature. Without it a consumer cannot rebuild the canonical string, so
    /// it cannot verify anything at all: the signature is over `(stream id, sequence, cursor
    /// id, count, digest)` and only the last two are derivable from the payload. This
    /// parameter exists because the trait previously did not carry it, which is why
    /// `POSITION_HEADER` was defined, documented as sent, and sent by nothing.
    fn deliver<'a>(
        &'a self,
        stream: &'a LogStreamRecord,
        credential: Option<&'a str>,
        events: &'a [Value],
        signature: Option<&'a str>,
        position: (i64, &'a str),
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

/// Re-ship every outstanding dead letter for `stream_id`, marking each replayed only when
/// the sink accepts it.
///
/// Reads the range back from `audit_log` rather than from a stored copy, so a replay
/// delivers the events as they are, and a range whose rows retention has since removed
/// simply replays fewer events rather than failing.
///
/// Marked replayed ONLY on acceptance. A replay that failed and was marked anyway would
/// erase the record of the gap, which is the one thing this table exists to keep.
///
/// # Errors
///
/// [`StoreError`] when the dead letters cannot be read or the mark cannot be written.
pub async fn replay_dead_letters(
    store: &Store,
    env: &Env,
    scope: Scope,
    stream_id: &str,
    sinks: &[Arc<dyn LogSink>],
) -> Result<u64, StoreError> {
    let scoped = store.scoped(scope);
    let Some(stream) = scoped
        .log_streams()
        .list_active()
        .await?
        .into_iter()
        .find(|candidate| candidate.id == stream_id)
    else {
        return Ok(0);
    };
    let Some(sink) = sinks
        .iter()
        .find(|sink| sink.sink_type() == stream.sink_type)
    else {
        return Ok(0);
    };
    let credential = scoped
        .log_streams()
        .open_credential(&stream)
        .await?
        .and_then(|opened| String::from_utf8(opened).ok());

    let mut replayed = 0_u64;
    for dead in scoped
        .log_streams()
        .outstanding_dead_letters(stream_id)
        .await?
    {
        let chain = scoped.audit_chain();
        // Read from just BEFORE the range start, since `rows_after` is exclusive and the
        // recorded range is inclusive at both ends.
        let cursor = predecessor_of(&dead.from);
        let mut events = Vec::new();
        for audit_stream in ["admin_action", "authentication"] {
            if !stream.source.carries(audit_stream) {
                continue;
            }
            for row in chain
                .rows_after(
                    audit_stream,
                    Some((cursor.0, cursor.1.as_str())),
                    // Synthetic: `predecessor_of` names no row, and the range this walks is
                    // one the dead letter already recorded. A retention gap is not a
                    // question this position can answer.
                    CursorOrigin::BoundedRange,
                    SHIP_BATCH,
                    stream.organization_id.as_deref(),
                )
                .await?
            {
                if (row.occurred_micros, row.audit_id.as_str()) > (dead.to.0, dead.to.1.as_str()) {
                    break;
                }
                if let Some(event) = render(&row, scope) {
                    events.push(event);
                }
            }
        }
        if events.is_empty() {
            // Nothing left to send: retention removed the range. Mark it replayed rather
            // than leaving an entry that can never clear.
            scoped.log_streams().mark_replayed(env, &dead.id).await?;
            continue;
        }
        // A replay is signed over the DEAD LETTER's own position, not a fresh one: it is the
        // same batch being delivered again, so a consumer that already verified it sees the
        // position it already has and treats it as the replay it is.
        let replay_signature = match scoped.log_streams().open_signing_secret(&stream).await? {
            Some(key) => serde_json::to_string(&events).ok().map(|events_json| {
                crate::log_stream_signature::sign(
                    &key,
                    &crate::log_stream_signature::canonical_string(
                        &stream.id,
                        dead.from.0,
                        &dead.from.1,
                        events.len(),
                        &events_json,
                    ),
                )
            }),
            None => None,
        };
        if matches!(
            sink.deliver(
                &stream,
                credential.as_deref(),
                &events,
                replay_signature.as_deref(),
                (dead.from.0, dead.from.1.as_str())
            )
            .await,
            SinkOutcome::Accepted
        ) {
            scoped.log_streams().mark_replayed(env, &dead.id).await?;
            replayed += u64::try_from(events.len()).unwrap_or(0);
        }
    }
    Ok(replayed)
}

/// The cursor position immediately BEFORE `at`, so an exclusive read includes `at`.
///
/// The audit id sorts as text, and the empty string sorts below every id, so pairing the
/// same instant with an empty id is strictly less than `at` and greater than everything at
/// an earlier instant. Subtracting a microsecond instead would skip any row that shares the
/// instant and sorts below `at`.
fn predecessor_of(at: &(i64, String)) -> (i64, String) {
    (at.0, String::new())
}

/// Ship ONE stream once, returning how many events the sink accepted.
// Sat at exactly the 100-line limit, and the retention-gap fix adds ONE argument line at the
// `rows_after` call. Allowed rather than split: the natural seam is the two-stream read loop,
// and lifting it out would put the cursor handling in one function and the ordering that
// depends on it in another, which is how the two get changed apart.
#[allow(clippy::too_many_lines)]
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
        candidates.extend(
            chain
                .rows_after(
                    audit_stream,
                    cursor,
                    // The shipper's own resume position: a row this stream was handed and
                    // recorded. If it has been pruned the stream MUST be told, which is the
                    // refusal this discriminator preserves.
                    CursorOrigin::ConsumerResume,
                    SHIP_BATCH,
                    // A per-organization stream filters in SQL rather than in the loop
                    // below. Filtering here is what makes the isolation a property of the
                    // QUERY: a row belonging to another organization is never read, so no
                    // later mistake in this function can put it in a batch.
                    stream.organization_id.as_deref(),
                )
                .await?,
        );
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

    // Resolved ONCE, here, and handed to the sink as a value. A sink that took a name
    // would need the master key, which would put the ability to open every environment
    // secret behind every sink implementation including ones a deployment adds itself.
    let credential = resolve_credential(store, scope, stream).await?;

    // SIGNED before delivery, over the position this batch is about to advance the cursor to
    // (issue #110 criterion 5). Computed here rather than inside each sink because it must be
    // identical whatever carried it: a consumer reading the S3 sink's objects and one behind
    // the HTTP sink verify the same bytes, and a per-sink signature would be four chances to
    // get the canonical form subtly different.
    //
    // A stream with no signing secret ships unsigned, exactly as every stream did before this
    // existed. That is the deliberate default: signing with a key no consumer holds would
    // present as every batch failing verification, which is worse than not signing.
    let signature = match store
        .scoped(scope)
        .log_streams()
        .open_signing_secret(stream)
        .await?
    {
        Some(key) => {
            // These events came out of the store as `Value`, so re-serializing them cannot
            // fail. Handled rather than unwrapped because a panic in the shipper stops every
            // stream, and a stream that ships unsigned is strictly better than one that
            // stops: the operator sees an unsigned batch, not silence.
            let Ok(events_json) = serde_json::to_string(&events) else {
                return Ok(0);
            };
            let canonical = crate::log_stream_signature::canonical_string(
                &stream.id,
                position.0,
                &position.1,
                events.len(),
                &events_json,
            );
            Some(crate::log_stream_signature::sign(&key, &canonical))
        }
        None => None,
    };

    match sink
        .deliver(
            stream,
            credential.as_deref(),
            &events,
            signature.as_deref(),
            (position.0, position.1.as_str()),
        )
        .await
    {
        SinkOutcome::Accepted => {
            let accepted = u64::try_from(events.len()).unwrap_or(u64::MAX);
            scoped
                .log_streams()
                .record_success(env, &stream.id, (position.0, &position.1))
                .await?;
            Ok(accepted)
        }
        SinkOutcome::Rejected(reason) => {
            scoped
                .log_streams()
                .record_failure(env, &stream.id, &reason)
                .await?;
            // One MORE than the run recorded before this pass, since the read above
            // predates it.
            let failures = stream.health.consecutive_failures.saturating_add(1);
            if failures < DEAD_LETTER_AFTER {
                // The cursor is NOT advanced, so the batch is retried from the same place.
                return Ok(0);
            }
            // The run is over. Record the RANGE and advance past it, because a batch the
            // sink refuses forever would otherwise be retried forever from the same
            // position and every LATER event would never reach the SIEM. Losing sight of
            // this batch is bad; losing sight of everything after it is worse.
            // The range spans the batch: first considered row to last. A single-point
            // range would replay one event and report the whole batch recovered.
            let first = candidates.first().map_or_else(
                || position.clone(),
                |row| (row.occurred_micros, row.audit_id.clone()),
            );
            // Recorded BEFORE the cursor advances, and with `?`, so a dead letter that
            // cannot be written stops the advance. Advancing anyway would drop the batch
            // with no record of it existing.
            scoped
                .log_streams()
                .dead_letter(
                    env,
                    &stream.id,
                    (first.0, &first.1, position.0, &position.1),
                    i32::try_from(events.len()).unwrap_or(i32::MAX),
                    &reason,
                )
                .await?;
            scoped
                .log_streams()
                .record_success(env, &stream.id, (position.0, &position.1))
                .await?;
            Ok(0)
        }
    }
}

/// Open the secret a stream names, or [`None`] when it names none.
///
/// A stream that NAMES a credential and cannot open it is an ERROR, not an empty
/// credential: delivering without it would present an unauthenticated batch to the sink,
/// which either rejects it (noise) or accepts it (an audit trail arriving somewhere with
/// no proof of who sent it).
async fn resolve_credential(
    store: &Store,
    scope: Scope,
    stream: &LogStreamRecord,
) -> Result<Option<String>, ShipError> {
    let Some(opened) = store
        .scoped(scope)
        .log_streams()
        .open_credential(stream)
        .await?
    else {
        return Ok(None);
    };
    // A credential that is not UTF-8 cannot go in a header, and guessing an encoding
    // would send a mangled token that the sink rejects for reasons an operator cannot
    // see from here.
    String::from_utf8(opened)
        .map(Some)
        .map_err(|_| ShipError::CredentialNotText)
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
    /// The named credential is not UTF-8, so it cannot be presented in a header.
    CredentialNotText,
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
            // Says the SHAPE is wrong and nothing about the value.
            ShipError::CredentialNotText => "the named credential is not valid UTF-8".to_string(),
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
        _credential: Option<&'a str>,
        events: &'a [Value],
        signature: Option<&'a str>,
        position: (i64, &'a str),
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
            let mut request = ironauth_fetch::FetchRequest::new(
                ironauth_fetch::FetchPurpose::LogStreamDelivery,
                http::Method::POST,
                endpoint,
            )
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            )
            .body(body);
            if let Some(signature) = signature {
                // A signature that will not encode means the batch cannot be presented with
                // the proof a consumer verifies. Sending it WITHOUT would deliver the
                // environment's audit trail unauthenticated to a consumer that is configured
                // to expect authentication, so refusing is the only safe answer -- the same
                // reasoning `post_json` applies to its own headers.
                let Ok(value) = http::HeaderValue::from_str(signature) else {
                    return SinkOutcome::Rejected(
                        "the batch signature could not be encoded as a header".to_string(),
                    );
                };
                request = request.header(http::HeaderName::from_static(SIGNATURE_HEADER), value);
                // The position travels WITH the signature or the signature is unverifiable.
                // Built from the same values the shipper signed, one line above the send, so
                // the two cannot drift apart.
                let position_value = position_header_value(&stream.id, position.0, position.1);
                // REFUSED on an encode failure, exactly as the signature above is. Sending
                // the signature without the position ships a batch that LOOKS verifiable and
                // is not: a consumer cannot rebuild the canonical string without the
                // position, so it would reject an honest batch as tampered. Dropping it
                // quietly was the same shape as the defect this wiring repairs.
                let Ok(value) = http::HeaderValue::from_str(&position_value) else {
                    return SinkOutcome::Rejected(
                        "the batch position could not be encoded as a header".to_string(),
                    );
                };
                request = request.header(http::HeaderName::from_static(POSITION_HEADER), value);
            }
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
                Err(ironauth_fetch::FetchError::SchemeNotAllowed) => SinkOutcome::Rejected(
                    "the endpoint must be https; a plaintext http sink would export the \
                     audit trail in cleartext"
                        .to_string(),
                ),
                Err(_) => SinkOutcome::Rejected("the sink could not be reached".to_string()),
            }
        })
    }
}

// ===========================================================================
// The vendor adapters (issue #110).
//
// Both are HTTPS POSTs that differ in three ways only: the header the credential goes in,
// the path appended to the configured endpoint, and the body shape. They therefore share
// one POST helper rather than each restating the fetch, the status mapping and the
// operator-safe error rendering, which is where three copies would drift.

/// POST `body` to `url` with `headers`, mapping the outcome the same way for every sink.
///
/// Shared on purpose: a per-sink copy of this is three places for the status boundary to be
/// written differently and three places for a response body to leak into a stored reason.
async fn post_json(
    fetcher: &ironauth_fetch::Fetcher,
    url: String,
    headers: Vec<(&'static str, String)>,
    body: String,
) -> SinkOutcome {
    let mut request = ironauth_fetch::FetchRequest::new(
        ironauth_fetch::FetchPurpose::LogStreamDelivery,
        http::Method::POST,
        url,
    )
    .header(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    )
    .body(body);
    for (name, value) in headers {
        // A header value that will not encode means the batch cannot be presented
        // correctly. Sending it WITHOUT the header would deliver the environment's audit
        // trail unauthenticated, so refusing is the only safe answer.
        let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) else {
            return SinkOutcome::Rejected("a required header could not be encoded".to_string());
        };
        request = request.header(name, value);
    }
    match fetcher.fetch(request).await {
        Ok(response) if response.status().is_success() => SinkOutcome::Accepted,
        Ok(response) => {
            SinkOutcome::Rejected(format!("sink answered {}", response.status().as_u16()))
        }
        Err(ironauth_fetch::FetchError::Blocked) => {
            SinkOutcome::Rejected("the outbound policy refused the configured endpoint".to_string())
        }
        Err(ironauth_fetch::FetchError::Timeout) => {
            SinkOutcome::Rejected("the sink timed out".to_string())
        }
        // Named specifically, because it is a CONFIGURATION mistake and the generic
        // "could not be reached" sends an operator looking at their network. An audit
        // export must not travel in cleartext, so an `http://` endpoint is refused before
        // a socket is opened, and the reason has to say which of those two happened.
        Err(ironauth_fetch::FetchError::SchemeNotAllowed) => SinkOutcome::Rejected(
            "the endpoint must be https; a plaintext http sink would export the audit \
             trail in cleartext"
                .to_string(),
        ),
        Err(_) => SinkOutcome::Rejected("the sink could not be reached".to_string()),
    }
}

/// The endpoint a stream's `sink_config` names, if it names a usable one.
fn configured_endpoint(stream: &LogStreamRecord) -> Option<&str> {
    stream.sink_config.get("endpoint")?.as_str()
}

/// The Datadog intake body: a JSON ARRAY of envelopes carrying the OCSF event whole.
///
/// Pure so the shape is testable without a socket. The shape is the part that is easy to
/// get wrong and impossible to notice: a malformed body is a 400 from a vendor, which
/// looks exactly like a credential problem in the stored reason.
#[must_use]
pub fn datadog_body(events: &[Value]) -> String {
    let payload: Vec<Value> = events
        .iter()
        .map(|event| {
            json!({
                "ddsource": "ironauth",
                "service": "ironauth",
                "message": event,
            })
        })
        .collect();
    serde_json::to_string(&payload).unwrap_or_else(|_| "[]".to_string())
}

/// The Splunk HEC body: NEWLINE-DELIMITED event objects, NOT a JSON array.
///
/// HEC parses a concatenated stream of objects and REJECTS a JSON array. Sending an array
/// is the natural mistake, it is what every other sink here wants, and it fails as an
/// opaque 400.
#[must_use]
pub fn splunk_body(events: &[Value], index: Option<&str>) -> String {
    events
        .iter()
        .map(|event| {
            let mut envelope = json!({ "sourcetype": "ironauth:ocsf", "event": event });
            if let (Some(index), Some(object)) = (index, envelope.as_object_mut()) {
                object.insert("index".to_string(), json!(index));
            }
            serde_json::to_string(&envelope).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The Datadog logs intake adapter.
///
/// Datadog authenticates with the API key in `DD-API-KEY` and takes a JSON array of log
/// objects. The OCSF event is carried whole under `message`, and the envelope around it
/// gives Datadog the `ddsource` and `service` it indexes on.
pub struct DatadogSink {
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl DatadogSink {
    /// Ship through `fetcher`.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self { fetcher }
    }
}

impl LogSink for DatadogSink {
    fn sink_type(&self) -> SinkType {
        SinkType::Datadog
    }

    fn deliver<'a>(
        &'a self,
        stream: &'a LogStreamRecord,
        credential: Option<&'a str>,
        events: &'a [Value],
        signature: Option<&'a str>,
        position: (i64, &'a str),
    ) -> std::pin::Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>> {
        let fetcher = Arc::clone(&self.fetcher);
        let endpoint = configured_endpoint(stream).map(str::to_owned);
        let credential = credential.map(str::to_owned);
        let body = datadog_body(events);
        Box::pin(async move {
            let Some(endpoint) = endpoint else {
                return SinkOutcome::Rejected(
                    "sink_config carries no `endpoint` string".to_string(),
                );
            };
            let Some(credential) = credential else {
                // Datadog rejects an unauthenticated intake, so sending anyway would burn
                // a retry budget on a request that cannot succeed.
                return SinkOutcome::Rejected(
                    "the datadog sink needs an API key; set credential_secret_name".to_string(),
                );
            };
            let mut headers = vec![("dd-api-key", credential)];
            headers.extend(signed_batch_headers(&stream.id, signature, position));
            post_json(&fetcher, endpoint, headers, body).await
        })
    }
}

/// The Splunk HTTP Event Collector adapter.
///
/// HEC authenticates with `Authorization: Splunk <token>` and takes NEWLINE-DELIMITED
/// event objects rather than a JSON array. That is not a stylistic difference: HEC parses
/// a concatenated stream of objects, and sending it a JSON array is rejected.
pub struct SplunkHecSink {
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl SplunkHecSink {
    /// Ship through `fetcher`.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self { fetcher }
    }
}

impl LogSink for SplunkHecSink {
    fn sink_type(&self) -> SinkType {
        SinkType::SplunkHec
    }

    fn deliver<'a>(
        &'a self,
        stream: &'a LogStreamRecord,
        credential: Option<&'a str>,
        events: &'a [Value],
        signature: Option<&'a str>,
        position: (i64, &'a str),
    ) -> std::pin::Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>> {
        let fetcher = Arc::clone(&self.fetcher);
        let endpoint = configured_endpoint(stream).map(str::to_owned);
        let credential = credential.map(str::to_owned);
        // An optional index, which HEC takes per event rather than per request.
        let index = stream
            .sink_config
            .get("index")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let body = splunk_body(events, index.as_deref());
        Box::pin(async move {
            let Some(endpoint) = endpoint else {
                return SinkOutcome::Rejected(
                    "sink_config carries no `endpoint` string".to_string(),
                );
            };
            let Some(credential) = credential else {
                return SinkOutcome::Rejected(
                    "the splunk_hec sink needs a token; set credential_secret_name".to_string(),
                );
            };
            let mut headers = vec![("authorization", format!("Splunk {credential}"))];
            headers.extend(signed_batch_headers(&stream.id, signature, position));
            post_json(&fetcher, endpoint, headers, body).await
        })
    }
}

/// One stream's state at the end of a pass, for the metrics surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamObservation {
    /// Which sink this stream ships to.
    pub sink_type: SinkType,
    /// Its coarse delivery status.
    pub status: ironauth_store::log_stream::StreamStatus,
    /// Outstanding dead letters: batches set aside and not yet replayed.
    pub outstanding_dead_letters: u64,
}

/// Told what each shipping pass saw, so the BINARY can emit metrics.
///
/// An observer rather than a metrics call here, matching the outbox and retention
/// sweepers: this crate takes no metrics dependency, and the aggregation that keeps
/// cardinality bounded belongs with the exporter.
pub trait LogShipperObserver: Send + Sync {
    /// Every active stream in one scope, at the end of a pass over it.
    fn observed(&self, streams: &[StreamObservation]);
}

/// An observer that says nothing, for tests and for a deployment with no exporter.
pub struct SilentShipperObserver;

impl LogShipperObserver for SilentShipperObserver {
    fn observed(&self, _streams: &[StreamObservation]) {}
}

/// Collect the observation for every active stream in `scope`.
///
/// # Errors
///
/// [`StoreError`] when the streams cannot be listed.
pub async fn observe(store: &Store, scope: Scope) -> Result<Vec<StreamObservation>, StoreError> {
    let scoped = store.scoped(scope);
    let mut out = Vec::new();
    for stream in scoped.log_streams().list_active().await? {
        let outstanding = scoped
            .log_streams()
            .outstanding_dead_letters(&stream.id)
            .await?
            .len();
        out.push(StreamObservation {
            sink_type: stream.sink_type,
            status: stream.health.status(),
            outstanding_dead_letters: u64::try_from(outstanding).unwrap_or(u64::MAX),
        });
    }
    Ok(out)
}

/// The background task that ships every configured stream on an interval.
///
/// Modelled on the audit retention sweeper (issue #109) and for the same reason: a pass
/// that fails must not stop the next one, and shutdown must not wait out a whole interval.
pub struct LogShipper {
    handle: Option<tokio::task::JoinHandle<()>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl LogShipper {
    /// Spawn the shipper. Returns immediately; it runs until
    /// [`shutdown`](LogShipper::shutdown) is awaited or it is dropped.
    #[must_use]
    pub fn spawn(
        store: Store,
        env: Env,
        scopes: Arc<dyn ironauth_store::outbox::ScopeSource>,
        sinks: Vec<Arc<dyn LogSink>>,
        observer: Arc<dyn LogShipperObserver>,
        interval: std::time::Duration,
    ) -> Self {
        use std::sync::atomic::Ordering;

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            while !task_stop.load(Ordering::Relaxed) {
                match scopes.scopes().await {
                    Ok(resolved) => {
                        for scope in resolved {
                            // Checked BETWEEN scopes, so a shutdown is bounded by one
                            // scope's bounded pass rather than by the whole sweep.
                            if task_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            // A per-stream failure is already recorded on its own row by
                            // `ship_once`; only a failure to LIST reaches here.
                            if let Err(error) = ship_once(&store, &env, scope, &sinks).await {
                                tracing::error!(
                                    %error,
                                    "a log stream shipping pass could not read its streams"
                                );
                                continue;
                            }
                            // Observed AFTER the pass, so the status reflects what this
                            // pass did rather than what the previous one left behind.
                            match observe(&store, scope).await {
                                Ok(streams) => observer.observed(&streams),
                                Err(error) => tracing::error!(
                                    %error,
                                    "a log stream pass could not be observed for metrics"
                                ),
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "log stream shipping could not enumerate scopes");
                    }
                }
                let mut slept = std::time::Duration::ZERO;
                while slept < interval && !task_stop.load(Ordering::Relaxed) {
                    let slice =
                        std::time::Duration::from_millis(200).min(interval.saturating_sub(slept));
                    tokio::time::sleep(slice).await;
                    slept += slice;
                }
            }
        });
        Self {
            handle: Some(handle),
            stop,
        }
    }

    /// Stop the shipper and wait for the in-flight pass to finish.
    pub async fn shutdown(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for LogShipper {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The S3-compatible object-store sink.
///
/// The header a shipped batch's signature travels in (issue #110 criterion 5).
///
/// One name across every sink, because a consumer verifying batches from an HTTP forwarder
/// and from a Splunk index is running the same code: a per-sink header would make the sample
/// consumer sink-aware for no reason a SIEM operator would accept.
pub const SIGNATURE_HEADER: &str = "x-ironauth-log-signature";

/// The header carrying the cursor position the signature covers.
///
/// Sent BESIDE the signature rather than only inside it, because a consumer needs the
/// position to rebuild the canonical string before it can verify anything -- and it must then
/// check the rebuilt string against the signature, which is what stops a sender rewriting the
/// position it claims. A position a consumer cannot see is a position it cannot check for a
/// gap or a replay.
pub const POSITION_HEADER: &str = "x-ironauth-log-position";

/// Render the position header's value.
///
/// `<stream id> <sequence> <cursor id>`, space separated, in the order the canonical string
/// uses them. Space separated because all three are opaque identifiers a consumer splits
/// positionally, and because a `:` or `.` would be a separator that could plausibly occur
/// inside an id and turn a parse bug into a verification failure with no visible cause.
///
/// The STREAM ID is in here as well as the position, despite the constant's name, because a
/// consumer needs all three to rebuild the canonical string and a second header would be a
/// second thing to forget to send.
#[must_use]
pub fn position_header_value(stream_id: &str, sequence: i64, cursor_id: &str) -> String {
    format!("{stream_id} {sequence} {cursor_id}")
}

/// The headers a batch carries when the stream is signed: the signature, and the position it
/// covers. Empty when the batch ships unsigned.
///
/// ONE function for all three HTTP-shaped sinks, because the two headers are only useful
/// together. A sink that sent the signature and forgot the position would ship something that
/// looks verifiable and is not, which is precisely the state this repaired: `POSITION_HEADER`
/// was defined and documented as sent, and the only reference to it in the workspace was its
/// own declaration.
#[must_use]
pub fn signed_batch_headers(
    stream_id: &str,
    signature: Option<&str>,
    position: (i64, &str),
) -> Vec<(&'static str, String)> {
    signature.map_or_else(Vec::new, |signature| {
        vec![
            (SIGNATURE_HEADER, signature.to_owned()),
            (
                POSITION_HEADER,
                position_header_value(stream_id, position.0, position.1),
            ),
        ]
    })
}

/// The S3 object metadata key the batch signature travels in.
///
/// An S3 object carries no headers once written, so the signature has to become metadata or a
/// consumer reading the bucket has nowhere to find it. `x-amz-meta-` is the only prefix S3
/// preserves.
pub const S3_SIGNATURE_METADATA: &str = "x-amz-meta-ironauth-log-signature";

/// The S3 object metadata key the batch POSITION travels in.
///
/// Same reasoning as the signature: an object carries no headers once written, so a consumer
/// reading the bucket needs the position as metadata or it cannot rebuild the canonical
/// string. Both go inside the `SigV4` canonical headers for the same reason, that a metadata
/// header `SigV4` did not sign can be stripped or rewritten in flight, and a position an
/// attacker can rewrite is a gap and replay check an attacker controls.
pub const S3_POSITION_METADATA: &str = "x-amz-meta-ironauth-log-position";

/// One PUT per batch, keyed by stream and cursor position, signed with AWS `SigV4`.
///
/// # The key is derived from the batch, not from a clock
///
/// `<prefix>/<stream id>/<last audit id>.json`. Delivery is at least once, so the same
/// batch can be PUT twice; a key derived from the batch means the retry overwrites its own
/// object rather than creating a second copy of the same events. A timestamped key would
/// turn every retry into a duplicate object that a downstream consumer has to deduplicate.
pub struct S3LogSink {
    fetcher: Arc<ironauth_fetch::Fetcher>,
    /// The clock seam, so the signing timestamp is deterministic under test.
    env: Env,
}

impl S3LogSink {
    /// Ship through `fetcher`, timestamping from `env`'s clock.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>, env: Env) -> Self {
        Self { fetcher, env }
    }
}

impl LogSink for S3LogSink {
    fn sink_type(&self) -> SinkType {
        SinkType::S3
    }

    // The S3 delivery is one operation: build the key, hash the payload, construct the
    // canonical request, sign it, and PUT. Splitting it would separate the canonical
    // request from the signature computed over it, which is the one pairing in this file
    // that must be read together to be checked.
    #[allow(clippy::too_many_lines)]
    fn deliver<'a>(
        &'a self,
        stream: &'a LogStreamRecord,
        credential: Option<&'a str>,
        events: &'a [Value],
        signature: Option<&'a str>,
        position: (i64, &'a str),
    ) -> std::pin::Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>> {
        // Captured under its own name because this method shadows `signature` with the
        // SigV4 request signature further down, and the two are entirely different things:
        // one authenticates this PUT to S3, the other proves the BATCH to whoever reads the
        // object afterwards. Conflating them is the mistake this rename exists to prevent.
        let batch_signature = signature.map(str::to_owned);
        // Owned before the async block, like the signature above and for the same reason: the
        // future outlives the borrow of `position`. `stream_id` is already owned inside the
        // block for the object key.
        let position_sequence = position.0;
        let position_cursor = position.1.to_owned();
        let fetcher = Arc::clone(&self.fetcher);
        let endpoint = configured_endpoint(stream).map(str::to_owned);
        let region = stream
            .sink_config
            .get("region")
            .and_then(Value::as_str)
            .unwrap_or("us-east-1")
            .to_owned();
        let bucket = stream
            .sink_config
            .get("bucket")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let prefix = stream
            .sink_config
            .get("prefix")
            .and_then(Value::as_str)
            .unwrap_or("ironauth")
            .trim_matches('/')
            .to_owned();
        let credential = credential.map(str::to_owned);
        let stream_id = stream.id.clone();
        // The last event's id names the object, so a retry of the same batch overwrites
        // rather than duplicating.
        let last = events
            .last()
            .and_then(|event| event["uid"].as_str())
            .unwrap_or("empty")
            .to_owned();
        let body = serde_json::to_string(events).unwrap_or_else(|_| "[]".to_string());
        let now = self.env.clock().now_utc();
        Box::pin(async move {
            let (Some(endpoint), Some(bucket)) = (endpoint, bucket) else {
                return SinkOutcome::Rejected(
                    "sink_config needs both an `endpoint` and a `bucket`".to_string(),
                );
            };
            // `<access key>:<secret>`, the same shape every S3 tool takes.
            let Some((access_key, secret)) = credential
                .as_deref()
                .and_then(|credential| credential.split_once(':'))
            else {
                return SinkOutcome::Rejected(
                    "the s3 sink needs an `<access key id>:<secret access key>` credential; \
                     set credential_secret_name"
                        .to_string(),
                );
            };

            let Some((date, timestamp)) = sigv4_timestamps(now) else {
                return SinkOutcome::Rejected("the signing clock is before the epoch".to_string());
            };
            let host = endpoint
                .split("://")
                .nth(1)
                .unwrap_or(&endpoint)
                .trim_end_matches('/')
                .to_owned();
            let path = format!("/{bucket}/{prefix}/{stream_id}/{last}.json");
            let payload_hash = crate::sigv4::sha256_hex(body.as_bytes());
            let canonical = crate::sigv4::CanonicalRequest {
                method: "PUT",
                path: &path,
                headers: {
                    let mut headers = vec![
                        ("host".to_string(), host.clone()),
                        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
                        ("x-amz-date".to_string(), timestamp.clone()),
                    ];
                    // Object METADATA, because an S3 object has no headers once written and
                    // a consumer reading the bucket later has nowhere else to find it.
                    //
                    // Inside the CANONICAL headers, not merely on the request: a metadata
                    // header SigV4 did not sign can be stripped or rewritten in flight, and
                    // the batch signature is exactly the thing an attacker would remove.
                    if let Some(signature) = batch_signature.as_deref() {
                        headers.push((S3_SIGNATURE_METADATA.to_string(), signature.to_owned()));
                        headers.push((
                            S3_POSITION_METADATA.to_string(),
                            position_header_value(&stream_id, position_sequence, &position_cursor),
                        ));
                    }
                    headers
                },
                payload_hash: &payload_hash,
            };
            let scope = crate::sigv4::credential_scope(&date, &region, "s3");
            let to_sign = crate::sigv4::string_to_sign(&timestamp, &scope, &canonical.render());
            let signature = crate::sigv4::sign(secret, &date, &region, "s3", &to_sign);
            let authorization = crate::sigv4::authorization_header(
                access_key,
                &scope,
                &canonical.signed_headers(),
                &signature,
            );

            post_object(
                &fetcher,
                format!("{}{path}", endpoint.trim_end_matches('/')),
                {
                    let mut headers = vec![
                        ("x-amz-content-sha256", payload_hash),
                        ("x-amz-date", timestamp),
                        ("authorization", authorization),
                    ];
                    if let Some(signature) = batch_signature {
                        headers.push((S3_SIGNATURE_METADATA, signature));
                        headers.push((
                            S3_POSITION_METADATA,
                            position_header_value(&stream_id, position_sequence, &position_cursor),
                        ));
                    }
                    headers
                },
                body,
            )
            .await
        })
    }
}

/// `(yyyymmdd, yyyymmddThhmmssZ)` for a signing instant.
///
/// Derived from the passed instant rather than read from a clock here, so a test can pin
/// it. Returns [`None`] before the epoch, which cannot happen in practice and is refused
/// rather than wrapped into a signature that would be rejected for an unrelated reason.
fn sigv4_timestamps(at: std::time::SystemTime) -> Option<(String, String)> {
    let secs = at
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let days = secs / 86_400;
    let (year, month, day) = civil_from_days(i64::try_from(days).ok()?);
    let rest = secs % 86_400;
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    Some((
        format!("{year:04}{month:02}{day:02}"),
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
    ))
}

/// Days since the epoch to a civil date, by Howard Hinnant's algorithm.
///
/// Written out rather than pulled in, because the only alternative in this tree is a date
/// crate this crate does not otherwise need, and `SigV4` wants nothing beyond `yyyymmdd`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (
        year,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// PUT `body` to `url`, mapping the outcome exactly as [`post_json`] does.
async fn post_object(
    fetcher: &ironauth_fetch::Fetcher,
    url: String,
    headers: Vec<(&'static str, String)>,
    body: String,
) -> SinkOutcome {
    let mut request = ironauth_fetch::FetchRequest::new(
        ironauth_fetch::FetchPurpose::LogStreamDelivery,
        http::Method::PUT,
        url,
    )
    .header(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    )
    .body(body);
    for (name, value) in headers {
        let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) else {
            return SinkOutcome::Rejected("a required header could not be encoded".to_string());
        };
        request = request.header(name, value);
    }
    match fetcher.fetch(request).await {
        Ok(response) if response.status().is_success() => SinkOutcome::Accepted,
        Ok(response) => {
            SinkOutcome::Rejected(format!("sink answered {}", response.status().as_u16()))
        }
        Err(ironauth_fetch::FetchError::Blocked) => {
            SinkOutcome::Rejected("the outbound policy refused the configured endpoint".to_string())
        }
        Err(ironauth_fetch::FetchError::Timeout) => {
            SinkOutcome::Rejected("the sink timed out".to_string())
        }
        Err(ironauth_fetch::FetchError::SchemeNotAllowed) => SinkOutcome::Rejected(
            "the endpoint must be https; a plaintext http sink would export the audit \
             trail in cleartext"
                .to_string(),
        ),
        Err(_) => SinkOutcome::Rejected("the sink could not be reached".to_string()),
    }
}

#[cfg(test)]
mod s3_tests {
    use super::*;

    #[test]
    fn the_signing_timestamps_render_the_expected_civil_date() {
        // 2024-01-02T03:04:05Z.
        let at = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_704_164_645);
        let (date, timestamp) = sigv4_timestamps(at).expect("after the epoch");
        assert_eq!(date, "20240102");
        assert_eq!(timestamp, "20240102T030405Z");
        assert!(
            timestamp.starts_with(&date),
            "the two must agree, or the credential scope and the x-amz-date disagree and \
             the signature is rejected: {date} {timestamp}"
        );
    }

    #[test]
    fn the_epoch_itself_renders_as_1970() {
        let (date, timestamp) =
            sigv4_timestamps(std::time::SystemTime::UNIX_EPOCH).expect("the epoch");
        assert_eq!(date, "19700101");
        assert_eq!(timestamp, "19700101T000000Z");
    }
}

// ===========================================================================
// The signed security-event stream (issue #110, exploratory slice).
//
// EXPLORATORY under the feature maturity ladder. It is off unless a stream names a signing
// secret, and the full productization (SSF/CAEP transmitter) is M14's, not this.

/// The header carrying the batch signature: `v1=<lowercase hex>`.
pub const HEADER_SIGNATURE: &str = "x-ironauth-signature";
/// The header carrying the batch's position, so a consumer can order and deduplicate.
pub const HEADER_SEQUENCE: &str = "x-ironauth-sequence";

/// What a consumer must be given to verify a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBatch {
    /// The exact bytes that were signed and sent.
    pub body: String,
    /// `v1=<hex>`.
    pub signature: String,
    /// The last audit id in the batch: this batch's position in the stream's order.
    pub sequence: String,
}

/// Sign `body` for `sequence` under `secret`.
///
/// The SEQUENCE is inside the signed input, not merely alongside it. Signing the body alone
/// would let an attacker who can reorder deliveries replay an older batch under a newer
/// position, and the signature would still verify: the consumer would accept stale events
/// as current. Binding the two means a batch verifies only at the position it was sent for.
#[must_use]
pub fn sign_batch(secret: &str, sequence: &str, body: &str) -> SignedBatch {
    let signed_input = format!("{sequence}.{body}");
    let digest = crate::sigv4::hmac_sha256_hex(secret.as_bytes(), signed_input.as_bytes());
    SignedBatch {
        body: body.to_string(),
        signature: format!("v1={digest}"),
        sequence: sequence.to_string(),
    }
}

/// Why a consumer refused a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyFailure {
    /// The signature header is not `v1=<hex>`.
    Malformed,
    /// The signature does not match the body and sequence under this secret.
    BadSignature,
    /// The batch's position is not after the last one accepted.
    OutOfOrder,
}

/// The reference consumer: verify `batch` under `secret`, given the last accepted sequence.
///
/// This IS the published sample consumer the issue asks for, kept in the same crate as the
/// signer so the two cannot drift. A sample that lived in documentation would be a second
/// implementation nobody compiles.
///
/// # Errors
///
/// [`VerifyFailure`] naming which check failed.
pub fn verify_batch(
    secret: &str,
    last_accepted: Option<&str>,
    batch: &SignedBatch,
) -> Result<(), VerifyFailure> {
    let Some(offered) = batch.signature.strip_prefix("v1=") else {
        return Err(VerifyFailure::Malformed);
    };
    if offered.is_empty() || !offered.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VerifyFailure::Malformed);
    }
    let expected = sign_batch(secret, &batch.sequence, &batch.body);
    let Some(expected_hex) = expected.signature.strip_prefix("v1=") else {
        return Err(VerifyFailure::Malformed);
    };
    // Constant-time: a byte-by-byte early exit leaks how much of a forged signature was
    // right, which is enough to build one a byte at a time.
    if !constant_time_eq(offered.as_bytes(), expected_hex.as_bytes()) {
        return Err(VerifyFailure::BadSignature);
    }
    // Ordering, checked AFTER the signature. Checking it first would answer a question
    // about the stream's position to a caller who has not proven they hold the secret.
    if let Some(last) = last_accepted {
        if batch.sequence.as_str() <= last {
            return Err(VerifyFailure::OutOfOrder);
        }
    }
    Ok(())
}

/// Whether two byte strings are equal, in time independent of where they differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod signed_stream_tests {
    use super::*;

    const SECRET: &str = "stream-signing-secret";

    fn batch() -> SignedBatch {
        sign_batch(SECRET, "aud_10", r#"[{"uid":"aud_10"}]"#)
    }

    #[test]
    fn the_sample_consumer_accepts_what_the_signer_produced() {
        assert_eq!(verify_batch(SECRET, None, &batch()), Ok(()));
        assert_eq!(verify_batch(SECRET, Some("aud_09"), &batch()), Ok(()));
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let mut tampered = batch();
        tampered.body = r#"[{"uid":"aud_10","injected":true}]"#.to_string();
        assert_eq!(
            verify_batch(SECRET, None, &tampered),
            Err(VerifyFailure::BadSignature)
        );
    }

    /// The sequence is INSIDE the signed input, so a batch cannot be replayed at a
    /// different position.
    ///
    /// Signing the body alone would let anyone who can reorder deliveries present an old
    /// batch under a newer sequence, and it would verify. The consumer would accept stale
    /// events as current, which is exactly what a signed audit stream must prevent.
    #[test]
    fn a_batch_cannot_be_replayed_under_a_different_sequence() {
        let mut moved = batch();
        moved.sequence = "aud_99".to_string();
        assert_eq!(
            verify_batch(SECRET, None, &moved),
            Err(VerifyFailure::BadSignature),
            "moving a batch to another position must break the signature, not merely the \
             ordering check"
        );
    }

    #[test]
    fn a_batch_at_or_before_the_last_accepted_position_is_out_of_order() {
        assert_eq!(
            verify_batch(SECRET, Some("aud_10"), &batch()),
            Err(VerifyFailure::OutOfOrder),
            "the same position twice is a replay, not progress"
        );
        assert_eq!(
            verify_batch(SECRET, Some("aud_11"), &batch()),
            Err(VerifyFailure::OutOfOrder)
        );
    }

    #[test]
    fn another_secret_does_not_verify() {
        assert_eq!(
            verify_batch("someone-elses-secret", None, &batch()),
            Err(VerifyFailure::BadSignature)
        );
    }

    #[test]
    fn a_malformed_signature_header_is_refused_before_anything_else() {
        for offered in ["", "abc", "v2=abcd", "v1=", "v1=nothex"] {
            let mut malformed = batch();
            malformed.signature = offered.to_string();
            assert_eq!(
                verify_batch(SECRET, None, &malformed),
                Err(VerifyFailure::Malformed),
                "`{offered}` must be refused as malformed"
            );
        }
    }

    /// The ordering answer is only given to a caller who proved they hold the secret.
    #[test]
    fn a_bad_signature_is_reported_even_when_the_order_is_also_wrong() {
        let mut both = batch();
        both.body = "[]".to_string();
        assert_eq!(
            verify_batch(SECRET, Some("aud_99"), &both),
            Err(VerifyFailure::BadSignature),
            "the signature is checked first, so ordering is never answered to an \
             unauthenticated caller"
        );
    }
}
