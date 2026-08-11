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
    ///
    /// `credential` is the RESOLVED secret value the stream named, opened by the shipper.
    /// Sinks never resolve it themselves: one resolution path means one place that can
    /// leak it, and a sink that took a secret NAME would have to hold the master key.
    fn deliver<'a>(
        &'a self,
        stream: &'a LogStreamRecord,
        credential: Option<&'a str>,
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

    // Resolved ONCE, here, and handed to the sink as a value. A sink that took a name
    // would need the master key, which would put the ability to open every environment
    // secret behind every sink implementation including ones a deployment adds itself.
    let credential = resolve_credential(store, scope, stream).await?;
    match sink.deliver(stream, credential.as_deref(), &events).await {
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
            post_json(&fetcher, endpoint, vec![("dd-api-key", credential)], body).await
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
            post_json(
                &fetcher,
                endpoint,
                vec![("authorization", format!("Splunk {credential}"))],
                body,
            )
            .await
        })
    }
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
