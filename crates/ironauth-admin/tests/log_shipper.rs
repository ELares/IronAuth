// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIEM log stream shipping (issue #110).
//!
//! Drives the real shipper against real audit rows with a recording sink standing in for a
//! destination. The sink is a double because the interesting properties are about what the
//! shipper does with the cursor and the health, and a real HTTP endpoint would only add a
//! socket to the things that can go wrong.

use std::sync::{Arc, Mutex};

use ironauth_admin::log_shipper::{LogSink, SinkOutcome, ship_once};
use ironauth_env::Env;
use ironauth_store::log_stream::{LogStreamRecord, SinkType, StreamSource, StreamStatus};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewLogStream, Scope, Store};
use serde_json::Value;

/// A sink that records what it was given and answers however it was told to.
struct RecordingSink {
    sink_type: SinkType,
    accept: bool,
    batches: Mutex<Vec<Vec<Value>>>,
}

impl RecordingSink {
    fn new(sink_type: SinkType, accept: bool) -> Arc<Self> {
        Arc::new(Self {
            sink_type,
            accept,
            batches: Mutex::new(Vec::new()),
        })
    }

    /// Every event handed to this sink across every batch, in order.
    fn events(&self) -> Vec<Value> {
        self.batches
            .lock()
            .expect("not poisoned")
            .iter()
            .flatten()
            .cloned()
            .collect()
    }

    fn batch_count(&self) -> usize {
        self.batches.lock().expect("not poisoned").len()
    }
}

impl LogSink for RecordingSink {
    fn sink_type(&self) -> SinkType {
        self.sink_type
    }

    fn deliver<'a>(
        &'a self,
        _stream: &'a LogStreamRecord,
        events: &'a [Value],
    ) -> std::pin::Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>> {
        let accept = self.accept;
        let recorded = events.to_vec();
        Box::pin(async move {
            self.batches.lock().expect("not poisoned").push(recorded);
            if accept {
                SinkOutcome::Accepted
            } else {
                SinkOutcome::Rejected("the double refuses".to_string())
            }
        })
    }
}

/// Write `count` admin-stream audit rows.
async fn seed_admin(db: &TestDatabase, env: &Env, scope: Scope, count: usize, prefix: &str) {
    for index in 0..count {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .clients()
            .create(env, &format!("{prefix}-{index}"))
            .await
            .expect("create a client");
    }
}

async fn configure(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    source: StreamSource,
    sink_type: SinkType,
    filter: Option<Vec<String>>,
) -> String {
    db.control_store()
        .scoped(scope)
        .log_streams()
        .create(
            env,
            &NewLogStream {
                description: "test stream",
                source,
                sink_type,
                sink_config: serde_json::json!({ "endpoint": "https://sink.example/in" }),
                credential_secret_name: None,
                event_type_filter: filter,
            },
        )
        .await
        .expect("configure a stream")
}

async fn health(store: &Store, scope: Scope, id: &str) -> ironauth_store::log_stream::StreamHealth {
    store
        .scoped(scope)
        .log_streams()
        .list_active()
        .await
        .expect("list")
        .into_iter()
        .find(|stream| stream.id == id)
        .expect("the stream is listed")
        .health
}

#[tokio::test]
async fn a_pass_ships_the_audit_rows_and_advances_the_cursor() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 3, "ship").await;

    let sink = RecordingSink::new(SinkType::Http, true);
    let sinks: Vec<Arc<dyn LogSink>> = vec![sink.clone()];
    let shipped = ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");
    assert!(shipped >= 3, "the seeded rows must ship: {shipped}");

    let events = sink.events();
    assert!(
        events
            .iter()
            .any(|event| event["activity_name"] == "client.create"),
        "the OCSF events must name the action: {events:?}"
    );
    assert!(
        events.iter().all(|event| event["uid"].is_string()),
        "every event must carry the audit id, which is the sink's dedup key"
    );
    assert!(
        events.iter().all(|event| event["class_uid"].is_number()),
        "every event must carry its OCSF class"
    );
    assert_eq!(
        health(db.store(), scope, &id).await.status(),
        StreamStatus::Healthy
    );

    // A second pass with nothing new ships nothing and does NOT re-deliver.
    let again = ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship again");
    assert_eq!(again, 0, "an idle pass must ship nothing");
    assert_eq!(
        sink.batch_count(),
        1,
        "the cursor must have advanced, or the same batch reships forever"
    );
}

/// A refused batch is retried from the same position rather than lost.
///
/// Delivery is at least once by design: a SIEM that sees an event twice deduplicates on
/// the event id, and one that never sees it cannot.
#[tokio::test]
async fn a_refused_batch_is_not_lost_and_is_redelivered() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 2, "retry").await;

    let failing = RecordingSink::new(SinkType::Http, false);
    let sinks: Vec<Arc<dyn LogSink>> = vec![failing.clone()];
    assert_eq!(
        ship_once(db.store(), &env, scope, &sinks)
            .await
            .expect("ship"),
        0,
        "a refused batch ships nothing"
    );
    let after = health(db.store(), scope, &id).await;
    assert_eq!(after.consecutive_failures, 1);
    assert_eq!(after.status(), StreamStatus::Degraded);
    assert_eq!(after.last_error.as_deref(), Some("the double refuses"));

    // The SAME events come back on the next pass, because the cursor never moved.
    let first_batch = failing.events();
    ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");
    let batches = failing.batch_count();
    assert_eq!(batches, 2, "the batch must be attempted again");
    assert!(!first_batch.is_empty(), "the first attempt carried events");

    // And once the sink recovers, they are accepted and the run resets.
    let healthy = RecordingSink::new(SinkType::Http, true);
    let recovered: Vec<Arc<dyn LogSink>> = vec![healthy.clone()];
    let shipped = ship_once(db.store(), &env, scope, &recovered)
        .await
        .expect("ship");
    assert!(shipped >= 2, "the held batch is delivered on recovery");
    let done = health(db.store(), scope, &id).await;
    assert_eq!(done.consecutive_failures, 0);
    assert!(done.last_error.is_none());
}

/// One failing stream must not stop or delay another. This is the isolation criterion.
#[tokio::test]
async fn a_failing_stream_does_not_stop_a_healthy_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // Two streams, two sink types, so each resolves to a different double.
    let broken = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    let working = configure(
        &db,
        &env,
        scope,
        StreamSource::Both,
        SinkType::Datadog,
        None,
    )
    .await;
    seed_admin(&db, &env, scope, 2, "isolate").await;

    let dead = RecordingSink::new(SinkType::Http, false);
    let alive = RecordingSink::new(SinkType::Datadog, true);
    let sinks: Vec<Arc<dyn LogSink>> = vec![dead.clone(), alive.clone()];
    let shipped = ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");

    assert!(
        shipped >= 2,
        "the healthy stream must deliver even though its neighbour failed"
    );
    assert!(
        !alive.events().is_empty(),
        "the healthy sink received its batch"
    );
    assert_eq!(
        health(db.store(), scope, &broken).await.status(),
        StreamStatus::Degraded,
        "the failure is recorded against the failing stream"
    );
    assert_eq!(
        health(db.store(), scope, &working).await.status(),
        StreamStatus::Healthy,
        "and NOT against its neighbour"
    );
}

/// A stream that ERRORS, rather than merely having its batch refused, must also not stop
/// its neighbours.
///
/// These are different code paths. A refused batch is an outcome the shipper expects; an
/// error is the arm that decides whether the pass continues at all. A mutation turning
/// that arm into an early return SURVIVED a suite that covered only refusal, which is why
/// this test exists.
#[tokio::test]
async fn a_stream_that_errors_does_not_stop_a_healthy_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // S3 has no registered implementation here, so shipping that stream ERRORS.
    let broken = configure(&db, &env, scope, StreamSource::Both, SinkType::S3, None).await;
    let working = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 2, "erroring").await;

    let alive = RecordingSink::new(SinkType::Http, true);
    let sinks: Vec<Arc<dyn LogSink>> = vec![alive.clone()];
    let shipped = ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("the pass itself must succeed");

    assert!(
        shipped >= 2,
        "the healthy stream must deliver even though another stream errored"
    );
    assert!(!alive.events().is_empty());
    let recorded = health(db.store(), scope, &broken).await;
    assert_eq!(recorded.consecutive_failures, 1);
    assert!(
        recorded
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("s3")),
        "the erroring stream names its reason: {:?}",
        recorded.last_error
    );
    assert_eq!(
        health(db.store(), scope, &working).await.status(),
        StreamStatus::Healthy
    );
}

/// A filter excludes events from the sink without stalling the cursor behind them.
#[tokio::test]
async fn filtered_out_rows_advance_the_cursor_without_a_delivery() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // A filter naming an action these rows are not.
    let id = configure(
        &db,
        &env,
        scope,
        StreamSource::Both,
        SinkType::Http,
        Some(vec!["nothing.matches".to_string()]),
    )
    .await;
    seed_admin(&db, &env, scope, 2, "filtered").await;

    let sink = RecordingSink::new(SinkType::Http, true);
    let sinks: Vec<Arc<dyn LogSink>> = vec![sink.clone()];
    let shipped = ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");
    assert_eq!(shipped, 0, "nothing matched the filter");
    assert_eq!(
        sink.batch_count(),
        0,
        "an empty batch must not be delivered at all"
    );
    // The health is untouched: no delivery happened, so calling it a success would be a
    // lie and calling it a failure would be worse.
    assert_eq!(
        health(db.store(), scope, &id).await.status(),
        StreamStatus::Healthy
    );

    // The cursor DID advance, so the excluded rows are not reconsidered forever.
    let cursor = db
        .store()
        .scoped(scope)
        .log_streams()
        .list_active()
        .await
        .expect("list")
        .into_iter()
        .find(|stream| stream.id == id)
        .expect("listed")
        .cursor;
    assert!(
        cursor.is_some(),
        "the cursor must move past rows that will never be shippable"
    );
}

/// A stream configured for a sink this build does not implement says so.
#[tokio::test]
async fn a_stream_with_no_sink_implementation_records_why() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::S3, None).await;
    seed_admin(&db, &env, scope, 1, "nosink").await;

    // Only an HTTP sink is registered, so the S3 stream resolves to nothing.
    let sinks: Vec<Arc<dyn LogSink>> = vec![RecordingSink::new(SinkType::Http, true)];
    ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");

    let recorded = health(db.store(), scope, &id).await;
    assert_eq!(recorded.consecutive_failures, 1);
    assert!(
        recorded
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("s3")),
        "a stream that can never ship must name the reason: {:?}",
        recorded.last_error
    );
}
