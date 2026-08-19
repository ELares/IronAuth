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
    /// The `(signature, position)` pair each batch was handed.
    ///
    /// Recorded because binding these as `_signature` and `_position` is what let the
    /// shipper's own wiring go unguarded: review mutated the replay path to send the wrong
    /// position and the shipper to send one it had not signed, and the whole suite stayed
    /// green. A test double that discards an argument cannot notice the argument being wrong.
    signed: Mutex<Vec<(Option<String>, i64, String)>>,
}

impl RecordingSink {
    fn new(sink_type: SinkType, accept: bool) -> Arc<Self> {
        Arc::new(Self {
            sink_type,
            accept,
            batches: Mutex::new(Vec::new()),
            signed: Mutex::new(Vec::new()),
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

    /// The `(signature, sequence, cursor id)` handed to this sink, per batch, in order.
    fn signed(&self) -> Vec<(Option<String>, i64, String)> {
        self.signed.lock().expect("not poisoned").clone()
    }
}

impl LogSink for RecordingSink {
    fn sink_type(&self) -> SinkType {
        self.sink_type
    }

    fn deliver<'a>(
        &'a self,
        _stream: &'a LogStreamRecord,
        _credential: Option<&'a str>,
        events: &'a [Value],
        signature: Option<&'a str>,
        position: (i64, &'a str),
    ) -> std::pin::Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>> {
        let accept = self.accept;
        let recorded = events.to_vec();
        let handed = (
            signature.map(str::to_owned),
            position.0,
            position.1.to_owned(),
        );
        Box::pin(async move {
            self.batches.lock().expect("not poisoned").push(recorded);
            self.signed.lock().expect("not poisoned").push(handed);
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
    configure_for_org(db, env, scope, source, sink_type, filter, None).await
}

#[allow(clippy::too_many_arguments)]
async fn configure_for_org(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    source: StreamSource,
    sink_type: SinkType,
    filter: Option<Vec<String>>,
    organization_id: Option<&str>,
) -> String {
    db.control_store()
        .scoped(scope)
        .log_streams()
        .create(
            env,
            &NewLogStream {
                id: None,
                description: "test stream",
                source,
                sink_type,
                sink_config: serde_json::json!({ "endpoint": "https://sink.example/in" }),
                credential_secret_name: None,
                event_type_filter: filter,
                organization_id,
            },
            None,
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

    // THE POSITION HANDED TO THE SINK IS THE ONE THE CURSOR ADVANCED TO, and that pairing is
    // the whole point of sending it: a consumer rebuilds the canonical string from it, so a
    // shipper that sends a position it did not sign produces batches that verify as tampered.
    // Review mutated the shipper to send `position.0 + 1` and the entire suite stayed green,
    // because the only sink double discarded the argument.
    let handed = sink.signed();
    let last = handed.last().expect("a batch was delivered");
    let cursor = db
        .store()
        .scoped(scope)
        .log_streams()
        .list_active()
        .await
        .expect("list")
        .into_iter()
        .find(|stream| stream.id == id)
        .expect("the stream is listed")
        .cursor;
    assert_eq!(
        cursor,
        Some((last.1, last.2.clone())),
        "the position sent to the sink must be the one the stream advanced to: {handed:?}"
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

/// A per-organization stream delivers ONLY that organization's events.
///
/// The adversarial half is what makes this worth writing: a second organization's events
/// and an unattributed environment-level event are both present, and neither may appear.
/// Cross-org leakage here does not fail anywhere: the delivery SUCCEEDS, and the operator
/// who finds out is the one receiving another customer's audit trail.
#[tokio::test]
async fn a_per_organization_stream_never_ships_another_organizations_events() {
    use ironauth_store::OrganizationId;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ours = OrganizationId::generate(&env, &scope);
    let theirs = OrganizationId::generate(&env, &scope);

    let id = configure_for_org(
        &db,
        &env,
        scope,
        StreamSource::Both,
        SinkType::Http,
        None,
        Some(&ours.to_string()),
    )
    .await;

    // Ours, theirs, and one belonging to NO organization.
    for (label, org) in [
        ("ours", Some(ours)),
        ("theirs", Some(theirs)),
        ("neither", None),
    ] {
        let acting = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env));
        let acting = match org {
            Some(org) => acting.in_organization(org),
            None => acting,
        };
        acting
            .clients()
            .create(&env, &format!("client-{label}"))
            .await
            .expect("create a client");
    }

    let sink = RecordingSink::new(SinkType::Http, true);
    let sinks: Vec<Arc<dyn LogSink>> = vec![sink.clone()];
    ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");

    let events = sink.events();
    assert!(!events.is_empty(), "our organization's event must ship");
    for event in &events {
        let target = event["resources"][0]["uid"].as_str().unwrap_or_default();
        assert!(
            !target.is_empty(),
            "every shipped event names its target: {event:?}"
        );
    }
    // The decisive assertion: exactly one audit row was ours, so exactly one ships.
    assert_eq!(
        events.len(),
        1,
        "a per-organization stream shipped {} events when only ONE belonged to it. The \
         other organization's event and the unattributed one must never appear: {events:?}",
        events.len()
    );
    assert_eq!(
        health(db.store(), scope, &id).await.status(),
        ironauth_store::log_stream::StreamStatus::Healthy
    );
}

/// A permanently failing sink accumulates a dead letter, stops blocking, and recovers via
/// replay.
///
/// The head-of-line half is the point. Without dead-lettering, a batch the sink refuses
/// forever is retried forever from the same position and every LATER event stops reaching
/// the SIEM, so the operator loses the whole export rather than one batch.
#[tokio::test]
async fn a_permanently_failing_batch_dead_letters_stops_blocking_and_replays() {
    use ironauth_admin::log_shipper::{DEAD_LETTER_AFTER, replay_dead_letters};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 2, "poison").await;

    // Fail until the run reaches the dead-letter threshold.
    let dead_sink = RecordingSink::new(SinkType::Http, false);
    let failing: Vec<Arc<dyn LogSink>> = vec![dead_sink.clone()];
    for _ in 0..DEAD_LETTER_AFTER {
        ship_once(db.store(), &env, scope, &failing)
            .await
            .expect("ship");
    }

    let outstanding = db
        .store()
        .scoped(scope)
        .log_streams()
        .outstanding_dead_letters(&id)
        .await
        .expect("read dead letters");
    assert_eq!(
        outstanding.len(),
        1,
        "the refused batch must be recorded exactly once: {outstanding:?}"
    );
    assert!(outstanding[0].event_count >= 2);
    assert_eq!(outstanding[0].last_error, "the double refuses");

    // The stream is no longer stuck, and the cursor really MOVED PAST the poisoned batch.
    //
    // Asserting only that something ships is not enough: a healthy sink would re-deliver
    // the poisoned batch successfully and that assertion would pass with the cursor still
    // parked. A mutation that dead-lettered WITHOUT advancing survived exactly that. So
    // the count is exact: only the newly written event may ship.
    let poisoned = dead_sink.events().len();
    assert!(poisoned >= 2, "the failing sink saw the batch: {poisoned}");
    seed_admin(&db, &env, scope, 1, "after-poison").await;
    let healthy = RecordingSink::new(SinkType::Http, true);
    let recovered: Vec<Arc<dyn LogSink>> = vec![healthy.clone()];
    let shipped = ship_once(db.store(), &env, scope, &recovered)
        .await
        .expect("ship");
    assert_eq!(
        shipped, 1,
        "exactly the ONE event written after the dead letter may ship. More means the \
         cursor never advanced and the poisoned batch is being re-delivered; head-of-line \
         blocking is the failure this exists to prevent"
    );

    // Replay delivers the set-aside range and clears it.
    let replay_sink = RecordingSink::new(SinkType::Http, true);
    let replay: Vec<Arc<dyn LogSink>> = vec![replay_sink.clone()];
    // The range the dead letter set aside, read BEFORE the replay clears it, so the
    // assertion below compares against what was actually stored rather than a guess.
    let set_aside = db
        .store()
        .scoped(scope)
        .log_streams()
        .outstanding_dead_letters(&id)
        .await
        .expect("read dead letters")
        .first()
        .map(|dead| dead.from.clone())
        .expect("a dead letter is outstanding");
    let count = replay_dead_letters(db.store(), &env, scope, &id, &replay)
        .await
        .expect("replay");
    assert!(
        count >= 2,
        "the dead-lettered events are re-delivered: {count}"
    );
    assert!(
        db.store()
            .scoped(scope)
            .log_streams()
            .outstanding_dead_letters(&id)
            .await
            .expect("read")
            .is_empty(),
        "a replayed dead letter must clear"
    );

    // A REPLAY SIGNS OVER THE RANGE IT SET ASIDE, so it must SEND that range too. Sending a
    // current position instead would hand a consumer a signature over one position and a
    // header claiming another, and the batch would verify as tampered: a replay that cannot
    // be verified is not a recovery. Review mutated this to send the range END and the whole
    // suite stayed green, because the sink double discarded the argument.
    let replayed = replay_sink.signed();
    let handed = replayed.first().expect("the replay delivered a batch");
    assert_eq!(
        (handed.1, handed.2.clone()),
        set_aside,
        "the replay must send the position it signed, the dead letter's own range start: \
         {replayed:?}"
    );
}

/// A replay that the sink REFUSES leaves the dead letter outstanding.
///
/// Marking it replayed anyway would erase the record of the gap, which is the one thing
/// the table exists to keep.
#[tokio::test]
async fn a_refused_replay_leaves_the_dead_letter_outstanding() {
    use ironauth_admin::log_shipper::{DEAD_LETTER_AFTER, replay_dead_letters};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 1, "still-broken").await;

    let dead_sink = RecordingSink::new(SinkType::Http, false);
    let failing: Vec<Arc<dyn LogSink>> = vec![dead_sink.clone()];
    for _ in 0..DEAD_LETTER_AFTER {
        ship_once(db.store(), &env, scope, &failing)
            .await
            .expect("ship");
    }
    assert_eq!(
        db.store()
            .scoped(scope)
            .log_streams()
            .outstanding_dead_letters(&id)
            .await
            .expect("read")
            .len(),
        1
    );

    let count = replay_dead_letters(db.store(), &env, scope, &id, &failing)
        .await
        .expect("replay runs");
    assert_eq!(count, 0, "a refused replay delivers nothing");
    assert_eq!(
        db.store()
            .scoped(scope)
            .log_streams()
            .outstanding_dead_letters(&id)
            .await
            .expect("read")
            .len(),
        1,
        "a refused replay must NOT clear the dead letter"
    );
}

/// The metrics observation reports each stream's sink type, status and outstanding gap.
///
/// Checked through `observe` rather than through the exporter, because what a wrong
/// implementation gets wrong is the DATA (a stream counted under the wrong status, or a
/// dead-letter gap reported as zero), not the gauge call.
#[tokio::test]
async fn the_metrics_observation_reports_status_and_the_outstanding_gap() {
    use ironauth_admin::log_shipper::{DEAD_LETTER_AFTER, observe};
    use ironauth_store::log_stream::StreamStatus;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 1, "observed").await;

    // Healthy before anything fails.
    let before = observe(db.store(), scope).await.expect("observe");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].sink_type, SinkType::Http);
    assert_eq!(before[0].status, StreamStatus::Healthy);
    assert_eq!(before[0].outstanding_dead_letters, 0);

    // Fail it into a dead letter.
    let failing: Vec<Arc<dyn LogSink>> = vec![RecordingSink::new(SinkType::Http, false)];
    for _ in 0..DEAD_LETTER_AFTER {
        ship_once(db.store(), &env, scope, &failing)
            .await
            .expect("ship");
    }
    let after = observe(db.store(), scope).await.expect("observe");
    assert_eq!(
        after[0].outstanding_dead_letters, 1,
        "the export gap must be visible as a number, not only as a status: {after:?}"
    );
}
