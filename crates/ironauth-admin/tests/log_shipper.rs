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
                signing_secret_name: None,
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

/// A stream configured with a signing secret actually SIGNS, and ships the position that
/// signature covers (issue #110 criterion 5).
///
/// # Why nothing caught this before
///
/// Review mutated the shipper so that a stream WITH a signing secret shipped every batch
/// unsigned, and the whole suite stayed green. The reason was not a missing assertion: no
/// fixture in this file could set `signing_secret_name`, because `NewLogStream` did not carry
/// it and the INSERT did not write it. The column migration 0144 added was written by
/// nothing, so `open_signing_secret` returned `None` for every stream on every deployment and
/// every batch shipped unsigned. An unsigned batch is a legitimate configuration, so nothing
/// failed anywhere.
///
/// That is why this test asserts the signature is PRESENT before asserting anything about it:
/// the interesting failure is not a wrong signature, it is no signature at all on a stream
/// the operator configured to sign.
///
/// It then rebuilds the canonical string from what the sink was handed and checks the
/// signature verifies under the same secret. That is what makes the position assertion
/// meaningful rather than decorative: a position that does not reconstruct the signed string
/// is exactly as useless to a consumer as no position.
#[tokio::test]
async fn a_signing_stream_signs_its_batches_and_ships_the_position_it_signed() {
    const SECRET_NAME: &str = "siem-signing-key";
    const SECRET: &[u8] = b"a-shared-signing-secret";

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(&env, &db.master_key(), SECRET_NAME, SECRET, None)
        .await
        .expect("put the signing secret");

    let id = db
        .control_store()
        .scoped(scope)
        .log_streams()
        .create(
            &env,
            &NewLogStream {
                id: None,
                description: "signing stream",
                source: StreamSource::Both,
                sink_type: SinkType::Http,
                sink_config: serde_json::json!({ "endpoint": "https://sink.example/in" }),
                credential_secret_name: None,
                signing_secret_name: Some(SECRET_NAME),
                event_type_filter: None,
                organization_id: None,
            },
            None,
        )
        .await
        .expect("configure a signing stream");

    seed_admin(&db, &env, scope, 2, "signed").await;
    let sink = RecordingSink::new(SinkType::Http, true);
    let sinks: Vec<Arc<dyn LogSink>> = vec![sink.clone()];
    let shipped = ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");
    assert!(shipped >= 2, "the seeded rows must ship: {shipped}");

    let handed = sink.signed();
    let (signature, sequence, cursor_id) = handed.last().expect("a batch was delivered").clone();
    let signature = signature.expect(
        "a stream configured with a signing secret must sign: an absent signature here is the          whole feature being inert, not a wrong value",
    );

    // The batch as the sink received it, which is what the digest is taken over.
    let events = sink.events();
    let events_json = serde_json::to_string(&events).expect("serializes");
    let canonical = ironauth_admin::log_stream_signature::canonical_string(
        &id,
        sequence,
        &cursor_id,
        events.len(),
        &events_json,
    );
    assert!(
        ironauth_admin::log_stream_signature::verify(SECRET, &canonical, &signature),
        "the signature must verify against the position the sink was handed, or a consumer          holding both cannot check anything"
    );
}

/// The REPLAY CONSUMER executes the command the management endpoint enqueues (issue #938).
///
/// `replay_dead_letters` is tested above by calling it directly. That proves the mechanism
/// and says nothing about whether anything in production reaches it, which is exactly the
/// gap issue #938 was filed for: the function was `pub`, correct, and its only callers were
/// tests. This drives the consumer's own `handle`, so the command shape, the payload key
/// and the wiring between them are what is measured.
#[tokio::test]
async fn the_replay_consumer_executes_a_queued_command() {
    use ironauth_admin::log_shipper::{DEAD_LETTER_AFTER, LogStreamReplayConsumer};
    use ironauth_store::outbox::OutboxConsumer;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 2, "poison").await;

    // Drive a real dead letter rather than seeding one, so the consumer replays something
    // the shipper actually set aside.
    let dead_sink = RecordingSink::new(SinkType::Http, false);
    let failing: Vec<Arc<dyn LogSink>> = vec![dead_sink.clone()];
    for _ in 0..DEAD_LETTER_AFTER {
        ship_once(db.store(), &env, scope, &failing)
            .await
            .expect("ship");
    }
    assert!(
        !db.store()
            .scoped(scope)
            .log_streams()
            .outstanding_dead_letters(&id)
            .await
            .expect("read")
            .is_empty(),
        "the fixture must leave a dead letter outstanding, or this test replays nothing"
    );

    // The command the management endpoint enqueues, executed through the consumer's own
    // `handle` with a sink that now ACCEPTS.
    let healthy = RecordingSink::new(SinkType::Http, true);
    let consumer = LogStreamReplayConsumer::new(
        db.store().clone(),
        vec![healthy.clone() as Arc<dyn LogSink>],
    );
    let message = ironauth_store::OutboxMessage {
        id: "obm_replay_probe".to_owned(),
        consumer: ironauth_store::LOG_STREAM_REPLAY_CONSUMER.to_owned(),
        idempotency_key: format!("{id}:probe"),
        ordering_key: id.clone(),
        payload: serde_json::json!({ "log_stream_id": id }),
        sequence: 1,
        attempts: 0,
        last_error: None,
        next_attempt_at_unix_micros: 0,
        enqueued_at_unix_micros: 0,
        lease_stamp_unix_micros: None,
        completed_at_unix_micros: None,
        dead_lettered_at_unix_micros: None,
    };
    consumer
        .handle(&env, scope, &message)
        .await
        .expect("the consumer executes the command");

    assert!(
        db.store()
            .scoped(scope)
            .log_streams()
            .outstanding_dead_letters(&id)
            .await
            .expect("read")
            .is_empty(),
        "the consumer must have replayed the outstanding dead letter"
    );
    assert!(
        !healthy.events().is_empty(),
        "and it must have reached the SINK, not merely cleared the row"
    );
}

/// A command whose payload does not name a stream is PERMANENT, not retried forever.
#[tokio::test]
async fn a_replay_command_without_a_stream_id_is_permanent() {
    use ironauth_admin::log_shipper::LogStreamReplayConsumer;
    use ironauth_store::outbox::OutboxConsumer;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let consumer = LogStreamReplayConsumer::new(db.store().clone(), Vec::new());
    let message = ironauth_store::OutboxMessage {
        id: "obm_replay_malformed".to_owned(),
        consumer: ironauth_store::LOG_STREAM_REPLAY_CONSUMER.to_owned(),
        idempotency_key: "malformed".to_owned(),
        ordering_key: "malformed".to_owned(),
        payload: serde_json::json!({ "not_the_key": "x" }),
        sequence: 1,
        attempts: 0,
        last_error: None,
        next_attempt_at_unix_micros: 0,
        enqueued_at_unix_micros: 0,
        lease_stamp_unix_micros: None,
        completed_at_unix_micros: None,
        dead_lettered_at_unix_micros: None,
    };
    let error = consumer
        .handle(&env, scope, &message)
        .await
        .expect_err("a malformed command must not report success");
    // Asserted on the CLASSIFICATION, not on the Debug rendering. A `contains("permanent")`
    // over the formatted error passes or fails for reasons that have nothing to do with
    // whether the message will be retried.
    assert!(
        !error.is_retryable(),
        "a payload that can never become valid must not consume a retry budget: {error:?}"
    );
    assert_eq!(
        error.label(),
        "payload_missing_log_stream_id",
        "and the label an operator reads must name what was missing"
    );
}

/// A REAL POOL drains the command a real producer enqueued.
///
/// Two defects this pins that nothing else does.
///
/// The consumer's registered `name()` must equal the discriminator the producer writes. A
/// consumer whose name differs drains NOTHING, silently: the claim matches no rows, the
/// pool reports healthy, and the only symptom is replays that never happen. Mutating
/// `name()` to a near-miss string survived every other test in this crate, because they all
/// call `handle` directly and never go through a claim.
///
/// And the pool has to be HELD. `OutboxWorkerPool::drop` sets the stop flag, so a pool bound
/// to a temporary is stopped before its workers' first poll. That shipped in this branch's
/// first version: the boot path spawned the pool into a local that was dropped when the
/// function returned, so the endpoint accepted commands nothing executed. A test that calls
/// `handle` directly cannot see either fault.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_pool_drains_a_command_the_producer_enqueued() {
    use std::time::Duration;

    use ironauth_admin::log_shipper::{DEAD_LETTER_AFTER, LogStreamReplayConsumer};
    use ironauth_store::outbox::{
        ConsumerRegistry, OutboxConsumer, OutboxWorker, OutboxWorkerPool, ScopeSource,
        SilentObserver, StaticScopes, WorkerSettings,
    };

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;
    seed_admin(&db, &env, scope, 2, "poison").await;

    let dead_sink = RecordingSink::new(SinkType::Http, false);
    let failing: Vec<Arc<dyn LogSink>> = vec![dead_sink.clone()];
    for _ in 0..DEAD_LETTER_AFTER {
        ship_once(db.store(), &env, scope, &failing)
            .await
            .expect("ship");
    }

    // THE PRODUCER: the same store call the management endpoint makes.
    db.store()
        .scoped(scope)
        .log_streams()
        .request_dead_letter_replay(&env, &id, None, None)
        .await
        .expect("enqueue a replay command");

    let healthy = RecordingSink::new(SinkType::Http, true);
    let consumer = LogStreamReplayConsumer::new(
        db.store().clone(),
        vec![healthy.clone() as Arc<dyn LogSink>],
    );
    let mut registry = ConsumerRegistry::new();
    registry
        .register(Arc::new(consumer) as Arc<dyn OutboxConsumer>)
        .expect("register");
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        registry
            .get(ironauth_store::LOG_STREAM_REPLAY_CONSUMER)
            .expect("the consumer is registered under the name the producer writes"),
        WorkerSettings {
            concurrency: 1,
            visibility_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(20),
            batch: 16,
            retry: ironauth_store::RetryPolicy::default(),
        },
    );
    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let observer: Arc<dyn ironauth_store::outbox::OutboxObserver> = Arc::new(SilentObserver);
    // BOUND, deliberately: dropping this binding stops the workers.
    let pool = OutboxWorkerPool::spawn(&worker, &scopes, &observer);

    let mut drained = false;
    for _ in 0..200 {
        if db
            .store()
            .scoped(scope)
            .log_streams()
            .outstanding_dead_letters(&id)
            .await
            .expect("read")
            .is_empty()
        {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    pool.shutdown().await;

    assert!(
        drained,
        "the replay command a producer enqueued must be drained by a held pool"
    );
    assert!(
        !healthy.events().is_empty(),
        "and the replay must have reached the sink"
    );
}

/// A failed replay is RETRYABLE, not permanent.
///
/// Inverting it is a one-word edit that dead-letters an operator's replay command the first
/// time a sink blinks, and it survived every test in this crate while the choice lived
/// inline in the error path. Its sibling, `permanent` for a payload that can never become
/// valid, is pinned by `a_replay_command_without_a_stream_id_is_permanent`; the two together
/// are the whole classification.
///
/// This asserts the CHOICE rather than driving a store fault to reach it. Inducing a real
/// fault here would mean breaking the database out from under a live consumer, which tests
/// something else and leaves the classification just as unpinned if it were ever reached by
/// a different path.
#[test]
fn a_failed_replay_is_retryable() {
    let error = ironauth_admin::log_shipper::replay_failure_for_test();
    assert!(
        error.is_retryable(),
        "a sink that is down again must not permanently dead-letter the request: {error:?}"
    );
    assert_eq!(error.label(), "replay_failed");
}

/// A SIEM INGESTS THE AGENT EVENTS, and each one names the agent, its linked user, and its
/// organization (issue #130, criterion 2).
///
/// The criterion asks for OCSF events "attributable to the agent and its linked user and
/// organization, and a SIEM fixture ingests them". Before this there was no fixture: `git ls-files
/// | grep -i siem` matched nothing, this suite's twenty tests never mentioned an agent, and the
/// shipped event carried neither the linked user nor the organization at all -- `ChainedAuditRow`
/// simply did not select those columns, so `render` could not name them.
///
/// What makes this a real ingestion rather than a render check: the event is taken from the
/// SINK, after `ship_once` has selected it, rendered it, batched it and delivered it. A test that
/// called `render` directly would prove the formatter works and say nothing about whether an
/// agent event ever reaches a stream.
///
/// The rows are written through the ACTING STORE with the same attribution the production write
/// sites use, so this is not a fixture inventing a shape the code does not produce.
#[tokio::test]
async fn a_siem_ingests_agent_events_naming_the_agent_its_user_and_its_organization() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = configure(&db, &env, scope, StreamSource::Both, SinkType::Http, None).await;

    let planted = seed_agent_audit_rows(&db, &env, scope).await;

    let sink = RecordingSink::new(SinkType::Http, true);
    let sinks: Vec<Arc<dyn LogSink>> = vec![sink.clone()];
    ship_once(db.store(), &env, scope, &sinks)
        .await
        .expect("ship");

    let events = sink.events();
    for action in [
        "agent.register",
        "agent.state.set",
        "agent_token.issue",
        "agent_token.deny",
    ] {
        let event = events
            .iter()
            .find(|event| event["activity_name"] == action)
            .unwrap_or_else(|| panic!("the SIEM received no {action} event: {events:?}"));

        // THE AGENT, as the OCSF target resource.
        let uids: Vec<&str> = event["resources"]
            .as_array()
            .expect("resources is an array")
            .iter()
            .filter_map(|resource| resource["uid"].as_str())
            .collect();
        assert!(
            uids.contains(&planted.agent.as_str()),
            "{action} must name the agent, got {uids:?}"
        );
        // THE ORGANIZATION and THE LINKED USER, typed so a consumer selects rather than
        // guesses by position.
        for (label, uid) in [
            ("organization", planted.organization.as_str()),
            ("user", planted.linked_user.as_str()),
        ] {
            assert!(
                event["resources"]
                    .as_array()
                    .expect("resources is an array")
                    .iter()
                    .any(|resource| resource["type"] == label && resource["uid"] == uid),
                "{action} must carry the {label} {uid} as a typed resource, got {event}"
            );
        }
        // The stream split is part of the criterion too: registration and lifecycle ship on
        // the ADMIN_ACTION stream, issuance and denial on AUTHENTICATION, because they answer
        // different questions and a SIEM files them under different dashboards.
        //
        // `admin_action`, not `account_change`: the latter is the OCSF CLASS name, and the
        // stream is what `ship_once` loops over. Naming the class here made the assertion
        // unsatisfiable for two of the four actions.
        let expected_stream = if action.starts_with("agent_token.") {
            "authentication"
        } else {
            "admin_action"
        };
        assert_eq!(
            event["stream"], expected_stream,
            "{action} belongs in the {expected_stream} stream"
        );
    }

    assert_eq!(
        health(db.store(), scope, &id).await.status(),
        StreamStatus::Healthy
    );
}

/// What `seed_agent_audit_rows` planted, so assertions name the EXACT ids.
struct PlantedAgent {
    agent: String,
    linked_user: String,
    organization: String,
}

/// Write one row of each agent action, with the attribution the production sites use.
async fn seed_agent_audit_rows(db: &TestDatabase, env: &Env, scope: Scope) -> PlantedAgent {
    let organization = ironauth_store::OrganizationId::generate(env, &scope);
    sqlx::query(
        "INSERT INTO organizations /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, display_name) VALUES ($1, $2, $3, 'siem org')",
    )
    .bind(organization.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .expect("seed organization");

    let user = ironauth_store::UserId::generate(env, &scope);
    sqlx::query(
        // FIVE columns, not three. `password_hash` is NOT NULL since 0006, and 0028 added
        // `identifier_bidx`, `identifier_sealed`, `claims_sealed` and `pii_dek_version` and made
        // all four NOT NULL when it moved PII behind envelope encryption. The three-column form
        // this used to be could never insert a row on any schema this repository has shipped: a
        // seed that cannot run is a test that can only fail, and this one shipped that way
        // because nothing ever ran it.
        //
        // The sealed values are placeholders. This row exists to be an audit SUBJECT, and
        // nothing in these tests decrypts it; a real seal would need a DEK and would test the
        // crypto rather than the thing under test.
        "INSERT INTO users /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, password_hash, \
          identifier_bidx, identifier_sealed, claims_sealed, pii_dek_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
    )
    .bind(user.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind("not-a-real-hash")
    .bind(vec![0_u8; 32])
    .bind(vec![0_u8; 16])
    .bind(vec![0_u8; 16])
    .execute(db.owner_pool())
    .await
    .expect("seed user");

    let agent = ironauth_store::AgentPrincipalId::generate(env, &scope);
    let acting = db
        // The CONTROL store: migration 0176 grants `ironauth_app` SELECT on `agents` and
        // nothing else, and `.management()` wraps the SAME pool rather than switching to
        // another, so seeding through `db.store()` is refused by Postgres.
        .control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .in_organization(organization)
        .about_subject(user);
    acting
        .agents(scope)
        .register(
            env,
            ironauth_store::NewAgent {
                id: &agent,
                organization_id: &organization,
                linked_user_id: &user,
                display_name: "siem bot",
                tool_scopes: &["deploy".to_owned()],
                client_id: None,
            },
            0,
            None,
            None,
        )
        .await
        .expect("register the agent");
    acting
        .agents(scope)
        .set_state(env, &agent, "suspended", 0, None)
        .await
        .expect("suspend the agent");

    // The two TOKEN-door rows, written through the data-plane acting store exactly as
    // `record_agent_issuance` and `gate_agent_issuance` write them.
    // These two ARE data-plane writes in production (the token doors run as `ironauth_app`),
    // so the fixture uses that role deliberately rather than by omission.
    let data_plane = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .in_organization(organization)
        .about_subject(user);
    data_plane
        .agents()
        .record_token_issued(env, &agent, "deploy")
        .await
        .expect("record an issuance");
    data_plane
        .agents()
        .record_token_denied(env, &agent, "suspended")
        .await
        .expect("record a denial");

    PlantedAgent {
        agent: agent.to_string(),
        linked_user: user.to_string(),
        organization: organization.to_string(),
    }
}
