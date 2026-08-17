// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIEM log stream configuration against a real database (issue #110).
//!
//! The selection logic is unit tested in the module; this file covers what only a database
//! can answer: that a configured stream round-trips through the columns, that success and
//! failure move the health and the cursor the way the status surface reports them, and that
//! the data plane cannot create or remove a stream.
//!
//! That last one is the interesting one. If the data-plane role could delete a stream, a
//! compromised data-plane credential could stop an export silently, and the operator would
//! see a stream that simply is not there rather than one that is failing.

use ironauth_env::Env;
use ironauth_store::log_stream::{SinkType, StreamSource, StreamStatus};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CursorOrigin, NewLogStream};

fn new_stream() -> NewLogStream<'static> {
    NewLogStream {
        id: None,
        description: "ship everything to the collector",
        source: StreamSource::Both,
        sink_type: SinkType::Http,
        sink_config: serde_json::json!({ "endpoint": "https://collector.example/ingest" }),
        credential_secret_name: Some("collector_token"),
        event_type_filter: None,
        organization_id: None,
    }
}

#[tokio::test]
async fn a_configured_stream_round_trips_and_starts_healthy_with_no_cursor() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = db
        .control_store()
        .scoped(scope)
        .log_streams()
        .create(&env, &new_stream(), None)
        .await
        .expect("configure a stream");
    assert!(
        id.starts_with("lgs_"),
        "the id must be scoped and typed: {id}"
    );

    let streams = db
        .store()
        .scoped(scope)
        .log_streams()
        .list_active()
        .await
        .expect("list");
    assert_eq!(streams.len(), 1, "the configured stream must be listed");
    let stream = &streams[0];
    assert_eq!(stream.id, id);
    assert_eq!(stream.source, StreamSource::Both);
    assert_eq!(stream.sink_type, SinkType::Http);
    assert_eq!(
        stream.credential_secret_name.as_deref(),
        Some("collector_token"),
        "the credential is referenced by NAME, never held here"
    );
    assert_eq!(
        stream.sink_config["endpoint"], "https://collector.example/ingest",
        "the sink shape round-trips"
    );
    assert!(
        stream.event_type_filter.is_none(),
        "an absent filter must stay absent rather than becoming an empty list, which \
         would ship nothing"
    );
    assert!(stream.cursor.is_none(), "nothing has shipped yet");
    assert_eq!(stream.health.status(), StreamStatus::Healthy);
}

#[tokio::test]
async fn an_empty_filter_survives_the_round_trip_as_empty() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let mut parked = new_stream();
    parked.event_type_filter = Some(Vec::new());
    db.control_store()
        .scoped(scope)
        .log_streams()
        .create(&env, &parked, None)
        .await
        .expect("configure a parked stream");

    let streams = db
        .store()
        .scoped(scope)
        .log_streams()
        .list_active()
        .await
        .expect("list");
    // The distinction only matters if it SURVIVES storage: an empty array read back as
    // NULL would silently turn a parked stream into one shipping everything.
    assert_eq!(
        streams[0].event_type_filter.as_deref(),
        Some(&[][..]),
        "an empty filter must not come back as absent"
    );
    assert!(!streams[0].accepts("admin_action", "client.create"));
}

#[tokio::test]
async fn success_and_failure_move_the_cursor_and_the_health_the_way_status_reports_them() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = db
        .control_store()
        .scoped(scope)
        .log_streams()
        .create(&env, &new_stream(), None)
        .await
        .expect("configure");

    let scoped = db.store().scoped(scope);
    let repo = scoped.log_streams();

    // A run of failures walks healthy to degraded to failing.
    repo.record_failure(&env, &id, "502 from sink")
        .await
        .expect("record a failure");
    let after_one = &repo.list_active().await.expect("list")[0];
    assert_eq!(after_one.health.consecutive_failures, 1);
    assert_eq!(after_one.health.status(), StreamStatus::Degraded);
    assert_eq!(
        after_one.health.last_error.as_deref(),
        Some("502 from sink")
    );
    assert!(
        after_one.cursor.is_none(),
        "a failure must NOT advance the cursor, or the batch is lost rather than retried"
    );

    for _ in 0..4 {
        repo.record_failure(&env, &id, "502 from sink")
            .await
            .expect("record a failure");
    }
    let failing = &repo.list_active().await.expect("list")[0];
    assert_eq!(failing.health.consecutive_failures, 5);
    assert_eq!(failing.health.status(), StreamStatus::Failing);

    // One success resets the run AND advances the cursor, together.
    repo.record_success(&env, &id, (1_700_000_000_000_000, "aud_42"))
        .await
        .expect("record a success");
    let recovered = &repo.list_active().await.expect("list")[0];
    assert_eq!(
        recovered.health.consecutive_failures, 0,
        "a sink that recovers must not carry its failure history forever"
    );
    assert_eq!(recovered.health.status(), StreamStatus::Healthy);
    assert!(
        recovered.health.last_error.is_none(),
        "the stale error must be cleared, or the status surface reports a fixed stream \
         as broken"
    );
    assert_eq!(
        recovered.cursor,
        Some((1_700_000_000_000_000, "aud_42".to_string())),
        "the cursor must advance with the success, or the batch reships forever"
    );
    assert!(recovered.health.last_success_micros.is_some());
}

/// The data plane ships; it does not configure. A compromised data-plane credential must
/// not be able to stop an export by dropping its configuration.
#[tokio::test]
async fn the_data_plane_cannot_create_a_stream() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let refused = db
        .store()
        .scoped(scope)
        .log_streams()
        .create(&env, &new_stream(), None)
        .await;
    let error = format!(
        "{:?}",
        refused.expect_err("the data plane must not configure")
    );
    assert!(
        error.contains("permission denied"),
        "the refusal must come from the GRANT, not from a broken query: {error}"
    );
}

/// A per-organization stream round-trips its organization, and an environment-wide one
/// stays absent.
///
/// The two must stay distinguishable in storage: absent means the whole environment, and a
/// per-org stream read back as environment-wide would start shipping every organization's
/// events to one customer's SIEM.
#[tokio::test]
async fn a_per_organization_stream_round_trips_its_organization() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = ironauth_store::OrganizationId::generate(&env, &scope).to_string();

    let mut scoped_stream = new_stream();
    scoped_stream.organization_id = Some(&organization);
    db.control_store()
        .scoped(scope)
        .log_streams()
        .create(&env, &scoped_stream, None)
        .await
        .expect("configure a per-organization stream");
    db.control_store()
        .scoped(scope)
        .log_streams()
        .create(&env, &new_stream(), None)
        .await
        .expect("configure an environment-wide stream");

    let streams = db
        .store()
        .scoped(scope)
        .log_streams()
        .list_active()
        .await
        .expect("list");
    assert_eq!(streams.len(), 2);
    let scoped: Vec<&String> = streams
        .iter()
        .filter_map(|stream| stream.organization_id.as_ref())
        .collect();
    assert_eq!(
        scoped,
        vec![&organization],
        "exactly one stream is organization-scoped, and it names the right one"
    );
    assert!(
        streams
            .iter()
            .any(|stream| stream.organization_id.is_none()),
        "the environment-wide stream must stay unscoped rather than inheriting the other's \
         organization"
    );
}

/// A per-organization stream sees ONLY that organization's rows (issue #110, criterion 3:
/// "cross-org leakage is impossible (adversarial test)").
///
/// The existing round-trip test above proves the `organization_id` column persists. It would
/// pass unchanged if selection ignored the column entirely, which is the leak this criterion
/// is about, so it cannot be the evidence for it. This one writes rows for TWO organizations
/// plus an unattributed row and asserts what comes back.
///
/// Both directions are required and they fail differently. Missing the positive means a
/// per-org stream ships nothing and someone notices immediately. Missing the negative means
/// it ships another tenant's audit trail to this tenant's collector, and the delivery
/// SUCCEEDS, so nothing in the system reports it: the operator learns from the recipient.
#[tokio::test]
async fn a_per_organization_stream_never_sees_another_organizations_rows() {
    use ironauth_store::{CorrelationId, OrganizationId};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = OrganizationId::generate(&env, &scope);
    let theirs = OrganizationId::generate(&env, &scope);

    // One admin mutation per organization, plus one belonging to neither. The audit row
    // records the generated client id as its target, so the ids are captured here: matching
    // on the human-readable name would find nothing and the negative assertions would then
    // pass for the wrong reason.
    let mine_client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .in_organization(mine)
        .clients()
        .create(&env, "mine-1")
        .await
        .expect("create a client in my organization");
    let theirs_client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .in_organization(theirs)
        .clients()
        .create(&env, "theirs-1")
        .await
        .expect("create a client in the other organization");
    let unattributed_client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "environment-wide")
        .await
        .expect("create an unattributed client");

    let rows = db
        .store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "admin_action",
            None,
            CursorOrigin::ConsumerResume,
            100,
            Some(mine.to_string().as_str()),
        )
        .await
        .expect("read this organization's rows");

    // Positive: the stream is not simply empty, which would satisfy the negative vacuously.
    assert!(
        rows.iter()
            .any(|row| row.target_id == mine_client.to_string()),
        "the organization's own row must ship: {rows:?}"
    );
    // Negative: nothing from the other organization.
    assert!(
        !rows
            .iter()
            .any(|row| row.target_id == theirs_client.to_string()),
        "another organization's row reached this organization's stream, which is the \
         cross-org leak: {rows:?}"
    );
    // And the unattributed row is not this organization's event either. `NULL = 'org'` is
    // NULL rather than true, so the SQL already excludes it; asserting it pins that a future
    // rewrite to `IS NOT DISTINCT FROM` or a COALESCE default cannot quietly widen the feed.
    assert!(
        !rows
            .iter()
            .any(|row| row.target_id == unattributed_client.to_string()),
        "a row belonging to no organization is not this organization's event: {rows:?}"
    );
}

/// A cursor older than the oldest retained row is REFUSED, not silently answered with the
/// surviving tail (issue #107, criterion 6).
///
/// This is the criterion's whole point. A gap has no representation in a list of rows: a
/// consumer resuming from a pruned cursor and receiving what survives cannot tell that from
/// an uneventful period, so it would skip everything in between and go on believing it had
/// seen the stream whole. Refusing is the only answer that reaches it.
#[tokio::test]
async fn a_cursor_before_the_oldest_retained_row_is_refused_with_guidance() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Something to read, so the refusal below is about the CURSOR and not an empty stream.
    db.store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "survivor")
        .await
        .expect("create a client");

    let rows = db
        .store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "admin_action",
            None,
            CursorOrigin::ConsumerResume,
            100,
            None,
        )
        .await
        .expect("read from the start");
    assert!(!rows.is_empty(), "the stream has rows to be read past");
    let oldest = &rows[0];

    // Resuming AT the oldest row is the ordinary case: the row it names still exists.
    db.store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "admin_action",
            Some((oldest.occurred_micros, oldest.audit_id.as_str())),
            CursorOrigin::ConsumerResume,
            100,
            None,
        )
        .await
        .expect("a cursor AT the oldest retained row still reads");

    // A cursor strictly BEFORE it names a position whose rows are gone.
    let refusal = db
        .store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "admin_action",
            Some((oldest.occurred_micros - 1, "aud_pruned_away")),
            CursorOrigin::ConsumerResume,
            100,
            None,
        )
        .await;

    let error = refusal.expect_err("a pruned cursor must not be answered with rows");
    assert!(
        matches!(error, ironauth_store::StoreError::RetentionGap),
        "the refusal must be the typed retention gap, not a generic fault: {error:?}"
    );

    // The GUIDANCE half of the criterion: the message has to say what to do, because a
    // consumer told only that it has a problem still does not know the move.
    let rendered = error.to_string();
    assert!(
        rendered.contains("Reconcile"),
        "the refusal must carry reconcile guidance: {rendered}"
    );
    assert!(
        rendered.contains("resume from a fresh cursor"),
        "the guidance must name the resume step: {rendered}"
    );
}

/// The SAME below-the-oldest cursor is refused as a resume and answered as a bounded range.
///
/// The regression this pins: the gap check refused the dead-letter replay. `rows_after` is
/// exclusive, so the replay derives a position just below the range's first row, and when
/// that range began at the stream's oldest surviving row the derived position sorted below it
/// and the read was refused -- with nothing pruned and no row missing. Two shipped tests in
/// `log_shipper` went red on a live feature.
///
/// Both halves are asserted with ONE cursor value, so nothing but the origin can account for
/// the difference in outcome. Asserting only the permissive half would pass just as well if
/// the check had been deleted outright, which is the thing that must not happen: a consumer
/// resuming from a pruned cursor still has to be told.
#[tokio::test]
async fn a_bounded_range_cursor_is_not_a_retention_gap() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Something to read, so the outcome below is about the CURSOR and not an empty stream --
    // an empty stream is answered as empty for either origin and would prove nothing.
    db.store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "survivor-bounded")
        .await
        .expect("create a client");

    let rows = db
        .store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "admin_action",
            None,
            CursorOrigin::ConsumerResume,
            100,
            None,
        )
        .await
        .expect("read from the start");
    assert!(
        !rows.is_empty(),
        "the stream must have rows or this proves nothing"
    );

    // Exactly what `predecessor_of` derives: the same microsecond, an empty id, which sorts
    // below every real id and therefore below the oldest row itself.
    let below = (rows[0].occurred_micros, "");

    db.store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "admin_action",
            Some(below),
            CursorOrigin::BoundedRange,
            100,
            None,
        )
        .await
        .expect("a bounded range names no row, so no row of it can have been pruned");

    let refusal = db
        .store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "admin_action",
            Some(below),
            CursorOrigin::ConsumerResume,
            100,
            None,
        )
        .await;
    assert!(
        matches!(refusal, Err(ironauth_store::StoreError::RetentionGap)),
        "the same position, claimed as a resume, still has to be refused"
    );
}

/// An EMPTY stream reads as empty rather than as a gap.
///
/// The paired negative, and it guards a real confusion: a consumer resuming against a stream
/// that never had rows is in a different situation from one that missed them, and answering
/// both with a refusal would send it reconciling against nothing.
#[tokio::test]
async fn a_cursor_against_an_empty_stream_is_not_a_retention_gap() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let rows = db
        .store()
        .scoped(scope)
        .audit_chain()
        .rows_after(
            "a_stream_with_no_rows",
            Some((1, "aud_anything")),
            CursorOrigin::ConsumerResume,
            100,
            None,
        )
        .await
        .expect("an empty stream is empty, not a gap");
    assert!(rows.is_empty(), "and it reads as empty: {rows:?}");
}
