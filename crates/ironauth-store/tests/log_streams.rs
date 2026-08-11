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
use ironauth_store::NewLogStream;
use ironauth_store::log_stream::{SinkType, StreamSource, StreamStatus};
use ironauth_store::test_support::TestDatabase;

fn new_stream() -> NewLogStream<'static> {
    NewLogStream {
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
        .create(&env, &new_stream())
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
        .create(&env, &parked)
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
        .create(&env, &new_stream())
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
        .create(&env, &new_stream())
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
        .create(&env, &scoped_stream)
        .await
        .expect("configure a per-organization stream");
    db.control_store()
        .scoped(scope)
        .log_streams()
        .create(&env, &new_stream())
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
