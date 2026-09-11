// SPDX-License-Identifier: MIT OR Apache-2.0

//! The audit-retention report (issue #145 criterion 3).
//!
//! The zero-means-forever rule is unit-tested where it lives. What is worth driving here is
//! what the HTTP layer adds: that the endpoint answers for a default deployment and that its
//! answer is the honest one for that deployment, which keeps everything and enforces nothing.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use serde_json::Value;

#[tokio::test]
async fn a_default_deployment_reports_that_it_enforces_nothing() {
    // `AuditRetentionConfig::default()` is `enabled: false` with both windows at zero, so the
    // truthful report is "nothing is deleted, and both streams are kept forever". A report
    // that published the windows without the flag would describe a policy nothing applies.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/audit-retention");

    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: Value = serde_json::from_str(&body).expect("json");

    assert_eq!(
        view["enforced"],
        Value::Bool(false),
        "the default deployment does not run the reaper: {body}"
    );
    assert!(
        view["sweep_interval_secs"].is_null(),
        "an interval is meaningless when nothing sweeps: {body}"
    );

    let streams = view["streams"].as_array().expect("an array");
    assert_eq!(streams.len(), 2, "one entry per audit stream: {body}");
    let names: Vec<&str> = streams
        .iter()
        .map(|s| s["stream"].as_str().unwrap_or_default())
        .collect();
    assert!(
        names.contains(&"admin_action") && names.contains(&"authentication"),
        "both streams must be named: {body}"
    );
    for stream in streams {
        assert_eq!(
            stream["retained_forever"],
            Value::Bool(true),
            "a zero window is forever: {body}"
        );
        assert!(
            stream["retention_secs"].is_null(),
            "a forever stream must carry no number a reader could take literally: {body}"
        );
    }
}

/// A sink that refuses every batch and remembers how big the last one was.
///
/// The size is the point: it is what the attestation's event count is compared against, and
/// it is measured on the SINK side. Comparing the handler's count against the store row it
/// read from would compare the code with itself.
struct RefusingSink {
    largest_refused: std::sync::Mutex<usize>,
}

impl ironauth_admin::log_shipper::LogSink for RefusingSink {
    fn sink_type(&self) -> ironauth_store::log_stream::SinkType {
        ironauth_store::log_stream::SinkType::Http
    }

    fn deliver<'a>(
        &'a self,
        _stream: &'a ironauth_store::log_stream::LogStreamRecord,
        _credential: Option<&'a str>,
        events: &'a [Value],
        _signature: Option<&'a str>,
        _position: (i64, &'a str),
    ) -> std::pin::Pin<Box<dyn Future<Output = ironauth_admin::log_shipper::SinkOutcome> + Send + 'a>>
    {
        let seen = events.len();
        Box::pin(async move {
            let mut largest = self.largest_refused.lock().expect("not poisoned");
            *largest = (*largest).max(seen);
            ironauth_admin::log_shipper::SinkOutcome::Rejected("the sink is down".to_string())
        })
    }
}

/// An INDUCED gap is flagged, counted, and dated (issue #145 criterion 3).
///
/// # Why the gap is induced through the shipper rather than written
///
/// Inserting a `log_stream_dead_letters` row directly would prove the handler can read a
/// table. What an auditor is promised is narrower and harder: that when delivery ACTUALLY
/// fails, the surface says so. So the gap here is produced the way a real one is, by a sink
/// that refuses until the shipper gives up on the batch, and the attestation is read before
/// and after that happens.
///
/// # Why the control leg comes first
///
/// `gap: false` on a healthy stream is the assertion that the flag MEANS something. Without
/// it a handler hard-coding `gap: true` would pass the interesting half of this test.
#[tokio::test]
async fn an_induced_delivery_failure_is_flagged_counted_and_dated() {
    use ironauth_admin::log_shipper::{DEAD_LETTER_AFTER, ship_once};

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::parse(&tenant).expect("tenant parses"),
        ironauth_store::EnvironmentId::parse(&environment).expect("environment parses"),
    );
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    let (status, _, created) = h
        .post(
            &format!("{base}/log-streams"),
            "ls-gap",
            &serde_json::json!({
                "source": "admin_action",
                "sink_type": "http",
                "sink_config": { "url": "https://sink.example/ingest" },
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed log stream: {created}");
    let stream = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("stream id")
        .to_owned();
    let path = format!("{base}/log-streams/{stream}/attestation");

    // THE CONTROL. Nothing has shipped and nothing has failed, so the honest answer is that
    // nothing is outstanding, and the fields that only mean something during a gap are
    // absent rather than zeroed.
    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        view["gap"],
        Value::Bool(false),
        "a stream that has never failed must not report a gap: {body}"
    );
    assert_eq!(view["undelivered_batches"], 0, "{body}");
    assert_eq!(view["undelivered_events"], 0, "{body}");
    assert!(
        view["earliest_undelivered_at_unix_ms"].is_null(),
        "there is no earliest undelivered event when none is undelivered: {body}"
    );
    assert!(
        view["last_error"].is_null(),
        "a healthy stream must not publish an error it never received: {body}"
    );

    // MORE THAN ONE AUDITABLE ROW, written AFTER the stream so they fall on its cursor.
    //
    // Three, not one, and that is load-bearing. A mutant reporting `outstanding.len()` as
    // the event count -- batches where events are meant -- survived this test when the
    // refused batch happened to hold exactly one event, because 1 == 1. The counts have to
    // differ for the assertion below to distinguish them.
    for index in 0..3 {
        let (status, _, body) = h
            .post(
                &format!("{base}/organizations"),
                &format!("org-{index}"),
                &serde_json::json!({ "display_name": format!("Gap {index}") }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed audited row: {body}");
    }

    // INDUCE THE GAP. The stream carries the audit rows this test's own setup wrote, and the
    // sink refuses them until the shipper sets the batch aside.
    let sink = std::sync::Arc::new(RefusingSink {
        largest_refused: std::sync::Mutex::new(0),
    });
    let sinks: Vec<std::sync::Arc<dyn ironauth_admin::log_shipper::LogSink>> = vec![sink.clone()];
    for _ in 0..DEAD_LETTER_AFTER {
        ship_once(h.store(), &Env::system(), scope, &sinks)
            .await
            .expect("a refused batch is not an error");
    }
    let refused = *sink.largest_refused.lock().expect("not poisoned");
    assert!(
        refused > 1,
        "the batch must hold MORE events than there are batches, or the event-count \
         assertion below is satisfied by a handler that counts batches. The sink was \
         handed {refused}"
    );

    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        view["gap"],
        Value::Bool(true),
        "delivery failed and the attestation did not say so: {body}"
    );
    assert_eq!(
        view["undelivered_batches"], 1,
        "one batch was set aside: {body}"
    );
    assert_eq!(
        view["undelivered_events"],
        Value::from(refused),
        "the attestation must account for every event the sink refused, not merely report \
         that something is outstanding. The sink saw {refused}: {body}"
    );
    assert!(
        view["earliest_undelivered_at_unix_ms"]
            .as_i64()
            .is_some_and(|at| at > 0),
        "an auditor needs to know FROM WHEN the trail is incomplete: {body}"
    );
    assert_eq!(
        view["last_error"], "the sink is down",
        "the attestation must carry what the destination actually said, not a placeholder: \
         {body}"
    );
}
