// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8936 poll delivery (issue #143).
//!
//! # What this owes
//!
//! #143's criterion is that "poll delivery per RFC 8936 honors acknowledgment and redelivers
//! unacknowledged SETs". Both halves are asserted directly, and the second is the one a
//! status-only test would miss: an unacknowledged SET must come back **byte-identical**, or a
//! receiver comparing two deliveries of one event sees a difference it cannot explain.
//!
//! The fence is the other thing here. The poll endpoint is addressed per STREAM, so the URL
//! names what the receiver is collecting for; a second receiver calling it is refused with the
//! same not-found an absent stream gets.

#![cfg(feature = "testing")]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::Harness;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{
    ClientId, CorrelationId, NewSsfStream, SsfDelivery, SsfStreamId, SsfStreamStatus,
    SsfSubjectFormat,
};

fn basic(client_id: &ClientId, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

async fn send(
    harness: &Harness,
    uri: &str,
    auth: Option<&str>,
    body: Option<String>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let request = builder
        .body(body.map_or_else(Body::empty, Body::from))
        .expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

/// A poll stream owned by `client`, with `count` SETs already owed to it.
async fn poll_stream(harness: &Harness, client: &ClientId, count: usize) -> SsfStreamId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let id = SsfStreamId::generate(&env, &scope);
    let audience = vec!["https://receiver.example.com".to_owned()];
    let none: Vec<String> = Vec::new();
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            NewSsfStream {
                id: &id,
                client_id: client,
                delivery: &SsfDelivery::Poll,
                events_requested: &none,
                events_delivered: &none,
                subject_format: SsfSubjectFormat::IssSub,
                audience: &audience,
                description: None,
            },
            20,
            None,
        )
        .await
        .expect("seed a poll stream");
    for n in 0..count {
        harness
            .db()
            .store()
            .scoped(scope)
            .ssf_stream_sets()
            .queue(
                &id,
                &format!("evt_{n}"),
                &format!("header.payload{n}.sig"),
                // FROM THE CONFIGURED CEILING, not a literal. `ssf.max_owed_sets_per_stream` is
                // what supplies this conjunct in production, so a test passing its own number
                // would keep passing after the config key stopped reaching the queue.
                harness.state().ssf_max_owed_sets_per_stream(),
            )
            .await
            .expect("queue a SET");
    }
    id
}

fn poll_uri(harness: &Harness, stream: &SsfStreamId) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/ssf/poll/{}",
        scope.tenant(),
        scope.environment(),
        stream
    )
}

#[tokio::test]
async fn a_poll_collects_what_is_owed_oldest_first_and_says_whether_more_remains() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = poll_stream(&harness, &client, 3).await;
    let uri = poll_uri(&harness, &stream);

    let (status, body) = send(
        &harness,
        &uri,
        Some(&auth),
        Some(serde_json::json!({ "maxEvents": 2 }).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page: serde_json::Value = serde_json::from_str(&body).expect("json");
    let sets = page["sets"].as_object().expect("sets");
    assert_eq!(sets.len(), 2, "maxEvents was honoured: {body}");
    // OLDEST FIRST: a receiver draining a backlog reads its events in the order they happened.
    assert!(
        sets.contains_key("evt_0") && sets.contains_key("evt_1"),
        "{body}"
    );
    assert_eq!(page["moreAvailable"], true, "one is still owed: {body}");

    // AN EMPTY BODY IS A VALID POLL. Every RFC 8936 member is optional.
    let (status, body) = send(&harness, &uri, Some(&auth), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["sets"]
            .as_object()
            .expect("sets")
            .len(),
        3,
        "nothing was acknowledged, so all three are still owed: {body}"
    );
}

#[tokio::test]
async fn an_unacknowledged_set_comes_back_byte_identical_and_an_acknowledged_one_does_not() {
    // #143's criterion, both halves. The second is why the assertion compares the TOKEN and not
    // merely the count: a receiver that sees a different JWS for one `jti` cannot tell a
    // redelivery from a new event.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = poll_stream(&harness, &client, 2).await;
    let uri = poll_uri(&harness, &stream);

    let (_, first) = send(&harness, &uri, Some(&auth), None).await;
    let first: serde_json::Value = serde_json::from_str(&first).expect("json");
    let original = first["sets"]["evt_0"].as_str().expect("evt_0").to_owned();

    // Nothing acknowledged: the same tokens come back.
    let (_, again) = send(&harness, &uri, Some(&auth), None).await;
    let again: serde_json::Value = serde_json::from_str(&again).expect("json");
    assert_eq!(
        again["sets"]["evt_0"].as_str(),
        Some(original.as_str()),
        "a redelivered SET differed from the original"
    );

    // Acknowledge one; it stops being owed and the other does not.
    let (status, body) = send(
        &harness,
        &uri,
        Some(&auth),
        Some(serde_json::json!({ "ack": ["evt_0"] }).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after: serde_json::Value = serde_json::from_str(&body).expect("json");
    let sets = after["sets"].as_object().expect("sets");
    assert!(
        !sets.contains_key("evt_0"),
        "an acknowledged SET was redelivered: {body}"
    );
    assert!(
        sets.contains_key("evt_1"),
        "an unacknowledged SET was dropped: {body}"
    );
    assert_eq!(after["moreAvailable"], false);

    // ACKNOWLEDGING TWICE IS NOT AN ERROR. RFC 8936 lets a receiver repeat an ack, and a retry
    // of a poll whose response was lost carries exactly that.
    let (status, _) = send(
        &harness,
        &uri,
        Some(&auth),
        Some(serde_json::json!({ "ack": ["evt_0"] }).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a repeated ack was refused");
}

#[tokio::test]
async fn a_second_receiver_can_neither_collect_nor_acknowledge() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (owner, owner_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let (intruder, intruder_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let stream = poll_stream(&harness, &owner, 2).await;
    let uri = poll_uri(&harness, &stream);

    let (status, _) = send(
        &harness,
        &uri,
        Some(&basic(&intruder, &intruder_secret)),
        Some(serde_json::json!({ "ack": ["evt_0"] }).to_string()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a second receiver reached the queue"
    );

    // AND NOTHING WAS ACKNOWLEDGED. Without this the refusal above would pass equally well
    // against a queue the intruder had actually drained.
    let (status, body) = send(&harness, &uri, Some(&basic(&owner, &owner_secret)), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["sets"]
            .as_object()
            .expect("sets")
            .len(),
        2,
        "the owner's queue was changed by another receiver: {body}"
    );
}

#[tokio::test]
async fn a_push_stream_has_nothing_to_collect() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let id = SsfStreamId::generate(&env, &scope);
    let audience = vec!["https://receiver.example.com".to_owned()];
    let none: Vec<String> = Vec::new();
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            NewSsfStream {
                id: &id,
                client_id: &client,
                delivery: &SsfDelivery::Push {
                    endpoint_url: "https://receiver.example.com/e".to_owned(),
                    secret_name: None,
                },
                events_requested: &none,
                events_delivered: &none,
                subject_format: SsfSubjectFormat::IssSub,
                audience: &audience,
                description: None,
            },
            20,
            None,
        )
        .await
        .expect("seed a push stream");

    // Letting a push stream collect too would hand one SET out twice, under two delivery
    // methods.
    let (status, _) = send(
        &harness,
        &poll_uri(&harness, &id),
        Some(&basic(&client, &secret)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_configuration_publishes_the_poll_address_for_the_stream_it_describes() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let scope = harness.scope();
    let created = send(
        &harness,
        &format!(
            "/t/{}/e/{}/ssf/streams",
            scope.tenant(),
            scope.environment()
        ),
        Some(&auth),
        Some(
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8936" },
                "aud": ["https://receiver.example.com"],
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(created.0, StatusCode::CREATED, "{}", created.1);
    let doc: serde_json::Value = serde_json::from_str(&created.1).expect("json");
    let stream_id = doc["stream_id"].as_str().expect("stream_id");
    // PER STREAM, and it names THIS one: a credential holding several poll streams must be able
    // to say which it is collecting for.
    assert!(
        doc["delivery"]["endpoint_url"]
            .as_str()
            .expect("endpoint_url")
            .ends_with(&format!("/ssf/poll/{stream_id}")),
        "{}",
        created.1
    );
}

/// Set `stream` to `status` as its owner would, and report what it still owes.
async fn set_status_then_owed(
    harness: &Harness,
    client: &ClientId,
    stream: &SsfStreamId,
    status: SsfStreamStatus,
) -> i64 {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .set_status(&env, stream, client, status, None)
        .await
        .expect("set the stream status");
    harness
        .db()
        .store()
        .scoped(scope)
        .ssf_stream_sets()
        .owed_count(stream)
        .await
        .expect("count what is owed")
}

/// POLL IS DELIVERY, so a stream that is not delivering does not deliver here either.
///
/// Both non-default statuses, and both halves of each: what the poll answers, and what the
/// stream still owes afterwards. The second half is the one that matters, because the
/// acknowledgement is a DELETE -- a refusal that arrived after the delete would read as a
/// refusal while having destroyed the backlog it claimed to protect.
///
/// The two statuses differ in exactly that retention, which is their whole distinction in 0216:
/// `paused` RETAINS what it cannot deliver, `disabled` retains nothing.
#[tokio::test]
async fn a_stream_that_is_not_delivering_serves_no_poll_and_cannot_be_drained_by_one() {
    for (status, owed_after_status_change, label) in [
        (SsfStreamStatus::Paused, 3, "paused"),
        (SsfStreamStatus::Disabled, 0, "disabled"),
    ] {
        let mut harness = Harness::start_store_backed().await;
        harness.enable_ssf(20);
        let (client, secret) = harness
            .create_confidential_client(ClientAuthMethod::Basic)
            .await;
        let auth = basic(&client, &secret);
        let stream = poll_stream(&harness, &client, 3).await;

        // The receiver collects once while the stream is enabled, so it holds three real `jti`s
        // to acknowledge with. An ack of invented ones would be refused for the wrong reason.
        let (status_code, body) = send(
            &harness,
            &poll_uri(&harness, &stream),
            Some(&auth),
            Some(r#"{"maxEvents":3,"returnImmediately":true}"#.to_owned()),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK, "the enabled poll: {body}");
        let sets: serde_json::Value = serde_json::from_str(&body).expect("a poll document");
        let jtis: Vec<String> = sets["sets"]
            .as_object()
            .expect("sets is an object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(jtis.len(), 3, "the enabled poll handed over three SETs");

        let owed = set_status_then_owed(&harness, &client, &stream, status).await;
        assert_eq!(
            owed, owed_after_status_change,
            "{label} kept the wrong number of SETs at the moment its status changed"
        );

        // The ack rides along, because a receiver retrying a failed acknowledgement is exactly
        // when this happens: if the refusal came after the delete, the SETs would be gone.
        let acknowledgement = serde_json::json!({
            "maxEvents": 3,
            "returnImmediately": true,
            "ack": jtis,
        })
        .to_string();
        let (status_code, body) = send(
            &harness,
            &poll_uri(&harness, &stream),
            Some(&auth),
            Some(acknowledgement),
        )
        .await;
        assert_eq!(
            status_code,
            StatusCode::FORBIDDEN,
            "a {label} stream served a poll: {body}"
        );
        assert!(
            body.contains("access_denied") && body.contains(label),
            "the refusal did not name the {label} status: {body}"
        );

        let still_owed = harness
            .db()
            .store()
            .scoped(harness.scope())
            .ssf_stream_sets()
            .owed_count(&stream)
            .await
            .expect("count what is owed");
        assert_eq!(
            still_owed, owed_after_status_change,
            "the refused poll's acknowledgement still drained a {label} stream"
        );
    }
}

/// Re-enabling a paused stream redelivers what it held; re-enabling a disabled one has nothing.
///
/// This is the pair above read from the receiver's side, and it is what makes the retention
/// difference observable through the API rather than only in a row count.
#[tokio::test]
async fn re_enabling_redelivers_what_paused_held_and_nothing_of_what_disabled_discarded() {
    for (status, expected, label) in [
        (SsfStreamStatus::Paused, 3, "paused"),
        (SsfStreamStatus::Disabled, 0, "disabled"),
    ] {
        let mut harness = Harness::start_store_backed().await;
        harness.enable_ssf(20);
        let (client, secret) = harness
            .create_confidential_client(ClientAuthMethod::Basic)
            .await;
        let auth = basic(&client, &secret);
        let stream = poll_stream(&harness, &client, 3).await;

        set_status_then_owed(&harness, &client, &stream, status).await;
        set_status_then_owed(&harness, &client, &stream, SsfStreamStatus::Enabled).await;

        let (status_code, body) = send(
            &harness,
            &poll_uri(&harness, &stream),
            Some(&auth),
            Some(r#"{"maxEvents":10,"returnImmediately":true}"#.to_owned()),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK, "the re-enabled poll: {body}");
        let sets: serde_json::Value = serde_json::from_str(&body).expect("a poll document");
        assert_eq!(
            sets["sets"].as_object().expect("sets is an object").len(),
            expected,
            "a re-enabled stream redelivered the wrong number of SETs after {label}"
        );
    }
}
