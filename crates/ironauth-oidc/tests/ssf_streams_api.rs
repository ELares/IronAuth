// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Shared Signals stream-management surface (issue #143).
//!
//! # What this owes
//!
//! The store already fences a stream on its receiver, and `ironauth-store`'s own suite
//! mutation-tests that fence. What THIS file owes is the half only the surface can answer:
//!
//! - the fence survives the HTTP layer. A second receiver's credential reaches all four
//!   operations and is refused by each, and the owner's stream is read back afterwards so the
//!   refusals cannot be passing against a stream the intruder destroyed;
//! - a credential for one environment presented at ANOTHER environment's path is refused. The
//!   scope comes from the credential and the path is what discovery publishes, so the two
//!   agreeing is a check somebody has to perform;
//! - a public client cannot create a stream at all;
//! - while `ssf.enabled` is off, every path is a uniform 404, including discovery.

#![cfg(feature = "testing")]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::Harness;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::ClientId;

fn basic(client_id: &ClientId, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

fn streams_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/ssf/streams",
        scope.tenant(),
        scope.environment()
    )
}

fn status_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/ssf/status", scope.tenant(), scope.environment())
}

fn push_body() -> String {
    serde_json::json!({
        "delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": "https://receiver.example.com/events",
        },
        "events_requested": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
        "aud": ["https://receiver.example.com"],
        "format": "email",
        "description": "the sweep receiver",
    })
    .to_string()
}

async fn send(
    harness: &Harness,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<String>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
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

#[tokio::test]
async fn a_receiver_creates_reads_and_deletes_its_own_stream() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let path = streams_path(&harness);

    let (status, body) = send(&harness, "POST", &path, Some(&auth), Some(push_body())).await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("json");
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();
    assert!(stream_id.starts_with("sst_"), "{body}");
    assert_eq!(created["delivery"]["method"], "urn:ietf:rfc:8935");
    assert_eq!(created["format"], "email");
    // WHAT IT AGREED TO SEND is the intersection with what this build emits, which is empty
    // until the vocabularies land. The receiver can SEE that the type it asked for is not
    // coming, which is the whole reason both halves are published.
    assert_eq!(created["events_delivered"], serde_json::json!([]));
    assert_eq!(
        created["events_requested"].as_array().expect("array").len(),
        1
    );
    // THE PUSH CREDENTIAL'S NAME IS NOT ECHOED BACK.
    assert!(
        !body.contains("authorization_secret_name"),
        "the response repeats the credential name: {body}"
    );

    let one = format!("{path}?stream_id={stream_id}");
    let (status, body) = send(&harness, "GET", &one, Some(&auth), None).await;
    assert_eq!(status, StatusCode::OK, "read: {body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["stream_id"],
        stream_id.as_str()
    );

    let (status, body) = send(&harness, "GET", &path, Some(&auth), None).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body)
            .expect("json")
            .as_array()
            .expect("array")
            .len(),
        1
    );

    let (status, body) = send(&harness, "DELETE", &one, Some(&auth), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete: {body}");
    let (status, _) = send(&harness, "GET", &one, Some(&auth), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "it is gone");
}

#[tokio::test]
async fn a_second_receiver_reaches_none_of_the_operations_over_http() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (owner, owner_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let (intruder, intruder_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let owner_auth = basic(&owner, &owner_secret);
    let intruder_auth = basic(&intruder, &intruder_secret);
    let path = streams_path(&harness);

    let (status, body) = send(
        &harness,
        "POST",
        &path,
        Some(&owner_auth),
        Some(push_body()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let stream_id = serde_json::from_str::<serde_json::Value>(&body).expect("json")["stream_id"]
        .as_str()
        .expect("stream_id")
        .to_owned();
    let one = format!("{path}?stream_id={stream_id}");

    let (status, _) = send(&harness, "GET", &one, Some(&intruder_auth), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "read another's stream");

    let (status, body) = send(&harness, "GET", &path, Some(&intruder_auth), None).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body)
            .expect("json")
            .as_array()
            .expect("array")
            .len(),
        0,
        "list another's stream: {status}"
    );

    let change = serde_json::json!({ "stream_id": stream_id, "status": "disabled" }).to_string();
    let (status, _) = send(
        &harness,
        "POST",
        &status_path(&harness),
        Some(&intruder_auth),
        Some(change),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "change another's status");

    let (status, _) = send(&harness, "DELETE", &one, Some(&intruder_auth), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "delete another's stream");

    // AND THE OWNER STILL HAS IT, ENABLED. Without this the four refusals above would pass
    // just as well against a stream the intruder had actually destroyed or disabled.
    let (status, body) = send(&harness, "GET", &one, Some(&owner_auth), None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner's stream survived: {body}"
    );
    let (status, body) = send(
        &harness,
        "GET",
        &format!("{}?stream_id={stream_id}", status_path(&harness)),
        Some(&owner_auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["status"],
        "enabled"
    );
}

#[tokio::test]
async fn a_credential_for_another_environment_is_refused_at_this_path() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);

    // The SAME credential, presented at a path naming a DIFFERENT environment. The scope comes
    // from the credential, so without the comparison this would act in the credential's own
    // environment while the caller addressed another -- which is the shape a receiver would use
    // to find out whether that other environment exists.
    let scope = harness.scope();
    let elsewhere = format!(
        "/t/{}/e/{}/ssf/streams",
        scope.tenant(),
        ironauth_store::EnvironmentId::generate(harness.state().env())
    );
    let (status, body) = send(&harness, "POST", &elsewhere, Some(&auth), Some(push_body())).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a credential acted outside the environment the path named: {body}"
    );
}

#[tokio::test]
async fn a_missing_or_public_credential_creates_nothing() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let path = streams_path(&harness);

    let (status, _) = send(&harness, "POST", &path, None, Some(push_body())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no credential");

    // A public client presents a `client_id` and no secret. A `client_id` is not a secret, and
    // a stream decides where this environment's security events are sent.
    let public = harness
        .create_public_client_with_redirects("public", &[common::REDIRECT_URI])
        .await;
    let form = format!("Basic {}", STANDARD.encode(format!("{public}:")));
    let (status, _) = send(&harness, "POST", &path, Some(&form), Some(push_body())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a public client");
}

#[tokio::test]
async fn the_delivery_object_is_validated_before_anything_is_written() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let path = streams_path(&harness);

    let cases = [
        (
            "push with no endpoint",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8935" },
                "aud": ["https://receiver.example.com"],
            }),
        ),
        (
            "push over plaintext",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8935", "endpoint_url": "http://receiver.example.com/e" },
                "aud": ["https://receiver.example.com"],
            }),
        ),
        (
            "poll carrying an endpoint",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8936", "endpoint_url": "https://receiver.example.com/e" },
                "aud": ["https://receiver.example.com"],
            }),
        ),
        (
            "an unknown delivery method",
            serde_json::json!({
                "delivery": { "method": "urn:example:carrier-pigeon" },
                "aud": ["https://receiver.example.com"],
            }),
        ),
        (
            "a format this transmitter does not render",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8936" },
                "aud": ["https://receiver.example.com"],
                "format": "phone_number",
            }),
        ),
        (
            "no audience",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8936" },
                "aud": [],
            }),
        ),
    ];
    for (what, body) in cases {
        let (status, text) =
            send(&harness, "POST", &path, Some(&auth), Some(body.to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {text}");
    }

    // AND NOTHING WAS WRITTEN by any of them. A 400 that still created a row would leave the
    // receiver with a stream it was told it did not get.
    let (_, body) = send(&harness, "GET", &path, Some(&auth), None).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body)
            .expect("json")
            .as_array()
            .expect("array")
            .len(),
        0,
        "a refused create left a row behind: {body}"
    );
}

#[tokio::test]
async fn the_stream_ceiling_refuses_rather_than_evicting() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(2);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let path = streams_path(&harness);

    let mut ids = Vec::new();
    for _ in 0..2 {
        let (status, body) = send(&harness, "POST", &path, Some(&auth), Some(push_body())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        ids.push(
            serde_json::from_str::<serde_json::Value>(&body).expect("json")["stream_id"]
                .as_str()
                .expect("stream_id")
                .to_owned(),
        );
    }
    let (status, body) = send(&harness, "POST", &path, Some(&auth), Some(push_body())).await;
    assert_eq!(status, StatusCode::CONFLICT, "the third: {body}");

    // THE TWO IT ALREADY HAD ARE STILL THERE. A ceiling that evicted would take away the
    // stream a receiver is polling, which is a delivery gap the receiver cannot detect.
    let (_, body) = send(&harness, "GET", &path, Some(&auth), None).await;
    let listed: Vec<String> = serde_json::from_str::<serde_json::Value>(&body)
        .expect("json")
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry["stream_id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(listed.len(), 2, "{body}");
    for id in &ids {
        assert!(listed.contains(id), "{id} was evicted: {body}");
    }
}

#[tokio::test]
async fn a_paused_stream_reports_its_reason_and_can_be_resumed() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let path = streams_path(&harness);
    let (_, body) = send(&harness, "POST", &path, Some(&auth), Some(push_body())).await;
    let stream_id = serde_json::from_str::<serde_json::Value>(&body).expect("json")["stream_id"]
        .as_str()
        .expect("stream_id")
        .to_owned();
    let status_uri = status_path(&harness);

    let pause = serde_json::json!({
        "stream_id": stream_id,
        "status": "paused",
        "reason": "receiver maintenance",
    })
    .to_string();
    let (status, body) = send(&harness, "POST", &status_uri, Some(&auth), Some(pause)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let paused: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(paused["status"], "paused");
    assert_eq!(paused["reason"], "receiver maintenance");

    let resume = serde_json::json!({ "stream_id": stream_id, "status": "enabled" }).to_string();
    let (status, body) = send(&harness, "POST", &status_uri, Some(&auth), Some(resume)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resumed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(resumed["status"], "enabled");
    // THE REASON IS CLEARED, not carried over: a stream that is running must not still report
    // why it was once paused.
    assert_eq!(resumed["reason"], serde_json::Value::Null);

    let bad = serde_json::json!({ "stream_id": stream_id, "status": "asleep" }).to_string();
    let (status, _) = send(&harness, "POST", &status_uri, Some(&auth), Some(bad)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an unknown status");
}

#[tokio::test]
async fn discovery_advertises_only_what_is_mounted() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let scope = harness.scope();
    let uri = format!(
        "/.well-known/ssf-configuration/t/{}/e/{}",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = send(&harness, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("json");

    assert_eq!(
        doc["delivery_methods_supported"],
        serde_json::json!(["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"])
    );
    assert!(
        doc["configuration_endpoint"]
            .as_str()
            .expect("configuration_endpoint")
            .ends_with("/ssf/streams")
    );
    assert!(
        doc["status_endpoint"]
            .as_str()
            .expect("status_endpoint")
            .ends_with("/ssf/status")
    );
    // NOTHING THIS SLICE DOES NOT SERVE. SSF 1.0 also defines add-subject, remove-subject and
    // verification endpoints; naming one here would tell a receiver to call a 404.
    for absent in [
        "add_subject_endpoint",
        "remove_subject_endpoint",
        "verification_endpoint",
    ] {
        assert!(
            doc.get(absent).is_none(),
            "discovery advertises {absent}, which is not mounted: {body}"
        );
    }
    // AND NO EVENT TYPE, because nothing emits one yet.
    assert_eq!(doc["events_supported"], serde_json::json!([]));
}

#[tokio::test]
async fn every_path_is_a_uniform_404_while_the_surface_is_off() {
    // No `enable_ssf`: this is the DEFAULT boot. A deployment that has not opted in should be
    // indistinguishable from one that does not implement SSF, so the answer is 404 rather than
    // a 501 or a document advertising nothing.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let paths = [
        format!(
            "/t/{}/e/{}/ssf/streams",
            scope.tenant(),
            scope.environment()
        ),
        format!("/t/{}/e/{}/ssf/status", scope.tenant(), scope.environment()),
        format!(
            "/.well-known/ssf-configuration/t/{}/e/{}",
            scope.tenant(),
            scope.environment()
        ),
    ];
    for path in paths {
        let (status, body) = send(&harness, "GET", &path, Some(&auth), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
    }
}
