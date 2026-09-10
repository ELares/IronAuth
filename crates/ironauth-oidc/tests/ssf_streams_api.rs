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

fn push_body_for(client: &ClientId) -> String {
    serde_json::json!({
        "delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": "https://receiver.example.com/events",
            // SET ON THE REQUEST so the response can be scanned for it. Without this the
            // "not echoed" assertion below passed against a string that was never sent.
            //
            // INSIDE `ssf::PUSH_SECRET_PREFIX`: a receiver may only name a credential in its
            // own namespace, or it could have this deployment open the LDAP bind password and
            // POST it to an address the receiver chose.
            "authorization_secret_name": format!("ssf_push_{client}_bearer"),
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

    let (status, body) = send(
        &harness,
        "POST",
        &path,
        Some(&auth),
        Some(push_body_for(&client)),
    )
    .await;
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
        !body.contains("authorization_secret_name") && !body.contains("_bearer"),
        "the response repeats the credential the receiver supplied: {body}"
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
        Some(push_body_for(&owner)),
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
    let (status, body) = send(
        &harness,
        "POST",
        &elsewhere,
        Some(&auth),
        Some(push_body_for(&client)),
    )
    .await;
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

    // The body is never validated on this path: authentication runs first, which is the
    // property under test. A body naming no credential keeps that unambiguous.
    let body = serde_json::json!({
        "delivery": { "method": "urn:ietf:rfc:8935", "endpoint_url": "https://r.example.com/e" },
        "aud": ["https://receiver.example.com"],
    })
    .to_string();
    let (status, _) = send(&harness, "POST", &path, None, Some(body.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no credential");

    // A public client presents a `client_id` and no secret. A `client_id` is not a secret, and
    // a stream decides where this environment's security events are sent.
    let public = harness
        .create_public_client_with_redirects("public", &[common::REDIRECT_URI])
        .await;
    let form = format!("Basic {}", STANDARD.encode(format!("{public}:")));
    let (status, _) = send(&harness, "POST", &path, Some(&form), Some(body)).await;
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
            "poll carrying an endpoint, which is the transmitter's to publish",
            serde_json::json!({
                "delivery": {
                    "method": "urn:ietf:rfc:8936",
                    "endpoint_url": "https://receiver.example.com/collect",
                },
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
                "delivery": { "method": "urn:ietf:rfc:8935", "endpoint_url": "https://r.example.com/e" },
                "aud": ["https://receiver.example.com"],
                "format": "phone_number",
            }),
        ),
        (
            "no audience",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8935", "endpoint_url": "https://r.example.com/e" },
                "aud": [],
            }),
        ),
        (
            "more audiences than a stream may name",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8935", "endpoint_url": "https://r.example.com/e" },
                "aud": (0..9).map(|n| format!("https://r{n}.example.com")).collect::<Vec<_>>(),
            }),
        ),
        (
            "a credential outside the receiver's own namespace",
            serde_json::json!({
                "delivery": {
                    "method": "urn:ietf:rfc:8935",
                    "endpoint_url": "https://r.example.com/e",
                    // The LDAP bind password's namespace. Accepting this would let a receiver
                    // have the delivery worker open that secret and POST it to an address the
                    // same receiver supplied.
                    "authorization_secret_name": "ldap_bind_corp",
                },
                "aud": ["https://receiver.example.com"],
            }),
        ),
        (
            "a description longer than the column stores",
            serde_json::json!({
                "delivery": { "method": "urn:ietf:rfc:8935", "endpoint_url": "https://r.example.com/e" },
                "aud": ["https://receiver.example.com"],
                "description": "d".repeat(253),
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
        let (status, body) = send(
            &harness,
            "POST",
            &path,
            Some(&auth),
            Some(push_body_for(&client)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        ids.push(
            serde_json::from_str::<serde_json::Value>(&body).expect("json")["stream_id"]
                .as_str()
                .expect("stream_id")
                .to_owned(),
        );
    }
    let (status, body) = send(
        &harness,
        "POST",
        &path,
        Some(&auth),
        Some(push_body_for(&client)),
    )
    .await;
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
    let (_, body) = send(
        &harness,
        "POST",
        &path,
        Some(&auth),
        Some(push_body_for(&client)),
    )
    .await;
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

    // ONLY WHAT IS SERVED, and both now are: push through the RFC 8935 worker and poll through
    // the RFC 8936 endpoint. This list held push alone while poll was modelled and unserved,
    // and it is the SAME constant the create validator reads, so the advertisement and the
    // acceptance cannot drift apart.
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
    // NOTHING THIS BUILD DOES NOT SERVE. SSF 1.0 also defines add-subject and remove-subject
    // endpoints; naming one here would tell a receiver to call a 404. `verification_endpoint`
    // left this list when the endpoint was mounted, which is the only way an entry may leave it.
    for absent in ["add_subject_endpoint", "remove_subject_endpoint"] {
        assert!(
            doc.get(absent).is_none(),
            "discovery advertises {absent}, which is not mounted: {body}"
        );
    }
    // AND EXACTLY THE EVENT TYPES THIS BUILD EMITS, which is now SSF's own verification event
    // and still nothing from CAEP or RISC. Asserting emptiness was right while nothing produced
    // a SET; asserting only non-emptiness would pass the day a type nothing emits was added.
    assert_eq!(
        doc["events_supported"],
        serde_json::json!([ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE])
    );

    // THE HOLD POLICY IS PUBLISHED, because the poll response cannot carry it. RFC 8936 makes
    // `returnImmediately: false` the default -- "hold the request open" -- and this transmitter
    // never does; section 2.3 gives the response only `sets` and `moreAvailable`, so this
    // document is the one place a receiver can learn the policy before depending on it.
    assert_eq!(doc["long_poll_supported"], serde_json::json!(false));

    // THE ADVERTISED JWKS IS FETCHED, not eyeballed. This field named
    // `{issuer}/.well-known/jwks.json`, which nothing mounts -- and every other assertion in
    // this test passed while it did. A receiver bootstraps from this document to get the keys
    // that verify a SET, so an unreachable `jwks_uri` makes the transmitter unusable.
    let jwks_uri = doc["jwks_uri"].as_str().expect("jwks_uri");
    let path = jwks_uri
        .strip_prefix("https://issuer.test")
        .or_else(|| jwks_uri.strip_prefix("http://issuer.test"))
        .unwrap_or(jwks_uri);
    let (status, keys) = send(&harness, "GET", path, None, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the advertised jwks_uri 404s: {jwks_uri}"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&keys).expect("jwks json")["keys"]
            .as_array()
            .is_some_and(|keys| !keys.is_empty()),
        "the advertised jwks_uri served no keys: {keys}"
    );
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
    // EVERY MOUNTED PATH, WITH THE VERB IT ACTUALLY SERVES. This drove GET against three paths,
    // which left the writes and the two delivery endpoints unasserted: a route mounted outside
    // the `ssf_enabled` block would have answered a PATCH or a poll on a deployment that never
    // turned SSF on, and every assertion here would still have passed.
    let base = format!("/t/{}/e/{}", scope.tenant(), scope.environment());
    let cases = [
        ("GET", format!("{base}/ssf/streams")),
        ("POST", format!("{base}/ssf/streams")),
        ("PATCH", format!("{base}/ssf/streams")),
        ("PUT", format!("{base}/ssf/streams")),
        ("DELETE", format!("{base}/ssf/streams?stream_id=sst_x")),
        ("GET", format!("{base}/ssf/status?stream_id=sst_x")),
        ("POST", format!("{base}/ssf/status")),
        ("POST", format!("{base}/ssf/poll/sst_x")),
        ("POST", format!("{base}/ssf/verify")),
        (
            "GET",
            format!(
                "/.well-known/ssf-configuration/t/{}/e/{}",
                scope.tenant(),
                scope.environment()
            ),
        ),
    ];
    for (method, path) in cases {
        let body = (method != "GET" && method != "DELETE").then(|| "{}".to_owned());
        let (status, text) = send(&harness, method, &path, Some(&auth), body).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {path} answered on a deployment with SSF off: {text}"
        );
    }
}

/// Create a poll stream with a description and one requested event, and return its object.
async fn seeded_stream(harness: &Harness, auth: &str) -> serde_json::Value {
    let body = serde_json::json!({
        "delivery": { "method": "urn:ietf:rfc:8936" },
        "events_requested": [ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE],
        "aud": ["https://receiver.example.com"],
        "format": "iss_sub",
        "description": "the original label",
    })
    .to_string();
    let (status, text) = send(
        harness,
        "POST",
        &streams_path(harness),
        Some(auth),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    serde_json::from_str(&text).expect("a stream object")
}

/// PATCH changes what it names and leaves out what it does not.
///
/// SSF 1.0 section 8.1.2: "Any properties missing in the request MUST NOT be changed by the
/// Transmitter." Both halves are asserted, because a handler that rebuilt the whole
/// configuration from the request would pass a test that only checked the changed property and
/// would silently drop the description of every receiver that patched its delivery.
#[tokio::test]
async fn a_patch_changes_the_named_property_and_leaves_the_rest() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let created = seeded_stream(&harness, &auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    let body = serde_json::json!({
        "stream_id": stream_id,
        "description": "the new label",
    })
    .to_string();
    let (status, text) = send(
        &harness,
        "PATCH",
        &streams_path(&harness),
        Some(&auth),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let patched: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(patched["description"], serde_json::json!("the new label"));
    // UNTOUCHED, because the request did not name them.
    assert_eq!(patched["delivery"], created["delivery"]);
    assert_eq!(
        patched["events_requested"], created["events_requested"],
        "a patch that named only the description changed the event negotiation"
    );
    assert_eq!(patched["events_delivered"], created["events_delivered"]);
    // AND THE RESPONSE IS THE STORED STATE, not the request echoed: a re-read must agree.
    let (status, text) = send(
        &harness,
        "GET",
        &format!("{}?stream_id={stream_id}", streams_path(&harness)),
        Some(&auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let read_back: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        read_back, patched,
        "the PATCH response is not what was stored"
    );
}

/// PUT deletes what it omits.
///
/// SSF 1.0 section 8.1.3: "Missing Receiver-Supplied properties MUST be interpreted as requested
/// to be deleted." This is the whole reason PATCH and PUT are separate verbs rather than one
/// handler with a flag, so it is the property most worth pinning: a PUT carrying only the
/// delivery must clear the description and the event negotiation.
#[tokio::test]
async fn a_put_deletes_the_receiver_properties_it_omits() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let created = seeded_stream(&harness, &auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();
    assert_eq!(
        created["events_delivered"],
        serde_json::json!([ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE]),
        "the fixture did not start with something to delete"
    );

    let body = serde_json::json!({
        "stream_id": stream_id,
        "delivery": { "method": "urn:ietf:rfc:8936" },
    })
    .to_string();
    let (status, text) = send(
        &harness,
        "PUT",
        &streams_path(&harness),
        Some(&auth),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let replaced: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        replaced["description"],
        serde_json::Value::Null,
        "a PUT that omitted the description did not delete it"
    );
    assert_eq!(replaced["events_requested"], serde_json::json!([]));
    assert_eq!(
        replaced["events_delivered"],
        serde_json::json!([]),
        "the transmitter still agrees to send an event the receiver stopped asking for"
    );
}

/// An update RECOMPUTES what the transmitter agreed to send; it does not echo the request.
///
/// `events_delivered` is Transmitter-Supplied: it is the intersection of what the receiver asked
/// for with what this build emits, so a receiver that renegotiates towards something not
/// produced here must SEE that it is not coming.
///
/// THE REQUESTED SET HAS TO CONTAIN SOMETHING UNSUPPORTED for this to bite, which is the whole
/// point of the case. Measured: with `events_delivered = events_requested.clone()` substituted
/// for the intersection, every other test in this file still passed, because every one of them
/// requests only types this build supports -- so the intersection and the echo agree. (An
/// earlier version of this note said they all end with an EMPTY set, which is wrong: three of
/// them end with a one-element set. The reason they survive is that nothing they ask for is
/// ever dropped, not that nothing is ever delivered.)
#[tokio::test]
async fn an_update_recomputes_what_the_transmitter_agreed_to_send() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let created = seeded_stream(&harness, &auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    let unsupported = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    let body = serde_json::json!({
        "stream_id": stream_id,
        "events_requested": [
            ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE,
            unsupported,
        ],
    })
    .to_string();
    let (status, text) = send(
        &harness,
        "PATCH",
        &streams_path(&harness),
        Some(&auth),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let updated: serde_json::Value = serde_json::from_str(&text).expect("a stream object");

    // WHAT THE RECEIVER ASKED FOR is kept verbatim, including the part it will not get: SSF has
    // the transmitter record the request and answer it, not silently rewrite it.
    assert_eq!(
        updated["events_requested"],
        serde_json::json!([ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE, unsupported])
    );
    // WHAT IT WILL ACTUALLY BE SENT excludes the type this build does not emit.
    assert_eq!(
        updated["events_delivered"],
        serde_json::json!([ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE]),
        "the transmitter agreed to send an event type it cannot produce"
    );
}

/// A receiver can re-point its own push stream, and only its own.
///
/// `delivery` is receiver-supplied, so re-pointing is the feature. 0220 grants the data plane
/// UPDATE on the endpoint columns to allow it, which means the SQL conjunct on `client_id` is
/// now the only thing standing between one receiver and another's endpoint. Both directions are
/// driven here for that reason.
#[tokio::test]
async fn a_receiver_repoints_its_own_stream_and_reaches_no_others() {
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
    let created = seeded_stream(&harness, &owner_auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    let repoint = serde_json::json!({
        "stream_id": stream_id,
        "delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": "https://receiver.example.com/moved",
        },
    })
    .to_string();

    // THE INTRUDER FIRST, so a handler that wrote before checking is caught by the owner's
    // assertion below rather than being masked by the owner's own successful edit.
    let (status, text) = send(
        &harness,
        "PATCH",
        &streams_path(&harness),
        Some(&intruder_auth),
        Some(repoint.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a second receiver re-pointed a stream it does not own: {text}"
    );

    let (status, text) = send(
        &harness,
        "GET",
        &format!("{}?stream_id={stream_id}", streams_path(&harness)),
        Some(&owner_auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let untouched: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        untouched["delivery"], created["delivery"],
        "the refused request moved the endpoint anyway"
    );

    let (status, text) = send(
        &harness,
        "PATCH",
        &streams_path(&harness),
        Some(&owner_auth),
        Some(repoint),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let moved: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        moved["delivery"]["endpoint_url"],
        serde_json::json!("https://receiver.example.com/moved"),
        "the owner could not re-point its own stream"
    );
}

/// A second receiver gets the uniform not-found even when its request would be a 400.
///
/// THE FENCE COMES BEFORE THE VALIDATION, and this is what pins the order. The read-only
/// comparison needs the stream as it stands, so it runs after a read; if that read were not
/// receiver-fenced, an intruder sending a deliberately WRONG `aud` for somebody else's stream
/// would get a `400 aud is supplied by the transmitter` and learn the stream exists, while an
/// absent handle still answered `404`. The update would still be refused -- the store's conjunct
/// catches it -- so the leak would be in the status code alone, which is exactly the kind of
/// difference no test of the happy path can see.
#[tokio::test]
async fn a_second_receivers_invalid_update_is_still_the_uniform_not_found() {
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
    let created = seeded_stream(&harness, &owner_auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    // A request that WOULD be a 400 if the intruder owned the stream: it tries to change a
    // transmitter-supplied property.
    let body = serde_json::json!({
        "stream_id": stream_id,
        "aud": ["https://somebody-else.example"],
    })
    .to_string();
    let (owned_status, text) = send(
        &harness,
        "PATCH",
        &streams_path(&harness),
        Some(&intruder_auth),
        Some(body.clone()),
    )
    .await;
    assert_eq!(
        owned_status,
        StatusCode::NOT_FOUND,
        "an intruder learned a stream exists by sending an invalid update: {text}"
    );

    // AN ABSENT HANDLE ANSWERS IDENTICALLY, which is the half that makes the first one mean
    // something: two different answers here would be the enumeration oracle.
    let absent = serde_json::json!({
        "stream_id": ironauth_store::SsfStreamId::generate(
            harness.state().env(),
            &harness.scope(),
        )
        .to_string(),
        "aud": ["https://somebody-else.example"],
    })
    .to_string();
    let (absent_status, text) = send(
        &harness,
        "PATCH",
        &streams_path(&harness),
        Some(&intruder_auth),
        Some(absent),
    )
    .await;
    assert_eq!(
        absent_status, owned_status,
        "an absent stream answered differently from another receiver's: {text}"
    );
}

/// A transmitter-supplied property may be PRESENT, but it must MATCH.
///
/// SSF 1.0: "Transmitter-Supplied properties besides the `stream_id` MAY be present, but they MUST
/// match the expected value." Both halves matter and both are driven: echoing the current value
/// back is fine, and changing it is a 400 that names the property. A handler that simply ignored
/// these members would pass the first half and silently accept the second, leaving a receiver
/// believing it had changed its own audience.
#[tokio::test]
async fn a_transmitter_supplied_property_may_be_echoed_but_not_changed() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let created = seeded_stream(&harness, &auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    // ECHOED: every read-only property sent back exactly as the transmitter supplied it.
    let echo = serde_json::json!({
        "stream_id": stream_id,
        "aud": created["aud"],
        "iss": created["iss"],
        "format": created["format"],
        "events_supported": created["events_supported"],
        "events_delivered": created["events_delivered"],
        "min_verification_interval": created["min_verification_interval"],
        "description": "still fine",
    })
    .to_string();
    let (status, text) = send(
        &harness,
        "PATCH",
        &streams_path(&harness),
        Some(&auth),
        Some(echo),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "echoing the transmitter's own values back was refused: {text}"
    );

    // CHANGED: one property at a time, so a refusal names the property that caused it.
    for (property, value) in [
        ("aud", serde_json::json!(["https://somebody-else.example"])),
        ("iss", serde_json::json!("https://issuer.example/t/x/e/y")),
        ("format", serde_json::json!("email")),
        (
            "events_supported",
            serde_json::json!(["https://made.up/event"]),
        ),
        (
            "events_delivered",
            serde_json::json!(["https://made.up/event"]),
        ),
        ("min_verification_interval", serde_json::json!(9999)),
    ] {
        let mut body = serde_json::Map::new();
        body.insert("stream_id".to_owned(), serde_json::json!(stream_id));
        body.insert(property.to_owned(), value);
        let (status, text) = send(
            &harness,
            "PATCH",
            &streams_path(&harness),
            Some(&auth),
            Some(serde_json::Value::Object(body).to_string()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "changing the transmitter-supplied {property} was accepted: {text}"
        );
        assert!(
            text.contains(property),
            "the refusal does not name {property}: {text}"
        );
    }

    // AND NOTHING MOVED. Six refusals must leave the stream exactly as the echo left it.
    let (status, text) = send(
        &harness,
        "GET",
        &format!("{}?stream_id={stream_id}", streams_path(&harness)),
        Some(&auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let after: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(after["aud"], created["aud"]);
    assert_eq!(after["format"], created["format"]);
    assert_eq!(after["description"], serde_json::json!("still fine"));
}

/// A replacement without a delivery is refused rather than leaving the stream undeliverable.
///
/// A PUT treats an omitted receiver-supplied property as a deletion, and `delivery` is one. But
/// a stream with no delivery method is not a state this schema can hold -- 0216's CHECK ties the
/// method to the endpoint and there is no third value -- so the honest answer is that the
/// request is invalid, not that the stream is now unreachable.
#[tokio::test]
async fn a_replacement_without_a_delivery_is_refused() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let created = seeded_stream(&harness, &auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    let body = serde_json::json!({ "stream_id": stream_id }).to_string();
    let (status, text) = send(
        &harness,
        "PUT",
        &streams_path(&harness),
        Some(&auth),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");

    let (status, text) = send(
        &harness,
        "GET",
        &format!("{}?stream_id={stream_id}", streams_path(&harness)),
        Some(&auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let after: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        after["delivery"], created["delivery"],
        "the refused replacement changed the delivery anyway"
    );
}

/// A receiver can PUT back exactly the configuration it was given.
///
/// THE SPEC MANDATES THE ROUND TRIP. A PUT must carry the full receiver-supplied set, "not only
/// those specifically intended to be changed", so the natural client is read-modify-write: GET
/// the stream, change one field, PUT the whole thing. For a POLL stream that body includes the
/// `delivery.endpoint_url` this transmitter synthesises, and the delivery validator refused it,
/// so every poll stream was un-PUT-able and the transmitter rejected the document it had just
/// published.
///
/// UNMODIFIED, DELIBERATELY. The read-modify-write is driven with NO edit at all, because that
/// is the case where every value came from the transmitter: if the round trip cannot survive
/// changing nothing, no edit built on it can survive either.
#[tokio::test]
async fn a_poll_stream_can_be_replaced_with_exactly_what_the_transmitter_published() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let created = seeded_stream(&harness, &auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();
    assert!(
        created["delivery"]["endpoint_url"].is_string(),
        "the fixture does not publish a poll address, so this proves nothing: {created}"
    );

    let body = serde_json::json!({
        "stream_id": stream_id,
        "delivery": created["delivery"],
        "events_requested": created["events_requested"],
        "description": created["description"],
    })
    .to_string();
    let (status, text) = send(
        &harness,
        "PUT",
        &streams_path(&harness),
        Some(&auth),
        Some(body),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the transmitter refused the configuration it published: {text}"
    );
    let replaced: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        replaced, created,
        "a replacement that changed nothing changed something"
    );

    // A DIFFERENT ADDRESS IS STILL REFUSED. Tolerating our own value must not become tolerating
    // any value: a receiver does not get to choose where it collects from.
    let elsewhere = serde_json::json!({
        "stream_id": stream_id,
        "delivery": {
            "method": "urn:ietf:rfc:8936",
            "endpoint_url": "https://attacker.example/collect",
        },
    })
    .to_string();
    let (status, text) = send(
        &harness,
        "PUT",
        &streams_path(&harness),
        Some(&auth),
        Some(elsewhere),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a receiver chose its own poll address: {text}"
    );
}

/// Input the schema refuses is a 400, not a 500.
///
/// The update path inherited create's `Err(_) => server_error()` mapping without inheriting the
/// bounds that justify it. An empty `description` violates 0216's `ssf_streams_description_shaped`
/// CHECK, so it reached Postgres and came back as a transmitter fault -- for the obvious thing a
/// receiver sends when clearing its label, and for input the identical create refuses with a
/// 400.
#[tokio::test]
async fn input_the_schema_refuses_is_a_bad_request_on_update_as_it_is_on_create() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let created = seeded_stream(&harness, &auth).await;
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    for (label, value) in [
        ("an empty description", serde_json::json!("")),
        ("a whitespace description", serde_json::json!("   ")),
    ] {
        for method in ["PATCH", "PUT"] {
            let body = serde_json::json!({
                "stream_id": stream_id,
                "delivery": created["delivery"],
                "description": value,
            })
            .to_string();
            let (status, text) = send(
                &harness,
                method,
                &streams_path(&harness),
                Some(&auth),
                Some(body),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{method} with {label} was not a bad request: {text}"
            );
        }
    }

    // THE WAY TO CLEAR IT is to omit it from a replacement, which is what the spec defines a
    // deletion to be. A refusal with no way to achieve the intent would just be a trap.
    let body = serde_json::json!({
        "stream_id": stream_id,
        "delivery": created["delivery"],
    })
    .to_string();
    let (status, text) = send(
        &harness,
        "PUT",
        &streams_path(&harness),
        Some(&auth),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let cleared: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(cleared["description"], serde_json::Value::Null);
}
