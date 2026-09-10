// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSF 1.0 section 7.1.4 stream verification (issue #143).
//!
//! # What this owes
//!
//! #143's first acceptance criterion names "stream CRUD, status transitions, and verification
//! events". Verification is the receiver asking the transmitter to prove the delivery path works
//! without waiting for a real security signal, and the properties that matter are the ones a
//! receiver's own conformance check depends on:
//!
//! - the SET REALLY ARRIVES, by the delivery method the stream negotiated. A 204 that queued
//!   nothing would be the exact failure verification exists to detect, so wherever a test
//!   asserts a verification SUCCEEDED it reads the delivery side and not merely the status.
//!   The cases that assert a status alone are the ones whose whole subject IS the status: that
//!   two refusals are indistinguishable, that a second stream is not refused, and that the
//!   advertised endpoint answers at all;
//! - the subject is an OPAQUE identifier naming the STREAM, whatever format the stream
//!   negotiated. Section 7.1.4 requires it, and a stream that negotiated `email` getting an
//!   email-shaped subject here would name a person who has nothing to do with the event;
//! - `state` comes back verbatim, because the 204 names nothing and echoing it is the receiver's
//!   only way to match the SET it collects to the request it made;
//! - the rate limit is real, per stream, AND not resettable by the receiver. The per-stream
//!   column lives on a row the receiver deletes at will, so a second floor keyed on the client
//!   is what actually bounds the work; both are driven here.
//!
//! # This is the first production caller of the two queues
//!
//! `SsfStreamSetRepo::queue` and `enqueue_push` shipped with the delivery machinery and no
//! production caller: #144's fan-out is the general one. Verification is a producer that does
//! not need a vocabulary, so it reaches both, and these tests are the first to drive either from
//! an HTTP request rather than from a test seeding rows directly.

#![cfg(feature = "testing")]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::Harness;
use ironauth_oidc::ClientAuthMethod;
use ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE;
use ironauth_store::{
    ClientId, CorrelationId, NewSsfStream, SsfDelivery, SsfStreamId, SsfStreamStatus,
    SsfSubjectFormat, StoreError,
};

fn basic(client_id: &ClientId, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

async fn provision_envelope(harness: &Harness, env: &ironauth_env::Env) {
    let acting = harness
        .db()
        .store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(env), CorrelationId::generate(env));
    for (label, outcome) in [
        (
            "kek",
            acting
                .envelope()
                .provision_kek(env, &harness.db().master_key())
                .await
                .map(|_| ()),
        ),
        (
            "dek",
            acting
                .envelope()
                .provision_dek(env, &harness.db().master_key())
                .await
                .map(|_| ()),
        ),
    ] {
        match outcome {
            Ok(()) | Err(StoreError::Conflict) => {}
            Err(error) => panic!("provision the scope {label}: {error:?}"),
        }
    }
}

/// A stream owned by `client`, delivered as `delivery`, negotiating `format`.
///
/// The subject format is a PARAMETER because one test's whole point is that it does not reach
/// the verification event: a stream negotiating `email` must still get an opaque subject.
async fn stream(
    harness: &Harness,
    client: &ClientId,
    delivery: &SsfDelivery,
    format: SsfSubjectFormat,
) -> SsfStreamId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    provision_envelope(harness, &env).await;
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
                delivery,
                events_requested: &none,
                events_delivered: &none,
                subject_format: format,
                audience: &audience,
                description: None,
            },
            20,
            None,
        )
        .await
        .expect("seed a stream");
    id
}

fn verify_uri(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/ssf/verify", scope.tenant(), scope.environment())
}

async fn post(
    harness: &Harness,
    uri: &str,
    auth: Option<&str>,
    body: String,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let request = builder.body(Body::from(body)).expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

/// Ask for a verification event on `stream`, echoing `state` when given.
async fn ask(
    harness: &Harness,
    auth: &str,
    stream: &SsfStreamId,
    state: Option<&str>,
) -> (StatusCode, String) {
    let mut body = serde_json::Map::new();
    body.insert(
        "stream_id".to_owned(),
        serde_json::Value::String(stream.to_string()),
    );
    if let Some(state) = state {
        body.insert(
            "state".to_owned(),
            serde_json::Value::String(state.to_owned()),
        );
    }
    post(
        harness,
        &verify_uri(harness),
        Some(auth),
        serde_json::Value::Object(body).to_string(),
    )
    .await
}

/// The claims of the one SET a poll stream is owed, decoded without verifying.
///
/// NOT VERIFIED HERE, deliberately: `ssf_set.rs` owns the signature and `ssf_set_corpus.rs` has
/// an independent library check it. What these tests are about is the CONTENT of a verification
/// event, and decoding it directly is what keeps them from passing on a token that verifies and
/// says the wrong thing.
fn claims_of(token: &str) -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = token.split('.').nth(1).expect("a three segment JWS");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("the payload is JSON")
}

async fn owed_tokens(harness: &Harness, stream: &SsfStreamId) -> Vec<String> {
    harness
        .db()
        .store()
        .scoped(harness.scope())
        .ssf_stream_sets()
        .owed(stream, 10)
        .await
        .expect("read what is owed")
        .into_iter()
        .map(|set| set.set_jws)
        .collect()
}

/// A poll receiver asks, and collects a verification SET that names its stream.
///
/// THE SUBJECT FORMAT IS `Email` ON PURPOSE. Section 7.1.4 makes the verification event's
/// `sub_id` an `opaque` identifier whose `id` is the stream, regardless of what the stream
/// negotiated, and a build that rendered the negotiated format here would put an email-shaped
/// subject on an event that is about a stream rather than a person. A test using a stream that
/// negotiated `opaque` anyway would pass either way.
#[tokio::test]
async fn a_poll_receiver_is_owed_a_verification_set_naming_its_stream_opaquely() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let id = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::Email,
    )
    .await;

    let (status, body) = ask(&harness, &auth, &id, Some("probe-42")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(body.is_empty(), "204 carried a body: {body}");

    let tokens = owed_tokens(&harness, &id).await;
    assert_eq!(
        tokens.len(),
        1,
        "the 204 promised a transmission and queued nothing"
    );
    let claims = claims_of(&tokens[0]);
    assert_eq!(
        claims["sub_id"],
        serde_json::json!({ "format": "opaque", "id": id.to_string() }),
        "the verification event does not name its stream as an opaque subject"
    );
    let event = &claims["events"][VERIFICATION_EVENT_TYPE];
    assert!(
        !event.is_null(),
        "the SET is not keyed by the verification event type: {claims}"
    );
    assert_eq!(
        event["state"],
        serde_json::json!("probe-42"),
        "the state the receiver chose was not echoed back"
    );
}

/// With no `state`, the member is ABSENT rather than null or empty.
///
/// Section 7.1.4 makes `state` optional and says the transmitter echoes what it was given. A
/// receiver that did not send one and reads `null` cannot tell that from a transmitter that lost
/// its value.
#[tokio::test]
async fn a_verification_without_state_carries_no_state_member() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let id = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;

    let (status, body) = ask(&harness, &auth, &id, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let tokens = owed_tokens(&harness, &id).await;
    let claims = claims_of(&tokens[0]);
    let event = &claims["events"][VERIFICATION_EVENT_TYPE];
    assert!(
        event.is_object(),
        "the event body is not an object: {claims}"
    );
    assert!(
        event.get("state").is_none(),
        "a state member appeared for a request that sent none: {event}"
    );
}

/// A push receiver's verification goes to the outbox, not to the poll queue.
///
/// The two delivery methods have separate durable paths, and putting a push stream's event in
/// the poll queue would leave it owed forever to a receiver that never polls.
#[tokio::test]
async fn a_push_receivers_verification_is_enqueued_for_the_push_worker() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let delivery = SsfDelivery::Push {
        endpoint_url: "https://receiver.example.com/events".to_owned(),
        secret_name: None,
    };
    let id = stream(&harness, &client, &delivery, SsfSubjectFormat::IssSub).await;

    let (status, body) = ask(&harness, &auth, &id, Some("push-probe")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let claimed = harness
        .db()
        .store()
        .scoped(harness.scope())
        .outbox()
        .claim(
            harness.state().env(),
            ironauth_store::SSF_PUSH_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(
        claimed.len(),
        1,
        "the push stream's verification was not enqueued for delivery"
    );
    assert_eq!(
        claimed[0].payload[ironauth_oidc::ssf_push::PAYLOAD_EVENT_TYPE],
        serde_json::json!(VERIFICATION_EVENT_TYPE)
    );
    assert_eq!(
        claimed[0].payload[ironauth_oidc::ssf_push::PAYLOAD_SUB_ID],
        serde_json::json!({ "format": "opaque", "id": id.to_string() })
    );
    assert!(
        owed_tokens(&harness, &id).await.is_empty(),
        "a push stream's verification also landed in the poll queue"
    );
}

/// The rate limit refuses the second request, and it is PER STREAM.
///
/// Both halves matter. Without the first, one receiver mints unbounded signed SETs from one
/// small POST each. Without the second, the limit would be a shared budget one stream could
/// spend on behalf of every other stream in the environment.
#[tokio::test]
async fn a_second_verification_is_refused_and_a_second_stream_is_not() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let first = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;
    let second = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;

    let (status, body) = ask(&harness, &auth, &first, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, body) = ask(&harness, &auth, &first, None).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a second verification inside the interval was accepted: {body}"
    );
    assert_eq!(
        owed_tokens(&harness, &first).await.len(),
        1,
        "the refused request minted a SET anyway"
    );

    let (status, body) = ask(&harness, &auth, &second, None).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "one stream's verification spent another stream's budget: {body}"
    );
}

/// A second receiver cannot verify a stream it does not own, and cannot tell it apart from one
/// that does not exist.
#[tokio::test]
async fn a_second_receiver_reaches_no_stream_and_learns_nothing() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (owner, _) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let (intruder, intruder_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let intruder_auth = basic(&intruder, &intruder_secret);
    let id = stream(
        &harness,
        &owner,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;

    let (owned_status, body) = ask(&harness, &intruder_auth, &id, None).await;
    assert_eq!(
        owned_status,
        StatusCode::NOT_FOUND,
        "a second receiver verified a stream it does not own: {body}"
    );
    assert!(
        owed_tokens(&harness, &id).await.is_empty(),
        "the owner's queue was written by another receiver"
    );

    // AN ABSENT STREAM ANSWERS IDENTICALLY, which is what stops the endpoint being a way to
    // learn which stream handles exist in this environment.
    let absent = SsfStreamId::generate(harness.state().env(), &harness.scope());
    let (absent_status, body) = ask(&harness, &intruder_auth, &absent, None).await;
    assert_eq!(
        absent_status, owned_status,
        "an absent stream answered differently from another receiver's: {body}"
    );
}

/// `paused` is verified and RETAINS it; `disabled` is refused.
///
/// The distinction 0216 draws, applied here. A paused receiver is asking to be left alone for a
/// while and collects on resume, so a verification queued now is a verification it will get. A
/// disabled stream retains nothing, so a 204 would promise a transmission that will never happen
/// -- and section 7.1.4's success means exactly "has transmitted or will".
#[tokio::test]
async fn a_paused_stream_is_verified_and_a_disabled_one_is_refused() {
    for (status_to_set, expected, owed_after, label) in [
        (SsfStreamStatus::Paused, StatusCode::NO_CONTENT, 1, "paused"),
        (
            SsfStreamStatus::Disabled,
            StatusCode::FORBIDDEN,
            0,
            "disabled",
        ),
    ] {
        let mut harness = Harness::start_store_backed().await;
        harness.enable_ssf(20);
        let (client, secret) = harness
            .create_confidential_client(ClientAuthMethod::Basic)
            .await;
        let auth = basic(&client, &secret);
        let id = stream(
            &harness,
            &client,
            &SsfDelivery::Poll,
            SsfSubjectFormat::IssSub,
        )
        .await;
        let env = harness.state().env().clone();
        harness
            .db()
            .store()
            .scoped(harness.scope())
            .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
            .ssf_streams()
            .set_status(&env, &id, &client, status_to_set, None)
            .await
            .expect("set the status");

        let (status, body) = ask(&harness, &auth, &id, None).await;
        assert_eq!(
            status, expected,
            "a {label} stream answered wrongly: {body}"
        );
        assert_eq!(
            owed_tokens(&harness, &id).await.len(),
            owed_after,
            "a {label} stream holds the wrong number of verification SETs"
        );
    }
}

/// Discovery advertises the endpoint, the endpoint resolves, and it advertises nothing else.
///
/// The `jwks_uri` lesson applied to a second field: this surface once published a path nothing
/// mounted and every assertion about the document passed anyway. So the advertised endpoint is
/// CALLED here rather than eyeballed.
#[tokio::test]
async fn discovery_advertises_the_verification_endpoint_and_nothing_ssf_puts_elsewhere() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let id = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;

    let scope = harness.scope();
    let request = Request::builder()
        .method("GET")
        .uri(format!(
            "/.well-known/ssf-configuration/t/{}/e/{}",
            scope.tenant(),
            scope.environment()
        ))
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("a configuration document");

    // NOT IN THIS DOCUMENT. SSF 1.0 makes `min_verification_interval` a read-only STREAM
    // configuration property; it was published here, where a conformant receiver never looks
    // for it. `a_receiver_is_told_which_of_its_requested_events_will_arrive` pins it on the
    // stream object, and `the_enforced_interval_is_the_one_that_is_advertised` measures the
    // number the handler actually enforces rather than reading it back off its own accessor.
    assert!(
        doc.get("min_verification_interval").is_none(),
        "the transmitter metadata carries a member SSF does not define for it: {body}"
    );
    // AND THE EVENT IS ADVERTISED, since the transmitter can now emit one.
    assert_eq!(
        doc["events_supported"],
        serde_json::json!([VERIFICATION_EVENT_TYPE])
    );

    let advertised = doc["verification_endpoint"]
        .as_str()
        .expect("verification_endpoint");
    let path = advertised
        .strip_prefix("https://issuer.test")
        .or_else(|| advertised.strip_prefix("http://issuer.test"))
        .unwrap_or_else(|| panic!("the advertised endpoint is not on this issuer: {advertised}"));
    let body = serde_json::json!({ "stream_id": id.to_string() }).to_string();
    let (status, text) = post(&harness, path, Some(&auth), body).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the advertised verification endpoint does not serve a verification: {text}"
    );
}

/// An SSF config with a one-second interval and an allowance of `allowance`.
///
/// SHORT ENOUGH TO WAIT OUT. A test measuring a limit has to set it: against the shipped sixty
/// seconds these tests would either take a minute each or assert nothing.
fn quick_ssf(allowance: u32) -> ironauth_config::SsfConfig {
    ironauth_config::SsfConfig {
        enabled: true,
        max_streams_per_client: allowance,
        min_verification_interval_secs: 1,
        ..ironauth_config::SsfConfig::default()
    }
}

/// Deleting and recreating a stream does NOT hand the receiver a fresh verification budget.
///
/// THE BYPASS THIS EXISTS TO CLOSE. The per-stream floor lives on `ssf_streams`, a row the
/// receiver deletes at will, so `create -> verify -> delete -> create` gives a stream whose
/// `last_verification_at` is NULL and passes immediately. Measured in review: the loop minted
/// signed SETs as fast as a client could issue three requests, and the advertised floor stopped
/// none of it. The budget keyed on the CLIENT is what makes the bound real.
#[tokio::test]
async fn a_receiver_cannot_reset_its_verification_budget_by_recreating_the_stream() {
    let mut harness = Harness::start_store_backed().await;
    // An allowance of one, so the second verification of the window must be refused however
    // the receiver arranges its streams.
    harness.enable_ssf_with(&quick_ssf(1));
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);

    let first = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;
    let (status, body) = ask(&harness, &auth, &first, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Destroy the row the per-stream floor lives on, exactly as the bypass does.
    let env = harness.state().env().clone();
    harness
        .db()
        .store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .delete(&env, &first, &client)
        .await
        .expect("the receiver deletes its own stream");

    let second = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;
    let (status, body) = ask(&harness, &auth, &second, None).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a recreated stream handed the receiver a fresh verification slot: {body}"
    );
    assert!(
        owed_tokens(&harness, &second).await.is_empty(),
        "the refused request minted a SET anyway"
    );
}

/// The interval the limiter ENFORCES is measured, not read back off the document that states it.
///
/// The discovery assertion compares the published number against the same accessor the handler
/// reads, so it cannot tell an enforcing handler from one that ignores the value entirely. This
/// drives the clock instead: refused inside the window, allowed once it has passed.
#[tokio::test]
async fn the_enforced_interval_is_the_one_that_is_advertised() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf_with(&quick_ssf(10));
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let id = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;

    let (status, body) = ask(&harness, &auth, &id, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = ask(&harness, &auth, &id, None).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a second verification inside the interval was accepted: {body}"
    );

    // PAST THE ADVERTISED INTERVAL, and the same request now succeeds. If the handler enforced
    // some other number this is the assertion that would fail.
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    let (status, body) = ask(&harness, &auth, &id, None).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the interval the handler enforces is longer than the one it advertises: {body}"
    );
    assert_eq!(
        owed_tokens(&harness, &id).await.len(),
        2,
        "the accepted requests did not each queue a SET"
    );
}

/// The refusal tells the receiver how long to wait.
///
/// `Retry-After: 0` was the first version, and it is the one value that makes the header worse
/// than absent: a receiver obeying it retries immediately and is refused again, so the header
/// turns a rate limit into an invitation to spin.
#[tokio::test]
async fn the_rate_limit_refusal_names_the_interval_in_retry_after() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf_with(&quick_ssf(10));
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let id = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;
    ask(&harness, &auth, &id, None).await;

    let body = serde_json::json!({ "stream_id": id.to_string() }).to_string();
    let request = Request::builder()
        .method("POST")
        .uri(verify_uri(&harness))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, &auth)
        .body(Body::from(body))
        .expect("request builds");
    let (status, headers, text) = harness.send(request).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{text}");
    assert_eq!(
        headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1"),
        "the refusal did not tell the receiver to wait the interval it enforces"
    );
}

/// An over-long `state` is refused WITHOUT spending the receiver's slot.
///
/// A 400 for a request that minted and queued nothing must not also cost an interval: the
/// receiver fixes its request and asks again, and it should not have to wait to do so.
#[tokio::test]
async fn an_over_long_state_is_refused_and_costs_no_slot() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf_with(&quick_ssf(10));
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let id = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;

    let too_long = "x".repeat(253);
    let (status, body) = ask(&harness, &auth, &id, Some(&too_long)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        owed_tokens(&harness, &id).await.is_empty(),
        "the refused request queued a SET"
    );

    // THE SLOT SURVIVED. This is the half that fails if the limiter is claimed before the
    // request is validated.
    let (status, body) = ask(&harness, &auth, &id, Some("fixed")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a 400 spent the receiver's verification slot: {body}"
    );
}

/// A receiver is told which of the events it asked for will actually arrive.
///
/// `events_delivered` is the intersection of what the receiver requested with what this build
/// emits, and it stopped always being empty when the verification endpoint landed. Both halves
/// are driven: the type this build emits comes back, and one it does not is dropped.
#[tokio::test]
async fn a_receiver_is_told_which_of_its_requested_events_will_arrive() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);

    let body = serde_json::json!({
        "delivery": { "method": "urn:ietf:rfc:8936" },
        "events_requested": [
            VERIFICATION_EVENT_TYPE,
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        ],
        "aud": ["https://receiver.example.com"],
        "format": "iss_sub",
    })
    .to_string();
    let scope = harness.scope();
    let (status, text) = post(
        &harness,
        &format!(
            "/t/{}/e/{}/ssf/streams",
            scope.tenant(),
            scope.environment()
        ),
        Some(&auth),
        body,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    let created: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        created["events_delivered"],
        serde_json::json!([VERIFICATION_EVENT_TYPE]),
        "the transmitter did not agree to send the one event it can emit"
    );
    // AND THE STREAM OBJECT CARRIES THE INTERVAL, which is where SSF 1.0 defines it. It was
    // published in the transmitter metadata document instead, where a conformant receiver never
    // looks for it.
    assert_eq!(
        created["min_verification_interval"],
        serde_json::json!(harness.state().ssf_min_verification_interval_secs()),
        "the stream configuration does not carry the verification interval: {text}"
    );
}

/// A receiver that has stopped collecting is told so, and it is a 429 rather than a 500.
///
/// `owed_queue_full` is the only answer to a full poll queue and nothing drove it. The
/// distinction it draws matters operationally: a full queue means the RECEIVER stopped
/// collecting, so a 500 would send an operator looking at the transmitter, and the two 429s
/// differ in what they tell the receiver to do -- wait, versus collect what you already have.
#[tokio::test]
async fn a_verification_for_a_stream_that_is_already_full_is_refused_as_a_rate_limit() {
    let mut harness = Harness::start_store_backed().await;
    // An owed ceiling of one, so a single pre-queued SET fills the stream.
    harness.enable_ssf_with(&ironauth_config::SsfConfig {
        enabled: true,
        max_streams_per_client: 20,
        max_owed_sets_per_stream: 1,
        max_subjects_per_stream: 20,
        min_verification_interval_secs: 1,
    });
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let id = stream(
        &harness,
        &client,
        &SsfDelivery::Poll,
        SsfSubjectFormat::IssSub,
    )
    .await;

    let env = harness.state().env().clone();
    harness
        .db()
        .store()
        .scoped(harness.scope())
        .ssf_stream_sets()
        .queue(&env, &id, "evt_backlog", "header.payload.sig", 1)
        .await
        .expect("fill the stream's queue");

    let (status, body) = ask(&harness, &auth, &id, None).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a verification for a full stream was not refused as a rate limit: {body}"
    );
    // AND IT SAYS WHICH 429 IT IS. The two refusals are fixed by different actions, so a
    // receiver that cannot tell them apart cannot act on either.
    assert!(
        body.contains("acknowledge what you have been given"),
        "the refusal reads as a rate limit rather than a full queue: {body}"
    );
    assert_eq!(
        owed_tokens(&harness, &id).await.len(),
        1,
        "the refused verification queued a SET past the ceiling"
    );
}
