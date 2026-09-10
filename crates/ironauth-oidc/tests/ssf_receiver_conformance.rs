// SPDX-License-Identifier: MIT OR Apache-2.0

//! The in-repo SSF receiver conformance fixture (issue #143).
//!
//! # What this owes
//!
//! #143's first acceptance criterion ends "exercised by an in-repo receiver conformance
//! fixture", and its verification section asks for "integration tests with an in-repo SSF
//! receiver fixture covering push, poll, verification, and outage/redelivery, in CI".
//!
//! The other SSF suites test the transmitter a piece at a time: one asserts a row appeared,
//! another asserts a status code, another asserts a claim set. None of them is a RECEIVER. This
//! one is: [`Receiver`] bootstraps from the discovery document exactly as a real one would,
//! fetches the JWKS the document advertises, builds its verifying key from the published JWK
//! members, and refuses anything it cannot verify. Every SET in this file goes through it.
//!
//! # What that catches that a status code cannot
//!
//! A transmitter can answer 204, write a row, and still be unusable: signing with a key it does
//! not publish, publishing a `jwks_uri` nothing serves, or minting a token whose `aud` or `iss`
//! no receiver matches. Those are all green to a test that reads the store and all fatal to a
//! receiver, and each is caught here.
//!
//! WHAT IS NOT CLAIMED: this fixture recognises a REDELIVERY of one event, because it retires
//! each `jti` it accepts, but no test here hands it two DIFFERENT events sharing a `jti`. The
//! transmitter mints one per event from entropy, so producing that collision would mean
//! mutating the minting side rather than exercising it.
//!
//! # What it deliberately is NOT
//!
//! It is not the independent-library check. That is `ssf_set_corpus.rs` plus
//! `scripts/validate-set-external.py`, which judge our tokens with `PyJWT` precisely because
//! this fixture shares a crate with the code that signed them. This one proves the DELIVERY
//! story end to end; that one proves the bytes are a SET anyone can read.

#![cfg(feature = "testing")]

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::Harness;
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, TokenTyp, TrustedKey, VerificationPolicy, trusted_keys_from_jwks,
    verify,
};
use ironauth_oidc::ClientAuthMethod;
use ironauth_oidc::SendFailure;
use ironauth_oidc::ssf_push::{PushOutcome, SsfPushConsumer, SsfPushSender};
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::{
    ClientId, CorrelationId, FailureOutcome, NewSsfStream, RetryPolicy, SSF_PUSH_CONSUMER,
    SsfDelivery, SsfStreamId, SsfStreamStatus, SsfSubjectFormat, StoreError,
};

const AUDIENCE: &str = "https://receiver.example.com";

fn basic(client_id: &ClientId, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// What a receiver concluded about one SET it was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Verified, and its `jti` had not been seen before.
    Accepted(String),
    /// Verified, but its `jti` was already retired: a redelivery.
    Duplicate(String),
    /// Refused, with the reason.
    Refused(String),
}

/// An SSF receiver, as far as this repository can build one.
///
/// BOOTSTRAPPED FROM DISCOVERY, which is the part that makes it a receiver rather than a
/// verifier: it reads `jwks_uri` out of the SSF configuration document, FETCHES that URL, and
/// builds its key from the JWK members it finds.
///
/// NOT THE ONLY PLACE THE FETCH HAPPENS. `ssf_streams_api`'s discovery test already fetches
/// the advertised `jwks_uri` and requires it to resolve, which is the fix for the defect that
/// prompted it. What is new here is the SECOND half: the key that comes back is then used to
/// verify an actual SET, so a transmitter that publishes a reachable JWKS and signs with a key
/// missing from it is caught here and nowhere else.
#[derive(Clone)]
struct Receiver {
    issuer: String,
    keys: Vec<TrustedKey>,
    seen: Arc<Mutex<Vec<String>>>,
    verdicts: Arc<Mutex<Vec<Verdict>>>,
    /// The raw token of every delivery, in order. What `verdicts` cannot answer: two
    /// deliveries can carry one `jti` and different BYTES.
    tokens: Arc<Mutex<Vec<String>>>,
    /// How many more delivery attempts to refuse before accepting again.
    outage: Arc<Mutex<u32>>,
}

impl Receiver {
    /// Bootstrap from the environment's SSF configuration document.
    async fn bootstrap(harness: &Harness) -> Self {
        let scope = harness.scope();
        let doc: serde_json::Value = serde_json::from_str(
            &get(
                harness,
                &format!(
                    "/.well-known/ssf-configuration/t/{}/e/{}",
                    scope.tenant(),
                    scope.environment()
                ),
            )
            .await
            .1,
        )
        .expect("a configuration document");
        let issuer = doc["issuer"].as_str().expect("issuer").to_owned();
        let jwks_uri = doc["jwks_uri"].as_str().expect("jwks_uri").to_owned();

        // FETCHED, not assembled. The `jwks_uri` this document advertises once named a path
        // nothing served, and every assertion about the document passed while it did.
        let path = jwks_uri
            .strip_prefix("https://issuer.test")
            .or_else(|| jwks_uri.strip_prefix("http://issuer.test"))
            .unwrap_or_else(|| panic!("the advertised jwks_uri is not on this issuer: {jwks_uri}"));
        let (status, body) = get(harness, path).await;
        assert_eq!(status, StatusCode::OK, "the advertised jwks_uri: {body}");
        // PARSED AS JSON FIRST, so a document that is not one fails here rather than as an
        // empty trusted-key set, which the reader below would report the same way as a
        // document naming no usable key.
        serde_json::from_str::<serde_json::Value>(&body).expect("the advertised jwks_uri is JSON");

        // PARSED BY THE JWKS READER THIS REPOSITORY ALREADY SHIPS, which is what a receiver
        // built on ironauth-jose would use: it skips any JWK it cannot turn into a usable
        // public key and never trusts a malformed one, so an empty result is fail-closed.
        let keys = trusted_keys_from_jwks(body.as_bytes());
        assert!(
            !keys.is_empty(),
            "the published JWKS carries no key this receiver can use: {body}"
        );
        Self {
            issuer,
            keys,
            seen: Arc::new(Mutex::new(Vec::new())),
            verdicts: Arc::new(Mutex::new(Vec::new())),
            tokens: Arc::new(Mutex::new(Vec::new())),
            outage: Arc::new(Mutex::new(0)),
        }
    }

    /// Take delivery of one SET, exactly as a receiver would.
    fn accept(&self, set: &str) -> Verdict {
        self.tokens
            .lock()
            .expect("not poisoned")
            .push(set.to_owned());
        let verdict = self.judge(set);
        self.verdicts
            .lock()
            .expect("not poisoned")
            .push(verdict.clone());
        verdict
    }

    fn judge(&self, set: &str) -> Verdict {
        let Some(header) = set.split('.').next().and_then(|segment| {
            URL_SAFE_NO_PAD
                .decode(segment)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        }) else {
            return Verdict::Refused("the token is not a compact JWS".to_owned());
        };
        if header["kid"].as_str().is_none() {
            return Verdict::Refused("no kid, so no key can be selected".to_owned());
        }
        // A SET CARRIES NO `exp` (SSF 1.0 section 4.1.7), and `secevent+jwt` is REQUIRED. Every
        // other check stays on: the signature, the algorithm, the issuer, the audience.
        // EVERY PUBLISHED KEY IS OFFERED, and the verifier selects. A receiver holding a JWKS
        // does not know which key signed a token before it looks, so narrowing to one here
        // would be testing a shortcut this receiver does not have.
        let policy = VerificationPolicy::new(
            vec![JwsAlgorithm::EdDsa],
            self.keys.clone(),
            self.issuer.clone(),
            AUDIENCE.to_owned(),
            ExpectedTyp::Required(TokenTyp::SecurityEventToken),
        )
        .expect("a verification policy")
        .allow_absent_exp(true);
        let clock = ironauth_env::Env::system();
        let Ok(verified) = verify(set, &policy, clock.clock()) else {
            return Verdict::Refused("the signature or the claims did not verify".to_owned());
        };
        let claims = verified.claims();
        let Some(jti) = claims.get("jti").and_then(serde_json::Value::as_str) else {
            return Verdict::Refused("no jti, so this cannot be deduplicated".to_owned());
        };
        if claims.get("sub_id").is_none() {
            return Verdict::Refused("no top-level sub_id".to_owned());
        }
        let mut seen = self.seen.lock().expect("not poisoned");
        if seen.iter().any(|known| known == jti) {
            return Verdict::Duplicate(jti.to_owned());
        }
        seen.push(jti.to_owned());
        Verdict::Accepted(jti.to_owned())
    }

    /// Refuse the next `attempts` push deliveries, as an outage would.
    fn go_down_for(&self, attempts: u32) {
        *self.outage.lock().expect("not poisoned") = attempts;
    }

    fn accepted(&self) -> Vec<String> {
        self.verdicts
            .lock()
            .expect("not poisoned")
            .iter()
            .filter_map(|verdict| match verdict {
                Verdict::Accepted(jti) => Some(jti.clone()),
                _ => None,
            })
            .collect()
    }

    /// Every token this receiver was handed, in order, byte for byte.
    fn tokens(&self) -> Vec<String> {
        self.tokens.lock().expect("not poisoned").clone()
    }

    /// Every `jti` this receiver was handed, in order, redeliveries included.
    fn handled(&self) -> Vec<String> {
        self.verdicts
            .lock()
            .expect("not poisoned")
            .iter()
            .filter_map(|verdict| match verdict {
                Verdict::Accepted(jti) | Verdict::Duplicate(jti) => Some(jti.clone()),
                Verdict::Refused(_) => None,
            })
            .collect()
    }

    fn refusals(&self) -> Vec<String> {
        self.verdicts
            .lock()
            .expect("not poisoned")
            .iter()
            .filter_map(|verdict| match verdict {
                Verdict::Refused(why) => Some(why.clone()),
                _ => None,
            })
            .collect()
    }
}

/// The receiver IS the push endpoint, so a delivery reaches the same validator a poll does.
impl SsfPushSender for Receiver {
    async fn push(&self, _url: &str, _bearer: Option<&str>, set: &str) -> PushOutcome {
        // VALIDATED FIRST, EVEN WHILE DOWN. An earlier version returned the 503 before
        // looking at the token, so every refused attempt went unseen and the module header's
        // claim that every SET here is validated was false. It also let an outage HIDE a
        // transmitter that changed the token between attempts, because the test only ever
        // saw the last one.
        //
        // A receiver failing for its own reasons has still RECEIVED the bytes, so recording
        // them and then refusing is the more faithful model as well as the more testable one.
        let verdict = self.accept(set);
        let mut outage = self.outage.lock().expect("not poisoned");
        if *outage > 0 {
            *outage -= 1;
            drop(outage);
            // 503: the transmitter must treat this as transient and come back.
            return PushOutcome::failed(Some(503), SendFailure::Status(503));
        }
        drop(outage);
        match verdict {
            Verdict::Accepted(_) | Verdict::Duplicate(_) => PushOutcome::accepted(202),
            Verdict::Refused(_) => PushOutcome::failed(Some(400), SendFailure::Status(400)),
        }
    }
}

async fn patch(harness: &Harness, uri: &str, auth: &str, body: String) -> (StatusCode, String) {
    let request = Request::builder()
        .method("PATCH")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, auth)
        .body(Body::from(body))
        .expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

async fn get_with_auth(harness: &Harness, uri: &str, auth: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

/// Read one stream as its receiver.
async fn read_stream(
    harness: &Harness,
    auth: &str,
    streams: &str,
    stream_id: &str,
) -> serde_json::Value {
    let (status, text) =
        get_with_auth(harness, &format!("{streams}?stream_id={stream_id}"), auth).await;
    assert_eq!(status, StatusCode::OK, "read the stream: {text}");
    serde_json::from_str(&text).expect("a stream object")
}

async fn get(harness: &Harness, uri: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

async fn post(harness: &Harness, uri: &str, auth: &str, body: String) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, auth)
        .body(Body::from(body))
        .expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

async fn provision_envelope(harness: &Harness, env: &ironauth_env::Env) {
    let acting = harness
        .db()
        .store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(env), CorrelationId::generate(env));
    for outcome in [
        acting
            .envelope()
            .provision_kek(env, &harness.db().master_key())
            .await
            .map(|_| ()),
        acting
            .envelope()
            .provision_dek(env, &harness.db().master_key())
            .await
            .map(|_| ()),
    ] {
        match outcome {
            Ok(()) | Err(StoreError::Conflict) => {}
            Err(error) => panic!("provision the scope keys: {error:?}"),
        }
    }
}

async fn seed_stream(harness: &Harness, client: &ClientId, delivery: SsfDelivery) -> SsfStreamId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    provision_envelope(harness, &env).await;
    let id = SsfStreamId::generate(&env, &scope);
    let audience = vec![AUDIENCE.to_owned()];
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
                delivery: &delivery,
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
        .expect("seed a stream");
    id
}

/// Ask the transmitter for a verification event on `stream`.
async fn request_verification(harness: &Harness, auth: &str, stream: &SsfStreamId) -> StatusCode {
    let scope = harness.scope();
    let (status, _) = post(
        harness,
        &format!("/t/{}/e/{}/ssf/verify", scope.tenant(), scope.environment()),
        auth,
        serde_json::json!({ "stream_id": stream.to_string() }).to_string(),
    )
    .await;
    status
}

/// Run the push worker until it has nothing left it can deliver. Returns attempts made.
async fn drain_push(harness: &Harness, receiver: &Receiver, rounds: usize) -> usize {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let consumer = SsfPushConsumer::new(
        harness.db().store().clone(),
        harness.db().master_key(),
        receiver.clone(),
    );
    let mut attempts = 0;
    for _ in 0..rounds {
        let claimed = harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                SSF_PUSH_CONSUMER,
                std::time::Duration::from_secs(30),
                10,
            )
            .await
            .expect("claim");
        if claimed.is_empty() {
            break;
        }
        for message in &claimed {
            attempts += 1;
            let store = harness.db().store().clone();
            let queue = store.scoped(scope);
            let queue = queue.outbox();
            match consumer.handle(&env, scope, message).await {
                Ok(()) => {
                    queue.complete(&env, message).await.expect("complete");
                }
                // THE FAILURE IS RECORDED, which an earlier version of this drain skipped.
                // `fail` is where the attempt counter, the backoff and the dead-letter
                // decision live, so a drain that only ever completed was re-claiming a
                // message the queue did not know had failed: `retryable` and `permanent` had
                // no observable difference, and the outage test wound back a backoff that
                // had never been set.
                Err(error) => {
                    let outcome = queue
                        .fail(&env, message, error.label(), RetryPolicy::default())
                        .await
                        .expect("record the failure");
                    // A DEAD LETTER IS THE END. The caller has to be able to see it, or a
                    // test asserting the event survived would loop instead of failing.
                    if matches!(outcome, FailureOutcome::DeadLettered { .. }) {
                        return attempts;
                    }
                }
            }
        }
    }
    attempts
}

/// The receiver provisions its own stream over HTTP: create, read, update, delete.
///
/// CRITERION 1 SAYS "STREAM CRUD ... EXERCISED BY AN IN-REPO RECEIVER CONFORMANCE FIXTURE",
/// and the other tests here seed their stream through the STORE, which is a shortcut no
/// receiver has. This one uses the endpoints, in the order a receiver would: create, read back
/// what was created, change what SSF lets it change, and delete.
///
/// THE READ-BACK IS THE POINT of the first half. A create that answers 201 with a body it
/// invented, while storing something else, is green to a test that only checks the response.
#[tokio::test]
async fn a_receiver_provisions_its_own_stream_over_http() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    provision_envelope(&harness, &harness.state().env().clone()).await;
    let scope = harness.scope();
    let streams = format!(
        "/t/{}/e/{}/ssf/streams",
        scope.tenant(),
        scope.environment()
    );

    // CREATE
    let (status, text) = post(
        &harness,
        &streams,
        &auth,
        serde_json::json!({
            "delivery": { "method": "urn:ietf:rfc:8936" },
            "events_requested": [],
            "aud": [AUDIENCE],
            "format": "iss_sub",
            "description": "the receiver's own label",
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    let created: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    let stream_id = created["stream_id"].as_str().expect("stream_id").to_owned();

    // READ, and it must agree with what the create returned.
    let (status, text) = get(&harness, &format!("{streams}?stream_id={stream_id}")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an uncredentialed read answered: {text}"
    );
    let read_back = read_stream(&harness, &auth, &streams, &stream_id).await;
    assert_eq!(
        read_back, created,
        "the create returned a configuration the store does not hold"
    );

    // UPDATE, one receiver-supplied property, and the rest must survive it.
    let (status, text) = patch(
        &harness,
        &streams,
        &auth,
        serde_json::json!({
            "stream_id": stream_id,
            "description": "renamed by its receiver",
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let updated: serde_json::Value = serde_json::from_str(&text).expect("a stream object");
    assert_eq!(
        updated["description"],
        serde_json::json!("renamed by its receiver")
    );
    assert_eq!(
        updated["delivery"], created["delivery"],
        "an update naming only the description changed the delivery"
    );

    // AND IT IS DELIVERABLE AFTER THE ROUND TRIP, which is what makes CRUD worth testing from
    // here rather than from a suite that only reads the store: a configuration surviving
    // create-read-update and then unable to carry an event is still broken.
    assert_provisioned_stream_delivers(&harness, &auth, &stream_id).await;

    // DELETE, and it is gone for good.
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("{streams}?stream_id={stream_id}"))
        .header(header::AUTHORIZATION, &auth)
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    let (status, text) =
        get_with_auth(&harness, &format!("{streams}?stream_id={stream_id}"), &auth).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deleted stream is still readable: {text}"
    );
}

/// Ask for a verification event on a stream named by handle, collect it, and require a
/// freshly bootstrapped receiver to accept it.
async fn assert_provisioned_stream_delivers(harness: &Harness, auth: &str, stream_id: &str) {
    let scope = harness.scope();
    let id = SsfStreamId::parse_in_scope(stream_id, &scope).expect("the handle parses");
    let receiver = Receiver::bootstrap(harness).await;
    assert_eq!(
        request_verification(harness, auth, &id).await,
        StatusCode::NO_CONTENT
    );
    let (status, text) = post(
        harness,
        &format!(
            "/t/{}/e/{}/ssf/poll/{stream_id}",
            scope.tenant(),
            scope.environment()
        ),
        auth,
        r#"{"maxEvents":10,"returnImmediately":true}"#.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let page: serde_json::Value = serde_json::from_str(&text).expect("a poll document");
    let set = page["sets"]
        .as_object()
        .expect("sets")
        .values()
        .next()
        .expect("one SET")
        .as_str()
        .expect("a compact JWS")
        .to_owned();
    assert!(
        matches!(receiver.accept(&set), Verdict::Accepted(_)),
        "the stream the receiver provisioned could not carry an event: {:?}",
        receiver.refusals()
    );
}

/// A push receiver bootstraps, is verified, and validates what arrives.
///
/// THE WHOLE PATH, and every step is one a real receiver takes: read the configuration
/// document, fetch the advertised JWKS, ask for a verification event, take delivery, and verify
/// the token against the key the transmitter published rather than one handed over in-process.
#[tokio::test]
async fn a_push_receiver_bootstraps_and_verifies_what_it_is_sent() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let receiver = Receiver::bootstrap(&harness).await;
    let stream = seed_stream(
        &harness,
        &client,
        SsfDelivery::Push {
            endpoint_url: "https://receiver.example.com/events".to_owned(),
            secret_name: None,
        },
    )
    .await;

    assert_eq!(
        request_verification(&harness, &auth, &stream).await,
        StatusCode::NO_CONTENT
    );
    let attempts = drain_push(&harness, &receiver, 5).await;
    assert_eq!(attempts, 1, "the worker made more attempts than it needed");
    assert_eq!(
        receiver.accepted().len(),
        1,
        "the receiver did not accept the verification event: {:?}",
        receiver.refusals()
    );
}

/// A receiver that is DOWN loses nothing: the transmitter comes back.
///
/// THE OUTAGE CRITERION. #143 asks that push delivery "retries through receiver outages and
/// resumes without event loss". The receiver refuses three attempts with a 503, which RFC 8935
/// makes transient, and the fourth succeeds; the SET that arrives is the one that was queued
/// before the outage began.
#[tokio::test]
async fn a_receiver_outage_delays_delivery_and_loses_nothing() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let receiver = Receiver::bootstrap(&harness).await;
    let stream = seed_stream(
        &harness,
        &client,
        SsfDelivery::Push {
            endpoint_url: "https://receiver.example.com/events".to_owned(),
            secret_name: None,
        },
    )
    .await;

    receiver.go_down_for(3);
    assert_eq!(
        request_verification(&harness, &auth, &stream).await,
        StatusCode::NO_CONTENT
    );

    // TIME IS WOUND BACK RATHER THAN WAITED OUT. Each refusal records a real failure, which
    // sets a backoff the worker would otherwise sleep through and releases the lease; clearing
    // the gate is what a later wall clock would do. What is proven is that the message SURVIVES
    // the refusals, not how long the worker sleeps.
    //
    // `TIMESTAMPTZ 'epoch'` AND NOT `now()`, which is the detail worth recording: `claim`
    // compares `next_attempt_at` against the APPLICATION clock, not the database's, so a row
    // dated from `now()` sits in the future of a harness whose clock is not wall time and is
    // never eligible again. Measured: the first version used `now()` and the worker made
    // exactly one attempt.
    let mut attempts = drain_push(&harness, &receiver, 1).await;
    for _ in 0..3 {
        harness
            .db()
            .execute_owner_sql(
                "UPDATE outbox_messages \
                 SET next_attempt_at = TIMESTAMPTZ 'epoch' \
                 WHERE completed_at IS NULL AND dead_lettered_at IS NULL",
            )
            .await;
        attempts += drain_push(&harness, &receiver, 1).await;
    }
    assert_eq!(
        attempts, 4,
        "the worker did not keep trying through the outage"
    );
    assert_eq!(
        *receiver.outage.lock().expect("not poisoned"),
        0,
        "the outage was not exhausted, so fewer attempts were made than this test intends"
    );

    // THE RECEIVER SAW ALL FOUR, because it validates before it decides whether it is up. That
    // is what lets the next assertion be about IDENTITY rather than merely about arrival.
    let handled = receiver.handled();
    assert_eq!(
        handled.len(),
        4,
        "the receiver did not see every delivery attempt: {handled:?}"
    );

    // AND ALL FOUR WERE THE SAME EVENT. This is the assertion the test's name promises and the
    // one an "it arrived" check cannot make: a transmitter that minted a fresh `jti` per
    // attempt would deliver something after the outage and still have lost the original, and
    // the receiver would have no way to connect the two.
    assert!(
        handled.windows(2).all(|pair| pair[0] == pair[1]),
        "the attempts carried different events, so the one queued before the outage was not \
         the one delivered after it: {handled:?}"
    );

    // AND BYTE FOR BYTE THE SAME TOKEN, which the `jti` comparison above cannot see (issue
    // #1200). The consumer used to mint on every attempt, so a retry re-sent a DIFFERENT token
    // under the same `jti`: a fresh `iat`, and a fresh signature for any algorithm that is not
    // deterministic. A receiver that caches by `jti` and compares what it was sent -- which is
    // the dedup strategy 0217 assumes for poll -- would see two tokens claiming to be one
    // event and have no way to explain the difference.
    let tokens = receiver.tokens();
    assert_eq!(tokens.len(), 4, "the receiver did not see four deliveries");
    assert!(
        tokens.windows(2).all(|pair| pair[0] == pair[1]),
        "the retries re-signed the event instead of re-sending it: the four deliveries carry \
         {} distinct tokens",
        tokens
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    assert_eq!(
        receiver.accepted().len(),
        1,
        "the event did not survive the outage exactly once: {:?}",
        receiver.refusals()
    );
}

/// A poll receiver collects, validates, acknowledges, and is not given it twice.
#[tokio::test]
async fn a_poll_receiver_collects_validates_and_acknowledges() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let receiver = Receiver::bootstrap(&harness).await;
    let stream = seed_stream(&harness, &client, SsfDelivery::Poll).await;
    assert_eq!(
        request_verification(&harness, &auth, &stream).await,
        StatusCode::NO_CONTENT
    );

    let scope = harness.scope();
    let poll_uri = format!(
        "/t/{}/e/{}/ssf/poll/{stream}",
        scope.tenant(),
        scope.environment()
    );

    // COLLECT WITHOUT ACKNOWLEDGING, then collect again: RFC 8936 redelivers, and the receiver
    // must see the SAME event rather than a second one.
    let (status, body) = post(
        &harness,
        &poll_uri,
        &auth,
        r#"{"maxEvents":10,"returnImmediately":true}"#.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let first: serde_json::Value = serde_json::from_str(&body).expect("a poll document");
    let sets = first["sets"].as_object().expect("sets");
    assert_eq!(sets.len(), 1, "nothing was owed: {body}");
    let (jti, token) = sets.iter().next().expect("one SET");
    let first_verdict = receiver.accept(token.as_str().expect("a compact JWS"));
    assert!(
        matches!(&first_verdict, Verdict::Accepted(accepted) if accepted == jti),
        "the receiver refused the first delivery: {first_verdict:?}"
    );

    let (status, body) = post(
        &harness,
        &poll_uri,
        &auth,
        r#"{"maxEvents":10,"returnImmediately":true}"#.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second: serde_json::Value = serde_json::from_str(&body).expect("a poll document");
    assert_eq!(
        second["sets"], first["sets"],
        "an unacknowledged SET came back different, so a receiver comparing two deliveries of \
         one event sees a difference it cannot explain"
    );
    let redelivered = receiver.accept(
        second["sets"][jti]
            .as_str()
            .expect("the same SET, byte for byte"),
    );
    assert_eq!(
        redelivered,
        Verdict::Duplicate(jti.clone()),
        "the receiver could not tell a redelivery from a new event"
    );

    // ACKNOWLEDGE, and it is gone.
    let ack =
        serde_json::json!({ "maxEvents": 10, "returnImmediately": true, "ack": [jti] }).to_string();
    let (status, body) = post(&harness, &poll_uri, &auth, ack).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after: serde_json::Value = serde_json::from_str(&body).expect("a poll document");
    assert!(
        after["sets"].as_object().expect("sets").is_empty(),
        "an acknowledged SET was handed over again: {body}"
    );
    assert_eq!(receiver.refusals(), Vec::<String>::new());
}

/// A paused stream holds what it cannot deliver, and the receiver gets it on resume.
///
/// The status criterion, read from the receiver's side: 0216 defines `paused` as the state that
/// RETAINS, and the only way to know it does is to resume and be given the event.
#[tokio::test]
async fn a_paused_stream_delivers_on_resume_and_the_receiver_sees_one_event() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let receiver = Receiver::bootstrap(&harness).await;
    let stream = seed_stream(&harness, &client, SsfDelivery::Poll).await;
    assert_eq!(
        request_verification(&harness, &auth, &stream).await,
        StatusCode::NO_CONTENT
    );

    let env = harness.state().env().clone();
    let write = harness
        .db()
        .store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env));
    write
        .ssf_streams()
        .set_status(&env, &stream, &client, SsfStreamStatus::Paused, None)
        .await
        .expect("pause");

    let scope = harness.scope();
    let poll_uri = format!(
        "/t/{}/e/{}/ssf/poll/{stream}",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = post(
        &harness,
        &poll_uri,
        &auth,
        r#"{"maxEvents":10,"returnImmediately":true}"#.to_owned(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a paused stream served a poll: {body}"
    );

    write
        .ssf_streams()
        .set_status(&env, &stream, &client, SsfStreamStatus::Enabled, None)
        .await
        .expect("resume");
    let (status, body) = post(
        &harness,
        &poll_uri,
        &auth,
        r#"{"maxEvents":10,"returnImmediately":true}"#.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resumed: serde_json::Value = serde_json::from_str(&body).expect("a poll document");
    let sets = resumed["sets"].as_object().expect("sets");
    assert_eq!(
        sets.len(),
        1,
        "the pause lost the event it was documented to retain: {body}"
    );
    let verdict = receiver.accept(
        sets.values()
            .next()
            .expect("one SET")
            .as_str()
            .expect("jws"),
    );
    assert!(
        matches!(verdict, Verdict::Accepted(_)),
        "the receiver refused the retained event: {verdict:?}"
    );
}

/// The receiver refuses a SET whose signature does not check out.
///
/// THE FIXTURE HAS TO BE ABLE TO SAY NO, or every assertion above it is a tautology.
///
/// WHAT IT IS HANDED, precisely: the genuine token with one bit flipped in its SIGNATURE. The
/// header and payload are untouched, so it names a `kid` the JWKS DOES publish and parses like
/// any other SET; only the signature check can refuse it. That is the narrowest mutation that
/// still reaches the verification, which is what makes it a control rather than a smoke test.
///
/// An earlier version of this comment described the same token three different and mutually
/// contradictory ways: as coming from another environment, as naming an unpublished key, and
/// as carrying "the signature of a different token". It is none of those.
#[tokio::test]
async fn the_fixture_refuses_a_set_whose_signature_does_not_verify() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let receiver = Receiver::bootstrap(&harness).await;
    let stream = seed_stream(&harness, &client, SsfDelivery::Poll).await;
    assert_eq!(
        request_verification(&harness, &auth, &stream).await,
        StatusCode::NO_CONTENT
    );

    let scope = harness.scope();
    let (status, body) = post(
        &harness,
        &format!(
            "/t/{}/e/{}/ssf/poll/{stream}",
            scope.tenant(),
            scope.environment()
        ),
        &auth,
        r#"{"maxEvents":10,"returnImmediately":true}"#.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("a poll document");
    let genuine = doc["sets"]
        .as_object()
        .expect("sets")
        .values()
        .next()
        .expect("one SET")
        .as_str()
        .expect("a compact JWS")
        .to_owned();

    // The real one is accepted, which is the control.
    assert!(matches!(receiver.accept(&genuine), Verdict::Accepted(_)));

    // ONE BIT, in the signature. Well formed, and it names a published kid, so the only check
    // that can refuse it is the signature.
    let mut parts = genuine.split('.');
    let head = parts.next().expect("header");
    let payload = parts.next().expect("payload");
    let signature = parts.next().expect("signature");
    let mut raw = URL_SAFE_NO_PAD.decode(signature).expect("base64url");
    raw[0] ^= 0x01;
    let forged = format!("{head}.{payload}.{}", URL_SAFE_NO_PAD.encode(&raw));
    let verdict = receiver.accept(&forged);
    assert!(
        matches!(verdict, Verdict::Refused(_)),
        "the fixture accepted a token this transmitter did not sign, so every acceptance above \
         proves nothing: {verdict:?}"
    );
}
