// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8935 push delivery (issue #143).
//!
//! # What this owes
//!
//! #143's acceptance criterion is that push delivery "retries through receiver outages and
//! resumes without event loss". Two halves, and the second is the one a boolean would miss:
//!
//! - a receiver that is down produces a RETRYABLE failure, not a dropped message and not a
//!   dead letter;
//! - when it comes back, the SAME token arrives. The `jti` lives on the message's immutable
//!   payload, so a receiver's dedup works across the outage rather than seeing one event twice
//!   under two identities. `an_outage_retries_and_the_receiver_gets_the_same_token` asserts on
//!   the `jti` of both attempts, which is the assertion that separates "it retried" from "it
//!   retried with the same event".
//!
//! Nothing here touches a socket: `SsfPushSender` is the one outbound seam and every test
//! substitutes a recording implementation for it.

#![cfg(feature = "testing")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Harness;
use ironauth_oidc::SendFailure;
use ironauth_oidc::ssf_push::{
    PushOutcome, QueuedPush, SsfPushConsumer, SsfPushSender, enqueue_push,
};
use ironauth_oidc::ssf_set::{SecurityEvent, SubjectIdentifier};
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::{
    ClientId, CorrelationId, NewSsfStream, SSF_PUSH_CONSUMER, Scope, SsfDelivery, SsfStreamId,
    SsfSubjectFormat, Store,
};

const EVENT_TYPE: &str = "https://example.test/event-type/probe";

/// What one attempt handed the seam.
#[derive(Debug, Clone)]
struct Sent {
    url: String,
    bearer: Option<String>,
    set: String,
}

/// A sender that records and answers from a programmable script, never a socket.
///
/// CLONE over shared state rather than an `Arc<RecordingSender>`: the consumer takes its sender
/// by value, and `impl SsfPushSender for Arc<..>` is not allowed here (the outermost type is
/// foreign). A clone shares both handles, so the test reads what the consumer sent.
#[derive(Clone, Default)]
struct RecordingSender {
    sent: Arc<Mutex<Vec<Sent>>>,
    outcomes: Arc<Mutex<Vec<PushOutcome>>>,
}

impl RecordingSender {
    fn answering(outcomes: Vec<PushOutcome>) -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            outcomes: Arc::new(Mutex::new(outcomes)),
        }
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().expect("not poisoned").clone()
    }
}

impl SsfPushSender for RecordingSender {
    async fn push(&self, url: &str, bearer: Option<&str>, set: &str) -> PushOutcome {
        self.sent.lock().expect("not poisoned").push(Sent {
            url: url.to_owned(),
            bearer: bearer.map(ToOwned::to_owned),
            set: set.to_owned(),
        });
        let mut outcomes = self.outcomes.lock().expect("not poisoned");
        if outcomes.is_empty() {
            PushOutcome::accepted(202)
        } else {
            outcomes.remove(0)
        }
    }
}

/// The `jti` a delivered SET carries, read out of its payload.
fn jti_of(set: &str) -> String {
    use base64::Engine;
    let payload = set
        .split('.')
        .nth(1)
        .expect("a compact JWS has three parts");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url");
    serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")["jti"]
        .as_str()
        .expect("jti")
        .to_owned()
}

async fn seed_stream(harness: &Harness, client: &ClientId, delivery: SsfDelivery) -> SsfStreamId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let id = SsfStreamId::generate(&env, &scope);
    let audience = vec!["https://receiver.example.com".to_owned()];
    let events: Vec<String> = Vec::new();
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
                events_requested: &events,
                events_delivered: &events,
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

fn push_stream() -> SsfDelivery {
    SsfDelivery::Push {
        endpoint_url: "https://receiver.example.com/events".to_owned(),
        secret_name: None,
    }
}

fn subject() -> SubjectIdentifier {
    SubjectIdentifier::IssSub {
        iss: "https://issuer.test".to_owned(),
        sub: "usr_alice".to_owned(),
    }
}

fn event() -> SecurityEvent {
    SecurityEvent {
        event_type: EVENT_TYPE.to_owned(),
        payload: serde_json::Map::from_iter([(
            "reason".to_owned(),
            serde_json::Value::String("probe".to_owned()),
        )]),
    }
}

/// Queue one SET and claim it back off the outbox, ready to hand to a consumer.
///
/// ONE PER STREAM PER TEST. The outbox serialises an ordering key: a second message on a stream
/// is not claimable until the first is COMPLETED, and a test that handles rather than completes
/// leaves it in flight. A case that needs two messages needs two streams -- which is also the
/// realistic shape, since the ordering key is the stream precisely so two receivers cannot
/// block each other.
async fn queue_one(
    store: &Store,
    harness: &Harness,
    stream: &SsfStreamId,
    jti: &str,
) -> ironauth_store::OutboxMessage {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let queued = enqueue_push(
        store,
        &env,
        scope,
        &QueuedPush {
            stream_id: stream,
            jti,
            subject: &subject(),
            event: &event(),
        },
    )
    .await
    .expect("enqueue");
    assert!(
        queued,
        "the first enqueue of a (stream, jti) is not a duplicate"
    );
    let mut claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, SSF_PUSH_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "one queued push");
    claimed.remove(0)
}

fn consumer<S: SsfPushSender>(harness: &Harness, sender: S) -> SsfPushConsumer<S> {
    SsfPushConsumer::new(
        harness.db().store().clone(),
        Arc::clone(harness.state().issuers()),
        harness.db().master_key(),
        sender,
    )
}

#[tokio::test]
async fn a_queued_set_reaches_the_receivers_endpoint_as_a_secevent() {
    let harness = Harness::start_store_backed().await;
    let scope: Scope = harness.scope();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let stream = seed_stream(&harness, &client, push_stream()).await;
    let store = harness.db().store().clone();
    let message = queue_one(&store, &harness, &stream, "evt_first").await;

    let sender = RecordingSender::default();
    let pusher = consumer(&harness, sender.clone());
    pusher
        .handle(harness.state().env(), scope, &message)
        .await
        .expect("the receiver accepted it");

    let sent = sender.sent();
    assert_eq!(sent.len(), 1, "one POST");
    assert_eq!(sent[0].url, "https://receiver.example.com/events");
    assert_eq!(sent[0].bearer, None, "no bearer was named on this stream");
    assert_eq!(jti_of(&sent[0].set), "evt_first");
}

#[tokio::test]
async fn an_outage_retries_and_the_receiver_gets_the_same_token() {
    // #143's criterion, both halves. The receiver is down, so the attempt must be RETRYABLE --
    // not dropped and not dead-lettered. Then it comes back, and what arrives is the SAME
    // token: the `jti` lives on the message's immutable payload, so the receiver's dedup works
    // across the outage instead of seeing one event under two identities.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let stream = seed_stream(&harness, &client, push_stream()).await;
    let store = harness.db().store().clone();
    let message = queue_one(&store, &harness, &stream, "evt_outage").await;

    let sender = RecordingSender::answering(vec![PushOutcome::failed(
        Some(503),
        SendFailure::Status(503),
    )]);
    let pusher = consumer(&harness, sender.clone());

    let first = pusher
        .handle(harness.state().env(), scope, &message)
        .await
        .expect_err("a receiver answering 503 is a failure");
    assert!(
        first.is_retryable(),
        "a receiver outage must RETRY, not dead-letter: {}",
        first.label()
    );

    // The receiver is back. The SAME message is handled again, exactly as the worker would
    // hand it back after the backoff.
    let second = pusher.handle(harness.state().env(), scope, &message).await;
    assert!(second.is_ok(), "the retry was refused: {second:?}");

    let sent = sender.sent();
    assert_eq!(sent.len(), 2, "two attempts");
    assert_eq!(
        jti_of(&sent[0].set),
        jti_of(&sent[1].set),
        "the retry carried a DIFFERENT token, so the receiver cannot dedup it"
    );
    assert_eq!(jti_of(&sent[1].set), "evt_outage");
}

#[tokio::test]
async fn a_receiver_rejecting_the_set_is_permanent_but_asking_for_less_is_not() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let store = harness.db().store().clone();

    // A 400 is the receiver saying this SET is wrong, which no retry fixes.
    let rejecting = seed_stream(&harness, &client, push_stream()).await;
    let rejected = queue_one(&store, &harness, &rejecting, "evt_rejected").await;
    let sender = RecordingSender::answering(vec![PushOutcome::failed(
        Some(400),
        SendFailure::Status(400),
    )]);
    let error = consumer(&harness, sender.clone())
        .handle(harness.state().env(), scope, &rejected)
        .await
        .expect_err("a 400 is a failure");
    assert!(
        !error.is_retryable(),
        "a rejected SET must dead-letter rather than retry forever: {}",
        error.label()
    );

    // A 429 is the receiver asking for LESS, not saying no. Its own stream: see `queue_one`.
    let throttling = seed_stream(&harness, &client, push_stream()).await;
    let throttled = queue_one(&store, &harness, &throttling, "evt_throttled").await;
    let sender = RecordingSender::answering(vec![PushOutcome::failed(
        Some(429),
        SendFailure::Status(429),
    )]);
    let error = consumer(&harness, sender.clone())
        .handle(harness.state().env(), scope, &throttled)
        .await
        .expect_err("a 429 is a failure");
    assert!(
        error.is_retryable(),
        "a 429 asks for less; it must retry: {}",
        error.label()
    );
}

#[tokio::test]
async fn a_paused_stream_holds_its_events_and_a_disabled_one_does_not() {
    // The distinction the three statuses exist for, at the delivery layer: `paused` RETAINS, so
    // the queued event waits for the receiver to resume; `disabled` retains nothing, so holding
    // the message would be a queue that never drains.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let store = harness.db().store().clone();

    for (status, should_retry) in [
        (ironauth_store::SsfStreamStatus::Paused, true),
        (ironauth_store::SsfStreamStatus::Disabled, false),
    ] {
        // A STREAM EACH: see `queue_one`.
        let stream = seed_stream(&harness, &client, push_stream()).await;
        store
            .scoped(scope)
            .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
            .ssf_streams()
            .set_status(&env, &stream, &client, status, None)
            .await
            .expect("set the status");
        let message = queue_one(
            &store,
            &harness,
            &stream,
            &format!("evt_{}", status.as_str()),
        )
        .await;
        let sender = RecordingSender::default();
        let error = consumer(&harness, sender.clone())
            .handle(&env, scope, &message)
            .await
            .expect_err("a non-delivering stream does not deliver");
        assert_eq!(
            error.is_retryable(),
            should_retry,
            "{}: retryable was {} ({})",
            status.as_str(),
            error.is_retryable(),
            error.label()
        );
        assert!(
            sender.sent().is_empty(),
            "{}: something was POSTed anyway",
            status.as_str()
        );
    }
}

#[tokio::test]
async fn a_deleted_stream_stops_delivery_rather_than_retrying_forever() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let stream = seed_stream(&harness, &client, push_stream()).await;
    let store = harness.db().store().clone();
    let message = queue_one(&store, &harness, &stream, "evt_orphan").await;

    store
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .delete(&env, &stream, &client)
        .await
        .expect("the receiver deleted its stream");

    let sender = RecordingSender::default();
    let error = consumer(&harness, sender.clone())
        .handle(&env, scope, &message)
        .await
        .expect_err("there is nowhere to deliver");
    assert!(
        !error.is_retryable(),
        "a deleted stream is not a transient fault: {}",
        error.label()
    );
    assert!(sender.sent().is_empty(), "it POSTed to a deleted stream");
}

#[tokio::test]
async fn a_poll_stream_is_never_pushed_to() {
    // A poll receiver COLLECTS. A push queued for one is a producer bug, and delivering it
    // anywhere would be worse than refusing.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let stream = seed_stream(&harness, &client, SsfDelivery::Poll).await;
    let store = harness.db().store().clone();
    let message = queue_one(&store, &harness, &stream, "evt_poll").await;

    let sender = RecordingSender::default();
    let error = consumer(&harness, sender.clone())
        .handle(harness.state().env(), scope, &message)
        .await
        .expect_err("a poll stream is not pushed to");
    assert!(!error.is_retryable(), "{}", error.label());
    assert!(sender.sent().is_empty(), "it POSTed to a poll stream");
}

#[tokio::test]
async fn one_event_for_one_receiver_is_queued_once() {
    // At-least-once delivery is safe for a receiver only because a redelivery is detectable,
    // and the second enqueue of one (stream, jti) is a no-op rather than a second message.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let stream = seed_stream(&harness, &client, push_stream()).await;
    let store = harness.db().store().clone();

    let queued = |jti: &'static str| {
        let store = store.clone();
        let env = env.clone();
        async move {
            enqueue_push(
                &store,
                &env,
                scope,
                &QueuedPush {
                    stream_id: &stream,
                    jti,
                    subject: &subject(),
                    event: &event(),
                },
            )
            .await
            .expect("enqueue")
        }
    };

    assert!(queued("evt_once").await, "the first is new");
    assert!(!queued("evt_once").await, "the second is a duplicate");
    assert!(queued("evt_twice").await, "a different event is not");

    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, SSF_PUSH_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    // ONE, not two: the outbox serialises a stream's messages, which is the per-receiver
    // ordering this design relies on.
    assert_eq!(claimed.len(), 1, "a stream's events do not go out together");
}

#[tokio::test]
async fn a_credential_outside_the_namespace_is_never_opened_or_sent() {
    // THE READ-SIDE FENCE, which is the one that matters. `delivery.authorization_secret_name`
    // comes from the RECEIVER and this worker opens it and presents it as a Bearer to a URL the
    // same receiver chose, so without a namespace it is a read primitive for every secret in
    // the environment. The create door refuses a name outside `ssf::PUSH_SECRET_PREFIX` -- but
    // a row written before that rule, or restored by a config import, never passed the door,
    // which is why the check is here too. This test writes such a row DIRECTLY through the
    // store, which is exactly the shape the door cannot see.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let stream = seed_stream(
        &harness,
        &client,
        SsfDelivery::Push {
            endpoint_url: "https://receiver.example.com/events".to_owned(),
            // The LDAP bind password's namespace, not this one.
            secret_name: Some("ldap_bind_corp".to_owned()),
        },
    )
    .await;
    let store = harness.db().store().clone();
    let message = queue_one(&store, &harness, &stream, "evt_exfil").await;

    let sender = RecordingSender::default();
    let error = consumer(&harness, sender.clone())
        .handle(&env, scope, &message)
        .await
        .expect_err("a credential outside the namespace must not be opened");
    assert!(
        !error.is_retryable(),
        "no amount of waiting makes the name legal: {}",
        error.label()
    );
    assert_eq!(error.label(), "push_secret_outside_namespace");
    // AND NOTHING WENT OUT. The assertion that matters: not merely that the attempt failed, but
    // that no POST carrying anything reached the receiver's address.
    assert!(
        sender.sent().is_empty(),
        "it POSTed to the receiver anyway: {:?}",
        sender.sent()
    );
}

#[tokio::test]
async fn a_named_credential_inside_the_namespace_is_presented_as_a_bearer() {
    // The other side of the fence: a legal name IS opened and presented, so the refusal above
    // is a namespace check rather than the feature being broken.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(
            &env,
            &harness.db().master_key(),
            &format!("ssf_push_{client}_receiver"),
            b"the-receivers-bearer",
            None,
        )
        .await
        .expect("store the receiver's credential");

    let stream = seed_stream(
        &harness,
        &client,
        SsfDelivery::Push {
            endpoint_url: "https://receiver.example.com/events".to_owned(),
            secret_name: Some(format!("ssf_push_{client}_receiver")),
        },
    )
    .await;
    let store = harness.db().store().clone();
    let message = queue_one(&store, &harness, &stream, "evt_bearer").await;

    let sender = RecordingSender::default();
    consumer(&harness, sender.clone())
        .handle(&env, scope, &message)
        .await
        .expect("delivered");
    let sent = sender.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].bearer.as_deref(), Some("the-receivers-bearer"));
}

#[tokio::test]
async fn one_receiver_cannot_name_another_receivers_credential() {
    // The escape an environment-wide `ssf_push_` prefix would NOT have closed. Receiver A names
    // the secret receiver B registered, and without a per-receiver namespace this worker would
    // open B's bearer and POST it to A's endpoint.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let mine = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    let theirs = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0;
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(
            &env,
            &harness.db().master_key(),
            &format!("ssf_push_{theirs}_receiver"),
            b"the-other-receivers-bearer",
            None,
        )
        .await
        .expect("the other receiver's credential");

    // MY stream, naming THEIR credential. Written through the store, because the door refuses
    // it -- and the door is not the fence under test.
    let stream = seed_stream(
        &harness,
        &mine,
        SsfDelivery::Push {
            endpoint_url: "https://mine.example.com/events".to_owned(),
            secret_name: Some(format!("ssf_push_{theirs}_receiver")),
        },
    )
    .await;
    let store = harness.db().store().clone();
    let message = queue_one(&store, &harness, &stream, "evt_cross").await;

    let sender = RecordingSender::default();
    let error = consumer(&harness, sender.clone())
        .handle(&env, scope, &message)
        .await
        .expect_err("another receiver's credential must not be opened");
    assert_eq!(error.label(), "push_secret_outside_namespace");
    assert!(!error.is_retryable(), "{}", error.label());
    assert!(
        sender.sent().is_empty(),
        "it POSTed to my endpoint carrying their bearer: {:?}",
        sender.sent()
    );
}
