// SPDX-License-Identifier: MIT OR Apache-2.0

//! Webhook DISPATCH driven end to end against a real database (issue #105, slice 4).
//!
//! Every earlier slice could be proved in isolation. This one cannot: its whole job is to
//! join three things that were built separately, so the property worth pinning is that
//! they agree. A delivery signed by the consumer must verify under the secret the
//! MANAGEMENT API handed the operator at registration, which is only true if the seal in
//! migration 0111, the open in `delivery_target`, and the signing contract in
//! `ironauth_jose::webhooks` all line up. Any one of them drifting breaks this, and
//! nothing else in the tree would notice.
//!
//! The transport is the only thing stubbed. A recording sender captures what the consumer
//! decided to send, so the decisions ABOVE the socket (which secrets, which headers, which
//! bytes) are exercised for real rather than mocked out alongside the network.

mod common;

use std::future::Future;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use common::Harness;
use ironauth_admin::webhook_delivery::{
    DeliveryHeaders, DeliveryOutcome, WebhookDeliveryConsumer, WebhookReplayConsumer, WebhookSender,
};
use ironauth_env::Env;
use ironauth_jose::webhooks::{WebhookSecret, verify_delivery};
use ironauth_oidc::SendFailure;
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::{EnvironmentId, OutboxMessage, Scope, TenantId, WEBHOOK_DELIVERY_CONSUMER};
use serde_json::Value;

/// One captured delivery: everything the consumer decided, and nothing about the socket.
#[derive(Debug, Clone)]
struct Recorded {
    url: String,
    headers: DeliveryHeaders,
    body: String,
}

/// A sender that records instead of sending, and answers with a programmable outcome.
#[derive(Clone)]
struct RecordingSender {
    sent: Arc<Mutex<Vec<Recorded>>>,
    outcome: Option<SendFailure>,
}

impl RecordingSender {
    fn accepting() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            outcome: None,
        }
    }

    fn failing(outcome: SendFailure) -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            outcome: Some(outcome),
        }
    }

    fn recorded(&self) -> Vec<Recorded> {
        self.sent.lock().expect("recorder lock").clone()
    }
}

impl WebhookSender for RecordingSender {
    fn deliver(
        &self,
        url: &str,
        headers: &DeliveryHeaders,
        body: &str,
    ) -> impl Future<Output = DeliveryOutcome> + Send {
        self.sent.lock().expect("recorder lock").push(Recorded {
            url: url.to_owned(),
            headers: headers.clone(),
            body: body.to_owned(),
        });
        let outcome = self.outcome;
        async move {
            match outcome {
                // A programmed status is echoed back as the receiver's answer, so a test
                // asserting on the recorded history reads the code it asked for.
                Some(failure @ SendFailure::Status(status)) => {
                    DeliveryOutcome::failed(Some(status), failure)
                }
                Some(failure) => DeliveryOutcome::failed(None, failure),
                None => DeliveryOutcome::success(200),
            }
        }
    }
}

/// A message as the worker would hand it to the consumer: only the fields a consumer
/// reads carry meaning, and the lifecycle columns are the substrate's business.
fn queued(endpoint_id: &str, idempotency_key: &str, body: &Value) -> OutboxMessage {
    OutboxMessage {
        id: "obx_test".to_owned(),
        sequence: 1,
        consumer: WEBHOOK_DELIVERY_CONSUMER.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        ordering_key: endpoint_id.to_owned(),
        payload: serde_json::json!({ "endpoint_id": endpoint_id, "body": body }),
        attempts: 0,
        last_error: None,
        next_attempt_at_unix_micros: 0,
        enqueued_at_unix_micros: 0,
        lease_stamp_unix_micros: None,
        completed_at_unix_micros: None,
        dead_lettered_at_unix_micros: None,
    }
}

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Register an endpoint through the REAL management API and return `(id, secret, base)`.
///
/// Registration goes over HTTP deliberately: a helper that seeded the row directly would
/// seal the secret its own way, and then this file would prove the deliverer agrees with
/// the test rather than with the API an operator actually uses.
async fn register(h: &Harness, tenant: &str, environment: &str) -> (String, String, String) {
    register_as(h, tenant, environment, "k-register").await
}

/// Register an endpoint under a caller-chosen idempotency key, so one test can register
/// more than one without the second replaying the first's response.
async fn register_as(
    h: &Harness,
    tenant: &str,
    environment: &str,
    key: &str,
) -> (String, String, String) {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/webhook-endpoints");
    let (status, _, body) = h
        .post(
            &base,
            key,
            &serde_json::json!({ "url": "https://example.test/hook" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let created: Value = serde_json::from_str(&body).expect("json");
    (
        created["id"].as_str().expect("id").to_owned(),
        created["secret"].as_str().expect("secret").to_owned(),
        base,
    )
}

/// Drive ONE delivery for `endpoint` to a dead letter through the REAL failure path:
/// enqueue it, claim it, then fail it under a one-attempt budget. Nothing is written into
/// a terminal state by hand, so what a test then reads is what the substrate produced.
async fn dead_letter_one(
    store: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    endpoint: &str,
    webhook_id: &str,
) {
    use std::time::Duration;

    use ironauth_store::{FailureOutcome, NewOutboxMessage, RetryPolicy};

    store
        .scoped(scope)
        .outbox()
        .enqueue(
            env,
            &NewOutboxMessage {
                consumer: WEBHOOK_DELIVERY_CONSUMER,
                idempotency_key: webhook_id,
                ordering_key: endpoint,
                payload: serde_json::json!({
                    "endpoint_id": endpoint,
                    "body": { "type": "user.created" },
                }),
            },
        )
        .await
        .expect("enqueue the delivery");
    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim it");
    let message = claimed
        .iter()
        .find(|m| m.idempotency_key == webhook_id)
        .expect("the delivery is claimable");
    let outcome = store
        .scoped(scope)
        .outbox()
        .fail(
            env,
            message,
            "http_status_500",
            RetryPolicy {
                max_attempts: 1,
                retry_base: Duration::from_secs(1),
            },
        )
        .await
        .expect("record the failure");
    assert!(
        matches!(outcome, FailureOutcome::DeadLettered { .. }),
        "a one-attempt budget dead-letters on the first failure: {outcome:?}"
    );
}

#[tokio::test]
async fn a_queued_delivery_is_signed_under_the_secret_the_api_issued_at_registration() {
    // THE joining property of this slice. The consumer never sees the secret the operator
    // was handed; it opens its own copy out of the sealed column. The two agreeing is what
    // makes a webhook verifiable by the consumer that registered for it, and it spans the
    // migration's AAD, the store's open, and the signing contract.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, secret, _) = register(&h, &tenant, &environment).await;

    let sender = RecordingSender::accepting();
    let consumer = WebhookDeliveryConsumer::new(h.store().clone(), sender.clone());
    let env = Env::system();
    let message = queued(
        &id,
        "evt_42",
        &serde_json::json!({ "type": "user.created" }),
    );

    consumer
        .handle(&env, scope_of(&tenant, &environment), &message)
        .await
        .expect("the delivery is made");

    let sent = sender.recorded();
    assert_eq!(sent.len(), 1, "one message, one POST");
    let delivery = &sent[0];
    assert_eq!(
        delivery.url, "https://example.test/hook",
        "delivered to the registered destination"
    );
    // `webhook-id` is the producer's dedup handle rather than anything minted here. That
    // is what makes it IDENTICAL across a redelivery, which is the only reason a receiver
    // can deduplicate at-least-once delivery at all.
    assert_eq!(
        delivery.headers.id, "evt_42",
        "the receiver's dedupe key is the message's own idempotency key"
    );

    let held = WebhookSecret::parse(&secret).expect("the issued secret parses");
    let now: i64 = delivery.headers.timestamp.parse().expect("unix seconds");
    verify_delivery(
        &[held],
        &delivery.headers.id,
        &delivery.headers.timestamp,
        delivery.body.as_bytes(),
        &delivery.headers.signature,
        300,
        now,
    )
    .expect("the consumer that registered this endpoint verifies the delivery");

    // And it is NOT verifiable under some other secret, so the assertion above is about
    // THIS endpoint's key rather than about the signature merely being well formed.
    let stranger = WebhookSecret::from_bytes(vec![7; 32]);
    verify_delivery(
        &[stranger],
        &delivery.headers.id,
        &delivery.headers.timestamp,
        delivery.body.as_bytes(),
        &delivery.headers.signature,
        300,
        now,
    )
    .expect_err("a secret this endpoint never issued does not verify");
}

#[tokio::test]
async fn a_delivery_during_a_rotation_window_verifies_under_either_secret() {
    // Slice 3 opened the window in the ROW; this is the half that makes it mean something.
    // If the deliverer signed under the current secret alone, the window would be a column
    // nothing reads and every consumer would still have to redeploy in lockstep.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, old_secret, base) = register(&h, &tenant, &environment).await;

    let (status, _, body) = h
        .post(&format!("{base}/{id}/rotate-secret"), "k-rot", "")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_secret = serde_json::from_str::<Value>(&body).expect("json")["secret"]
        .as_str()
        .expect("secret")
        .to_owned();

    let sender = RecordingSender::accepting();
    let consumer = WebhookDeliveryConsumer::new(h.store().clone(), sender.clone());
    let env = Env::system();
    let message = queued(
        &id,
        "evt_rot",
        &serde_json::json!({ "type": "user.updated" }),
    );

    consumer
        .handle(&env, scope_of(&tenant, &environment), &message)
        .await
        .expect("the delivery is made");

    let sent = sender.recorded();
    let delivery = &sent[0];
    assert_eq!(
        delivery.headers.signature.split(' ').count(),
        2,
        "one signature per live secret while the window is open: {}",
        delivery.headers.signature
    );
    let now: i64 = delivery.headers.timestamp.parse().expect("unix seconds");
    for (label, raw) in [("outgoing", &old_secret), ("incoming", &new_secret)] {
        let held = WebhookSecret::parse(raw).expect("parses");
        verify_delivery(
            &[held],
            &delivery.headers.id,
            &delivery.headers.timestamp,
            delivery.body.as_bytes(),
            &delivery.headers.signature,
            300,
            now,
        )
        .unwrap_or_else(|_| panic!("a consumer holding the {label} secret verifies"));
    }
}

#[tokio::test]
async fn a_delivery_for_a_withdrawn_endpoint_is_completed_without_a_post() {
    // Deleting an endpoint has to stop deliveries that were ALREADY queued for it, or the
    // operation would only stop the ones nobody had enqueued yet. Completing rather than
    // retrying is the deliberate half: retrying would burn the attempt budget reaching a
    // destination that has been withdrawn, and dead-lettering would report the operator's
    // own action as a delivery failure.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, _, base) = register(&h, &tenant, &environment).await;

    let (status, _, body) = h.delete(&format!("{base}/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let sender = RecordingSender::accepting();
    let consumer = WebhookDeliveryConsumer::new(h.store().clone(), sender.clone());
    let message = queued(
        &id,
        "evt_gone",
        &serde_json::json!({ "type": "user.created" }),
    );

    consumer
        .handle(&Env::system(), scope_of(&tenant, &environment), &message)
        .await
        .expect("the message is completed rather than retried or dead-lettered");
    assert!(
        sender.recorded().is_empty(),
        "nothing is POSTed for an endpoint that no longer exists"
    );
}

#[tokio::test]
async fn a_paused_endpoint_receives_nothing_and_resuming_restores_its_original_secret() {
    // `active` shipped with the table in slice 2 and nothing could write it, so the flag
    // described a capability no operator had and no reader could ever observe false. This
    // is both halves at once: the toggle that sets it, and the delivery consequence that
    // makes it mean something rather than being a column in a schema.
    //
    // The secret surviving is the reason pause exists as something other than delete.
    // Deleting destroys the signing secret, so coming back means re-registering AND every
    // consumer adopting a new one; pausing has to cost nothing to undo.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, secret, base) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();

    let (status, _, body) = h.post(&format!("{base}/{id}/pause"), "k-pause", "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["active"],
        Value::Bool(false),
        "the response describes the state the request committed: {body}"
    );

    let paused = RecordingSender::accepting();
    let consumer = WebhookDeliveryConsumer::new(h.store().clone(), paused.clone());
    let error = consumer
        .handle(
            &env,
            scope,
            &queued(
                &id,
                "evt_paused",
                &serde_json::json!({ "type": "user.created" }),
            ),
        )
        .await
        .expect_err("a paused endpoint does not accept the delivery");
    // DEAD-LETTERED rather than completed, which is the difference between "held for you"
    // and "silently dropped". Pausing is reversible, so a message queued for a paused
    // endpoint has somewhere to come back to, and #106's rule is that nothing is dropped
    // without landing where an operator can replay it from. Retrying instead would burn
    // the attempt budget waiting for a human to act.
    assert!(
        !error.is_retryable(),
        "a paused endpoint dead-letters immediately rather than retrying: {}",
        error.label()
    );
    assert_eq!(error.label(), "endpoint_paused");
    assert!(
        paused.recorded().is_empty(),
        "a paused endpoint is POSTed nothing at all"
    );

    let (status, _, body) = h.post(&format!("{base}/{id}/resume"), "k-resume", "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["active"],
        Value::Bool(true),
        "{body}"
    );

    let resumed = RecordingSender::accepting();
    let consumer = WebhookDeliveryConsumer::new(h.store().clone(), resumed.clone());
    consumer
        .handle(
            &env,
            scope,
            &queued(
                &id,
                "evt_resumed",
                &serde_json::json!({ "type": "user.created" }),
            ),
        )
        .await
        .expect("the delivery is made");
    let sent = resumed.recorded();
    assert_eq!(sent.len(), 1, "deliveries resume");
    let delivery = &sent[0];
    let now: i64 = delivery.headers.timestamp.parse().expect("unix seconds");
    verify_delivery(
        &[WebhookSecret::parse(&secret).expect("parses")],
        &delivery.headers.id,
        &delivery.headers.timestamp,
        delivery.body.as_bytes(),
        &delivery.headers.signature,
        300,
        now,
    )
    .expect("the secret issued before the pause still signs after the resume");
}

#[tokio::test]
async fn a_dead_letter_is_listed_replayed_across_planes_and_redelivered_under_its_original_id() {
    // The whole of #106's first slice, driven end to end, because every interesting part of
    // it is a JOIN between pieces that are individually unremarkable.
    //
    // The design worth proving is the cross-plane hop. The management plane may INSERT on
    // the queue and holds no UPDATE (migration 0099, so the role that also holds the
    // retention DELETE can never have been the role that marked a message terminal), so an
    // operator's replay travels as a COMMAND and the drain executes it. This test uses the
    // real control-plane HTTP surface to ask and the real data-plane store to execute, so
    // a grant missing on either side fails it rather than being discovered in production.
    use std::time::Duration;

    use ironauth_store::WEBHOOK_REPLAY_CONSUMER;

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, secret, base) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let store = h.store().clone();

    // A SECOND endpoint with its own dead letter, so every per-endpoint claim below is
    // measured rather than trivially true. With one endpoint, a listing that ignored its
    // ordering key and a replay that revived the whole environment would both pass.
    let (other, _, _) = register_as(&h, &tenant, &environment, "k-register-2").await;
    dead_letter_one(&store, &env, scope, &other, "evt_other").await;

    dead_letter_one(&store, &env, scope, &id, "evt_dead").await;

    // THE LISTING, over the real management surface.
    let (status, _, body) = h.get(&format!("{base}/{id}/dead-letters")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        listed["items"].as_array().expect("items").len(),
        1,
        "exactly this endpoint's dead letter, not the other endpoint's too: {body}"
    );
    assert_eq!(
        listed["items"][0]["webhook_id"], "evt_dead",
        "the listing shows the id the delivery carried, which is what a receiver \
         deduplicated on: {body}"
    );
    assert_eq!(listed["items"][0]["attempts"], 1, "{body}");
    assert_eq!(
        listed["items"][0]["last_error"], "http_status_500",
        "{body}"
    );

    // THE REQUEST, which only enqueues. A 202 rather than a count is the honest answer:
    // the management plane cannot perform the revive and no number it returned would be
    // true by the time a caller read it.
    let (status, _, body) = h.post(&format!("{base}/{id}/replay"), "k-replay", "").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    // THE EXECUTION, on the data plane, through the real consumer and the real queue.
    let commands = store
        .scoped(scope)
        .outbox()
        .claim(&env, WEBHOOK_REPLAY_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim the replay command");
    assert_eq!(
        commands.len(),
        1,
        "the management plane's INSERT reached the queue the drain reads"
    );
    WebhookReplayConsumer::new(store.clone())
        .handle(&env, scope, &commands[0])
        .await
        .expect("the replay executes");

    // The dead letter is gone from the listing because the row went back on the queue,
    // rather than because a copy of it was made somewhere else.
    let (status, _, body) = h.get(&format!("{base}/{id}/dead-letters")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_str::<Value>(&body).expect("json")["items"]
            .as_array()
            .expect("items")
            .is_empty(),
        "the replayed delivery is no longer dead-lettered: {body}"
    );

    // ...and the OTHER endpoint's dead letter is still there, which is what proves the
    // replay acted on one aggregate rather than on the environment.
    let (status, _, body) = h.get(&format!("{base}/{other}/dead-letters")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let others: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        others["items"].as_array().expect("items").len(),
        1,
        "another endpoint's dead letter is neither listed under the first nor replayed          by it: {body}"
    );
    assert_eq!(others["items"][0]["webhook_id"], "evt_other", "{body}");

    // AND IT REDELIVERS UNDER THE ORIGINAL webhook-id, which is the acceptance criterion
    // the in-place revive exists to satisfy. A re-enqueued copy could not have done this:
    // the unique index would have forced a new idempotency key, and the receiver's
    // deduplication would treat the replay as a brand new event.
    let revived = store
        .scoped(scope)
        .outbox()
        .claim(&env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim the revived delivery");
    assert_eq!(revived.len(), 1, "the revived message is claimable again");
    let sender = RecordingSender::accepting();
    WebhookDeliveryConsumer::new(store.clone(), sender.clone())
        .handle(&env, scope, &revived[0])
        .await
        .expect("the replayed delivery is made");
    let sent = sender.recorded();
    assert_eq!(sent.len(), 1, "one replay, one POST");
    assert_eq!(
        sent[0].headers.id, "evt_dead",
        "the replay carries the ORIGINAL webhook-id, so consumer-side dedupe still works"
    );
    let now: i64 = sent[0].headers.timestamp.parse().expect("unix seconds");
    verify_delivery(
        &[WebhookSecret::parse(&secret).expect("parses")],
        &sent[0].headers.id,
        &sent[0].headers.timestamp,
        sent[0].body.as_bytes(),
        &sent[0].headers.signature,
        300,
        now,
    )
    .expect("and it verifies under the endpoint's current secret");
}

#[tokio::test]
async fn every_attempt_is_recorded_with_what_the_receiver_actually_answered() {
    // The debugging surface #106 asks for: what the endpoint actually answered, and when.
    //
    // The case that matters is the RETRIED failure. A history that recorded only terminal
    // outcomes would omit precisely the attempts an operator opens it to see, and it would
    // still look correct on a delivery that succeeded first time. So this drives a failure
    // and then a success on the same message and asserts both are there, with the status
    // the receiver returned rather than merely that each one failed or did not.
    use std::time::Duration;

    use ironauth_store::{NewOutboxMessage, RetryPolicy, WEBHOOK_DELIVERY_CONSUMER};

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, _, base) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    // A MANUAL clock, because this test has to cross a retry backoff and the alternative
    // is sleeping for it. Advancing the seam is also what makes the recorded latency and
    // the attempt ordering deterministic rather than dependent on how fast the machine is.
    let (env, clock) = Env::deterministic(
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        7,
    );
    let store = h.store().clone();

    store
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_DELIVERY_CONSUMER,
                idempotency_key: "evt_hist",
                ordering_key: &id,
                payload: serde_json::json!({
                    "endpoint_id": id,
                    "body": { "type": "user.created" },
                }),
            },
        )
        .await
        .expect("enqueue");

    // A FAILED attempt first. It is retried rather than terminal, which is precisely the
    // case a history that only recorded final outcomes would lose.
    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    WebhookDeliveryConsumer::new(
        store.clone(),
        RecordingSender::failing(SendFailure::Status(503)),
    )
    .handle(&env, scope, &claimed[0])
    .await
    .expect_err("a 503 is a failed delivery");
    let outcome = store
        .scoped(scope)
        .outbox()
        .fail(
            &env,
            &claimed[0],
            "http_status_503",
            RetryPolicy {
                max_attempts: 5,
                retry_base: Duration::from_secs(0),
            },
        )
        .await
        .expect("record the failure");
    assert!(
        matches!(outcome, ironauth_store::FailureOutcome::Retrying { .. }),
        "five attempts remain, so this is a retry rather than a dead letter: {outcome:?}"
    );

    // Past the backoff the failure just scheduled, through the seam rather than by
    // waiting. A retry that is not yet due is not claimable, which is the substrate
    // working; stepping the clock is how a test crosses it.
    clock.advance(Duration::from_secs(600));

    // Then a SUCCESS on the retry, so the history holds one of each.
    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("re-claim");
    assert_eq!(claimed.len(), 1, "the retry is claimable");
    WebhookDeliveryConsumer::new(store.clone(), RecordingSender::accepting())
        .handle(&env, scope, &claimed[0])
        .await
        .expect("the retry succeeds");

    let (status, _, body) = h.get(&format!("{base}/{id}/attempts")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Value = serde_json::from_str(&body).expect("json");
    let items = listed["items"].as_array().expect("items");
    assert_eq!(items.len(), 2, "both attempts are recorded: {body}");

    // Newest first, so the SUCCESS leads.
    assert_eq!(items[0]["status_code"], 200, "{body}");
    assert_eq!(
        items[0]["error"],
        Value::Null,
        "a success carries no error: {body}"
    );
    assert_eq!(items[0]["attempt_number"], 2, "{body}");
    assert_eq!(
        items[1]["status_code"], 503,
        "the failed attempt records what the RECEIVER said, not merely that it failed: \
         {body}"
    );
    assert_eq!(items[1]["error"], "http_status_503", "{body}");
    assert_eq!(items[1]["attempt_number"], 1, "{body}");
    for item in items {
        assert_eq!(
            item["webhook_id"], "evt_hist",
            "every attempt is correlatable by the id the receiver deduplicated on: {body}"
        );
        assert!(item["latency_ms"].as_i64().expect("latency") >= 0, "{body}");
    }
}

#[tokio::test]
async fn a_reaped_message_takes_its_attempt_history_with_it() {
    // The retention half, kept separate because it is an independent claim: a history that
    // records the right things and a history that is bounded are two different properties,
    // and a test asserting both at once reports one failure for either.
    //
    // This table has NO reaper of its own, deliberately. Migration 0099 shipped the queue
    // with no retention and 0102 had to add a sweeper afterwards; a per-ATTEMPT table grows
    // faster than the messages it describes, so the bound here is structural. If the
    // cascade were dropped, nothing else in the tree would ever delete one of these rows.
    use std::time::Duration;

    use ironauth_store::{NewOutboxMessage, WEBHOOK_DELIVERY_CONSUMER};

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, _, base) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let store = h.store().clone();

    store
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_DELIVERY_CONSUMER,
                idempotency_key: "evt_reap",
                ordering_key: &id,
                payload: serde_json::json!({
                    "endpoint_id": id,
                    "body": { "type": "user.created" },
                }),
            },
        )
        .await
        .expect("enqueue");
    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    WebhookDeliveryConsumer::new(store.clone(), RecordingSender::accepting())
        .handle(&env, scope, &claimed[0])
        .await
        .expect("the delivery is made");

    let (_, _, body) = h.get(&format!("{base}/{id}/attempts")).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        1,
        "the attempt is recorded before retention has any reason to run: {body}"
    );

    // Completing it is the WORKER's step, not the consumer's, so the test does it here:
    // without it the message is not terminal and retention would find nothing to reap,
    // which would make the assertion below pass for the wrong reason.
    assert!(
        store
            .scoped(scope)
            .outbox()
            .complete(&env, &claimed[0])
            .await
            .expect("complete the delivered message"),
        "the completion is accepted under the lease this claim holds"
    );

    // RETENTION, which is the whole reason this table has a foreign key rather than a
    // second reaper. Reaping the message must take its history with it; nothing else in
    // the tree deletes these rows, so without the cascade they would accumulate forever.
    // Through the CONTROL store, because 0102 gave the retention DELETE to that role
    // alone. Reaping from the data plane would fail on the grant, so this also measures
    // that the cascade works for the role that actually performs retention.
    let deleted = h
        .control_store()
        .scoped(scope)
        .outbox()
        .reap_completed(WEBHOOK_DELIVERY_CONSUMER, i64::MAX, 100)
        .await
        .expect("reap the completed message");
    assert_eq!(deleted, 1, "the completed message is reaped");
    let (status, _, body) = h.get(&format!("{base}/{id}/attempts")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_str::<Value>(&body).expect("json")["items"]
            .as_array()
            .expect("items")
            .is_empty(),
        "the attempts went with the message they describe, under the outbox's own \
         retention rather than a second one: {body}"
    );
}

#[tokio::test]
async fn sustained_failure_disables_an_endpoint_and_one_success_resets_the_run() {
    // Auto-disable, and the property that keeps it from firing on a working endpoint.
    //
    // The rule is a CONSECUTIVE run rather than a rate, because a busy endpoint that fails
    // a fraction of the time is working and must not be turned off. So this drives the
    // threshold to within one, lands a SUCCESS, and asserts the endpoint is still live:
    // one success anywhere in the run resets it, which is what makes the rule
    // self-clearing with no separate counter to reset.
    use std::time::Duration;

    use ironauth_store::{NewOutboxMessage, WEBHOOK_DELIVERY_CONSUMER};

    const THRESHOLD: u32 = 3;

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, _, base) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let store = h.store().clone();

    // Each pass is its own message, because a single message's retry budget would
    // dead-letter before the threshold and stop producing attempts.
    let deliver = async |key: &str, sender: RecordingSender| {
        store
            .scoped(scope)
            .outbox()
            .enqueue(
                &env,
                &NewOutboxMessage {
                    consumer: WEBHOOK_DELIVERY_CONSUMER,
                    idempotency_key: key,
                    ordering_key: key,
                    payload: serde_json::json!({
                        "endpoint_id": id,
                        "body": { "type": "user.created" },
                    }),
                },
            )
            .await
            .expect("enqueue");
        let claimed = store
            .scoped(scope)
            .outbox()
            .claim(&env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
            .await
            .expect("claim");
        let message = claimed
            .iter()
            .find(|m| m.idempotency_key == key)
            .expect("claimable");
        WebhookDeliveryConsumer::with_auto_disable(store.clone(), sender, THRESHOLD)
            .handle(&env, scope, message)
            .await
    };

    // One short of the threshold.
    for pass in 0..THRESHOLD - 1 {
        deliver(
            &format!("evt_fail_{pass}"),
            RecordingSender::failing(SendFailure::Status(500)),
        )
        .await
        .expect_err("a 500 is a failed delivery");
    }
    let (_, _, body) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["items"][0]["active"],
        Value::Bool(true),
        "below the threshold the endpoint stays live: {body}"
    );

    // A SUCCESS resets the run, so the next failures start counting from zero.
    deliver("evt_ok", RecordingSender::accepting())
        .await
        .expect("the delivery succeeds");
    for pass in 0..THRESHOLD - 1 {
        deliver(
            &format!("evt_after_{pass}"),
            RecordingSender::failing(SendFailure::Status(500)),
        )
        .await
        .expect_err("a 500 is a failed delivery");
    }
    let (_, _, body) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["items"][0]["active"],
        Value::Bool(true),
        "a success in between resets the run, so these failures did not reach the \
         threshold either: {body}"
    );

    // One more failure completes an unbroken run of THRESHOLD.
    deliver(
        "evt_last",
        RecordingSender::failing(SendFailure::Status(500)),
    )
    .await
    .expect_err("a 500 is a failed delivery");
    let (_, _, body) = h.get(&base).await;
    let endpoint = &serde_json::from_str::<Value>(&body).expect("json")["items"][0];
    assert_eq!(
        endpoint["active"],
        Value::Bool(false),
        "an unbroken run of {THRESHOLD} disables the endpoint: {body}"
    );
    // Recorded ON THE ROW rather than as an audit row, because an automatic disable has no
    // actor. The operator can tell this apart from a pause they performed themselves.
    assert_eq!(
        endpoint["disabled_reason"], "consecutive_delivery_failures",
        "{body}"
    );
    assert!(
        endpoint["auto_disabled_at_unix_ms"]
            .as_i64()
            .expect("stamp")
            > 0,
        "{body}"
    );
}

#[tokio::test]
async fn a_delivery_queued_for_a_disabled_endpoint_is_recoverable_rather_than_dropped() {
    // The property that makes automatic disabling SAFE, and the reason it is a separate
    // test: auto-disable turns an endpoint off underneath messages that are already
    // queued, so if those were dropped the feature would silently discard exactly the
    // events an operator most wants back. #106 forbids that in absolute terms.
    //
    // Driven through the same paused arm the manual pause uses, since an auto-disabled
    // endpoint is simply a paused one that the system paused.
    use std::time::Duration;

    use ironauth_store::{NewOutboxMessage, WEBHOOK_DELIVERY_CONSUMER};

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, _, base) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let store = h.store().clone();

    let (status, _, body) = h.post(&format!("{base}/{id}/pause"), "k-pause", "").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The message has to stay in hand rather than go through a helper, because reporting
    // its failure needs the lease stamp the claim handed out.
    store
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_DELIVERY_CONSUMER,
                idempotency_key: "evt_after_disable",
                // The ENDPOINT id, as the real producer uses, because that is what the
                // per-endpoint dead-letter listing narrows by.
                ordering_key: &id,
                payload: serde_json::json!({
                    "endpoint_id": id,
                    "body": { "type": "user.created" },
                }),
            },
        )
        .await
        .expect("enqueue");
    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    let message = claimed
        .iter()
        .find(|m| m.idempotency_key == "evt_after_disable")
        .expect("claimable");
    let error = WebhookDeliveryConsumer::new(store.clone(), RecordingSender::accepting())
        .handle(&env, scope, message)
        .await
        .expect_err("a disabled endpoint does not accept the delivery");
    assert!(!error.is_retryable(), "{}", error.label());
    // Reporting the failure is the WORKER's step, and it maps a permanent error to a
    // one-attempt policy so the queue stays the single place that decides what terminal
    // means. Mirrored here, or this would assert on a dead letter nothing had written yet.
    let outcome = store
        .scoped(scope)
        .outbox()
        .fail(
            &env,
            message,
            error.label(),
            ironauth_store::RetryPolicy {
                max_attempts: 1,
                retry_base: Duration::from_secs(1),
            },
        )
        .await
        .expect("report the failure");
    assert!(
        matches!(outcome, ironauth_store::FailureOutcome::DeadLettered { .. }),
        "a permanent failure is terminal on the first report: {outcome:?}"
    );

    let (_, _, body) = h.get(&format!("{base}/{id}/dead-letters")).await;
    let dead: Vec<String> = serde_json::from_str::<Value>(&body).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["webhook_id"].as_str().expect("id").to_owned())
        .collect();
    assert!(
        dead.contains(&"evt_after_disable".to_owned()),
        "the event queued after the endpoint was disabled is recoverable, not dropped: \
         {body}"
    );

    // And RESUMING clears the auto-disable record, so the endpoint does not keep reporting
    // itself system-disabled after an operator has turned it back on.
    let (status, _, body) = h.post(&format!("{base}/{id}/resume"), "k-resume", "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resumed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(resumed["active"], Value::Bool(true), "{body}");
    assert_eq!(resumed["auto_disabled_at_unix_ms"], Value::Null, "{body}");
    assert_eq!(resumed["disabled_reason"], Value::Null, "{body}");
}

#[tokio::test]
async fn a_refused_delivery_is_retryable_and_a_malformed_payload_is_not() {
    // The two halves of the failure classification, together, because the value of each is
    // that it differs from the other. A receiver answering 500 recovers on a later attempt;
    // a payload with no endpoint on it never will, and retrying it five times only delays
    // the dead letter while blocking anything behind it in the same ordering group.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, _, _) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();

    let sender = RecordingSender::failing(SendFailure::Status(500));
    let consumer = WebhookDeliveryConsumer::new(h.store().clone(), sender.clone());
    let error = consumer
        .handle(
            &env,
            scope,
            &queued(
                &id,
                "evt_500",
                &serde_json::json!({ "type": "user.created" }),
            ),
        )
        .await
        .expect_err("a 500 is a failed delivery");
    assert!(
        error.is_retryable(),
        "a receiver that answered 500 may answer 200 later: {}",
        error.label()
    );
    assert_eq!(
        error.label(),
        "http_status_500",
        "the recorded reason is a bounded, non-secret token"
    );

    let mut malformed = queued(&id, "evt_bad", &serde_json::json!({}));
    malformed.payload = serde_json::json!({ "body": { "type": "user.created" } });
    let error = consumer
        .handle(&env, scope, &malformed)
        .await
        .expect_err("a payload naming no endpoint cannot be delivered");
    assert!(
        !error.is_retryable(),
        "no later attempt adds a field to a row that is already written: {}",
        error.label()
    );
}

#[tokio::test]
async fn queue_depth_reports_the_backlog_a_dead_letter_leaves_behind() {
    // `OutboxRepo::depth` shipped with the outbox and its own documentation recorded that
    // it had no production caller, so the observability #104 and #106 both ask for was a
    // method nobody could reach. This is that reader.
    //
    // The number that matters is `dead_lettered`: it is the one an operator alerts on,
    // because a dead letter is work that will never happen unless somebody replays it. So
    // this drives a real delivery to a real dead letter and asserts the depth moves,
    // rather than asserting that an empty environment reports zeros, which would pass
    // against a handler that returned a constant.
    use ironauth_store::WEBHOOK_DELIVERY_CONSUMER;

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (id, _, _) = register(&h, &tenant, &environment).await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let store = h.store().clone();
    let queues = format!("/v1/tenants/{tenant}/environments/{environment}/queues");

    // Before: the webhook queue either is absent or reports nothing dead-lettered.
    let (status, _, body) = h.get(&queues).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before: Value = serde_json::from_str(&body).expect("json");
    let dead_before = before["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["consumer"] == WEBHOOK_DELIVERY_CONSUMER)
        .map_or(0, |item| item["dead_lettered"].as_i64().expect("count"));
    assert_eq!(dead_before, 0, "nothing is dead-lettered yet: {body}");

    dead_letter_one(&store, &env, scope, &id, "evt_depth").await;

    let (status, _, body) = h.get(&queues).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after: Value = serde_json::from_str(&body).expect("json");
    let webhook = after["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["consumer"] == WEBHOOK_DELIVERY_CONSUMER)
        .expect("the webhook delivery queue is reported once it has rows");
    assert_eq!(
        webhook["dead_lettered"], 1,
        "the dead letter shows up in the depth an operator alerts on: {body}"
    );
    // And it is NOT double counted as still pending: a dead letter is terminal, so the
    // backlog a worker would claim is unchanged by it.
    assert_eq!(webhook["ready"], 0, "{body}");
    assert_eq!(webhook["in_flight"], 0, "{body}");

    // The listing enumerates the consumers that HAVE rows rather than a hard-coded list,
    // so a queue this binary does not run still shows its backlog. Nothing has enqueued
    // for the replay consumer, so it is absent rather than reported as an empty row.
    assert!(
        after["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|item| item["consumer"] == WEBHOOK_DELIVERY_CONSUMER),
        "only queues with rows are listed: {body}"
    );
}
