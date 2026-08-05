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
    DeliveryHeaders, WEBHOOK_DELIVERY_CONSUMER, WebhookDeliveryConsumer, WebhookSender,
};
use ironauth_env::Env;
use ironauth_jose::webhooks::{WebhookSecret, verify_delivery};
use ironauth_oidc::SendFailure;
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::{EnvironmentId, OutboxMessage, Scope, TenantId};
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
    ) -> impl Future<Output = Result<(), SendFailure>> + Send {
        self.sent.lock().expect("recorder lock").push(Recorded {
            url: url.to_owned(),
            headers: headers.clone(),
            body: body.to_owned(),
        });
        let outcome = self.outcome;
        async move {
            match outcome {
                Some(failure) => Err(failure),
                None => Ok(()),
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
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/webhook-endpoints");
    let (status, _, body) = h
        .post(
            &base,
            "k-register",
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
    consumer
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
        .expect("the message is completed rather than left to retry");
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
