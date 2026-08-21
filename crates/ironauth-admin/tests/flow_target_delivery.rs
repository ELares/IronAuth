// SPDX-License-Identifier: MIT OR Apache-2.0

//! ASYNC flow-target DELIVERY driven end to end against a real database (issue #112,
//! criterion 2).
//!
//! The sibling file `webhook_delivery.rs` measures the same seam for webhooks, and the
//! property worth pinning is the same one: a delivery signed by the consumer must verify
//! under the secret the OPERATOR registered. What differs is where that secret comes from,
//! and it is the whole reason this file exists rather than a few more cases over there.
//!
//! A webhook endpoint MINTS its own secret at registration and seals it in its own column,
//! so one write establishes both halves. A flow target instead names an ENVIRONMENT SECRET
//! the operator wrote separately, so the agreeing parts are a secret written through one
//! management route, a target registered through another, and a consumer that opens the
//! first by the name recorded on the second. Any of the three drifting breaks delivery, and
//! nothing else in the tree joins them.
//!
//! That indirection also buys two behaviours a webhook endpoint cannot have, and both are
//! measured below: the secret is resolved at DELIVERY time, so rotating it works without
//! touching the target; and a target may legitimately have NO secret, so the unsigned path
//! is real here rather than unreachable.
//!
//! The transport is the only thing stubbed. A recording sender captures what the consumer
//! decided, so every decision above the socket is exercised for real.

mod common;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use common::Harness;
use ironauth_admin::flow_target_delivery::FlowTargetDeliveryConsumer;
use ironauth_admin::webhook_delivery::{
    DeliveryHeaders, DeliveryOutcome, SignaturePair, WebhookSender,
};
use ironauth_env::Env;
use ironauth_jose::webhooks::{WebhookSecret, verify_delivery};
use ironauth_oidc::SendFailure;
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::{
    EnvironmentId, FLOW_TARGET_DELIVERY_CONSUMER, OutboxMessage, Scope, TenantId,
};
use serde_json::Value;

/// The environment secret every signed target in this file names.
const SECRET_NAME: &str = "FLOW_TARGET_SIGNING_KEY";
/// Its value, as an operator would write it.
const SECRET_VALUE: &str = "whsec_flow_target_alpha";
/// A second value, for the rotation case.
const ROTATED_VALUE: &str = "whsec_flow_target_beta";

/// One captured delivery: everything the consumer decided, and nothing about the socket.
#[derive(Debug, Clone)]
struct Recorded {
    url: String,
    headers: DeliveryHeaders,
    body: String,
}

impl Recorded {
    /// The signature pair, for a delivery this test expects to be SIGNED.
    fn signed(&self) -> &SignaturePair {
        self.headers
            .signature
            .as_ref()
            .expect("this delivery was expected to be signed")
    }
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
                Some(failure @ SendFailure::Status(status)) => {
                    DeliveryOutcome::failed(Some(status), failure)
                }
                Some(failure) => DeliveryOutcome::failed(None, failure),
                None => DeliveryOutcome::success(200),
            }
        }
    }
}

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// A message as the WORKER would hand it to the consumer.
///
/// Built by hand rather than claimed off the queue, for the same reason the webhook file
/// does it: only the fields a consumer READS carry meaning here, and the lifecycle columns
/// are the substrate's business. The one case that must not be built this way is the
/// dead-letter path, which is driven through the real queue below.
fn queued(target_id: &str, idempotency_key: &str, signed: bool, body: &Value) -> OutboxMessage {
    OutboxMessage {
        id: "obx_test".to_owned(),
        sequence: 1,
        consumer: FLOW_TARGET_DELIVERY_CONSUMER.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        ordering_key: target_id.to_owned(),
        payload: serde_json::json!({
            "target_id": target_id,
            "signed": signed,
            "body": body,
        }),
        attempts: 0,
        last_error: None,
        next_attempt_at_unix_micros: 0,
        enqueued_at_unix_micros: 0,
        lease_stamp_unix_micros: None,
        completed_at_unix_micros: None,
        dead_lettered_at_unix_micros: None,
    }
}

/// The signup envelope a producer composes, near enough for a delivery to carry.
fn signup_body(target_id: &str) -> Value {
    serde_json::json!({
        "target_id": target_id,
        "class": "event",
        "timing": "post_persist",
        "data": { "subject": "usr_test" },
    })
}

/// The `.../flow-targets` base path.
fn targets_base(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/flow-targets")
}

/// Write an environment secret through the REAL management route.
///
/// Through the API rather than into the column, because a helper that sealed it here would
/// seal it this file's way and the test would then prove the consumer agrees with the test
/// rather than with the route an operator uses.
async fn write_secret(h: &Harness, tenant: &str, environment: &str, key: &str, value: &str) {
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/secrets/{SECRET_NAME}");
    let (status, _, body) = h
        .put_with_key(
            &path,
            key,
            &serde_json::json!({ "value": value }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "write the secret: {body}");
}

/// Register an ASYNC target through the REAL management API and return its id.
async fn register_target(
    h: &Harness,
    tenant: &str,
    environment: &str,
    key: &str,
    name: &str,
    signing_secret_name: Option<&str>,
) -> String {
    let mut request = serde_json::json!({
        "name": name,
        "target_class": "event",
        "invocation": "async",
        "timing": "post_persist",
        "endpoint": "https://target.example/hook",
        "failure_policy": "fail_closed",
    });
    if let Some(secret) = signing_secret_name {
        request["signing_secret_name"] = serde_json::Value::String(secret.to_owned());
    }
    let (status, _, body) = h
        .post(
            &targets_base(tenant, environment),
            key,
            &request.to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "register target: {body}");
    let created: Value = serde_json::from_str(&body).expect("json");
    created["id"].as_str().expect("id").to_owned()
}

/// Reconfigure a target IN PLACE by re-registering it under the same name.
async fn reconfigure(
    h: &Harness,
    tenant: &str,
    environment: &str,
    key: &str,
    name: &str,
    signing_secret_name: Option<&str>,
    enabled: bool,
) {
    let mut request = serde_json::json!({
        "name": name,
        "target_class": "event",
        "invocation": "async",
        "timing": "post_persist",
        "endpoint": "https://target.example/hook",
        "failure_policy": "fail_closed",
        "enabled": enabled,
    });
    if let Some(secret) = signing_secret_name {
        request["signing_secret_name"] = serde_json::Value::String(secret.to_owned());
    }
    let (status, _, body) = h
        .post(
            &targets_base(tenant, environment),
            key,
            &request.to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "reconfigure target: {body}");
}

#[tokio::test]
async fn a_delivery_is_signed_under_the_environment_secret_the_target_names() {
    // THE joining property of this slice, and the reason the file exists. The consumer
    // never sees the value an operator wrote; it opens its own copy out of the sealed
    // environment secret by the NAME recorded on the target. The two agreeing spans the
    // secret route's seal, the target registration, and the signing contract.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    write_secret(&h, &tenant, &environment, "k-secret", SECRET_VALUE).await;
    let target = register_target(
        &h,
        &tenant,
        &environment,
        "k-t1",
        "signed",
        Some(SECRET_NAME),
    )
    .await;

    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
    let env = Env::system();
    let message = queued(&target, "ftg_delivery_1", true, &signup_body(&target));

    consumer
        .handle(&env, scope_of(&tenant, &environment), &message)
        .await
        .expect("the delivery is made");

    let sent = sender.recorded();
    assert_eq!(sent.len(), 1, "one message, one POST");
    let delivery = &sent[0];
    assert_eq!(
        delivery.url, "https://target.example/hook",
        "delivered to the registered destination"
    );
    // `webhook-id` is the MESSAGE's dedup handle rather than anything minted here, which is
    // what makes it identical across a redelivery and is the only reason a receiver can
    // deduplicate at-least-once delivery at all.
    assert_eq!(
        delivery.headers.id, "ftg_delivery_1",
        "the receiver's dedupe key is the message's own idempotency key"
    );

    let held = WebhookSecret::from_bytes(SECRET_VALUE.as_bytes().to_vec());
    let now: i64 = delivery.signed().timestamp.parse().expect("unix seconds");
    // The timestamp is checked against an INDEPENDENT reading of the clock, not merely
    // round-tripped through the verifier. Every other assertion here takes `now` from the
    // header itself, so a consumer that stamped a constant would verify against its own
    // constant and this file would not notice, while a receiver enforcing a tolerance window
    // would reject every delivery. Measured: that mutant survived this suite until this
    // assertion existed.
    //
    // Read through the `Env` clock seam rather than the standard library's wall clock
    // directly, which the `time-via-env` invariant lint forbids outright so protocol logic
    // stays deterministic under a test clock. That lint is a TEXT scan over `*.rs`, so it
    // sees a mention in a comment exactly as it sees a call; this sentence is worded to say
    // what it means without naming the symbol. Independence is preserved regardless: the
    // consumer stamps from the clock, and a hardcoded constant does not move with it.
    let wall = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs(),
    )
    .expect("fits");
    assert!(
        (wall - now).abs() < 300,
        "the signature timestamp must track the clock: header {now}, clock {wall}"
    );
    verify_delivery(
        &[held],
        &delivery.headers.id,
        &delivery.signed().timestamp,
        delivery.body.as_bytes(),
        &delivery.signed().signature,
        300,
        now,
    )
    .expect("a receiver holding the operator's secret verifies the delivery");

    // And NOT under some other secret, so the assertion above is about THIS secret rather
    // than about the signature merely being well formed.
    let other = WebhookSecret::from_bytes(ROTATED_VALUE.as_bytes().to_vec());
    verify_delivery(
        &[other],
        &delivery.headers.id,
        &delivery.signed().timestamp,
        delivery.body.as_bytes(),
        &delivery.signed().signature,
        300,
        now,
    )
    .expect_err("a different secret must not verify this delivery");
}

#[tokio::test]
async fn the_secret_is_resolved_at_delivery_time_so_rotation_needs_no_target_write() {
    // A behaviour a webhook endpoint cannot have, and the reason the payload carries the
    // target id rather than the secret. An operator rotating the shared secret writes ONE
    // route; every already-queued delivery then goes out under the new value, which is what
    // a receiver that just rotated expects. Carrying the secret in the payload would have
    // sent the pre-rotation value and the receiver would have rejected it.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    write_secret(&h, &tenant, &environment, "k-secret", SECRET_VALUE).await;
    let target = register_target(
        &h,
        &tenant,
        &environment,
        "k-t1",
        "signed",
        Some(SECRET_NAME),
    )
    .await;

    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    let message = queued(&target, "ftg_delivery_1", true, &signup_body(&target));

    // Rotated AFTER the message exists, so the delivery below is one that was queued under
    // the old value.
    write_secret(&h, &tenant, &environment, "k-rotate", ROTATED_VALUE).await;

    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
    consumer
        .handle(&env, scope, &message)
        .await
        .expect("the delivery is made");

    let sent = sender.recorded();
    assert_eq!(sent.len(), 1, "one message, one POST");
    let delivery = &sent[0];
    let now: i64 = delivery.signed().timestamp.parse().expect("unix seconds");
    verify_delivery(
        &[WebhookSecret::from_bytes(ROTATED_VALUE.as_bytes().to_vec())],
        &delivery.headers.id,
        &delivery.signed().timestamp,
        delivery.body.as_bytes(),
        &delivery.signed().signature,
        300,
        now,
    )
    .expect("the delivery is signed under the value the secret holds NOW");
    verify_delivery(
        &[WebhookSecret::from_bytes(SECRET_VALUE.as_bytes().to_vec())],
        &delivery.headers.id,
        &delivery.signed().timestamp,
        delivery.body.as_bytes(),
        &delivery.signed().signature,
        300,
        now,
    )
    .expect_err("the pre-rotation value must no longer verify");
}

#[tokio::test]
async fn an_unsigned_target_still_carries_the_dedup_handle() {
    // The other behaviour the environment-secret indirection buys. A webhook endpoint always
    // has a secret, so the unsigned arm is unreachable there. A flow target may legitimately
    // name no secret, and this is the case that makes that arm real.
    //
    // This test previously asserted that an unsigned delivery went out with NO HEADERS AT
    // ALL, and passed -- pinning a defect rather than a guarantee. `webhook-id` is not part
    // of the signature, it is the delivery's IDENTITY, and the queue is at-least-once whether
    // or not the target signs. Without it a receiver that got a redelivery (worker killed
    // after the POST, before the completion write) could not tell it from a second signup.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let target = register_target(&h, &tenant, &environment, "k-t1", "unsigned", None).await;

    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
    let message = queued(&target, "ftg_delivery_1", false, &signup_body(&target));

    consumer
        .handle(&Env::system(), scope_of(&tenant, &environment), &message)
        .await
        .expect("an unsigned delivery is made");

    let sent = sender.recorded();
    assert_eq!(sent.len(), 1, "one message, one POST");
    assert!(
        sent[0].headers.signature.is_none(),
        "an unsigned target gets no signature pair rather than empty strings: {:?}",
        sent[0].headers
    );
    assert_eq!(
        sent[0].headers.id, "ftg_delivery_1",
        "and it STILL carries the dedup handle, which is what makes an at-least-once \
         redelivery distinguishable from a second signup"
    );
}

#[tokio::test]
async fn a_delivery_enqueued_as_signed_is_never_sent_unsigned() {
    // The downgrade guard, and the case it exists for is an ordinary operator edit rather
    // than an attack: clearing a target's secret name between enqueue and delivery. Without
    // the guard the queued delivery would go out UNSIGNED, and a receiver that verifies
    // would start rejecting deliveries it should trust, with nothing saying why.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    write_secret(&h, &tenant, &environment, "k-secret", SECRET_VALUE).await;
    let target = register_target(
        &h,
        &tenant,
        &environment,
        "k-t1",
        "signed",
        Some(SECRET_NAME),
    )
    .await;

    let message = queued(&target, "ftg_delivery_1", true, &signup_body(&target));
    // The name cleared after the message was queued as SIGNED.
    reconfigure(&h, &tenant, &environment, "k-clear", "signed", None, true).await;

    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
    let error = consumer
        .handle(&Env::system(), scope_of(&tenant, &environment), &message)
        .await
        .expect_err("a signed delivery whose secret is gone must not be sent");

    assert_eq!(error.label(), "target_signing_downgraded");
    assert!(
        !error.is_retryable(),
        "retrying cannot restore a name an operator cleared, so this dead-letters at once"
    );
    assert!(
        sender.recorded().is_empty(),
        "nothing left the process: the guard is BEFORE the POST, not after it"
    );
}

#[tokio::test]
async fn a_disabled_target_retries_while_a_deregistered_one_completes() {
    // The one decision in this consumer that is not inherited from the queue, and the two
    // halves are asserted TOGETHER because the distinction is the whole content of it: what
    // separates them is whether an operator can undo the state.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());

    // DISABLED: a flag someone can flip back, so the delivery is kept, not dropped.
    let disabled = register_target(&h, &tenant, &environment, "k-t1", "off", None).await;
    reconfigure(&h, &tenant, &environment, "k-off", "off", None, false).await;
    let error = consumer
        .handle(
            &env,
            scope,
            &queued(&disabled, "ftg_delivery_1", false, &signup_body(&disabled)),
        )
        .await
        .expect_err("a disabled target does not deliver");
    assert_eq!(error.label(), "target_disabled");
    assert!(
        error.is_retryable(),
        "a disable is a PAUSE, so the delivery is kept and retried rather than dead-lettered \
         on the spot. Dead-lettering would preserve the backlog only if something could \
         revive a dead letter for this consumer, and nothing can: `revive_dead_lettered` is \
         generic over the consumer name but its only caller hardcodes the webhook one. So \
         the rule meant to preserve the backlog destroyed it, on the most ordinary operator \
         action there is. Retrying makes the attempts cap the give-up and lets a re-enable \
         inside the window drain the backlog with no new machinery."
    );

    // DEREGISTERED: there is nothing to deliver to and the secret is gone with it, so the
    // message is DONE. Dead-lettering it would fill the queue with deliveries no operator
    // can ever act on.
    let gone = register_target(&h, &tenant, &environment, "k-t2", "gone", None).await;
    let (status, _, body) = h
        .delete(&format!("{}/{gone}", targets_base(&tenant, &environment)))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "deregister: {body}");
    consumer
        .handle(
            &env,
            scope,
            &queued(&gone, "ftg_delivery_2", false, &signup_body(&gone)),
        )
        .await
        .expect("a deregistered target completes its queued deliveries rather than retrying");

    assert!(
        sender.recorded().is_empty(),
        "neither case reached the socket"
    );
}

#[tokio::test]
async fn a_delivery_naming_another_tenants_target_is_never_made() {
    // The scope fence, from the direction that matters: not "can tenant A read tenant B's
    // targets" (RLS answers that) but "can a QUEUED MESSAGE carry tenant B's target id and be
    // delivered while draining tenant A". The worker drains every scope in a loop, so the id
    // in a payload and the scope the drain is running under are two independent things, and
    // nothing but this fence makes them agree.
    //
    // Refused BEFORE any read, by `parse_in_scope`, so the answer does not depend on RLS
    // returning an empty set. Both fences are real and this pins the outer one: were it
    // removed, the inner read would return `Absent` and the message would COMPLETE silently,
    // which looks like success and is how a cross-tenant delivery would go unnoticed.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant_a, environment_a) = h.create_tenant("acme", "k-tenant-a").await;
    let (tenant_b, environment_b) = h.create_tenant("globex", "k-tenant-b").await;
    let victim = register_target(&h, &tenant_b, &environment_b, "k-t1", "theirs", None).await;

    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
    let error = consumer
        .handle(
            &Env::system(),
            // Draining tenant A, with tenant B's target id in the payload.
            scope_of(&tenant_a, &environment_a),
            &queued(&victim, "ftg_delivery_1", false, &signup_body(&victim)),
        )
        .await
        .expect_err("a target id from another scope is not deliverable here");

    assert_eq!(error.label(), "target_id_malformed");
    assert!(
        !error.is_retryable(),
        "another tenant's id will not become this tenant's on a retry"
    );
    assert!(
        sender.recorded().is_empty(),
        "nothing was POSTed to the other tenant's target"
    );
}

#[tokio::test]
async fn a_payload_this_consumer_cannot_read_is_permanent_rather_than_retried() {
    // Retrying an unreadable payload fourteen times produces the same unreadable payload
    // fourteen times, and because the outbox serializes per ordering key it would also hold
    // every LATER delivery to that target behind it for the length of the backoff schedule.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());

    let mut no_target = queued("ftg_x", "k1", false, &signup_body("ftg_x"));
    no_target.payload = serde_json::json!({ "body": { "a": 1 } });
    let mut no_body = queued("ftg_x", "k2", false, &signup_body("ftg_x"));
    no_body.payload = serde_json::json!({ "target_id": "ftg_x" });
    let malformed = queued("not-an-id", "k3", false, &signup_body("not-an-id"));

    for (message, label) in [
        (no_target, "payload_missing_target_id"),
        (no_body, "payload_missing_body"),
        (malformed, "target_id_malformed"),
    ] {
        let error = consumer
            .handle(&env, scope, &message)
            .await
            .expect_err("an unreadable payload fails");
        assert_eq!(error.label(), label);
        assert!(
            !error.is_retryable(),
            "{label} is not something another attempt could fix"
        );
    }
    assert!(
        sender.recorded().is_empty(),
        "none of these reached the socket"
    );
}

#[tokio::test]
async fn every_answer_from_the_world_is_retryable_so_the_attempts_cap_decides() {
    // The consumer deliberately has no second opinion about when to give up. A persistently
    // dead receiver becomes a dead letter by exhausting the attempts bound the operator
    // configured, and a consumer that shortcut that would be a second retry policy drifting
    // from the one operators already know.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let target = register_target(&h, &tenant, &environment, "k-t1", "unsigned", None).await;

    for (failure, label) in [
        (SendFailure::Blocked, "blocked_by_ssrf_policy"),
        (SendFailure::Timeout, "timeout"),
        (SendFailure::Status(500), "http_status_500"),
        (SendFailure::Status(404), "http_status_404"),
        (SendFailure::Transport, "transport_error"),
    ] {
        let sender = RecordingSender::failing(failure);
        let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
        let error = consumer
            .handle(
                &env,
                scope,
                &queued(&target, "ftg_delivery_1", false, &signup_body(&target)),
            )
            .await
            .expect_err("a refused delivery fails");
        assert_eq!(error.label(), label, "the label an operator reads");
        assert!(
            error.is_retryable(),
            "{label} leaves the give-up decision to the attempts cap"
        );
    }
}

#[tokio::test]
async fn an_exhausted_delivery_dead_letters_through_the_real_queue() {
    // Everything above hands the consumer a message by hand. This one does not: the message
    // is enqueued, CLAIMED off the queue, refused by the receiver and then failed under a
    // one-attempt budget, so what criterion 2 calls "failures land in the DLQ" is measured
    // on the substrate rather than inferred from a consumer that returned a retryable error.
    //
    // Nothing is written into a terminal state by hand, so what this reads back is what the
    // queue produced.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let target = register_target(&h, &tenant, &environment, "k-t1", "unsigned", None).await;

    let store = h.store().clone();
    store
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &ironauth_store::NewOutboxMessage {
                consumer: FLOW_TARGET_DELIVERY_CONSUMER,
                idempotency_key: "ftg_delivery_1",
                ordering_key: &target,
                payload: serde_json::json!({
                    "target_id": &target,
                    "signed": false,
                    "body": signup_body(&target),
                }),
            },
        )
        .await
        .expect("enqueue the delivery");

    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            FLOW_TARGET_DELIVERY_CONSUMER,
            Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim it");
    let message = claimed
        .iter()
        .find(|m| m.idempotency_key == "ftg_delivery_1")
        .expect("the delivery this test enqueued is claimable");

    let sender = RecordingSender::failing(SendFailure::Status(500));
    let consumer = FlowTargetDeliveryConsumer::new(store.clone(), sender.clone());
    let error = consumer
        .handle(&env, scope, message)
        .await
        .expect_err("the receiver refused it");
    assert!(
        error.is_retryable(),
        "a 500 is the queue's decision to make"
    );

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
        .expect("record the failure");
    assert!(
        matches!(outcome, ironauth_store::FailureOutcome::DeadLettered { .. }),
        "a one-attempt budget dead-letters on the first failure: {outcome:?}"
    );

    // And the label an operator reads on the dead letter is the receiver's status, carried
    // through unchanged from the consumer.
    let sent = sender.recorded();
    assert_eq!(sent.len(), 1, "one claim, one POST attempt");
    assert_eq!(error.label(), "http_status_500");
}
