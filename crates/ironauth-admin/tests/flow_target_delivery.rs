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
async fn a_disabled_target_dead_letters_while_a_deregistered_one_completes() {
    // The one decision in this consumer that is not inherited from the queue, and the two
    // halves are asserted TOGETHER because the distinction is the whole content of it: what
    // separates them is whether an operator can undo the state.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());

    // DISABLED: a flag someone can flip back, so the delivery is KEPT as a dead letter that
    // the replay route returns -- not dropped, and not retried.
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
        !error.is_retryable(),
        "a disable dead-letters after ONE attempt, and the replay route is what returns the \
         backlog. This classification has been both ways: it was retryable while nothing \
         could revive a flow-target dead letter, because dead-lettering then destroyed the \
         backlog. Now that a replay exists, retryable is the harmful one -- `revive_dead_\
         lettered` resets attempts to zero, so replaying a target that is still off would \
         restart a fourteen-attempt schedule whose revived head blocks every newer delivery \
         to that target for days. A dead letter is terminal and blocks nothing."
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

#[tokio::test]
async fn an_async_registration_may_not_set_a_per_target_timeout() {
    // The consumer bounds every POST with `flow_targets.delivery_timeout_secs` and never reads
    // `timeout_ms`, so a value accepted here would round-trip through the API, appear in the
    // listing, and do nothing. That is the accepted-and-ignored shape the enqueue guard
    // refuses one layer down, on the grounds that it is indistinguishable from working.
    //
    // The migration does NOT enforce this: its CHECK only REQUIRES a timeout on sync. So the
    // rule lives at the boundary, and this is what says the boundary still holds it.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;

    let (status, _, body) = h
        .post(
            &targets_base(&tenant, &environment),
            "k-async-timeout",
            &serde_json::json!({
                "name": "async-with-timeout",
                "target_class": "event",
                "invocation": "async",
                "timing": "post_persist",
                "endpoint": "https://target.example/hook",
                "timeout_ms": 500,
                "failure_policy": "fail_closed",
            })
            .to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an async target must not carry a per-call timeout: {body}"
    );
    assert!(
        body.contains("delivery_timeout_secs"),
        "the refusal names the setting that DOES bound an async delivery: {body}"
    );

    // The same registration without it is accepted, so the refusal above is the rule talking
    // rather than the route being broken.
    let (status, _, body) = h
        .post(
            &targets_base(&tenant, &environment),
            "k-async-ok",
            &serde_json::json!({
                "name": "async-without-timeout",
                "target_class": "event",
                "invocation": "async",
                "timing": "post_persist",
                "endpoint": "https://target.example/hook",
                "failure_policy": "fail_closed",
            })
            .to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the same target without it: {body}"
    );
}

#[tokio::test]
async fn a_target_that_became_sync_does_not_deliver_its_queued_async_messages() {
    // Re-registering a target as SYNC rewrites `invocation` in place. Without this guard the
    // already-queued async deliveries still POST to a receiver that is now written as a GATE:
    // it would answer `interrupt`, nothing reads an async response, and the message would be
    // marked completed. The operator would see a clean queue and believe the new gate covered
    // those signups.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let target = register_target(&h, &tenant, &environment, "k-t1", "gate", None).await;
    let message = queued(&target, "ftg_delivery_1", false, &signup_body(&target));

    // Hardened into a gate AFTER the delivery was queued. A sync target requires a timeout,
    // which is what makes this a realistic re-registration rather than a contrived one.
    let (status, _, body) = h
        .post(
            &targets_base(&tenant, &environment),
            "k-harden",
            &serde_json::json!({
                "name": "gate",
                "target_class": "request",
                "invocation": "sync",
                "timing": "pre_persist",
                "endpoint": "https://target.example/hook",
                "timeout_ms": 500,
                "failure_policy": "fail_closed",
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "re-register as sync: {body}");

    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
    let error = consumer
        .handle(&Env::system(), scope_of(&tenant, &environment), &message)
        .await
        .expect_err("a target that became sync must not receive an async delivery");

    assert_eq!(error.label(), "target_became_sync");
    assert!(
        !error.is_retryable(),
        "the target will not become async again on its own, so this dead-letters rather than \
         retrying against a receiver that is now a gate"
    );
    assert!(
        sender.recorded().is_empty(),
        "nothing was POSTed to the gate"
    );
}

#[tokio::test]
async fn the_delivered_body_carries_the_targets_config_as_it_is_now() {
    // `config` is resolved at DELIVERY from the live record, like `endpoint` and the signing
    // secret, rather than frozen into the payload at enqueue. Editing a target's config
    // therefore reaches deliveries that are already queued -- which is the behaviour its
    // neighbour fields have, and the inconsistency that motivated moving it.
    //
    // Asserted on the DELIVERED body rather than on the payload, because the payload's half of
    // this (config absent) is pinned in the store suite; this is the half that says the
    // consumer puts it back.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;

    let (status, _, body) = h
        .post(
            &targets_base(&tenant, &environment),
            "k-t1",
            &serde_json::json!({
                "name": "crm",
                "target_class": "event",
                "invocation": "async",
                "timing": "post_persist",
                "endpoint": "https://target.example/hook",
                "failure_policy": "fail_closed",
                "config": { "route": "before" },
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    let target = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let message = queued(&target, "ftg_delivery_1", false, &signup_body(&target));

    // Edited AFTER the delivery was queued.
    let (status, _, body) = h
        .post(
            &targets_base(&tenant, &environment),
            "k-edit",
            &serde_json::json!({
                "name": "crm",
                "target_class": "event",
                "invocation": "async",
                "timing": "post_persist",
                "endpoint": "https://target.example/hook",
                "failure_policy": "fail_closed",
                "config": { "route": "after" },
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "reconfigure: {body}");

    let sender = RecordingSender::accepting();
    let consumer = FlowTargetDeliveryConsumer::new(h.store().clone(), sender.clone());
    consumer
        .handle(&Env::system(), scope_of(&tenant, &environment), &message)
        .await
        .expect("the delivery is made");

    let sent = sender.recorded();
    assert_eq!(sent.len(), 1, "one message, one POST");
    let delivered: Value = serde_json::from_str(&sent[0].body).expect("the body is json");
    assert_eq!(
        delivered["config"],
        serde_json::json!({ "route": "after" }),
        "the delivery carries the config the target holds NOW, not the one it held at \
         enqueue: {delivered}"
    );
}

/// The whole replay loop, end to end (issue #112 criterion 2: "replay works").
///
/// This is the test the criterion turns on, and it is deliberately not three tests. Each half
/// can pass alone while the loop does nothing: a route that answers 202 and enqueues a command
/// nothing drains, a consumer with a full unit suite that boot never registers, or either side
/// passing the wrong consumer constant -- reviving under the REPLAY name matches no rows and
/// reports success. So this drives the sequence an operator actually performs and asserts the
/// delivery becomes claimable again at the end.
///
/// Nothing is written into a terminal state by hand: the dead letter is produced by failing a
/// real claimed message under a one-attempt budget.
#[tokio::test]
// Over the readable-length lint deliberately. Splitting this is the one change that would
// destroy it: every seam it crosses passes in isolation while the loop does nothing, so the
// single uninterrupted sequence IS the assertion.
#[allow(clippy::too_many_lines)]
async fn a_dead_lettered_delivery_is_listed_and_comes_back_after_a_replay() {
    use ironauth_admin::flow_target_delivery::FlowTargetReplayConsumer;
    use ironauth_store::{FailureOutcome, NewOutboxMessage, RetryPolicy};

    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let store = h.store().clone();
    let target = register_target(&h, &tenant, &environment, "k-t1", "crm", None).await;

    // A real queued delivery, driven to a dead letter through the substrate.
    store
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &NewOutboxMessage {
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
        .expect("the delivery is claimable");
    let outcome = store
        .scoped(scope)
        .outbox()
        .fail(
            &env,
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

    // The LISTING shows it, with the failure reason an operator decides on.
    let (status, _, body) = h
        .get(&format!(
            "{}/{target}/dead-letters",
            targets_base(&tenant, &environment)
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "the dead-letter tail: {body}");
    let listed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        listed["items"].as_array().map(Vec::len),
        Some(1),
        "the dead letter is listed: {body}"
    );
    assert_eq!(listed["items"][0]["webhook_id"], "ftg_delivery_1");
    assert_eq!(
        listed["items"][0]["last_error"],
        serde_json::json!("http_status_500"),
        "carrying WHY, which is what separates a replayable dead letter from one that will \
         fail identically again: {body}"
    );
    assert_eq!(listed["truncated"], serde_json::json!(false));

    // Nothing is claimable now: the delivery is terminal.
    assert!(
        store
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                FLOW_TARGET_DELIVERY_CONSUMER,
                Duration::from_secs(30),
                10
            )
            .await
            .expect("claim")
            .is_empty(),
        "a dead letter is terminal, so it is not claimable until something revives it"
    );

    // The operator asks for a replay over HTTP.
    let (status, _, body) = h
        .post(
            &format!("{}/{target}/replay", targets_base(&tenant, &environment)),
            "k-replay",
            "{}",
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "the replay is queued: {body}");

    // The command is a real queue row on its OWN consumer, which the data plane drains. This
    // is the link that makes the route more than a 202: without a registered consumer the
    // request is durable and inert.
    let commands = store
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::FLOW_TARGET_REPLAY_CONSUMER,
            Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim the replay command");
    assert_eq!(
        commands.len(),
        1,
        "one replay asked, one command: {commands:?}"
    );

    FlowTargetReplayConsumer::new(store.clone())
        .handle(&env, scope, &commands[0])
        .await
        .expect("the replay executes");

    // And the delivery is claimable again, under its ORIGINAL webhook-id: revived in place
    // rather than re-enqueued as a copy, so a receiver still deduplicates it against the
    // attempt it already saw.
    let revived = store
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            FLOW_TARGET_DELIVERY_CONSUMER,
            Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim after the replay");
    assert_eq!(revived.len(), 1, "the dead letter came back: {revived:?}");
    assert_eq!(
        revived[0].idempotency_key, "ftg_delivery_1",
        "and kept its dedup handle, so a receiver sees one event rather than two"
    );
    assert_eq!(
        revived[0].attempts, 0,
        "with its attempt budget restored, so it gets a real chance rather than one attempt"
    );
}

/// Asking for a replay over HTTP ANNOUNCES the request (issue #112 criterion 2).
///
/// Driven through the route rather than the store method, because the store method taking an
/// event proves nothing about whether the handler passes one. `event_catalog::envelope`
/// returns an `Option` and every builder here propagates it, so a handler whose event type was
/// never added to the registry silently passes `None`, writes without an event, and still
/// answers 202. `scripts/producer-coverage.py` does not catch that: its numerator is a regex
/// over event CONSTRUCTION, never over registration.
///
/// The announcement earns its place. A replay re-POSTs signup announcements a receiver already
/// had the chance to see, so anything reconciling against its own records needs to know a
/// redelivery burst was asked for rather than a live spike.
#[tokio::test]
async fn asking_for_a_replay_announces_the_request() {
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let target = register_target(&h, &tenant, &environment, "k-t1", "crm", None).await;

    // Everything the FIXTURE enqueued, drained first, so the count below measures the replay.
    drain_events(&h, scope, &env).await;

    let (status, _, body) = h
        .post(
            &format!("{}/{target}/replay", targets_base(&tenant, &environment)),
            "k-replay",
            &serde_json::json!({ "since_unix_ms": 1_700_000_000_000_i64 }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "the replay is queued: {body}");

    let events = drain_events(&h, scope, &env).await;
    assert_eq!(
        events.len(),
        1,
        "the request announces exactly once: {events:?}"
    );
    assert_eq!(
        events[0]["type"],
        serde_json::json!("flow_target.replay_requested"),
        "and under the registered type: {:?}",
        events[0]
    );
    assert_eq!(
        events[0]["payload"]["flow_target_id"],
        serde_json::json!(target)
    );
    assert_eq!(
        events[0]["payload"]["since_unix_ms"],
        serde_json::json!(1_700_000_000_000_i64),
        "carrying the bound, because a consumer reconciling a redelivery burst needs to know \
         whether it was everything or a window: {:?}",
        events[0]
    );
    // The registry the FAN-OUT enforces, not just the one the builder consulted. An envelope
    // that fails here is dropped permanently and silently in a release build.
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// Drain every queued domain event in the scope and return their envelopes.
///
/// A LOOP, because the outbox serializes per ordering key and a single claim would return one
/// message per key -- so a single-pass drain silently stops being a drain the moment a fixture
/// grows a second event on one key.
async fn drain_events(h: &Harness, scope: Scope, env: &Env) -> Vec<Value> {
    let mut drained = Vec::new();
    loop {
        let claimed = h
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                env,
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim the queued events");
        if claimed.is_empty() {
            return drained;
        }
        for message in &claimed {
            drained.push(message.payload.clone());
            h.store()
                .scoped(scope)
                .outbox()
                .complete(env, message)
                .await
                .expect("complete it, so the next on this ordering key is claimable");
        }
    }
}
