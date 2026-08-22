// SPDX-License-Identifier: MIT OR Apache-2.0

//! ASYNC flow-target delivery: the outbox consumer that signs a queued delivery and POSTs it
//! (issue #112 criterion 2).
//!
//! The sync half of #112 calls a target INSIDE the flow and waits for its verdict. This is the
//! other half: a target the flow does not wait for, announced after the signup commits.
//!
//! It rides the generic transactional outbox rather than a bespoke queue, which is what
//! criterion 2 means by "deliver through the webhook machinery". Retries, the backoff curve,
//! the attempts cap, dead-lettering, per-target ordering, scope fencing and panic containment
//! are all inherited unchanged -- "ordering" here meaning the per-target head-of-group
//! serialization the queue guarantees unconditionally, not strict ordering, which needs a
//! producer-side row lock this producer does not take (see `enqueue_async_delivery`). This
//! file contributes only the parts that are flow-target specific: which record to look up, which secret to sign under, and how each answer from the
//! world is classified.
//!
//! ## What is deliberately NOT reimplemented
//!
//! No retry logic. A consumer returning [`ConsumerError::retryable`] or `permanent` is the
//! whole of its say; the queue owns when and how often. A second backoff curve here would be a
//! second place for the schedule to drift from the one operators already know.
//!
//! No per-attempt history. The webhook path records one, but its row type is hard-typed to a
//! webhook endpoint id. Criterion 2 names retries, dead letters and replay, not an attempt
//! log, and `attempts` plus `last_error` on the queue row carry the operator-visible failure.
//!
//! ## The two decisions that are not obvious
//!
//! A target that is GONE completes the message; a target that is DISABLED dead-letters it. The
//! difference is whether an operator can undo it: a deregistered target will never come back
//! and its secret is gone with it, so there is nothing to recover and nothing to retry against,
//! while a switched-off one is a flag someone can flip and then replay the backlog through
//! `POST .../flow-targets/{id}/replay`.
//!
//! Dead-lettering rather than retrying, and the ROUTE is what makes that the safe choice: a
//! dead letter is terminal, so it blocks nothing, while a retrying head would occupy its
//! target's ordering group for the whole backoff schedule.
//!
//! A delivery enqueued as SIGNED is never sent unsigned, even if the target's secret name has
//! since been cleared. Without that guard, clearing a name silently converts a signed
//! integration into an unsigned POST, which is the same downgrade `open_signing_secret`
//! refuses at the other end.

use std::future::Future;
use std::pin::Pin;

use ironauth_env::Env;
use ironauth_jose::webhooks::WebhookSecret;
use ironauth_store::flow_target::FlowTargetDelivery;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    FLOW_TARGET_DELIVERY_CONSUMER, FLOW_TARGET_REPLAY_CONSUMER, FlowTargetId, OutboxMessage, Scope,
    Store,
};

use crate::webhook_delivery::{DeliveryHeaders, SignaturePair, WebhookSender};

/// The payload key naming the target this message is destined for.
const PAYLOAD_TARGET_ID: &str = "target_id";
/// The payload key recording whether the target was SIGNED when the delivery was enqueued.
const PAYLOAD_SIGNED: &str = "signed";
/// The payload key carrying the JSON body to POST.
const PAYLOAD_BODY: &str = "body";

/// The consumer that turns one queued message into one delivered flow-target call.
pub struct FlowTargetDeliveryConsumer<S> {
    store: Store,
    sender: S,
}

impl<S: WebhookSender> FlowTargetDeliveryConsumer<S> {
    /// Build the consumer over a DATA-plane store and an outbound sender.
    ///
    /// The store must carry a master key: opening a target's sealed signing secret is what
    /// the read is for, and without one every signed delivery fails RETRYABLY rather than
    /// silently going out unsigned.
    #[must_use]
    pub fn new(store: Store, sender: S) -> Self {
        Self { store, sender }
    }

    async fn deliver_one(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        // A payload this consumer cannot read is PERMANENT. Retrying it fourteen times would
        // produce the same unreadable payload fourteen times and delay every later delivery
        // to the same target behind it.
        let Some(raw_id) = message
            .payload
            .get(PAYLOAD_TARGET_ID)
            .and_then(|v| v.as_str())
        else {
            return Err(ConsumerError::permanent("payload_missing_target_id"));
        };
        let Some(body) = message.payload.get(PAYLOAD_BODY) else {
            return Err(ConsumerError::permanent("payload_missing_body"));
        };
        let Ok(target_id) = FlowTargetId::parse_in_scope(raw_id, &scope) else {
            return Err(ConsumerError::permanent("target_id_malformed"));
        };

        let lookup = self
            .store
            .scoped(scope)
            .flow_targets()
            .delivery_target(&target_id)
            .await
            .map_err(|_| ConsumerError::retryable("target_read_failed"))?;

        let target = match lookup {
            FlowTargetDelivery::Deliverable(target) => target,
            // Deregistered. Nothing to deliver to and the secret is gone with it, so this
            // message is done rather than retried against a row that will never return.
            //
            // LOGGED, because completing it discards a real announcement and leaves no other
            // trace: the message goes to `completed`, which reads exactly like a delivery
            // that succeeded. An operator who deregistered a target while deliveries were in
            // flight would otherwise have no way to learn that any were dropped.
            //
            // The webhook consumer's identical arm does not log
            // (`DeliveryTargetLookup::Absent`, webhook_delivery.rs). The two deliberately
            // differ: that it is the older precedent is not an argument that the silence is
            // right, and changing that consumer is not this change's business.
            FlowTargetDelivery::Absent => {
                tracing::warn!(
                    target_id = %target_id,
                    delivery = %message.idempotency_key,
                    "flow target is deregistered; discarding its queued delivery"
                );
                return Ok(());
            }
            // Switched OFF, which an operator can switch back. PERMANENT: the delivery
            // dead-letters after ONE attempt and the replay route returns it.
            //
            // This classification has been both ways, and the reason it settled here is worth
            // keeping. It was permanent first, justified as "stays replayable" while nothing
            // could replay a flow-target dead letter -- so a disable for ten minutes of
            // receiver maintenance destroyed every signup in the window. It became RETRYABLE
            // to make that untrue without new machinery.
            //
            // Now that `POST .../flow-targets/{id}/replay` exists, retryable is the harmful
            // one. `revive_dead_lettered` sets `attempts = 0`, so replaying a target that is
            // still off restarts a fourteen-attempt schedule whose tail is ten-hour gaps, and
            // the outbox leases only the lowest-sequenced NON-TERMINAL message of a group --
            // so that revived head would block every newer delivery to the target for days.
            // A dead letter is terminal and blocks nothing. Permanent costs one attempt, and
            // the backlog is recoverable because there is now a route that recovers it.
            //
            // Which is exactly why the webhook sibling's paused arm is permanent too.
            FlowTargetDelivery::Disabled => {
                return Err(ConsumerError::permanent("target_disabled"));
            }
        };

        // A target that BECAME sync is refused, mirroring the enqueue's own guard. The
        // enqueue says why in as many words: "Refused rather than accepted-and-ignored,
        // because the second is indistinguishable from working." Re-registering a target as
        // sync rewrites `invocation` in place, and without this the already-queued async
        // deliveries would still POST to a receiver now written as a GATE -- which would
        // answer `interrupt`, be ignored because nothing reads an async response, and be
        // marked completed. The operator would see a clean queue and believe the new gate
        // covered those signups.
        if matches!(
            target.invocation,
            ironauth_store::flow_target::Invocation::Sync
        ) {
            return Err(ConsumerError::permanent("target_became_sync"));
        }

        // Resolved at DELIVERY time from the live record, not carried in the payload. That is
        // what makes secret rotation between enqueue and delivery work for free: the delivery
        // signs under whatever the name resolves to now, which is what a receiver rotating a
        // shared secret expects. It is also why the payload never carries the secret VALUE.
        // The target's `config` rides the delivery so a receiver shared by several targets
        // can tell which registration it is answering. Taken from the LIVE record for the
        // same reason the secret below is: an operator editing it expects the next delivery
        // to carry the edit, not the value that was current when the signup happened.
        let Some(body) = body.as_object() else {
            return Err(ConsumerError::permanent("payload_body_not_an_object"));
        };
        let mut body = body.clone();
        body.insert("config".to_owned(), target.config.clone());
        // Serialized ONCE, and these exact bytes are both signed and sent. Signing one
        // rendering and sending another is the classic way to ship deliveries that verify
        // nowhere, and JSON object order is not guaranteed to survive a round trip.
        let Ok(body) = serde_json::to_string(&serde_json::Value::Object(body)) else {
            return Err(ConsumerError::permanent("payload_body_not_serializable"));
        };

        let secret = self
            .store
            .scoped(scope)
            .flow_targets()
            .open_signing_secret(&target)
            .await
            .map_err(|_| ConsumerError::retryable("secret_unavailable"))?;

        // A delivery enqueued as signed is NEVER sent unsigned. Clearing a target's secret
        // name would otherwise silently downgrade a signed integration to an unsigned POST,
        // and a receiver that verifies would start rejecting deliveries it should trust.
        let was_signed = message
            .payload
            .get(PAYLOAD_SIGNED)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if was_signed && secret.is_none() {
            return Err(ConsumerError::permanent("target_signing_downgraded"));
        }

        // The id is set whether or not this delivery is signed. It is the message's own key,
        // identical on every retry and across a replay, so a receiver deduplicating on
        // `webhook-id` sees ONE delivery however many attempts it took. An unsigned target
        // needs that every bit as much as a signed one: the queue is at-least-once either way,
        // and without the header a receiver cannot tell a redelivery from a second signup.
        let headers = DeliveryHeaders {
            id: message.idempotency_key.clone(),
            signature: secret.map(|bytes| {
                let now = unix_secs(env.clock().now_utc());
                SignaturePair {
                    timestamp: now.to_string(),
                    signature: ironauth_store::flow_target::sign_payload(
                        &WebhookSecret::from_bytes(bytes),
                        &message.idempotency_key,
                        now,
                        body.as_bytes(),
                    ),
                }
            }),
        };

        let outcome = self.sender.deliver(&target.endpoint, &headers, &body).await;

        let Some(failure) = outcome.failure else {
            return Ok(());
        };
        // A refused destination, a timeout, a non-2xx and a transport fault are all
        // RETRYABLE: the attempts cap is what turns a persistently dead receiver into a dead
        // letter, so nothing here needs a second way to give up.
        Err(ConsumerError::retryable(failure.label()))
    }
}

impl<S: WebhookSender> OutboxConsumer for FlowTargetDeliveryConsumer<S> {
    fn name(&self) -> &str {
        FLOW_TARGET_DELIVERY_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.deliver_one(env, scope, message).await })
    }
}

/// Seconds since the Unix epoch for a wall-clock instant (saturating).
///
/// The signature timestamp LEAVES the process and a receiver compares it against its own
/// clock, which is what `Clock::now_utc` is for. Nothing here measures elapsed time with it.
fn unix_secs(at: std::time::SystemTime) -> i64 {
    match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// The payload key naming the `since` bound a replay command carries.
const PAYLOAD_SINCE: &str = "since_unix_micros";

/// The consumer that executes an operator's dead-letter REPLAY command (issue #112
/// criterion 2).
///
/// It exists because the plane that may ASK for a replay and the plane that may PERFORM one
/// are different by GRANT. The management API holds INSERT on the queue and no UPDATE of any
/// shape, while the drain holds the lifecycle columns, so an operator's request travels as a
/// message and this is what picks it up on the data plane and does the revive with grants
/// that already existed.
///
/// It drains under [`FLOW_TARGET_REPLAY_CONSUMER`] and revives under
/// [`FLOW_TARGET_DELIVERY_CONSUMER`]. Those are DIFFERENT names and the asymmetry is the
/// whole point: this consumer's own queue holds commands, and the queue it repairs holds
/// deliveries. Passing either name where the other belongs is silent -- reviving under this
/// consumer's name matches no rows and reports `revived=0`, which reads exactly like a
/// target that had nothing outstanding.
pub struct FlowTargetReplayConsumer {
    store: Store,
}

impl FlowTargetReplayConsumer {
    /// Build the consumer over a DATA-plane store.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Execute ONE replay command.
    async fn replay_one(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let Some(raw_id) = message
            .payload
            .get(PAYLOAD_TARGET_ID)
            .and_then(serde_json::Value::as_str)
        else {
            return Err(ConsumerError::permanent("payload_missing_target_id"));
        };
        // Parsed IN SCOPE, so a command carrying another tenant's target id cannot be
        // executed while draining this one. The worker loops over every scope, so the id in
        // a payload and the scope the drain runs under are two independent things.
        let Ok(target_id) = FlowTargetId::parse_in_scope(raw_id, &scope) else {
            return Err(ConsumerError::permanent("target_id_malformed"));
        };
        // Absent means EVERYTHING, which is a legitimate command rather than a malformed one,
        // so only a present-but-not-an-integer value is refused.
        let since = match message.payload.get(PAYLOAD_SINCE) {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .ok_or_else(|| ConsumerError::permanent("payload_since_not_an_integer"))?,
            ),
        };

        let revived = self
            .store
            .scoped(scope)
            .outbox()
            // The DELIVERY consumer's dead letters, narrowed to this target by the ordering
            // key -- which IS the target id, so the generic queue read expresses a per-target
            // replay without knowing anything about flow targets.
            .revive_dead_lettered(
                env,
                FLOW_TARGET_DELIVERY_CONSUMER,
                Some(&target_id.to_string()),
                since,
            )
            .await
            // A failed revive can succeed later, so this retries rather than dropping the
            // operator's request; the substrate's attempt budget is what bounds it.
            .map_err(|_| ConsumerError::retryable("replay_failed"))?;
        tracing::info!(
            target_id = %target_id,
            revived,
            "replayed dead-lettered flow-target deliveries"
        );
        Ok(())
    }
}

impl OutboxConsumer for FlowTargetReplayConsumer {
    fn name(&self) -> &str {
        FLOW_TARGET_REPLAY_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.replay_one(env, scope, message).await })
    }
}
