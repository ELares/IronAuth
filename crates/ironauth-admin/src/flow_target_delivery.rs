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

/// What resolving a delivery's subject settled.
///
/// The SETTLED half of `FlowTargetDeliveryConsumer::resolve_subject`'s answer; a read that
/// failed for some other reason is the `Err`, not a variant here. Naming both outcomes rather
/// than returning a bool is what keeps visible the one thing [`FlowTargetDelivery`] and this
/// genuinely share: a delivery whose subject is gone is discarded exactly as one whose target
/// is deregistered is. The correspondence stops there, and deliberately: see that method.
#[derive(Debug)]
enum SubjectResolution {
    /// The subject resolved and the body now carries what a receiver needs.
    Enriched,
    /// The account was deleted before the delivery drained. Discard it.
    Gone,
}

impl<S: WebhookSender> FlowTargetDeliveryConsumer<S> {
    /// Build the consumer over a DATA-plane store and an outbound sender.
    ///
    /// The store must carry a master key, and since issue #954 that is true of EVERY delivery
    /// rather than only signed ones. THREE reads need it: opening a target's sealed signing
    /// secret, which is why a signed delivery fails RETRYABLY rather than silently going out
    /// unsigned; opening the subject's sealed identifier; and opening the subject's sealed
    /// trait document, a separate read in its own transaction. The last two are what
    /// [`Self::resolve_subject`] added on every delivery. Before that, an UNSIGNED target
    /// needed no master key at all, because `open_signing_secret` answers `Ok(None)` before it
    /// consults one.
    ///
    /// Without a master key every delivery therefore fails retryably, and because the outbox
    /// leases only the lowest-sequenced NON-TERMINAL message of an ordering group, the
    /// target's whole backlog waits behind it for the full backoff schedule. The head then
    /// dead letters, which IS terminal, and the group moves on.
    #[must_use]
    pub fn new(store: Store, sender: S) -> Self {
        Self { store, sender }
    }

    /// Resolve the delivery's subject and write what a receiver needs into `body`.
    ///
    /// Three outcomes: enriched, gone (discard the delivery), or a read that failed for some
    /// other reason (retry).
    ///
    /// What that shares with [`FlowTargetDelivery`] is the DISCARD arm and only that arm:
    /// `Gone` is discarded exactly as [`FlowTargetDelivery::Absent`] is, and for the same
    /// reason. The remaining arms do not correspond, and the difference is worth naming
    /// because it is easy to assume otherwise: a subject read that fails for another reason is
    /// RETRYABLE, whereas [`FlowTargetDelivery::Disabled`] is deliberately PERMANENT, with its
    /// own comment in `deliver_one` explaining why retrying there was the harmful choice.
    ///
    /// The caller does the logging, so the two discard paths read alike at the one place a
    /// maintainer compares them.
    ///
    /// # Errors
    ///
    /// Permanent when the payload's body is a shape this consumer cannot read:
    /// `payload_body_data_not_an_object`, `payload_body_missing_subject`, or
    /// `payload_subject_not_a_user_id` (which also covers a subject id belonging to another
    /// scope). Retryable when a store read fails for any reason other than the subject being
    /// absent: `subject_read_failed`, or `subject_traits_read_failed` for the traits read on
    /// its own.
    async fn resolve_subject(
        &self,
        scope: Scope,
        body: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<SubjectResolution, ConsumerError> {
        // The subject's identifier and traits, resolved HERE rather than carried in the
        // payload (issue #954).
        //
        // The payload keeps ids only. `outbox_messages.payload` is plaintext `jsonb`, and
        // while migration 0102 grants DELETE and a reaper exists in Rust
        // (`OutboxRepo::reap_dead_lettered`), two facts make an identifier written there
        // effectively permanent: `dead_letter_retention_secs`
        // defaults to 0, which means KEEP, and the dead-letter tail is exactly where a failed
        // delivery comes to rest; and neither reaper DELETE carries a subject predicate, so
        // no erasure request can ever reach one person's rows. Meanwhile `users.identifier`
        // is sealed by migration 0028 under the scope's envelope DEK, one per (tenant,
        // environment) and versioned, with each row recording the version that sealed it. So
        // writing it in the clear one table over would undo that seal, and would put it beyond
        // the reach of the KEK shred that is the scope-level answer to an erasure.
        //
        // Delivery-time rather than enqueue-time, as [`Self::deliver_one`] already resolves
        // `config` and the signing secret, though those and these reach it from different
        // directions. `traits` is mutable, so it inherits config's
        // property exactly: an edit between the signup and the drain is what the receiver
        // sees. `identifier` has no update path at all (it is sealed, and this repository
        // exposes no rename), so for it "now" and "then" differ only when the
        // account was DELETED in the window, which the arm below handles rather than delivers.
        //
        // A real trade rather than a free win, for the mutable half. The event's subject is
        // "this signup happened", so the signup-time traits are arguably the correct ones,
        // and they are exactly what is no longer available. Rendering now is chosen because
        // the alternative is holding them at rest forever.

        // Taken MUTABLY once and held, rather than read now and re-opened to write. Two
        // lookups would make the second refusal unreachable -- proving `data.subject` is a
        // string already proves `data` is an object -- and an unreachable arm is a label an
        // operator can never see. Holding it also keeps both refusals honest: an earlier
        // revision wrote the enrichment under an `if let`, which turned a shape this consumer
        // cannot read into a silently unenriched delivery, indistinguishable at the receiver
        // from a subject that genuinely has no traits.
        //
        // The borrow is of `*body` and the reads below borrow `self`, so they do not conflict.
        let Some(data) = body
            .get_mut("data")
            .and_then(serde_json::Value::as_object_mut)
        else {
            return Err(ConsumerError::permanent("payload_body_data_not_an_object"));
        };
        let Some(subject) = data
            .get("subject")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
        else {
            return Err(ConsumerError::permanent("payload_body_missing_subject"));
        };
        // Also the answer for an id belonging to ANOTHER scope: `parse_id` refuses it exactly
        // as it refuses a malformed one, so a payload naming a foreign subject is a permanent
        // read failure rather than a cross-tenant lookup.
        let Ok(subject_id) = self.store.scoped(scope).users().parse_id(&subject) else {
            return Err(ConsumerError::permanent("payload_subject_not_a_user_id"));
        };

        match self.store.scoped(scope).users().get(&subject_id).await {
            Ok(user) => {
                // The USER-VISIBLE projection, not the full document. The two differ by the
                // fields an operator annotated `x-ironauth: {"visibility": "admin"}`, the
                // canonical one being `risk_score`.
                //
                // The full document is right for a management read (`users::get_user_traits`)
                // and for the flow evaluator (`flow::eval_ctx`), and both say so at the call
                // site. Not every reader in the tree does: `flow::profiling`'s plan path takes
                // the full document and states nothing, while its own submit path states the
                // opposite choice two hundred lines below it. The evaluator's stated reason is that the value "never
                // reaches the end user" and "the only place it is serialized is the journey
                // REPLAY transcript, an operator and CI artifact". That is exactly the reason
                // this call site cannot borrow: here the document is serialized into an HTTP
                // body and POSTed off-platform to whatever endpoint a target names.
                //
                // So the annotation is honoured. An operator marking a field admin-only has
                // declared it is not for wider circulation, and a third-party integration is
                // wider circulation than the management API they marked it against. It also
                // fails in the safe direction: with no active schema there are no annotations
                // to read, and the full document is then also the correct answer, because
                // nothing has been declared admin-only.
                //
                // RETRYABLE on error rather than absorbed. Swallowing the read would deliver
                // a body saying this person has no traits, which a receiver cannot tell from
                // the truthful version of the same body -- so a transient database fault
                // would land as durable wrong data on the far side. `Ok(None)` is different
                // and is the honest answer: the subject genuinely carries no traits document,
                // and the key is then absent rather than null.
                let Ok(traits) = self
                    .store
                    .scoped(scope)
                    .users()
                    .traits_user_visible(&subject_id)
                    .await
                else {
                    return Err(ConsumerError::retryable("subject_traits_read_failed"));
                };
                data.insert(
                    "identifier".to_owned(),
                    serde_json::Value::String(user.identifier),
                );
                // Inserted only when there IS one, so a subject with no traits document
                // yields an ABSENT key rather than an explicit null. `json!` would have made
                // the opposite choice: `"traits": None` lowers to `Value::Null` and the key
                // is present, which tells a receiver "we looked and there are none" using the
                // same bytes a bug that dropped the read would produce.
                if let Some(traits) = traits {
                    data.insert("traits".to_owned(), traits);
                }
            }
            // The account is GONE before the delivery drained. Discard rather than deliver,
            // and rather than retry.
            //
            // Not retryable, because a deleted account does not come back and fourteen
            // attempts would delay every later delivery on this ordering key. Not a permanent
            // ERROR either, because nothing is broken: the operator deleted a user, which is
            // allowed. Discarding is also the only privacy-correct answer, and it is the
            // reason this arm matters rather than being tidiness. If the deletion was an
            // erasure request, sending that person's identifier to a third party afterwards
            // is precisely what erasure was supposed to prevent.
            //
            // Same shape as the [`FlowTargetDelivery::Absent`] arm in `deliver_one`, for the
            // same reason.
            Err(ironauth_store::StoreError::NotFound) => return Ok(SubjectResolution::Gone),
            Err(_) => return Err(ConsumerError::retryable("subject_read_failed")),
        }
        Ok(SubjectResolution::Enriched)
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

        // The subject's identifier and traits, resolved HERE rather than carried in the
        // payload (issue #954). `Gone` is discarded exactly as the target lookup's `Absent`
        // arm is; the other outcomes do not correspond, and `resolve_subject` says why.
        match self.resolve_subject(scope, &mut body).await? {
            SubjectResolution::Enriched => {}
            SubjectResolution::Gone => {
                tracing::warn!(
                    target_id = %target_id,
                    delivery = %message.idempotency_key,
                    "signup subject is gone; discarding its queued delivery rather than \
                     announcing a deleted account"
                );
                return Ok(());
            }
        }
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
