// SPDX-License-Identifier: MIT OR Apache-2.0

//! The event ENVELOPE and the fan-out that turns one domain event into deliveries
//! (issues #105, #108).
//!
//! The webhook chain had every stage but its first. #554 shipped the signing contract,
//! #555 endpoints and secrets, #556 rotation, #557 the asymmetric scheme, #558 dispatch,
//! #559 the dead-letter view and replay, #560 attempt history, #561 auto-disable, and
//! `grep -rn WEBHOOK_DELIVERY_CONSUMER` still showed nothing that ENQUEUED a delivery. An
//! operator could configure the whole subsystem and no event would ever arrive.
//!
//! This is the producer, for one event type.
//!
//! ## Why the envelope is #108's and not a new one
//!
//! #108 owns the catalogue: 100+ typed events, a JSON Schema registry, generated docs and
//! a CI validation gate. That is several changes and it is blocked on #107. What it also
//! specifies, in one paragraph, is the ENVELOPE every event shares: id, type, payload
//! schema version, occurred-at, tenant and environment, payload.
//!
//! That envelope is built here, exactly as specified, for `user.created`. Implementing the
//! shape #108 already fixed is forward compatible by construction: the catalogue adds
//! types and a registry around this envelope rather than replacing it. Inventing a
//! different one now, or waiting for the whole catalogue, are the two ways to get this
//! wrong.
//!
//! ## Two stages, and why the ordering key differs from the logout fan-out
//!
//! A domain write emits ONE message; this consumer explodes it into one delivery per
//! ACTIVE endpoint. That is the #104 shape the back-channel logout fan-out established,
//! for the same reason: a create must not enqueue a message per endpoint inside its own
//! transaction, or its cost grows with how many webhooks happen to be registered.
//!
//! The logout fan-out gives every delivery a SINGLETON ordering group so no relying party
//! waits behind another. Webhook deliveries key on the ENDPOINT instead, deliberately: a
//! receiver is promised its events in order, the dead-letter view and the replay in #559
//! both narrow by `ordering_key = endpoint`, and a singleton group would leave both of
//! those surfaces addressing nothing.

use std::future::Future;
use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    NewOutboxMessage, OutboxMessage, Scope, Store, WEBHOOK_DELIVERY_CONSUMER,
    WEBHOOK_EVENT_CONSUMER,
};

/// The event type emitted when an operator creates a user.
pub const USER_CREATED: &str = "user.created";
/// The wire type a management delete emits.
pub const USER_DELETED: &str = "user.deleted";
/// The wire type a management PATCH emits, once per field it wrote.
pub const USER_UPDATED: &str = "user.updated";
/// The wire type creating an organization emits.
pub const ORGANIZATION_CREATED: &str = "organization.created";
/// The wire type deleting an organization emits.
pub const ORGANIZATION_DELETED: &str = "organization.deleted";
/// The wire type deleting a client emits.
pub const CLIENT_DELETED: &str = "client.deleted";

/// The payload schema version every event in this envelope carries.
///
/// One, and it is a FIELD rather than a constant folded into the type name, because #108's
/// versioning policy is that additive changes extend a version and breaking changes mint a
/// new one. A consumer pins this and an upgrade cannot silently change what it receives.
pub const PAYLOAD_SCHEMA_VERSION: u32 = 1;

/// Build the envelope a receiver is sent, to the shape issue #108 specifies.
///
/// `occurred_at_unix_ms` is the instant the DOMAIN write happened, taken from the clock
/// seam by the caller rather than read here, so the envelope records when the thing
/// happened rather than when this function ran.
#[must_use]
pub fn envelope(
    id: &str,
    event_type: &str,
    scope: Scope,
    occurred_at_unix_ms: i64,
    payload: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "type": event_type,
        "payload_schema_version": PAYLOAD_SCHEMA_VERSION,
        "occurred_at_unix_ms": occurred_at_unix_ms,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "payload": payload,
    })
}

/// An event a producer has minted and not yet handed to the write that emits it.
///
/// It owns its strings so a handler can build it in one statement and borrow a
/// [`DomainEvent`] from it at the call that needs one. Without this every producer repeats
/// the same three-field literal beside its store call, which is where the id and the
/// envelope drift apart.
pub struct PendingEvent {
    /// The event's stable id, which becomes the `webhook-id` of every delivery.
    pub id: String,
    /// The entity the event is about; two events about one subject stay ordered.
    pub subject: String,
    /// The envelope a receiver is sent.
    pub envelope: serde_json::Value,
}

impl PendingEvent {
    /// Borrow this as the carrier an emitting store write takes.
    #[must_use]
    pub fn domain_event(&self) -> ironauth_store::DomainEvent<'_> {
        ironauth_store::DomainEvent {
            id: &self.id,
            subject: &self.subject,
            envelope: &self.envelope,
        }
    }
}

/// The key under which the fan-out reads the event's own id off its envelope.
const ENVELOPE_ID: &str = "id";
/// The key under which the fan-out reads the event's type off its envelope.
const ENVELOPE_TYPE: &str = "type";

/// The consumer that explodes one domain event into one delivery per active endpoint.
pub struct WebhookFanoutConsumer {
    store: Store,
}

impl WebhookFanoutConsumer {
    /// Build the consumer over a DATA-plane store.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Explode ONE event.
    async fn explode(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let event_id = message
            .payload
            .get(ENVELOPE_ID)
            .and_then(serde_json::Value::as_str)
            // Permanent: no retry adds a field to a row that is already written.
            .ok_or_else(|| ConsumerError::permanent("envelope_missing_id"))?
            .to_owned();
        let event_type = message
            .payload
            .get(ENVELOPE_TYPE)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ConsumerError::permanent("envelope_missing_type"))?
            .to_owned();

        // Validate against the CATALOG (issue #108) before a single delivery is created.
        //
        // PERMANENT, never retryable: no number of retries turns an unregistered type into
        // a registered one or fixes a payload that violates its schema. Retrying would burn
        // the budget and land the same event in every endpoint's dead letters.
        //
        // Here rather than at the producer, because this is the ONE choke point every
        // event passes through on the way out. A check at each producer is a check the next
        // producer forgets, and the failure of that omission is an event on the wire that
        // no consumer can parse.
        if let Err(error) = ironauth_store::event_catalog::validate_event(&message.payload) {
            tracing::error!(
                event_type = %event_type,
                ?error,
                "an event failed catalog validation and was not delivered to any endpoint"
            );
            return Err(ConsumerError::permanent("event_failed_catalog_validation"));
        }

        let scoped = self.store.scoped(scope);
        let endpoints = scoped
            .webhook_endpoints()
            .list()
            .await
            .map_err(|_| ConsumerError::retryable("endpoint_read_failed"))?;
        // PAUSED endpoints are skipped at fan-out rather than enqueued and dropped later.
        // A paused endpoint is one an operator turned off, so an event that arrives while
        // it is off was never promised to it; this differs from an endpoint that pauses
        // AFTER a delivery is queued, which dead-letters and stays replayable (#561).
        // ACTIVE, and SUBSCRIBED to this type. The subscription is applied HERE rather
        // than at delivery, because #106 requires that a non-matching event never has a
        // delivery attempt created for it at all: filtering later would still queue the
        // message, still consume its retry budget, and still show up in that endpoint's
        // dead letters as work an operator never asked for.
        //
        // `None` is no filter and receives everything, which is what every endpoint
        // registered before 0116 already did. Matching is EXACT: a wildcard grammar
        // without the catalogue (#108) to validate against would let a typo match nothing
        // and look identical to a filter that works.
        let live: Vec<_> = endpoints
            .into_iter()
            .filter(|e| e.active)
            .filter(|e| {
                e.event_types
                    .as_ref()
                    .is_none_or(|types| types.iter().any(|t| t == &event_type))
            })
            .collect();
        if live.is_empty() {
            // Nothing to deliver to is a completed event, not a failure. An environment
            // with no endpoints is the common case and must not accumulate dead letters.
            return Ok(());
        }

        // Built first and borrowed by the messages, because `NewOutboxMessage` holds
        // `&str` and the fan-out must be ONE slice so it commits atomically.
        let keys: Vec<String> = live
            .iter()
            .map(|endpoint| format!("{event_id}:{endpoint}", endpoint = endpoint.id))
            .collect();
        let endpoint_ids: Vec<String> = live.iter().map(|e| e.id.to_string()).collect();
        let messages: Vec<NewOutboxMessage<'_>> = keys
            .iter()
            .zip(&endpoint_ids)
            .map(|(key, endpoint_id)| NewOutboxMessage {
                consumer: WEBHOOK_DELIVERY_CONSUMER,
                // `{event}:{endpoint}`. It becomes the `webhook-id` header, so it is
                // stable across every retry AND distinct per endpoint: two endpoints
                // receiving one event are two deliveries, and a receiver that saw one of
                // them must not deduplicate the other away.
                idempotency_key: key,
                // The ENDPOINT, which is what the dead-letter view and the replay both
                // narrow by, and what promises a receiver its events in order.
                ordering_key: endpoint_id,
                payload: serde_json::json!({
                    "endpoint_id": endpoint_id,
                    "body": message.payload,
                }),
            })
            .collect();
        scoped
            .outbox()
            .enqueue_all(env, &messages)
            .await
            .map_err(|_| ConsumerError::retryable("fanout_enqueue_failed"))?;
        Ok(())
    }
}

impl OutboxConsumer for WebhookFanoutConsumer {
    fn name(&self) -> &str {
        WEBHOOK_EVENT_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.explode(env, scope, message).await })
    }
}
