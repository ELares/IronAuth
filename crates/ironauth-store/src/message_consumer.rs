// SPDX-License-Identifier: MIT OR Apache-2.0

//! The delivery consumer for the messaging island (issue #111).
//!
//! WHAT IS AND IS NOT WIRED. The shipped binary constructs this and registers it as a
//! consumer pool when `messaging.delivery_enabled` is set, so the island runs in a process
//! rather than only under test. What is still missing is a PRODUCER: nothing in production
//! enqueues a message yet, because the doors that would are waiting on the template
//! resolution that decides what a message says. So the worker is real and the queue it
//! drains is empty, which is the honest state and is one step short of a product.
//!
//! Eleven `message_*` modules decide everything about a send and, until this, not one of them
//! ran outside a unit test. [`message_prepare`](crate::message_prepare) composes suppression, rate
//! limiting, template resolution, rendering and MIME into a [`PreparedMessage`];
//! [`message_delivery`](crate::message_delivery) walks the configured providers and applies the
//! failover policy. What was missing between them was something that reads a queued row, drives
//! that pipeline, and writes down what happened. This is that.
//!
//! # Why it is an outbox consumer rather than a courier
//!
//! Issue #111 names the shape directly: "horizontally scalable worker pools, never a singleton
//! courier". Kratos's courier is a mandatory singleton and its most brittle component, and the
//! failure modes it is known for -- duplicate sends when misrun, retry-burning bugs -- are
//! properties of being a singleton with its own queue rather than of sending mail. Running as a
//! consumer on the #104 substrate means the lease, the backoff, the attempt bound and the
//! dead-letter queue are the ones every other consumer already uses, and a second replica is
//! safe for the same reason a second replica of anything else is.
//!
//! # The three outcomes, and why they are not the same outcome
//!
//! A delivery ends in one of three ways and they demand different things:
//!
//! - DELIVERED. The row resolves to `sent` and the job completes.
//! - The MESSAGE was refused (an unroutable address, refused content). Every provider is
//!   looking at the same message and will agree, so retrying buys N bounces at N vendors and
//!   damages sender reputation with each. The row resolves to `failed` and the job completes:
//!   it is finished, not deferred.
//!   
//! - Every PROVIDER was unavailable. The message is probably fine and the infrastructure is
//!   not, so this is the one that retries, and eventually dead-letters where an operator can
//!   see it.
//!
//! Collapsing the last two is the expensive mistake in both directions: retrying a rejection
//! mails a bounce repeatedly, and failing a provider outage permanently drops mail that would
//! have gone out on the next attempt.

use std::sync::Arc;

use ironauth_env::Env;

use crate::message_delivery::{MessageProvider, deliver};
use crate::message_failover::GiveUpReason;
use crate::message_prepare::PreparedMessage;
use crate::outbox::{ConsumerError, OutboxConsumer};
use crate::repository::{
    MESSAGE_DELIVERY_CONSUMER, MessageTemplateRecord, OutboxMessage, Resolution,
};
use crate::scope::Scope;
use crate::store::Store;

/// Builds the message a queued row should send.
///
/// A seam rather than a concrete step, because what it needs -- the templates, the locale, the
/// per-tenant sender identity -- is IO this module deliberately does not do, and because the
/// template hierarchy is its own change. A deployment with no templates configured renders the
/// built-in default; that is the last level of the resolution order issue #111 specifies
/// (organization, then environment, then tenant, then built-in), not a placeholder.
pub trait MessageComposer: Send + Sync + std::fmt::Debug {
    /// Compose the message for one ledger row, or explain why there is none.
    ///
    /// `recipient` has been opened from the row's sealed copy. It is the live address and must
    /// not be logged or persisted by an implementation.
    ///
    /// `configured` is every LIVE template this scope defines for this kind, strongest level
    /// first. Loaded by the CONSUMER rather than by the composer, because loading is IO and a
    /// composer that reached for a database would be untestable without one. An empty slice is
    /// the ordinary case, not a failure: it means the deployment has configured nothing, and
    /// the built-in applies, which is the LAST level of the resolution order issue #111
    /// specifies rather than a fallback bolted on beside it.
    ///
    /// # Errors
    ///
    /// A short, non-secret classification. It becomes the row's `failure_reason`, which an
    /// operator groups by, so it must be a bounded token rather than a rendered detail.
    fn compose(
        &self,
        scope: Scope,
        kind: &str,
        recipient: &str,
        payload: &serde_json::Value,
        configured: &[MessageTemplateRecord],
    ) -> Result<PreparedMessage, String>;
}

/// Drains `message.delivery` and resolves each row (issue #111 criterion 1).
pub struct MessageDeliveryConsumer {
    store: Store,
    providers: Vec<Box<dyn MessageProvider>>,
    composer: Arc<dyn MessageComposer>,
}

impl std::fmt::Debug for MessageDeliveryConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageDeliveryConsumer")
            .field("providers", &self.providers.len())
            .finish_non_exhaustive()
    }
}

impl MessageDeliveryConsumer {
    /// Build the consumer over an ORDERED provider list.
    ///
    /// The order is the failover order, and it is the operator's, not this module's: the
    /// primary is first and each subsequent one is tried only when the previous was unavailable.
    #[must_use]
    pub fn new(
        store: Store,
        providers: Vec<Box<dyn MessageProvider>>,
        composer: Arc<dyn MessageComposer>,
    ) -> Self {
        Self {
            store,
            providers,
            composer,
        }
    }
}

impl OutboxConsumer for MessageDeliveryConsumer {
    fn name(&self) -> &str {
        MESSAGE_DELIVERY_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        _env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConsumerError>> + Send + 'a>>
    {
        Box::pin(async move {
            // The job's idempotency key IS the message id: `MessageRepo::enqueue` writes it
            // that way inside the same transaction as the row, so a job can always name its
            // row and a row can always be found from its job.
            let repo = self.store.scoped(scope);
            let messages = repo.messages();
            let id = crate::id::MessageId::parse_in_scope(&message.idempotency_key, &scope)
                .map_err(|_| ConsumerError::permanent("message_id_unparseable"))?;
            let Some(record) = messages
                .by_id(&id)
                .await
                .map_err(|_| ConsumerError::retryable("ledger_read_failed"))?
            else {
                // The row is gone. Retention pruned it, or it never committed. Either way there
                // is nothing to send and nothing to resolve, and retrying re-reads the same
                // absence, so the job is finished rather than deferred.
                return Ok(());
            };
            // CLAIM IT, rather than reading the state and acting on what it said. The read
            // and the send are two steps and the window between them is real: the outbox
            // leases a job, but a lease can LAPSE, and a worker whose job was re-claimed while
            // it is still running would observe `pending` alongside the new owner and both
            // would mail. The conditional UPDATE is serialised on the row, so exactly one
            // worker wins and the loser stops here.
            if !messages
                .claim_for_delivery(&id)
                .await
                .map_err(|_| ConsumerError::retryable("claim_failed"))?
            {
                // Somebody else has it, or it is already resolved. Either way this attempt
                // sends nothing: at-least-once delivery of the JOB must not become
                // at-least-once delivery of the MAIL.
                return Ok(());
            }

            let recipient = messages
                .open_recipient(&id)
                .await
                .map_err(|_| ConsumerError::retryable("recipient_unopenable"))?;
            let Some(recipient) = recipient else {
                // A row from before migration 0155 carries no sealed recipient and never can:
                // there is no plaintext anywhere to seal it from. Retrying cannot fix that, so
                // it is recorded and finished rather than retried into the dead-letter queue.
                let _ = messages
                    .resolve(
                        &id,
                        Resolution::Failed {
                            reason: "no_sealed_recipient",
                        },
                    )
                    .await;
                return Ok(());
            };

            // The scope's own templates, strongest level first. A read failure is TRANSIENT
            // rather than a broken message, so it retries instead of resolving the row failed:
            // composing from the built-in when a configured template merely could not be READ
            // would silently send the wrong wording and record it as a success.
            let configured = repo
                .message_templates()
                .candidates_for(&record.kind)
                .await
                .map_err(|_| ConsumerError::retryable("template_read_failed"))?;

            let prepared = match self.composer.compose(
                scope,
                &record.kind,
                &recipient,
                &message.payload,
                &configured,
            ) {
                Ok(prepared) => prepared,
                Err(reason) => {
                    // Policy refused, or the template is broken. Neither improves on a retry.
                    messages
                        .resolve(&id, Resolution::Failed { reason: &reason })
                        .await
                        .map_err(|_| ConsumerError::retryable("resolve_failed"))?;
                    return Ok(());
                }
            };

            let report = deliver(&self.providers, &prepared).await;
            if report.delivered_by.is_some() {
                messages
                    .resolve(&id, Resolution::Sent)
                    .await
                    .map_err(|_| ConsumerError::retryable("resolve_failed"))?;
                return Ok(());
            }

            match report.gave_up {
                // The message is undeliverable as written. Finished, not deferred.
                Some(GiveUpReason::MessageRejected) => {
                    messages
                        .resolve(
                            &id,
                            Resolution::Failed {
                                reason: "message_rejected",
                            },
                        )
                        .await
                        .map_err(|_| ConsumerError::retryable("resolve_failed"))?;
                    Ok(())
                }
                // The infrastructure is down, not the message. Leave the row PENDING and let
                // the outbox retry: resolving it `failed` here would tell an operator the send
                // is finished while the substrate is still going to try again.
                Some(GiveUpReason::AllProvidersExhausted) => {
                    // Nothing was delivered and the substrate will try again, so the claim is
                    // RELEASED rather than left held: a row stuck in `sending` with a retry
                    // queued behind it would be claimed by nobody and finished by nobody.
                    messages
                        .release_claim(&id)
                        .await
                        .map_err(|_| ConsumerError::retryable("release_failed"))?;
                    Err(ConsumerError::retryable("all_providers_unavailable"))
                }
                // No provider configured at all. A deployment error, and retrying a deployment
                // error forever is how a queue fills up silently, so it dead-letters where
                // somebody will see it.
                Some(GiveUpReason::NoProvidersConfigured) | None => {
                    // A deployment error. The job dead-letters, so the row must not stay
                    // `sending`: released, so that configuring a provider and replaying the
                    // dead letter finds a message it can still send.
                    messages
                        .release_claim(&id)
                        .await
                        .map_err(|_| ConsumerError::retryable("release_failed"))?;
                    Err(ConsumerError::permanent("no_providers_configured"))
                }
            }
        })
    }
}
