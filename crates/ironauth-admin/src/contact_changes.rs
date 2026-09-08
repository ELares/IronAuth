// SPDX-License-Identifier: MIT OR Apache-2.0

//! Applying a contact change made from the portal (issue #141 criterion 3).
//!
//! # Why this exists
//!
//! 0207 grants `org_contacts` INSERT, and the soft-delete `UPDATE (updated_at, deleted_at)`, to
//! `ironauth_control` alone; `ironauth_app` -- the role the portal serves on -- holds SELECT.
//! The portal therefore validates and enqueues, and this applies from the plane that may write.
//! Same shape and same reasoning as `certificate_pin_requests`.
//!
//! # Both directions on one queue
//!
//! Adding and removing share a consumer because they must not overtake each other: removing a
//! contact and adding them back is a different outcome from the reverse. The outbox serialises
//! per ordering key and the portal keys on the ORGANIZATION, so one customer's changes apply in
//! order while another's never wait behind them.

use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    ActorRef, CONTACT_CHANGE_CONSUMER, CorrelationId, NewOrgContact, OrgContactId, OrganizationId,
    Scope, ServiceId, Store, StoreError,
};

/// Applies queued contact changes.
pub struct ContactChangeConsumer {
    store: Store,
}

impl ContactChangeConsumer {
    /// A consumer writing through `store`, which MUST be the control-plane one.
    ///
    /// The type cannot say so -- both planes are a `Store` -- so it is said here. Handed the
    /// data-plane store this fails on every write, which is the grant doing its job.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    async fn apply(
        &self,
        env: &Env,
        scope: Scope,
        message: &ironauth_store::OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let payload = &message.payload;
        let organization = payload["organization_id"]
            .as_str()
            .and_then(|id| OrganizationId::parse_in_scope(id, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("change_without_organization"))?;
        let now = i64::try_from(
            env.clock()
                .now_utc()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ConsumerError::permanent("clock_before_epoch"))?
                .as_micros(),
        )
        .map_err(|_| ConsumerError::permanent("clock_out_of_range"))?;

        let acting = self.store.scoped(scope).acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        );
        match payload["action"].as_str() {
            Some("add") => {
                let (Some(display_name), Some(email), Some(category)) = (
                    payload["display_name"].as_str(),
                    payload["email"].as_str(),
                    payload["category"].as_str(),
                ) else {
                    return Err(ConsumerError::permanent("add_without_fields"));
                };
                // RE-CHECKED HERE. The portal checked before queueing so the person was told
                // while looking at the form; this is the write, and a value carried across a
                // queue is a value this would otherwise be trusting a previous process --
                // possibly an older build -- to have got right.
                if !ironauth_store::contact_is_acceptable(display_name, email, category) {
                    return Err(ConsumerError::permanent("add_not_acceptable"));
                }
                let id = OrgContactId::generate(env, &scope);
                match acting
                    .org_contacts()
                    .add(
                        env,
                        NewOrgContact {
                            id: &id,
                            organization_id: &organization,
                            display_name,
                            email,
                            category,
                            created_at_micros: now,
                        },
                    )
                    .await
                {
                    // ADDED, or ALREADY LISTED -- the same outcome, deliberately. The
                    // organization has this address either way, which is what the request asked
                    // for, and a redelivery after a successful add reaches the conflict arm
                    // because the outbox is at-least-once by design.
                    Ok(()) | Err(StoreError::Conflict) => Ok(()),
                    // The store refused what the portal accepted. Permanent, because the same
                    // bytes will be refused on every attempt, and loud enough to notice: the two
                    // checks disagreeing means one of them is wrong.
                    Err(StoreError::Invalid) => {
                        Err(ConsumerError::permanent("add_refused_by_store"))
                    }
                    Err(_) => Err(ConsumerError::retryable("add_failed")),
                }
            }
            Some("remove") => {
                let contact = payload["contact_id"]
                    .as_str()
                    .and_then(|id| OrgContactId::parse_in_scope(id, &scope).ok())
                    .ok_or_else(|| ConsumerError::permanent("remove_without_contact"))?;
                match acting
                    .org_contacts()
                    .remove(env, &organization, &contact, now)
                    .await
                {
                    // `remove` reports whether a row changed. FALSE IS SUCCESS: the contact is
                    // not on this organization's list, which is what was asked for.
                    // REMOVED, or NOT THERE -- one outcome. `remove` reports whether a row
                    // changed, and false means the contact is not on this organization's list,
                    // which is what was asked for.
                    //
                    // NOT-FOUND JOINS THEM, and getting that wrong is what the cross-organization
                    // test caught. `remove` answers a uniform not-found for a handle belonging to
                    // another organization -- the right refusal, because telling the two apart
                    // would let a portal holder discover a handle exists elsewhere. Treated as a
                    // fault it made the consumer retry a row that can never succeed, for the
                    // whole attempt budget, then dead-letter: a queue backed up and an operator
                    // paged, over a request the system had refused correctly.
                    Ok(_) | Err(StoreError::NotFound) => Ok(()),
                    Err(_) => Err(ConsumerError::retryable("remove_failed")),
                }
            }
            _ => Err(ConsumerError::permanent("change_without_action")),
        }
    }
}

impl OutboxConsumer for ContactChangeConsumer {
    fn name(&self) -> &str {
        CONTACT_CHANGE_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a ironauth_store::OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(self.apply(env, scope, message))
    }
}
