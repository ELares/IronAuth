// SPDX-License-Identifier: MIT OR Apache-2.0

//! Creating a provisioning connection an IT admin configured from the portal
//! (issue #140 criterion 1).
//!
//! # Why this exists at all
//!
//! 0183 grants `scim_connections` INSERT to `ironauth_control` alone; the portal serves on
//! `ironauth_app`, which holds SELECT. `saml_connection_setup` beside this records the same
//! split and the same answer: the portal validates and enqueues, and a consumer applies from the
//! plane that may.
//!
//! # It never sees the token
//!
//! Unlike its SAML sibling, which carries a certificate this worker re-parses, the row here
//! carries a DIGEST and nothing else. The portal minted the token, showed it to the admin who
//! asked for it, and kept no copy; a queue is the last place a live bearer credential should sit,
//! because the row is durable, read by every replica, and survives in backups longer than the
//! connection does.
//!
//! SO THERE IS NOTHING TO VALIDATE HERE, and that is a real difference rather than an oversight.
//! The digest's SHAPE is all this can check, and the column's own CHECK constraint does that
//! better than a Rust guard would.

use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    ActorRef, CorrelationId, NewScimConnection, OrganizationId, SCIM_CONNECTION_SETUP_CONSUMER,
    ScimConnectionId, Scope, ServiceId, Store, StoreError,
};

/// Applies queued provisioning-connection setups.
pub struct ScimConnectionSetupConsumer {
    store: Store,
}

impl ScimConnectionSetupConsumer {
    /// A consumer writing through `store`, which MUST be the control-plane one.
    ///
    /// The type cannot say so -- both planes are a `Store` -- so it is said here, as its two
    /// siblings say it. Handed the data-plane store this fails on the insert, which is the grant
    /// doing its job rather than a bug.
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
            .and_then(|raw| OrganizationId::parse_in_scope(raw, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("scim_setup_without_organization"))?;
        // THE ID IS MINTED BY THE PORTAL AND CARRIED, for the reason its SAML sibling gives and
        // for one more that is specific to this surface: the token the admin was already shown
        // NAMES this id in its own `{scim_id}.{secret}` first half. An id generated here would
        // make the token they are holding refer to a connection that does not exist, and
        // `authenticate` would refuse it forever with nothing on any page to explain why.
        let connection = payload["scim_connection_id"]
            .as_str()
            .and_then(|raw| ScimConnectionId::parse_in_scope(raw, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("scim_setup_without_connection"))?;
        let display_name = required(payload, "display_name")?;
        let provider = required(payload, "provider")?;
        let token_digest = required(payload, "token_digest")?;

        match self
            .store
            .scoped(scope)
            .acting(
                ActorRef::service(ServiceId::generate(env)),
                CorrelationId::generate(env),
            )
            .scim_connections()
            .create(
                env,
                NewScimConnection {
                    id: &connection,
                    organization_id: &organization,
                    display_name,
                    provider,
                    token_digest,
                    // NO HORIZON. `create` is the ONLY path that writes
                    // `scim_connections.expires_at` and nothing UPDATES it -- 0183 grants the
                    // control role `UPDATE (revoked_at, updated_at)` and no more -- so once a
                    // connection carries one, that date is fixed and `rotate_token` refuses the
                    // connection after it passes. A portal form setting one would be handing a
                    // customer a provisioning connection with a one-way expiry and no remedy but
                    // asking their vendor for a replacement. An operator may still choose that
                    // through the management API, where the decision is theirs.
                    expires_at_unix_micros: None,
                },
                None,
            )
            .await
        {
            // CREATED, or ALREADY THERE. The outbox is at-least-once, so a redelivery after a
            // successful create is ordinary, and the conflict it raises means the connection
            // this row asked for exists -- which is what the admin's token needs.
            Ok(()) | Err(StoreError::Conflict) => Ok(()),
            // THE ORGANIZATION WENT AWAY between the form and the worker, which is the only way
            // an in-scope payload produces this. Retrying it for the fourteen attempts the
            // outbox allows delays the dead letter by roughly a day and a half, and the answer
            // will be the same every time -- the SAML sibling makes the same argument about a
            // certificate that will never parse.
            Err(StoreError::NotFound) => {
                tracing::info!(
                    target: "ironauth.scim_setup",
                    connection = %connection,
                    "queued provisioning setup not applied: the organization no longer exists"
                );
                Ok(())
            }
            Err(_) => Err(ConsumerError::retryable("scim_setup_create_failed")),
        }
    }
}

/// One required string out of the payload, or a permanent failure naming which was absent.
fn required<'a>(payload: &'a serde_json::Value, field: &str) -> Result<&'a str, ConsumerError> {
    payload[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConsumerError::permanent(format!("scim_setup_without_{field}")))
}

impl OutboxConsumer for ScimConnectionSetupConsumer {
    fn name(&self) -> &str {
        SCIM_CONNECTION_SETUP_CONSUMER
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
