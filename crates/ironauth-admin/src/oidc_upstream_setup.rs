// SPDX-License-Identifier: MIT OR Apache-2.0

//! Creating an OpenID Connect upstream an IT admin configured from the portal
//! (issue #140 criterion 1).
//!
//! # Why this exists at all
//!
//! 0056 grants `connectors` INSERT to `ironauth_control` alone; the portal serves on
//! `ironauth_app`, which holds SELECT. Its two siblings in this crate record the same split.
//!
//! # The secret arrives SEALED, and that is the whole difference from the siblings
//!
//! `saml_connection_setup` queues a certificate, which is public material an identity provider
//! publishes. `scim_connection_setup` queues a digest, which is not a credential. This one has
//! to move an upstream CLIENT SECRET across the same queue, and an outbox row is durable,
//! replicated, and present in backups long after the connector is gone.
//!
//! So the portal seals it first -- under this scope and this connector's own id, exactly as
//! `ConnectorRepo::open_client_secret` expects to find it -- and this stores the bytes verbatim
//! through `create_presealed`. This worker never holds the plaintext and cannot: the AAD binds
//! the ciphertext to a connector id, so nothing outside that scope opens it either.
//!
//! # Two writes, and the second is what makes the first useful
//!
//! A connector nothing is bound to signs nobody in: an OIDC upstream reaches an organization
//! through an `org_connections` row, which is why the portal's SSO page reads that table to find
//! them at all. Creating the connector alone would leave an admin with a configuration that
//! exists and does nothing, so the binding follows and a failure to write it is retried.

use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    ActorRef, ConnectorCapabilities, ConnectorId, CorrelationId, NewOrgConnection,
    OIDC_UPSTREAM_SETUP_CONSUMER, OrgConnectionId, OrgConnectionUpstream, OrganizationId,
    PresealedConnector, Scope, ServiceId, Store, StoreError,
};

/// Applies queued OpenID Connect upstream setups.
pub struct OidcUpstreamSetupConsumer {
    store: Store,
}

impl OidcUpstreamSetupConsumer {
    /// A consumer writing through `store`, which MUST be the control-plane one.
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
        use base64::Engine as _;

        let payload = &message.payload;
        let organization = payload["organization_id"]
            .as_str()
            .and_then(|raw| OrganizationId::parse_in_scope(raw, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("oidc_setup_without_organization"))?;
        // THE IDS ARE MINTED BY THE PORTAL AND CARRIED, for the reason the SAML sibling gives,
        // and for a second one here: the ciphertext's AAD binds it to the CONNECTOR id, so an id
        // generated in this worker would produce a connector whose secret nothing can open.
        let connector = payload["connector_id"]
            .as_str()
            .and_then(|raw| ConnectorId::parse_in_scope(raw, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("oidc_setup_without_connector"))?;
        let binding = payload["binding_id"]
            .as_str()
            .and_then(|raw| OrgConnectionId::parse_in_scope(raw, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("oidc_setup_without_binding"))?;
        let slug = required(payload, "slug")?;
        let definition = required(payload, "definition_json")?;
        let sealed = payload["client_secret_sealed_base64"]
            .as_str()
            .and_then(|raw| base64::engine::general_purpose::STANDARD.decode(raw).ok())
            .ok_or_else(|| ConsumerError::permanent("oidc_setup_without_secret"))?;
        let dek_version = payload["client_secret_dek_version"]
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| ConsumerError::permanent("oidc_setup_without_dek_version"))?;
        let created_at_micros = payload["created_at_unix_micros"]
            .as_i64()
            .ok_or_else(|| ConsumerError::permanent("oidc_setup_without_created_at"))?;

        let acting = self.store.scoped(scope).acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        );
        match acting
            .connectors()
            .create_presealed(
                env,
                &connector,
                created_at_micros,
                PresealedConnector {
                    slug,
                    definition_json: definition,
                    client_secret_sealed: &sealed,
                    client_secret_dek_version: dek_version,
                    // WHAT THE UPSTREAM SUPPORTS IS NOT THE ADMIN'S TO DECLARE. Each of these
                    // widens what this deployment will do with an upstream's answers -- trust
                    // its `email_verified`, act on its group claims, honour its logout
                    // propagation -- and a portal link holder asserting them would be
                    // configuring how much we believe their identity provider. An operator sets
                    // them through the management API, where the decision is theirs.
                    capabilities: ConnectorCapabilities {
                        refresh: false,
                        groups: false,
                        logout_propagation: false,
                        email_verified_trust: "untrusted",
                    },
                    enabled: true,
                },
                None,
            )
            .await
        {
            Ok(()) | Err(StoreError::Conflict) => {}
            // NOTHING TO CREATE IT AGAINST. An in-scope payload reaches this only when the scope
            // itself has gone, and the answer will be the same on every attempt.
            Err(StoreError::NotFound) => {
                tracing::info!(
                    target: "ironauth.oidc_setup",
                    connector = %connector,
                    "queued upstream setup not applied: the scope no longer exists"
                );
                return Ok(());
            }
            Err(_) => return Err(ConsumerError::retryable("oidc_setup_create_failed")),
        }

        match acting
            .org_connections()
            .create(
                env,
                &binding,
                created_at_micros,
                NewOrgConnection {
                    organization_id: &organization,
                    upstream: OrgConnectionUpstream::Connector(&connector),
                    overlay_min_acr: None,
                    max_age_secs: None,
                    overlay_min_class: None,
                    capture_upstream_tokens: false,
                    enabled: true,
                },
            )
            .await
        {
            Ok(()) | Err(StoreError::Conflict) => Ok(()),
            // THE ORGANIZATION WENT AWAY between the connector landing and this, which leaves a
            // connector bound to nothing. That is untidy and it is not a fault: there is no
            // organization left to bind it to, and retrying cannot make one.
            Err(StoreError::NotFound) => {
                tracing::info!(
                    target: "ironauth.oidc_setup",
                    connector = %connector,
                    "queued upstream created but not bound: the organization no longer exists"
                );
                Ok(())
            }
            // RETRYABLE, and this is the branch that matters: a connector nothing is bound to
            // reaches no organization, so reporting the job done here would leave the admin a
            // configuration that exists and signs nobody in.
            Err(_) => Err(ConsumerError::retryable("oidc_setup_binding_failed")),
        }
    }
}

/// One required string out of the payload, or a permanent failure naming which was absent.
fn required<'a>(payload: &'a serde_json::Value, field: &str) -> Result<&'a str, ConsumerError> {
    payload[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConsumerError::permanent(format!("oidc_setup_without_{field}")))
}

impl OutboxConsumer for OidcUpstreamSetupConsumer {
    fn name(&self) -> &str {
        OIDC_UPSTREAM_SETUP_CONSUMER
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
