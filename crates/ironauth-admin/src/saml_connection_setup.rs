// SPDX-License-Identifier: MIT OR Apache-2.0

//! Creating a SAML connection an IT admin configured from the portal (issue #140 criterion 1).
//!
//! # Why this exists at all
//!
//! 0196 grants `saml_connections` INSERT to `ironauth_control` alone; the portal serves on
//! `ironauth_app`, which holds SELECT. `certificate_pin_requests` records the same split and the
//! same answer: the portal validates and enqueues, and a consumer applies from the plane that
//! may. Handing the portal the grant would let a customer-facing surface create the object every
//! sign-in through that organization is checked against.
//!
//! # It re-parses rather than trusting the row
//!
//! The portal already parsed the certificate -- that is how the admin learns immediately that
//! their paste is not one. This parses it again from the DER on the row, for the reason its
//! sibling gives: a value carried across a queue is a value this worker would otherwise be
//! trusting a previous process, possibly an older build, to have got right.
//!
//! # Two writes, and the second is not optional
//!
//! A connection with no pinned certificate refuses every response its provider sends. Creating
//! one without pinning would hand the admin something that looks finished and signs nobody in --
//! the exact failure the connection-test surface exists to explain. So the pin follows the
//! create, and a failure to pin is retried rather than reported as done.
//!
//! ONE-WAY, deliberately: a redelivery after a successful create finds the connection already
//! there and pins onto it, which is the same end state. Nothing here deletes or rewrites, so an
//! at-least-once queue cannot undo an operator's later change.

use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    ActorRef, CorrelationId, NewSamlCertificate, NewSamlConnection, OrganizationId,
    SAML_CONNECTION_SETUP_CONSUMER, SamlCertificateId, SamlConnectionId, SamlKeyKind, Scope,
    ServiceId, Store, StoreError,
};

/// Applies queued SAML connection setups.
pub struct SamlConnectionSetupConsumer {
    store: Store,
}

impl SamlConnectionSetupConsumer {
    /// A consumer writing through `store`, which MUST be the control-plane one.
    ///
    /// The type cannot say so -- both planes are a `Store` -- so it is said here, exactly as
    /// `CertificatePinRequestConsumer::new` says it. Handed the data-plane store this fails on
    /// the insert, which is the grant doing its job rather than a bug.
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
            .ok_or_else(|| ConsumerError::permanent("setup_request_without_organization"))?;
        // THE ID IS MINTED BY THE PORTAL AND CARRIED, not generated here. A redelivery has to
        // land on the SAME connection, and an id generated in this function would make every
        // retry create another one -- so an at-least-once queue would leave an organization with
        // a connection per delivery attempt, all of them unusable except whichever the admin
        // happened to pin against.
        let connection = payload["saml_connection_id"]
            .as_str()
            .and_then(|raw| SamlConnectionId::parse_in_scope(raw, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("setup_request_without_connection"))?;
        let display_name = required(payload, "display_name")?;
        let idp_entity_id = required(payload, "idp_entity_id")?;
        let idp_sso_url = required(payload, "idp_sso_url")?;
        let sp_entity_id = required(payload, "sp_entity_id")?;
        let acs_url = required(payload, "acs_url")?;
        let nameid_format = required(payload, "nameid_format")?;
        let der = payload["certificate_der_base64"]
            .as_str()
            .and_then(|raw| base64::engine::general_purpose::STANDARD.decode(raw).ok())
            .ok_or_else(|| ConsumerError::permanent("setup_request_without_certificate"))?;
        // PERMANENT, NOT RETRYABLE, as its sibling argues: DER that does not parse now will not
        // parse on the fourteenth attempt either, and retrying holds back the dead letter that
        // is the only way an operator learns this happened.
        let parsed = ironauth_saml::x509::pinned(&der)
            .map_err(|_| ConsumerError::permanent("setup_request_certificate_unreadable"))?;

        let acting = self.store.scoped(scope).acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        );
        match acting
            .saml_connections()
            .create(
                env,
                NewSamlConnection {
                    id: &connection,
                    organization_id: &organization,
                    display_name,
                    idp_entity_id,
                    idp_sso_url,
                    // THIS DEPLOYMENT'S OWN VALUES, carried from the portal because that is
                    // where they were PRINTED. The admin copied them off the page into their
                    // provider's console, and a connection created with anything else would
                    // refuse every response they then send. Reading them again here from
                    // configuration would be a second derivation of one pair of strings, and
                    // the failure when the two disagreed would be a wrong-audience error on a
                    // setup the admin performed exactly as instructed.
                    sp_entity_id,
                    acs_url,
                    // THE SAFE DEFAULTS, and not the admin's to choose. Accepting a response
                    // nobody asked for, widening the clock tolerance, or lengthening what
                    // counts as a fresh assertion are all decisions that weaken a check, and a
                    // portal link holder is not the party that gets to make them.
                    allow_unsolicited: false,
                    clock_skew_secs: 30,
                    max_assertion_age_secs: 300,
                    nameid_format,
                    attribute_mapping: &serde_json::json!({}),
                    require_encrypted_assertion: false,
                },
                None,
                None,
            )
            .await
        {
            Ok(()) => {}
            // A CONFLICT IS TWO DIFFERENT THINGS AND THEY NEED OPPOSITE ANSWERS, which an
            // earlier version of this arm got wrong by assuming the first.
            //
            // A REDELIVERY raises it on the connection ID, and the connection this row asked
            // for exists -- which is what was wanted, so the pin below proceeds.
            //
            // A SECOND CONNECTION TO THE SAME IDENTITY PROVIDER raises it on
            // `saml_connections_one_per_idp`, `UNIQUE (tenant, environment, organization,
            // idp_entity_id)`. There the row this asked for does NOT exist and never will: the
            // admin's whole setup is gone, they were answered 303, and treating it as done
            // pinned their certificate onto somebody else's connection or onto nothing. It has
            // to dead-letter, which is the only way an operator learns to tell them.
            //
            // WHICH ONE IT IS, BY READING. The store does not distinguish them and the two are
            // told apart by one fact: does the connection this row names exist?
            Err(StoreError::Conflict) => {
                match self
                    .store
                    .scoped(scope)
                    .saml_connections()
                    .find_in_org(&organization, &connection)
                    .await
                {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err(ConsumerError::permanent(
                            "setup_conflicts_with_an_existing_connection_to_that_provider",
                        ));
                    }
                    // THE READ ITSELF FAILED, which says nothing about which conflict this was.
                    Err(_) => return Err(ConsumerError::retryable("setup_conflict_unreadable")),
                }
            }
            Err(_) => return Err(ConsumerError::retryable("setup_create_failed")),
        }

        match pin_parsed(&acting, env, scope, &connection, &der, &parsed).await {
            Ok(()) | Err(StoreError::Conflict) => Ok(()),
            // THE CONNECTION WENT AWAY between the create above and this pin, which means an
            // operator deleted it in between. The deletion wins and there is nothing to pin
            // onto; retrying would recreate nothing, because the create is not repeated here.
            Err(StoreError::NotFound) => {
                tracing::info!(
                    target: "ironauth.saml_setup",
                    connection = %connection,
                    "queued setup not completed: the connection no longer exists"
                );
                Ok(())
            }
            // RETRYABLE, and this is the branch that matters: a connection with no trust anchor
            // refuses every response its provider sends. Reporting the job done here would leave
            // the admin a connection that looks configured and signs nobody in.
            Err(_) => Err(ConsumerError::retryable("setup_pin_failed")),
        }
    }
}

/// Pin one parsed certificate onto a connection.
///
/// SPLIT OUT so `apply` reads as the two writes it performs rather than as the shape of an X.509
/// key, which is the same reason its OIDC sibling reads its payload through a struct.
async fn pin_parsed(
    acting: &ironauth_store::ActingStore<'_>,
    env: &Env,
    scope: Scope,
    connection: &SamlConnectionId,
    der: &[u8],
    parsed: &ironauth_saml::x509::Pinned,
) -> Result<(), StoreError> {
    use ironauth_jose::xmldsig::XmlSigKey;
    use sha2::{Digest as _, Sha256};

    let (key_kind, public_key, rsa_exponent) = match &parsed.key {
        XmlSigKey::EcdsaP256(point) => (SamlKeyKind::EcdsaP256, point.clone(), None),
        XmlSigKey::EcdsaP384(point) => (SamlKeyKind::EcdsaP384, point.clone(), None),
        XmlSigKey::Rsa { modulus, exponent } => {
            (SamlKeyKind::Rsa, modulus.clone(), Some(exponent.clone()))
        }
    };
    // OF THE WHOLE DER, which is the number an identity provider's console shows and the one an
    // operator compares against.
    let fingerprint: Vec<u8> = Sha256::digest(der).to_vec();
    acting
        .saml_connections()
        .pin_certificate(
            env,
            NewSamlCertificate {
                id: &SamlCertificateId::generate(env, &scope),
                connection_id: connection,
                key_kind,
                public_key: &public_key,
                rsa_exponent: rsa_exponent.as_deref(),
                certificate_der: der,
                fingerprint_sha256: &fingerprint,
                // SECONDS ON THE CERTIFICATE, MICROSECONDS IN THE COLUMN.
                not_before_unix_micros: parsed.not_before_unix_secs * 1_000_000,
                not_after_unix_micros: parsed.not_after_unix_secs * 1_000_000,
            },
            None,
            None,
        )
        .await
}

/// One required string out of the payload, or a permanent failure naming which was absent.
///
/// NAMING WHICH, because these land in a dead letter an operator reads, and a bare
/// "malformed request" would tell them to go and diff two JSON documents.
fn required<'a>(payload: &'a serde_json::Value, field: &str) -> Result<&'a str, ConsumerError> {
    payload[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConsumerError::permanent(format!("setup_request_without_{field}")))
}

impl OutboxConsumer for SamlConnectionSetupConsumer {
    fn name(&self) -> &str {
        SAML_CONNECTION_SETUP_CONSUMER
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
