// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pinning a certificate a renewal-portal holder pasted (issue #141 criterion 2).
//!
//! # Why this exists at all
//!
//! 0197 grants `saml_connection_certificates` INSERT to `ironauth_control` alone, and states the
//! rule it is keeping: "Pinning and unpinning are operator actions on the control plane, like the
//! connection itself... The data plane READS, because the ACS verifies there. It never writes a
//! trust anchor."
//!
//! The renewal portal is a data-plane surface. It could have been given the grant, or a
//! control-plane connection of its own, and either would have saved this file -- at the cost of
//! letting a customer-facing surface write the key every future assertion is checked against.
//! Instead the portal validates the paste and enqueues; this consumer performs the pin from the
//! plane that is allowed to.
//!
//! # It re-parses rather than trusting the row
//!
//! The portal has already parsed the certificate -- that is how the holder learns immediately
//! that their paste is not one. This parses it again from the DER on the row, because a value
//! carried across a queue is a value this worker would otherwise be trusting a previous process,
//! possibly an older build, to have got right. Parsing costs microseconds and removes the
//! question.

use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    ActorRef, CERTIFICATE_PIN_REQUEST_CONSUMER, CorrelationId, NewSamlCertificate,
    SamlCertificateId, SamlConnectionId, SamlKeyKind, Scope, ServiceId, Store,
};

/// Applies queued pin requests.
pub struct CertificatePinRequestConsumer {
    store: Store,
}

impl CertificatePinRequestConsumer {
    /// A consumer writing through `store`, which MUST be the control-plane one.
    ///
    /// The type cannot say so -- both planes are a `Store` -- so it is said here, as
    /// `certificate_expiry::run_once` says it for the same reason. Handed the data-plane store
    /// this fails on the insert, which is the grant doing its job rather than a bug.
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
        use ironauth_jose::xmldsig::XmlSigKey;
        use sha2::{Digest as _, Sha256};

        let payload = &message.payload;
        let connection = payload["saml_connection_id"]
            .as_str()
            .and_then(|raw| SamlConnectionId::parse_in_scope(raw, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("pin_request_without_connection"))?;
        let der = payload["certificate_der_base64"]
            .as_str()
            .and_then(|raw| base64::engine::general_purpose::STANDARD.decode(raw).ok())
            .ok_or_else(|| ConsumerError::permanent("pin_request_without_certificate"))?;
        // PERMANENT, NOT RETRYABLE. A row whose DER does not parse will not parse on a later
        // attempt either. The budget is `outbox.max_attempts`, which defaults to FOURTEEN over
        // roughly a day and a half -- an earlier version of this comment said five, which is what
        // that setting used to be -- so retrying would hold the dead letter back by that long,
        // and the dead letter is the only way an operator learns this happened.
        let parsed = ironauth_saml::x509::pinned(&der)
            .map_err(|_| ConsumerError::permanent("pin_request_certificate_unreadable"))?;

        let (key_kind, public_key, rsa_exponent) = match &parsed.key {
            XmlSigKey::EcdsaP256(point) => (SamlKeyKind::EcdsaP256, point.clone(), None),
            XmlSigKey::EcdsaP384(point) => (SamlKeyKind::EcdsaP384, point.clone(), None),
            XmlSigKey::Rsa { modulus, exponent } => {
                (SamlKeyKind::Rsa, modulus.clone(), Some(exponent.clone()))
            }
        };
        // OF THE WHOLE DER, which is the number an identity provider's console shows and the one
        // an operator compares against. A digest of the key alone would match nothing they see.
        let fingerprint: Vec<u8> = Sha256::digest(&der).to_vec();
        let id = SamlCertificateId::generate(env, &scope);

        match self
            .store
            .scoped(scope)
            .acting(
                ActorRef::service(ServiceId::generate(env)),
                CorrelationId::generate(env),
            )
            .saml_connections()
            .pin_certificate(
                env,
                NewSamlCertificate {
                    id: &id,
                    connection_id: &connection,
                    key_kind,
                    public_key: &public_key,
                    rsa_exponent: rsa_exponent.as_deref(),
                    certificate_der: &der,
                    fingerprint_sha256: &fingerprint,
                    // SECONDS ON THE CERTIFICATE, MICROSECONDS IN THE COLUMN. `x509::pinned`
                    // reports what the certificate encodes; the store keeps microseconds like
                    // every other instant it holds.
                    not_before_unix_micros: parsed.not_before_unix_secs * 1_000_000,
                    not_after_unix_micros: parsed.not_after_unix_secs * 1_000_000,
                },
                None,
                None,
            )
            .await
        {
            // PINNED, or ALREADY PINNED -- the same outcome, deliberately. The outbox is
            // at-least-once, so a redelivery after a successful pin is ordinary rather than
            // exceptional, and the unique-fingerprint conflict it raises means the certificate
            // this row asked for is on the connection. Reporting that as an error would
            // dead-letter a request that did exactly what it was asked to.
            Ok(()) | Err(ironauth_store::StoreError::Conflict) => Ok(()),
            // THE CONNECTION WENT AWAY between the paste and the pin. Not a fault: an operator
            // deleting a connection while somebody renews its certificate is a race the deletion
            // wins, and there is nothing to pin onto.
            Err(ironauth_store::StoreError::NotFound) => {
                tracing::info!(
                    target: "ironauth.certificate_pin",
                    connection = %connection,
                    "queued certificate not pinned: the connection no longer exists"
                );
                Ok(())
            }
            Err(_) => Err(ConsumerError::retryable("pin_failed")),
        }
    }
}

impl OutboxConsumer for CertificatePinRequestConsumer {
    fn name(&self) -> &str {
        CERTIFICATE_PIN_REQUEST_CONSUMER
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
