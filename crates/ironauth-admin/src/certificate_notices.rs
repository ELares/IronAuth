// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning one recorded certificate-expiry notice into mail for an organization's IT contacts
//! (issue #141).
//!
//! # Why this is a consumer and not part of the sweep
//!
//! The sweep records a notice and enqueues a row here in ONE transaction, so "the ledger says
//! this organization was told" and "somebody was actually told" cannot come apart. What it does
//! not do is resolve the contact list or take the per-recipient locks
//! [`ironauth_store::MessageRepo::enqueue`] needs: that would make announcing one certificate
//! cost a lock per contact inside a write that already races with certificate rollover.
//!
//! # Who gets it
//!
//! The `technical` contacts, and that is a POLICY DECISION rather than something derived from
//! anything. A certificate replacement is work for whoever administers the IdP; a security
//! contact watching for incidents and a billing contact are not the people who can act on it,
//! and mailing all three to be safe is how an operational alert becomes noise that gets filtered.
//! An organization that wants a security contact told can list them as technical too.

use std::pin::Pin;

use ironauth_env::Env;
use ironauth_oidc::message_sender::notice_payload;
use ironauth_store::message_hygiene::{dedup_key, normalize_recipient};
use ironauth_store::message_rate::RateBudget;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    CERTIFICATE_NOTICE_CONSUMER, CursorPosition, Enqueued, MessageId, NewMessage, OrganizationId,
    Scope, Store,
};

/// The message kind these notices are recorded under.
pub const NOTICE_KIND: &str = "saml_certificate_expiring";

/// The category of contact a certificate expiry is addressed to. See the module header: a
/// decision, not a derivation.
pub const NOTIFIED_CATEGORY: &str = "technical";

/// How many contacts are read per page while resolving the list.
///
/// A PAGE SIZE, NOT A CEILING. The loop below runs to exhaustion; this only bounds how much is
/// held at once. Reading one page and stopping is a defect this codebase has already shipped
/// once, on the delete path for these very contacts, where a contact past the first page was
/// removed while the event announcing it named the wrong category.
const PAGE: i64 = 100;

/// Collapses one notice into mail for the organization's technical contacts.
pub struct CertificateNoticeConsumer {
    store: Store,
    budget: RateBudget,
    page: i64,
}

impl CertificateNoticeConsumer {
    /// A consumer sending under `budget`.
    #[must_use]
    pub fn new(store: Store, budget: RateBudget) -> Self {
        Self {
            store,
            budget,
            page: PAGE,
        }
    }

    /// The same consumer reading `page` contacts at a time.
    ///
    /// For tests of the pagination loop, which is the whole point of the loop: the property is
    /// that a contact past the page boundary is still told, and lowering the boundary proves it
    /// with two rows instead of a hundred and one. Seeding the real page size would make the
    /// test slow enough that nobody runs it, which is how the same defect shipped on the delete
    /// path for these contacts.
    #[must_use]
    pub fn with_page_size(store: Store, budget: RateBudget, page: i64) -> Self {
        Self {
            store,
            budget,
            page: page.max(1),
        }
    }

    async fn send(
        &self,
        env: &Env,
        scope: Scope,
        message: &ironauth_store::OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let payload = &message.payload["payload"];
        let organization = payload["organization_id"]
            .as_str()
            .and_then(|id| OrganizationId::parse_in_scope(id, &scope).ok())
            .ok_or_else(|| ConsumerError::permanent("notice_without_organization"))?;
        let lead_secs = payload["lead_secs"]
            .as_i64()
            .ok_or_else(|| ConsumerError::permanent("notice_without_lead"))?;
        let connection = payload["saml_connection_id"]
            .as_str()
            .ok_or_else(|| ConsumerError::permanent("notice_without_connection"))?;
        let certificate = payload["saml_certificate_id"]
            .as_str()
            .ok_or_else(|| ConsumerError::permanent("notice_without_certificate"))?;
        let body = notice_body(connection, lead_secs);

        let now_epoch_seconds = env
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ConsumerError::permanent("clock_before_epoch"))?
            .as_secs();

        // TO EXHAUSTION. See `PAGE`.
        let mut after = None;
        loop {
            let page = self
                .store
                .scoped(scope)
                .org_contacts()
                .list_for_organization(&organization, self.page, after.as_ref())
                .await
                .map_err(|_| ConsumerError::retryable("contact_read_failed"))?;
            let Some(last) = page.last() else {
                // NO CONTACTS IS A COMPLETED NOTICE, not a failure. An organization that has
                // listed nobody is the common case before anyone sets contacts up, and
                // dead-lettering those would fill an operator's queue with work nobody can do.
                return Ok(());
            };
            let next = CursorPosition {
                created_at_unix_micros: last.created_at_unix_micros,
                id: last.id.to_string(),
            };
            let exhausted = i64::try_from(page.len()).unwrap_or(self.page) < self.page;

            for contact in &page {
                if contact.category != NOTIFIED_CATEGORY {
                    continue;
                }
                let (Some(recipient), Some(key)) = (
                    normalize_recipient(&contact.email),
                    dedup_key(
                        NOTICE_KIND,
                        &contact.email,
                        notice_discriminator(certificate, lead_secs),
                    ),
                ) else {
                    // An address the ledger cannot key on is skipped rather than failing the
                    // notice: one unusable row must not stop the other contacts being told.
                    tracing::warn!(
                        target: "ironauth.certificate_notice",
                        contact = %contact.id,
                        "contact skipped: the address will not normalize"
                    );
                    continue;
                };
                let id = MessageId::generate(env, &scope);
                let outcome = self
                    .store
                    .scoped(scope)
                    .messages()
                    .enqueue(
                        env,
                        NewMessage {
                            id: &id,
                            kind: NOTICE_KIND,
                            recipient: &recipient,
                            dedup_key: &key,
                        },
                        &notice_payload(&id, &body),
                        self.budget,
                        now_epoch_seconds,
                    )
                    .await
                    .map_err(|_| ConsumerError::retryable("message_enqueue_failed"))?;
                // Collapsed, Suppressed and RateLimited are the ledger DECIDING about this
                // recipient, not failing on them. Retrying past a suppression is what a
                // suppression list exists to prevent.
                debug_assert!(matches!(
                    outcome,
                    Enqueued::Accepted
                        | Enqueued::Collapsed
                        | Enqueued::Suppressed { .. }
                        | Enqueued::RateLimited { .. }
                ));
            }

            if exhausted {
                return Ok(());
            }
            after = Some(next);
        }
    }
}

/// What makes two expiry notices the same notice, for the collapse.
///
/// `dedup_key`'s third argument is a DISCRIMINATOR, not a duration: two sends collapse when the
/// kind, the recipient and this number all agree. Its usual caller passes a time window index,
/// because "do not send the same verification code twice in a minute" is a question about time.
/// This one is not. The thing that must not be said twice here is one CERTIFICATE at one LEAD,
/// and it must not be said twice ever, not merely twice in an hour.
///
/// AN EARLIER VERSION PASSED THE LEAD ALONE, which reads plausibly and is wrong in a way no test
/// here caught: the key then contained no certificate, so an organization with two SAML
/// connections crossing the same threshold on the same day was told about ONE of them and never
/// about the other. Losing an expiry warning is the exact failure this feature exists to
/// prevent, so the identity it collapses on names the certificate.
fn notice_discriminator(certificate: &str, lead_secs: i64) -> u64 {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    // Length-prefixed for the reason `dedup_key` gives: joined with a separator, a crafted
    // identifier could collide with a different (certificate, lead) pair and suppress its mail.
    hasher.update(
        u64::try_from(certificate.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(certificate.as_bytes());
    hasher.update(lead_secs.to_be_bytes());
    let digest = hasher.finalize();
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(head)
}

/// The text a contact receives.
fn notice_body(connection: &str, lead_secs: i64) -> String {
    let days = lead_secs / (24 * 60 * 60);
    format!(
        "The SAML signing certificate pinned to connection {connection} expires in about \
         {days} days. Replace it before then, or sign-in for this organization will stop \
         working when it expires."
    )
}

impl OutboxConsumer for CertificateNoticeConsumer {
    fn name(&self) -> &str {
        CERTIFICATE_NOTICE_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a ironauth_store::OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(self.send(env, scope, message))
    }
}
