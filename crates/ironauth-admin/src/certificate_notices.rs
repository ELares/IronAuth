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
/// held at once.
///
/// Reading one page and stopping is a defect this codebase has already written once, on the
/// delete path for these very contacts: `delete_org_contact` learned an event's category by
/// scanning ONE page of the listing, so a contact past the first page was removed, audited and
/// answered 204 while announcing NOTHING. Caught by mutation before it merged, not in
/// production. The event was DROPPED rather than mislabelled, and dropped is the failure this
/// loop would repeat: a contact past page one is never told, while the ledger records that the
/// organization was.
const PAGE: i64 = 100;

// THE LOOP RUNS TO EXHAUSTION ONLY WHILE THIS HOLDS. `list_for_organization` clamps its limit to
// `MANAGEMENT_LIST_HARD_CAP + 1`, so a `PAGE` above that would ask for more than it can get, come
// back short, and be read as the last page -- turning a documented tuning knob into a silent
// ceiling on who is told, with the ledger already recording that they were.
const _: () = assert!(
    PAGE <= ironauth_store::MANAGEMENT_LIST_HARD_CAP,
    "PAGE must stay within the store's list cap or the paging loop silently truncates"
);

/// The one notice being delivered, as every contact on the list sees it.
///
/// Bundled rather than passed as four more parameters: the certificate and the lead are the two
/// halves of the collapse key and the body is derived from both, so they travel together or a
/// caller can pass a body describing one certificate while keying the collapse on another.
struct Notice<'a> {
    /// The certificate this notice is about, as the wire spells it.
    certificate: &'a str,
    /// The threshold that was crossed.
    lead_secs: i64,
    /// The rendered text.
    body: &'a str,
}

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
        let not_after_unix_ms = payload["not_after_unix_ms"]
            .as_i64()
            .ok_or_else(|| ConsumerError::permanent("notice_without_expiry"))?;

        let now_epoch_seconds = env
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ConsumerError::permanent("clock_before_epoch"))?
            .as_secs();
        // The body states the ACTUAL remaining time, so it needs the clock this consumer reads,
        // not the lead that was crossed. Milliseconds because that is the unit the wire carries.
        let now_unix_ms = i64::try_from(now_epoch_seconds)
            .map_err(|_| ConsumerError::permanent("clock_out_of_range"))?
            * 1_000;
        let body = notice_body(connection, not_after_unix_ms, now_unix_ms);

        // TO EXHAUSTION. See `PAGE`.
        let mut deferred = 0_usize;
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
                break;
            };
            let next = CursorPosition {
                created_at_unix_micros: last.created_at_unix_micros,
                id: last.id.to_string(),
            };
            let exhausted = i64::try_from(page.len()).unwrap_or(self.page) < self.page;

            deferred += self
                .mail_page(
                    env,
                    scope,
                    &page,
                    &Notice {
                        certificate,
                        lead_secs,
                        body: &body,
                    },
                    now_epoch_seconds,
                )
                .await?;

            if exhausted {
                break;
            }
            after = Some(next);
        }

        if deferred > 0 {
            // AFTER EVERY CONTACT HAS BEEN TRIED, not at the first refusal. Returning as soon as
            // one contact is rate limited leaves every contact after them in the list unmailed
            // until that one recipient's window rolls, which is a delay they did nothing to
            // earn. Deferring the error means the others go out now and the retry re-reaches
            // only the refused ones -- the rest collapse on their dedup keys.
            return Err(ConsumerError::retryable("notice_rate_limited"));
        }
        Ok(())
    }

    /// Mail one page of contacts, returning how many were RATE LIMITED rather than sent.
    ///
    /// Split out because the whole notice would otherwise be one function past the readable
    /// length lint, and because "what happens to one contact" is the part worth naming: the four
    /// answers the ledger can give are not interchangeable, and treating them as if they were is
    /// what silently discarded notices.
    async fn mail_page(
        &self,
        env: &Env,
        scope: Scope,
        page: &[ironauth_store::OrgContact],
        notice: &Notice<'_>,
        now_epoch_seconds: u64,
    ) -> Result<usize, ConsumerError> {
        let Notice {
            certificate,
            lead_secs,
            body,
        } = *notice;
        let mut deferred = 0_usize;
        for contact in page {
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
                // An address the ledger cannot key on is skipped rather than failing the notice:
                // one unusable row must not stop the other contacts being told.
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
                    &notice_payload(&id, body),
                    self.budget,
                    now_epoch_seconds,
                )
                .await
                .map_err(|_| ConsumerError::retryable("message_enqueue_failed"))?;
            // WHAT THE LEDGER ANSWERED, and the four answers are NOT interchangeable. The first
            // version of this was a `debug_assert!` matching all four variants of a four-variant
            // enum: a tautology wearing a check, which discarded the one piece of information
            // that decides whether the customer was actually told.
            match outcome {
                Enqueued::Accepted => {}
                // Already sent this exact notice. The dedup key is (kind, recipient,
                // certificate, lead), so a collapse means a previous attempt at THIS notice got
                // through -- which is what makes retrying the whole message safe.
                Enqueued::Collapsed => tracing::debug!(
                    target: "ironauth.certificate_notice",
                    contact = %contact.id,
                    "expiry notice already sent to this contact"
                ),
                // A PERMANENT decision about the recipient, so it completes rather than
                // retrying: driving mail past a suppression is exactly what a suppression list
                // exists to prevent. Loud, because an organization whose only technical contact
                // is suppressed will not be warned and nobody would otherwise know.
                Enqueued::Suppressed { .. } => tracing::warn!(
                    target: "ironauth.certificate_notice",
                    contact = %contact.id,
                    "expiry notice NOT sent: this recipient is suppressed"
                ),
                // RETRIED, NOT DROPPED, and this is the correction that matters most here.
                //
                // Completing the message on a rate-limited send loses the notice for good: the
                // ledger row recording that this organization was told has already committed, so
                // no later pass re-announces it, and the outbox row would be marked done.
                // Measured on the budget this shipped with, an organization with two connections
                // and the three default leads had six crossings announced and three mails sent.
                //
                // The rate limiter's own doc says exceeding it BLOCKS rather than delays, which
                // is right for a login code the user will ask for again and wrong for a notice
                // nothing re-requests. Counted here and raised by the caller once every contact
                // has been tried.
                Enqueued::RateLimited { .. } => {
                    tracing::info!(
                        target: "ironauth.certificate_notice",
                        contact = %contact.id,
                        "expiry notice rate limited; retrying rather than dropping it"
                    );
                    deferred += 1;
                }
            }
        }
        Ok(deferred)
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
///
/// # It states the ACTUAL time remaining, not the lead
///
/// The first version formatted `lead_secs`, which is the threshold that was crossed rather than
/// the time left, and the two are only equal at the instant of crossing. On the first sweep of
/// any existing deployment -- the case #141 is written for, where certificates are already deep
/// inside their windows -- a certificate two days from expiry crosses the thirty-day lead and
/// the mail said "expires in about 30 days". It understated the urgency by up to the whole lead
/// and contradicted itself across the three notices about one certificate.
///
/// ALREADY EXPIRED IS ITS OWN SENTENCE, because "expires in about 0 days" reads as a rounding
/// artifact rather than an outage that has already started.
fn notice_body(connection: &str, not_after_unix_ms: i64, now_unix_ms: i64) -> String {
    const MS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;

    let remaining_ms = not_after_unix_ms - now_unix_ms;
    if remaining_ms <= 0 {
        return format!(
            "The SAML signing certificate pinned to connection {connection} HAS EXPIRED. \
             Sign-in for this organization is failing until it is replaced."
        );
    }
    // UNDER A DAY IS ITS OWN SENTENCE. Any rounding of a few hours into a whole number of days
    // is either alarming or reassuring by up to twelve hours, and this is the one range where
    // the difference decides whether somebody acts tonight.
    if remaining_ms < MS_PER_DAY {
        return format!(
            "The SAML signing certificate pinned to connection {connection} expires in LESS \
             THAN A DAY. Replace it now, or sign-in for this organization will stop working \
             when it expires."
        );
    }
    // ROUNDED TO NEAREST, not up. Rounding up was measured wrong by the test above: the clock
    // this reads is truncated to whole seconds, so a certificate exactly two days out computes
    // as a hair over two days and rendered as "3". Nearest is also the honest reading of "about
    // N days", and the sub-day case above is what rounding up was really guarding against.
    let days = (remaining_ms + MS_PER_DAY / 2) / MS_PER_DAY;
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
