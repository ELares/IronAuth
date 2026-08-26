// SPDX-License-Identifier: MIT OR Apache-2.0
//! The first real producer for the messaging ledger (issue #111).
//!
//! # What this closes
//!
//! Issue #111 shipped an entire messaging platform with no producer. The ledger, the
//! collapse-on-dedup, the per-recipient rate limit, the suppression check, the provider
//! failover, the delivery consumer and both management endpoints all exist, are wired into the
//! shipped binary, and are covered by passing tests -- and `MessageRepo::enqueue` had ZERO
//! production callers.
//!
//! # Which door may use this path, and why it is only PART of one
//!
//! Two rules narrow it, and each one cost a round of review.
//!
//! **A payload must be safe to write down.** `message_composer` states it: a payload rides "a
//! durable queue every consumer worker reads", and the management events API returns it
//! verbatim. So a message whose body carries a token cannot use this path at all. That excludes
//! `deliver_email_otp`, `deliver_magic_link`, `deliver_new_device_notice` and
//! `deliver_recovery_cancel_notice` outright, and it excluded my first attempt, which put a
//! single-use disavowal link into the payload while claiming the ledger sealed it. `enqueue`
//! seals the RECIPIENT and nothing else.
//!
//! **And a message must carry its own body.** `DefaultComposer::compose` refuses a payload with
//! no `body` field, before template resolution, and the consumer resolves that refusal to
//! `Failed` with no provider contacted. So the producer must RENDER the message, and it can
//! only render one it knows the whole text of. That is the second rule, and it is what narrows
//! `send` from a door to part of a door.
//!
//! `send` has five call sites carrying three purposes:
//!
//! | site | purpose | rendered here? |
//! |---|---|---|
//! | `account.rs` | `AccountLinked` / `AccountUnlinked` | YES |
//! | `recovery.rs`, `advanced_recovery.rs` | `Recovery` | no |
//! | `register.rs`, `flow/registration.rs` | `Registration` | no |
//!
//! `Recovery` and `Registration` are not coarse alerts. `advanced_recovery.rs` says so in as
//! many words -- "the real transport embeds the confirm link" -- and a registration
//! verification exists to deliver a link that confirms a newly claimed identifier. A transport
//! that mailed those with no link would not be a degraded version of the right message; it
//! would break the flow, because the recipient has nothing to act on.
//!
//! So this producer fires for the two `account_*` alerts and DELEGATES everything else,
//! unchanged, to the sender it wraps. That delegation is the whole shape of the type: turning
//! messaging on must not silently retire the transport that was carrying the other four
//! methods.
//!
//! # Failure is logged, not propagated
//!
//! The seam returns nothing, and that is deliberate rather than a limitation worked around: a
//! login that has already succeeded must not fail because a NOTICE could not be queued. What
//! this must never do is fail silently, so every non-accepted outcome is recorded on the
//! observability plane with the reason, and a suppressed or collapsed send is reported as the
//! ordinary thing it is rather than as an error.

use std::sync::Arc;

use ironauth_env::Env;
use ironauth_store::message_hygiene::{dedup_key, normalize_recipient, window_index};
use ironauth_store::message_rate::RateBudget;
use ironauth_store::{Enqueued, MessageId, NewMessage, Store};

use ironauth_store::Scope;

use crate::verification::{
    EmailOtpMessage, MagicLinkMessage, NewDeviceNotice, RecoveryCancelNotice, VerificationPurpose,
    VerificationSender,
};

/// How wide the collapse window is for a notice, in seconds.
///
/// Fifteen minutes. A second notice of the SAME purpose to the same recipient inside it is the
/// same event seen twice, and mailing it twice is the failure this window exists to prevent.
/// Wider than an OTP window would be, because a notice has no code that expires.
///
/// The key is (purpose, recipient, window) and all three dimensions are asserted in
/// `tests/notice_enqueues.rs`: two purposes to one recipient do not collapse, two recipients in
/// one window do not collapse, and one recipient in two windows does not collapse.
pub const NOTICE_WINDOW_SECS: u64 = 900;

/// A compile-time floor on the window.
///
/// A window of zero or a few seconds collapses nothing, which would silently turn a retried
/// login into two mails. Asserted beside the constant rather than in a test, because a test
/// comparing the value to itself is the shape that cannot fail.
const _: () = assert!(NOTICE_WINDOW_SECS >= 60);

/// The message text for a coarse account-link alert.
///
/// A CONSTANT per purpose, with no interpolation, and the absence of a parameter is the point:
/// there is no provider, no identifier and no link to splice in, so there is nothing here that
/// could be a secret written onto a durable queue. The template wraps it (`{{ body }}`), so an
/// operator restyles the mail without this function changing.
///
/// [`None`] for a purpose this producer does not render. That is not a default and must not
/// become one: a purpose reaching here that has no body is one whose real message carries a
/// link, and inventing a linkless body for it would send a real person a mail they cannot act
/// on. The caller delegates instead.
#[must_use]
pub fn notice_body(purpose: VerificationPurpose) -> Option<&'static str> {
    match purpose {
        VerificationPurpose::AccountLinked => Some(
            "A new sign-in method was linked to your account. If this was you, no action is \
             needed. If it was not, change your password and review your sign-in methods.",
        ),
        VerificationPurpose::AccountUnlinked => Some(
            "A sign-in method was removed from your account. If this was you, no action is \
             needed. If it was not, change your password and review your sign-in methods.",
        ),
        // Both carry a link in their real message. See the module header.
        VerificationPurpose::Registration | VerificationPurpose::Recovery => None,
    }
}

/// The exact payload this producer writes, as a function of its two inputs.
///
/// Public and pure so the COMPOSER can be tested against it. The defect this exists to prevent
/// is one review already found: `notice_enqueues.rs` asserted the payload "still composes" by
/// hand-copying `message_id_local`'s charset predicate, which cannot see
/// `DefaultComposer::compose`'s separate `missing_body` refusal -- so the test passed while
/// every notice the producer wrote would have terminated `Failed` with no provider contacted.
///
/// A test in `ironauth-admin` composes THIS function's output through the real composer.
/// `ironauth-oidc` cannot do it itself; the dependency runs the other way.
#[must_use]
pub fn notice_payload(message_id: &MessageId, body: &str) -> serde_json::Value {
    // Exactly two fields. `kind` and `tenant` are inserted by the composer from its own
    // arguments and a payload may not override them; anything else here would be a value the
    // built-in template does not reference, sitting on a durable queue for no reason.
    serde_json::json!({
        "message_id": message_id.to_string(),
        "body": body,
    })
}

/// A `VerificationSender` that writes coarse account-link alerts into the messaging ledger and
/// passes everything else through.
pub struct MessagingVerificationSender {
    inner: Arc<dyn VerificationSender>,
    store: Store,
    env: Env,
    budget: RateBudget,
}

/// Hand-written because `Store` holds a connection pool and does not implement `Debug`, and
/// because a sender's debug output must never be a route to its contents: the trait requires
/// `Debug`, so the safe rendering is the type's name and the one it wraps.
impl std::fmt::Debug for MessagingVerificationSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessagingVerificationSender")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl MessagingVerificationSender {
    /// Wrap `inner`, enqueueing the purposes this renders and delegating the rest.
    ///
    /// `inner` is REQUIRED rather than optional. The four non-`send` methods and the two
    /// link-carrying purposes still need a transport, and the wiring this replaces is a
    /// wholesale swap: without delegation, enabling messaging would move `deliver_email_otp`,
    /// `deliver_magic_link`, `deliver_new_device_notice` and `deliver_recovery_cancel_notice`
    /// from "logged" to completely silent, because the trait's defaults discard them.
    ///
    /// Takes the `Store` by value: it is `Clone` and the pool inside it is reference counted,
    /// so wrapping it in another `Arc` would be a second layer of counting over the same pool.
    #[must_use]
    pub fn new(
        inner: Arc<dyn VerificationSender>,
        store: Store,
        env: Env,
        budget: RateBudget,
    ) -> Self {
        Self {
            inner,
            store,
            env,
            budget,
        }
    }

    /// Enqueue one rendered notice. Separate from [`Self::send`] so the delegation decision and
    /// the ledger write read as two things.
    async fn enqueue_notice(&self, scope: Scope, purpose: VerificationPurpose, recipient: &str) {
        let Some(body) = notice_body(purpose) else {
            // Unreachable through `send`, which checks before calling. Kept as a refusal rather
            // than an `expect` because the failure it guards against is a purpose added later
            // with no body, and mailing an empty message to a real person is worse than not
            // mailing one.
            tracing::error!(
                target: "ironauth.messaging",
                purpose = purpose.as_str(),
                "notice not queued: no body is rendered for this purpose"
            );
            return;
        };
        let Some(recipient) = normalize_recipient(recipient) else {
            // Not a deliverable address. This door fires for every VERIFIED channel, and a
            // tenant whose identifier type is a username or a phone reaches here with something
            // that is not an email. Recorded rather than swallowed, and not an error in the
            // action that triggered it.
            tracing::debug!(
                target: "ironauth.messaging",
                tenant = %scope.tenant(),
                purpose = purpose.as_str(),
                "notice not queued: the recipient is not a deliverable address"
            );
            return;
        };

        let kind = purpose.as_str();
        let now = self.env.clock().now_utc();
        let epoch_seconds = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |delta| delta.as_secs());
        let Some(key) = dedup_key(
            kind,
            &recipient,
            window_index(epoch_seconds, NOTICE_WINDOW_SECS),
        ) else {
            tracing::warn!(target: "ironauth.messaging", kind, "notice not queued: no dedup key");
            return;
        };

        let id = MessageId::generate(&self.env, &scope);
        let payload = notice_payload(&id, body);

        let outcome = self
            .store
            .scoped(scope)
            .messages()
            .enqueue(
                &self.env,
                NewMessage {
                    id: &id,
                    kind,
                    recipient: &recipient,
                    dedup_key: &key,
                },
                &payload,
                self.budget,
                epoch_seconds,
            )
            .await;

        match outcome {
            Ok(Enqueued::Accepted) => {}
            Ok(Enqueued::Collapsed) => tracing::debug!(
                target: "ironauth.messaging",
                kind,
                "notice collapsed onto one already in the window"
            ),
            Ok(other) => tracing::info!(
                target: "ironauth.messaging",
                kind,
                outcome = ?other,
                "notice was not queued"
            ),
            // The action that triggered this has already succeeded, so it must not fail over a
            // NOTICE. What it must not do is fail silently, so the reason is recorded.
            Err(error) => tracing::error!(
                target: "ironauth.messaging",
                kind,
                ?error,
                "notice could not be queued"
            ),
        }
    }
}

#[async_trait::async_trait]
impl VerificationSender for MessagingVerificationSender {
    async fn send(&self, scope: Scope, purpose: VerificationPurpose, recipient: &str) {
        if notice_body(purpose).is_some() {
            self.enqueue_notice(scope, purpose, recipient).await;
        } else {
            // A link-carrying purpose. Delegated UNCHANGED, which also keeps the registration
            // path's timing shape: `flow/registration.rs` relies on the known and unknown
            // branches taking the same work, and routing one of them through a transactional
            // write with an advisory lock would make the difference measurable from outside.
            self.inner.send(scope, purpose, recipient).await;
        }
    }

    fn deliver_email_otp(&self, message: &EmailOtpMessage<'_>) {
        self.inner.deliver_email_otp(message);
    }

    fn deliver_magic_link(&self, message: &MagicLinkMessage<'_>) {
        self.inner.deliver_magic_link(message);
    }

    fn deliver_new_device_notice(&self, message: &NewDeviceNotice<'_>) {
        self.inner.deliver_new_device_notice(message);
    }

    fn deliver_recovery_cancel_notice(&self, message: &RecoveryCancelNotice<'_>) {
        self.inner.deliver_recovery_cancel_notice(message);
    }
}
