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

/// The rendered text of the account-LINKED alert.
///
/// Named constants rather than literals inline in the match, so a test in another crate can pin
/// the exact text without restating it -- restating is how a substring pin gets written, and a
/// substring pin let three mutations through, including one putting a live token in the body.
///
/// Pinning the CONSTANT is not `f(x) == f(x)`: what the tests assert of these two is that they
/// differ, that neither is empty, that neither looks like a link, and -- in
/// `notice_enqueues.rs` -- their exact text as a literal written out in full. This name is the
/// address, not the expectation.
pub const LINKED_NOTICE_BODY: &str = "A new sign-in method was linked to your account. If this \
     was you, no action is needed. If it was not, change your password and review your sign-in \
     methods.";

/// The rendered text of the account-UNLINKED alert. See [`LINKED_NOTICE_BODY`].
pub const UNLINKED_NOTICE_BODY: &str = "A sign-in method was removed from your account. If this \
     was you, no action is needed. If it was not, change your password and review your sign-in \
     methods.";

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
///
/// # What is asserted about these strings, and why it is not "whatever the function returns"
///
/// `notice_enqueues.rs` compared the payload's body against `notice_body(purpose)` -- the
/// function under test -- which is `f(x) == f(x)` and holds for every possible body. Three
/// mutations survived both suites: making the unlink alert EMPTY (so it ships as a blank mail,
/// walking around the `missing_body` refusal whose own doc says a delivered empty message is
/// worse than none); giving the unlink alert the LINK alert's text (telling a user a sign-in
/// method was added when one was removed); and putting a live token in the linked alert's body,
/// which is the one rule this whole module is organised around.
///
/// So the tests assert LITERAL text per purpose, that the two differ, that neither is empty,
/// and that neither contains a URL -- and they do it for BOTH purposes rather than splitting
/// the checks across two fixtures, which is how all three survived.
#[must_use]
pub fn notice_body(purpose: VerificationPurpose) -> Option<&'static str> {
    match purpose {
        VerificationPurpose::AccountLinked => Some(LINKED_NOTICE_BODY),
        VerificationPurpose::AccountUnlinked => Some(UNLINKED_NOTICE_BODY),
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
///
/// It lives there because that is where `DefaultComposer` is, not because this crate could not
/// reach it -- `ironauth-oidc` already carries `ironauth-admin` as a dev-dependency, so the
/// earlier claim here that "the dependency runs the other way" was false. The reason to keep it
/// on the admin side is narrower and still holds: the composer is the thing under test, and a
/// test of a component belongs beside it, where somebody changing `compose` will run it.
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
        // The BUDGET is rendered too, and it is not decoration. `Arc<dyn VerificationSender>`
        // erases everything else, so this is the only thing a wiring test can ask the installed
        // sender -- and "which budget did the boot path actually build it with" is a question
        // that had no answer, which is why the shipped budget was the one configuration nothing
        // ever ran. It carries no secret: a limit, a window, and a scope.
        f.debug_struct("MessagingVerificationSender")
            .field("inner", &self.inner)
            .field("budget", &self.budget)
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

    /// Try to enqueue one rendered notice, and SAY whether the caller must delegate.
    ///
    /// The return type is the point. Three review rounds each found this invariant broken on an
    /// axis nobody had enumerated -- by METHOD (the four `deliver_*` inheriting discarding
    /// defaults), by PURPOSE (a link-carrying purpose), by RECIPIENT (a verified phone has no
    /// `@`, and phone is the default), and by OUTCOME (a store fault logged and returned). Each
    /// time the fix was a new early return plus a sentence promising there were no others. That
    /// sentence has now been wrong twice.
    ///
    /// So it is not a sentence any more. Every path out returns a [`Handled`], the caller
    /// matches on it, and a new early return has to CHOOSE -- which is a question a compiler
    /// asks and a doc comment cannot.
    ///
    ///
    /// Every path out of this function either enqueues or delegates. That is not tidiness: the
    /// first version RETURNED on a recipient it could not normalize, and `account.rs` dispatches
    /// these alerts to every verified channel -- including a verified PHONE, which has no `@` and
    /// so fails `normalize_recipient`. Turning messaging on therefore moved every phone-channel
    /// alert from "logged by the transport that was there" to nothing at all, while the module
    /// header claimed everything this producer does not handle is delegated unchanged. It was
    /// the same defect review had already found on the METHOD axis, wearing the recipient axis.
    async fn enqueue_notice(
        &self,
        scope: Scope,
        purpose: VerificationPurpose,
        recipient: &str,
    ) -> Handled {
        let Some(body) = notice_body(purpose) else {
            // Unreachable through `send`, which checks before calling. Kept as a delegation
            // rather than an `expect` because the failure it guards against is a purpose added
            // later with no body, and the safe answer for one is the transport that was already
            // carrying it.
            tracing::error!(
                target: "ironauth.messaging",
                purpose = purpose.as_str(),
                "notice not queued: no body is rendered for this purpose"
            );
            return Handled::Delegate;
        };
        let Some(normalized) = normalize_recipient(recipient) else {
            // Not an email address. This door fires for every VERIFIED channel, and a tenant
            // with a verified PHONE reaches here with a number -- which is the default, since
            // `annotated_verification_kinds` reports `phone: true` for any deployment carrying
            // no `verification_addresses` annotation. Delegated, because a channel this ledger
            // cannot address is one the wrapped transport was addressing before.
            tracing::debug!(
                target: "ironauth.messaging",
                tenant = %scope.tenant(),
                purpose = purpose.as_str(),
                "notice not queued here: the recipient is not an email address; delegating"
            );
            return Handled::Delegate;
        };
        let recipient = normalized;

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
            tracing::warn!(
                target: "ironauth.messaging",
                kind,
                "notice not queued here: no dedup key; delegating"
            );
            return Handled::Delegate;
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

        // A POLICY answer is HANDLED; a FAILURE delegates. That split is the whole rule, and it
        // is not symmetry for its own sake:
        //
        // - `Collapsed` and `Suppressed` are the ledger deciding this person should not receive
        //   this mail. Delegating either hands it to a transport that mails, which is exactly
        //   what a suppression list exists to prevent.
        // - `RateLimited` is the same kind of answer, per recipient rather than per message.
        //   Routing round it defeats the anti-flood bound rather than honouring it.
        // - `Err` is not an answer at all. The ledger could not take the message, no policy
        //   decision was made about it, and the transport that carried these alerts before
        //   messaging was enabled should carry this one.
        //
        // That last arm is a real production state, not a defensive one. `database.master_key`
        // is optional and absent by default, `validate_messaging` requires only a non-empty
        // provider list, so `delivery_enabled = true` with no master key BOOTS -- and then every
        // enqueue is `StoreError::Encryption`. Before this arm, that configuration dropped one
        // hundred percent of account-link alerts on every channel while the only boot message
        // said the delivery consumer had not started, which reads as "the queue will drain
        // later".
        match outcome {
            Ok(Enqueued::Accepted) => Handled::Queued,
            Ok(Enqueued::Collapsed) => {
                tracing::debug!(
                    target: "ironauth.messaging",
                    kind,
                    "notice collapsed onto one already in the window"
                );
                Handled::Queued
            }
            Ok(other) => {
                tracing::info!(
                    target: "ironauth.messaging",
                    kind,
                    outcome = ?other,
                    "notice was not queued"
                );
                Handled::Queued
            }
            Err(error) => {
                tracing::error!(
                    target: "ironauth.messaging",
                    kind,
                    ?error,
                    "notice could not be queued; delegating"
                );
                Handled::Delegate
            }
        }
    }
}

/// What [`MessagingVerificationSender::enqueue_notice`] did, and what the caller owes.
///
/// `#[must_use]` because ignoring the answer IS the bug this type exists to prevent: three
/// review rounds each found a path that fell out of the enqueue and reached neither the ledger
/// nor the wrapped transport.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handled {
    /// The ledger answered. Accepted, collapsed, suppressed or rate limited -- all four are the
    /// ledger DECIDING, and a decision is not a reason to try somewhere else.
    Queued,
    /// This producer could not carry the message. The caller must pass it to the sender it
    /// wraps, which is what was carrying it before messaging was enabled.
    Delegate,
}

#[async_trait::async_trait]
impl VerificationSender for MessagingVerificationSender {
    async fn send(&self, scope: Scope, purpose: VerificationPurpose, recipient: &str) {
        if notice_body(purpose).is_some() {
            if self.enqueue_notice(scope, purpose, recipient).await == Handled::Delegate {
                self.inner.send(scope, purpose, recipient).await;
            }
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
