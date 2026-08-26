// SPDX-License-Identifier: MIT OR Apache-2.0
//! The first real producer for the messaging ledger (issue #111).
//!
//! # What this closes
//!
//! Issue #111 shipped an entire messaging platform with no producer. The ledger, the
//! collapse-on-dedup, the per-recipient rate limit, the suppression check, the provider
//! failover, the delivery consumer and both management endpoints all exist, are wired into the
//! shipped binary, and are covered by passing tests -- and `MessageRepo::enqueue` had ZERO
//! production callers. Three of that issue's acceptance criteria (failover with per-message
//! status and resend, `Message-ID` and multipart MIME, and the rate limit with its
//! `message.rate_limited` event) are implemented and asserted, and were false only because
//! nothing handed the machinery a message.
//!
//! The mechanical reason was the seam, not an oversight: `VerificationSender`'s methods were
//! all synchronous, and `enqueue` is an async transactional write. A sync method cannot await
//! one. `deliver_new_device_notice` is async now, and this is what implements it.
//!
//! # Which door may use this path, and why it is only one
//!
//! `message_composer` states the rule: a payload rides "a durable queue every consumer worker
//! reads", so "this path is for messages whose variables are safe to write down".
//!
//! Four of the five delivery doors carry a token in their body -- an OTP code, a magic link, a
//! disavowal link, a recovery-cancellation link -- and every one of them is excluded by that
//! rule. The FIFTH, `send`, carries no body variables at all: a scope, a coarse purpose, and a
//! recipient. Its body comes from a template.
//!
//! I chose the new-device notice first and was wrong: its disavowal link is a single-use token
//! that signs a user out everywhere, and putting it in the payload would have published it to
//! anything reading the outbox. The test is not "does the same request also return it" but the
//! composer's: are its variables safe to write down?
//!
//! `send` has live callers -- `account.rs` fires `AccountLinked` and `AccountUnlinked` to every
//! verified channel, purposes documented as "a coarse security alert... never an OTP".
//!
//! # Failure is logged, not propagated
//!
//! The seam returns nothing, and that is deliberate rather than a limitation worked around: a
//! login that has already succeeded must not fail because a NOTICE could not be queued. What
//! this must never do is fail silently, so every non-accepted outcome is recorded on the
//! observability plane with the reason, and a suppressed or collapsed send is reported as the
//! ordinary thing it is rather than as an error.

use ironauth_env::Env;
use ironauth_store::message_hygiene::{dedup_key, normalize_recipient, window_index};
use ironauth_store::message_rate::RateBudget;
use ironauth_store::{Enqueued, MessageId, NewMessage, Store};

use ironauth_store::Scope;

use crate::verification::{VerificationPurpose, VerificationSender};

// The message kind a notice is recorded under is the PURPOSE's own wire name, not a constant.
// The ledger groups and rate-limits by kind and the dedup key is built from it, so an
// account-linked alert and an account-unlinked alert to one recipient never collapse onto each
// other -- which they would if every notice shared one kind.

/// How wide the collapse window is for a notice, in seconds.
///
/// Fifteen minutes. A second notice of the SAME purpose to the same recipient inside it is the
/// same event seen twice, and mailing it twice is the failure this window exists to prevent.
/// Wider than an OTP window would be, because a notice has no code that expires.
///
/// The key is (purpose, recipient, window), so two DIFFERENT purposes never collapse onto each
/// other. That matters: a collapse across purposes would suppress an alert about one event
/// because an unrelated one had just fired.
pub const NOTICE_WINDOW_SECS: u64 = 900;

/// A compile-time floor on the window.
///
/// A window of zero or a few seconds collapses nothing, which would silently turn a retried
/// login into two mails. Asserted beside the constant rather than in a test, because a test
/// comparing the value to itself is the shape that cannot fail.
const _: () = assert!(NOTICE_WINDOW_SECS >= 60);

/// A `VerificationSender` that writes notices into the messaging ledger.
pub struct MessagingVerificationSender {
    store: Store,
    env: Env,
    budget: RateBudget,
}

/// Hand-written because `Store` holds a connection pool and does not implement `Debug`, and
/// because a sender's debug output must never be a route to its contents: the trait requires
/// `Debug`, so the safe rendering is the type's name and nothing else.
impl std::fmt::Debug for MessagingVerificationSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MessagingVerificationSender")
    }
}

impl MessagingVerificationSender {
    /// Build a sender that enqueues through `store`.
    ///
    /// Takes the `Store` by value: it is `Clone` and the pool inside it is reference counted,
    /// so wrapping it in another `Arc` would be a second layer of counting over the same pool.
    #[must_use]
    pub fn new(store: Store, env: Env, budget: RateBudget) -> Self {
        Self { store, env, budget }
    }
}

#[async_trait::async_trait]
impl VerificationSender for MessagingVerificationSender {
    async fn send(&self, scope: Scope, purpose: VerificationPurpose, recipient: &str) {
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
        // The payload carries NO secret, and that is the whole reason this door may use this
        // path. `message_composer` states the rule: a payload rides a durable queue every
        // consumer worker reads, so "this path is for messages whose variables are safe to write
        // down". A purpose and a message id are; a token is not, which is why the four
        // token-carrying doors are excluded.
        //
        // `message_id` is REQUIRED: without it `DefaultComposer::compose` returns
        // `Err("no_message_id")`, the consumer marks the job Failed, and every notice terminates
        // without a provider ever being contacted. The body itself comes from the template, not
        // from here.
        let payload = serde_json::json!({
            "message_id": id.to_string(),
            "purpose": kind,
        });

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
