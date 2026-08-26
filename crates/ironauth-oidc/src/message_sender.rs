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
//! # Why the new-device notice is the right first door
//!
//! It is a NOTIFICATION. The doors that carry a secret the same request also returns -- email
//! OTP, magic links -- are deliberately kept off this path, and `message_composer` says so:
//! "their bodies are delivered in the request that minted them". Wiring email OTP through the
//! collapse was tried once and withdrawn, because a 60-second window turned five
//! `advanced_recovery` tests red: the recovery flow calls `/otp/send` twice by design, and
//! collapsing the second call is correct for mail and wrong for that flow.
//!
//! A new-device notice has neither problem. Nothing returns it in a response, and a second
//! identical notice inside the window is exactly what the collapse is for.
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

use crate::verification::{NewDeviceNotice, VerificationSender};

/// The message kind a new-device notice is recorded under.
///
/// The ledger groups and rate-limits by kind, and the dedup key is built from it, so two
/// different notifications to one recipient never collapse onto each other.
pub const NEW_DEVICE_KIND: &str = "new_device";

/// How wide the collapse window is for a new-device notice, in seconds.
///
/// Fifteen minutes. A second notice for the same recipient inside it is the same event seen
/// twice -- a retried login, a second tab -- and mailing it twice is the failure this window
/// exists to prevent. It is deliberately wider than an OTP window would be, because a notice
/// has no code that expires.
pub const NEW_DEVICE_WINDOW_SECS: u64 = 900;

/// A compile-time floor on the window.
///
/// A window of zero or a few seconds collapses nothing, which would silently turn a retried
/// login into two mails. Asserted beside the constant rather than in a test, because a test
/// comparing the value to itself is the shape that cannot fail.
const _: () = assert!(NEW_DEVICE_WINDOW_SECS >= 60);

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
    fn send(
        &self,
        _scope: ironauth_store::Scope,
        _purpose: crate::verification::VerificationPurpose,
        _recipient: &str,
    ) {
        // The generic notification carries no body this ledger could deliver. It stays a no-op
        // until a door that needs it exists, rather than enqueuing an empty message so this
        // impl looks complete.
    }

    async fn deliver_new_device_notice(&self, message: &NewDeviceNotice<'_>) {
        let Some(recipient) = normalize_recipient(message.recipient) else {
            // Not a deliverable address. Recorded rather than swallowed: a notice that cannot be
            // addressed is a real fact about this account, and it is not an error in the login.
            tracing::warn!(
                target: "ironauth.messaging",
                tenant = %message.scope.tenant(),
                environment = %message.scope.environment(),
                kind = NEW_DEVICE_KIND,
                "new-device notice not queued: the recipient is not a deliverable address"
            );
            return;
        };

        let now = self.env.clock().now_utc();
        let epoch_seconds = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |delta| delta.as_secs());
        let Some(key) = dedup_key(
            NEW_DEVICE_KIND,
            &recipient,
            window_index(epoch_seconds, NEW_DEVICE_WINDOW_SECS),
        ) else {
            tracing::warn!(
                target: "ironauth.messaging",
                kind = NEW_DEVICE_KIND,
                "new-device notice not queued: no dedup key"
            );
            return;
        };

        // The payload the renderer reads. No token and no precise location: the disavowal link
        // is single-use and IS the sensitive part, so it rides the sealed payload the ledger
        // already encrypts rather than any log line.
        let payload = serde_json::json!({
            "user_agent": message.user_agent,
            "location_hint": message.location_hint,
            "disavowal_link": message.disavowal_link,
        });

        let id = MessageId::generate(&self.env, &message.scope);
        let outcome = self
            .store
            .scoped(message.scope)
            .messages()
            .enqueue(
                &self.env,
                NewMessage {
                    id: &id,
                    kind: NEW_DEVICE_KIND,
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
                kind = NEW_DEVICE_KIND,
                "new-device notice collapsed onto one already in the window"
            ),
            Ok(other) => tracing::info!(
                target: "ironauth.messaging",
                kind = NEW_DEVICE_KIND,
                outcome = ?other,
                "new-device notice was not queued"
            ),
            // A login that already succeeded must not fail because a NOTICE could not be
            // queued. Logged with the reason rather than dropped, so a ledger that is refusing
            // writes is visible instead of silent.
            Err(error) => tracing::error!(
                target: "ironauth.messaging",
                kind = NEW_DEVICE_KIND,
                ?error,
                "new-device notice could not be queued"
            ),
        }
    }
}
