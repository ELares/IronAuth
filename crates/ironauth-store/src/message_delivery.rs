// SPDX-License-Identifier: MIT OR Apache-2.0

//! The provider seam and the delivery driver (issue #111).
//!
//! Issue #111 asks for "first-party SMTP and generic HTTP channels, plus adapters for SES,
//! `Postmark`, Resend, `SendGrid`, Mailgun and Twilio, behind ONE provider interface", with
//! "provider failover per configuration when the primary fails".
//!
//! [`MessageProvider`] is that one interface, and [`deliver`] is the driver that walks it. The
//! failover POLICY already exists in [`message_failover`](crate::message_failover) as a pure
//! function; this is what calls it. Until now that policy had no caller at all, which is the
//! correct-but-inert shape: every test passed and the behaviour never ran.
//!
//! # The interface is deliberately tiny
//!
//! One method, taking an already-prepared message and returning an
//! [`Outcome`](crate::message_failover::Outcome). Everything an adapter might want to do
//! differently (credentials, endpoints, retries WITHIN one provider, payload shape) lives
//! inside its implementation, because those differ per vendor and none of them belong in the
//! seam.
//!
//! What the seam DOES insist on is the outcome vocabulary, and that is the whole point. An
//! adapter must decide whether a failure was about the PROVIDER or about the MESSAGE, because
//! the driver fails over on one and not the other. Getting that classification wrong is how a
//! rejected recipient turns into N bounces at N vendors. The trait's documentation says so at
//! the point an adapter author reads it, which is the only place it can help them.
//!
//! # No transport here
//!
//! No SMTP, no HTTP, no vendor SDKs. Those are adapters and they are IO; this module is the
//! seam and the walk, so both stay testable without a network. An adapter that cannot be
//! written against this trait is a signal the trait is wrong, not a reason to reach around it.

use std::future::Future;
use std::pin::Pin;

use crate::message_failover::{GiveUpReason, Outcome, Step, next_step};
use crate::message_prepare::PreparedMessage;

/// A boxed future, so the trait stays object safe and a provider list can be heterogeneous.
///
/// `async fn` in traits does not give object safety, and a delivery worker holds a
/// `Vec<Box<dyn MessageProvider>>` assembled from configuration: the whole point is that the
/// concrete set is not known at compile time.
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Outcome> + Send + 'a>>;

/// One message channel: SMTP, a generic HTTP webhook, or a vendor adapter.
pub trait MessageProvider: Send + Sync {
    /// The provider's configured name, used in the delivery record and in failover reporting.
    fn name(&self) -> &str;

    /// Attempt delivery.
    ///
    /// The RETURN VALUE carries the whole contract, and an adapter author should read this
    /// before writing one:
    ///
    /// - [`Outcome::Delivered`]: the provider accepted the message.
    /// - [`Outcome::ProviderUnavailable`]: the failure was about THIS provider (a timeout, a
    ///   5xx, a rate limit, an outage, a credential problem). The driver will try the next
    ///   provider, because another one may well succeed.
    /// - [`Outcome::MessageRejected`]: the provider refused because of the MESSAGE (an unknown
    ///   recipient, a malformed address, refused content). The driver will NOT fail over, and
    ///   that is deliberate: every other provider is looking at the same message and will reach
    ///   the same conclusion, so failing over buys N bounces at N vendors and damages sender
    ///   reputation with each.
    ///
    /// When in doubt between the last two, choose [`Outcome::ProviderUnavailable`]: a needless
    /// retry at a second vendor costs one message, while a misclassified provider outage
    /// silently drops mail that would have been delivered.
    fn send<'a>(&'a self, message: &'a PreparedMessage) -> SendFuture<'a>;
}

/// What one delivery attempt did, for the record a caller persists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    /// The provider tried.
    pub provider: String,
    /// Its position in the configured order, zero-based.
    pub position: usize,
    /// What happened.
    pub outcome: Outcome,
}

/// The result of driving a message through the configured providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    /// The provider that accepted it, or [`None`] if none did.
    pub delivered_by: Option<String>,
    /// Why delivery stopped without success, or [`None`] on success.
    pub gave_up: Option<GiveUpReason>,
    /// Every attempt, in order. Kept even on success, because "delivered, but only after the
    /// primary was down" is what tells an operator a provider is failing.
    pub attempts: Vec<AttemptRecord>,
}

/// Drive `message` through `providers` until it is delivered or the policy gives up.
///
/// The walk is entirely the policy's decision: this function contributes no rules of its own,
/// it just performs the IO the policy asks for. That separation is what lets every failover
/// rule be tested without a network, and it means a change to the rules cannot be made here by
/// accident.
///
/// The loop is bounded by the provider count through the policy, which returns
/// [`Step::GiveUp`] once the attempts are exhausted. A defensive cap is included anyway: a
/// policy bug that returned `Attempt` forever would otherwise hang a delivery worker rather
/// than fail it, and a hang is far harder to notice than an error.
pub async fn deliver(
    providers: &[Box<dyn MessageProvider>],
    message: &PreparedMessage,
) -> DeliveryReport {
    let names: Vec<String> = providers
        .iter()
        .map(|provider| provider.name().to_owned())
        .collect();
    let mut attempts: Vec<AttemptRecord> = Vec::new();
    let mut outcomes: Vec<Outcome> = Vec::new();

    // One more than the provider count: enough for every legitimate walk, and a hard stop if
    // the policy ever fails to terminate.
    for _ in 0..=providers.len() {
        match next_step(&names, &outcomes) {
            Step::Attempt { provider, position } => {
                let outcome = providers[position].send(message).await;
                attempts.push(AttemptRecord {
                    provider,
                    position,
                    outcome,
                });
                outcomes.push(outcome);
            }
            Step::Delivered { provider } => {
                return DeliveryReport {
                    delivered_by: Some(provider),
                    gave_up: None,
                    attempts,
                };
            }
            Step::GiveUp(reason) => {
                return DeliveryReport {
                    delivered_by: None,
                    gave_up: Some(reason),
                    attempts,
                };
            }
        }
    }

    // Unreachable while the policy terminates. Reported rather than panicked: a delivery worker
    // is the worst place to discover a policy bug by crashing mid-send.
    DeliveryReport {
        delivered_by: None,
        gave_up: Some(GiveUpReason::AllProvidersExhausted),
        attempts,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{DeliveryReport, MessageProvider, SendFuture, deliver};
    use crate::message_failover::{GiveUpReason, Outcome};
    use crate::message_prepare::PreparedMessage;
    use crate::message_template::{Locale, TemplateLevel};

    /// A provider that returns a scripted outcome and counts its calls.
    struct Scripted {
        name: String,
        outcome: Outcome,
        calls: Mutex<usize>,
    }

    impl Scripted {
        fn new(name: &str, outcome: Outcome) -> Self {
            Self {
                name: name.to_owned(),
                outcome,
                calls: Mutex::new(0),
            }
        }
    }

    impl MessageProvider for Scripted {
        fn name(&self) -> &str {
            &self.name
        }

        fn send<'a>(&'a self, _message: &'a PreparedMessage) -> SendFuture<'a> {
            Box::pin(async move {
                *self.calls.lock().expect("not poisoned") += 1;
                self.outcome
            })
        }
    }

    fn providers(entries: Vec<Scripted>) -> Vec<Box<dyn MessageProvider>> {
        entries
            .into_iter()
            .map(|entry| Box::new(entry) as Box<dyn MessageProvider>)
            .collect()
    }

    fn message() -> PreparedMessage {
        PreparedMessage {
            recipient: "ada@example.test".to_owned(),
            subject: "Verify".to_owned(),
            message_id: "<m@mail.example.test>".to_owned(),
            body: "--b\r\n--b--\r\n".to_owned(),
            boundary: "b".to_owned(),
            dedup_key: "k".to_owned(),
            template_level: TemplateLevel::Default,
            template_locale: Locale::new("en"),
            locale_fallback_applied: false,
        }
    }

    /// A block-on that needs no runtime dependency: these futures never yield to a reactor,
    /// because every provider here is synchronous behind an async signature.
    fn run(future: impl std::future::Future<Output = DeliveryReport>) -> DeliveryReport {
        use std::task::{Context, Poll, Waker};
        // `Waker::noop` is exactly right here and hand-rolling one was needless: nothing in
        // these futures ever yields to a reactor, so no wake can occur to be missed.
        let mut context = Context::from_waker(Waker::noop());
        let mut pinned = Box::pin(future);
        loop {
            if let Poll::Ready(report) = pinned.as_mut().poll(&mut context) {
                return report;
            }
        }
    }

    #[test]
    fn the_primary_delivers_and_nothing_else_is_tried() {
        let list = providers(vec![
            Scripted::new("ses", Outcome::Delivered),
            Scripted::new("postmark", Outcome::Delivered),
        ]);
        let report = run(deliver(&list, &message()));
        assert_eq!(report.delivered_by.as_deref(), Some("ses"));
        assert_eq!(report.gave_up, None);
        assert_eq!(report.attempts.len(), 1, "the fallback must not be called");
    }

    /// Issue #111's criterion: the primary is down and the send completes via the fallback.
    #[test]
    fn an_unavailable_primary_fails_over_and_the_record_shows_it() {
        let list = providers(vec![
            Scripted::new("ses", Outcome::ProviderUnavailable),
            Scripted::new("postmark", Outcome::Delivered),
        ]);
        let report = run(deliver(&list, &message()));
        assert_eq!(report.delivered_by.as_deref(), Some("postmark"));
        assert_eq!(report.attempts.len(), 2);
        // The failed attempt is KEPT. "Delivered, but only after the primary was down" is what
        // tells an operator a provider is failing; discarding it hides an outage behind a
        // success.
        assert_eq!(report.attempts[0].provider, "ses");
        assert_eq!(report.attempts[0].outcome, Outcome::ProviderUnavailable);
        assert_eq!(report.attempts[1].position, 1);
    }

    /// A rejected message does NOT walk the provider list, and the driver is what must honour
    /// that, not just the policy.
    #[test]
    fn a_rejected_message_is_not_offered_to_the_next_provider() {
        let list = providers(vec![
            Scripted::new("ses", Outcome::MessageRejected),
            Scripted::new("postmark", Outcome::Delivered),
        ]);
        let report = run(deliver(&list, &message()));
        assert_eq!(report.delivered_by, None);
        assert_eq!(report.gave_up, Some(GiveUpReason::MessageRejected));
        assert_eq!(
            report.attempts.len(),
            1,
            "failing over here would buy a second bounce at a second vendor"
        );
    }

    #[test]
    fn exhausting_every_provider_reports_that_reason() {
        let list = providers(vec![
            Scripted::new("ses", Outcome::ProviderUnavailable),
            Scripted::new("postmark", Outcome::ProviderUnavailable),
        ]);
        let report = run(deliver(&list, &message()));
        assert_eq!(report.gave_up, Some(GiveUpReason::AllProvidersExhausted));
        assert_eq!(report.attempts.len(), 2);
    }

    #[test]
    fn no_providers_configured_attempts_nothing() {
        let report = run(deliver(&[], &message()));
        assert_eq!(report.gave_up, Some(GiveUpReason::NoProvidersConfigured));
        assert!(report.attempts.is_empty());
    }

    /// Each provider is called at most once per delivery, so the driver cannot silently retry a
    /// vendor and double-send.
    #[test]
    fn each_provider_is_called_at_most_once() {
        let ses = Scripted::new("ses", Outcome::ProviderUnavailable);
        let postmark = Scripted::new("postmark", Outcome::Delivered);
        let list = providers(vec![ses, postmark]);
        let report = run(deliver(&list, &message()));
        assert_eq!(report.attempts.len(), 2);
        // Positions are distinct, which is the observable form of "each provider once".
        let positions: Vec<usize> = report.attempts.iter().map(|a| a.position).collect();
        assert_eq!(positions, vec![0, 1]);
    }
}
