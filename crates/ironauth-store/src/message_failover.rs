// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provider failover policy (issue #111).
//!
//! Issue #111 requires that "with the primary provider failing, sends complete via the
//! configured fallback". This is the decision procedure for that, as a pure function of the
//! configured provider order and what has been attempted: no clock, no network, no store.
//!
//! # A permanent failure must NOT fail over, and that is the whole point
//!
//! The temptation is to treat every failure the same and walk the provider list. That is wrong
//! in a way that gets worse the more providers you configure.
//!
//! A provider rejecting a message for a REASON INTRINSIC TO THE MESSAGE (the recipient does not
//! exist, the address is malformed, the content was refused) will be joined in that judgement by
//! every other provider, because they are all looking at the same message. Trying the fallback
//! achieves nothing except sending the same rejected message to another vendor, which costs
//! money, burns reputation with a second provider, and turns one hard bounce into N.
//!
//! A provider failing for a reason intrinsic to the PROVIDER (a timeout, a 500, a rate limit,
//! an outage) says nothing about the message, and that is exactly when the fallback should run.
//!
//! So [`Outcome`] distinguishes them, and [`next_step`] fails over on one and not the other.
//! Getting this backwards produces a system that looks resilient in a demo and multiplies
//! bounces in production.

/// What one delivery attempt produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The provider accepted the message. Nothing further is attempted.
    Delivered,
    /// The provider failed for a reason about ITSELF: a timeout, a 5xx, a rate limit, an
    /// outage. This says nothing about the message, so another provider may well succeed.
    ProviderUnavailable,
    /// The provider refused for a reason about the MESSAGE: an unknown recipient, a malformed
    /// address, refused content. Every other provider is looking at the same message and will
    /// reach the same conclusion, so failing over would just buy N bounces instead of one.
    MessageRejected,
}

/// What to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Attempt delivery through this provider.
    Attempt {
        /// The provider's configured name.
        provider: String,
        /// Its position in the configured order, zero-based. Carried so a caller can record
        /// "this went out via the second fallback" without recomputing it.
        position: usize,
    },
    /// The message was delivered. Recorded so a caller can distinguish success from give-up
    /// without inspecting the history again.
    Delivered {
        /// The provider that accepted it.
        provider: String,
    },
    /// Stop. Carries WHY, because the two reasons demand different operator responses.
    GiveUp(GiveUpReason),
}

/// Why no further attempt will be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiveUpReason {
    /// A provider judged the message itself undeliverable. Failing over is pointless: the next
    /// provider sees the same message. This belongs on a suppression or bounce path, not in a
    /// retry queue.
    MessageRejected,
    /// Every configured provider was tried and each was unavailable. THIS one belongs in the
    /// dead-letter queue and is worth alerting on: the message is probably fine and the
    /// infrastructure is not.
    AllProvidersExhausted,
    /// No provider is configured at all, which is a deployment error rather than a send
    /// failure. Distinguished so it cannot hide inside "exhausted", which would read as an
    /// outage and send an operator looking in the wrong place.
    NoProvidersConfigured,
}

impl GiveUpReason {
    /// A stable, value-free description.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MessageRejected => {
                "a provider judged the message undeliverable, so failover would not help"
            }
            Self::AllProvidersExhausted => {
                "every configured provider was unavailable, so the message is dead lettered"
            }
            Self::NoProvidersConfigured => {
                "no message provider is configured, which is a deployment error"
            }
        }
    }
}

/// Decide the next step from the configured provider order and the outcomes so far.
///
/// `providers` is in configured preference order, primary first. `attempts` is the outcome of
/// each attempt made so far, in order, so `attempts[i]` is the result of trying `providers[i]`.
///
/// The function is TOTAL and takes no clock: the same inputs always give the same answer, which
/// is what lets a worker resume a partially attempted send after a restart and reach the same
/// decision the previous worker would have.
///
/// More attempts than providers is treated as exhaustion rather than a panic. It should not
/// happen, and a delivery worker is the wrong place to discover a bookkeeping bug by crashing.
#[must_use]
pub fn next_step(providers: &[String], attempts: &[Outcome]) -> Step {
    if providers.is_empty() {
        return Step::GiveUp(GiveUpReason::NoProvidersConfigured);
    }
    // Scan the outcomes in order. The FIRST terminal one decides, so a later attempt cannot
    // overturn an earlier delivery or rejection.
    for (index, outcome) in attempts.iter().enumerate() {
        match outcome {
            Outcome::Delivered => {
                return Step::Delivered {
                    provider: providers
                        .get(index)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_owned()),
                };
            }
            Outcome::MessageRejected => return Step::GiveUp(GiveUpReason::MessageRejected),
            // The only outcome that continues the walk.
            Outcome::ProviderUnavailable => {}
        }
    }
    match providers.get(attempts.len()) {
        Some(provider) => Step::Attempt {
            provider: provider.clone(),
            position: attempts.len(),
        },
        None => Step::GiveUp(GiveUpReason::AllProvidersExhausted),
    }
}

#[cfg(test)]
mod tests {
    use super::{GiveUpReason, Outcome, Step, next_step};

    fn providers(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn attempt(provider: &str, position: usize) -> Step {
        Step::Attempt {
            provider: provider.to_owned(),
            position,
        }
    }

    #[test]
    fn the_primary_is_tried_first() {
        assert_eq!(
            next_step(&providers(&["ses", "postmark"]), &[]),
            attempt("ses", 0)
        );
    }

    /// Issue #111's criterion: the primary fails and the send completes via the fallback.
    #[test]
    fn an_unavailable_primary_fails_over_to_the_next_provider() {
        let configured = providers(&["ses", "postmark", "resend"]);
        assert_eq!(
            next_step(&configured, &[Outcome::ProviderUnavailable]),
            attempt("postmark", 1)
        );
        assert_eq!(
            next_step(
                &configured,
                &[Outcome::ProviderUnavailable, Outcome::ProviderUnavailable]
            ),
            attempt("resend", 2)
        );
    }

    /// THE distinction: a rejected message does NOT walk the provider list.
    ///
    /// Every other provider is looking at the same message and will reach the same conclusion,
    /// so failing over buys N bounces instead of one, at N vendors, damaging reputation with
    /// each. A system that fails over here looks resilient in a demo and multiplies bounces in
    /// production.
    #[test]
    fn a_rejected_message_does_not_fail_over() {
        let configured = providers(&["ses", "postmark", "resend"]);
        assert_eq!(
            next_step(&configured, &[Outcome::MessageRejected]),
            Step::GiveUp(GiveUpReason::MessageRejected)
        );
        // The control that makes this meaningful: the SAME position with the OTHER failure
        // kind does fail over, so the refusal above is the outcome kind and nothing else.
        assert_eq!(
            next_step(&configured, &[Outcome::ProviderUnavailable]),
            attempt("postmark", 1)
        );
    }

    /// A rejection after a run of outages still stops, rather than continuing the walk.
    #[test]
    fn a_rejection_stops_a_failover_walk_already_in_progress() {
        let configured = providers(&["ses", "postmark", "resend"]);
        assert_eq!(
            next_step(
                &configured,
                &[Outcome::ProviderUnavailable, Outcome::MessageRejected]
            ),
            Step::GiveUp(GiveUpReason::MessageRejected)
        );
    }

    #[test]
    fn a_delivery_names_the_provider_that_accepted_it() {
        let configured = providers(&["ses", "postmark"]);
        assert_eq!(
            next_step(
                &configured,
                &[Outcome::ProviderUnavailable, Outcome::Delivered]
            ),
            Step::Delivered {
                provider: "postmark".to_owned()
            }
        );
    }

    /// The FIRST terminal outcome decides, so a later attempt cannot overturn a delivery.
    ///
    /// Bookkeeping that recorded an attempt after a success would otherwise be able to turn a
    /// delivered message into a dead letter, and the recipient already has the email.
    #[test]
    fn a_later_outcome_cannot_overturn_an_earlier_delivery() {
        let configured = providers(&["ses", "postmark"]);
        assert_eq!(
            next_step(
                &configured,
                &[Outcome::Delivered, Outcome::ProviderUnavailable]
            ),
            Step::Delivered {
                provider: "ses".to_owned()
            }
        );
        assert_eq!(
            next_step(&configured, &[Outcome::Delivered, Outcome::MessageRejected]),
            Step::Delivered {
                provider: "ses".to_owned()
            }
        );
    }

    /// Exhausting every provider is its own reason, distinct from a rejection.
    ///
    /// This one belongs in the dead-letter queue and is worth alerting on: the message is
    /// probably fine and the infrastructure is not. A rejection is the opposite.
    #[test]
    fn exhausting_every_provider_is_distinct_from_a_rejection() {
        let configured = providers(&["ses", "postmark"]);
        assert_eq!(
            next_step(
                &configured,
                &[Outcome::ProviderUnavailable, Outcome::ProviderUnavailable]
            ),
            Step::GiveUp(GiveUpReason::AllProvidersExhausted)
        );
    }

    /// No providers configured is a DEPLOYMENT error, not an outage.
    ///
    /// Folding it into "exhausted" would read as an infrastructure failure and send an operator
    /// looking at provider status pages instead of at their own configuration.
    #[test]
    fn no_providers_configured_is_its_own_reason() {
        assert_eq!(
            next_step(&[], &[]),
            Step::GiveUp(GiveUpReason::NoProvidersConfigured)
        );
        assert_eq!(
            next_step(&[], &[Outcome::ProviderUnavailable]),
            Step::GiveUp(GiveUpReason::NoProvidersConfigured)
        );
    }

    /// A single configured provider still fails over correctly: straight to exhausted.
    #[test]
    fn a_lone_provider_exhausts_after_one_outage() {
        let configured = providers(&["ses"]);
        assert_eq!(next_step(&configured, &[]), attempt("ses", 0));
        assert_eq!(
            next_step(&configured, &[Outcome::ProviderUnavailable]),
            Step::GiveUp(GiveUpReason::AllProvidersExhausted)
        );
    }

    /// More attempts than providers is exhaustion, not a panic.
    ///
    /// It should not happen. A delivery worker is also the worst place to discover a
    /// bookkeeping bug by crashing mid-send.
    #[test]
    fn more_attempts_than_providers_does_not_panic() {
        let configured = providers(&["ses"]);
        assert_eq!(
            next_step(
                &configured,
                &[Outcome::ProviderUnavailable, Outcome::ProviderUnavailable]
            ),
            Step::GiveUp(GiveUpReason::AllProvidersExhausted)
        );
    }

    /// The decision is a pure function of its inputs, so a worker that restarts mid-send
    /// reaches the same conclusion the previous one would have.
    #[test]
    fn the_decision_is_reproducible_from_the_history_alone() {
        let configured = providers(&["ses", "postmark", "resend"]);
        let history = [Outcome::ProviderUnavailable, Outcome::ProviderUnavailable];
        let first = next_step(&configured, &history);
        let second = next_step(&configured, &history);
        assert_eq!(first, second);
        assert_eq!(first, attempt("resend", 2));
    }

    #[test]
    fn every_give_up_reason_describes_itself_distinctly() {
        let all = [
            GiveUpReason::MessageRejected,
            GiveUpReason::AllProvidersExhausted,
            GiveUpReason::NoProvidersConfigured,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for reason in all {
            assert!(reason.as_str().len() > 20);
            assert!(seen.insert(reason.as_str()), "{reason:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }
}
