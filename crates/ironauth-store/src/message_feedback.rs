// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounce and complaint handling (issue #111).
//!
//! Issue #111 requires "suppression-list management (bounces, complaints, manual suppression)
//! enforced before send". [`message_hygiene`](crate::message_hygiene) enforces the list; this
//! decides what goes ON it, which is the harder half.
//!
//! Pure: a feedback event and the recipient's recent history in, a decision out. No clock, no
//! store.
//!
//! # Both errors here are expensive, in opposite directions
//!
//! Suppress too eagerly and a legitimate recipient is silenced permanently. Their mailbox was
//! full for an afternoon, and now they never receive a verification email again, cannot sign
//! in, and nothing in the product tells either of you why. That failure is invisible: it looks
//! like the user simply stopped trying.
//!
//! Suppress too reluctantly and you keep mailing addresses that bounce. Receivers score that
//! directly against the sending DOMAIN, so the cost lands on every OTHER recipient's
//! deliverability, including people whose mail is working today.
//!
//! So the classification is per feedback KIND rather than one threshold for everything.
//!
//! ## A complaint is the most serious signal there is
//!
//! [`FeedbackKind::Complaint`] means the recipient pressed "this is spam". It suppresses
//! IMMEDIATELY and permanently, on a single occurrence, and it is the one case where erring
//! toward over-suppression is clearly right: the recipient has said they do not want this, and
//! a feedback loop complaint costs far more reputation than one bounce.
//!
//! ## A hard bounce is a fact about the address
//!
//! The mailbox does not exist. Retrying tomorrow changes nothing, and every send to it is pure
//! reputation damage, so it suppresses on first occurrence too.
//!
//! ## A soft bounce is the one that needs a threshold
//!
//! A full mailbox, a greylist, a server that was down. Any single one of these is temporary and
//! suppressing on it would silence a real user for an afternoon's outage. Repeated ones are
//! indistinguishable from a dead address. So soft bounces suppress only after
//! [`SOFT_BOUNCE_THRESHOLD`] CONSECUTIVE failures, and a single success in between resets the
//! count, because it proves the address is alive.

/// What a provider told us about a delivery after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackKind {
    /// The recipient marked the message as spam. The most serious signal available.
    Complaint,
    /// The address does not exist, or the domain does not accept mail at all. Permanent.
    HardBounce,
    /// A temporary failure: a full mailbox, a greylist, a server that was down.
    SoftBounce,
    /// The recipient asked to stop receiving mail.
    Unsubscribe,
    /// The message was accepted. Present because it RESETS the soft-bounce run, which is the
    /// only thing that distinguishes a bad afternoon from a dead address.
    Delivered,
}

/// How many CONSECUTIVE soft bounces suppress an address.
///
/// Five, deliberately toward the tolerant end. The asymmetry justifies it: suppressing a live
/// address permanently locks a real person out of their account with no visible cause, while
/// five extra sends to a genuinely dead one is a small, bounded amount of reputation damage
/// that the hard-bounce and complaint paths would usually have caught first anyway.
pub const SOFT_BOUNCE_THRESHOLD: usize = 5;

/// What to do with the recipient after this feedback event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionAction {
    /// Add the address to the suppression list, with the reason recorded so it is queryable and
    /// so an operator can tell a complaint from a dead mailbox when deciding to lift it.
    Suppress(SuppressionReason),
    /// Take no action. The address stays sendable.
    None,
}

/// Why an address was suppressed. Recorded, because lifting a suppression is a judgement call
/// and "which kind" is most of the input to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionReason {
    /// The recipient reported the message as spam.
    Complaint,
    /// The address is permanently undeliverable.
    HardBounce,
    /// Repeated temporary failures, indistinguishable from a dead address.
    RepeatedSoftBounce,
    /// The recipient asked to stop.
    Unsubscribe,
}

impl SuppressionReason {
    /// A stable, value-free description.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Complaint => "the recipient reported a message as spam",
            Self::HardBounce => "the address is permanently undeliverable",
            Self::RepeatedSoftBounce => {
                "repeated temporary failures, indistinguishable from a dead address"
            }
            Self::Unsubscribe => "the recipient asked to stop receiving mail",
        }
    }
}

/// Decide what this feedback event means for the recipient's suppression state.
///
/// `recent` is the recipient's feedback history, oldest first. Only the trailing run matters,
/// and only for soft bounces; the other kinds decide on the event alone.
///
/// The `event` itself is NOT expected to appear in `recent`: callers hold history and receive
/// the new event separately, and requiring them to append first would make the answer depend on
/// whether they remembered to.
#[must_use]
pub fn suppression_action(event: FeedbackKind, recent: &[FeedbackKind]) -> SuppressionAction {
    match event {
        // One occurrence is enough. The recipient has said they do not want this, and a
        // feedback-loop complaint costs far more reputation than a bounce.
        FeedbackKind::Complaint => SuppressionAction::Suppress(SuppressionReason::Complaint),
        FeedbackKind::Unsubscribe => SuppressionAction::Suppress(SuppressionReason::Unsubscribe),
        // A fact about the address. Retrying changes nothing.
        FeedbackKind::HardBounce => SuppressionAction::Suppress(SuppressionReason::HardBounce),
        FeedbackKind::SoftBounce => {
            // Count the CONSECUTIVE soft bounces ending here, including this event. Anything
            // that is not a soft bounce breaks the run, which is what makes a single delivery
            // in between exonerate the address.
            let prior = recent
                .iter()
                .rev()
                .take_while(|kind| **kind == FeedbackKind::SoftBounce)
                .count();
            if prior + 1 >= SOFT_BOUNCE_THRESHOLD {
                SuppressionAction::Suppress(SuppressionReason::RepeatedSoftBounce)
            } else {
                SuppressionAction::None
            }
        }
        // A success is not a reason to suppress anything. It matters only as the thing that
        // breaks a soft-bounce run, which the branch above reads out of the history.
        FeedbackKind::Delivered => SuppressionAction::None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FeedbackKind, SOFT_BOUNCE_THRESHOLD, SuppressionAction, SuppressionReason,
        suppression_action,
    };

    fn softs(count: usize) -> Vec<FeedbackKind> {
        vec![FeedbackKind::SoftBounce; count]
    }

    /// A complaint suppresses immediately. This is the one case where over-suppression is
    /// clearly right: the recipient has said they do not want this.
    #[test]
    fn a_complaint_suppresses_on_the_first_occurrence() {
        assert_eq!(
            suppression_action(FeedbackKind::Complaint, &[]),
            SuppressionAction::Suppress(SuppressionReason::Complaint)
        );
    }

    /// A hard bounce is a fact about the address; retrying tomorrow changes nothing.
    #[test]
    fn a_hard_bounce_suppresses_on_the_first_occurrence() {
        assert_eq!(
            suppression_action(FeedbackKind::HardBounce, &[]),
            SuppressionAction::Suppress(SuppressionReason::HardBounce)
        );
    }

    #[test]
    fn an_unsubscribe_suppresses_on_the_first_occurrence() {
        assert_eq!(
            suppression_action(FeedbackKind::Unsubscribe, &[]),
            SuppressionAction::Suppress(SuppressionReason::Unsubscribe)
        );
    }

    /// THE asymmetry: one soft bounce must NOT suppress.
    ///
    /// A mailbox full for an afternoon would otherwise silence a real user permanently. They
    /// stop receiving verification email, cannot sign in, and nothing tells either party why.
    #[test]
    fn a_single_soft_bounce_does_not_suppress() {
        assert_eq!(
            suppression_action(FeedbackKind::SoftBounce, &[]),
            SuppressionAction::None
        );
    }

    /// The threshold counts the event itself, so it takes exactly `SOFT_BOUNCE_THRESHOLD` soft
    /// bounces in total rather than that many PLUS the current one.
    #[test]
    fn soft_bounces_suppress_exactly_at_the_threshold() {
        // One short: still sendable.
        assert_eq!(
            suppression_action(FeedbackKind::SoftBounce, &softs(SOFT_BOUNCE_THRESHOLD - 2)),
            SuppressionAction::None,
            "one below the threshold must stay sendable"
        );
        // At the threshold: suppressed.
        assert_eq!(
            suppression_action(FeedbackKind::SoftBounce, &softs(SOFT_BOUNCE_THRESHOLD - 1)),
            SuppressionAction::Suppress(SuppressionReason::RepeatedSoftBounce),
        );
    }

    /// A single delivery in between EXONERATES the address, because it proves it is alive.
    ///
    /// Without this the counter would accumulate across months of healthy delivery and suppress
    /// a perfectly good address on its fifth unlucky afternoon.
    #[test]
    fn a_delivery_resets_the_soft_bounce_run() {
        let mut history = softs(SOFT_BOUNCE_THRESHOLD - 1);
        history.push(FeedbackKind::Delivered);
        history.extend(softs(1));
        assert_eq!(
            suppression_action(FeedbackKind::SoftBounce, &history),
            SuppressionAction::None,
            "a success in between proves the address is alive"
        );
    }

    /// Only the TRAILING run counts, so old soft bounces before a success are irrelevant however
    /// many there were.
    #[test]
    fn only_the_trailing_run_of_soft_bounces_counts() {
        let mut history = softs(50);
        history.push(FeedbackKind::Delivered);
        assert_eq!(
            suppression_action(FeedbackKind::SoftBounce, &history),
            SuppressionAction::None,
            "fifty old soft bounces before a delivery must not suppress"
        );
    }

    /// A delivery is never itself a reason to suppress.
    #[test]
    fn a_delivery_suppresses_nothing() {
        assert_eq!(
            suppression_action(FeedbackKind::Delivered, &softs(50)),
            SuppressionAction::None
        );
    }

    /// A complaint or hard bounce ignores history entirely: it decides on the event alone.
    #[test]
    fn the_permanent_kinds_ignore_history() {
        let healthy = vec![FeedbackKind::Delivered; 100];
        assert_eq!(
            suppression_action(FeedbackKind::Complaint, &healthy),
            SuppressionAction::Suppress(SuppressionReason::Complaint)
        );
        assert_eq!(
            suppression_action(FeedbackKind::HardBounce, &healthy),
            SuppressionAction::Suppress(SuppressionReason::HardBounce)
        );
    }

    /// The reason travels with the suppression, because lifting one is a judgement call and
    /// "which kind" is most of the input to it. A complaint and a dead mailbox are not the same
    /// conversation with an operator.
    #[test]
    fn each_reason_is_distinct_and_describes_itself() {
        let all = [
            SuppressionReason::Complaint,
            SuppressionReason::HardBounce,
            SuppressionReason::RepeatedSoftBounce,
            SuppressionReason::Unsubscribe,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for reason in all {
            assert!(reason.as_str().len() > 20, "{reason:?} has no useful text");
            assert!(seen.insert(reason.as_str()), "{reason:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }

    /// Nothing except a soft bounce is affected by the threshold, asserted over every kind so a
    /// new one cannot quietly inherit threshold behaviour it was never meant to have.
    #[test]
    fn only_soft_bounces_depend_on_history() {
        for kind in [
            FeedbackKind::Complaint,
            FeedbackKind::HardBounce,
            FeedbackKind::Unsubscribe,
            FeedbackKind::Delivered,
        ] {
            assert_eq!(
                suppression_action(kind, &[]),
                suppression_action(kind, &softs(SOFT_BOUNCE_THRESHOLD * 3)),
                "{kind:?} must decide on the event alone"
            );
        }
    }
}
