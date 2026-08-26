// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-recipient send rate limiting (issue #111).
//!
//! Issue #111 requires that "exceeding the per-recipient rate limit blocks the send and emits a
//! `Message.RateLimited` event". This is the decision, pure: the recent send history for one
//! recipient and a configured budget in, allow or block out. No clock (the evaluation instant
//! is passed), no store, no counters held here.
//!
//! # A rate limit protects the RECIPIENT, not the server
//!
//! That framing decides the design. This is not a capacity control: a verification email costs
//! the server almost nothing to send. What it protects against is a stranger typing someone
//! else's address into a signup form repeatedly and using an honest system to deliver a stream
//! of mail to a person who never asked for any of it. The victim is the recipient, and they
//! have no account, no session, and no way to complain to anyone but their mail provider, who
//! will act against the SENDER's domain.
//!
//! Two consequences follow, and both are load bearing:
//!
//! - The limit is keyed on the RECIPIENT, never on the requester. Keying on the requesting IP
//!   or session would let an attacker rotate either and keep sending, which is trivial and free.
//! - Exceeding it BLOCKS rather than delays. A queued send arrives eventually, which is the
//!   same harm later; a blocked one does not arrive at all.
//!
//! # A sliding window, unlike the dedup window
//!
//! [`message_hygiene::window_index`](crate::message_hygiene::window_index) uses fixed windows
//! because dedup only needs one integer and a boundary miss there is harmless: two identical
//! verification emails a second apart is a nuisance.
//!
//! A rate limit cannot afford that. With fixed windows an attacker sends the full budget at the
//! very end of one window and the full budget at the start of the next, delivering twice the
//! intended rate in a moment, which is exactly the burst the limit exists to prevent. So this
//! takes the actual send timestamps and counts those inside a true sliding window. The cost is
//! that the caller must keep those timestamps; that cost is the point.

/// Whether a send may proceed, and why not when it may not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// Under budget. Carries how many sends remain in the current window, so a caller can
    /// surface "1 of 3 remaining" without recomputing it.
    Allow {
        /// Sends still permitted in this window, after this one.
        remaining: u32,
    },
    /// Over budget. The send is BLOCKED, not queued.
    Block {
        /// When the oldest counted send leaves the window, in epoch seconds: the earliest
        /// instant a retry could succeed. Carried so a caller can tell the requester when to
        /// come back instead of leaving them to guess.
        retry_after_epoch_seconds: u64,
    },
}

/// WHAT the budget counts: every send to this recipient, or only sends of the same kind.
///
/// The distinction exists because two message classes want opposite things from the same
/// mechanism, and the module header above only argues one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateScope {
    /// Every send to this recipient, whatever kind. The DEFAULT, and correct for anything an
    /// unauthenticated stranger can trigger.
    ///
    /// This is the anti-flood bound the module header describes: someone types a victim's
    /// address into a signup form repeatedly, and what the victim experiences is the TOTAL
    /// volume, not a per-kind breakdown. Counting per kind here would multiply the bound by the
    /// number of kinds and let the same attacker send three times as much by alternating.
    EveryKind,
    /// Only sends of the same kind. For a message the ACCOUNT OWNER needs to receive about
    /// their own account.
    ///
    /// Review found the case: an attacker with a session links a sign-in method, unlinks it,
    /// links it again -- three real state changes, each a real alert -- and the recipient's
    /// hourly budget is spent. The fourth action, linking the attacker's own passkey, is
    /// rate limited, and the alert about it is never delivered on any channel. Seventeen
    /// minutes of churn buys forty-three of silence.
    ///
    /// Cross-kind counting turns a volume control into a silencing primitive there, because the
    /// attacker CHOOSES the volume. Per-kind does not remove the bound -- an alert kind is still
    /// capped for that recipient -- it removes the attacker's ability to spend one kind's budget
    /// to suppress another's.
    ///
    /// Not the default, and it must not become one: it is only sound where the sends are
    /// triggered by an authenticated change to the recipient's OWN account, so the recipient
    /// wanted every one of them.
    SameKind,
}

/// The budget for one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateBudget {
    /// How many sends are permitted inside the window.
    pub limit: u32,
    /// The window length in seconds.
    pub window_seconds: u64,
    /// What the count covers. See [`RateScope`].
    pub scope: RateScope,
}

impl RateBudget {
    /// A budget, with both fields floored at 1.
    ///
    /// A zero limit would block every send including the first, turning a misconfiguration into
    /// a total outage of verification email, which is indistinguishable from the feature being
    /// broken. A zero window would make the limit meaningless in the other direction. Both
    /// degrade to the nearest sane value rather than panicking inside a send path.
    #[must_use]
    pub fn new(limit: u32, window_seconds: u64) -> Self {
        Self {
            limit: limit.max(1),
            window_seconds: window_seconds.max(1),
            scope: RateScope::EveryKind,
        }
    }

    /// The same budget, counting only sends of the SAME KIND.
    ///
    /// A separate constructor rather than a parameter on [`Self::new`], so every existing caller
    /// keeps the cross-kind bound the module header argues for and a caller wanting the other
    /// has to say so at the call site. See [`RateScope::SameKind`] for when that is sound; it is
    /// a narrow case.
    #[must_use]
    pub fn per_kind(self) -> Self {
        Self {
            scope: RateScope::SameKind,
            ..self
        }
    }
}

/// Decide whether a send to this recipient may proceed.
///
/// `recent_sends` holds the epoch-second timestamps of prior sends to this recipient, in any
/// order. `now` is the evaluation instant. Entries outside the window are ignored rather than
/// requiring the caller to prune first, because a caller that had to prune correctly to get a
/// correct answer would eventually not.
///
/// The comparison is `>=`: a send at exactly `now - window_seconds` has left the window. Stating
/// it because an off-by-one here is worth either a permanently over-tight or over-loose limit,
/// and both are silent.
#[must_use]
pub fn rate_decision(recent_sends: &[u64], now: u64, budget: RateBudget) -> RateDecision {
    let cutoff = now.saturating_sub(budget.window_seconds);
    // Strictly AFTER the cutoff: a send exactly one window old has aged out.
    let mut in_window: Vec<u64> = recent_sends
        .iter()
        .copied()
        .filter(|sent| *sent > cutoff)
        .collect();

    let used = u32::try_from(in_window.len()).unwrap_or(u32::MAX);
    if used < budget.limit {
        return RateDecision::Allow {
            remaining: budget.limit - used - 1,
        };
    }

    // Blocked. The earliest a retry can succeed is when the OLDEST counted send leaves the
    // window, because that is the moment the count drops below the limit.
    in_window.sort_unstable();
    let oldest = in_window.first().copied().unwrap_or(now);
    RateDecision::Block {
        retry_after_epoch_seconds: oldest.saturating_add(budget.window_seconds),
    }
}

#[cfg(test)]
mod tests {
    use super::{RateBudget, RateDecision, rate_decision};

    /// A fixed evaluation instant, well clear of zero so window arithmetic never underflows
    /// into a different meaning.
    const NOW: u64 = 1_800_000_000;

    fn budget() -> RateBudget {
        RateBudget::new(3, 60)
    }

    #[test]
    fn a_first_send_is_allowed_and_reports_the_remainder() {
        assert_eq!(
            rate_decision(&[], NOW, budget()),
            RateDecision::Allow { remaining: 2 }
        );
    }

    #[test]
    fn the_remainder_falls_with_each_send_in_the_window() {
        assert_eq!(
            rate_decision(&[NOW - 10], NOW, budget()),
            RateDecision::Allow { remaining: 1 }
        );
        assert_eq!(
            rate_decision(&[NOW - 10, NOW - 5], NOW, budget()),
            RateDecision::Allow { remaining: 0 }
        );
    }

    /// At the limit the send is BLOCKED, not queued. A queued send arrives eventually, which is
    /// the same harm to the recipient a little later.
    #[test]
    fn exceeding_the_budget_blocks() {
        let decision = rate_decision(&[NOW - 30, NOW - 20, NOW - 10], NOW, budget());
        assert!(
            matches!(decision, RateDecision::Block { .. }),
            "expected a block, got {decision:?}"
        );
    }

    /// The retry instant is when the OLDEST counted send leaves the window, because that is the
    /// moment the count drops below the limit.
    #[test]
    fn a_block_says_when_a_retry_could_succeed() {
        let oldest = NOW - 30;
        assert_eq!(
            rate_decision(&[oldest, NOW - 20, NOW - 10], NOW, budget()),
            RateDecision::Block {
                retry_after_epoch_seconds: oldest + 60
            }
        );
        // And at that instant the send is genuinely allowed again, so the number is a promise
        // the function keeps rather than an estimate.
        assert_eq!(
            rate_decision(&[oldest, NOW - 20, NOW - 10], oldest + 60, budget()),
            RateDecision::Allow { remaining: 0 }
        );
    }

    /// Sends outside the window are ignored WITHOUT the caller pruning first.
    ///
    /// A caller that had to prune correctly in order to get a correct answer would eventually
    /// not, and the failure would be a silently loosened limit.
    #[test]
    fn sends_outside_the_window_do_not_count() {
        let ancient = [NOW - 600, NOW - 300, NOW - 120];
        assert_eq!(
            rate_decision(&ancient, NOW, budget()),
            RateDecision::Allow { remaining: 2 },
            "three sends, all older than the window, must count for nothing"
        );
    }

    /// The boundary, stated explicitly: a send exactly one window old has LEFT the window.
    #[test]
    fn the_window_boundary_is_exclusive() {
        let exactly_one_window = NOW - 60;
        assert_eq!(
            rate_decision(
                &[exactly_one_window, exactly_one_window, exactly_one_window],
                NOW,
                budget()
            ),
            RateDecision::Allow { remaining: 2 },
            "at exactly the cutoff a send has aged out"
        );
        // One second newer and it is inside.
        let just_inside = NOW - 59;
        assert!(matches!(
            rate_decision(&[just_inside, just_inside, just_inside], NOW, budget()),
            RateDecision::Block { .. }
        ));
    }

    /// THE reason this window slides rather than snapping to fixed buckets.
    ///
    /// With fixed windows an attacker sends the full budget at the end of one bucket and the
    /// full budget at the start of the next, delivering double the intended rate in a moment.
    /// A sliding window counts across that seam, so the burst is refused.
    #[test]
    fn a_burst_across_a_bucket_edge_is_still_refused() {
        // Three sends in the last two seconds: under a 60-second bucket scheme that straddled
        // an edge these could look like two separate windows. They do not here.
        let burst = [NOW - 2, NOW - 1, NOW];
        assert!(
            matches!(
                rate_decision(&burst, NOW, budget()),
                RateDecision::Block { .. }
            ),
            "a burst must be refused however it straddles a boundary"
        );
    }

    /// Order does not matter: the caller may hand back history in any order.
    #[test]
    fn the_decision_does_not_depend_on_history_order() {
        let forward = [NOW - 30, NOW - 20, NOW - 10];
        let mut reversed = forward;
        reversed.reverse();
        assert_eq!(
            rate_decision(&forward, NOW, budget()),
            rate_decision(&reversed, NOW, budget())
        );
    }

    /// A zero limit degrades to one rather than blocking every send.
    ///
    /// A misconfigured zero would take verification email out entirely, which is
    /// indistinguishable from the feature being broken and is a far worse failure than a
    /// limit that is tighter than intended.
    #[test]
    fn a_zero_budget_degrades_instead_of_blocking_everything() {
        let degraded = RateBudget::new(0, 0);
        assert_eq!(degraded.limit, 1);
        assert_eq!(degraded.window_seconds, 1);
        assert_eq!(
            rate_decision(&[], NOW, degraded),
            RateDecision::Allow { remaining: 0 },
            "the first send must still go out"
        );
    }

    /// A window reaching past the epoch saturates rather than wrapping.
    #[test]
    fn an_early_instant_does_not_underflow() {
        assert_eq!(
            rate_decision(&[1, 2], 5, RateBudget::new(3, 3600)),
            RateDecision::Allow { remaining: 0 },
            "both sends are inside a window that saturates at zero"
        );
    }

    /// A larger limit is genuinely larger, so the budget is read rather than hardcoded.
    #[test]
    fn the_configured_limit_is_what_is_enforced() {
        let history = [NOW - 30, NOW - 20, NOW - 10];
        assert!(matches!(
            rate_decision(&history, NOW, RateBudget::new(3, 60)),
            RateDecision::Block { .. }
        ));
        assert_eq!(
            rate_decision(&history, NOW, RateBudget::new(4, 60)),
            RateDecision::Allow { remaining: 0 }
        );
    }
}
