// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8628 device-flow polling state machine for `ironauth login` (issue #120).
//!
//! Pure logic, no I/O. The transport is the caller's; what lives here is the part the
//! issue singles out as separating a good client from a sloppy one, and it is the part
//! that is wrong in the field: honouring `slow_down` instead of hammering the token
//! endpoint.
//!
//! Section 3.5 is unusually prescriptive, and each rule exists because clients got it
//! wrong:
//!
//! * `slow_down` means the interval **MUST** increase by 5 seconds "for this and all
//!   subsequent requests". Cumulatively, and permanently. A client that backs off once and
//!   then reverts is the reason the server had to say so twice.
//! * an omitted `interval` means 5 seconds, not "as fast as you like".
//! * for **any** error other than `authorization_pending` and `slow_down`, the client MUST
//!   stop. Treating an unrecognised error as retryable turns one server-side change into a
//!   fleet of clients polling forever, which is the failure this rule is written against.
//!
//! Keeping it I/O-free is what makes those rules assertable: every case below is a table
//! entry rather than a mocked HTTP exchange, so the state machine is tested at the level
//! the RFC describes it.

use std::time::Duration;

/// The RFC 8628 default when the authorization server omits `interval`.
const DEFAULT_INTERVAL_SECS: u64 = 5;

/// The mandated `slow_down` increment (section 3.5).
const SLOW_DOWN_INCREMENT_SECS: u64 = 5;

/// What the token endpoint said, reduced to the cases section 3.5 defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// Credentials were issued. Polling is over.
    Issued,
    /// `authorization_pending`: the user has not finished yet.
    Pending,
    /// `slow_down`: still pending, and we are polling too fast.
    SlowDown,
    /// `access_denied`: the user refused.
    Denied,
    /// `expired_token`: the device code is dead.
    Expired,
    /// Any other error code. Section 3.5 is explicit that this stops polling.
    Other(String),
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Sleep this long, then poll again.
    WaitThenPoll(Duration),
    /// Stop: credentials were issued.
    Done,
    /// Stop: report this to the user. The message is deliberately distinct per cause,
    /// because "login failed" for a refusal, an expiry, and a server fault sends a user
    /// looking in three wrong places.
    Stop(&'static str),
}

/// The polling loop's state.
#[derive(Debug, Clone)]
pub struct DevicePoll {
    interval: Duration,
    elapsed: Duration,
    expires_in: Duration,
}

impl DevicePoll {
    /// Start a poll loop from a device authorization response.
    ///
    /// `interval_secs` is `None` when the server omitted it, which the RFC defines as 5
    /// rather than as "unspecified".
    #[must_use]
    pub fn new(interval_secs: Option<u64>, expires_in: Duration) -> Self {
        Self {
            interval: Duration::from_secs(interval_secs.unwrap_or(DEFAULT_INTERVAL_SECS)),
            elapsed: Duration::ZERO,
            expires_in,
        }
    }

    /// The interval the next poll will wait, for a caller that wants to display it.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Fold in one token-endpoint answer and decide what happens next.
    pub fn advance(&mut self, outcome: &PollOutcome) -> Next {
        match outcome {
            PollOutcome::Issued => Next::Done,
            PollOutcome::Denied => Next::Stop("the request was denied on the other device"),
            PollOutcome::Expired => {
                Next::Stop("the code expired before it was approved; run the command again")
            }
            // "for any other error code ... it MUST stop polling". An unrecognised error is
            // NOT a reason to keep going: the client cannot know it is transient, and
            // guessing that it is turns one server change into a fleet polling forever.
            PollOutcome::Other(_) => {
                Next::Stop("the authorization server refused the request; run the command again")
            }
            PollOutcome::Pending | PollOutcome::SlowDown => {
                if matches!(outcome, PollOutcome::SlowDown) {
                    // "MUST be increased by 5 seconds for this AND ALL SUBSEQUENT requests":
                    // the new interval is kept, not applied once.
                    self.interval += Duration::from_secs(SLOW_DOWN_INCREMENT_SECS);
                }
                // Stop at the device code's own lifetime rather than polling into a
                // guaranteed `expired_token`. The server will refuse anyway; the point is
                // to tell the user why without another round trip.
                let next_at = self.elapsed + self.interval;
                if next_at >= self.expires_in {
                    return Next::Stop(
                        "the code expired before it was approved; run the command again",
                    );
                }
                self.elapsed = next_at;
                Next::WaitThenPoll(self.interval)
            }
        }
    }
}

/// Parse a token-endpoint error body's `error` field into a [`PollOutcome`].
#[must_use]
pub fn outcome_for_error(code: &str) -> PollOutcome {
    match code {
        "authorization_pending" => PollOutcome::Pending,
        "slow_down" => PollOutcome::SlowDown,
        "access_denied" => PollOutcome::Denied,
        "expired_token" => PollOutcome::Expired,
        other => PollOutcome::Other(other.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll() -> DevicePoll {
        DevicePoll::new(Some(5), Duration::from_secs(600))
    }

    #[test]
    fn an_omitted_interval_is_five_seconds_not_zero() {
        // The RFC gives a default precisely so a client cannot read "absent" as "no wait".
        let waiting = DevicePoll::new(None, Duration::from_secs(600));
        assert_eq!(waiting.interval(), Duration::from_secs(5));
    }

    #[test]
    fn pending_waits_the_server_specified_interval() {
        let mut waiting = poll();
        assert_eq!(
            waiting.advance(&PollOutcome::Pending),
            Next::WaitThenPoll(Duration::from_secs(5))
        );
    }

    #[test]
    fn slow_down_adds_five_seconds_and_keeps_it() {
        // The half of section 3.5 clients get wrong: the increase applies to "this and all
        // subsequent requests". A client that backs off once and reverts still hammers.
        let mut waiting = poll();

        assert_eq!(
            waiting.advance(&PollOutcome::SlowDown),
            Next::WaitThenPoll(Duration::from_secs(10))
        );
        assert_eq!(
            waiting.advance(&PollOutcome::Pending),
            Next::WaitThenPoll(Duration::from_secs(10)),
            "the raised interval must persist through an ordinary pending"
        );
        assert_eq!(
            waiting.advance(&PollOutcome::SlowDown),
            Next::WaitThenPoll(Duration::from_secs(15)),
            "and a second slow_down must raise it again, cumulatively"
        );
    }

    #[test]
    fn an_unrecognised_error_stops_rather_than_retrying() {
        // "For any other error code ... it MUST stop polling." A client that treats an
        // unknown error as retryable turns one server-side change into a fleet polling
        // forever, which is the failure the rule exists against.
        let mut waiting = poll();
        let next = waiting.advance(&PollOutcome::Other("invalid_client".to_owned()));
        assert!(matches!(next, Next::Stop(_)), "{next:?}");
    }

    #[test]
    fn refusal_expiry_and_fault_are_three_different_messages() {
        // "login failed" for all three sends a user looking in three wrong places.
        let mut waiting = poll();
        let denied = waiting.advance(&PollOutcome::Denied);
        let expired = poll().advance(&PollOutcome::Expired);
        let other = poll().advance(&PollOutcome::Other("server_error".to_owned()));

        let messages = [&denied, &expired, &other].map(|next| match next {
            Next::Stop(message) => *message,
            other => panic!("expected a stop, got {other:?}"),
        });
        assert_eq!(
            messages.iter().collect::<std::collections::BTreeSet<_>>().len(),
            3,
            "each cause must say something different: {messages:?}"
        );
    }

    #[test]
    fn issuance_ends_the_loop() {
        assert_eq!(poll().advance(&PollOutcome::Issued), Next::Done);
    }

    #[test]
    fn polling_stops_at_the_codes_lifetime_rather_than_running_past_it() {
        // Polling into a guaranteed `expired_token` costs a round trip to learn what the
        // client already knew.
        let mut waiting = DevicePoll::new(Some(5), Duration::from_secs(12));
        assert_eq!(
            waiting.advance(&PollOutcome::Pending),
            Next::WaitThenPoll(Duration::from_secs(5))
        );
        assert_eq!(
            waiting.advance(&PollOutcome::Pending),
            Next::WaitThenPoll(Duration::from_secs(5))
        );
        // The third poll would land at 15s, past the 12s lifetime.
        assert!(matches!(
            waiting.advance(&PollOutcome::Pending),
            Next::Stop(_)
        ));
    }

    #[test]
    fn a_slow_down_can_push_the_next_poll_past_expiry() {
        // The interaction between the two rules, which neither test above reaches: backing
        // off is mandatory, and backing off can itself exhaust the code's lifetime.
        let mut waiting = DevicePoll::new(Some(5), Duration::from_secs(8));
        assert!(
            matches!(waiting.advance(&PollOutcome::SlowDown), Next::Stop(_)),
            "5 + 5 = 10 is past an 8 second lifetime"
        );
    }

    #[test]
    fn every_defined_error_code_maps_to_its_own_outcome() {
        assert_eq!(outcome_for_error("authorization_pending"), PollOutcome::Pending);
        assert_eq!(outcome_for_error("slow_down"), PollOutcome::SlowDown);
        assert_eq!(outcome_for_error("access_denied"), PollOutcome::Denied);
        assert_eq!(outcome_for_error("expired_token"), PollOutcome::Expired);
        assert_eq!(
            outcome_for_error("something_new"),
            PollOutcome::Other("something_new".to_owned())
        );
    }
}
