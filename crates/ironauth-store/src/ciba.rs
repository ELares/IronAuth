// SPDX-License-Identifier: MIT OR Apache-2.0

//! CIBA backchannel authentication (issue #131, OpenID Connect Client Initiated
//! Backchannel Authentication Flow -- Core 1.0): the domain types behind
//! `backchannel_authentication_requests`.
//!
//! A client asks for a user it names but does not have in front of it to be
//! authenticated. The endpoint answers an `auth_req_id`; the user approves on their own
//! device; the client obtains tokens by POLLING or by being PINGED and then fetching.
//!
//! # What lives here and what does not
//!
//! The rules that hold regardless of the database: which delivery modes exist, which
//! lifecycle transitions are legal, and how a client's `requested_expiry` is bounded. They
//! are here rather than in the repository because each is a claim about the PROTOCOL, and a
//! protocol rule expressed as a SQL predicate can only be tested against a live database.
//!
//! The schema enforces the same rules a second time (closed `CHECK` vocabularies, a
//! write-once `expires_at`, a column-scoped `UPDATE` grant). That is deliberate duplication:
//! this module is what a caller is refused BY, and the schema is what the data cannot escape
//! even if a future caller forgets to ask.

use std::time::Duration;

/// How the client learns its authentication request has been decided.
///
/// Two variants, and `Push` is deliberately not one of them. `docs/WILL-NOT-IMPLEMENT.md`
/// records the reason: push has the weakest security properties of the three CIBA modes
/// (the tokens themselves are delivered to the notification endpoint), it is forbidden by
/// the FAPI-CIBA profile, and supporting it would make the deployment uncertifiable. A
/// missing variant is a stronger statement than a rejected one -- there is no state in which
/// a push-mode request exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryMode {
    /// The client polls the token endpoint until the request is decided.
    Poll,
    /// The server notifies the client's endpoint, and the client then fetches tokens.
    Ping,
}

/// Why a delivery mode was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryModeError {
    /// The client asked for `push`, which this deployment does not implement (#131
    /// criterion 6). Distinguished from an unrecognized mode because the answer to an
    /// operator asking "why" is completely different: push is a real CIBA mode we refuse on
    /// purpose, and saying "unknown" would suggest a typo or a version mismatch.
    PushNotSupported,
    /// The value is not a CIBA delivery mode at all.
    Unknown,
}

impl DeliveryMode {
    /// Parse a registered `backchannel_token_delivery_mode`.
    ///
    /// # Errors
    ///
    /// [`DeliveryModeError::PushNotSupported`] for `push`, and
    /// [`DeliveryModeError::Unknown`] for anything else.
    pub fn parse(value: &str) -> Result<Self, DeliveryModeError> {
        match value {
            "poll" => Ok(Self::Poll),
            "ping" => Ok(Self::Ping),
            "push" => Err(DeliveryModeError::PushNotSupported),
            _ => Err(DeliveryModeError::Unknown),
        }
    }

    /// The wire and column spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Poll => "poll",
            Self::Ping => "ping",
        }
    }

    /// Whether this mode requires a client notification endpoint and token.
    ///
    /// Ping needs somewhere to send the notification and a credential the client can
    /// authenticate it with. Poll must carry NEITHER, so a poll-mode request cannot smuggle
    /// a notification target past a later reader that would honour it.
    #[must_use]
    pub const fn requires_notification(self) -> bool {
        matches!(self, Self::Ping)
    }
}

/// Where an authentication request is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestStatus {
    /// Awaiting the user's decision.
    Pending,
    /// The user consented; the next poll or fetch issues tokens.
    Approved,
    /// The user refused.
    Denied,
    /// Past its TTL.
    Expired,
    /// Tokens have been issued. Terminal, and what makes an `auth_req_id` single-use.
    Redeemed,
}

impl RequestStatus {
    /// The wire and column spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Redeemed => "redeemed",
        }
    }

    /// Parse a stored status. Returns [`None`] for an unknown value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "expired" => Some(Self::Expired),
            "redeemed" => Some(Self::Redeemed),
            _ => None,
        }
    }

    /// Whether this status can still change.
    ///
    /// `Denied`, `Expired` and `Redeemed` are terminal. Stated as its own function because
    /// three call sites otherwise each write their own list of three, and a fourth terminal
    /// status added later would have to find all of them.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Denied | Self::Expired | Self::Redeemed)
    }

    /// Whether a transition to `next` is legal.
    ///
    /// The single-use property (#131 criterion 3) is this function's job: `Approved ->
    /// Redeemed` is legal exactly once because `Redeemed` is terminal, so a second
    /// redemption is a transition OUT of a terminal state and is refused. Expressing it as a
    /// transition table rather than as an `if` at the redemption site means the same rule
    /// covers every future caller.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            // A pending request can be decided either way, expire, or -- notably -- NOT go
            // straight to Redeemed. Tokens require an approval that actually happened.
            Self::Pending => matches!(next, Self::Approved | Self::Denied | Self::Expired),
            // An approved request is redeemed once, or expires first if the client never
            // came back for it.
            Self::Approved => matches!(next, Self::Redeemed | Self::Expired),
            // Terminal.
            Self::Denied | Self::Expired | Self::Redeemed => false,
        }
    }
}

/// How long a request may live, given what the client asked for.
///
/// The client's `requested_expiry` may SHORTEN the lifetime but never extend it (#131
/// criterion 3). A client that asks for a day gets the ceiling; one that asks for thirty
/// seconds gets thirty seconds, because a client that wants to fail fast should be able to.
///
/// The floor exists for a different reason and is worth separating: a lifetime shorter than
/// a couple of polling intervals cannot be redeemed even by a well-behaved client, so
/// honouring a one-second request would manufacture a flow that always fails. Clamping up to
/// the floor is the one case where the answer exceeds the request, and it is a refusal to
/// build something unusable rather than a lifetime extension.
#[must_use]
pub fn bounded_expiry(requested: Option<Duration>, floor: Duration, ceiling: Duration) -> Duration {
    // A ceiling below the floor is a misconfiguration; the floor wins, since a request that
    // cannot be completed is worse than one that lives slightly too long.
    let ceiling = ceiling.max(floor);
    match requested {
        Some(asked) => asked.clamp(floor, ceiling),
        None => ceiling,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `push` is refused, and refused DISTINGUISHABLY (#131 criterion 6).
    ///
    /// The distinction is the point. An operator whose client fails registration needs to
    /// learn that push is refused on purpose and that poll or ping will work -- not that
    /// their value was unrecognized, which reads like a typo or a version skew and sends
    /// them looking in the wrong place.
    #[test]
    fn push_is_refused_and_is_not_merely_unknown() {
        assert_eq!(
            DeliveryMode::parse("push"),
            Err(DeliveryModeError::PushNotSupported)
        );
        assert_eq!(
            DeliveryMode::parse("shove"),
            Err(DeliveryModeError::Unknown)
        );
        assert_eq!(DeliveryMode::parse("poll"), Ok(DeliveryMode::Poll));
        assert_eq!(DeliveryMode::parse("ping"), Ok(DeliveryMode::Ping));
    }

    /// Only ping carries a notification target.
    #[test]
    fn only_ping_requires_a_notification_target() {
        assert!(DeliveryMode::Ping.requires_notification());
        assert!(!DeliveryMode::Poll.requires_notification());
    }

    /// An `auth_req_id` is redeemable exactly once (#131 criterion 3).
    ///
    /// Driven over the WHOLE transition space rather than the happy path, so a status added
    /// later is covered here the moment it exists: every pair is checked, and the legal set
    /// is written out independently of the function under test. Reading the expectation from
    /// `can_transition_to` itself would be a guard computing its own expectation.
    #[test]
    fn redemption_is_single_use_and_the_transition_table_is_exhaustive() {
        use RequestStatus::{Approved, Denied, Expired, Pending, Redeemed};
        let all = [Pending, Approved, Denied, Expired, Redeemed];
        // Written by hand from the protocol, NOT derived from the code under test.
        let legal = [
            (Pending, Approved),
            (Pending, Denied),
            (Pending, Expired),
            (Approved, Redeemed),
            (Approved, Expired),
        ];
        for from in all {
            for to in all {
                let expected = legal.contains(&(from, to));
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "{from:?} -> {to:?} should be {}",
                    if expected { "legal" } else { "refused" }
                );
            }
        }
        // The single-use property, stated directly as well as falling out of the table
        // above: once redeemed, nothing follows.
        assert!(!Redeemed.can_transition_to(Redeemed));
        assert!(Redeemed.is_terminal());
        // And tokens cannot be reached without an approval that actually happened.
        assert!(!Pending.can_transition_to(Redeemed));
    }

    /// Every terminal status agrees with the transition table.
    ///
    /// Two representations of one fact (`is_terminal`, and having no legal successor) are
    /// two things that can drift. This pins them to each other.
    #[test]
    fn terminal_means_no_legal_successor() {
        use RequestStatus::{Approved, Denied, Expired, Pending, Redeemed};
        let all = [Pending, Approved, Denied, Expired, Redeemed];
        for from in all {
            let has_successor = all.iter().any(|&to| from.can_transition_to(to));
            assert_eq!(
                from.is_terminal(),
                !has_successor,
                "{from:?}: is_terminal() and the transition table disagree"
            );
        }
    }

    /// A status survives a round trip through its stored spelling.
    #[test]
    fn every_status_round_trips_through_its_column_value() {
        use RequestStatus::{Approved, Denied, Expired, Pending, Redeemed};
        for status in [Pending, Approved, Denied, Expired, Redeemed] {
            assert_eq!(RequestStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(RequestStatus::parse("push"), None);
    }

    /// `requested_expiry` shortens but never extends (#131 criterion 3).
    #[test]
    fn a_client_can_shorten_its_request_but_never_extend_it() {
        let floor = Duration::from_secs(30);
        let ceiling = Duration::from_secs(600);

        // Asking for more than the ceiling gets the ceiling, NOT the request.
        assert_eq!(
            bounded_expiry(Some(Duration::from_secs(86_400)), floor, ceiling),
            ceiling
        );
        // Asking for less is honoured: a client that wants to fail fast may.
        assert_eq!(
            bounded_expiry(Some(Duration::from_secs(120)), floor, ceiling),
            Duration::from_secs(120)
        );
        // Asking for nothing gets the ceiling.
        assert_eq!(bounded_expiry(None, floor, ceiling), ceiling);
        // Below the floor clamps UP -- the one case where the answer exceeds the request,
        // because a request too short to redeem is one manufactured to fail.
        assert_eq!(
            bounded_expiry(Some(Duration::from_secs(1)), floor, ceiling),
            floor
        );
        // A ceiling misconfigured below the floor does not produce an unusable lifetime.
        assert_eq!(
            bounded_expiry(
                Some(Duration::from_secs(300)),
                floor,
                Duration::from_secs(5)
            ),
            floor
        );
    }
}
