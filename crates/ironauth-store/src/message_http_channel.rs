// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic HTTP channel, and the response classification every adapter needs (issue #111).
//!
//! Issue #111 names "first-party SMTP and generic HTTP channels, plus adapters for SES,
//! `Postmark`, Resend, `SendGrid`, Mailgun and Twilio, behind one provider interface". This is the
//! generic HTTP one: POST the prepared message to a configured endpoint.
//!
//! # The classification is the whole adapter
//!
//! Posting JSON is trivial. What is not trivial, and what every one of those vendor adapters
//! will get right or wrong independently, is deciding which
//! [`Outcome`](crate::message_failover::Outcome) a response means. The
//! [`MessageProvider`](crate::message_delivery::MessageProvider) seam fails over on
//! `ProviderUnavailable` and refuses to on `MessageRejected`, so this one decision is the
//! difference between a fallback that rescues a send and a rejected recipient bounced at every
//! vendor you have configured.
//!
//! [`classify_status`] is therefore a pure function with its own tests, separate from the
//! transport, so the rule can be reviewed and reused by every future adapter rather than
//! reimplemented six times.
//!
//! ## The rules, and why each one
//!
//! - **2xx**: delivered. The provider accepted it.
//! - **408 and 429**: the provider is unavailable. A timeout or a rate limit says nothing about
//!   the message, and both are the archetypal "try the fallback" case. 429 in particular must
//!   NOT be a rejection: being rate limited by one vendor is precisely when another should be
//!   tried.
//! - **other 4xx**: the message is rejected. The provider is telling us the REQUEST was wrong,
//!   and every other provider will be handed the same message.
//! - **401 and 403**: the provider is unavailable, NOT a rejection, and this is the exception
//!   that matters most. They are 4xx, but they mean OUR credential is wrong, not that the
//!   message is bad. Classifying them as a rejection would silently discard every message the
//!   moment an API key expired, with no failover and no retry, which is the worst possible
//!   response to a routine operational event.
//! - **5xx**: the provider is unavailable.
//! - **anything else**, including a transport failure with no status at all: unavailable. The
//!   tie-break is deliberate and is stated in the seam's own documentation: a needless retry at
//!   a second vendor costs one message, while a misclassified outage silently drops mail.

use crate::message_failover::Outcome;

/// Classify an HTTP response status into a delivery outcome.
///
/// `status` is the HTTP status code, or [`None`] for a transport failure that never produced
/// one (a DNS failure, a connection reset, a timeout at the socket).
///
/// See the module documentation for the reasoning behind each band; the 401/403 carve-out is
/// the one that is easy to get wrong and expensive to get wrong.
#[must_use]
pub fn classify_status(status: Option<u16>) -> Outcome {
    let Some(status) = status else {
        // No response at all. Nothing was learned about the message.
        return Outcome::ProviderUnavailable;
    };
    match status {
        200..=299 => Outcome::Delivered,
        // The 4xx carve-outs. Same answer, two distinct reasons, both worth stating:
        //
        // 401 and 403 mean OUR credential is wrong, not that the message is bad. A rejection
        // here would silently discard every message the moment an API key expired, with no
        // failover and no retry.
        //
        // 408 and 429 are a timeout and a rate limit, which say nothing about the message.
        // Being rate limited by one vendor is precisely when another should be tried.
        //
        // The exact set is pinned by `the_client_error_carve_outs_are_exactly_401_403_408_and_429`,
        // so adding one is a deliberate edit rather than something that slips in and quietly
        // stops a whole class of response from failing over.
        401 | 403 | 408 | 429 => Outcome::ProviderUnavailable,
        400..=499 => Outcome::MessageRejected,
        // 5xx and anything unrecognised: assume the provider, not the message.
        _ => Outcome::ProviderUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::classify_status;
    use crate::message_failover::Outcome;

    #[test]
    fn a_success_is_delivered() {
        for status in [200, 201, 202, 204, 299] {
            assert_eq!(
                classify_status(Some(status)),
                Outcome::Delivered,
                "{status} must be a delivery"
            );
        }
    }

    /// A redirect is NOT a delivery.
    ///
    /// Nothing was accepted: an unfollowed 3xx means the request landed somewhere that pointed
    /// elsewhere, so the message may never have been sent at all. Reporting it as delivered
    /// would drop the message silently AND record a success, which is worse than either alone.
    /// A mutation widening the success band to `200..=399` survived until this test existed.
    #[test]
    fn a_redirect_is_not_a_delivery() {
        for status in [300, 301, 302, 307, 308, 399] {
            assert_eq!(
                classify_status(Some(status)),
                Outcome::ProviderUnavailable,
                "{status} accepted nothing, so it must not read as a delivery"
            );
        }
    }

    /// Delivery is confined to 2xx over the WHOLE status space, not just the codes listed
    /// above, so no band can quietly start reporting success.
    #[test]
    fn nothing_outside_the_success_band_reports_a_delivery() {
        for status in 100_u16..=599 {
            if classify_status(Some(status)) == Outcome::Delivered {
                assert!(
                    (200..=299).contains(&status),
                    "{status} reported a delivery from outside the 2xx band"
                );
            }
        }
        assert_ne!(classify_status(None), Outcome::Delivered);
    }

    /// An ordinary 4xx is about the MESSAGE, so failing over would hand the same message to the
    /// next vendor and buy a second bounce.
    #[test]
    fn an_ordinary_client_error_rejects_the_message() {
        for status in [400, 404, 409, 413, 422, 451, 499] {
            assert_eq!(
                classify_status(Some(status)),
                Outcome::MessageRejected,
                "{status} must be a message rejection"
            );
        }
    }

    /// THE carve-out that matters most: 401 and 403 are OUR problem, not the message's.
    ///
    /// Classifying an expired API key as a message rejection would silently discard every
    /// message, with no failover and no retry, the moment a routine credential rotation was
    /// missed. That is the worst possible response to an ordinary operational event, and it is
    /// exactly the mistake a "4xx means the request was bad" rule makes.
    #[test]
    fn an_auth_failure_is_the_providers_problem_not_the_messages() {
        for status in [401, 403] {
            assert_eq!(
                classify_status(Some(status)),
                Outcome::ProviderUnavailable,
                "{status} means our credential is wrong, so the fallback must be tried"
            );
        }
        // The control: a neighbouring 4xx really is a rejection, so the carve-out is specific
        // rather than a blanket softening of the whole band.
        assert_eq!(classify_status(Some(402)), Outcome::MessageRejected);
        assert_eq!(classify_status(Some(400)), Outcome::MessageRejected);
    }

    /// Being rate limited by one vendor is precisely when another should be tried.
    #[test]
    fn a_rate_limit_or_timeout_tries_the_fallback() {
        for status in [408, 429] {
            assert_eq!(
                classify_status(Some(status)),
                Outcome::ProviderUnavailable,
                "{status} says nothing about the message"
            );
        }
    }

    #[test]
    fn a_server_error_is_the_providers_problem() {
        for status in [500, 502, 503, 504, 599] {
            assert_eq!(classify_status(Some(status)), Outcome::ProviderUnavailable);
        }
    }

    /// A transport failure produced no status, so nothing was learned about the message.
    #[test]
    fn no_response_at_all_tries_the_fallback() {
        assert_eq!(classify_status(None), Outcome::ProviderUnavailable);
    }

    /// The tie-break, asserted as a property over the WHOLE status space rather than the
    /// handful of codes listed above.
    ///
    /// Only 4xx may ever reject a message. If any status outside that band were classified as a
    /// rejection, a provider quirk would permanently discard mail with no failover, and a
    /// hand-written list of examples would not necessarily catch it.
    #[test]
    fn nothing_outside_the_client_error_band_can_reject_a_message() {
        for status in 100_u16..=599 {
            if classify_status(Some(status)) == Outcome::MessageRejected {
                assert!(
                    (400..=499).contains(&status),
                    "{status} rejected the message from outside the 4xx band"
                );
            }
        }
    }

    /// And within 4xx, exactly the documented carve-outs are unavailable rather than rejections.
    ///
    /// Pinning the SET, so adding a carve-out is a deliberate edit here rather than something
    /// that slips in unnoticed and quietly stops failing over.
    #[test]
    fn the_client_error_carve_outs_are_exactly_401_403_408_and_429() {
        let carved: Vec<u16> = (400_u16..=499)
            .filter(|status| classify_status(Some(*status)) != Outcome::MessageRejected)
            .collect();
        assert_eq!(carved, vec![401, 403, 408, 429]);
    }
}
