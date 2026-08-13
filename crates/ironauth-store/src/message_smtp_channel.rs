// SPDX-License-Identifier: MIT OR Apache-2.0

//! SMTP reply-code classification (issue #111).
//!
//! The SMTP half of what [`message_http_channel`](crate::message_http_channel) does for HTTP:
//! turn a server reply into the [`Outcome`](crate::message_failover::Outcome) the provider seam
//! fails over on. Pure, so the rule can be reviewed without a mail server.
//!
//! # SMTP says this more clearly than HTTP does, and it is still easy to get wrong
//!
//! RFC 5321 splits replies by leading digit, and the split is almost exactly the distinction
//! the seam needs:
//!
//! - **2yz**: accepted.
//! - **4yz**: TRANSIENT negative. The command failed but the condition is temporary, and RFC
//!   5321 section 4.2.1 says the sender SHOULD retry. That is `ProviderUnavailable`.
//! - **5yz**: PERMANENT negative. Retrying the same command to the same host will fail the same
//!   way, which is `MessageRejected`.
//!
//! So the leading digit does most of the work, and a naive implementation that stopped there
//! would be right far more often than the HTTP one. The exceptions are where it goes wrong, and
//! they go wrong in the expensive direction.
//!
//! ## The permanent codes that are not about the message
//!
//! `530`, `534`, `535` and `538` are all 5yz, and all mean AUTHENTICATION failed: our
//! credential is wrong, expired, or the server wants a mechanism we did not offer. Treating
//! them as message rejections would discard every message the instant an SMTP password rotated,
//! silently and with no failover, exactly as the HTTP 401 case would.
//!
//! `550` is the opposite and is the one people reach for first: mailbox unavailable really is
//! about the recipient, and every relay will agree, so it must NOT fail over.
//!
//! ## The transient code that people mistake for permanence
//!
//! `421` means the service is closing the channel, usually because it is overloaded or shutting
//! down. It arrives mid-session and looks fatal. It is the archetypal reason to try the
//! fallback.
//!
//! ## Greylisting
//!
//! `450` and `451` are how a greylisting relay says "come back shortly". They are transient by
//! the leading digit, so the general rule already handles them, and the tests pin that because
//! misclassifying greylisting as rejection would drop mail from every correctly-configured
//! receiver that uses it.

use crate::message_failover::Outcome;

/// Classify an SMTP reply code into a delivery outcome.
///
/// `code` is the three-digit reply, or [`None`] when the session failed before one arrived (a
/// connection refused, a TLS failure, a socket timeout).
///
/// See the module documentation for the exceptions; the authentication codes are the ones that
/// are easy to get wrong and expensive to get wrong.
#[must_use]
pub fn classify_reply(code: Option<u16>) -> Outcome {
    let Some(code) = code else {
        // No reply at all. Nothing was learned about the message.
        return Outcome::ProviderUnavailable;
    };
    match code {
        200..=299 => Outcome::Delivered,
        // The ONLY branch that rejects: a permanent failure that is not about our credential.
        // The same command to the same host will fail identically, so every other relay agrees
        // and failing over buys nothing but another bounce.
        500..=599 if !AUTH_FAILURE_CODES.contains(&code) => Outcome::MessageRejected,
        // Everything else tries the fallback, and expressing it as one default is the honest
        // shape of the rule rather than an accident of grouping. It covers, deliberately:
        //
        //   - the authentication codes above, which are 5yz but mean OUR credential is wrong;
        //   - 4yz transients, which RFC 5321 4.2.1 says to retry, including 421 service-closing
        //     and the 450/451 greylisting replies;
        //   - 1yz and 3yz intermediate replies, which are never a final result;
        //   - anything unrecognised, and the no-reply case handled above.
        //
        // The tie-break is the seam's: a needless retry at a second provider costs one message,
        // while a misclassified outage silently drops mail that would have been delivered.
        _ => Outcome::ProviderUnavailable,
    }
}

/// The 5yz replies that mean AUTHENTICATION failed rather than the message being bad.
///
/// 530 auth required, 534 mechanism too weak, 535 credentials rejected, 538 encryption required
/// for the requested mechanism. Treating any of these as a message rejection would discard every
/// message the instant an SMTP password rotated, silently and with no failover.
///
/// The exact set is independently restated by
/// `the_permanent_carve_outs_are_exactly_the_authentication_codes`, which derives it from the
/// function's behaviour rather than reading this constant, so the two cannot drift together.
const AUTH_FAILURE_CODES: [u16; 4] = [530, 534, 535, 538];

#[cfg(test)]
mod tests {
    use super::classify_reply;
    use crate::message_failover::Outcome;

    #[test]
    fn a_positive_completion_is_delivered() {
        for code in [250, 251, 200, 299] {
            assert_eq!(classify_reply(Some(code)), Outcome::Delivered, "{code}");
        }
    }

    /// A permanent failure about the RECIPIENT must not fail over: every relay agrees.
    #[test]
    fn a_permanent_recipient_failure_rejects_the_message() {
        // 550 mailbox unavailable, 551 not local, 552 storage exceeded, 553 bad name,
        // 554 transaction failed.
        for code in [550, 551, 552, 553, 554, 500, 501, 502] {
            assert_eq!(
                classify_reply(Some(code)),
                Outcome::MessageRejected,
                "{code} is permanent and about the message"
            );
        }
    }

    /// THE carve-out: authentication codes are 5yz but are OUR problem.
    ///
    /// Treating them as message rejections would discard every message the instant an SMTP
    /// password rotated, silently and with no failover. Same shape as the HTTP 401 case, and
    /// harder to spot here because the leading digit genuinely does mean "permanent".
    #[test]
    fn an_authentication_failure_is_the_providers_problem() {
        for code in [530, 534, 535, 538] {
            assert_eq!(
                classify_reply(Some(code)),
                Outcome::ProviderUnavailable,
                "{code} means our credential is wrong, so the fallback must be tried"
            );
        }
        // The control: neighbouring 5yz codes really are rejections, so the carve-out is
        // specific rather than a blanket softening of the permanent band.
        assert_eq!(classify_reply(Some(531)), Outcome::MessageRejected);
        assert_eq!(classify_reply(Some(536)), Outcome::MessageRejected);
        assert_eq!(classify_reply(Some(550)), Outcome::MessageRejected);
    }

    /// 421 arrives mid-session and looks fatal. It means the service is going away.
    #[test]
    fn a_service_closing_reply_tries_the_fallback() {
        assert_eq!(classify_reply(Some(421)), Outcome::ProviderUnavailable);
    }

    /// Greylisting must not be mistaken for rejection, or mail is dropped from every
    /// correctly-configured receiver that uses it.
    #[test]
    fn greylisting_replies_try_the_fallback() {
        for code in [450, 451, 452] {
            assert_eq!(
                classify_reply(Some(code)),
                Outcome::ProviderUnavailable,
                "{code} is a transient 'come back shortly'"
            );
        }
    }

    #[test]
    fn no_reply_at_all_tries_the_fallback() {
        assert_eq!(classify_reply(None), Outcome::ProviderUnavailable);
    }

    /// Intermediate replies are never a final result and must never read as delivery.
    #[test]
    fn intermediate_replies_are_not_deliveries() {
        for code in [220, 221, 354, 334, 100, 399] {
            let outcome = classify_reply(Some(code));
            if (200..=299).contains(&code) {
                // 220 and 221 are 2yz and legitimately positive; the point is 3yz is not.
                assert_eq!(outcome, Outcome::Delivered, "{code}");
            } else {
                assert_ne!(outcome, Outcome::Delivered, "{code} is not a delivery");
            }
        }
    }

    /// Asserted over the WHOLE code space, not a list of examples: only 5yz may ever reject a
    /// message, and only 2yz may ever report a delivery.
    ///
    /// A hand-written list would not necessarily catch a band that started behaving
    /// differently, and both directions here are expensive: a rejection outside 5yz drops mail
    /// permanently with no failover, and a delivery outside 2yz records a success for a message
    /// that was never accepted.
    #[test]
    fn the_bands_are_confined_over_the_whole_code_space() {
        for code in 100_u16..=599 {
            match classify_reply(Some(code)) {
                Outcome::MessageRejected => assert!(
                    (500..=599).contains(&code),
                    "{code} rejected the message from outside the permanent band"
                ),
                Outcome::Delivered => assert!(
                    (200..=299).contains(&code),
                    "{code} reported a delivery from outside the positive band"
                ),
                Outcome::ProviderUnavailable => {}
            }
        }
    }

    /// The permanent-band carve-outs are exactly the four authentication codes.
    ///
    /// Pinning the SET, so adding one is a deliberate edit here rather than something that
    /// slips in and quietly stops a class of permanent failure from being reported as such.
    #[test]
    fn the_permanent_carve_outs_are_exactly_the_authentication_codes() {
        let carved: Vec<u16> = (500_u16..=599)
            .filter(|code| classify_reply(Some(*code)) != Outcome::MessageRejected)
            .collect();
        assert_eq!(carved, vec![530, 534, 535, 538]);
    }

    /// The two channels agree on the SHAPE of the decision even though their codes differ.
    ///
    /// Both carve authentication out of their permanent band, both treat rate limiting or
    /// overload as transient, and both refuse to report a delivery for anything that accepted
    /// nothing. Stated as a test so a future adapter author sees the pattern is intentional
    /// rather than coincidental.
    #[test]
    fn the_smtp_and_http_channels_make_the_same_shaped_decision() {
        use crate::message_http_channel::classify_status;

        // Authentication: permanent-looking, provider's problem, in both.
        assert_eq!(classify_reply(Some(535)), classify_status(Some(401)));
        // Overload or rate limit: transient in both.
        assert_eq!(classify_reply(Some(421)), classify_status(Some(429)));
        // A genuinely bad recipient or request: rejected in both.
        assert_eq!(classify_reply(Some(550)), classify_status(Some(400)));
        // Nothing arrived: provider's problem in both.
        assert_eq!(classify_reply(None), classify_status(None));
    }
}
