// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a service provider must check about an assertion whose signature already verified
//! (issue #139).
//!
//! # A verified signature is not an accepted assertion
//!
//! [`crate::verify`] answers one question: did a key this deployment pinned sign these bytes.
//! Every CVE class #139 names is about what happens NEXT, and each of them is a check somebody
//! shipped without:
//!
//! - **CVE-2026-9093, audience.** An assertion for a different service provider is still validly
//!   signed. Without an audience check, an assertion a customer's identity provider minted for
//!   any other relying party is accepted here.
//! - **CVE-2026-9096, time bounds.** An assertion from last year is still validly signed. Without
//!   `NotBefore` and `NotOnOrAfter`, a captured assertion never expires.
//! - **CVE-2026-9098, `InResponseTo`.** A response nobody asked for is still validly signed.
//!   Without correlation, anyone who obtains one can replay it at the assertion consumer.
//!
//! They share a shape, which is why they share a module: each is a value in the assertion that
//! has to equal something THIS deployment already knew, and skipping any of them leaves a
//! signature check that proves the document is genuine and nothing about whether it is for us,
//! for now, or for a sign-in anybody started.
//!
//! # Every check is mandatory and there is no way to turn one off
//!
//! There is no configuration here beyond the values to compare against. A deployment cannot
//! disable the audience check the way several implementations allow, because an operator does not
//! reach for that switch except to make an integration work that should not, and the CVE list
//! above is what happens after they do.
//!
//! The one thing an operator chooses is whether an UNSOLICITED response is admissible at all, and
//! that is expressed by whether [`Expectations::in_response_to`] carries a request id: `Some`
//! means this response must name that request, `None` means the caller has accepted an
//! unsolicited one and has its own replay defence.

use crate::instant::parse_utc;
use crate::verify::VerifiedAssertion;

/// The SAML 2.0 assertion namespace.
const ASSERTION: &str = crate::ASSERTION_NS;

/// What this deployment already knew, which the assertion has to agree with.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// This deployment's entity id for the connection the response arrived for. The assertion's
    /// `Audience` must equal it.
    pub audience: &'a str,
    /// The assertion consumer URL the response arrived at. `Destination` and `Recipient` must
    /// equal it where they are present.
    pub recipient: &'a str,
    /// The `AuthnRequest` this response must answer.
    ///
    /// `Some` is the ordinary case and is what makes a captured response useless a second time.
    /// `None` says the caller has accepted an unsolicited response and is defending it another
    /// way -- see the module note.
    pub in_response_to: Option<&'a str>,
    /// How far outside a window a clock may be and still be believed, in seconds.
    pub clock_skew_secs: i64,
    /// The longest this deployment will treat an assertion as valid, whatever the identity
    /// provider asserted, in seconds.
    pub max_age_secs: i64,
}

/// Why an assertion whose signature verified is still not acceptable.
///
/// # One variant per THING AN OPERATOR HAS TO FIX
///
/// #139 asks for typed failures so a connection test can say what is wrong, and that is what
/// decides the taxonomy: `WrongAudience` means the entity ids do not match and somebody has to
/// edit one, `Expired` means the clocks disagree or the response is old, `UnknownRequest` means
/// the correlation failed. Collapsing them into one "invalid assertion" is what makes SAML
/// integrations take days.
///
/// It is deliberately NOT finer than that. A variant per FIELD would tell an attacker which of
/// their forgeries got furthest, and that is the reasoning [`crate::VerifyError`] already gives
/// for its own coarseness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionError {
    /// The assertion names no `Audience`, or names one that is not this deployment.
    ///
    /// CVE-2026-9093 is the class: an assertion minted for another relying party verifies
    /// perfectly and is not for us.
    WrongAudience {
        /// What the assertion said, if it said anything unambiguous.
        found: Option<String>,
    },
    /// The assertion carries no usable time bounds, or the clock is outside them.
    ///
    /// CVE-2026-9096. An assertion with no `NotOnOrAfter` never expires, so its ABSENCE is a
    /// refusal here rather than an open window.
    Expired,
    /// The assertion is valid for longer than this deployment will believe.
    ///
    /// Separate from [`Self::Expired`] because the fix is different: an operator has to shorten
    /// what their identity provider issues, or raise `max_age_secs` knowing what it buys. An
    /// identity provider that asserts a twelve-hour window is handing out twelve-hour bearer
    /// tokens.
    TooLongLived,
    /// The response does not answer a request this deployment issued.
    ///
    /// CVE-2026-9098. Includes an assertion carrying no `InResponseTo` when one was required:
    /// silence is not a match.
    UnknownRequest,
    /// `Destination` or `Recipient` names somewhere other than where this response arrived.
    ///
    /// The token-recipient-confusion class: a response captured at one service provider and
    /// replayed at another verifies, and this is what refuses it.
    WrongRecipient {
        /// What the assertion said, if it said anything unambiguous.
        found: Option<String>,
    },
    /// The assertion is not a `saml:Assertion`, or carries two of something it may carry one of.
    ///
    /// An ambiguous read is no read: [`VerifiedAssertion`] answers `None` for two matches as
    /// well as none, so a document carrying two `Conditions` lands here rather than having one
    /// of them believed.
    Malformed,
}

impl core::fmt::Display for ConditionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongAudience { .. } => {
                f.write_str("the assertion is addressed to a different service provider")
            }
            Self::Expired => f.write_str("the assertion is outside its validity window"),
            Self::TooLongLived => {
                f.write_str("the assertion is valid for longer than this connection allows")
            }
            Self::UnknownRequest => {
                f.write_str("the response does not answer a sign-in this server started")
            }
            Self::WrongRecipient { .. } => {
                f.write_str("the assertion was addressed to a different endpoint")
            }
            Self::Malformed => f.write_str("the assertion is not one this server can read"),
        }
    }
}

impl core::error::Error for ConditionError {}

/// What an accepted assertion says about the person, once every condition has held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The `NameID` text: who the identity provider says this is.
    pub name_id: String,
    /// The `NameID`'s `Format`, where it named one.
    pub name_id_format: Option<String>,
    /// The assertion's own `ID`, which a caller records so the same one cannot be admitted twice.
    pub assertion_id: String,
    /// When this deployment stops treating the assertion as valid, in epoch seconds. The EARLIER
    /// of what the assertion said and what `max_age_secs` allows, which is what a replay cache
    /// remembers it until.
    pub expires_at_unix_secs: i64,
}

/// Check every condition, or say which one failed.
///
/// `now_unix_secs` comes from the caller's clock seam, never from the database or the system
/// clock reached directly: a check on a window has to be deterministic under a manual clock or
/// its own tests cannot drive the edges.
///
/// # Errors
///
/// [`ConditionError`], one variant per thing an operator has to fix.
pub fn check(
    assertion: &VerifiedAssertion,
    expectations: &Expectations<'_>,
    now_unix_secs: i64,
) -> Result<Accepted, ConditionError> {
    // IT MUST BE AN ASSERTION. `verify` takes the element to read as an argument, so a caller
    // could have asked it for something else entirely and handed the result here.
    if !assertion.name().ends_with("Assertion") {
        return Err(ConditionError::Malformed);
    }
    let assertion_id = assertion
        .attribute("ID")
        .ok_or(ConditionError::Malformed)?
        .to_owned();

    // THE AUDIENCE. Absence is a refusal, not a wildcard: an assertion that restricts itself to
    // nobody is one any relying party would accept, which is the opposite of what an
    // `AudienceRestriction` is for.
    let audience = assertion.text_of(ASSERTION, "Audience");
    match audience.as_deref() {
        Some(found) if found == expectations.audience => {}
        found => {
            return Err(ConditionError::WrongAudience {
                found: found.map(ToOwned::to_owned),
            });
        }
    }

    // THE TIME BOUNDS. Both are required: an assertion with no `NotOnOrAfter` never expires, and
    // one with no `NotBefore` can be pre-dated. `Conditions` carries them.
    let not_before = assertion
        .attribute_of(ASSERTION, "Conditions", "NotBefore")
        .and_then(parse_utc)
        .ok_or(ConditionError::Expired)?;
    let not_on_or_after = assertion
        .attribute_of(ASSERTION, "Conditions", "NotOnOrAfter")
        .and_then(parse_utc)
        .ok_or(ConditionError::Expired)?;
    // A WINDOW THAT ENDS BEFORE IT STARTS is not a window. Refused rather than evaluated, because
    // every comparison below would then be against a range nothing is inside and the answer would
    // be "expired", which is the wrong thing to tell an operator.
    if not_on_or_after <= not_before {
        return Err(ConditionError::Expired);
    }
    let skew = expectations.clock_skew_secs.max(0);
    if now_unix_secs + skew < not_before || now_unix_secs - skew >= not_on_or_after {
        return Err(ConditionError::Expired);
    }
    // AND THIS DEPLOYMENT'S OWN CEILING, applied to what the identity provider asserted rather
    // than to the clock: an assertion issued with a twelve-hour window is a twelve-hour bearer
    // token whether or not it is currently inside it.
    if not_on_or_after - not_before > expectations.max_age_secs {
        return Err(ConditionError::TooLongLived);
    }

    // THE CORRELATION. `SubjectConfirmationData` carries it, and where a request was required its
    // absence is a refusal: silence is not a match.
    let carried = assertion.attribute_of(ASSERTION, "SubjectConfirmationData", "InResponseTo");
    match (expectations.in_response_to, carried) {
        (Some(expected), Some(found)) if expected == found => {}
        (None, None) => {}
        // EVERYTHING ELSE IS THE SAME REFUSAL, and the arms are written out rather than collapsed
        // because each is a different attack and the list is the documentation:
        //
        // `(Some(_), None)` is a response carrying no correlation at all where one was required.
        // `(Some(_), Some(_))` past the guard above is a response answering a DIFFERENT sign-in.
        // `(None, Some(_))` is a response naming a request on a connection that is not
        // correlating -- a sign-in somebody else started, which would otherwise ride an
        // unsolicited-enabled connection.
        _ => return Err(ConditionError::UnknownRequest),
    }

    // THE RECIPIENT. Both `Destination` on the response and `Recipient` on the confirmation name
    // where the assertion was meant to be delivered; this checks the one inside the SIGNED
    // element, which is the only one whose integrity this crate can speak for.
    if let Some(found) = assertion.attribute_of(ASSERTION, "SubjectConfirmationData", "Recipient") {
        if found != expectations.recipient {
            return Err(ConditionError::WrongRecipient {
                found: Some(found.to_owned()),
            });
        }
    }

    // WHO IT IS. Ambiguity is a refusal: two `NameID`s inside one assertion verify like any other
    // document, and choosing one is choosing which half of a contradiction to believe.
    let name_id = assertion
        .text_of(ASSERTION, "NameID")
        .filter(|text| !text.trim().is_empty())
        .ok_or(ConditionError::Malformed)?;
    let name_id_format = assertion
        .attribute_of(ASSERTION, "NameID", "Format")
        .map(ToOwned::to_owned);

    Ok(Accepted {
        name_id,
        name_id_format,
        assertion_id,
        // THE EARLIER OF THE TWO. A replay cache that remembered it only until the identity
        // provider's own expiry would forget a long-lived assertion this deployment had already
        // refused for length; remembering the shorter is what matches what was accepted.
        expires_at_unix_secs: not_on_or_after.min(not_before + expectations.max_age_secs),
    })
}
