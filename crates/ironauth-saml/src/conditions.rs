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
use crate::verify::{SignedElement, VerifiedAssertion};

/// The SAML 2.0 assertion namespace.
const ASSERTION: &str = crate::ASSERTION_NS;

/// The bearer subject-confirmation method (SAML Profiles 4.1.4.2).
///
/// The only one this profile uses. A holder-of-key confirmation asks the service provider to
/// prove possession of a key, which is a different protocol; ignoring the `Method` and reading
/// whichever confirmation came first would let a holder-of-key confirmation be honoured as a
/// bearer one, which is the whole difference between the two.
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// What this deployment already knew, which the assertion has to agree with.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// What the connection this response resolved to says its identity provider calls itself.
    /// The assertion's `Issuer` must equal it.
    ///
    /// A response is resolved by the URL it arrived at, so this is what ties the assertion's own
    /// claim of authorship to the connection whose keys verified it.
    pub issuer: &'a str,
    /// This deployment's entity id for the connection the response arrived for. The assertion's
    /// `Audience` must equal it.
    pub audience: &'a str,
    /// The assertion consumer URL the response arrived at. The bearer `Recipient` must
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
    /// The assertion is not from the identity provider this connection trusts.
    ///
    /// A response is resolved by the URL it arrived at, so a signature verifying against this
    /// connection's keys and an `Issuer` naming somebody else is a contradiction, and refusing it
    /// is what stops a pinned key being used to assert on another identity provider's behalf.
    WrongIssuer {
        /// What the assertion said, if it said anything unambiguous.
        found: Option<String>,
    },
    /// The `Conditions` element carries a restriction this server cannot evaluate.
    ///
    /// SAML Core 2.5 requires a service provider that does not understand a `Condition` to treat
    /// the assertion as INVALID. Ignoring one would turn every restriction an identity provider
    /// adds in future into a no-op, which is the opposite of what the element is for.
    UnsupportedCondition {
        /// The local name of the condition, so an operator can say what their identity provider
        /// is sending.
        name: String,
    },
    /// The assertion names no `Audience`, or names one that is not this deployment.
    ///
    /// CVE-2026-9093 is the class: an assertion minted for another relying party verifies
    /// perfectly and is not for us.
    WrongAudience {
        /// What the assertion said, if it said anything unambiguous.
        found: Option<String>,
    },
    /// The clock is outside the window the assertion or its confirmation named.
    ///
    /// CVE-2026-9096.
    Expired,
    /// A bound this server requires is absent.
    ///
    /// SEPARATE FROM [`Self::Expired`] BECAUSE THE OPERATOR'S FIX IS DIFFERENT. "Expired" sends
    /// somebody to look at clock skew; what actually happened is that their identity provider
    /// does not emit the attribute named here. SAML Core 2.5.1.2 makes `NotBefore` OPTIONAL and
    /// this server requires it anyway -- without it a bearer assertion can be pre-dated, and its
    /// lifetime cannot be bounded at all, which would make [`Self::TooLongLived`] unenforceable.
    /// That is a deliberate tightening, and an operator is entitled to be told it in those terms
    /// rather than through an expiry that did not happen.
    MissingBound {
        /// The attribute, or the element, that was not there.
        attribute: &'static str,
    },
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
    /// `Recipient` names somewhere other than where this response arrived.
    ///
    /// NOT `Destination`, WHICH THIS LAYER CANNOT SEE. `Destination` is an attribute of the
    /// `samlp:Response`, and what [`check`] is handed is the SIGNED `saml:Assertion` -- the
    /// Response's attributes are not inside it, so no fixture could even construct a mismatch.
    /// Nor would reading it be worth much: Okta and Entra both leave the Response unsigned by
    /// default, which makes `Destination` attacker-mutable, and `tests/owasp_checklist.rs`
    /// already records it as not applicable for exactly that reason. `Recipient` is inside the
    /// signature and is the value that actually binds a response to this endpoint.
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
            Self::WrongIssuer { .. } => f.write_str(
                "the assertion is not from the identity provider this connection trusts",
            ),
            Self::UnsupportedCondition { .. } => {
                f.write_str("the assertion carries a condition this server cannot evaluate")
            }
            Self::WrongAudience { .. } => {
                f.write_str("the assertion is addressed to a different service provider")
            }
            Self::Expired => f.write_str("the assertion is outside its validity window"),
            Self::MissingBound { attribute } => {
                write!(
                    f,
                    "the assertion carries no {attribute}, which this server requires"
                )
            }
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
/// # Every read names the PARENT it means
///
/// SAML reuses element names under different parents with different meanings, so a search of
/// every descendant is the wrong question. `saml:Audience` is a child of `AudienceRestriction`
/// ("this assertion is addressed to you") and of `ProxyRestriction` ("somebody else may re-assert
/// this to you"); `saml:NameID` is the Subject's ("who this is") and the `SubjectConfirmation`'s
/// ("who may present this"). A first version of this function read both by descendant search, so
/// an assertion carrying only a `ProxyRestriction` naming this deployment passed the audience
/// check, and a `NameID` inside a confirmation could become the signed-in identity.
///
/// # Errors
///
/// [`ConditionError`], one variant per thing an operator has to fix.
pub fn check(
    assertion: &VerifiedAssertion,
    expectations: &Expectations<'_>,
    now_unix_secs: i64,
) -> Result<Accepted, ConditionError> {
    // IT MUST BE AN ASSERTION, resolved rather than spelled. `verify` takes the element to read
    // as an argument, so a caller could have asked it for something else entirely and handed the
    // result here. An earlier version tested `name().ends_with("Assertion")`, which is a test on
    // the QUALIFIED name: true for `evil:NotAnAssertion` in any namespace at all, and false for
    // the `Assertion` Entra writes under a default `xmlns`.
    if !assertion.is(ASSERTION, "Assertion") {
        return Err(ConditionError::Malformed);
    }
    let assertion_id = assertion
        .attribute("ID")
        .ok_or(ConditionError::Malformed)?
        .to_owned();

    // WHO SIGNED IT. Compared here rather than left to the caller: the earlier version documented
    // the issuer as "a check the caller makes" and gave no field to make it with, which is a
    // control that exists only in prose. A response is resolved by the URL it arrived at, so this
    // is what ties the assertion's own claim of authorship to the connection it was resolved to.
    let issuer = assertion
        .elements(ASSERTION, "Issuer")
        .first()
        .map(SignedElement::text);
    match issuer.as_deref() {
        Some(found) if found == expectations.issuer => {}
        found => {
            return Err(ConditionError::WrongIssuer {
                found: found.map(ToOwned::to_owned),
            });
        }
    }

    // EXACTLY ONE `Conditions`, resolved as an element so everything below is read WITHIN it.
    let conditions = assertion.elements(ASSERTION, "Conditions");
    let conditions = match conditions.as_slice() {
        [single] => single,
        // NONE AND TWO ARE DIFFERENT FAULTS and the operator's fix differs, so they do not share
        // an error: an assertion with no `Conditions` never expires and never named an audience;
        // one with two is a contradiction, and a reader that took either would be choosing which
        // half to believe -- so an attacker who can append or prepend chooses for it.
        [] => {
            return Err(ConditionError::MissingBound {
                attribute: "Conditions element",
            });
        }
        _ => return Err(ConditionError::Malformed),
    };

    let (not_before, not_on_or_after) = read_conditions(conditions, expectations, now_unix_secs)?;
    let (name_id_element, confirmation_expiry) =
        read_subject(assertion, expectations, now_unix_secs)?;
    let name_id = name_id_element.text();
    if name_id.trim().is_empty() {
        return Err(ConditionError::Malformed);
    }
    let name_id_format = name_id_element.attribute("Format").map(ToOwned::to_owned);

    Ok(Accepted {
        name_id,
        name_id_format,
        assertion_id,
        // THE EARLIEST OF THE THREE. The replay cache remembers an assertion until it could no
        // longer be accepted, and the confirmation's expiry is usually the soonest of them --
        // remembering only the assertion's would keep it long past the point it stopped being
        // usable, and remembering only the ceiling would forget a short one too late.
        //
        // The ceiling operand cannot bind on its own here, because a window longer than it was
        // already refused above; it is in the `min` so that a later change to that refusal cannot
        // silently make this value longer than what was accepted.
        //
        // `saturating_add` RATHER THAN `+`: `max_age_secs` is a public field with no bound, no
        // constructor and no validator, so `i64::MAX` is the only way this API lets a caller say
        // "no ceiling of my own". A plain `+` panics on it in debug and wraps to a large NEGATIVE
        // in release -- and that wrapped value would WIN the `min`, so the one case in which this
        // operand is not inert would be the one case in which it is wrong: an assertion just
        // accepted, stamped as having expired in 1969.
        expires_at_unix_secs: not_on_or_after
            .min(not_before.saturating_add(expectations.max_age_secs))
            .min(confirmation_expiry),
    })
}

/// Everything the `Conditions` element decides: who the assertion is addressed to, what
/// restrictions it carries, and the window it is true in. Answers the two bounds.
///
/// SPLIT OUT SO THE PARENT IS AN ARGUMENT rather than something rediscovered. Every read in here
/// is a read WITHIN `conditions`; taking it as a parameter is what makes that structural rather
/// than a rule somebody has to keep remembering.
fn read_conditions(
    conditions: &SignedElement<'_>,
    expectations: &Expectations<'_>,
    now_unix_secs: i64,
) -> Result<(i64, i64), ConditionError> {
    // THE AUDIENCE, read only from `AudienceRestriction` children of `Conditions`.
    //
    // SAML Core 2.5.1.4: an assertion may carry SEVERAL `AudienceRestriction` elements, each with
    // several `Audience` children, and the service provider must be named in EVERY restriction --
    // they intersect. A first version demanded exactly one `Audience` in the whole assertion,
    // which refused the ordinary multi-audience assertion an identity provider issues when one
    // relying party has several entity ids, and reported it as "the assertion named no audience".
    let restrictions = conditions.children(ASSERTION, "AudienceRestriction");
    if restrictions.is_empty() {
        // AN ASSERTION RESTRICTED TO NOBODY IS ONE ANY RELYING PARTY WOULD ACCEPT, which is the
        // opposite of what an `AudienceRestriction` is for.
        return Err(ConditionError::WrongAudience { found: None });
    }
    for restriction in &restrictions {
        let named = restriction.child_texts(ASSERTION, "Audience");
        if !named
            .iter()
            .any(|audience| audience == expectations.audience)
        {
            return Err(ConditionError::WrongAudience {
                found: named.first().cloned(),
            });
        }
    }

    // A CONDITION THIS SERVER DOES NOT UNDERSTAND IS A REFUSAL. SAML Core 2.5 is explicit: a
    // service provider that cannot evaluate a `Condition` MUST treat the assertion as invalid.
    // The whole point of the element is that an identity provider can add a restriction and rely
    // on it being honoured; silently ignoring one turns every future restriction into a no-op.
    for child in conditions.element_children() {
        if !matches!(
            child.as_str(),
            "AudienceRestriction" | "OneTimeUse" | "ProxyRestriction"
        ) {
            return Err(ConditionError::UnsupportedCondition {
                name: child.clone(),
            });
        }
    }

    // THE TIME BOUNDS, read as attributes OF `Conditions`. Both are required: an assertion with
    // no `NotOnOrAfter` never expires, and one with no `NotBefore` can be pre-dated.
    let not_before = conditions
        .attribute("NotBefore")
        .and_then(parse_utc)
        .ok_or(ConditionError::MissingBound {
            attribute: "Conditions/@NotBefore",
        })?;
    let not_on_or_after = conditions
        .attribute("NotOnOrAfter")
        .and_then(parse_utc)
        .ok_or(ConditionError::MissingBound {
            attribute: "Conditions/@NotOnOrAfter",
        })?;
    // A WINDOW THAT ENDS BEFORE IT STARTS is not a window. Refused as `Malformed` rather than
    // `Expired`, because nothing about a clock would make it valid and telling an operator it
    // expired sends them to look at clock skew.
    if not_on_or_after <= not_before {
        return Err(ConditionError::Malformed);
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

    Ok((not_before, not_on_or_after))
}

/// Everything the `Subject` decides: who this is, and how they were allowed to present it.
/// Answers the `NameID` element and the bearer confirmation's own expiry.
fn read_subject<'a>(
    assertion: &'a VerifiedAssertion,
    expectations: &Expectations<'_>,
    now_unix_secs: i64,
) -> Result<(SignedElement<'a>, i64), ConditionError> {
    let skew = expectations.clock_skew_secs.max(0);
    // THE SUBJECT, and EXACTLY ONE of it. Everything about who this is and how they may present
    // it is read within here, never by descendant search.
    let subjects = assertion.elements(ASSERTION, "Subject");
    let [subject] = subjects.as_slice() else {
        return Err(ConditionError::Malformed);
    };

    // THE BEARER CONFIRMATION, and exactly one. SAML Profiles 4.1.4.2 requires at least one
    // bearer `SubjectConfirmation`; more than one is ambiguity this crate refuses everywhere
    // else, and here the ambiguity decides which request the response answers.
    let confirmations: Vec<_> = subject
        .children(ASSERTION, "SubjectConfirmation")
        .into_iter()
        .filter(|confirmation| confirmation.attribute("Method") == Some(BEARER))
        .collect();
    let [confirmation] = confirmations.as_slice() else {
        return Err(ConditionError::Malformed);
    };
    let datas = confirmation.children(ASSERTION, "SubjectConfirmationData");
    let [data] = datas.as_slice() else {
        return Err(ConditionError::Malformed);
    };

    // THE CORRELATION. Where a request was required its absence is a refusal: silence is not a
    // match.
    let carried = data.attribute("InResponseTo");
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

    // THE RECIPIENT, and its ABSENCE IS A REFUSAL. SAML Profiles 4.1.4.2 requires it on a bearer
    // confirmation, and an earlier version skipped the check when it was missing -- so the
    // recipient-confusion defence disappeared exactly when an attacker omitted the attribute,
    // which is the one thing they control.
    let recipient = data.attribute("Recipient");
    match recipient {
        Some(found) if found == expectations.recipient => {}
        found => {
            return Err(ConditionError::WrongRecipient {
                found: found.map(ToOwned::to_owned),
            });
        }
    }

    // THE CONFIRMATION'S OWN EXPIRY, which is the bearer profile's and is a DIFFERENT bound from
    // the assertion's: 4.1.4.2 requires it, and it is usually much shorter, because it bounds how
    // long the response may be in flight rather than how long the statement is true.
    let confirmation_expiry =
        data.attribute("NotOnOrAfter")
            .and_then(parse_utc)
            .ok_or(ConditionError::MissingBound {
                attribute: "SubjectConfirmationData/@NotOnOrAfter",
            })?;
    if now_unix_secs - skew >= confirmation_expiry {
        return Err(ConditionError::Expired);
    }

    // WHO IT IS: the SUBJECT's `NameID`, never a descendant search. A `SubjectConfirmation` may
    // carry its own `NameID` naming who may PRESENT the assertion, and a descendant search would
    // have let that become the signed-in identity.
    let name_ids = subject.children(ASSERTION, "NameID");
    let [name_id_element] = name_ids.as_slice() else {
        return Err(ConditionError::Malformed);
    };
    Ok((name_id_element.clone(), confirmation_expiry))
}
