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
//! ONE HONEST EXCEPTION: [`Expectations::clock_skew_secs`] is unbounded above, and a large enough
//! value is the same as no time check at all. This module clamps it at zero from below and
//! saturates its arithmetic, but the ceiling belongs with whatever builds `Expectations` from a
//! connection's configuration -- nothing here can say what "too large" means for a deployment.
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
    /// The assertion consumer URL the response arrived at. The bearer confirmation's
    /// `Recipient` must equal it, and its ABSENCE is a refusal -- an earlier version of this
    /// sentence ended "where they are present", which licensed exactly the defect the code now
    /// refuses: the recipient-confusion defence disappearing when an attacker omits the one
    /// attribute they control.
    pub recipient: &'a str,
    /// The `AuthnRequest` this response must answer.
    ///
    /// `Some` is the ordinary case and is what makes a captured response useless a second time.
    /// `None` says the caller has accepted an unsolicited response and is defending it another
    /// way -- see the module note.
    pub in_response_to: Option<&'a str>,
    /// How far outside a window a clock may be and still be believed, in seconds.
    ///
    /// NOT BOUNDED HERE, AND THAT IS THE CALLER'S PROBLEM TO SOLVE -- the one hole in the module
    /// note's "no way to turn one off". A large enough value is the same as no time check at all, and nothing in this module can say what "large enough"
    /// means for a deployment -- so it clamps the value at zero from below (a negative skew is
    /// read as none, never as a narrowing) and saturates its arithmetic, but the ceiling belongs
    /// with whatever constructs `Expectations` from a connection's configuration. Said plainly
    /// because an earlier test named itself "and is not unbounded" while measuring only that a
    /// SMALLER value refused more, which is a property of the caller's choice, not of a bound.
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
    /// A bound is present and this server cannot read it.
    ///
    /// SEPARATE FROM [`Self::MissingBound`] FOR THE SAME REASON THAT ONE IS SEPARATE FROM
    /// [`Self::Expired`]: the operator's fix differs. "Carries no `NotBefore`" sends somebody to
    /// look for an attribute that is right there in the document; what actually happened is that
    /// its VALUE is not the narrow `xsd:dateTime` form [`crate::parse_utc`] accepts -- an offset
    /// instead of `Z`, a year outside 1900..=2200, a leap second. Collapsing the two put a
    /// document an operator can see on screen behind an error saying it does not exist.
    UnreadableBound {
        /// The attribute whose value could not be read.
        attribute: &'static str,
        /// What it said, so an operator can see what their identity provider emitted.
        found: String,
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
    /// An ambiguous read is no read, so a document carrying two `Conditions`, two `Subject`s or
    /// two bearer `SubjectConfirmation`s lands here rather than having one of them believed.
    ///
    /// ABSENCE LANDS HERE TOO, for everything except the time bounds. An assertion with no
    /// `Subject`, no `NameID`, no bearer `SubjectConfirmation` and no `SubjectConfirmationData`
    /// is refused here rather than through a variant of its own, because there is nothing an
    /// operator could configure differently in response: a bearer assertion without a subject is
    /// not a misconfiguration, it is not an assertion this profile describes.
    ///
    /// The two exceptions are where naming the fault DOES change what somebody does about it.
    /// A missing time bound is [`Self::MissingBound`], because SAML makes `NotBefore` optional
    /// and this server requires it -- an operator has to be told that on purpose. And two
    /// `Issuer` elements are [`Self::WrongIssuer`] with `found: None`, because the question
    /// there is which provider signed this and "neither, unambiguously" answers that question.
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
            Self::UnreadableBound { attribute, found } => write!(
                f,
                "the assertion's {attribute} is {found:?}, which is not a UTC xsd:dateTime this \
                 server can read"
            ),
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
    /// The `InResponseTo` the bearer confirmation carried, when it carried one.
    ///
    /// # Why a caller needs this back, having just supplied it
    ///
    /// It supplied [`Expectations::in_response_to`] as a POLICY -- whether this connection
    /// correlates at all -- and a correlating connection does not know WHICH outstanding request
    /// a given response answers until it reads one. The endpoint has to spend exactly that
    /// request, once, and it can only name it if this hands it back.
    ///
    /// SAFE TO ACT ON BECAUSE IT IS POST-CHECK. By the time this exists the signature verified,
    /// and if the caller asked for correlation then this value equalled what the caller
    /// expected -- so a caller looping over its outstanding requests is not the shape here. What
    /// a caller does with it is prove the request was ITS OWN and unspent, which is a fact only
    /// the store has.
    ///
    /// [`None`] for a response this deployment did not solicit, which is admissible only on a
    /// connection that opted in.
    pub in_response_to: Option<String>,
    /// When this deployment stops treating the assertion as valid, in epoch seconds, which is
    /// what a replay cache remembers it until.
    ///
    /// The EARLIEST of FOUR things, not two: the assertion's own `NotOnOrAfter`, the bearer
    /// confirmation's own `NotOnOrAfter`, and `max_age_secs` measured from `NotBefore` -- plus
    /// `clock_skew_secs`, added at the end, because the window comparison admits the assertion
    /// for that long past every one of them. Remembering it only to the bound would forget it
    /// while it could still be presented, and then admit the replay.
    ///
    /// The `max_age_secs` operand cannot bind on its own: a window longer than it was already
    /// refused as [`ConditionError::TooLongLived`]. It is in the minimum so that a later change
    /// to that refusal cannot silently make this value outlast what was accepted.
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
    // the QUALIFIED name and is wrong on two axes: true for `evil:NotAnAssertion` because the
    // suffix matches, and true for `evil:Assertion` in a namespace nobody trusts because it
    // never looks at one.
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
    //
    // A DIRECT CHILD, AND EXACTLY ONE. `elements` searches every descendant, and SAML puts
    // `saml:Issuer` in more than one place: `saml:AttributeValue` is `xs:anyType`, so an
    // attribute's value may legitimately contain one, and nothing stops a second one being
    // appended at the top level either.
    //
    // (`saml:Advice` carries whole advisory ASSERTIONS, which would be the same problem -- but
    // `verify` refuses a document with two `saml:Assertion` candidates before this function sees
    // it, so that half is unreachable here and no fixture can express it. Said explicitly
    // because naming an unreachable example as the reason for a guard is how a guard ends up
    // with no test.) Reading by descendant search let an attacker append a
    // second `Issuer` naming the trusted provider and have it believed -- and because the walk
    // uses a stack, "the first" was the LAST in document order, so appending was enough.
    let issuers = assertion.children(ASSERTION, "Issuer");
    let issuer = match issuers.as_slice() {
        // COLLAPSED, AND NOT BECAUSE `Issuer` IS `anyURI` -- IT IS NOT. `saml:Issuer` is a
        // `saml:NameIDType`, whose content is `xsd:string` and preserves whitespace. It is
        // collapsed here because it is compared against ONE configured value: trimming can make
        // a padded spelling of the provider we already trust match, and it cannot make a
        // DIFFERENT provider match. `NameID` gets the opposite treatment, and for the opposite
        // reason: there the comparison is against an account, and collapsing would map two
        // schema-distinct people onto one.
        //
        // `None` here is either no text at all or MIXED CONTENT, which is a refusal.
        [single] => single.text_collapsed(),
        // TWO IS NOT ONE, and this module refuses ambiguity everywhere else. Reported as
        // `WrongIssuer { found: None }` rather than naming either: naming one would print the
        // value this server did NOT act on, which is worse than printing nothing.
        [] | [_, ..] => None,
    };
    match issuer.as_deref() {
        Some(found) if found == expectations.issuer => {}
        found => {
            return Err(ConditionError::WrongIssuer {
                found: found.map(ToOwned::to_owned),
            });
        }
    }

    // EXACTLY ONE `Conditions`, AS A DIRECT CHILD, resolved as an element so everything below is
    // read WITHIN it. A descendant search reached the advisory `Conditions` of an assertion
    // nested in `saml:Advice`, which then supplied this assertion's window and audience.
    let conditions = assertion.children(ASSERTION, "Conditions");
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

    let skew = expectations.clock_skew_secs.max(0);
    let (not_before, not_on_or_after) =
        read_conditions(conditions, expectations, now_unix_secs, skew)?;
    let (name_id_element, confirmation_expiry, correlation) =
        read_subject(assertion, expectations, now_unix_secs, skew)?;
    // THE VALUE THE GUARD CHECKED MUST BE THE VALUE RETURNED. An earlier version tested
    // `name_id.trim().is_empty()` and then returned the UNTRIMMED text, so " ada@globex.example "
    // passed a check on a string the caller never sees and was signed in with its spaces --
    // which is a different account key from the same name flush, and a way to mint a second
    // identity for one person.
    //
    // REFUSED RATHER THAN SILENTLY TRIMMED. `NameID` content is `xsd:string`, which PRESERVES
    // whitespace (unlike the `anyURI` audience and issuer, which XSD collapses before any
    // comparison), so trimming here would be this server deciding that two values the schema
    // says are different name one person. Refusing says so out loud.
    // `text_simple` RATHER THAN `text`: `saml:NameID` is `xsd:string`, which is SIMPLE content,
    // so an element child inside it is not a name with a decoration -- it is a document no
    // conforming reader would agree with this one about.
    let Some(name_id) = name_id_element.text_simple() else {
        return Err(ConditionError::Malformed);
    };
    if name_id.is_empty() || name_id.trim() != name_id {
        return Err(ConditionError::Malformed);
    }
    let name_id_format = name_id_element.attribute("Format").map(ToOwned::to_owned);

    Ok(Accepted {
        name_id,
        name_id_format,
        assertion_id,
        in_response_to: correlation,
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
            .min(confirmation_expiry)
            // AND THE SKEW THAT ADMITTED IT. The window comparison accepts while
            // `now - skew < not_on_or_after`, so this assertion stays admissible for `skew`
            // seconds past every bound above. A replay cache told to forget it at the bound
            // would forget it while it could still be presented, and would then admit the
            // replay -- which is the one thing the cache exists to stop.
            .saturating_add(skew),
    })
}

/// The one bearer `SubjectConfirmationData` inside a `Subject`.
///
/// SAML Profiles 4.1.4.2 requires at least one bearer `SubjectConfirmation`; more than one is
/// ambiguity this crate refuses everywhere else, and here the ambiguity decides which request
/// the response answers. Same for the `SubjectConfirmationData` inside it.
fn bearer_confirmation_data<'a>(
    subject: &SignedElement<'a>,
) -> Result<SignedElement<'a>, ConditionError> {
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
    Ok(data.clone())
}

/// The `InResponseTo` a verified assertion carries, if it carries one unambiguously.
///
/// # Why a caller needs this BEFORE `check`
///
/// [`Expectations::in_response_to`] is a policy -- whether this connection correlates -- and a
/// correlating deployment does not know WHICH of its outstanding requests a response answers
/// until it reads one. So the endpoint reads it, looks it up, and spends it; `check` then
/// confirms the value it acted on is the value the assertion carried.
///
/// # This is not authorization and must not be treated as it
///
/// It says a response NAMES a request, never that this deployment issued one. Only the store
/// knows that, and only an atomic spend proves it was unspent. A caller that stopped here would
/// accept any response that names any id.
///
/// READ THE SAME WAY `check` READS IT, through the same direct-child walk, so the two cannot
/// disagree about which confirmation is the one -- which is the defect class this crate is
/// built against. [`None`] for an assertion with no bearer confirmation, two of them, or no
/// `InResponseTo`: all three are "no unambiguous request named", and `check` gives each its own
/// refusal on the pass that matters.
#[must_use]
pub fn correlation(assertion: &VerifiedAssertion) -> Option<String> {
    let subjects = assertion.children(ASSERTION, "Subject");
    let [subject] = subjects.as_slice() else {
        return None;
    };
    bearer_confirmation_data(subject)
        .ok()?
        .attribute("InResponseTo")
        .map(ToOwned::to_owned)
}

/// One `xsd:dateTime` bound, distinguishing ABSENT from PRESENT-AND-UNREADABLE.
///
/// `Option::and_then(parse_utc).ok_or(MissingBound)` collapses the two, and the resulting error
/// says "the assertion carries no Conditions/@NotBefore" about an attribute an operator can see
/// on screen. The two faults have different fixes: one is an identity provider that does not
/// emit the attribute, the other is one that emits it in a form this server refuses -- an offset
/// instead of `Z`, a year outside [`crate::parse_utc`]'s range, a leap second.
fn read_instant(raw: Option<&str>, attribute: &'static str) -> Result<i64, ConditionError> {
    let Some(raw) = raw else {
        return Err(ConditionError::MissingBound { attribute });
    };
    // COLLAPSED FIRST. `xsd:dateTime` carries the same `whiteSpace="collapse"` facet as
    // `anyURI`, so ` 2026-01-01T00:00:00Z ` in an attribute is the same instant to any
    // schema-aware reader -- and `parse_utc` is deliberately positional, so it would refuse it
    // and this server would report a conformant document as unreadable.
    parse_utc(raw.trim_matches(['\t', '\n', '\r', ' '])).ok_or_else(|| {
        ConditionError::UnreadableBound {
            attribute,
            found: raw.to_owned(),
        }
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
    skew: i64,
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
            .any(|audience| audience.as_deref() == Some(expectations.audience))
        {
            return Err(ConditionError::WrongAudience {
                // The FIRST of this restriction's audiences, not of the assertion's: an operator
                // reading the error needs the restriction that actually excluded them.
                found: named.first().cloned().flatten(),
            });
        }
    }

    // A CONDITION THIS SERVER DOES NOT UNDERSTAND IS A REFUSAL. SAML Core 2.5 is explicit: a
    // service provider that cannot evaluate a `Condition` MUST treat the assertion as invalid.
    // The whole point of the element is that an identity provider can add a restriction and rely
    // on it being honoured; silently ignoring one turns every future restriction into a no-op.
    for (namespace, local) in conditions.element_children() {
        // THE NAMESPACE IS PART OF THE NAME. An allowlist over local names alone admits
        // `evil:OneTimeUse` bound to a namespace nobody trusts as something this server
        // understands -- the identical bypass the assertion gate above exists to prevent.
        // WHY EACH ENTRY IS UNDERSTOOD RATHER THAN IGNORED:
        //
        // `AudienceRestriction` is evaluated three statements above.
        //
        // `ProxyRestriction` restricts who may RE-ASSERT this assertion to somebody else. It
        // binds a proxying identity provider, not a relying party, so this deployment satisfies
        // it by not proxying, which it has no code to do.
        //
        // `OneTimeUse` is satisfied by `Accepted::assertion_id` and
        // `Accepted::expires_at_unix_secs`, which this function computes SO THAT a caller can
        // admit each id exactly once. That is a contract with the caller, not an enforcement
        // here, and the endpoint that closes it is not written yet -- so a deployment that
        // ignored those two fields would be honouring `OneTimeUse` in name only. Said out loud
        // because an earlier version of this comment claimed the store already enforced it,
        // naming a method no code path calls.
        if namespace != ASSERTION
            || !matches!(
                local.as_str(),
                "AudienceRestriction" | "OneTimeUse" | "ProxyRestriction"
            )
        {
            return Err(ConditionError::UnsupportedCondition { name: local });
        }
    }

    // THE TIME BOUNDS, read as attributes OF `Conditions`. Both are required: an assertion with
    // no `NotOnOrAfter` never expires, and one with no `NotBefore` can be pre-dated.
    let not_before = read_instant(conditions.attribute("NotBefore"), "Conditions/@NotBefore")?;
    let not_on_or_after = read_instant(
        conditions.attribute("NotOnOrAfter"),
        "Conditions/@NotOnOrAfter",
    )?;
    // A WINDOW THAT ENDS BEFORE IT STARTS is not a window. Refused as `Malformed` rather than
    // `Expired`, because nothing about a clock would make it valid and telling an operator it
    // expired sends them to look at clock skew.
    if not_on_or_after <= not_before {
        return Err(ConditionError::Malformed);
    }
    // SATURATING ON BOTH SIDES, for the reason the ceiling below is saturating: `skew` comes
    // from a public field with no validator, so `i64::MAX` reaches here, and `now + skew` would
    // panic in debug and wrap NEGATIVE in release. The `.max(0)` above bounds it below; nothing
    // bounded it above.
    if now_unix_secs.saturating_add(skew) < not_before
        || now_unix_secs.saturating_sub(skew) >= not_on_or_after
    {
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
    skew: i64,
) -> Result<(SignedElement<'a>, i64, Option<String>), ConditionError> {
    // THE SUBJECT, and EXACTLY ONE of it, AS A DIRECT CHILD. Everything about who this is and
    // how they may present it is read within here, never by descendant search -- and the Subject
    // itself is found the same way, because `saml:AttributeValue` is `xs:anyType`, so a
    // descendant search finds Subjects that are somebody else's and are inside this signature
    // just as much as the real one. (`saml:Advice` would be the other route and `verify` closes
    // it, as the Issuer read above records.)
    let subjects = assertion.children(ASSERTION, "Subject");
    let [subject] = subjects.as_slice() else {
        return Err(ConditionError::Malformed);
    };

    // THE BEARER CONFIRMATION AND ITS DATA, exactly one of each. Shared with
    // [`correlation`] rather than written twice, because two readers of `InResponseTo`
    // disagreeing about which confirmation is the one is the whole defect class this crate
    // exists for.
    let data = &bearer_confirmation_data(subject)?;

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

    // AND ITS ONE PROHIBITION. SAML Profiles 4.1.4.2 says a bearer `SubjectConfirmationData`
    // MUST NOT contain a `NotBefore` attribute -- the whole point of the bearer profile is that
    // the response is presented IMMEDIATELY, so a confirmation that only becomes usable later
    // describes something the profile does not have. Honouring it silently means honouring a
    // window this server never evaluates: an assertion the identity provider marked as not yet
    // presentable would be presented and accepted.
    if let Some(found) = data.attribute("NotBefore") {
        return Err(ConditionError::UnsupportedCondition {
            name: format!("SubjectConfirmationData/@NotBefore={found}"),
        });
    }

    // THE CONFIRMATION'S OWN EXPIRY, which is the bearer profile's and is a DIFFERENT bound from
    // the assertion's: 4.1.4.2 requires it, and it is usually much shorter, because it bounds how
    // long the response may be in flight rather than how long the statement is true.
    let confirmation_expiry = read_instant(
        data.attribute("NotOnOrAfter"),
        "SubjectConfirmationData/@NotOnOrAfter",
    )?;
    if now_unix_secs.saturating_sub(skew) >= confirmation_expiry {
        return Err(ConditionError::Expired);
    }

    // WHO IT IS: the SUBJECT's `NameID`, never a descendant search. A `SubjectConfirmation` may
    // carry its own `NameID` naming who may PRESENT the assertion, and a descendant search would
    // have let that become the signed-in identity.
    let name_ids = subject.children(ASSERTION, "NameID");
    let [name_id_element] = name_ids.as_slice() else {
        return Err(ConditionError::Malformed);
    };
    Ok((
        name_id_element.clone(),
        confirmation_expiry,
        // THE VALUE THE CONFIRMATION CARRIED, not the one the caller expected: on a correlating
        // connection the two are equal by the check above, and on a non-correlating one this is
        // `None` by the same check. Handing back the caller's own argument would be a field that
        // tells them nothing.
        carried.map(ToOwned::to_owned),
    ))
}
