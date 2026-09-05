// SPDX-License-Identifier: MIT OR Apache-2.0

//! The named CVE classes of #139, one test each, over documents that GENUINELY VERIFY.
//!
//! # What every entry here has in common
//!
//! Not one of them tampers with the cryptography. Each is a document whose signature is valid
//! against a pinned key -- so a service provider that checked only "does the signature verify"
//! accepts every single one. That is the point: the whole family of SAML CVEs this issue names
//! is about what a service provider fails to check AFTER the signature holds.
//!
//! - CVE-2026-9093, audience: an assertion minted for a different relying party.
//! - CVE-2026-9096, time bounds: an assertion from last year, and one with no expiry at all.
//! - CVE-2026-9098, correlation: a response nobody asked for.
//!
//! # And the mirror of each, because a refusal that refuses everything is not a check
//!
//! Every negative here has a positive beside it. A condition layer that answered "no" to all
//! six shapes would pass a suite of six refusals, and it would also refuse every genuine
//! sign-in. What makes each test meaningful is the control that differs from it in exactly one
//! value.
//!
//! Needs no database.

use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_saml::conditions::{ConditionError, Expectations, check};
use ironauth_saml::{ASSERTION_NS, Limits, TrustAnchor, verify};

const AUDIENCE: &str = "https://ironauth.example/saml/globex";
const RECIPIENT: &str = "https://ironauth.example/saml/acs/globex";
const REQUEST: &str = "_req_12345";
/// 2026-01-01T00:00:00Z, which every window below is written around.
const NOW: i64 = 1_767_225_600;

/// The children of an assertion, composed so one test can vary one value.
struct Body {
    audience: Option<&'static str>,
    not_before: Option<&'static str>,
    not_on_or_after: Option<&'static str>,
    in_response_to: Option<&'static str>,
    recipient: Option<&'static str>,
    name_id: Option<&'static str>,
}

impl Default for Body {
    /// A body that satisfies every condition. Each test changes exactly one field.
    fn default() -> Self {
        Self {
            audience: Some(AUDIENCE),
            not_before: Some("2025-12-31T23:55:00Z"),
            not_on_or_after: Some("2026-01-01T00:05:00Z"),
            in_response_to: Some(REQUEST),
            recipient: Some(RECIPIENT),
            name_id: Some("ada@globex.example"),
        }
    }
}

impl Body {
    fn xml(&self) -> String {
        let mut out = String::from("<saml:Issuer>urn:idp</saml:Issuer>");
        out.push_str("<saml:Subject>");
        if let Some(name_id) = self.name_id {
            out.push_str(
                "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
            );
            out.push_str(name_id);
            out.push_str("</saml:NameID>");
        }
        out.push_str("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">");
        out.push_str("<saml:SubjectConfirmationData");
        if let Some(value) = self.in_response_to {
            out.push_str(" InResponseTo=\"");
            out.push_str(value);
            out.push('"');
        }
        if let Some(value) = self.recipient {
            out.push_str(" Recipient=\"");
            out.push_str(value);
            out.push('"');
        }
        out.push_str("/></saml:SubjectConfirmation></saml:Subject>");
        out.push_str("<saml:Conditions");
        if let Some(value) = self.not_before {
            out.push_str(" NotBefore=\"");
            out.push_str(value);
            out.push('"');
        }
        if let Some(value) = self.not_on_or_after {
            out.push_str(" NotOnOrAfter=\"");
            out.push_str(value);
            out.push('"');
        }
        out.push('>');
        if let Some(audience) = self.audience {
            out.push_str("<saml:AudienceRestriction><saml:Audience>");
            out.push_str(audience);
            out.push_str("</saml:Audience></saml:AudienceRestriction>");
        }
        out.push_str("</saml:Conditions>");
        out
    }
}

fn expectations() -> Expectations<'static> {
    Expectations {
        audience: AUDIENCE,
        recipient: RECIPIENT,
        in_response_to: Some(REQUEST),
        clock_skew_secs: 30,
        max_age_secs: 600,
    }
}

/// Sign `body`, verify the signature, and run the conditions against it.
///
/// THE SIGNATURE IS CHECKED FIRST AND ITS SUCCESS IS ASSERTED. A conditions test whose document
/// failed to verify would be testing nothing, and would keep passing after the condition it names
/// was deleted.
fn decide(
    body: &Body,
    expectations: &Expectations<'_>,
    now: i64,
) -> Result<String, ConditionError> {
    let key = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_response_with(&key, "_assertion", &body.xml());
    let anchors = [TrustAnchor::EcdsaP256(key.public_point())];
    let assertion = verify(
        document.as_bytes(),
        &Limits::default(),
        &anchors,
        ASSERTION_NS,
        "Assertion",
    )
    .expect("the fixture's signature must verify, or this test measures nothing");
    check(&assertion, expectations, now).map(|accepted| accepted.name_id)
}

#[test]
fn a_genuine_assertion_is_accepted() {
    // THE CONTROL FOR EVERY REFUSAL BELOW. Without it a condition layer that refused everything
    // would pass this whole file.
    let who = decide(&Body::default(), &expectations(), NOW).expect("a genuine assertion");
    assert_eq!(who, "ada@globex.example");
}

#[test]
fn an_assertion_for_another_service_provider_is_refused() {
    // CVE-2026-9093. The signature is valid: this is an assertion the customer's identity
    // provider really minted, for somebody else. Without the audience check, every relying party
    // that customer uses can replay each other's assertions here.
    let body = Body {
        audience: Some("https://someone-else.example/saml/metadata"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongAudience { .. })),
        "an assertion addressed elsewhere was accepted: {refused:?}"
    );
}

#[test]
fn an_assertion_restricted_to_nobody_is_refused() {
    // THE ABSENCE IS THE ATTACK, and it is the shape a naive check misses: code that reads the
    // audience and compares it when present accepts an assertion carrying none. An assertion
    // that restricts itself to nobody is one every relying party would take.
    let body = Body {
        audience: None,
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongAudience { found: None })),
        "an assertion with no AudienceRestriction was accepted: {refused:?}"
    );
}

#[test]
fn an_expired_assertion_and_one_not_yet_valid_are_both_refused() {
    // CVE-2026-9096, both directions. A captured assertion stays validly signed for ever, so the
    // window is the only thing that stops it being replayed next year.
    let expired = Body {
        not_before: Some("2025-01-01T00:00:00Z"),
        not_on_or_after: Some("2025-01-01T00:05:00Z"),
        ..Body::default()
    };
    assert!(
        matches!(
            decide(&expired, &expectations(), NOW),
            Err(ConditionError::Expired)
        ),
        "a year-old assertion was accepted"
    );

    let future = Body {
        not_before: Some("2026-06-01T00:00:00Z"),
        not_on_or_after: Some("2026-06-01T00:05:00Z"),
        ..Body::default()
    };
    assert!(
        matches!(
            decide(&future, &expectations(), NOW),
            Err(ConditionError::Expired)
        ),
        "an assertion valid from June was accepted in January"
    );
}

#[test]
fn an_assertion_with_no_expiry_is_refused_rather_than_treated_as_open() {
    // A MISSING BOUND IS NOT AN UNBOUNDED ONE. The naive reading -- "no NotOnOrAfter, so nothing
    // to check" -- makes the assertion valid for ever, which is the CVE.
    for body in [
        Body {
            not_on_or_after: None,
            ..Body::default()
        },
        Body {
            not_before: None,
            ..Body::default()
        },
    ] {
        let refused = decide(&body, &expectations(), NOW);
        assert!(
            matches!(refused, Err(ConditionError::Expired)),
            "an assertion missing a time bound was accepted: {refused:?}"
        );
    }
}

#[test]
fn the_clock_skew_is_applied_at_both_edges_and_is_not_unbounded() {
    // THE SKEW HAS TO WORK AND HAS TO BE BOUNDED. Identity provider clocks drift, so a strict
    // comparison refuses genuine sign-ins; an unbounded one is the same as no time check at all.
    let body = Body {
        not_before: Some("2026-01-01T00:00:20Z"),
        not_on_or_after: Some("2026-01-01T00:05:00Z"),
        ..Body::default()
    };
    // Twenty seconds early, inside a thirty-second skew.
    assert!(
        decide(&body, &expectations(), NOW).is_ok(),
        "a sign-in twenty seconds ahead of the window was refused with a thirty-second skew"
    );
    // And outside a five-second one.
    let strict = Expectations {
        clock_skew_secs: 5,
        ..expectations()
    };
    assert!(
        matches!(decide(&body, &strict, NOW), Err(ConditionError::Expired)),
        "a five-second skew admitted a twenty-second difference"
    );
}

#[test]
fn an_assertion_valid_for_longer_than_this_connection_allows_is_refused() {
    // AN IDENTITY PROVIDER THAT ISSUES A TWELVE-HOUR WINDOW IS ISSUING A TWELVE-HOUR BEARER
    // TOKEN. Inside its own window, so the expiry check passes; refused on length instead, and
    // as a DIFFERENT error, because what an operator has to fix is different.
    let body = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T12:00:00Z"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::TooLongLived)),
        "a twelve-hour assertion was accepted under a ten-minute ceiling: {refused:?}"
    );
    // AND RAISING THE CEILING ACCEPTS IT, which is what proves the refusal was the ceiling and
    // not something else about the document.
    let generous = Expectations {
        max_age_secs: 86_400,
        ..expectations()
    };
    assert!(decide(&body, &generous, NOW).is_ok());
}

#[test]
fn a_response_naming_no_request_is_refused_when_one_was_required() {
    // CVE-2026-9098. An unsolicited response is validly signed and answers nothing this
    // deployment started, so anyone who obtains one can post it at the assertion consumer.
    let body = Body {
        in_response_to: None,
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::UnknownRequest)),
        "a response nobody asked for was accepted: {refused:?}"
    );
}

#[test]
fn a_response_naming_a_different_request_is_refused() {
    // The replay of a captured response into somebody else's sign-in.
    let body = Body {
        in_response_to: Some("_req_somebody_elses"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::UnknownRequest)),
        "a response answering another request was accepted: {refused:?}"
    );
}

#[test]
fn an_unsolicited_response_is_admissible_only_when_it_names_no_request() {
    // THE OPT-IN PATH. With no request to correlate, the caller has said it will defend the
    // replay another way -- but a response that NAMES a request is one for a sign-in somebody
    // else started, and taking it would let a captured response ride an unsolicited-enabled
    // connection.
    let unsolicited = Expectations {
        in_response_to: None,
        ..expectations()
    };

    let bare = Body {
        in_response_to: None,
        ..Body::default()
    };
    assert!(
        decide(&bare, &unsolicited, NOW).is_ok(),
        "an unsolicited response was refused on a connection that accepts them"
    );

    let carries_one = Body::default();
    let refused = decide(&carries_one, &unsolicited, NOW);
    assert!(
        matches!(refused, Err(ConditionError::UnknownRequest)),
        "a response for somebody else's sign-in was accepted as unsolicited: {refused:?}"
    );
}

#[test]
fn an_assertion_addressed_to_another_endpoint_is_refused() {
    // The recipient-confusion class: a response captured at one service provider and posted at
    // another verifies, and `Recipient` is what refuses it.
    let body = Body {
        recipient: Some("https://someone-else.example/saml/acs"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongRecipient { .. })),
        "an assertion addressed to another endpoint was accepted: {refused:?}"
    );
}

#[test]
fn an_assertion_with_no_subject_is_refused_rather_than_signing_in_nobody() {
    // A document that verifies and says who nobody is. Accepting it would create or match an
    // identity from an empty string, which is the worst possible outcome of a successful
    // signature check.
    let body = Body {
        name_id: None,
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "an assertion naming nobody was accepted: {refused:?}"
    );
}

#[test]
fn the_accepted_expiry_is_the_earlier_of_the_two_bounds() {
    // WHAT THE REPLAY CACHE REMEMBERS. Recording the identity provider's own expiry would keep a
    // long-lived assertion beyond what this deployment actually accepted, and recording the
    // ceiling alone would forget a short one too late. The earlier of the two is what matches
    // the decision that was made.
    let key = XmlTestKey::generate();
    let body = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:02:00Z"),
        ..Body::default()
    };
    let document = ironauth_saml::test_util::signed_response_with(&key, "_assertion", &body.xml());
    let anchors = [TrustAnchor::EcdsaP256(key.public_point())];
    let assertion = verify(
        document.as_bytes(),
        &Limits::default(),
        &anchors,
        ASSERTION_NS,
        "Assertion",
    )
    .expect("verifies");
    let accepted = check(&assertion, &expectations(), NOW).expect("accepted");
    // The assertion's own two-minute window is shorter than the ten-minute ceiling, so it wins.
    assert_eq!(accepted.expires_at_unix_secs, 1_767_225_720);
    assert_eq!(accepted.assertion_id, "_assertion");
    assert_eq!(
        accepted.name_id_format.as_deref(),
        Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    );
}

/// Sign arbitrary assertion children and run the conditions, for shapes [`Body`] cannot compose.
fn decide_raw(
    children: &str,
    expectations: &Expectations<'_>,
    now: i64,
) -> Result<String, ConditionError> {
    let key = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_response_with(&key, "_assertion", children);
    let anchors = [TrustAnchor::EcdsaP256(key.public_point())];
    let assertion = verify(
        document.as_bytes(),
        &Limits::default(),
        &anchors,
        ASSERTION_NS,
        "Assertion",
    )
    .expect("the fixture's signature must verify, or this test measures nothing");
    check(&assertion, expectations, now).map(|accepted| accepted.name_id)
}

#[test]
fn a_present_but_empty_subject_is_refused_as_firmly_as_a_missing_one() {
    // AN ABSENT NameID AND AN EMPTY ONE ARE DIFFERENT CODE PATHS. The first answers `None` from
    // the read; the second answers `Some("")`, and a check that only asked whether the read
    // succeeded would sign in an identity whose name is the empty string -- which then matches or
    // creates whatever account the empty string maps to.
    for subject in [
        "<saml:Subject><saml:NameID></saml:NameID>",
        "<saml:Subject><saml:NameID>   </saml:NameID>",
    ] {
        let children = [
            "<saml:Issuer>urn:idp</saml:Issuer>",
            subject,
            "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
            "<saml:SubjectConfirmationData InResponseTo=\"",
            REQUEST,
            "\" Recipient=\"",
            RECIPIENT,
            "\"/></saml:SubjectConfirmation></saml:Subject>",
            "<saml:Conditions NotBefore=\"2025-12-31T23:55:00Z\" ",
            "NotOnOrAfter=\"2026-01-01T00:05:00Z\">",
            "<saml:AudienceRestriction><saml:Audience>",
            AUDIENCE,
            "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
        ]
        .concat();
        let refused = decide_raw(&children, &expectations(), NOW);
        assert!(
            matches!(refused, Err(ConditionError::Malformed)),
            "an assertion naming the empty string was accepted: {refused:?}"
        );
    }
}

#[test]
fn two_conditions_elements_make_the_window_unreadable_rather_than_letting_one_win() {
    // THE AMBIGUITY RULE, on the values that decide validity. Two `Conditions` inside one signed
    // assertion verify like any other document, and a reader that took the first would be
    // choosing which half of a contradiction to believe -- so an attacker who can influence the
    // document chooses for it. Here the first window is live and the second is a year old.
    //
    // The refusal is `Expired` rather than `Malformed` because the read of the bound is what came
    // back empty, and the caller cannot be told the window is fine when nothing could read it.
    let children = [
        "<saml:Issuer>urn:idp</saml:Issuer>",
        "<saml:Subject><saml:NameID>ada@globex.example</saml:NameID>",
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
        "<saml:SubjectConfirmationData InResponseTo=\"",
        REQUEST,
        "\" Recipient=\"",
        RECIPIENT,
        "\"/></saml:SubjectConfirmation></saml:Subject>",
        // LIVE.
        "<saml:Conditions NotBefore=\"2025-12-31T23:55:00Z\" ",
        "NotOnOrAfter=\"2026-01-01T00:05:00Z\">",
        "<saml:AudienceRestriction><saml:Audience>",
        AUDIENCE,
        "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
        // AND ALSO LIVE, with a different window. Either would be accepted alone.
        "<saml:Conditions NotBefore=\"2025-12-31T23:50:00Z\" ",
        "NotOnOrAfter=\"2026-01-01T00:02:00Z\"/>",
    ]
    .concat();
    let refused = decide_raw(&children, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Expired)),
        "an assertion carrying two contradicting windows had one of them believed: {refused:?}"
    );
}

#[test]
fn two_subject_confirmations_make_the_correlation_unreadable() {
    // The same rule on the value that decides WHICH SIGN-IN this answers. One confirmation names
    // the request this deployment issued and the other names somebody else's; taking the first
    // would let an attacker append a confirmation and have the genuine one believed, or prepend
    // one and have theirs believed, depending on which end the reader started from.
    let children = [
        "<saml:Issuer>urn:idp</saml:Issuer>",
        "<saml:Subject><saml:NameID>ada@globex.example</saml:NameID>",
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
        "<saml:SubjectConfirmationData InResponseTo=\"",
        REQUEST,
        "\" Recipient=\"",
        RECIPIENT,
        "\"/></saml:SubjectConfirmation>",
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
        "<saml:SubjectConfirmationData InResponseTo=\"_req_somebody_elses\"/>",
        "</saml:SubjectConfirmation></saml:Subject>",
        "<saml:Conditions NotBefore=\"2025-12-31T23:55:00Z\" ",
        "NotOnOrAfter=\"2026-01-01T00:05:00Z\">",
        "<saml:AudienceRestriction><saml:Audience>",
        AUDIENCE,
        "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
    ]
    .concat();
    let refused = decide_raw(&children, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::UnknownRequest)),
        "an assertion carrying two confirmations had one of them believed: {refused:?}"
    );
}
