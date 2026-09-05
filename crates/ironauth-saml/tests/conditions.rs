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
use ironauth_saml::conditions::{Accepted, ConditionError, Expectations, check};
use ironauth_saml::{ASSERTION_NS, Limits, TrustAnchor, verify};

const ISSUER: &str = "urn:idp";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const AUDIENCE: &str = "https://ironauth.example/saml/globex";
const RECIPIENT: &str = "https://ironauth.example/saml/acs/globex";
const REQUEST: &str = "_req_12345";
/// 2026-01-01T00:00:00Z, which every window below is written around.
const NOW: i64 = 1_767_225_600;

/// The children of an assertion, composed so one test can vary one value.
struct Body {
    issuer: Option<&'static str>,
    /// Each entry is one `AudienceRestriction`, holding the `Audience` children named.
    restrictions: Vec<Vec<&'static str>>,
    /// A condition element beyond the three this server evaluates.
    extra_condition: Option<&'static str>,
    not_before: Option<&'static str>,
    not_on_or_after: Option<&'static str>,
    in_response_to: Option<&'static str>,
    recipient: Option<&'static str>,
    /// The bearer confirmation's own expiry, which the profile requires.
    confirmation_expiry: Option<&'static str>,
    method: Option<&'static str>,
    name_id: Option<&'static str>,
    /// A `NameID` inside the confirmation, naming who may PRESENT the assertion.
    confirmation_name_id: Option<&'static str>,
    /// A second bearer confirmation, for the ambiguity cases.
    second_confirmation: bool,
    /// A `ProxyRestriction` naming this deployment, which is not an address to it.
    proxy_audience: Option<&'static str>,
    /// A second `Issuer`, appended AFTER the Conditions, for the ambiguity case.
    second_issuer: Option<&'static str>,
    /// An `AttributeStatement` whose value carries a whole nested Issuer, Subject and
    /// Conditions -- all of which `xs:anyType` permits and none of which are this assertion's.
    nested_impostor: bool,
}

impl Default for Body {
    /// A body that satisfies every condition. Each test changes exactly one field.
    fn default() -> Self {
        Self {
            issuer: Some(ISSUER),
            restrictions: vec![vec![AUDIENCE]],
            extra_condition: None,
            not_before: Some("2025-12-31T23:55:00Z"),
            not_on_or_after: Some("2026-01-01T00:05:00Z"),
            in_response_to: Some(REQUEST),
            recipient: Some(RECIPIENT),
            confirmation_expiry: Some("2026-01-01T00:05:00Z"),
            method: Some(BEARER),
            name_id: Some("ada@globex.example"),
            confirmation_name_id: None,
            second_confirmation: false,
            proxy_audience: None,
            second_issuer: None,
            nested_impostor: false,
        }
    }
}

impl Body {
    fn confirmation(&self, in_response_to: Option<&str>, recipient: Option<&str>) -> String {
        let mut out = String::from("<saml:SubjectConfirmation");
        if let Some(method) = self.method {
            out.push_str(" Method=\"");
            out.push_str(method);
            out.push('"');
        }
        out.push('>');
        if let Some(who) = self.confirmation_name_id {
            out.push_str("<saml:NameID>");
            out.push_str(who);
            out.push_str("</saml:NameID>");
        }
        out.push_str("<saml:SubjectConfirmationData");
        if let Some(value) = in_response_to {
            out.push_str(" InResponseTo=\"");
            out.push_str(value);
            out.push('"');
        }
        if let Some(value) = recipient {
            out.push_str(" Recipient=\"");
            out.push_str(value);
            out.push('"');
        }
        if let Some(value) = self.confirmation_expiry {
            out.push_str(" NotOnOrAfter=\"");
            out.push_str(value);
            out.push('"');
        }
        out.push_str("/></saml:SubjectConfirmation>");
        out
    }

    fn xml(&self) -> String {
        let mut out = String::new();
        if let Some(issuer) = self.issuer {
            out.push_str("<saml:Issuer>");
            out.push_str(issuer);
            out.push_str("</saml:Issuer>");
        }
        out.push_str("<saml:Subject>");
        if let Some(name_id) = self.name_id {
            out.push_str(
                "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
            );
            out.push_str(name_id);
            out.push_str("</saml:NameID>");
        }
        out.push_str(&self.confirmation(self.in_response_to, self.recipient));
        if self.second_confirmation {
            out.push_str(&self.confirmation(Some("_req_somebody_elses"), Some(RECIPIENT)));
        }
        out.push_str("</saml:Subject>");
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
        for restriction in &self.restrictions {
            out.push_str("<saml:AudienceRestriction>");
            for audience in restriction {
                out.push_str("<saml:Audience>");
                out.push_str(audience);
                out.push_str("</saml:Audience>");
            }
            out.push_str("</saml:AudienceRestriction>");
        }
        if let Some(audience) = self.proxy_audience {
            out.push_str("<saml:ProxyRestriction Count=\"1\"><saml:Audience>");
            out.push_str(audience);
            out.push_str("</saml:Audience></saml:ProxyRestriction>");
        }
        if let Some(extra) = self.extra_condition {
            out.push_str(extra);
        }
        out.push_str("</saml:Conditions>");
        if self.nested_impostor {
            // `saml:AttributeValue` IS `xs:anyType`, so all of this is a conformant document.
            out.push_str(concat!(
                "<saml:AttributeStatement><saml:Attribute Name=\"dept\"><saml:AttributeValue>",
                "<saml:Issuer>urn:idp</saml:Issuer>",
                "<saml:Subject><saml:NameID>attacker@evil.example</saml:NameID>",
                "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
                "<saml:SubjectConfirmationData InResponseTo=\"_req_12345\" ",
                "Recipient=\"https://ironauth.example/saml/acs/globex\" ",
                "NotOnOrAfter=\"2026-01-01T00:05:00Z\"/></saml:SubjectConfirmation></saml:Subject>",
                "<saml:Conditions NotBefore=\"2025-12-31T23:55:00Z\" ",
                "NotOnOrAfter=\"2026-01-01T00:05:00Z\"><saml:AudienceRestriction><saml:Audience>",
                "https://ironauth.example/saml/globex",
                "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
                "</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>",
            ));
        }
        if let Some(issuer) = self.second_issuer {
            out.push_str("<saml:Issuer>");
            out.push_str(issuer);
            out.push_str("</saml:Issuer>");
        }
        out
    }
}

fn expectations() -> Expectations<'static> {
    Expectations {
        issuer: ISSUER,
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
    decide_raw(&body.xml(), expectations, now)
}

/// Sign `body` and hand back the whole decision, for the tests that read more than the name.
fn accept(body: &Body, expectations: &Expectations<'_>, now: i64) -> Accepted {
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
    check(&assertion, expectations, now).expect("accepted")
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
        restrictions: vec![vec!["https://someone-else.example/saml/metadata"]],
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
        restrictions: Vec::new(),
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
            matches!(refused, Err(ConditionError::MissingBound { .. })),
            "an assertion missing a time bound was accepted: {refused:?}"
        );
    }
}

#[test]
fn the_clock_skew_is_applied_at_both_edges_and_a_smaller_one_refuses_more() {
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

    // NOW THE OTHER EDGE, which is the half the name claimed and no fixture reached: every window
    // in this suite ended at least 120 seconds after `NOW`, so the expiry-side skew term could be
    // deleted, or its sign flipped, and nothing would notice. Here the window closed twenty
    // seconds AGO.
    let just_closed = Body {
        not_before: Some("2025-12-31T23:55:00Z"),
        not_on_or_after: Some("2025-12-31T23:59:40Z"),
        ..Body::default()
    };
    assert!(
        decide(&just_closed, &expectations(), NOW).is_ok(),
        "a sign-in twenty seconds past the window was refused with a thirty-second skew"
    );
    assert!(
        matches!(
            decide(&just_closed, &strict, NOW),
            Err(ConditionError::Expired)
        ),
        "a five-second skew admitted a window that closed twenty seconds ago"
    );

    // AND A NEGATIVE SKEW IS ZERO, NOT A NARROWING. `clock_skew_secs` is a public field with no
    // validator, and without the `.max(0)` a negative value would subtract from both edges --
    // refusing an assertion that became valid at this very instant.
    let backwards = Expectations {
        clock_skew_secs: -30,
        ..expectations()
    };
    let exactly_now = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:05:00Z"),
        ..Body::default()
    };
    assert!(
        decide(&exactly_now, &backwards, NOW).is_ok(),
        "a negative skew narrowed the window instead of being read as none at all"
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
    let body = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:02:00Z"),
        ..Body::default()
    };
    let accepted = accept(&body, &expectations(), NOW);
    // The assertion's own two-minute window is shorter than the ten-minute ceiling, so it wins
    // -- PLUS THE THIRTY-SECOND SKEW, because the window comparison admits the assertion for
    // that long past the bound and a cache that forgot it sooner would admit the replay.
    assert_eq!(accepted.expires_at_unix_secs, 1_767_225_720 + 30);
    assert_eq!(accepted.assertion_id, "_assertion");
    assert_eq!(
        accepted.name_id_format.as_deref(),
        Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    );
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
            "\" NotOnOrAfter=\"2026-01-01T00:05:00Z\"",
            "/></saml:SubjectConfirmation></saml:Subject>",
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
    // document chooses for it.
    //
    // BOTH WINDOWS ARE LIVE, and that is deliberate. An earlier version made the second a year
    // old, so it would have passed against a reader that took EITHER one and simply found the
    // older expired -- and `collect` walks with a stack, so "the first" is not even document
    // order. With both live, only the ambiguity itself can refuse it, and the refusal is
    // `Malformed` for the same reason it is everywhere else in this module.
    let children = [
        "<saml:Issuer>urn:idp</saml:Issuer>",
        "<saml:Subject><saml:NameID>ada@globex.example</saml:NameID>",
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
        "<saml:SubjectConfirmationData InResponseTo=\"",
        REQUEST,
        "\" Recipient=\"",
        RECIPIENT,
        "\" NotOnOrAfter=\"2026-01-01T00:05:00Z\"/></saml:SubjectConfirmation></saml:Subject>",
        // LIVE.
        "<saml:Conditions NotBefore=\"2025-12-31T23:55:00Z\" ",
        "NotOnOrAfter=\"2026-01-01T00:05:00Z\">",
        "<saml:AudienceRestriction><saml:Audience>",
        AUDIENCE,
        "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
        // AND ALSO LIVE, with a different window -- AND COMPLETE, which the first version of
        // this fixture was not. It was self-closing, so it named no audience and its window was
        // 720s against a 600s ceiling: TWO further reasons to refuse it, either of which would
        // have satisfied the assertion below without the ambiguity rule existing at all.
        "<saml:Conditions NotBefore=\"2025-12-31T23:57:00Z\" ",
        "NotOnOrAfter=\"2026-01-01T00:02:00Z\">",
        "<saml:AudienceRestriction><saml:Audience>",
        AUDIENCE,
        "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
    ]
    .concat();
    let refused = decide_raw(&children, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "an assertion carrying two contradicting windows had one of them believed: {refused:?}"
    );
}

#[test]
fn a_proxy_restriction_naming_us_is_not_an_address_to_us() {
    // THE ROUTE-AROUND THE FIRST VERSION HAD. `saml:Audience` is a child of `AudienceRestriction`
    // ("this assertion is addressed to you") AND of `ProxyRestriction` ("somebody else may
    // re-assert this to you"). Same namespace, same local name, opposite meaning -- and the first
    // version searched every descendant, so an assertion carrying no `AudienceRestriction` at all
    // but a `ProxyRestriction` naming this deployment passed the audience check.
    let body = Body {
        restrictions: Vec::new(),
        proxy_audience: Some(AUDIENCE),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongAudience { .. })),
        "permission for somebody else to proxy this assertion was read as an address to us: \
         {refused:?}"
    );
    // AND IT IS HARMLESS BESIDE A REAL RESTRICTION, which is what stops the fix from refusing a
    // legitimate proxying assertion.
    let both = Body {
        proxy_audience: Some(AUDIENCE),
        ..Body::default()
    };
    assert!(
        decide(&both, &expectations(), NOW).is_ok(),
        "a genuine assertion that also permits proxying was refused"
    );
}

#[test]
fn an_assertion_naming_several_audiences_is_accepted_and_every_restriction_must_hold() {
    // SAML CORE 2.5.1.4. An `AudienceRestriction` may name several audiences and an assertion may
    // carry several restrictions; the service provider must be named in EVERY restriction, and
    // within one it is enough to be named at all. The first version demanded exactly one
    // `Audience` in the whole assertion, which refused the ordinary case where a relying party
    // has more than one entity id -- and reported it as "the assertion named no audience".
    let several = Body {
        restrictions: vec![vec!["https://other.example/sp", AUDIENCE]],
        ..Body::default()
    };
    assert!(
        decide(&several, &expectations(), NOW).is_ok(),
        "an assertion naming us among several audiences was refused"
    );

    // TWO RESTRICTIONS INTERSECT. Named in the first and not the second is not named.
    let intersecting = Body {
        restrictions: vec![vec![AUDIENCE], vec!["https://other.example/sp"]],
        ..Body::default()
    };
    let refused = decide(&intersecting, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongAudience { .. })),
        "a second restriction that excludes us was ignored: {refused:?}"
    );
}

#[test]
fn a_condition_this_server_cannot_evaluate_is_a_refusal() {
    // SAML CORE 2.5 IS EXPLICIT: a service provider that cannot evaluate a `Condition` MUST treat
    // the assertion as invalid. The whole point of the element is that an identity provider can
    // add a restriction and rely on it being honoured; ignoring one turns every future
    // restriction into a no-op.
    let body = Body {
        extra_condition: Some("<saml:Condition/>"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::UnsupportedCondition { .. })),
        "a condition this server cannot evaluate was ignored: {refused:?}"
    );
    // AND THE ONES IT CAN ARE NOT REFUSED, or the check would reject every ordinary assertion.
    let one_time = Body {
        extra_condition: Some("<saml:OneTimeUse/>"),
        ..Body::default()
    };
    assert!(
        decide(&one_time, &expectations(), NOW).is_ok(),
        "OneTimeUse, which this server evaluates by remembering the assertion, was refused"
    );
}

#[test]
fn an_assertion_from_another_identity_provider_is_refused() {
    // A response is resolved by the URL it arrived at, so the `Issuer` is what ties the
    // assertion's own claim of authorship to the connection whose keys verified it. The first
    // version documented this as "a check the caller makes" and gave `Expectations` no field to
    // make it with, which is a control that exists only in prose.
    let body = Body {
        issuer: Some("urn:somebody-else"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongIssuer { .. })),
        "an assertion claiming another identity provider was accepted: {refused:?}"
    );
    let none = Body {
        issuer: None,
        ..Body::default()
    };
    assert!(
        matches!(
            decide(&none, &expectations(), NOW),
            Err(ConditionError::WrongIssuer { found: None })
        ),
        "an assertion claiming no author was accepted"
    );
}

#[test]
fn a_missing_recipient_is_a_refusal_and_not_a_pass() {
    // SAML PROFILES 4.1.4.2 REQUIRES IT on a bearer confirmation. The first version skipped the
    // check when the attribute was absent, so the recipient-confusion defence disappeared exactly
    // when an attacker omitted it -- which is the one thing they control.
    let body = Body {
        recipient: None,
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongRecipient { found: None })),
        "an assertion with no Recipient was accepted: {refused:?}"
    );
}

#[test]
fn the_confirmations_own_expiry_is_checked_and_is_a_different_bound() {
    // THE BEARER PROFILE'S OWN WINDOW. It bounds how long the response may be IN FLIGHT, where
    // the assertion's bounds how long the statement is true, and it is usually much shorter.
    // The first version read it from nowhere, so a response captured hours after its confirmation
    // expired was accepted as long as the assertion itself was still live.
    let expired = Body {
        not_before: Some("2025-12-31T23:55:00Z"),
        not_on_or_after: Some("2026-01-01T00:05:00Z"),
        confirmation_expiry: Some("2025-12-31T23:56:00Z"),
        ..Body::default()
    };
    let refused = decide(&expired, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Expired)),
        "a response whose confirmation had expired was accepted while the assertion was live: \
         {refused:?}"
    );
    // Its ABSENCE is a refusal too, and it names itself:
    // `a_missing_bound_says_which_one_rather_than_reporting_an_expiry` pins that, because the
    // fault an operator has to fix there is a different one.
}

#[test]
fn a_holder_of_key_confirmation_is_not_honoured_as_a_bearer_one() {
    // A HOLDER-OF-KEY CONFIRMATION ASKS THE SERVICE PROVIDER TO PROVE POSSESSION OF A KEY, which
    // is a different protocol. Reading whichever confirmation came first, without checking the
    // `Method`, would honour it as a bearer one -- which is the entire difference between them.
    let body = Body {
        method: Some("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "a holder-of-key confirmation was honoured as a bearer one: {refused:?}"
    );
}

#[test]
fn the_confirming_partys_name_is_not_the_signed_in_identity() {
    // A `SubjectConfirmation` MAY CARRY ITS OWN `NameID`, naming who may PRESENT the assertion.
    // The first version read `NameID` by descendant search, so with the Subject's own omitted the
    // confirming party's would have become the signed-in identity -- and with both present the
    // read was ambiguous, which at least refused, but for the wrong reason.
    let body = Body {
        name_id: None,
        confirmation_name_id: Some("attacker@evil.example"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "the confirming party became the signed-in identity: {refused:?}"
    );
    // AND WITH BOTH PRESENT THE SUBJECT'S OWN IS USED, which a descendant search could not have
    // done at all.
    let both = Body {
        confirmation_name_id: Some("attacker@evil.example"),
        ..Body::default()
    };
    assert_eq!(
        decide(&both, &expectations(), NOW).expect("accepted"),
        "ada@globex.example",
        "the wrong NameID was read"
    );
}

#[test]
fn two_bearer_confirmations_are_refused_rather_than_letting_one_win() {
    // One names the request this deployment issued and the other names somebody else's. Taking
    // either is choosing which half of a contradiction to believe, and an attacker who can append
    // or prepend chooses for the reader. BOTH ARE INDIVIDUALLY WELL-FORMED -- same recipient,
    // same expiry -- so only the ambiguity itself can refuse this document.
    let body = Body {
        second_confirmation: true,
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "an assertion carrying two bearer confirmations had one of them believed: {refused:?}"
    );
}

#[test]
fn an_inverted_window_is_malformed_rather_than_expired() {
    // A WINDOW THAT ENDS BEFORE IT STARTS is not a window, and nothing about a clock would make
    // it valid. Reporting it as expired sends an operator to look at clock skew, which is the one
    // thing that cannot be the problem.
    let body = Body {
        not_before: Some("2026-01-01T00:05:00Z"),
        not_on_or_after: Some("2025-12-31T23:55:00Z"),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "an inverted window was reported as an expiry: {refused:?}"
    );
}

#[test]
fn what_is_remembered_is_bounded_by_the_confirmations_expiry_too() {
    // THE THIRD OPERAND OF THE SAME CEILING. `expires_at_unix_secs` is what a replay cache
    // remembers the assertion until, and the bearer confirmation's own expiry is usually the
    // soonest of the three -- so a value that ignored it would keep an assertion long past the
    // point this server would still accept it, and evict on the identity provider's schedule
    // rather than on the one that was actually enforced.
    let body = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:05:00Z"),
        confirmation_expiry: Some("2026-01-01T00:01:00Z"),
        ..Body::default()
    };
    let accepted = accept(&body, &expectations(), NOW);
    assert_eq!(
        accepted.expires_at_unix_secs,
        1_767_225_660 + 30,
        "the confirmation's one-minute expiry is the earliest of the three and did not bound what \
         is remembered"
    );

    // AND IT DOES NOT BIND WHEN IT IS THE LATEST, which is what keeps the assertion above from
    // passing for the wrong reason: same document, confirmation expiry moved past both.
    let later = Body {
        confirmation_expiry: Some("2026-01-01T00:09:00Z"),
        ..body
    };
    assert_eq!(
        accept(&later, &expectations(), NOW).expires_at_unix_secs,
        1_767_225_900 + 30,
        "a confirmation expiry later than the assertion's shortened the window anyway"
    );
}

#[test]
fn a_ceiling_of_i64_max_does_not_overflow_the_expiry_it_stamps() {
    // `max_age_secs` IS A PUBLIC FIELD WITH NO BOUND AND NO CONSTRUCTOR, so `i64::MAX` is the
    // only way this API lets a caller say "impose no ceiling of my own". A plain `+` would panic
    // here in debug and wrap to a large negative in release -- and the wrapped value would WIN
    // the `min`, so an assertion this function had just ACCEPTED would be stamped as having
    // expired in 1969, and a replay cache keyed on that value would forget it immediately.
    let boundless = Expectations {
        max_age_secs: i64::MAX,
        ..expectations()
    };
    let accepted = accept(&Body::default(), &boundless, NOW);
    assert_eq!(
        accepted.expires_at_unix_secs,
        1_767_225_900 + 30,
        "an unbounded ceiling did not leave the assertion's own expiry as the answer"
    );

    // AND THE SAME FOR THE SKEW, which is the sibling public field the round-1 overflow fix did
    // not sweep to: `now + skew` and `now - skew` are the window comparison, and `+ skew` is the
    // last term of the stamped expiry.
    let boundless_skew = Expectations {
        clock_skew_secs: i64::MAX,
        ..expectations()
    };
    let accepted = accept(&Body::default(), &boundless_skew, NOW);
    assert_eq!(
        accepted.expires_at_unix_secs,
        i64::MAX,
        "an unbounded skew did not saturate"
    );
}

#[test]
fn what_is_remembered_outlasts_the_window_by_the_skew_that_admitted_it() {
    // THE CACHE MUST OUTLIVE THE ADMISSION. `check` accepts while `now - skew < not_on_or_after`,
    // so an assertion stays presentable for `skew` seconds past every bound it names. A replay
    // cache told to forget it AT the bound has a window exactly `skew` seconds wide in which the
    // assertion is forgotten and still admissible -- which is the replay the cache exists to
    // stop.
    let body = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:02:00Z"),
        confirmation_expiry: Some("2026-01-01T00:02:00Z"),
        ..Body::default()
    };
    let bound = 1_767_225_720; // 2026-01-01T00:02:00Z

    // The same document under two skews. The bounds are identical, so the ONLY thing that can
    // move the answer is the skew term -- which is what makes this measure that term and not
    // some other operand of the minimum.
    let generous = accept(&body, &expectations(), NOW).expires_at_unix_secs;
    let strict = accept(
        &body,
        &Expectations {
            clock_skew_secs: 5,
            ..expectations()
        },
        NOW,
    )
    .expires_at_unix_secs;
    assert_eq!(
        generous,
        bound + 30,
        "the thirty-second skew is not in the stamp"
    );
    assert_eq!(
        strict,
        bound + 5,
        "the five-second skew is not in the stamp"
    );

    // AND A NEGATIVE SKEW ADDS NOTHING RATHER THAN SUBTRACTING, matching the `.max(0)` the
    // window comparison applies: the two must read the same field the same way or the cache
    // forgets an assertion the comparison would still admit.
    let backwards = accept(
        &body,
        &Expectations {
            clock_skew_secs: -30,
            ..expectations()
        },
        NOW,
    )
    .expires_at_unix_secs;
    assert_eq!(
        backwards, bound,
        "a negative skew shortened what is remembered"
    );
}

#[test]
fn a_missing_bound_says_which_one_rather_than_reporting_an_expiry() {
    // WHAT THE OPERATOR HAS TO FIX IS DIFFERENT. "Expired" sends somebody to look at clock skew;
    // what happened is that their identity provider does not emit the attribute. SAML Core
    // 2.5.1.2 makes `NotBefore` OPTIONAL and this server requires it anyway, which is a
    // deliberate tightening -- and one an operator can only act on if the refusal names it.
    for (body, expected) in [
        (
            Body {
                not_before: None,
                ..Body::default()
            },
            "Conditions/@NotBefore",
        ),
        (
            Body {
                not_on_or_after: None,
                ..Body::default()
            },
            "Conditions/@NotOnOrAfter",
        ),
        (
            Body {
                confirmation_expiry: None,
                ..Body::default()
            },
            "SubjectConfirmationData/@NotOnOrAfter",
        ),
    ] {
        let refused = decide(&body, &expectations(), NOW);
        assert!(
            matches!(&refused, Err(ConditionError::MissingBound { attribute }) if *attribute == expected),
            "a missing {expected} was not reported as the missing bound it is: {refused:?}"
        );
    }

    // AND AN ASSERTION WITH NO `Conditions` AT ALL names the element, not one of its attributes:
    // it is not a window that could not be read, it is a statement that never named one.
    let no_conditions = [
        "<saml:Issuer>urn:idp</saml:Issuer>",
        "<saml:Subject><saml:NameID>ada@globex.example</saml:NameID>",
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
        "<saml:SubjectConfirmationData InResponseTo=\"",
        REQUEST,
        "\" Recipient=\"",
        RECIPIENT,
        "\" NotOnOrAfter=\"2026-01-01T00:05:00Z\"/>",
        "</saml:SubjectConfirmation></saml:Subject>",
    ]
    .concat();
    let refused = decide_raw(&no_conditions, &expectations(), NOW);
    assert!(
        matches!(
            refused,
            Err(ConditionError::MissingBound {
                attribute: "Conditions element"
            })
        ),
        "an assertion that never named a window was not reported as missing one: {refused:?}"
    );
}

#[test]
fn a_signed_element_that_is_not_an_assertion_is_refused_by_name_not_by_spelling() {
    // `verify` TAKES THE ELEMENT TO READ AS AN ARGUMENT, so a caller can hand this function
    // something that is not an assertion at all. The first version tested
    // `name().ends_with("Assertion")`, which is a test on the QUALIFIED name -- so an element
    // called `evil:NotAnAssertion`, in a namespace nobody trusts, answered to it.
    //
    // THE BODY IS A COMPLETE, VALID ONE. That is the point: with the suffix test in place this
    // document passes every condition below the gate and is ACCEPTED, signing in
    // ada@globex.example on the authority of an element this crate never agreed to read. A
    // fixture with a broken body would refuse for the wrong reason and the bypass would stay
    // invisible.
    let key = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_element_with(
        &key,
        "evil:NotAnAssertion",
        r#" xmlns:evil="urn:evil""#,
        "_assertion",
        &Body::default().xml(),
    );
    let anchors = [TrustAnchor::EcdsaP256(key.public_point())];
    let signed = verify(
        document.as_bytes(),
        &Limits::default(),
        &anchors,
        "urn:evil",
        "NotAnAssertion",
    )
    .expect("the fixture must verify, or this test measures nothing");
    assert!(
        signed.name().ends_with("Assertion"),
        "the fixture no longer expresses the bypass: its name must END WITH \"Assertion\" while \
         resolving to something else, or the suffix test and the resolved test agree on it"
    );
    let refused = check(&signed, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "an element that merely ends with \"Assertion\" was read as one: {refused:?}"
    );

    // AND THE OTHER HALF: an element whose LOCAL NAME really is `Assertion`, in a namespace
    // nobody trusts. A gate that compared only the local name -- which is the mistake this
    // crate's wrapping defence already made once, one layer down -- refuses the case above and
    // admits this one. Both halves are needed because either check alone catches only one.
    let masquerade = ironauth_saml::test_util::signed_element_with(
        &key,
        "evil:Assertion",
        r#" xmlns:evil="urn:evil""#,
        "_assertion",
        &Body::default().xml(),
    );
    let signed = verify(
        masquerade.as_bytes(),
        &Limits::default(),
        &anchors,
        "urn:evil",
        "Assertion",
    )
    .expect("the fixture must verify, or this test measures nothing");
    let refused = check(&signed, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::Malformed)),
        "an `Assertion` in a namespace nobody trusts was read as a SAML one: {refused:?}"
    );
}

#[test]
fn a_second_issuer_appended_after_the_fact_does_not_become_the_author() {
    // THE ROUND-1 ISSUER FIX READ BY DESCENDANT SEARCH AND TOOK `.first()`, and the walk uses a
    // stack -- so `.first()` was the LAST in document order and appending an `Issuer` naming the
    // trusted provider was enough to defeat the check the same round had just added.
    let body = Body {
        issuer: Some("urn:attacker-idp"),
        second_issuer: Some(ISSUER),
        ..Body::default()
    };
    let refused = decide(&body, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongIssuer { found: None })),
        "an appended Issuer became the assertion's author: {refused:?}"
    );

    // AND THE OTHER ORDER REFUSES TOO, which is what shows the read is not merely first-wins
    // instead of last-wins: two authors is no author whichever came first.
    let reversed = Body {
        issuer: Some(ISSUER),
        second_issuer: Some("urn:attacker-idp"),
        ..Body::default()
    };
    assert!(
        matches!(
            decide(&reversed, &expectations(), NOW),
            Err(ConditionError::WrongIssuer { found: None })
        ),
        "a genuine assertion with an appended second Issuer was accepted"
    );
}

#[test]
fn an_assertion_nested_in_an_attribute_value_supplies_none_of_this_ones_answers() {
    // `saml:AttributeValue` IS `xs:anyType` AND `saml:Advice` CARRIES WHOLE ASSERTIONS, so a
    // conformant SAML document can contain a second `Issuer`, `Subject` and `Conditions` that
    // are somebody else's -- and they are inside this signature just as much as the real ones.
    // Reading any of the three by descendant search let the nested copies answer instead.
    //
    // THE OUTER ASSERTION IS OTHERWISE UNIMPEACHABLE and the nested one names a different
    // person, so if a nested value ever wins, the wrong human is signed in.
    let body = Body {
        nested_impostor: true,
        ..Body::default()
    };
    assert_eq!(
        decide(&body, &expectations(), NOW).expect("the outer assertion is valid"),
        "ada@globex.example",
        "a Subject buried in an AttributeValue became the signed-in identity"
    );

    // AND THE NESTED COPIES DO NOT RESCUE A BROKEN OUTER ONE, which is the direction that
    // matters: with the outer Conditions naming somebody else, the nested Conditions naming us
    // must not supply the audience.
    let wrong_audience = Body {
        nested_impostor: true,
        restrictions: vec![vec!["https://someone-else.example/sp"]],
        ..Body::default()
    };
    let refused = decide(&wrong_audience, &expectations(), NOW);
    assert!(
        matches!(refused, Err(ConditionError::WrongAudience { .. })),
        "a nested Conditions supplied the audience the real one did not name: {refused:?}"
    );

    // Same for the issuer, whose own read is the one round 1 got wrong.
    let wrong_issuer = Body {
        nested_impostor: true,
        issuer: Some("urn:somebody-else"),
        ..Body::default()
    };
    assert!(
        matches!(
            decide(&wrong_issuer, &expectations(), NOW),
            Err(ConditionError::WrongIssuer { .. })
        ),
        "a nested Issuer supplied the authorship the real one did not claim"
    );
}

#[test]
fn a_condition_in_a_foreign_namespace_is_not_understood_by_spelling_alone() {
    // THE ALLOWLIST COMPARED LOCAL NAMES. The parent's namespace says nothing about its
    // children's, so `evil:OneTimeUse` bound to `urn:evil` passed as something this server
    // understands -- the identical bypass the assertion gate one level up exists to prevent, and
    // the one this crate's wrapping defence was built around in the first place.
    for spelling in [
        "<evil:OneTimeUse xmlns:evil=\"urn:evil\"/>",
        "<evil:AudienceRestriction xmlns:evil=\"urn:evil\"><evil:Audience>\
         https://ironauth.example/saml/globex</evil:Audience></evil:AudienceRestriction>",
    ] {
        let body = Body {
            extra_condition: Some(spelling),
            ..Body::default()
        };
        let refused = decide(&body, &expectations(), NOW);
        assert!(
            matches!(refused, Err(ConditionError::UnsupportedCondition { .. })),
            "a condition in a namespace nobody trusts passed by spelling: {spelling} -> {refused:?}"
        );
    }
}

#[test]
fn a_pretty_printed_audience_is_the_same_audience() {
    // `saml:Audience` AND `saml:Issuer` ARE `xsd:anyURI`, which XML Schema gives the `collapse`
    // whiteSpace facet: leading and trailing whitespace is stripped BEFORE any comparison. An
    // identity provider that indents its assertions is not naming a different audience -- and
    // refusing it says "addressed to a different service provider", which sends an operator
    // hunting a misconfiguration that does not exist.
    let indented = [
        "<saml:Issuer>\n  urn:idp\n</saml:Issuer>",
        "<saml:Subject><saml:NameID>ada@globex.example</saml:NameID>",
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
        "<saml:SubjectConfirmationData InResponseTo=\"",
        REQUEST,
        "\" Recipient=\"",
        RECIPIENT,
        "\" NotOnOrAfter=\"2026-01-01T00:05:00Z\"/>",
        "</saml:SubjectConfirmation></saml:Subject>",
        "<saml:Conditions NotBefore=\"2025-12-31T23:55:00Z\" ",
        "NotOnOrAfter=\"2026-01-01T00:05:00Z\">",
        "<saml:AudienceRestriction>\n    <saml:Audience>\n      ",
        AUDIENCE,
        "\n    </saml:Audience>\n  </saml:AudienceRestriction></saml:Conditions>",
    ]
    .concat();
    assert_eq!(
        decide_raw(&indented, &expectations(), NOW).expect("a pretty-printed assertion is valid"),
        "ada@globex.example",
        "an indented Audience or Issuer was read as a different value"
    );

    // AND COLLAPSING DOES NOT MAKE TWO DIFFERENT URIS EQUAL: internal whitespace collapses to
    // one space, it does not vanish, so this is still not our audience.
    let smuggled = indented.replace(
        AUDIENCE,
        "https://ironauth.example/saml/globex https://evil.example/sp",
    );
    assert!(
        matches!(
            decide_raw(&smuggled, &expectations(), NOW),
            Err(ConditionError::WrongAudience { .. })
        ),
        "collapsing let two audiences in one element pass as ours"
    );
}

#[test]
fn a_name_id_padded_with_whitespace_is_refused_rather_than_signed_in_padded() {
    // THE GUARD CHECKED `name_id.trim()` AND THE VALUE RETURNED WAS UNTRIMMED, so
    // " ada@globex.example " passed a check on a string the caller never sees and was signed in
    // with its spaces -- a different account key from the same name flush, which is a way to
    // mint a second identity for one person.
    //
    // REFUSED RATHER THAN TRIMMED: `NameID` content is `xsd:string` and PRESERVES whitespace,
    // unlike the `anyURI` audience the test above collapses, so trimming would be this server
    // deciding two schema-distinct values name one person.
    for padded in [
        " ada@globex.example",
        "ada@globex.example ",
        "\n  ada@globex.example  \n",
    ] {
        let children = format!(
            "<saml:Issuer>{ISSUER}</saml:Issuer>\
             <saml:Subject><saml:NameID>{padded}</saml:NameID>\
             <saml:SubjectConfirmation Method=\"{BEARER}\">\
             <saml:SubjectConfirmationData InResponseTo=\"{REQUEST}\" Recipient=\"{RECIPIENT}\" \
             NotOnOrAfter=\"2026-01-01T00:05:00Z\"/></saml:SubjectConfirmation></saml:Subject>\
             <saml:Conditions NotBefore=\"2025-12-31T23:55:00Z\" \
             NotOnOrAfter=\"2026-01-01T00:05:00Z\"><saml:AudienceRestriction><saml:Audience>\
             {AUDIENCE}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
        );
        let refused = decide_raw(&children, &expectations(), NOW);
        assert!(
            matches!(refused, Err(ConditionError::Malformed)),
            "a padded NameID was signed in: {padded:?} -> {refused:?}"
        );
    }
}

#[test]
fn a_bound_that_is_present_and_unreadable_is_not_reported_as_absent() {
    // THE TWO FAULTS HAVE DIFFERENT FIXES. "The assertion carries no Conditions/@NotBefore" sent
    // an operator looking for an attribute that is right there in the document; what actually
    // happened is that its VALUE is not the narrow form `parse_utc` accepts. An offset instead
    // of `Z` is the common one, and `9999-12-31T23:59:59Z` -- the conventional never-expires
    // sentinel -- is another, since the parser's range stops at 2200.
    for (body, attribute, found) in [
        (
            Body {
                not_before: Some("2025-12-31T23:55:00+00:00"),
                ..Body::default()
            },
            "Conditions/@NotBefore",
            "2025-12-31T23:55:00+00:00",
        ),
        (
            Body {
                not_on_or_after: Some("9999-12-31T23:59:59Z"),
                ..Body::default()
            },
            "Conditions/@NotOnOrAfter",
            "9999-12-31T23:59:59Z",
        ),
        (
            Body {
                confirmation_expiry: Some("2026-01-01T00:05:60Z"),
                ..Body::default()
            },
            "SubjectConfirmationData/@NotOnOrAfter",
            "2026-01-01T00:05:60Z",
        ),
    ] {
        let refused = decide(&body, &expectations(), NOW);
        let Err(ConditionError::UnreadableBound {
            attribute: named,
            found: said,
        }) = &refused
        else {
            panic!("a present but unreadable {attribute} was not reported as such: {refused:?}");
        };
        assert_eq!(*named, attribute, "the wrong attribute was named");
        assert_eq!(
            said, found,
            "the operator was not shown what their provider sent"
        );
    }
}

#[test]
fn every_time_comparison_is_pinned_at_its_exact_boundary() {
    // A WINDOW TEST WITH MINUTES OF MARGIN CANNOT TELL `<` FROM `<=`. Every fixture in this
    // suite sits comfortably inside or outside its window, so all four comparisons in `check`
    // could have their strictness flipped and nothing would fail. Each pair below differs by ONE
    // SECOND across the boundary the comparison names.
    //
    // The skew is zero throughout, so the boundary is the bound itself and nothing else can move
    // the answer.
    let exact = Expectations {
        clock_skew_secs: 0,
        ..expectations()
    };

    // (1) `NotOnOrAfter` IS EXCLUSIVE -- the name says so. At the instant it names the assertion
    // is already over.
    // THE CONFIRMATION EXPIRY IS PUSHED WELL PAST THE ASSERTION'S, deliberately. With
    // `Body::default()`'s it lands on the SAME instant as `NotOnOrAfter`, and the confirmation
    // comparison would then refuse at the boundary no matter what the assertion comparison did
    // -- so making `NotOnOrAfter` inclusive survived this test until the two were separated.
    // Only one bound may be at its boundary at a time.
    let window = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:05:00Z"),
        confirmation_expiry: Some("2026-01-01T00:09:00Z"),
        ..Body::default()
    };
    let expiry = 1_767_225_900; // 2026-01-01T00:05:00Z
    assert!(
        decide(&window, &exact, expiry - 1).is_ok(),
        "one second before NotOnOrAfter was refused"
    );
    assert!(
        matches!(
            decide(&window, &exact, expiry),
            Err(ConditionError::Expired)
        ),
        "AT NotOnOrAfter the assertion was still accepted; the bound is not exclusive"
    );

    // (2) `NotBefore` IS INCLUSIVE, for the same reason: it is the instant validity begins.
    let start = 1_767_225_600; // 2026-01-01T00:00:00Z
    assert!(
        decide(&window, &exact, start).is_ok(),
        "AT NotBefore the assertion was refused; the bound is not inclusive"
    );
    assert!(
        matches!(
            decide(&window, &exact, start - 1),
            Err(ConditionError::Expired)
        ),
        "one second before NotBefore was accepted"
    );

    // (3) THE CONFIRMATION'S OWN EXPIRY, the same rule, measured where it is the binding one.
    // Mirror image: the assertion's own window is wide, so only the confirmation's bound is at
    // its boundary.
    let confirmation = Body {
        not_before: Some("2025-12-31T23:55:00Z"),
        not_on_or_after: Some("2026-01-01T00:05:00Z"),
        confirmation_expiry: Some("2026-01-01T00:01:00Z"),
        ..Body::default()
    };
    let confirmation_expiry = 1_767_225_660; // 2026-01-01T00:01:00Z
    assert!(
        decide(&confirmation, &exact, confirmation_expiry - 1).is_ok(),
        "one second before the confirmation expiry was refused"
    );
    assert!(
        matches!(
            decide(&confirmation, &exact, confirmation_expiry),
            Err(ConditionError::Expired)
        ),
        "AT the confirmation expiry the response was still accepted"
    );

    // (4) THE LENGTH CEILING IS INCLUSIVE: a window exactly `max_age_secs` long is allowed, and
    // one second longer is not. `expectations()` sets 600.
    let exactly_at_ceiling = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:10:00Z"),
        confirmation_expiry: Some("2026-01-01T00:10:00Z"),
        ..Body::default()
    };
    assert!(
        decide(&exactly_at_ceiling, &exact, start).is_ok(),
        "a window exactly max_age_secs long was refused as too long-lived"
    );
    let one_second_over = Body {
        not_on_or_after: Some("2026-01-01T00:10:01Z"),
        ..exactly_at_ceiling
    };
    assert!(
        matches!(
            decide(&one_second_over, &exact, start),
            Err(ConditionError::TooLongLived)
        ),
        "a window one second past the ceiling was accepted"
    );

    // (5) THE INVERTED-WINDOW GUARD is `<=`, so a ZERO-LENGTH window is inverted too: an
    // assertion valid for no time at all is not a window, and it is the degenerate input the
    // guard would otherwise let through into a comparison nothing is inside.
    let zero_length = Body {
        not_before: Some("2026-01-01T00:00:00Z"),
        not_on_or_after: Some("2026-01-01T00:00:00Z"),
        ..Body::default()
    };
    assert!(
        matches!(
            decide(&zero_length, &exact, start),
            Err(ConditionError::Malformed)
        ),
        "a window that opens and closes at the same instant was not read as malformed"
    );
}
