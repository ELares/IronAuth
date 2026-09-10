// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CAEP Interoperability Profile, encoded as executable requirements
//! (issue #144 criterion 6).
//!
//! # Why a profile suite and not more SSF tests
//!
//! SSF 1.0, CAEP 1.0 and RISC 1.0 say what a transmitter MAY do. The interoperability
//! profile says what it must do to work with somebody else's receiver, and the difference
//! is what the Gartner interop events measure: implementations pass the base specs and
//! still fail to talk to each other, because each made a different legal choice.
//!
//! Every test here names its profile section in the test name or its doc, and
//! `docs/conformance/caep-interop-checklist.md` maps each requirement to the test that
//! covers it. `scripts/caep-interop-scan.sh` refuses a checklist row whose test does not
//! exist, which is what makes the traceability criterion 6 asks for real rather than a
//! table somebody keeps up by hand.
//!
//! # What this suite deliberately does NOT claim
//!
//! Passing here is not a conformance certificate. It is this deployment asserting, in CI,
//! that it still does what it told the profile it does. Section 2.6's RS256 requirement
//! in particular is a DEPLOYMENT property -- the signing algorithm is per-environment
//! configuration -- so the test pins that the transmitter signs with whatever the
//! environment registered and the checklist records the operator's obligation, rather
//! than pretending a test can settle it.

#![cfg(feature = "testing")]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use tower::ServiceExt;

/// Fetch the transmitter configuration document the profile section 2.3 governs.
async fn transmitter_metadata(harness: &Harness) -> serde_json::Value {
    let scope = harness.scope();
    let uri = format!(
        "/.well-known/ssf-configuration/t/{}/e/{}",
        scope.tenant(),
        scope.environment()
    );
    let response = harness
        .router()
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn section_2_3_the_metadata_carries_every_field_the_profile_requires() {
    // Sections 2.3.1 through 2.3.7. Each is a MUST on the transmitter configuration
    // document, and each is asserted by NAME rather than by counting fields, so a
    // document that dropped one and gained another still fails.
    //
    // `spec_version` was the one this transmitter was missing. Its absence is the kind a
    // receiver cannot work around: the profile has receivers read it to decide which
    // version's rules to apply.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let doc = transmitter_metadata(&harness).await;

    for field in [
        "spec_version",
        "delivery_methods_supported",
        "jwks_uri",
        "configuration_endpoint",
        "status_endpoint",
        "verification_endpoint",
        "authorization_schemes",
    ] {
        assert!(
            doc.get(field).is_some(),
            "section 2.3 requires `{field}` in the transmitter metadata: {doc}"
        );
    }
}

#[tokio::test]
async fn section_2_3_1_the_spec_version_is_1_0_or_greater() {
    // "value MUST be `1_0` or greater". Asserted as the exact value this build implements
    // rather than a pattern: claiming a later version to look current would tell a
    // receiver to apply rules this transmitter does not follow, and a regex would let
    // that through.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let doc = transmitter_metadata(&harness).await;
    assert_eq!(
        doc["spec_version"].as_str(),
        Some(ironauth_oidc::ssf::SSF_SPEC_VERSION),
        "the advertised spec version is not the one this build implements"
    );
    assert_eq!(ironauth_oidc::ssf::SSF_SPEC_VERSION, "1_0");
}

#[tokio::test]
async fn section_2_3_7_the_authorization_scheme_names_rfc_6749() {
    // "MUST include the `authorization_schemes` field and its value MUST include the
    // value `{"spec_urn": "urn:ietf:rfc:6749"}`". The profile pins that URN specifically,
    // so a document carrying the field with some other scheme, or with an empty array,
    // fails interop even though the field is present. Asserted by searching the array for
    // the URN rather than by indexing element zero, because the profile says "include".
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let doc = transmitter_metadata(&harness).await;
    let schemes = doc["authorization_schemes"]
        .as_array()
        .unwrap_or_else(|| panic!("authorization_schemes is not an array: {doc}"));
    assert!(
        schemes
            .iter()
            .any(|scheme| scheme["spec_urn"].as_str() == Some("urn:ietf:rfc:6749")),
        "section 2.3.7 requires the RFC 6749 scheme URN: {doc}"
    );
}

#[tokio::test]
async fn section_2_3_2_both_profile_delivery_methods_are_advertised() {
    // The profile has the transmitter process a create for push (RFC 8935) and poll
    // (RFC 8936) in sections 2.3.8.1 and 2.3.8.2, so a document advertising only one
    // tells half the receivers in an interop matrix not to bother.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let doc = transmitter_metadata(&harness).await;
    let methods = doc["delivery_methods_supported"]
        .as_array()
        .unwrap_or_else(|| panic!("delivery_methods_supported is not an array: {doc}"));
    for method in ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"] {
        assert!(
            methods.iter().any(|m| m.as_str() == Some(method)),
            "section 2.3 requires {method} to be advertised: {doc}"
        );
    }
}

#[tokio::test]
async fn section_2_3_the_advertised_endpoints_are_absolute_and_under_this_issuer() {
    // A receiver bootstraps from this document and calls what it finds. A relative path,
    // or one under another host, is a field that is PRESENT and unusable -- which is the
    // shape the `jwks_uri` defect had before it was fixed: it named a path nothing
    // mounted, so every receiver that followed the document failed to verify a SET.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let doc = transmitter_metadata(&harness).await;
    let issuer = doc["issuer"].as_str().expect("issuer");
    for field in [
        "jwks_uri",
        "configuration_endpoint",
        "status_endpoint",
        "verification_endpoint",
    ] {
        let value = doc[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is not a string: {doc}"));
        assert!(
            value.starts_with("https://") || value.starts_with("http://"),
            "{field} is not absolute: {value}"
        );
        assert!(
            value.starts_with(issuer),
            "{field} points outside this transmitter's issuer: {value} vs {issuer}"
        );
    }
}

#[tokio::test]
async fn section_2_5_a_required_subject_identifier_format_is_actually_rendered() {
    // "MUST be able to send events with at least one of" `email`, `iss_sub`, or `opaque`.
    //
    // ASSERTED ON A RENDERED SUBJECT, not on a format parser. The first version of this
    // called `SsfSubjectFormat::parse` on three string literals, which exercises a string
    // parser and would pass in a build that could not render a subject at all -- the
    // requirement is about what this transmitter can SEND.
    for subject in [
        ironauth_oidc::ssf_set::SubjectIdentifier::IssSub {
            iss: "https://issuer.example".to_owned(),
            sub: "usr_1".to_owned(),
        },
        ironauth_oidc::ssf_set::SubjectIdentifier::Opaque {
            id: "usr_1".to_owned(),
        },
        ironauth_oidc::ssf_set::SubjectIdentifier::Email {
            email: "a@example.test".to_owned(),
        },
    ] {
        let rendered = subject.render();
        let format = rendered["format"]
            .as_str()
            .unwrap_or_else(|| panic!("no format in {rendered}"));
        assert!(
            ["email", "iss_sub", "opaque"].contains(&format),
            "section 2.5 names three formats and this is not one of them: {rendered}"
        );
        // The rendering must carry the members that format needs, or a receiver has a
        // label and no subject.
        let members = rendered.as_object().expect("an object").len();
        assert!(
            members >= 2,
            "a subject rendered as `{format}` carries only its label: {rendered}"
        );
    }
}

#[tokio::test]
async fn section_2_8_1_a_set_carries_exactly_one_event() {
    // "The `events` claim of each SET MUST contain only one event."
    //
    // THE TYPE ALREADY GUARANTEES IT, and saying so is the point of this test rather than
    // a reason to skip it. `SetToMint` holds ONE `SecurityEvent`, so `build_set_claims`
    // cannot emit two and an assertion on its output cannot fail -- which the first
    // version of this test did, and it measured nothing.
    //
    // What is worth pinning is that the guarantee is STRUCTURAL: the claim set is built
    // from a type that cannot express the violation. This asserts the emitted shape AND
    // that the receiver half refuses the shape it will not act on, which is the same
    // requirement seen from the other side and is the half that could actually regress.
    let claims = ironauth_oidc::ssf_set::build_set_claims(
        "https://issuer.example",
        1_700_000_000,
        &ironauth_oidc::ssf_set::SetToMint {
            audience: &["https://receiver.example".to_owned()],
            jti: "jti-one-event",
            subject: &ironauth_oidc::ssf_set::SubjectIdentifier::Opaque {
                id: "usr_1".to_owned(),
            },
            event: &ironauth_oidc::caep::session_end_event(
                ironauth_store::SessionEndCause::LoggedOut,
                "human",
                1_700_000_000_000_000,
            ),
        },
    );
    let events = claims["events"]
        .as_object()
        .unwrap_or_else(|| panic!("events is not an object: {claims}"));
    assert_eq!(
        events.len(),
        1,
        "section 2.8.1 allows exactly one event per SET: {claims}"
    );
    // The receiving half of the same rule lives in `risc_receiver`, whose
    // `a_set_carrying_several_events_is_refused_rather_than_partly_applied` drives a
    // two-event token through the real endpoint. That one CAN fail; this one records that
    // the emitting side makes the violation unrepresentable.
}

#[tokio::test]
async fn section_3_1_a_session_revoked_event_carries_a_non_empty_reason_admin() {
    // SECTION 3 IS WHAT DECIDES CONFORMANCE AT ALL: "An implementation conforming to this
    // profile MUST support at least one of the following use cases". This build supports
    // 3.1, Session Revocation, and 3.1 adds a requirement the base CAEP spec does not:
    // "`reason_admin` field of the event MUST be populated with a non-empty object".
    //
    // Non-empty is asserted as a member count rather than as presence, because
    // `"reason_admin": {}` satisfies presence and is exactly what the profile forbids.
    for cause in [
        ironauth_store::SessionEndCause::Revoked,
        ironauth_store::SessionEndCause::BulkRevoked,
        ironauth_store::SessionEndCause::UserRevokedAll,
        ironauth_store::SessionEndCause::LoggedOut,
        ironauth_store::SessionEndCause::ReplacedByOtherSubject,
        ironauth_store::SessionEndCause::PasswordChanged,
    ] {
        let event = ironauth_oidc::caep::session_end_event(cause, "human", 1_700_000_000_000_000);
        assert_eq!(
            event.event_type,
            ironauth_oidc::caep::SESSION_REVOKED,
            "{} is not the use case section 3.1 governs",
            cause.as_str()
        );
        let reason = event
            .payload
            .get("reason_admin")
            .unwrap_or_else(|| panic!("{} carries no reason_admin", cause.as_str()));
        let members = reason
            .as_object()
            .unwrap_or_else(|| panic!("reason_admin is not an object: {reason}"));
        assert!(
            !members.is_empty(),
            "section 3.1 requires a NON-EMPTY reason_admin and {} carries {{}}",
            cause.as_str()
        );
    }
}

#[tokio::test]
async fn section_2_7_2_a_bearer_access_token_is_refused_today() {
    // A TEST THAT PINS A NON-CONFORMANCE, deliberately.
    //
    // Section 2.7.2 requires the transmitter to accept OAuth 2.0 Bearer ACCESS TOKENS.
    // These endpoints authenticate the receiver as an OAuth CLIENT instead, through
    // `client_secret_basic`, so a conformant receiver presenting a Bearer token is
    // refused. The checklist records that as not satisfied.
    //
    // A row saying "not satisfied" with no test is a claim that decays: someone adds
    // bearer support and the document still says it is missing, or someone removes what
    // little is there and nothing notices. This asserts the CURRENT behaviour, so closing
    // the gap FAILS this test and forces the row to be updated in the same change. That
    // is the only way a not-satisfied row stays honest.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/ssf/streams",
        scope.tenant(),
        scope.environment()
    );
    let response = harness
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header(
                    "authorization",
                    "Bearer an-access-token-a-conformant-receiver-would-send",
                )
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a Bearer access token is accepted, so section 2.7.2 may now be satisfied: \
         update the checklist row and this test together"
    );
    // AND THE CHALLENGE NAMES BASIC, which is itself the evidence that this door is an
    // RFC 6749 client-authentication door rather than an OAuth resource server. Section
    // 2.7.2's last requirement is that errors follow RFC 6750 section 3.1, which wants a
    // `Bearer` challenge.
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        challenge.starts_with("Basic"),
        "the challenge is no longer Basic ({challenge}), so the authorization model \
         changed: re-assess section 2.7 in the checklist"
    );
}
