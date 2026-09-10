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
async fn section_2_5_a_required_subject_identifier_format_is_supported() {
    // "MUST be able to send events with at least one of" `email`, `iss_sub`, or `opaque`.
    // This build renders all three, and the profile's floor is one, so the assertion is
    // that the intersection is non-empty rather than that all three are present -- which
    // is what the profile actually requires and what a future build dropping one should
    // still satisfy.
    let rendered: Vec<&str> = ["email", "iss_sub", "opaque"]
        .into_iter()
        .filter(|format| ironauth_store::SsfSubjectFormat::parse(format).is_some())
        .collect();
    assert!(
        !rendered.is_empty(),
        "section 2.5 requires at least one of email, iss_sub or opaque"
    );
}

#[tokio::test]
async fn section_2_8_1_a_set_carries_exactly_one_event() {
    // "The `events` claim of each SET MUST contain only one event." Asserted on a MINTED
    // token rather than on the builder's input, because the requirement is about what
    // leaves this transmitter.
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
}
