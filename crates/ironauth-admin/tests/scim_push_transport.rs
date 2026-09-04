// SPDX-License-Identifier: MIT OR Apache-2.0

//! The PRODUCTION outbound transport (issue #137).
//!
//! # Why this file exists
//!
//! [`FetchScimTransport`] had no caller anywhere in the repository. The client suite drives a
//! fixture transport that satisfies the same trait, so every property the production one claims
//! for itself -- that customer-supplied URLs go through the SSRF-hardened fetcher, that the
//! bearer is presented as a header, that the SCIM media type is sent -- was asserted by its doc
//! comment and by nothing else. A seam with no caller compiles, and compiling is the only thing
//! it had been shown to do.
//!
//! # What can and cannot be measured here
//!
//! The hardened fetcher refuses loopback by design, so this file cannot point it at a local
//! server and read a 200 back: that is what the fixture transport is for. What it CAN measure is
//! every path that ends before a socket is opened, which is where this transport's own decisions
//! live. Everything below is one of those.

use ironauth_admin::scim_push_transport::{
    FetchScimTransport, ScimRequest, ScimTransport, ScimTransportError,
};
use ironauth_fetch::{FetchLimits, Fetcher};
use serde_json::json;
use std::sync::Arc;

fn transport() -> FetchScimTransport {
    FetchScimTransport::new(Arc::new(Fetcher::for_tests(FetchLimits::default())))
}

#[tokio::test]
async fn a_destination_the_outbound_policy_refuses_never_reaches_a_socket() {
    // Issue #137: "all outbound requests go through the SSRF-hardened outbound fetcher discipline
    // (customer-supplied URLs are untrusted)". A connection's base URL is typed by an operator
    // and points at somebody else's server, so it is exactly the input that reaches internal
    // addresses if nothing refuses it.
    //
    // This is the assertion that the purpose wiring is real: `FetchPurpose::ScimPush` selects the
    // policy, and a policy that was never consulted would let these through.
    // https, deliberately. The first draft of this test used `http` and passed nothing: the
    // fetcher refuses a plaintext scheme BEFORE it resolves anything, so every row was answered
    // by the scheme check and the address policy was never consulted. A test that cannot reach
    // the guard it names proves nothing about it.
    for base in [
        "https://127.0.0.1:8443/scim/v2",
        "https://169.254.169.254/scim/v2",
        "https://[::1]:9443/scim/v2",
    ] {
        let outcome = transport()
            .send(base, "token", ScimRequest::get("/Users/dsid-1"))
            .await;
        assert_eq!(
            outcome.err(),
            Some(ScimTransportError::Blocked),
            "{base} was not refused by the outbound policy"
        );
    }
}

#[tokio::test]
async fn a_plaintext_base_url_is_a_configuration_error_rather_than_an_outage() {
    // The fetcher refuses `http` without an explicit opt-in, because a bearer with authority over
    // somebody else's directory would otherwise cross the network in clear. What matters here is
    // how that refusal is REPORTED: called a transport failure it retries for ever and the
    // connection's health says the downstream could not be reached, which sends an operator to
    // investigate somebody else's server when the fix is one character of their own URL.
    let outcome = transport()
        .send(
            "http://downstream.example/scim/v2",
            "token",
            ScimRequest::get("/Users/dsid-1"),
        )
        .await;
    assert_eq!(
        outcome.err(),
        Some(ScimTransportError::Configuration),
        "a plaintext base URL must tell the operator to fix the connection"
    );
}

#[tokio::test]
async fn a_credential_that_cannot_be_a_header_is_a_configuration_error_not_an_outage() {
    // A bearer carrying a newline or a control byte cannot be presented, and no retry changes
    // that: the same stored secret fails identically forever. Reported as a transport failure it
    // is indistinguishable from a downstream being down, so the connection looks like it is
    // waiting for somebody else's server to come back while the fix is one field on the
    // connection.
    for bearer in ["line\nbreak", "nul\0byte"] {
        let outcome = transport()
            .send(
                "https://downstream.example/scim/v2",
                bearer,
                ScimRequest::get("/Users/dsid-1"),
            )
            .await;
        assert_eq!(
            outcome.err(),
            Some(ScimTransportError::Configuration),
            "a malformed credential was not reported as a configuration problem"
        );
    }
}

#[tokio::test]
async fn a_base_url_that_would_swallow_the_scim_path_is_refused_before_the_request() {
    // A base carrying a query folds the SCIM path INTO that query: `/Users` becomes part of a
    // parameter value and every request addresses the base path instead. A downstream that
    // ignores unknown parameters answers 200, so the client reads a create that never happened as
    // a success and records a downstream id for a resource that does not exist.
    for base in [
        "https://downstream.example/scim/v2?tenant=acme",
        "https://downstream.example/scim/v2#fragment",
    ] {
        let outcome = transport()
            .send(
                base,
                "token",
                ScimRequest::with_body(http::Method::POST, "/Users", json!({ "userName": "ada" })),
            )
            .await;
        assert_eq!(
            outcome.err(),
            Some(ScimTransportError::Configuration),
            "{base} was accepted"
        );
    }
}
