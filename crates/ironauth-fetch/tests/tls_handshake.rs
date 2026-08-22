// SPDX-License-Identifier: MIT OR Apache-2.0

//! A real HTTPS exchange through the hardened fetcher (issue #959).
//!
//! Every other test in this crate stops before the handshake, because `for_tests` and
//! `from_parts` trust NOTHING: an in-process server can be dialed and never spoken to. That
//! ceiling left the whole response half of every outbound feature untested across the
//! workspace, and made two of issue #112's acceptance criteria unprovable.
//!
//! These tests exist to prove two things that must BOTH hold, since the second is what keeps
//! the first from being a hole:
//!
//! 1. a handshake can complete against an in-process listener, so a target can ANSWER;
//! 2. the SSRF policy is completely untouched by that, so the seam is not a way around it.
//!
//! The second is not decoration. Supplying a trust anchor is one edit away from also skipping
//! destination validation, and if that happened every outbound test in the workspace would go
//! green for the wrong reason. The refusal test below is what would fail first.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;

use ironauth_fetch::{
    FetchError, FetchLimits, FetchPurpose, FetchRequest, Fetcher, RecordingDialer, StaticResolver,
    TestTlsIdentity, TestTlsTarget,
};

/// The name the certificate is minted for and the URL is written against. NOT the address the
/// dialer lands on: those differ deliberately, so the certificate answers for the NAME while
/// the deny policy still judges the ADDRESS.
const TARGET_HOST: &str = "gate.example";

#[tokio::test]
async fn the_hardened_fetcher_completes_an_https_exchange_with_an_in_process_target() {
    let identity = TestTlsIdentity::generate(TARGET_HOST);
    let target = TestTlsTarget::start(&identity, 200, r#"{"verdict":"allow"}"#).await;

    // A PUBLIC address from the resolver, so destination validation runs its real checks, and
    // a dialer that lands the socket locally. This is the same seam every other test here
    // uses; the only addition is the trust anchor.
    let resolver = Arc::new(StaticResolver::new(vec![common::public_ip()]));
    let dialer = Arc::new(RecordingDialer::new(target.addr));
    let fetcher = Fetcher::from_parts_trusting(
        FetchLimits::default(),
        resolver,
        Arc::clone(&dialer),
        &identity.root_der,
    );

    let request = FetchRequest::get(
        FetchPurpose::FlowTarget,
        format!("https://{TARGET_HOST}/consult"),
    );
    let response = fetcher
        .fetch(request)
        .await
        .expect("the exchange completes");

    assert_eq!(response.status().as_u16(), 200, "the target answered");
    assert_eq!(
        response.body(),
        br#"{"verdict":"allow"}"#,
        "and the BODY came back, which is the half no test in this workspace could reach \
         before: verdict parsing, signature verification and status classification all live \
         behind this line"
    );
}

#[tokio::test]
async fn the_trust_anchor_does_not_weaken_the_destination_policy() {
    // The property that keeps the test above from being a hole. Same trusting fetcher, same
    // real root, but the resolver now answers a LOOPBACK address. If supplying a trust anchor
    // had also loosened destination validation, this would connect.
    let identity = TestTlsIdentity::generate(TARGET_HOST);
    let target = TestTlsTarget::start(&identity, 200, r#"{"verdict":"allow"}"#).await;

    let resolver = Arc::new(StaticResolver::new(vec![Ipv4Addr::LOCALHOST.into()]));
    let dialer = Arc::new(RecordingDialer::new(target.addr));
    let fetcher = Fetcher::from_parts_trusting(
        FetchLimits::default(),
        resolver,
        Arc::clone(&dialer),
        &identity.root_der,
    );

    let request = FetchRequest::get(
        FetchPurpose::FlowTarget,
        format!("https://{TARGET_HOST}/consult"),
    );
    let error = fetcher
        .fetch(request)
        .await
        .expect_err("a loopback destination must still be refused");

    assert!(
        matches!(error, FetchError::Blocked),
        "the refusal must be the uniform Blocked, not a TLS or connection error that merely \
         looks like a refusal: got {error:?}"
    );
    assert!(
        dialer.requested().is_empty(),
        "and it must be refused BEFORE the socket, so the anchor never even gets the chance \
         to make a private host reachable"
    );
}

#[tokio::test]
async fn a_target_whose_certificate_is_not_under_the_trusted_root_is_refused() {
    // The anchor is exactly one root, not "any root". A leaf minted under a DIFFERENT root
    // must fail, or the seam would be trusting anything that offers a certificate.
    let served = TestTlsIdentity::generate(TARGET_HOST);
    let unrelated = TestTlsIdentity::generate(TARGET_HOST);
    let target = TestTlsTarget::start(&served, 200, r#"{"verdict":"allow"}"#).await;

    let resolver = Arc::new(StaticResolver::new(vec![common::public_ip()]));
    let dialer = Arc::new(RecordingDialer::new(target.addr));
    let fetcher = Fetcher::from_parts_trusting(
        FetchLimits::default(),
        resolver,
        Arc::clone(&dialer),
        // the OTHER root: nothing this server presents chains to it
        &unrelated.root_der,
    );

    let request = FetchRequest::get(
        FetchPurpose::FlowTarget,
        format!("https://{TARGET_HOST}/consult"),
    );
    let result = fetcher.fetch(request).await;
    assert!(
        result.is_err(),
        "a leaf outside the trusted root must not verify; otherwise the anchor is decorative"
    );
}
