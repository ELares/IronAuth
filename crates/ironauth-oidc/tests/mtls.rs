// SPDX-License-Identifier: MIT OR Apache-2.0

//! The self-signed mTLS client-authentication suite (issue #159), over a real
//! database.
//!
//! Exercises `self_signed_tls_client_auth` end to end through the reusable
//! [`ironauth_oidc::authenticate_client`] seam (the SAME seam the token endpoint
//! uses): the registered certificate authenticates, ANY other certificate is the
//! opaque `invalid_client` (a substitution, however well-formed, is not the
//! registered one), an expired certificate is rejected, a certificate-less
//! request is rejected, and a certificate-less registration is a store-level
//! conflict (the CHECK refuses it loudly, mirroring the keyless `private_key_jwt`
//! discipline).

mod common;

use std::time::{Duration, SystemTime};

use axum::http::StatusCode;

/// The proxy's escaped certificate form: percent-encode every byte (a header value
/// cannot carry the PEM's newlines).
fn percent_escape(pem: &str) -> String {
    pem.as_bytes()
        .iter()
        .fold(String::with_capacity(pem.len() * 3), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
            out
        })
}

use common::Harness;
use ironauth_oidc::{ClientAuthInputs, ClientAuthMethod, authenticate_client};
use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose};

/// The harness's deterministic clock starts at the UNIX epoch; a test advances it to
/// the REAL now so the auth instant lands inside every cert's validity window.
fn advance_to_now(h: &Harness) {
    let now = SystemTime::now() // invariant-allow: time-via-env (the harness clock is
        // advanced to REAL now so the auth instant lands inside the test certs' validity
        // windows; the certs themselves are anchored to the same real wall-clock).
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("post-epoch");
    h.clock().advance(now);
}

/// A fresh self-signed client certificate (its own issuer), valid for an hour
/// from the harness's now, PEM-encoded.
fn fresh_leaf_pem() -> String {
    leaf_pem(
        SystemTime::now() - Duration::from_secs(60), // invariant-allow: time-via-env
        SystemTime::now() + Duration::from_secs(3600), // invariant-allow: time-via-env
    )
}

/// A leaf certificate valid over `[not_before, not_after]`, PEM-encoded.
fn leaf_pem(not_before: SystemTime, not_after: SystemTime) -> String {
    // invariant-allow: time-via-env on the lines below: test certificate validity
    // windows are anchored to real wall-clock, as the advance helper documents.
    let key = KeyPair::generate().expect("the test key generates");
    let mut params = CertificateParams::default();
    params.not_before = not_before.into(); // invariant-allow: time-via-env
    params.not_after = not_after.into();
    params.not_after = not_after.into();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cert = params
        .self_signed(&key)
        .expect("the test certificate generates");
    cert.pem()
}

/// Drive the seam with `certificate_pem` (or none) for `client_id`.
async fn authenticate(
    h: &Harness,
    client_id: &str,
    certificate_pem: Option<&str>,
) -> Result<(), ironauth_oidc::ClientAuthError> {
    let inputs = ClientAuthInputs {
        authorization: None,
        client_id: Some(client_id),
        client_secret: None,
        client_assertion: None,
        client_assertion_type: None,
        client_certificate: certificate_pem,
    };
    authenticate_client(h.state(), h.scope(), inputs)
        .await
        .map(|_| ())
}

/// The registered certificate authenticates; the client id is the wire claim.
#[tokio::test]
async fn the_registered_certificate_authenticates() {
    let h = Harness::start().await;
    advance_to_now(&h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    authenticate(&h, &client.to_string(), Some(&cert))
        .await
        .expect("the registered certificate authenticates");
}

/// ANY other certificate is rejected: the substitution, however well-formed, is
/// not the registered one.
#[tokio::test]
async fn a_different_certificate_is_rejected() {
    let h = Harness::start().await;
    advance_to_now(&h);
    let registered = fresh_leaf_pem();
    let substituted = fresh_leaf_pem();
    assert_ne!(registered, substituted, "two fresh leaves differ");
    let client = h
        .create_self_signed_mtls_client(&registered)
        .await
        .expect("the mTLS client registers");
    let result = authenticate(&h, &client.to_string(), Some(&substituted)).await;
    assert!(
        matches!(
            result,
            Err(ironauth_oidc::ClientAuthError::InvalidClient { .. })
        ),
        "a substituted certificate must fail closed: {result:?}"
    );
}

/// An expired certificate is rejected even when it is the registered one: the
/// method demands validity at the request instant as well as DER equality.
#[tokio::test]
async fn an_expired_registered_certificate_is_rejected() {
    let h = Harness::start().await;
    advance_to_now(&h);
    let expired = leaf_pem(
        SystemTime::now() - Duration::from_secs(7200), // invariant-allow: time-via-env
        SystemTime::now() - Duration::from_secs(3600), // invariant-allow: time-via-env
    );
    let client = h
        .create_self_signed_mtls_client(&expired)
        .await
        .expect("the mTLS client registers");
    let result = authenticate(&h, &client.to_string(), Some(&expired)).await;
    assert!(
        matches!(
            result,
            Err(ironauth_oidc::ClientAuthError::InvalidClient { .. })
        ),
        "an expired registered certificate must fail closed: {result:?}"
    );
}

/// A certificate-less request is rejected for a method that requires one.
#[tokio::test]
async fn a_certificate_less_request_is_rejected() {
    let h = Harness::start().await;
    advance_to_now(&h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let result = authenticate(&h, &client.to_string(), None).await;
    assert!(
        matches!(
            result,
            Err(ironauth_oidc::ClientAuthError::InvalidClient { .. })
        ),
        "a certificate-less request must fail closed: {result:?}"
    );
}

/// END TO END THROUGH THE TOKEN ENDPOINT: a client registered for
/// `self_signed_tls_client_auth` exchanges client credentials over the stamped
/// certificate header, and a substituted certificate is refused.
#[tokio::test]
async fn the_token_endpoint_authenticates_an_mtls_client_end_to_end() {
    let h = Harness::start().await;
    advance_to_now(&h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let client_id = client.to_string();
    let body = common::form(&[
        ("grant_type", "client_credentials"),
        ("client_id", &client_id),
    ]);
    // The proxy's escaped form: the PEM's newlines cannot ride a header value.
    let escaped = percent_escape(&cert);
    let (status, _, response) = h.token_with_certificate(&body, &escaped).await;
    let diagnostics = h.client_auth_diagnostics(&client_id).await;
    eprintln!(
        "mtls diagnostics: {:?}",
        diagnostics
            .iter()
            .map(|d| d.failure_reason.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "the mTLS client exchanges tokens: {response}"
    );

    let substituted = fresh_leaf_pem();
    let escaped_sub = percent_escape(&substituted);
    let (status, _, response) = h.token_with_certificate(&body, &escaped_sub).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a substituted certificate is refused at the token endpoint: {response}"
    );
}

/// The method's registered method is the ONE the seam enforces: a client
/// registered for mTLS cannot authenticate any other way, and the out-of-band
/// diagnostic records the certificate failure (the wire stays opaque).
#[tokio::test]
async fn the_seam_enforces_the_registered_method_and_records_the_diagnostic() {
    let h = Harness::start().await;
    advance_to_now(&h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let client_id = client.to_string();
    let substituted = fresh_leaf_pem();
    let result = authenticate(&h, &client_id, Some(&substituted)).await;
    assert!(result.is_err(), "the substitution fails");
    let diagnostics = h.client_auth_diagnostics(&client_id).await;
    assert!(
        diagnostics
            .iter()
            .any(|record| record.failure_reason == "bad_certificate"),
        "the out-of-band diagnostic records the certificate failure"
    );
    assert_eq!(
        ClientAuthMethod::parse("self_signed_tls_client_auth"),
        Some(ClientAuthMethod::SelfSignedTlsClientAuth),
        "the wire method parses"
    );
}
