// SPDX-License-Identifier: MIT OR Apache-2.0

//! PKCE enforcement, exact redirect matching, native-app redirect rules, and the
//! RFC 9207 `iss`, end to end against a real Postgres (issue #13).
//!
//! These cover the #13 acceptance criteria that need the live authorization and
//! token endpoints over the store (the pure comparator corpus and the `iss`
//! parameter assembly are unit-tested in `ironauth-store` and the `response`
//! module respectively):
//!
//! - PKCE is S256-only (`plain` is `invalid_request`) and mandatory (a public
//!   client with no `code_challenge` is rejected; a confidential client follows the
//!   per-environment policy, required by default).
//! - Downgrade prevention in BOTH directions: a challenge-bound code needs the
//!   matching verifier, and a no-challenge code is never redeemable WITH one.
//! - `redirect_uri` is matched by EXACT string against the registered set, with the
//!   RFC 8252 loopback port exception, and native private-use-scheme redirects are
//!   accepted; a malformed scheme is rejected at registration AND at authorization.
//! - `iss` is emitted on success AND error authorization responses.

mod common;

use axum::http::{StatusCode, header};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location, location_param,
};
use ironauth_config::OidcConfig;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::StoreError;

/// The production-default config: PKCE required for confidential clients too.
fn strict_pkce_config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: true,
        ..OidcConfig::default()
    }
}

// ===========================================================================
// PKCE S256-only and mandatory (acceptance 1, 2).
// ===========================================================================

#[tokio::test]
async fn code_challenge_method_plain_is_invalid_request_with_iss() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    // A challenge with method=plain: plain is structurally absent, so it is
    // invalid_request (returned by redirect to the validated redirect_uri, which
    // carries the RFC 9207 iss).
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=s&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=plain",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::FOUND, "error redirect: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "plain is invalid_request"
    );
    assert_eq!(
        location_param(&headers, "iss").as_deref(),
        Some(harness.issuer()),
        "the error response carries iss"
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "no code is issued"
    );
}

#[tokio::test]
async fn a_malformed_s256_code_challenge_is_invalid_request_with_iss() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    // A syntactically valid S256 request whose challenge is NOT a 43-char base64url
    // SHA-256 digest (here it is truncated). An S256 challenge is always exactly 43
    // unpadded base64url chars, so a short/low-entropy binding is rejected up front
    // with invalid_request (by redirect, carrying iss) rather than deferred to a
    // guaranteed token failure.
    let truncated = &PKCE_CHALLENGE[..20];
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=s&\
         code_challenge={truncated}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::FOUND, "error redirect: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "a malformed S256 challenge is invalid_request"
    );
    assert_eq!(
        location_param(&headers, "iss").as_deref(),
        Some(harness.issuer()),
        "the error response carries iss"
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "no code is issued"
    );
}

#[tokio::test]
async fn a_public_client_without_a_code_challenge_is_rejected() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    // The harness client is public (method none): PKCE is mandatory, so a request
    // with no code_challenge is invalid_request (by redirect, with iss).
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=s",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::FOUND, "error redirect: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "a public client with no PKCE is rejected"
    );
    assert!(location_param(&headers, "code").is_none());
}

#[tokio::test]
async fn a_confidential_client_requires_pkce_under_the_default_policy() {
    // With the production-default policy (require_pkce_for_confidential_clients),
    // even a confidential client must send a code_challenge.
    let harness = Harness::start_with(strict_pkce_config()).await;
    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=s",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::FOUND, "error redirect: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "the default policy requires PKCE for confidential clients too"
    );
}

// ===========================================================================
// Downgrade prevention, both directions (acceptance 3).
// ===========================================================================

#[tokio::test]
async fn a_challenge_bound_code_needs_the_matching_verifier() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // Wrong verifier: invalid_grant.
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let wrong = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        (
            "code_verifier",
            "the-wrong-verifier-value-not-the-appendix-b-one",
        ),
    ]);
    let (status, _h, body) = harness.token(&wrong).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "wrong verifier: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");

    // Correct verifier on a fresh code: success.
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let right = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&right).await;
    assert_eq!(status, StatusCode::OK, "correct verifier: {body}");
    assert!(json(&body)["access_token"].is_string());
}

#[tokio::test]
async fn a_no_challenge_code_is_never_redeemable_with_a_verifier() {
    // The relaxed harness lets a confidential client complete without PKCE, so a
    // no-challenge code exists to exercise the reverse downgrade direction.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();

    // Presenting a verifier for a no-challenge code is a downgrade attempt:
    // invalid_grant.
    let code = harness.issue_authenticated_code(&client_id).await;
    let with_verifier = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", &secret),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&with_verifier).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "downgrade verifier: {body}"
    );
    assert_eq!(
        json(&body)["error"],
        "invalid_grant",
        "a verifier for a no-challenge code is refused"
    );

    // The same shape WITHOUT a verifier (the legitimate no-PKCE confidential path)
    // succeeds, on a fresh code.
    let code = harness.issue_authenticated_code(&client_id).await;
    let no_verifier = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let (status, _h, body) = harness.token(&no_verifier).await;
    assert_eq!(status, StatusCode::OK, "no-PKCE confidential path: {body}");
    assert!(json(&body)["access_token"].is_string());
}

// ===========================================================================
// Exact redirect matching, loopback, and native app support (acceptance 4, 5, 6).
// ===========================================================================

#[tokio::test]
async fn an_unregistered_but_valid_redirect_is_refused_by_an_error_page() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    // A perfectly registrable https URL that the client did NOT register: it must
    // NEVER receive a redirect (an error page instead), so it cannot be turned into
    // an open redirector.
    let other = "https://client.test/other";
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(other),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "must be a page: {body}");
    assert!(
        headers.get(header::LOCATION).is_none(),
        "an unregistered redirect_uri must NEVER redirect"
    );
    assert!(body.contains("<html"), "an error page is rendered");
}

#[tokio::test]
async fn a_loopback_ip_literal_matches_with_a_variable_port() {
    let harness = Harness::start().await;
    // A native client that registered a loopback redirect with no fixed port.
    let client = harness
        .create_public_client_with_redirects("native loopback", &["http://127.0.0.1/cb"])
        .await;
    let client_id = client.to_string();
    let cookie = harness.authenticated_cookie_for(&client_id).await;

    // A presented loopback URI that differs ONLY in the (ephemeral) port matches.
    let presented = "http://127.0.0.1:53127/cb";
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(presented),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "loopback variable port: {body}");
    assert!(
        location(&headers).is_some_and(|l| l.starts_with(presented)),
        "the code is delivered to the presented loopback URI"
    );
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued"
    );
}

#[tokio::test]
async fn a_non_loopback_host_gets_strict_exact_match_only() {
    let harness = Harness::start().await;
    // A registered https redirect on a fixed host: a different port is NOT a match
    // (the variable-port latitude is loopback-only).
    let client = harness
        .create_public_client_with_redirects("web client", &["https://app.test/cb"])
        .await;
    let client_id = client.to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc("https://app.test:8443/cb"),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "must be a page: {body}");
    assert!(
        headers.get(header::LOCATION).is_none(),
        "a non-loopback host does not get the variable-port exception"
    );
}

#[tokio::test]
async fn a_native_private_use_scheme_redirect_is_accepted() {
    let harness = Harness::start().await;
    let redirect = "com.example.app:/oauth2redirect";
    let client = harness
        .create_public_client_with_redirects("native app", &[redirect])
        .await;
    let client_id = client.to_string();
    let cookie = harness.authenticated_cookie_for(&client_id).await;

    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(redirect),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "custom scheme redirect: {body}");
    assert!(
        location(&headers).is_some_and(|l| l.starts_with("com.example.app:/oauth2redirect")),
        "the code is delivered to the custom-scheme URI"
    );
    assert!(location_param(&headers, "code").is_some());
}

#[tokio::test]
async fn a_malformed_scheme_is_rejected_at_registration_and_authorization() {
    let harness = Harness::start().await;

    // Registration time: a dangerous scheme is refused before it is ever stored.
    let (actor, corr) = (
        harness_actor(&harness),
        ironauth_store::CorrelationId::generate(harness.env()),
    );
    let client = harness
        .store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .clients()
        .create(harness.env(), "bad-scheme client")
        .await
        .expect("create client");
    let (actor, corr) = (
        harness_actor(&harness),
        ironauth_store::CorrelationId::generate(harness.env()),
    );
    let outcome = harness
        .store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .clients()
        .register_redirect_uris(harness.env(), &client, &["javascript:alert(1)"])
        .await;
    assert!(
        matches!(outcome, Err(StoreError::InvalidRedirectUri)),
        "a malformed scheme is rejected at registration, got {outcome:?}"
    );

    // Authorization time: a malformed presented redirect never redirects (a page).
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}",
        enc("javascript:alert(1)"),
    );
    let (status, headers, _body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "a malformed redirect_uri must NEVER redirect"
    );
}

// ===========================================================================
// RFC 9207 iss on success and error (acceptance 7).
// ===========================================================================

#[tokio::test]
async fn iss_is_emitted_on_the_success_response() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=xyz&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "success redirect: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued"
    );
    assert_eq!(
        location_param(&headers, "iss").as_deref(),
        Some(harness.issuer()),
        "the success response carries iss equal to the issuer"
    );
}

#[tokio::test]
async fn iss_is_emitted_on_the_error_response() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    // response_type=token is unsupported: an error by redirect, which must carry iss.
    let query = format!(
        "response_type=token&client_id={client_id}&redirect_uri={}&state=s1",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::FOUND, "error redirect: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("unsupported_response_type"),
    );
    assert_eq!(
        location_param(&headers, "iss").as_deref(),
        Some(harness.issuer()),
        "the error response carries iss equal to the issuer"
    );
}

/// A throwaway audit actor for direct store seeding in this binary.
fn harness_actor(harness: &Harness) -> ironauth_store::ActorRef {
    ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(harness.env()))
}
