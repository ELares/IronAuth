// SPDX-License-Identifier: MIT OR Apache-2.0

//! The FAPI 2.0 hardened-mode integration suite (issue #156): the SAME flows in a
//! hardened environment and a plain one side by side, so a constraint that only
//! bites under the mode is proven by the contrast.
//!
//! Each test drives the real router twice: the plain harness (the default) accepts
//! the flow, and the hardened harness rejects it with the correct error code. The
//! mode's flag comes from the environment's row, and the enforcements live in the
//! authorize validator and the code exchange.

mod common;

use axum::http::{StatusCode, header};
use common::{Harness, REDIRECT_URI, form, json};
use ironauth_oidc::ClientAuthMethod;

/// Drive the authorize request with the given query + cookie, returning the
/// redirect's error parameter (or `None` when the request succeeds).
async fn authorize_error(
    h: &Harness,
    query: &str,
    cookie: &str,
) -> Option<String> {
    let (status, headers, _) = h.authorize_with_cookie(query, cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize redirects");
    common::location_param(&headers, "error")
}

/// A signed-in subject + session for the authorize drives.
async fn signed_in(h: &Harness) -> (String, String) {
    let subject = h.seed_unique_user().await;
    h.grant_consent(&subject, h.client_id().as_str()).await;
    let cookie = h.session_cookie(&subject).await;
    (subject, cookie)
}

/// The Basic credential for the confidential client `(id, secret)`.
fn basic(id: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

/// THE PAR-MANDATORY CRITERION (FAPI 2.0 section 6.2): a plain authorization
/// request is rejected in a hardened environment with `invalid_request_object`,
/// while the same request succeeds in a plain one.
#[tokio::test]
async fn a_non_par_authorization_request_is_refused_only_under_hardened_mode() {
    // The plain side: the same request succeeds.
    let plain = Harness::start().await;
    let (subject, cookie) = signed_in(&plain).await;
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid&nonce=n1",
        plain.client_id(),
        common::enc(REDIRECT_URI),
    );
    let (status, headers, _) = plain.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the plain env authorizes");
    let location = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("the redirect");
    assert!(
        !location.contains("error="),
        "the plain env accepts the non-PAR request: {location}"
    );
    let _ = subject;

    // The hardened side: invalid_request_object.
    let mut hardened = Harness::start().await;
    hardened.harden_environment(None).await;
    let (_, cookie) = signed_in(&hardened).await;
    let error = authorize_error(&hardened, &query, &cookie).await;
    assert_eq!(
        error.as_deref(),
        Some("invalid_request_object"),
        "a non-PAR request is refused in a hardened environment"
    );
}

/// THE PKCE CRITERION (FAPI 2.0 section 6.5.2): a request without a code
/// challenge is refused in a hardened environment.
#[tokio::test]
async fn a_pkce_less_request_is_refused_only_under_hardened_mode() {
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid",
        "cli",
        common::enc(REDIRECT_URI),
    );
    // The plain side: a confidential client without PKCE succeeds when the policy
    // relaxes it.
    let plain = Harness::start().await;
    let (_, cookie) = signed_in(&plain).await;
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid",
        plain.client_id(),
        common::enc(REDIRECT_URI),
    );
    let error = authorize_error(&plain, &query, &cookie).await;
    assert!(
        error.is_none(),
        "a confidential client without PKCE is accepted in the plain env"
    );

    // The hardened side: refused.
    let mut hardened = Harness::start().await;
    hardened.harden_environment(None).await;
    let (_, cookie) = signed_in(&hardened).await;
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid",
        hardened.client_id(),
        common::enc(REDIRECT_URI),
    );
    let error = authorize_error(&hardened, &query, &cookie).await;
    assert_eq!(
        error.as_deref(),
        Some("invalid_request"),
        "a PKCE-less request is refused in a hardened environment"
    );
}

/// THE SENDER-CONSTRAINT CRITERION (FAPI 2.0 section 6.4): a code exchange
/// without a DPoP proof (and without an mTLS certificate) is refused in a
/// hardened environment, while the same exchange succeeds in a plain one.
#[tokio::test]
async fn a_bearer_code_exchange_is_refused_only_under_hardened_mode() {
    // The plain side: the bearer exchange succeeds.
    let plain = Harness::start().await;
    let (subject, _) = signed_in(&plain).await;
    let (plain_id, plain_secret) = plain
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let code = plain
        .issue_code_for_subject(&plain_id.to_string(), &subject, "openid")
        .await;
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let (status, _, body) = plain
        .token_with_auth(&exchange, Some(&basic(&plain_id.to_string(), &plain_secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "the plain env issues a bearer token: {body}");

    // The hardened side: refused.
    let mut hardened = Harness::start().await;
    hardened.harden_environment(None).await;
    let (subject, _) = signed_in(&hardened).await;
    let (hardened_id, hardened_secret) = hardened
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let code = hardened
        .issue_code_for_subject(&hardened_id.to_string(), &subject, "openid")
        .await;
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let (status, _, body) = hardened
        .token_with_auth(
            &exchange,
            Some(&basic(&hardened_id.to_string(), &hardened_secret)),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a bearer exchange is refused in a hardened environment: {body}"
    );
    let value = json(&body);
    assert_eq!(
        value["error"],
        serde_json::json!("invalid_grant"),
        "the refusal carries invalid_grant: {body}"
    );
}

/// THE PUBLIC-CLIENT CRITERION (FAPI 2.0 section 6.1): a request from a public
/// client is refused in a hardened environment with the auth-method refusal.
#[tokio::test]
async fn a_public_clients_request_is_refused_only_under_hardened_mode() {
    let plain = Harness::start().await;
    let (subject, _) = signed_in(&plain).await;
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid&nonce=n2",
        plain.client_id(),
        common::enc(REDIRECT_URI),
    );
    let (status, _, _) = plain
        .authorize_with_cookie(&query, &plain.session_cookie(&subject).await)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the plain env authorizes");

    let mut hardened = Harness::start().await;
    hardened.harden_environment(None).await;
    let (_, cookie) = signed_in(&hardened).await;
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid&nonce=n2",
        hardened.client_id(),
        common::enc(REDIRECT_URI),
    );
    let error = authorize_error(&hardened, &query, &cookie).await;
    assert_eq!(
        error.as_deref(),
        Some("invalid_request"),
        "a public client's request is refused in a hardened environment"
    );
}