// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret-based client authentication at the token endpoint, against a real
//! Postgres (issue #20): `client_secret_basic` and `client_secret_post` both
//! authenticate and issue tokens; a client registered for one method fails with
//! the spec-exact `invalid_client` when it presents another; a wrong secret is
//! `invalid_client` (401, with `WWW-Authenticate` for a Basic attempt); and the
//! generated secret is a 64-byte URL-safe value that authenticates via Basic.

mod common;

use axum::http::{StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{Harness, REDIRECT_URI, form, json};
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::ClientId;

/// Issue a code bound to `client_id` for a fresh consenting subject (no PKCE, so
/// the token exchange only has to satisfy client authentication and the
/// `redirect_uri` binding).
async fn issue_code_for(harness: &Harness, client_id: &str) -> String {
    harness.issue_authenticated_code(client_id).await
}

/// A standard-padded Basic credential of `client_id:client_secret`.
fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// The `grant_type`, `code`, and `redirect_uri` form (client credentials, if any,
/// are added by the caller).
fn base_form(code: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
    ])
}

#[tokio::test]
async fn client_secret_basic_authenticates_and_issues_tokens() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let code = issue_code_for(&harness, &client_id).await;

    let (status, _headers, body) = harness
        .token_with_auth(&base_form(&code), Some(&basic_header(&client_id, &secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "basic auth exchange: {body}");
    assert!(json(&body)["access_token"].is_string());
    assert!(json(&body)["id_token"].is_string());
}

#[tokio::test]
async fn client_secret_post_authenticates_and_issues_tokens() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();
    let code = issue_code_for(&harness, &client_id).await;

    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let (status, _headers, response) = harness.token(&body).await;
    assert_eq!(status, StatusCode::OK, "post auth exchange: {response}");
    assert!(json(&response)["access_token"].is_string());
}

#[tokio::test]
async fn a_basic_client_presenting_post_is_invalid_client() {
    // Registered for basic; presenting the secret in the body (post) is the
    // spec-forbidden mismatch and yields invalid_client (issue #20 acceptance 5).
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let code = issue_code_for(&harness, &client_id).await;

    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let (status, _headers, response) = harness.token(&body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "mismatch: {response}");
    assert_eq!(json(&response)["error"], "invalid_client");
}

#[tokio::test]
async fn a_post_client_presenting_basic_is_invalid_client() {
    // Registered for post; presenting Basic is the spec-forbidden mismatch.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();
    let code = issue_code_for(&harness, &client_id).await;

    let (status, _headers, response) = harness
        .token_with_auth(&base_form(&code), Some(&basic_header(&client_id, &secret)))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "mismatch: {response}");
    assert_eq!(json(&response)["error"], "invalid_client");
}

#[tokio::test]
async fn a_wrong_basic_secret_is_invalid_client_with_www_authenticate() {
    let harness = Harness::start().await;
    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let code = issue_code_for(&harness, &client_id).await;

    let (status, headers, response) = harness
        .token_with_auth(
            &base_form(&code),
            Some(&basic_header(&client_id, "the-wrong-secret")),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong secret: {response}");
    assert_eq!(json(&response)["error"], "invalid_client");
    assert!(
        headers.get(header::WWW_AUTHENTICATE).is_some(),
        "a failed Basic attempt must carry WWW-Authenticate (RFC 6749 5.2)"
    );
}

#[tokio::test]
async fn a_wrong_post_secret_is_invalid_client() {
    let harness = Harness::start().await;
    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();
    let code = issue_code_for(&harness, &client_id).await;

    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", "the-wrong-secret"),
    ]);
    let (status, headers, response) = harness.token(&body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong secret: {response}");
    assert_eq!(json(&response)["error"], "invalid_client");
    // A post (non-Authorization-header) attempt does not carry WWW-Authenticate.
    assert!(headers.get(header::WWW_AUTHENTICATE).is_none());
}

#[tokio::test]
async fn a_public_client_presenting_a_secret_is_invalid_client() {
    // The harness client is public (method none); presenting a secret is a method
    // mismatch, so it fails invalid_client rather than being silently ignored.
    let harness = Harness::start().await;
    let public = harness.client_id().to_string();
    let code = issue_code_for(&harness, &public).await;

    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &public),
        ("client_secret", "unexpected"),
    ]);
    let (status, _headers, response) = harness.token(&body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "public+secret: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_client");
}

#[tokio::test]
async fn an_unknown_client_is_invalid_client() {
    let harness = Harness::start().await;
    let public = harness.client_id().to_string();
    let code = issue_code_for(&harness, &public).await;

    // A well-formed but never-created client id: unknown, so invalid_client.
    let unknown = ClientId::generate(harness.env(), &harness.scope()).to_string();
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &unknown),
        ("client_secret", "whatever"),
    ]);
    let (status, _headers, response) = harness.token(&body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unknown client: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_client");
}

#[tokio::test]
async fn a_code_for_one_client_is_not_redeemable_by_another_authenticated_client() {
    // The Zitadel advisory class combined with client auth: client B authenticates
    // correctly with ITS OWN secret, but presents a code issued to client A. Auth
    // succeeds, then the client-binding re-check fails: uniform invalid_grant.
    let harness = Harness::start().await;
    let (client_a, _secret_a) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let (client_b, secret_b) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let code = issue_code_for(&harness, &client_a.to_string()).await;

    let (status, _headers, response) = harness
        .token_with_auth(
            &base_form(&code),
            Some(&basic_header(&client_b.to_string(), &secret_b)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "cross-client: {response}");
    assert_eq!(
        json(&response)["error"],
        "invalid_grant",
        "an authenticated wrong client is invalid_grant, not invalid_client"
    );
}

#[tokio::test]
async fn generated_secret_is_url_safe_64_bytes_and_authenticates_via_basic() {
    // Acceptance 3: the generated secret is a 64-byte base64url value. It is
    // URL-safe, so the client_secret_basic raw and form-encoded interpretations
    // coincide and the raw Basic header authenticates.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let decoded = URL_SAFE_NO_PAD
        .decode(&secret)
        .expect("secret is url-safe base64");
    assert_eq!(decoded.len(), 64, "64 random bytes");
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "url-safe alphabet: {secret}"
    );

    let client_id = client.to_string();
    let code = issue_code_for(&harness, &client_id).await;
    let (status, _headers, body) = harness
        .token_with_auth(&base_form(&code), Some(&basic_header(&client_id, &secret)))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "url-safe secret authenticates: {body}"
    );
}
