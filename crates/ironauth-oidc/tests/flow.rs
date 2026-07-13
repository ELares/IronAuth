// SPDX-License-Identifier: MIT OR Apache-2.0

//! The end-to-end authorization-code flow and its adversarial variants, against a
//! real Postgres: full issuance, single use, reuse revocation, per-binding
//! mismatch, expiry, cross-scope, tampering, and the no-redirect-before-validation
//! error behavior.

mod common;

use std::time::Duration;

use axum::http::{StatusCode, header};
use common::{
    Harness, ISSUER_BASE, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json,
    location_param,
};
use ironauth_config::OidcConfig;
use ironauth_jose::verify;
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, IssuedTokenId, RedeemOutcome, Scope, ServiceId, StoreError,
    TokenStatus,
};

/// Build the happy-path authorization query for the harness client.
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=xyz&nonce=n-123&\
         scope={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile"),
    )
}

/// Drive the authorization endpoint and return the issued code.
async fn get_code(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let (status, headers, body) = harness.authorize(&authorize_query(&client_id)).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize should redirect: {body}"
    );
    assert_eq!(
        location_param(&headers, "state").as_deref(),
        Some("xyz"),
        "state is echoed"
    );
    location_param(&headers, "code").expect("code in redirect")
}

/// The standard token exchange form for a code.
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Extract the `jti` from a signed access token by verifying it.
fn access_jti(harness: &Harness, access_token: &str, audience: &str) -> String {
    let policy = harness.policy(audience);
    let verified = verify(access_token, &policy, &common::verify_clock()).expect("access verifies");
    verified
        .claims()
        .get("jti")
        .and_then(|v| v.as_str())
        .expect("jti claim")
        .to_owned()
}

#[tokio::test]
async fn full_code_flow_issues_verifiable_tokens_end_to_end() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let code = get_code(&harness).await;

    let (status, headers, body) = harness.token(&token_form(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store",
        "token response must be no-store"
    );
    let value = json(&body);
    assert_eq!(value["token_type"], "Bearer");
    assert_eq!(value["expires_in"], 300);
    let id_token = value["id_token"].as_str().expect("id_token");
    let access_token = value["access_token"].as_str().expect("access_token");

    // The ID token verifies through the ONE hardened verify path, against the
    // per-environment issuer and the client audience, and carries the bound nonce.
    let policy = harness.policy(&client_id);
    let verified = verify(id_token, &policy, &common::verify_clock()).expect("id token verifies");
    assert_eq!(verified.claims().issuer(), harness.issuer());
    assert!(harness.issuer().starts_with(ISSUER_BASE));
    assert_eq!(
        verified.claims().get("nonce").and_then(|v| v.as_str()),
        Some("n-123"),
        "bound nonce is echoed into the ID token"
    );
    assert!(
        verified.claims().subject().is_some(),
        "ID token has a subject"
    );

    // The access token verifies too, and its jti is recorded as active.
    let jti = access_jti(&harness, access_token, &client_id);
    let jti_id = IssuedTokenId::parse_in_scope(&jti, &harness.scope()).expect("jti in scope");
    assert_eq!(
        harness
            .store()
            .scoped(harness.scope())
            .authorization()
            .token_status(&jti_id)
            .await
            .expect("token status"),
        TokenStatus::Active,
    );
}

#[tokio::test]
async fn code_is_single_use_and_reuse_revokes_the_grant_chain() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let code = get_code(&harness).await;

    // First exchange succeeds and issues tokens.
    let (status, _, body) = harness.token(&token_form(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "first exchange: {body}");
    let access_token = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let jti = access_jti(&harness, &access_token, &client_id);
    let jti_id = IssuedTokenId::parse_in_scope(&jti, &harness.scope()).expect("jti in scope");
    assert_eq!(
        harness
            .store()
            .scoped(harness.scope())
            .authorization()
            .token_status(&jti_id)
            .await
            .unwrap(),
        TokenStatus::Active,
        "issued token is active before reuse"
    );

    // Reusing the same code is invalid_grant AND revokes the grant chain.
    let (status, _, body) = harness.token(&token_form(&code, &client_id)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reuse rejected: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");

    // The previously issued token is now inactive: reuse revoked the chain.
    assert_eq!(
        harness
            .store()
            .scoped(harness.scope())
            .authorization()
            .token_status(&jti_id)
            .await
            .unwrap(),
        TokenStatus::Revoked,
        "reuse revokes every token issued from the grant"
    );

    // The reuse is audited.
    let audit = harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("audit list");
    assert!(
        audit.iter().any(|r| r.action == "authorization_code.reuse"),
        "the reuse event is audited: {:?}",
        audit.iter().map(|r| &r.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn each_single_binding_mismatch_yields_invalid_grant() {
    let harness = Harness::start().await;
    let good_client = harness.client_id().to_string();

    // A second, different, real client for the wrong-client_id case.
    let other_client = harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(harness.env())),
            CorrelationId::generate(harness.env()),
        )
        .clients()
        .create(harness.env(), "other client")
        .await
        .expect("second client")
        .to_string();

    // Each case: a FRESH code, then exactly one binding wrong. All are
    // invalid_grant, and the error never says which binding failed.
    let cases: Vec<(&str, String)> = vec![
        (
            "wrong client_id",
            form(&[
                ("grant_type", "authorization_code"),
                ("code", "PLACEHOLDER"),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", &other_client),
                ("code_verifier", PKCE_VERIFIER),
            ]),
        ),
        (
            "wrong redirect_uri",
            form(&[
                ("grant_type", "authorization_code"),
                ("code", "PLACEHOLDER"),
                ("redirect_uri", "https://client.test/OTHER"),
                ("client_id", &good_client),
                ("code_verifier", PKCE_VERIFIER),
            ]),
        ),
        (
            "wrong code_verifier",
            form(&[
                ("grant_type", "authorization_code"),
                ("code", "PLACEHOLDER"),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", &good_client),
                (
                    "code_verifier",
                    "the-wrong-verifier-value-that-is-long-enough",
                ),
            ]),
        ),
        (
            "missing code_verifier",
            form(&[
                ("grant_type", "authorization_code"),
                ("code", "PLACEHOLDER"),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", &good_client),
            ]),
        ),
    ];

    for (label, template) in cases {
        let code = get_code(&harness).await;
        let body = template.replace("PLACEHOLDER", &code);
        let (status, _, response) = harness.token(&body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} must be rejected: {response}"
        );
        assert_eq!(json(&response)["error"], "invalid_grant", "{label}");
        // Uniform: the description never names the failed binding.
        let description = json(&response)["error_description"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        for leak in ["client_id", "redirect_uri", "verifier", "challenge", "pkce"] {
            assert!(
                !description.contains(leak),
                "{label}: description leaks which binding failed: {description}"
            );
        }
    }
}

#[tokio::test]
async fn expired_code_is_invalid_grant() {
    // A 60-second code, then advance the clock two minutes before redeeming.
    let config = OidcConfig {
        authorization_code_ttl_secs: 60,
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let client_id = harness.client_id().to_string();
    let code = get_code(&harness).await;

    harness.clock().advance(Duration::from_secs(120));

    let (status, _, body) = harness.token(&token_form(&code, &client_id)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "expired code: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
}

#[tokio::test]
async fn tampered_code_is_invalid_grant() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let code = get_code(&harness).await;

    // Flip one character in the middle of the code payload.
    let mut chars: Vec<char> = code.chars().collect();
    let mid = chars.len() / 2;
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert_ne!(tampered, code);

    let (status, _, body) = harness.token(&token_form(&tampered, &client_id)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "tampered code: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
}

#[tokio::test]
async fn a_code_from_another_scope_cannot_be_redeemed() {
    // Cross-environment isolation at the store boundary: a code minted in scope A
    // is not redeemable under scope B (a fresh environment of the same tenant).
    let harness = Harness::start().await;
    let code = get_code(&harness).await;
    let code_id = harness
        .store()
        .scoped(harness.scope())
        .authorization()
        .parse_code_id(&code)
        .expect("code parses in its own scope");

    // A second environment of the same tenant is a different scope.
    let scope_b: Scope = harness.second_scope().await;

    let outcome = harness
        .store()
        .scoped(scope_b)
        .acting(
            ActorRef::service(ServiceId::generate(harness.env())),
            CorrelationId::generate(harness.env()),
        )
        .authorization()
        .redeem(harness.env(), &code_id)
        .await;
    // The code declares scope A, so redeeming it under scope B is a uniform
    // not-found (defense in depth), never a Consumed or Replayed.
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "cross-scope redeem must be a uniform not-found, got {outcome:?}"
    );

    // And it is still redeemable in its own scope afterwards (untouched).
    let good = harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(harness.env())),
            CorrelationId::generate(harness.env()),
        )
        .authorization()
        .redeem(harness.env(), &code_id)
        .await
        .expect("redeem in own scope");
    assert!(matches!(good, RedeemOutcome::Consumed(_)));
}

#[tokio::test]
async fn invalid_client_id_renders_an_error_page_and_never_redirects() {
    let harness = Harness::start().await;

    // A malformed client_id: no redirect, an error page instead.
    let query = format!(
        "response_type=code&client_id=not-a-real-client&redirect_uri={}",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "an invalid client_id must NEVER redirect"
    );
    assert!(body.contains("<html"), "an error page is rendered: {body}");

    // An unknown but well-formed client_id (right shape, never created): still a
    // page, still no redirect.
    let unknown = ClientId::generate(harness.env(), &harness.scope()).to_string();
    let query = format!(
        "response_type=code&client_id={unknown}&redirect_uri={}",
        enc(REDIRECT_URI)
    );
    let (status, headers, _) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::LOCATION).is_none());
}

#[tokio::test]
async fn invalid_redirect_uri_renders_an_error_page_and_never_redirects() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // A syntactically invalid redirect_uri (not absolute http/https): a page, no
    // redirect, even though the client is valid.
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}",
        enc("/relative/path")
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "an invalid redirect_uri must NEVER redirect"
    );
    assert!(body.contains("<html"), "an error page is rendered");
}

#[tokio::test]
async fn implicit_flow_response_types_are_refused_by_redirect_without_a_token() {
    // response_type=token (the implicit flow) is unrepresentable: the endpoint
    // returns unsupported_response_type by redirect and NEVER a token or a code.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=token&client_id={client_id}&redirect_uri={}&state=s1",
        enc(REDIRECT_URI)
    );
    let (status, headers, _) = harness.authorize(&query).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "a valid client redirects the error"
    );
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("unsupported_response_type"),
    );
    assert_eq!(location_param(&headers, "state").as_deref(), Some("s1"));
    assert!(
        location_param(&headers, "code").is_none(),
        "no code is ever issued for the implicit flow"
    );
    assert!(
        location_param(&headers, "access_token").is_none(),
        "no access token is ever issued from the authorization endpoint"
    );
}

#[tokio::test]
async fn ropc_and_unknown_grant_types_are_unsupported() {
    let harness = Harness::start().await;
    let code = get_code(&harness).await;
    let client_id = harness.client_id().to_string();

    for grant in ["password", "client_credentials", "refresh_token"] {
        let body = form(&[
            ("grant_type", grant),
            ("username", "alice"),
            ("password", "hunter2"),
            ("code", &code),
            ("client_id", &client_id),
        ]);
        let (status, _, response) = harness.token(&body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{grant}: {response}");
        assert_eq!(
            json(&response)["error"],
            "unsupported_grant_type",
            "{grant} must be unsupported (ROPC has no handler)"
        );
    }
}
