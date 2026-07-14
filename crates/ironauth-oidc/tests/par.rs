// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pushed authorization requests (PAR, RFC 9126, issue #27), end to end over a real
//! database, driven through the live router.
//!
//! Covers every acceptance criterion: a pushed `request_uri` works exactly once; an
//! expired one is rejected; a `request_uri` pushed by client A and presented by
//! client B is rejected (and not burned); invalid parameters are rejected AT the PAR
//! endpoint; the per-client and the global environment require-PAR switches reject a
//! plain request; discovery advertises the endpoint and the requirement flag on both
//! well-known forms; and an external `request_uri` is refused with no outbound fetch.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, ISSUER_BASE, PKCE_CHALLENGE, REDIRECT_URI, enc, form, json, location_param};
use ironauth_config::OidcConfig;
use ironauth_oidc::ClientAuthMethod;

/// The PAR request-uri urn prefix the endpoint returns and `/authorize` accepts.
const PAR_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// A valid pushed-request form for a PUBLIC client (PKCE mandatory), everything the
/// authorization endpoint needs to later issue a code.
fn valid_public_par_form(client_id: &str) -> String {
    form(&[
        ("client_id", client_id),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid"),
        ("state", "xyz"),
        ("nonce", "n-123"),
        ("code_challenge", PKCE_CHALLENGE),
        ("code_challenge_method", "S256"),
    ])
}

/// Push a request and return its `request_uri`, asserting the 201 Created shape.
async fn push_request_uri(harness: &Harness, form: &str, auth: Option<&str>) -> String {
    let (status, _, body) = harness.par(form, auth).await;
    assert_eq!(status, StatusCode::CREATED, "par push: {body}");
    let doc = json(&body);
    let request_uri = doc["request_uri"]
        .as_str()
        .expect("request_uri present")
        .to_owned();
    assert!(
        request_uri.starts_with(PAR_PREFIX),
        "request_uri is the PAR urn form: {request_uri}"
    );
    assert!(
        doc["expires_in"].as_u64().expect("expires_in present") > 0,
        "expires_in is a positive TTL"
    );
    request_uri
}

/// The `/authorize?...` query that presents a `request_uri` for `client_id`.
fn authorize_via_par(client_id: &str, request_uri: &str) -> String {
    format!("client_id={client_id}&request_uri={}", enc(request_uri))
}

#[tokio::test]
async fn a_pushed_request_uri_works_exactly_once() {
    // Acceptance criterion 1.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;

    // First use: an authenticated, consenting subject redeems it into a code, and the
    // pushed `state` is echoed (so the pushed request really drove the response).
    let cookie = harness.authenticated_cookie().await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_id, &request_uri), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND, "authorize via PAR: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued for the pushed request"
    );
    assert_eq!(
        location_param(&headers, "state").as_deref(),
        Some("xyz"),
        "the pushed state is echoed"
    );

    // Second use of the SAME request_uri is rejected (single use), even for another
    // authenticated subject.
    let cookie2 = harness.authenticated_cookie().await;
    let (status, _, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_id, &request_uri), &cookie2)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a reused request_uri is rejected: {body}"
    );
}

#[tokio::test]
async fn an_expired_request_uri_is_rejected() {
    // Acceptance criterion 2: TTL is configurable and bounded; here the default
    // (60s) is used and the clock is advanced past it.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;

    // Advance past the request_uri lifetime; the session cookie is far-future, so it
    // survives.
    harness.clock().advance(Duration::from_secs(61));

    let cookie = harness.authenticated_cookie().await;
    let (status, _, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_id, &request_uri), &cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an expired request_uri is rejected: {body}"
    );
}

#[tokio::test]
async fn a_configured_par_ttl_is_reflected_in_expires_in() {
    // Acceptance criterion 2 (configurable, bounded): a non-default, in-range TTL is
    // honored and surfaced in the response.
    let harness = Harness::start_with(OidcConfig {
        par_ttl_secs: 120,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let client_id = harness.client_id().to_string();
    let (status, _, body) = harness.par(&valid_public_par_form(&client_id), None).await;
    assert_eq!(status, StatusCode::CREATED, "par push: {body}");
    assert_eq!(
        json(&body)["expires_in"].as_u64(),
        Some(120),
        "expires_in reflects the configured par_ttl_secs"
    );
}

#[tokio::test]
async fn a_request_uri_from_client_a_is_rejected_for_client_b_and_not_burned() {
    // Acceptance criterion 3.
    let harness = Harness::start().await;
    let client_a = harness.client_id().to_string();
    let client_b = harness
        .create_public_client_with_redirects("client B", &[REDIRECT_URI])
        .await
        .to_string();

    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_a), None).await;

    // Client B presenting client A's request_uri is rejected.
    let cookie_b = harness.authenticated_cookie_for(&client_b).await;
    let (status, _, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_b, &request_uri), &cookie_b)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a request_uri presented by a different client is rejected: {body}"
    );

    // And it was NOT burned: client A can still use it.
    let cookie_a = harness.authenticated_cookie().await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_a, &request_uri), &cookie_a)
        .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the bound client can still use the un-burned request_uri: {body}"
    );
    assert!(location_param(&headers, "code").is_some());
}

#[tokio::test]
async fn an_invalid_redirect_uri_is_rejected_at_the_par_endpoint() {
    // Acceptance criterion 4: a bad redirect_uri is rejected at PUSH time, on the back
    // channel, not later at /authorize.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let bad = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        // A well-formed but UNREGISTERED redirect target.
        ("redirect_uri", "https://evil.test/cb"),
        ("scope", "openid"),
        ("code_challenge", PKCE_CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let (status, _, body) = harness.par(&bad, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "par rejects: {body}");
    assert_eq!(
        json(&body)["error"].as_str(),
        Some("invalid_request"),
        "an unregistered redirect_uri is invalid_request at PAR: {body}"
    );
}

#[tokio::test]
async fn a_missing_pkce_challenge_is_rejected_at_the_par_endpoint() {
    // Acceptance criterion 4: PKCE is mandatory for a public client, and the omission
    // is caught at PUSH time.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let no_pkce = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid"),
    ]);
    let (status, _, body) = harness.par(&no_pkce, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "par rejects: {body}");
    assert_eq!(
        json(&body)["error"].as_str(),
        Some("invalid_request"),
        "a missing PKCE challenge is invalid_request at PAR: {body}"
    );
}

#[tokio::test]
async fn a_pushed_request_may_not_itself_carry_a_request_uri() {
    // RFC 9126 section 2.1: a pushed request must not reference another one.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let mut body = valid_public_par_form(&client_id);
    body.push_str("&request_uri=");
    body.push_str(&enc("urn:ietf:params:oauth:request_uri:par_whatever"));
    let (status, _, response) = harness.par(&body, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "par rejects: {response}");
    assert_eq!(
        json(&response)["error"].as_str(),
        Some("invalid_request"),
        "a request_uri in a pushed request is invalid_request: {response}"
    );
}

#[tokio::test]
async fn require_par_per_client_rejects_a_plain_request_but_allows_a_pushed_one() {
    // Acceptance criterion 5 (per client).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    harness.require_par_for_client(harness.client_id()).await;

    // A plain (non-PAR) authorization request is now rejected.
    let cookie = harness.authenticated_cookie().await;
    let plain = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI)
    );
    let (status, _, body) = harness.authorize_with_cookie(&plain, &cookie).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a plain request from a require-PAR client is rejected: {body}"
    );

    // A pushed request still works for the same client.
    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;
    let cookie2 = harness.authenticated_cookie().await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_id, &request_uri), &cookie2)
        .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the pushed request is honored: {body}"
    );
    assert!(location_param(&headers, "code").is_some());
}

#[tokio::test]
async fn the_global_require_par_switch_rejects_a_plain_request() {
    // Acceptance criterion 5 (global environment switch): behaves the same as the
    // per-client flag, for every client in the environment.
    let harness = Harness::start_with(OidcConfig {
        require_pushed_authorization_requests: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let client_id = harness.client_id().to_string();

    // A plain request is rejected under the environment-wide switch.
    let cookie = harness.authenticated_cookie().await;
    let plain = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI)
    );
    let (status, _, body) = harness.authorize_with_cookie(&plain, &cookie).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a plain request under the global require switch is rejected: {body}"
    );

    // A pushed request works.
    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;
    let cookie2 = harness.authenticated_cookie().await;
    let (status, _, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_id, &request_uri), &cookie2)
        .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the pushed request is honored: {body}"
    );
}

#[tokio::test]
async fn the_par_endpoint_enforces_client_authentication() {
    // The PAR endpoint is an authenticated back-channel endpoint (RFC 9126 section
    // 2): a confidential client's wrong secret is the opaque invalid_client, its right
    // secret authenticates. This proves the same client-auth suite as the token
    // endpoint gates PAR.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    // A confidential client (PKCE relaxed in the default harness) pushes without PKCE.
    let push_form = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid"),
        ("state", "s"),
        ("nonce", "n"),
    ]);

    let good = format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")));
    let (status, _, body) = harness.par(&push_form, Some(&good)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a correctly authenticated push succeeds: {body}"
    );

    let bad = format!("Basic {}", STANDARD.encode(format!("{client_id}:wrong")));
    let (status, _, body) = harness.par(&push_form, Some(&bad)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a wrong secret is invalid_client: {body}"
    );
    assert_eq!(json(&body)["error"].as_str(), Some("invalid_client"));
}

#[tokio::test]
async fn an_external_request_uri_is_refused_without_any_outbound_fetch() {
    // The REFUSED non-goal: a code path must NEVER dereference an external
    // request_uri. The default harness wires NO outbound fetcher, and neither the PAR
    // endpoint nor the authorization endpoint calls ironauth-fetch for a request_uri
    // (structurally enforced by scripts/http-audit.sh); an http/https request_uri is
    // a uniform invalid_request with zero network activity.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    for external in [
        "https://evil.test/request.jwt",
        "http://169.254.169.254/latest/meta-data",
        "urn:example:not-par",
    ] {
        let query = format!("client_id={client_id}&request_uri={}", enc(external));
        let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an external request_uri ({external}) is refused: {body}"
        );
        assert!(
            location_param(&headers, "code").is_none(),
            "no code is issued for an external request_uri"
        );
    }
}

#[tokio::test]
async fn discovery_advertises_the_par_endpoint_and_the_require_flag_on_both_wellknown_forms() {
    // Acceptance criterion 6: the endpoint and the requirement flag are advertised,
    // generated from live config, on both well-known forms.
    let harness = Harness::start_store_backed_with(OidcConfig {
        require_pushed_authorization_requests: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let scope = harness.scope();
    let appended = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    let inserted = format!(
        "/.well-known/oauth-authorization-server/t/{}/e/{}",
        scope.tenant(),
        scope.environment()
    );

    for path in [appended, inserted] {
        let (status, _, body) = harness.get_with_cookie(&path, None).await;
        assert_eq!(status, StatusCode::OK, "discovery at {path}: {body}");
        let doc = json(&body);
        assert_eq!(
            doc["pushed_authorization_request_endpoint"].as_str(),
            Some(format!("{ISSUER_BASE}/par").as_str()),
            "PAR endpoint advertised at {path}"
        );
        assert_eq!(
            doc["require_pushed_authorization_requests"].as_bool(),
            Some(true),
            "require_pushed_authorization_requests advertised true at {path}"
        );
        // The JAR by-reference request_uri parameter stays UNsupported (that is
        // RFC 9101, out of scope): PAR does not flip it.
        assert_eq!(
            doc["request_uri_parameter_supported"].as_bool(),
            Some(false),
            "the JAR request_uri parameter stays unsupported at {path}"
        );
    }
}
