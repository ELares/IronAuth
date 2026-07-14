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

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{
    Harness, ISSUER_BASE, PKCE_CHALLENGE, REDIRECT_URI, SEED_PASSWORD, enc, form, form_field, json,
    location, location_param, send_through, set_cookie_pair,
};
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

// ===========================================================================
// Require-PAR through the full login/consent interaction (RFC 9126, issue #27).
//
// The regression these lock: a require-PAR client's request_uri is PEEKED (not
// consumed) at every authorization hop, so a fresh-login user resumes through login
// AND consent to a REAL code instead of a 400. The pre-existing require-PAR tests use
// an already-authenticated, already-consenting cookie and jump straight to issuance,
// so they never exercise this interaction->resume path (the broken path).
// ===========================================================================

/// Drive a PAR authorization request that requires interaction all the way through
/// login AND consent, returning the FINAL authorize response (the code redirect).
///
/// It mirrors the interactive-flow tests: walk each redirect and round-trip the hidden
/// `return_to` field through the login and consent forms. Along the way it asserts the
/// two properties the fix rests on: the resume target re-presents the `request_uri`
/// (the minimal PAR presentation, NOT the expanded params), and the RESUMED request is
/// not rejected by the require-PAR gate (it routes to consent, not a 400).
async fn drive_par_login_consent(
    harness: &Harness,
    client_id: &str,
    request_uri: &str,
    identifier: &str,
    password: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    // 1. Present client_id + request_uri with NO session -> login redirect.
    let (status, headers, body) = harness
        .authorize(&authorize_via_par(client_id, request_uri))
        .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "PAR authorize redirects to login: {body}"
    );
    let login_location = location(&headers).expect("login redirect");
    assert!(
        login_location.starts_with("/login?return_to="),
        "an unauthenticated PAR request routes to login: {login_location}"
    );
    let return_to = location_param(&headers, "return_to").expect("login return_to");
    assert!(
        return_to.contains("request_uri="),
        "the resume re-presents the request_uri (not the expanded params): {return_to}"
    );

    // 2. GET the login page, round-trip its return_to, POST the credentials.
    let (_s, _h, login_html) = harness.get_with_cookie(&login_location, None).await;
    let form_return_to = form_field(&login_html, "return_to").expect("login return_to field");
    let login_body = form(&[
        ("identifier", identifier),
        ("password", password),
        ("return_to", &form_return_to),
    ]);
    let (status, headers, body) = harness.post_form("/login", &login_body, None).await;
    assert_eq!(status, StatusCode::FOUND, "login post: {body}");
    let cookie = set_cookie_pair(&headers).expect("session cookie set on login");
    let resume = location(&headers).expect("resume after login");

    // 3. Resume (authenticated) -> consent required, NOT a 400. This is the exact hop
    //    that regressed: the require-PAR gate must accept the resumed PAR request.
    let (status, headers, body) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the resumed PAR request must not be rejected by the require-PAR gate: {body}"
    );
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with("/consent?return_to="),
        "the resumed request routes to consent: {consent_location}"
    );

    // 4. Consent allow, then the final resume issues the code.
    let (_s, _h, consent_html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    let consent_return_to = form_field(&consent_html, "return_to").expect("consent return_to");
    let consent_body = form(&[("decision", "allow"), ("return_to", &consent_return_to)]);
    let (status, headers, body) = harness
        .post_form("/consent", &consent_body, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::FOUND, "consent post: {body}");
    let resume = location(&headers).expect("resume after consent");
    harness.get_with_cookie(&resume, Some(&cookie)).await
}

#[tokio::test]
async fn require_par_per_client_resumes_through_login_and_consent_to_a_code() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    harness.require_par_for_client(harness.client_id()).await;
    harness
        .seed_user("par-e2e@example.test", SEED_PASSWORD)
        .await;

    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;
    let (status, headers, body) = drive_par_login_consent(
        &harness,
        &client_id,
        &request_uri,
        "par-e2e@example.test",
        SEED_PASSWORD,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "the final resume issues: {body}");
    assert!(
        location(&headers).is_some_and(|l| l.starts_with(REDIRECT_URI)),
        "the code is delivered to the redirect_uri"
    );
    assert!(
        location_param(&headers, "code").is_some(),
        "a real authorization code is issued through the interaction, not a 400"
    );
    assert_eq!(
        location_param(&headers, "state").as_deref(),
        Some("xyz"),
        "the pushed state is echoed"
    );
}

#[tokio::test]
async fn the_global_require_par_switch_resumes_through_login_and_consent_to_a_code() {
    let harness = Harness::start_with(OidcConfig {
        require_pushed_authorization_requests: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let client_id = harness.client_id().to_string();
    harness
        .seed_user("par-e2e-global@example.test", SEED_PASSWORD)
        .await;

    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;
    let (status, headers, body) = drive_par_login_consent(
        &harness,
        &client_id,
        &request_uri,
        "par-e2e-global@example.test",
        SEED_PASSWORD,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "the final resume issues: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a real authorization code is issued through the interaction under the global switch, not a 400"
    );
}

#[tokio::test]
async fn require_par_still_rejects_a_plain_and_a_forged_request() {
    // The fix must NOT weaken the gate: with require-PAR set, a PLAIN request (no
    // request_uri) is still rejected, and a FORGED/unknown request_uri is rejected too
    // (it resolves to nothing, so it is never a bypass and issues no code).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    harness.require_par_for_client(harness.client_id()).await;
    let cookie = harness.authenticated_cookie().await;

    let plain = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = harness.authorize_with_cookie(&plain, &cookie).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a plain request from a require-PAR client is still rejected: {body}"
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "no code for a plain request"
    );

    // A well-formed PAR urn with no backing storage row is a forged reference.
    let forged = format!("{PAR_PREFIX}par_forgedforgedforgedforgedforged");
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_via_par(&client_id, &forged), &cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a forged request_uri is rejected (no bypass): {body}"
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "no code is issued for a forged request_uri"
    );
}

#[tokio::test]
async fn an_invalid_response_mode_is_rejected_at_the_par_endpoint() {
    // Acceptance criterion 4 (push-time parity beyond redirect_uri/PKCE): an
    // unsupported response_mode is caught at PUSH time on the back channel as a JSON
    // invalid_request, not later at /authorize.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let bad = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("response_mode", "bogus"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid"),
        ("code_challenge", PKCE_CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let (status, _, body) = harness.par(&bad, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "par rejects: {body}");
    assert_eq!(
        json(&body)["error"].as_str(),
        Some("invalid_request"),
        "an unsupported response_mode is invalid_request at PAR: {body}"
    );
}

#[tokio::test]
async fn pushed_values_win_over_conflicting_inline_params_at_authorize() {
    // RFC 9126 section 4: when a request_uri is presented, the STORED pushed values are
    // authoritative and any conflicting inline query parameters are IGNORED.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    // The pushed request binds redirect_uri=REDIRECT_URI, scope=openid, state=xyz.
    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;

    // Present the request_uri alongside CONFLICTING inline redirect_uri/scope/state.
    let cookie = harness.authenticated_cookie().await;
    let conflicting = format!(
        "client_id={client_id}&request_uri={}&redirect_uri={}&scope={}&state=forged",
        enc(&request_uri),
        enc("https://evil.test/cb"),
        enc("openid profile email address"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&conflicting, &cookie).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize via PAR issues: {body}"
    );
    let loc = location(&headers).expect("code redirect");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "the code is delivered to the STORED redirect_uri, not the inline one: {loc}"
    );
    assert!(
        !loc.contains("evil.test"),
        "the inline redirect_uri is ignored: {loc}"
    );
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued for the pushed request"
    );
    assert_eq!(
        location_param(&headers, "state").as_deref(),
        Some("xyz"),
        "the STORED state wins over the conflicting inline state"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_issuances_of_one_request_uri_yield_at_most_one_code() {
    // The consume moved to issuance (RFC 9126, issue #27), so N concurrent issuances
    // driven by the SAME request_uri race on the atomic consume-at-issuance: exactly
    // one produces a code and the rest are rejected (single use holds end to end).
    const RACERS: usize = 6;

    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let request_uri = push_request_uri(&harness, &valid_public_par_form(&client_id), None).await;

    // Pre-seed an authenticated, consenting session per racer (distinct users), so the
    // race is purely on the issuance-time consume, not on login/consent.
    let mut cookies = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        cookies.push(harness.authenticated_cookie().await);
    }

    let query = authorize_via_par(&client_id, &request_uri);
    let mut tasks = Vec::with_capacity(RACERS);
    for cookie in cookies {
        let router = harness.router();
        let query = query.clone();
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method("GET")
                .uri(format!("/authorize?{query}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request builds");
            send_through(router, request).await
        }));
    }

    let mut codes = 0_usize;
    let mut rejected = 0_usize;
    for task in tasks {
        let (status, headers, _body) = task.await.expect("task joins");
        if status == StatusCode::FOUND && location_param(&headers, "code").is_some() {
            codes += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!(
        codes, 1,
        "exactly one concurrent issuance of a request_uri produces a code"
    );
    assert_eq!(
        rejected,
        RACERS - 1,
        "every other concurrent issuance is rejected (single use)"
    );
}
