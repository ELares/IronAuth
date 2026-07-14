// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9700 (OAuth 2.0 Security Best Current Practice) as executable CI
//! conformance invariants (issue #38).
//!
//! Each BCP item the shipped M2/M3 surface implements is encoded here as a named
//! test that drives the LIVE authorization, token, discovery, and interaction
//! endpoints over a real database and asserts the security property, so a future
//! refactor cannot silently reopen a closed CVE class. The full mapping from each
//! RFC 9700 requirement to the test(s) that cover it lives in
//! `docs/conformance/rfc9700-checklist.md`, and the design rationale (including the
//! 302-vs-303 and Referrer-Policy decisions and the non-vacuity argument) in
//! `docs/design/rfc9700-conformance.md`.
//!
//! # Non-vacuity: the shared-predicate mutation harness
//!
//! A conformance test that can pass but never fail is worthless. Every header- or
//! shape-based item reduces its assertion to a PURE PREDICATE in the [`checks`]
//! module: the conformance test extracts the security-relevant facts from the LIVE
//! response and asserts `checks::<item>(facts).is_ok()`. The [`mutation`] module
//! then feeds each SAME predicate the exact shape a flipped guard would produce (a
//! `307` where a `303` is required, a stripped `iss`, an injected
//! `Access-Control-Allow-Origin`, a success where a reuse must fail) and asserts it
//! returns `Err`. Because the conformance test relies on that predicate, proving the
//! predicate rejects the regression shape proves the conformance test would go RED
//! if the live guard flipped. Both the conformance tests and the mutation tests run
//! in this ONE integration-test binary on every PR (the workspace `test` lane), so
//! CI continuously enforces both directions: a guard that regresses fails the
//! conformance test, and a predicate that goes vacuous fails its mutation test.
//!
//! The mutation harness constructs its violating inputs entirely in memory in this
//! test binary. It introduces NO seeded-violation code path into the library or the
//! server: `tests/*.rs` is never compiled into the shipped or the musl release
//! binary (the musl lane builds `cargo build --release -p ironauth`, which links the
//! library and the binary, never the test crates), so the harness is provably absent
//! from every artifact.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, form_field, json, location,
    location_param,
};
use ironauth_config::OidcConfig;
use ironauth_oidc::ClientAuthMethod;
use serde_json::Value;

// ===========================================================================
// checks: the pure predicates the conformance tests and the mutation harness
// share. Each returns Ok(()) when the RFC 9700 property holds and Err(reason)
// when it is violated, so both the live response and a synthetic regression
// shape can be scored by the identical logic.
// ===========================================================================

mod checks {
    use axum::http::{HeaderMap, StatusCode};

    /// The lowercase value of `name`, if present and valid UTF-8.
    fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// The `Location` header value, if any.
    fn location(headers: &HeaderMap) -> Option<String> {
        header_value(headers, "location")
    }

    /// Whether a redirect `Location` carries `name=` in EITHER its query or its
    /// fragment (the two front-channel encodings), returning the percent-decoded
    /// value (so an encoded `iss` compares equal to the plain issuer string).
    fn location_param(headers: &HeaderMap, name: &str) -> Option<String> {
        let location = location(headers)?;
        let after = location.split_once('?').map_or("", |(_, q)| q);
        let fragment = location.split_once('#').map_or("", |(_, f)| f);
        for section in [after, fragment] {
            for pair in section.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    if key == name {
                        return Some(crate::common::percent_decode(value));
                    }
                }
            }
        }
        None
    }

    /// R12: the authorization endpoint MUST NOT emit `Access-Control-Allow-Origin`.
    /// CORS on `/authorize` would let a hostile origin read a browser's
    /// authorization response cross-origin (RFC 9700). Only `/userinfo` is a CORS
    /// resource, and only for exactly-registered origins.
    pub fn no_cors_on_authorize(headers: &HeaderMap) -> Result<(), String> {
        match header_value(headers, "access-control-allow-origin") {
            Some(value) => Err(format!(
                "/authorize returned Access-Control-Allow-Origin: {value}"
            )),
            None => Ok(()),
        }
    }

    /// R7: RFC 9207 requires the `iss` identifier on EVERY authorization response
    /// (success and error, in whatever response mode). A missing or wrong `iss`
    /// reopens the mix-up class.
    pub fn authorization_response_iss(headers: &HeaderMap, expected: &str) -> Result<(), String> {
        match location_param(headers, "iss") {
            Some(iss) if iss == expected => Ok(()),
            Some(iss) => Err(format!("iss mismatch: got {iss}, expected {expected}")),
            None => Err("authorization response carries no iss (RFC 9207)".to_owned()),
        }
    }

    /// R10: a credential-bearing redirect MUST be `303 See Other`, never the legacy
    /// `302` (browser-dependent method conversion) and never a body-preserving
    /// `307`/`308` (which would replay a request-body credential to the target).
    pub fn credential_bearing_redirect_status(status: StatusCode) -> Result<(), String> {
        if status == StatusCode::SEE_OTHER {
            Ok(())
        } else {
            Err(format!(
                "credential-bearing redirect status is {status}, must be 303 See Other"
            ))
        }
    }

    /// R11: every code-carrying response MUST set `Referrer-Policy: no-referrer`, so
    /// the authorization code (in the `Location` query for the `query` mode) is not
    /// leaked onward through the `Referer` header.
    pub fn referrer_policy_no_referrer(headers: &HeaderMap) -> Result<(), String> {
        match header_value(headers, "referrer-policy") {
            Some(ref value) if value == "no-referrer" => Ok(()),
            Some(value) => Err(format!("Referrer-Policy is {value}, must be no-referrer")),
            None => Err("code-carrying response has no Referrer-Policy".to_owned()),
        }
    }

    /// R9: a code-carrying or token response MUST set `Cache-Control: no-store`, so a
    /// code or token never lands in a shared cache.
    pub fn cache_control_no_store(headers: &HeaderMap) -> Result<(), String> {
        match header_value(headers, "cache-control") {
            Some(ref value) if value.contains("no-store") => Ok(()),
            other => Err(format!("Cache-Control is {other:?}, must contain no-store")),
        }
    }

    /// R6: the authorization endpoint MUST NOT put an access token in the front
    /// channel. No `access_token` or `token_type` may appear in the redirect query
    /// or fragment (the implicit access-token flow is structurally excluded).
    pub fn no_front_channel_access_token(headers: &HeaderMap) -> Result<(), String> {
        for forbidden in ["access_token", "token_type"] {
            if location_param(headers, forbidden).is_some() {
                return Err(format!(
                    "authorization response carries a front-channel {forbidden}"
                ));
            }
        }
        Ok(())
    }

    /// R9: the token endpoint MUST deliver tokens in the response body, never in a
    /// URL. A token response that carried a `Location` header would be placing a
    /// token (or a redirect target) in a URL, which RFC 9700 forbids for tokens.
    pub fn token_never_in_url(headers: &HeaderMap) -> Result<(), String> {
        match location(headers) {
            Some(value) => Err(format!(
                "token response set a Location (token in a URL?): {value}"
            )),
            None => Ok(()),
        }
    }

    /// R1/R3: an unvalidated or unregistered `redirect_uri` MUST be refused by an
    /// error PAGE, never by a redirect (a redirect to an attacker-chosen URI is the
    /// open-redirector / code-leak class). The property: status is a client error
    /// and NO `Location` is set.
    pub fn refused_by_error_page(status: StatusCode, headers: &HeaderMap) -> Result<(), String> {
        if location(headers).is_some() {
            return Err(
                "an unvalidated redirect_uri produced a redirect (open redirector)".to_owned(),
            );
        }
        if status.is_redirection() || status.is_success() {
            return Err(format!("expected a client-error page, got {status}"));
        }
        Ok(())
    }

    /// R13/R14: an outcome that MUST be a `400 invalid_grant`. Used for reuse,
    /// binding-mismatch, and downgrade rejections.
    pub fn is_invalid_grant(status: StatusCode, body: &str) -> Result<(), String> {
        if status != StatusCode::BAD_REQUEST {
            return Err(format!("expected 400, got {status}: {body}"));
        }
        let value: serde_json::Value =
            serde_json::from_str(body).map_err(|error| format!("body is not JSON: {error}"))?;
        if value.get("error").and_then(serde_json::Value::as_str) == Some("invalid_grant") {
            Ok(())
        } else {
            Err(format!("expected error=invalid_grant, got {body}"))
        }
    }

    /// R14: sender-uniform errors. A set of distinct failing redemptions MUST all
    /// render BYTE-IDENTICALLY, so the endpoint is never an oracle for WHICH check
    /// failed. Fewer than two samples cannot demonstrate uniformity.
    pub fn bodies_are_uniform(bodies: &[String]) -> Result<(), String> {
        if bodies.len() < 2 {
            return Err("need at least two error samples to prove uniformity".to_owned());
        }
        match bodies.iter().find(|body| **body != bodies[0]) {
            Some(divergent) => Err(format!(
                "token errors are not uniform: {:?} != {:?}",
                bodies[0], divergent
            )),
            None => Ok(()),
        }
    }

    /// R4: discovery MUST advertise S256 as the ONLY PKCE method (`plain` is
    /// structurally excluded, RFC 7636 / RFC 9700 2.1.1).
    pub fn pkce_methods_s256_only(doc: &serde_json::Value) -> Result<(), String> {
        let methods = doc
            .get("code_challenge_methods_supported")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "discovery has no code_challenge_methods_supported array".to_owned())?;
        let values: Vec<&str> = methods
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        if values == ["S256"] {
            Ok(())
        } else {
            Err(format!(
                "code_challenge_methods_supported is {values:?}, must be exactly [\"S256\"]"
            ))
        }
    }

    /// R9: an access token MUST be audience-restricted (RFC 9068 / RFC 8707). The
    /// `aud` claim must be present and non-empty and, when an expected audience is
    /// known, equal to it.
    pub fn audience_restricted(claims: &serde_json::Value, expected: &str) -> Result<(), String> {
        match claims.get("aud") {
            Some(serde_json::Value::String(aud)) if aud == expected => Ok(()),
            Some(serde_json::Value::String(aud)) => {
                Err(format!("aud is {aud}, expected {expected}"))
            }
            Some(serde_json::Value::Array(items)) if items.iter().any(|v| v == expected) => Ok(()),
            Some(other) => Err(format!("aud does not include {expected}: {other}")),
            None => Err("access token carries no aud (unrestricted audience)".to_owned()),
        }
    }

    /// R2: the RFC 8252 loopback / private-use redirect exception MUST stay scoped:
    /// the exact comparator may vary ONLY the port of an `http` loopback IP literal,
    /// never the host, path, or scheme. `must_match` is the expected verdict of the
    /// exact comparator for `(registered, presented)`; a disagreement is a broadening
    /// of the exception into an open redirect.
    pub fn loopback_exception_scoped(
        registered: &str,
        presented: &str,
        must_match: bool,
    ) -> Result<(), String> {
        let matched = ironauth_store::redirect_uri_matches(registered, presented);
        if matched == must_match {
            Ok(())
        } else {
            Err(format!(
                "redirect_uri_matches({registered:?}, {presented:?}) = {matched}, expected {must_match}"
            ))
        }
    }
}

// ===========================================================================
// Shared helpers for the live conformance tests.
// ===========================================================================

/// A config that enables the `form_post` response mode (for the code-carrying
/// `form_post` half of R11) while keeping the relaxed confidential-PKCE default.
fn form_post_config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        enable_response_mode_form_post: true,
        ..OidcConfig::default()
    }
}

/// Decode a JWT's claims segment WITHOUT verifying the signature (the signature is
/// verified end to end elsewhere; here only the `aud` claim shape is under test).
fn decode_jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("jwt has a claims segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("claims are base64url");
    serde_json::from_slice(&bytes).expect("claims are JSON")
}

/// Build a well-formed public-client `code` + S256 authorization query, with any
/// `extra` (already-encoded) parameters appended.
fn authorize_code_query(client_id: &str, extra: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256{extra}",
        enc(REDIRECT_URI),
    )
}

// ===========================================================================
// R1 / R3: exact redirect matching and no open redirector.
// ===========================================================================

#[tokio::test]
async fn rfc9700_exact_redirect_uri_unregistered_is_error_page() {
    // A perfectly registrable https URL the client did NOT register must be refused
    // by a PAGE, never a redirect, so it can never become an open redirector that
    // leaks the code (RFC 9700 2.1 / RFC 6749 4.1.2.1).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc("https://client.test/unregistered"),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    checks::refused_by_error_page(status, &headers)
        .unwrap_or_else(|reason| panic!("{reason}: {body}"));
    assert!(body.contains("<html"), "an error page is rendered: {body}");
}

#[tokio::test]
async fn rfc9700_exact_redirect_uri_comparator_rejects_cve_corpus() {
    // The exact-string comparator the endpoints call is the whole redirect policy.
    // A corpus of classic bypass techniques against a registered value must ALL be
    // rejected (zero accepted bypasses); the loopback port variance is the only
    // deviation and is covered separately.
    let registered = "https://client.example/cb";
    let bypasses = [
        "https://client.example/cb/*",
        "https://client.example/cb/extra",
        "https://client.example/cb/",
        "https://client.example/cb?x=1",
        "https://CLIENT.example/cb",
        "https://client.example@evil.example/cb",
        "https://client.example:443/cb",
        "https://client.example.evil.example/cb",
        "https://client.example//cb",
        "https://client.example/%2e%2e/cb",
        "http://client.example/cb",
    ];
    for presented in bypasses {
        checks::loopback_exception_scoped(registered, presented, false).unwrap_or_else(|reason| {
            panic!("redirect bypass accepted: {reason}");
        });
    }
    // The identical string still matches (the comparator is not vacuously false).
    checks::loopback_exception_scoped(registered, registered, true).expect("identical matches");
}

#[tokio::test]
async fn rfc9700_interaction_return_to_open_redirect_is_refused() {
    // The interaction pages carry an untrusted `return_to`. A non-local target (a
    // scheme-relative `//evil` or an absolute URL) must NEVER turn the interaction
    // page into an open redirector: it renders the invalid-link page, never a
    // redirect to the attacker host.
    let harness = Harness::start().await;
    for hostile in ["//evil.test/phish", "https://evil.test/phish"] {
        let path = format!("/login?return_to={}", enc(hostile));
        let (status, headers, body) = harness.get_with_cookie(&path, None).await;
        checks::refused_by_error_page(status, &headers)
            .unwrap_or_else(|reason| panic!("return_to {hostile}: {reason}: {body}"));
    }
}

// ===========================================================================
// R2: the loopback / native redirect exception stays exact.
// ===========================================================================

#[tokio::test]
async fn rfc9700_loopback_exception_varies_only_the_port() {
    // Live: a registered loopback redirect with no fixed port matches a presented
    // variant that differs ONLY in the port; a different PATH is refused by a page.
    let harness = Harness::start().await;
    let client = harness
        .create_public_client_with_redirects("native loopback", &["http://127.0.0.1/cb"])
        .await;
    let client_id = client.to_string();
    let cookie = harness.authenticated_cookie_for(&client_id).await;

    let ok_query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc("http://127.0.0.1:53127/cb"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&ok_query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "variable port accepted: {body}"
    );
    assert!(
        location(&headers).is_some_and(|l| l.starts_with("http://127.0.0.1:53127/cb")),
        "the code is delivered to the presented loopback URI"
    );

    let bad_path = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc("http://127.0.0.1:53127/other"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&bad_path, &cookie).await;
    checks::refused_by_error_page(status, &headers)
        .unwrap_or_else(|reason| panic!("loopback path swap: {reason}: {body}"));
}

#[tokio::test]
async fn rfc9700_native_redirect_exception_stays_exact() {
    // The exact comparator: a loopback port variant matches, but a host swap, a path
    // swap, a v4-vs-v6 swap, and a private-use-scheme path swap must NOT, so the RFC
    // 8252 exception can never broaden into an open redirect or SSRF.
    checks::loopback_exception_scoped("http://127.0.0.1/cb", "http://127.0.0.1:9000/cb", true)
        .expect("port variant matches");
    let seeded_violations = [
        ("http://127.0.0.1/cb", "http://127.0.0.2:9000/cb"),
        ("http://127.0.0.1/cb", "http://127.0.0.1:9000/other"),
        ("http://127.0.0.1/cb", "http://[::1]:9000/cb"),
        (
            "http://127.0.0.1/cb",
            "http://127.0.0.1.evil.example:9000/cb",
        ),
        ("com.example.app:/cb", "com.example.app:/evil"),
    ];
    for (registered, presented) in seeded_violations {
        checks::loopback_exception_scoped(registered, presented, false)
            .unwrap_or_else(|reason| panic!("native redirect exception broadened: {reason}"));
    }
}

// ===========================================================================
// R4: PKCE S256 published; R5: PKCE mandatory and downgrade-proof both ways.
// ===========================================================================

#[tokio::test]
async fn rfc9700_discovery_advertises_s256_only_pkce() {
    // The live discovery document (generated at serve time) advertises S256 as the
    // only PKCE method.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    let (status, _headers, body) = harness.get_with_cookie(&path, None).await;
    assert_eq!(status, StatusCode::OK, "discovery resolves: {body}");
    let doc = json(&body);
    checks::pkce_methods_s256_only(&doc).unwrap_or_else(|reason| panic!("{reason}"));
}

#[tokio::test]
async fn rfc9700_pkce_challenge_bound_code_needs_the_verifier() {
    // Forward downgrade: a code bound to an S256 challenge is NOT redeemable without
    // the matching verifier (a wrong verifier is invalid_grant).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let wrong = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        (
            "code_verifier",
            "the-wrong-verifier-value-not-appendix-b-000000",
        ),
    ]);
    let (status, _headers, body) = harness.token(&wrong).await;
    checks::is_invalid_grant(status, &body).unwrap_or_else(|reason| panic!("{reason}"));
}

#[tokio::test]
async fn rfc9700_pkce_no_challenge_code_rejects_a_verifier() {
    // Reverse downgrade (the Zitadel-class CVE): a code issued WITHOUT a challenge is
    // never redeemable WITH a verifier.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();
    let code = harness.issue_authenticated_code(&client_id).await;
    let with_verifier = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", &secret),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, body) = harness.token(&with_verifier).await;
    checks::is_invalid_grant(status, &body).unwrap_or_else(|reason| panic!("{reason}"));
}

#[tokio::test]
async fn rfc9700_pkce_plain_method_is_invalid_request() {
    // `plain` is structurally absent: a request naming it is invalid_request, and the
    // error redirect still carries iss and issues no code.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=s&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=plain",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "plain is invalid_request"
    );
    assert!(location_param(&headers, "code").is_none(), "no code issued");
}

// ===========================================================================
// R6: no access token in the front channel.
// ===========================================================================

#[tokio::test]
async fn rfc9700_no_front_channel_access_token() {
    // A token-bearing response type is unsupported, AND a legitimate code-flow
    // success carries no access_token in its front-channel redirect.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // response_type=token (and combinations) are unsupported_response_type.
    for response_type in ["token", "code token", "id_token token"] {
        let query = format!(
            "response_type={}&client_id={client_id}&redirect_uri={}&state=s&nonce=n",
            enc(response_type),
            enc(REDIRECT_URI),
        );
        let (status, headers, body) = harness.authorize(&query).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{response_type}: {body}");
        assert_eq!(
            location_param(&headers, "error").as_deref(),
            Some("unsupported_response_type"),
            "{response_type} must be unsupported"
        );
        checks::no_front_channel_access_token(&headers)
            .unwrap_or_else(|reason| panic!("{response_type}: {reason}"));
    }

    // A real code-flow success also never carries a front-channel access token.
    let cookie = harness.authenticated_cookie().await;
    let query = authorize_code_query(&client_id, "&state=xyz");
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "success redirect: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued"
    );
    checks::no_front_channel_access_token(&headers).unwrap_or_else(|reason| panic!("{reason}"));
}

// ===========================================================================
// R7: RFC 9207 iss on every authorization response.
// ===========================================================================

#[tokio::test]
async fn rfc9700_authorization_response_carries_iss() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let expected = harness.issuer().to_owned();

    // Success response.
    let cookie = harness.authenticated_cookie().await;
    let query = authorize_code_query(&client_id, "&state=ok");
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "success redirect: {body}");
    checks::authorization_response_iss(&headers, &expected)
        .unwrap_or_else(|reason| panic!("success: {reason}"));

    // Error response (unsupported response_type by redirect).
    let error_query = format!(
        "response_type=token&client_id={client_id}&redirect_uri={}&state=err",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&error_query).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
    checks::authorization_response_iss(&headers, &expected)
        .unwrap_or_else(|reason| panic!("error: {reason}"));
}

// ===========================================================================
// R8: refresh rotation and reuse family revocation.
// ===========================================================================

#[tokio::test]
async fn rfc9700_refresh_token_rotates_and_reuse_revokes_family() {
    // A public client rotates its refresh token on every refresh; presenting a
    // superseded (reused) refresh token is invalid_grant and revokes the whole
    // family, so a stolen token cannot be replayed (RFC 9700 2.2.2 / OAuth 2.1).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
        ("scope", "openid offline_access"),
    ]);
    let (status, _headers, body) = harness.token(&redeem).await;
    assert_eq!(status, StatusCode::OK, "initial exchange: {body}");
    let first_refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh token is issued")
        .to_owned();

    // First refresh rotates the token (a new one comes back, distinct from the old).
    let refresh_form = |token: &str| {
        form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", &client_id),
        ])
    };
    let (status, _headers, body) = harness.token(&refresh_form(&first_refresh)).await;
    assert_eq!(status, StatusCode::OK, "first refresh: {body}");
    let second_refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_owned();
    assert_ne!(
        first_refresh, second_refresh,
        "the refresh token rotates on every use"
    );

    // Advance past the default 10-second within-grace window so the replay is a
    // genuine reuse (a within-grace replay is an idempotent retry, not an attack).
    harness.clock().advance(Duration::from_secs(30));

    // Reusing the FIRST (now superseded) refresh token is invalid_grant.
    let (status, _headers, body) = harness.token(&refresh_form(&first_refresh)).await;
    checks::is_invalid_grant(status, &body).unwrap_or_else(|reason| panic!("reuse: {reason}"));

    // The reuse revoked the family: the rotated (second) token is now dead too.
    let (status, _headers, body) = harness.token(&refresh_form(&second_refresh)).await;
    checks::is_invalid_grant(status, &body)
        .unwrap_or_else(|reason| panic!("family revocation: {reason}"));
}

// ===========================================================================
// R9: audience-restricted tokens, never delivered in a URL.
// ===========================================================================

#[tokio::test]
async fn rfc9700_access_token_is_audience_restricted() {
    // A client-credentials at+jwt is audience-restricted (RFC 9068 / RFC 8707): the
    // aud claim is present and equals the default audience (the client id).
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let body = form(&[("grant_type", "client_credentials")]);
    let (status, _headers, response) = harness
        .token_with_auth(&body, Some(&format!("Basic {basic}")))
        .await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {response}");
    let access_token = json(&response)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let claims = decode_jwt_claims(&access_token);
    checks::audience_restricted(&claims, &client_id).unwrap_or_else(|reason| panic!("{reason}"));
}

#[tokio::test]
async fn rfc9700_token_endpoint_never_delivers_a_token_in_a_url() {
    // The token endpoint returns tokens in a JSON body with Cache-Control: no-store
    // and NO Location header, so a token never appears in a URL, a Location, or a
    // query string.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, headers, body) = harness.token(&redeem).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    assert!(json(&body)["access_token"].is_string(), "a token is issued");
    checks::token_never_in_url(&headers).unwrap_or_else(|reason| panic!("{reason}"));
    checks::cache_control_no_store(&headers).unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "tokens are delivered as JSON"
    );
}

// ===========================================================================
// R10: 303, never 307, for credential-bearing redirects.
// ===========================================================================

#[tokio::test]
async fn rfc9700_credential_bearing_redirect_uses_303_see_other() {
    // The authorization-success redirect (carrying the code) and the post-login
    // redirect (following a credential-bearing POST) are BOTH 303 See Other, never
    // 302 and never a body-preserving 307/308.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // Authorization success carrying the code.
    let cookie = harness.authenticated_cookie().await;
    let query = authorize_code_query(&client_id, "&state=s");
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is carried: {body}"
    );
    checks::credential_bearing_redirect_status(status)
        .unwrap_or_else(|reason| panic!("authorize success: {reason}"));

    // The interaction (login) redirect that GET /authorize issues when it needs an
    // interaction is also a 303.
    let interaction_query = authorize_code_query(&client_id, "");
    let (status, headers, _body) = harness.authorize(&interaction_query).await;
    assert!(
        location(&headers).is_some_and(|l| l.starts_with("/login")),
        "an unauthenticated authorize redirects to the login interaction"
    );
    checks::credential_bearing_redirect_status(status)
        .unwrap_or_else(|reason| panic!("interaction redirect: {reason}"));
}

// ===========================================================================
// R11: Referrer-Policy on every code-carrying response.
// ===========================================================================

#[tokio::test]
async fn rfc9700_code_carrying_response_sets_referrer_policy() {
    // The query-mode success redirect carries the code in the Location query; it MUST
    // set Referrer-Policy: no-referrer (and Cache-Control: no-store) at the single
    // response seam so the code is never leaked through Referer.
    let harness = Harness::start_with(form_post_config()).await;
    let client_id = harness.client_id().to_string();

    // Query mode (code in the Location).
    let cookie = harness.authenticated_cookie().await;
    let query = authorize_code_query(&client_id, "&state=s");
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "success redirect: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is carried"
    );
    checks::referrer_policy_no_referrer(&headers)
        .unwrap_or_else(|reason| panic!("query mode: {reason}"));
    checks::cache_control_no_store(&headers)
        .unwrap_or_else(|reason| panic!("query mode: {reason}"));

    // form_post mode (code in the posted body): the interstitial page carries the
    // same no-referrer.
    let cookie = harness.authenticated_cookie().await;
    let fp_query = format!(
        "response_type=code&response_mode=form_post&client_id={client_id}&redirect_uri={}&\
         state=s&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&fp_query, &cookie).await;
    assert_eq!(status, StatusCode::OK, "form_post page: {body}");
    assert!(
        form_field(&body, "code").is_some(),
        "the code is in the form body"
    );
    checks::referrer_policy_no_referrer(&headers)
        .unwrap_or_else(|reason| panic!("form_post mode: {reason}"));
}

// ===========================================================================
// R12: CORS disabled on the authorization endpoint.
// ===========================================================================

#[tokio::test]
async fn rfc9700_authorize_endpoint_has_no_cors() {
    // A real cross-origin probe: an OPTIONS preflight and a GET both carrying an
    // Origin header must NOT receive Access-Control-Allow-Origin from /authorize.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // Preflight OPTIONS with Origin and the preflight request headers.
    let preflight = Request::builder()
        .method("OPTIONS")
        .uri("/authorize")
        .header(header::ORIGIN, "https://attacker.test")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .expect("request builds");
    let (_status, headers, _body) = harness.send(preflight).await;
    checks::no_cors_on_authorize(&headers).unwrap_or_else(|reason| panic!("preflight: {reason}"));

    // A GET with an Origin (a cross-origin fetch) likewise gets no CORS grant.
    let query = authorize_code_query(&client_id, "&state=s");
    let get = Request::builder()
        .method("GET")
        .uri(format!("/authorize?{query}"))
        .header(header::ORIGIN, "https://attacker.test")
        .body(Body::empty())
        .expect("request builds");
    let (_status, headers, _body) = harness.send(get).await;
    checks::no_cors_on_authorize(&headers).unwrap_or_else(|reason| panic!("GET: {reason}"));
}

// ===========================================================================
// R13: authorization codes single-use and bound to client + redirect_uri.
// ===========================================================================

#[tokio::test]
async fn rfc9700_authorization_code_is_single_use() {
    // A code redeemed once is dead: the second redemption is invalid_grant.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, body) = harness.token(&redeem).await;
    assert_eq!(status, StatusCode::OK, "first redemption: {body}");
    let (status, _headers, body) = harness.token(&redeem).await;
    checks::is_invalid_grant(status, &body).unwrap_or_else(|reason| panic!("replay: {reason}"));
}

#[tokio::test]
async fn rfc9700_authorization_code_is_bound_to_client_and_redirect_uri() {
    // A code is bound to its client and its redirect_uri (RFC 6749 4.1.3): a wrong
    // redirect_uri, and a wrong client_id, are each invalid_grant.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let other = harness
        .create_public_client_with_redirects("other client", &[REDIRECT_URI])
        .await
        .to_string();

    // Wrong redirect_uri.
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let wrong_redirect = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", "https://client.test/unregistered"),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, body) = harness.token(&wrong_redirect).await;
    checks::is_invalid_grant(status, &body)
        .unwrap_or_else(|reason| panic!("redirect binding: {reason}"));

    // Wrong client_id (a different, validly-authenticated public client).
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let wrong_client = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &other),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, body) = harness.token(&wrong_client).await;
    checks::is_invalid_grant(status, &body)
        .unwrap_or_else(|reason| panic!("client binding: {reason}"));
}

// ===========================================================================
// R14: sender-uniform token errors (no failure oracle).
// ===========================================================================

#[tokio::test]
async fn rfc9700_token_error_is_sender_uniform() {
    // A bogus code, a wrong verifier, and a wrong redirect_uri are DISTINCT internal
    // failures that must all render byte-identically, so the endpoint never says
    // which check failed.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let mut bodies = Vec::new();

    // Bogus code.
    let bogus = form(&[
        ("grant_type", "authorization_code"),
        ("code", "ac_this_code_does_not_exist"),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, body) = harness.token(&bogus).await;
    checks::is_invalid_grant(status, &body).unwrap_or_else(|reason| panic!("bogus: {reason}"));
    bodies.push(body);

    // Wrong verifier on a fresh code.
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let wrong_verifier = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        (
            "code_verifier",
            "the-wrong-verifier-value-not-appendix-b-000000",
        ),
    ]);
    let (status, _headers, body) = harness.token(&wrong_verifier).await;
    checks::is_invalid_grant(status, &body).unwrap_or_else(|reason| panic!("verifier: {reason}"));
    bodies.push(body);

    // Wrong redirect_uri on a fresh code.
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let wrong_redirect = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", "https://client.test/unregistered"),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, body) = harness.token(&wrong_redirect).await;
    checks::is_invalid_grant(status, &body).unwrap_or_else(|reason| panic!("redirect: {reason}"));
    bodies.push(body);

    checks::bodies_are_uniform(&bodies).unwrap_or_else(|reason| panic!("{reason}"));
}

// ===========================================================================
// R15: ROPC absent (no resource-owner password grant).
// ===========================================================================

#[tokio::test]
async fn rfc9700_ropc_password_grant_is_unsupported() {
    // The resource-owner password-credentials grant has no handler to route to: it is
    // absent, not disabled. A request naming it is unsupported_grant_type.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let body = form(&[
        ("grant_type", "password"),
        ("username", "alice@example.test"),
        ("password", "hunter2"),
        ("client_id", &client_id),
    ]);
    let (status, _headers, response) = harness.token(&body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "ROPC: {response}");
    assert_eq!(
        json(&response)["error"],
        "unsupported_grant_type",
        "ROPC has no handler: {response}"
    );
}

// ===========================================================================
// The mutation harness: prove each shared predicate REJECTS the exact shape a
// flipped guard would produce, so no conformance test above can pass vacuously.
// Every mutant test also confirms the predicate ACCEPTS a conforming shape, so a
// predicate that always errs (which would fail the live conformance test) is
// caught here too. These run in normal CI; nothing here touches the library.
// ===========================================================================

mod mutation {
    use super::checks;
    use axum::http::{HeaderMap, StatusCode, header};

    /// A `HeaderMap` with a `Location` header set to `location`.
    fn with_location(location: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::LOCATION, location.parse().expect("valid header"));
        headers
    }

    #[test]
    fn rfc9700_mutant_no_cors_detects_allow_origin() {
        // Conforming: no CORS header.
        checks::no_cors_on_authorize(&HeaderMap::new()).expect("no CORS is conforming");
        // Seeded violation: the guard leaked an Access-Control-Allow-Origin.
        let mut headers = HeaderMap::new();
        headers.insert(
            "access-control-allow-origin",
            "https://attacker.test".parse().expect("valid header"),
        );
        checks::no_cors_on_authorize(&headers).expect_err("an ACAO on /authorize must be caught");
    }

    #[test]
    fn rfc9700_mutant_iss_detects_missing_iss() {
        let expected = "https://issuer.test/t/a/e/b";
        // Conforming: iss present and equal.
        checks::authorization_response_iss(
            &with_location(&format!("https://client.test/cb?code=x&iss={expected}")),
            expected,
        )
        .expect("a present, matching iss is conforming");
        // Seeded violation: the guard dropped iss.
        checks::authorization_response_iss(
            &with_location("https://client.test/cb?code=x"),
            expected,
        )
        .expect_err("a missing iss must be caught");
        // Seeded violation: a wrong iss (mix-up) is caught.
        checks::authorization_response_iss(
            &with_location("https://client.test/cb?code=x&iss=https://evil.test"),
            expected,
        )
        .expect_err("a mismatched iss must be caught");
    }

    #[test]
    fn rfc9700_mutant_redirect_status_detects_307_and_302() {
        checks::credential_bearing_redirect_status(StatusCode::SEE_OTHER)
            .expect("303 is conforming");
        // Seeded violations: a body-preserving 307/308 (would replay a POSTed
        // credential) and the legacy 302 (browser-dependent method conversion).
        for bad in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
            StatusCode::FOUND,
        ] {
            assert!(
                checks::credential_bearing_redirect_status(bad).is_err(),
                "status {bad} should have been rejected as non-303"
            );
        }
    }

    #[test]
    fn rfc9700_mutant_referrer_policy_detects_missing_header() {
        let mut ok = HeaderMap::new();
        ok.insert(
            header::REFERRER_POLICY,
            "no-referrer".parse().expect("valid"),
        );
        checks::referrer_policy_no_referrer(&ok).expect("no-referrer is conforming");
        // Seeded violation: the header is absent (the pre-fix hole).
        checks::referrer_policy_no_referrer(&HeaderMap::new())
            .expect_err("a missing Referrer-Policy must be caught");
        // Seeded violation: a weaker policy that would still leak the code.
        let mut weak = HeaderMap::new();
        weak.insert(
            header::REFERRER_POLICY,
            "origin-when-cross-origin".parse().expect("valid"),
        );
        checks::referrer_policy_no_referrer(&weak).expect_err("a weaker policy must be caught");
    }

    #[test]
    fn rfc9700_mutant_cache_control_detects_missing_no_store() {
        let mut ok = HeaderMap::new();
        ok.insert(header::CACHE_CONTROL, "no-store".parse().expect("valid"));
        checks::cache_control_no_store(&ok).expect("no-store is conforming");
        checks::cache_control_no_store(&HeaderMap::new())
            .expect_err("a missing Cache-Control must be caught");
    }

    #[test]
    fn rfc9700_mutant_front_channel_detects_access_token() {
        checks::no_front_channel_access_token(&with_location(
            "https://client.test/cb?code=x&iss=y",
        ))
        .expect("a code-only response is conforming");
        // Seeded violation: an access token leaked into the fragment.
        checks::no_front_channel_access_token(&with_location(
            "https://client.test/cb#access_token=leaked&token_type=Bearer",
        ))
        .expect_err("a front-channel access_token must be caught");
    }

    #[test]
    fn rfc9700_mutant_token_in_url_detects_location() {
        checks::token_never_in_url(&HeaderMap::new()).expect("no Location is conforming");
        checks::token_never_in_url(&with_location("https://client.test/cb?access_token=leaked"))
            .expect_err("a token response with a Location must be caught");
    }

    #[test]
    fn rfc9700_mutant_error_page_detects_open_redirect() {
        checks::refused_by_error_page(StatusCode::BAD_REQUEST, &HeaderMap::new())
            .expect("a 400 page with no Location is conforming");
        // Seeded violation: the endpoint redirected an unvalidated redirect_uri.
        checks::refused_by_error_page(
            StatusCode::SEE_OTHER,
            &with_location("https://evil.test/phish?code=leaked"),
        )
        .expect_err("a redirect to an unvalidated URI must be caught");
    }

    #[test]
    fn rfc9700_mutant_invalid_grant_detects_success() {
        checks::is_invalid_grant(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#)
            .expect("a 400 invalid_grant is conforming");
        // Seeded violation: a reused/mis-bound code was ACCEPTED (200 with a token).
        checks::is_invalid_grant(StatusCode::OK, r#"{"access_token":"minted"}"#)
            .expect_err("accepting a reused or mis-bound code must be caught");
    }

    #[test]
    fn rfc9700_mutant_uniform_errors_detects_divergent_bodies() {
        let uniform = vec![
            r#"{"error":"invalid_grant"}"#.to_owned(),
            r#"{"error":"invalid_grant"}"#.to_owned(),
        ];
        checks::bodies_are_uniform(&uniform).expect("identical bodies are conforming");
        // Seeded violation: one error body reveals WHICH check failed.
        let oracular = vec![
            r#"{"error":"invalid_grant"}"#.to_owned(),
            r#"{"error":"invalid_grant","error_description":"unknown code"}"#.to_owned(),
        ];
        checks::bodies_are_uniform(&oracular).expect_err("a divergent error body must be caught");
    }

    #[test]
    fn rfc9700_mutant_pkce_methods_detects_plain() {
        checks::pkce_methods_s256_only(&serde_json::json!({
            "code_challenge_methods_supported": ["S256"]
        }))
        .expect("S256-only is conforming");
        // Seeded violation: plain re-advertised.
        checks::pkce_methods_s256_only(&serde_json::json!({
            "code_challenge_methods_supported": ["S256", "plain"]
        }))
        .expect_err("advertising plain must be caught");
    }

    #[test]
    fn rfc9700_mutant_audience_detects_missing_aud() {
        checks::audience_restricted(&serde_json::json!({ "aud": "client-123" }), "client-123")
            .expect("a matching aud is conforming");
        // Seeded violation: an unrestricted (audience-less) token.
        checks::audience_restricted(&serde_json::json!({ "sub": "x" }), "client-123")
            .expect_err("a missing aud must be caught");
    }

    #[test]
    fn rfc9700_mutant_loopback_detects_host_swap() {
        // Conforming: a loopback port variant matches.
        checks::loopback_exception_scoped("http://127.0.0.1/cb", "http://127.0.0.1:9000/cb", true)
            .expect("a port variant matches");
        // Seeded violation: the exception broadened to accept a different host, which
        // the predicate (expecting NO match) must flag.
        checks::loopback_exception_scoped("http://127.0.0.1/cb", "http://127.0.0.2:9000/cb", false)
            .expect("a host swap must not match");
    }
}
