// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 7521 4.1 / RFC 7523 JWT bearer assertion grant (issue #26), over a real
//! database with a SIMULATED external issuer.
//!
//! Exercises the grant end to end through the live `/token` endpoint: an assertion
//! signed by a REGISTERED external issuer exchanges for a short-lived access token
//! under the mapped identity (inline `jwks` and `jwks_uri` key sources); the full
//! negative matrix (unregistered issuer, disabled issuer, bad signature, expired,
//! replayed `jti`, unmapped subject) is a uniform `invalid_grant` with a recorded
//! out-of-band diagnostic; the strict issuer-only audience mode rejects a
//! token-endpoint-audienced assertion (the FAPI-shaped set); NO refresh token is
//! issued; client authentication fails INDEPENDENTLY as `invalid_client`; and a
//! SHARED audience-policy test proves the ONE knob governs this grant and #25 client
//! assertions identically.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Harness, form, json};
use ironauth_config::{ClientAssertionAudience, OidcConfig};
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::{
    ClientAuthError, ClientAuthInputs, ClientAuthMethod, JWT_BEARER_ASSERTION_TYPE,
    authenticate_client,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The grant type under test.
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The simulated external issuer's identifier (its `iss` claim value).
const EXTERNAL_ISSUER: &str = "https://workload.issuer.test";
/// The external workload's `sub` (a stand-in for a SPIRE/Kubernetes subject).
const EXTERNAL_SUBJECT: &str = "spiffe://cluster.test/ns/prod/sa/alpha";
/// The mapped IronAuth principal the issued token carries as its `sub`.
const MAPPED_PRINCIPAL: &str = "usr_workload_alpha";

/// The external issuer's Ed25519 signing key (a fixed seed, deterministic and
/// committed only in the technical sense).
fn issuer_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("wk".to_owned()), &[7_u8; 32]).expect("issuer key")
}

/// A DIFFERENT Ed25519 key, for the bad-signature negative (the assertion is signed
/// with this while the registered JWKS holds `issuer_key`'s public key).
fn wrong_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("wk".to_owned()), &[42_u8; 32]).expect("wrong key")
}

/// The public JWK Set JSON for `key`, exactly what an issuer publishes.
fn jwks_json(key: &SigningKey) -> String {
    JwkSet::from_signing_keys([key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json")
}

/// Sign an assertion over `claims` with `key`.
fn sign_assertion(key: &SigningKey, claims: &serde_json::Value) -> String {
    let payload = serde_json::to_vec(claims).expect("serialize claims");
    sign_jws(key, &payload, &EmissionOptions::new()).expect("sign assertion")
}

/// A standard workload assertion: `iss`/`sub`/`aud`/`exp`/`iat`/`jti`.
fn assertion(key: &SigningKey, iss: &str, sub: &str, aud: &str, exp: i64, jti: &str) -> String {
    sign_assertion(
        key,
        &serde_json::json!({
            "iss": iss, "sub": sub, "aud": aud, "exp": exp, "iat": 0, "jti": jti,
        }),
    )
}

/// Present a jwt-bearer grant request through the live `/token` endpoint on behalf
/// of `client_id` (a public client id, in the form body).
async fn present(
    h: &Harness,
    client_id: &str,
    assertion: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let body = form(&[
        ("grant_type", JWT_BEARER_GRANT),
        ("assertion", assertion),
        ("client_id", client_id),
    ]);
    h.token(&body).await
}

/// Decode a compact JWS's payload into a JSON value (for asserting token claims).
fn jwt_payload(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("jws has a payload");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("payload base64url");
    serde_json::from_slice(&bytes).expect("payload json")
}

/// Register the standard trusted issuer (inline `jwks`) and a mapping from its
/// subject to [`MAPPED_PRINCIPAL`], returning the presenting (public harness) client
/// id string.
async fn seed_trust(h: &Harness) -> String {
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        None,
        None,
        MAPPED_PRINCIPAL,
    )
    .await;
    h.client_id().to_string()
}

#[tokio::test]
async fn a_registered_assertion_exchanges_for_a_mapped_identity_access_token() {
    // AC1: a valid assertion from a registered issuer exchanges for an access token
    // issued under the mapped identity, audienced to the presenting client, with NO
    // refresh token and NO ID token.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let key = issuer_key();
    let asrt = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-ok",
    );

    let (status, _headers, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let resp = json(&body);
    let access = resp["access_token"].as_str().expect("access token");
    assert_eq!(resp["token_type"], "Bearer");
    assert!(resp["expires_in"].is_number(), "short-lived token");

    // The token is issued under the MAPPED identity, audienced to the client.
    let claims = jwt_payload(access);
    assert_eq!(
        claims["sub"], MAPPED_PRINCIPAL,
        "sub is the mapped principal"
    );
    assert_eq!(claims["aud"], client_id, "aud is the presenting client");
    assert_eq!(claims["client_id"], client_id);
    assert_eq!(claims["iss"], h.issuer());
    // A machine/federation token asserts no interactive auth context.
    assert!(claims.get("acr").is_none(), "no acr");
    assert!(claims.get("auth_time").is_none(), "no auth_time");

    // No refresh token and no ID token (RFC 7521 4.1).
    assert!(
        resp.get("refresh_token").is_none(),
        "NO refresh token is issued on the assertion grant"
    );
    assert!(resp.get("id_token").is_none(), "no ID token (no user)");
}

#[tokio::test]
async fn no_refresh_family_or_row_is_opened_on_the_assertion_grant() {
    // AC4 at the DATABASE: the assertion grant opens NO refresh family and mints NO
    // refresh token, proven at the store rather than only in the response body.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let key = issuer_key();
    let asrt = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-norefresh",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        h.count_refresh_rows().await,
        (0, 0),
        "no refresh family and no refresh token row"
    );
}

#[tokio::test]
async fn an_unregistered_issuer_is_rejected_with_invalid_grant_and_a_diagnostic() {
    // AC2: an assertion from an UNREGISTERED issuer is invalid_grant with a recorded
    // diagnostic (assertion_issuer_untrusted).
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let key = issuer_key();
    // Signed by the real key but claiming an issuer we never registered.
    let asrt = assertion(
        &key,
        "https://evil.issuer.test",
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-unreg",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_issuer_untrusted"),
        "an unregistered issuer is diagnosed out of band"
    );
}

#[tokio::test]
async fn a_disabled_issuer_is_rejected() {
    // The enable switch: a REGISTERED but DISABLED issuer is rejected exactly as an
    // unregistered one is.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, false)
        .await;
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        None,
        None,
        MAPPED_PRINCIPAL,
    )
    .await;
    let client_id = h.client_id().to_string();
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-disabled",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_issuer_untrusted"),
        "a disabled issuer is diagnosed as untrusted"
    );
}

#[tokio::test]
async fn a_bad_signature_is_rejected_with_invalid_grant_and_a_diagnostic() {
    // AC2: an assertion signed with the WRONG key (the registered JWKS holds a
    // different public key) is invalid_grant with an assertion_invalid diagnostic.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let asrt = assertion(
        &wrong_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-badsig",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_invalid"),
        "a bad signature is diagnosed"
    );
}

#[tokio::test]
async fn an_expired_assertion_is_rejected_with_invalid_grant_and_a_diagnostic() {
    // AC2: an expired assertion (exp before now-skew, at the frozen epoch clock) is
    // invalid_grant with an assertion_invalid diagnostic.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        -1000,
        "jti-expired",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_invalid"),
        "an expired assertion is diagnosed"
    );
}

#[tokio::test]
async fn an_unmapped_subject_is_rejected_and_never_auto_provisioned() {
    // AC5: subject mapping fires ONLY for explicitly configured rules. A verified
    // assertion whose subject names no mapping rule is invalid_grant
    // (assertion_subject_unmapped), NEVER auto-provisioned.
    let h = Harness::start().await;
    // Register the issuer but NO mapping for this subject.
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;
    let client_id = h.client_id().to_string();
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        "spiffe://cluster.test/ns/prod/sa/unmapped",
        h.issuer(),
        3600,
        "jti-unmapped",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_subject_unmapped"),
        "an unmapped subject is diagnosed, never auto-provisioned"
    );
}

#[tokio::test]
async fn the_subject_claim_gate_fires_only_on_the_exact_claim_value() {
    // A mapping gated on an additional claim maps ONLY when the assertion carries the
    // claim with the exact value; a wrong or missing value is unmapped.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;
    // Map only when repository == "acme/api".
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        Some("repository"),
        Some("acme/api"),
        MAPPED_PRINCIPAL,
    )
    .await;
    let client_id = h.client_id().to_string();
    let key = issuer_key();

    // The exact value maps.
    let ok = sign_assertion(
        &key,
        &serde_json::json!({
            "iss": EXTERNAL_ISSUER, "sub": EXTERNAL_SUBJECT, "aud": h.issuer(),
            "exp": 3600, "iat": 0, "jti": "jti-gate-ok", "repository": "acme/api",
        }),
    );
    let (status, _h, body) = present(&h, &client_id, &ok).await;
    assert_eq!(status, StatusCode::OK, "the exact claim value maps: {body}");
    assert_eq!(
        jwt_payload(json(&body)["access_token"].as_str().unwrap())["sub"],
        MAPPED_PRINCIPAL
    );

    // A wrong value is unmapped.
    let bad = sign_assertion(
        &key,
        &serde_json::json!({
            "iss": EXTERNAL_ISSUER, "sub": EXTERNAL_SUBJECT, "aud": h.issuer(),
            "exp": 3600, "iat": 0, "jti": "jti-gate-bad", "repository": "evil/fork",
        }),
    );
    let (status, _h, body) = present(&h, &client_id, &bad).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a wrong claim value is unmapped: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");

    // A missing claim is unmapped too.
    let missing = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-gate-missing",
    );
    let (status, _h, body) = present(&h, &client_id, &missing).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a missing gate claim is unmapped: {body}"
    );
}

#[tokio::test]
async fn a_replayed_jti_is_rejected() {
    // The single-use jti (in the DISTINCT external-issuer cache): a second use of the
    // same assertion is a replay.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-replay",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::OK, "first use: {body}");
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "replay: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "replayed_jti"),
        "the replay is diagnosed"
    );
}

#[tokio::test]
async fn strict_issuer_only_aud_rejects_a_token_endpoint_audienced_assertion() {
    // AC3 (the FAPI-shaped set): under strict issuer-only audience, an assertion
    // audienced to the TOKEN ENDPOINT is rejected while an issuer-audienced one is
    // accepted. The SAME knob #25 introduced.
    let strict = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        client_assertion_audience: ClientAssertionAudience::IssuerOnly,
        ..OidcConfig::default()
    })
    .await;
    let client_id = seed_trust(&strict).await;
    let key = issuer_key();
    let endpoint = strict.state().token_endpoint_url();

    // Token-endpoint audience: rejected under strict.
    let tep = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        &endpoint,
        3600,
        "jti-strict-tep",
    );
    let (status, _h, body) = present(&strict, &client_id, &tep).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "strict rejects the token endpoint aud: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");

    // Issuer audience: still accepted under strict.
    let iss = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        strict.issuer(),
        3600,
        "jti-strict-iss",
    );
    let (status, _h, body) = present(&strict, &client_id, &iss).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "strict still accepts the issuer aud: {body}"
    );
}

#[tokio::test]
async fn client_authentication_fails_independently_with_invalid_client() {
    // A confidential presenting client that fails authentication is invalid_client
    // (401), INDEPENDENT of an otherwise-valid assertion.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        None,
        None,
        MAPPED_PRINCIPAL,
    )
    .await;
    let (confidential, _secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let cid = confidential.to_string();
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-badclient",
    );
    // Present the (valid) assertion with a WRONG client secret via Basic.
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{cid}:wrong-secret"))
    );
    let body = form(&[("grant_type", JWT_BEARER_GRANT), ("assertion", &asrt)]);
    let (status, headers, response) = h.token_with_auth(&body, Some(&auth)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{response}");
    assert_eq!(json(&response)["error"], "invalid_client");
    assert!(
        headers.contains_key(header::WWW_AUTHENTICATE),
        "a Basic attempt carries WWW-Authenticate"
    );
}

#[tokio::test]
async fn the_assertion_is_required() {
    // A jwt-bearer request without an `assertion` is invalid_request.
    let h = Harness::start().await;
    let client_id = h.client_id().to_string();
    let body = form(&[("grant_type", JWT_BEARER_GRANT), ("client_id", &client_id)]);
    let (status, _h, body) = h.token(&body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_request");
}

#[tokio::test]
async fn the_jwks_uri_key_source_authenticates_through_the_hardened_fetcher() {
    // AC1 (the jwks_uri source): an assertion authenticates with keys served from a
    // registered issuer's jwks_uri, fetched through the SSRF-hardened fetcher.
    let key = issuer_key();
    let jwks = jwks_json(&key);
    let server = start_jwks_server(jwks).await;

    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = Arc::new(ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    ));
    let h = Harness::start_with_resolver(
        OidcConfig {
            require_pkce_for_confidential_clients: false,
            ..OidcConfig::default()
        },
        resolver,
    )
    .await;
    h.register_external_issuer(
        EXTERNAL_ISSUER,
        None,
        Some("http://issuer.test/jwks.json"),
        None,
        true,
    )
    .await;
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        None,
        None,
        MAPPED_PRINCIPAL,
    )
    .await;
    let client_id = h.client_id().to_string();

    let asrt = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-uri",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::OK, "jwks_uri exchange: {body}");
    assert_eq!(
        jwt_payload(json(&body)["access_token"].as_str().unwrap())["sub"],
        MAPPED_PRINCIPAL
    );
    assert_eq!(dialer.requested().len(), 1, "the jwks_uri was fetched once");
}

#[tokio::test]
async fn the_shared_aud_policy_governs_this_grant_and_client_assertions_identically() {
    // The SHARED knob: under EACH audience policy, a jwt-bearer assertion and a #25
    // client assertion, both audienced to the TOKEN ENDPOINT, are accepted or
    // rejected IDENTICALLY, proving ONE config switch drives both surfaces.
    for (policy, token_endpoint_accepted) in [
        (ClientAssertionAudience::TokenEndpointOrIssuer, true),
        (ClientAssertionAudience::IssuerOnly, false),
    ] {
        let h = Harness::start_with(OidcConfig {
            require_pkce_for_confidential_clients: false,
            client_assertion_audience: policy,
            ..OidcConfig::default()
        })
        .await;
        let endpoint = h.state().token_endpoint_url();

        // The jwt-bearer surface: an external assertion audienced to the token
        // endpoint.
        let grant_client = seed_trust(&h).await;
        let ext = assertion(
            &issuer_key(),
            EXTERNAL_ISSUER,
            EXTERNAL_SUBJECT,
            &endpoint,
            3600,
            "jti-shared-grant",
        );
        let (grant_status, _h, grant_body) = present(&h, &grant_client, &ext).await;
        let grant_accepted = grant_status == StatusCode::OK;

        // The #25 client-assertion surface: a private_key_jwt client assertion
        // audienced to the token endpoint, presented through the shared seam.
        let client_key = issuer_key();
        let client_jwks = jwks_json(&client_key);
        let client = h
            .create_jwt_auth_client(
                ClientAuthMethod::PrivateKeyJwt,
                Some(&client_jwks),
                None,
                None,
            )
            .await;
        let ccid = client.to_string();
        let client_assertion = assertion(
            &client_key,
            &ccid,
            &ccid,
            &endpoint,
            3600,
            "jti-shared-client",
        );
        let client_result = authenticate_client(
            h.state(),
            h.scope(),
            ClientAuthInputs {
                client_assertion: Some(&client_assertion),
                client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE),
                ..ClientAuthInputs::default()
            },
        )
        .await;
        let client_accepted = client_result.is_ok();

        // The knob behaves IDENTICALLY on both surfaces.
        assert_eq!(
            grant_accepted, token_endpoint_accepted,
            "jwt-bearer token-endpoint aud under {policy:?}: {grant_body}"
        );
        assert_eq!(
            client_accepted, token_endpoint_accepted,
            "client-assertion token-endpoint aud under {policy:?}"
        );
        assert_eq!(
            grant_accepted, client_accepted,
            "the shared knob governs both surfaces identically under {policy:?}"
        );
        if !client_accepted {
            assert!(
                matches!(client_result, Err(ClientAuthError::InvalidClient { .. })),
                "a rejected client assertion is invalid_client"
            );
        }
    }
}

#[tokio::test]
async fn a_dual_source_or_keyless_issuer_registration_is_refused() {
    // The XOR key-source constraint fails LOUD at registration: an issuer that pins
    // both jwks and jwks_uri, or neither, is refused (a Conflict), so no
    // unverifiable issuer ever reaches the grant.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    let dual = h
        .try_register_external_issuer(
            EXTERNAL_ISSUER,
            Some(&jwks),
            Some("http://issuer.test/jwks"),
        )
        .await;
    assert!(
        matches!(dual, Err(ironauth_store::StoreError::Conflict)),
        "a dual-source issuer is refused: {dual:?}"
    );
    let keyless = h
        .try_register_external_issuer(EXTERNAL_ISSUER, None, None)
        .await;
    assert!(
        matches!(keyless, Err(ironauth_store::StoreError::Conflict)),
        "a keyless issuer is refused: {keyless:?}"
    );
}

#[tokio::test]
async fn disabling_a_live_issuer_revokes_the_grant() {
    // The revocability capability (issue #26 fix): a live, working issuer can be
    // DISABLED through the column-scoped data-plane grant, after which its assertions
    // reject exactly as an unregistered issuer's do. This is why `GRANT UPDATE
    // (enabled)` and the store toggle must ship now (the HTTP management surface is
    // M13): without them a compromised or decommissioned issuer could not be turned
    // off.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    let issuer_id = h
        .register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        None,
        None,
        MAPPED_PRINCIPAL,
    )
    .await;
    let client_id = h.client_id().to_string();
    let key = issuer_key();

    // While enabled, the grant succeeds.
    let ok = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-live-ok",
    );
    let (status, _h, body) = present(&h, &client_id, &ok).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the enabled issuer exchanges: {body}"
    );

    // Disable the issuer through the data-plane toggle (the revocation path).
    h.set_external_issuer_enabled(&issuer_id, false).await;

    // A FRESH assertion (distinct jti) now rejects as an untrusted issuer.
    let after = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-live-revoked",
    );
    let (status, _h, body) = present(&h, &client_id, &after).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the disabled issuer rejects: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_issuer_untrusted"),
        "a revoked issuer is diagnosed as untrusted"
    );
}

#[tokio::test]
async fn disabling_a_live_mapping_revokes_the_grant() {
    // The revocability capability for a mis-authored mapping (issue #26 fix): a live
    // mapping can be DISABLED through the column-scoped data-plane grant, after which
    // the subject resolves to no rule and the grant rejects it as unmapped
    // (reject-by-default), never auto-provisioned.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;
    let mapping_id = h
        .create_subject_mapping(
            EXTERNAL_ISSUER,
            EXTERNAL_SUBJECT,
            None,
            None,
            MAPPED_PRINCIPAL,
        )
        .await;
    let client_id = h.client_id().to_string();
    let key = issuer_key();

    // While enabled, the grant succeeds.
    let ok = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-map-ok",
    );
    let (status, _h, body) = present(&h, &client_id, &ok).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the enabled mapping exchanges: {body}"
    );

    // Disable the mapping through the data-plane toggle (the revocation path).
    h.set_subject_mapping_enabled(&mapping_id, false).await;

    // A FRESH assertion now rejects as unmapped.
    let after = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-map-revoked",
    );
    let (status, _h, body) = present(&h, &client_id, &after).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the disabled mapping rejects: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_subject_unmapped"),
        "a revoked mapping is diagnosed as unmapped"
    );
}

#[tokio::test]
async fn a_user_or_oidc_scope_is_rejected_as_invalid_scope() {
    // FIX 2 (spec): the assertion grant applies the SAME machine-grant scope policy as
    // the client-credentials grant, so a mapped-identity token can never carry
    // `openid` (an OIDC/user concept requiring an authenticated end user) or
    // `offline_access` (a refresh token, which this grant never issues). Either is
    // invalid_scope, rejected BEFORE the assertion's single-use jti is spent.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let key = issuer_key();

    for scope in ["openid", "offline_access"] {
        let asrt = assertion(
            &key,
            EXTERNAL_ISSUER,
            EXTERNAL_SUBJECT,
            h.issuer(),
            3600,
            "jti-scope-rejected",
        );
        let body = form(&[
            ("grant_type", JWT_BEARER_GRANT),
            ("assertion", &asrt),
            ("client_id", &client_id),
            ("scope", scope),
        ]);
        let (status, _h, resp) = h.token(&body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "scope `{scope}`: {resp}");
        assert_eq!(
            json(&resp)["error"],
            "invalid_scope",
            "an out-of-policy scope `{scope}` is invalid_scope"
        );
    }

    // Positive control: an in-policy scope is accepted and echoed (whitespace
    // collapsed), so the policy is not over-blocking.
    let asrt = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-scope-ok",
    );
    let body = form(&[
        ("grant_type", JWT_BEARER_GRANT),
        ("assertion", &asrt),
        ("client_id", &client_id),
        ("scope", "  read   write "),
    ]);
    let (status, _h, resp) = h.token(&body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an in-policy scope is accepted: {resp}"
    );
    assert_eq!(
        json(&resp)["scope"],
        "read write",
        "the granted scope is normalized and echoed"
    );
}

#[tokio::test]
async fn the_exp_skew_boundary_is_accepted_and_one_second_past_is_rejected() {
    // FIX 3 (test rigor): under an ADVANCING clock (not the frozen-epoch default), an
    // assertion whose `exp` sits EXACTLY at the acceptance boundary (now == exp + skew)
    // is accepted, and a fresh one just past it (now == exp + skew + 1) is rejected
    // invalid_grant. Verification rejects only once now_secs > exp + skew.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let key = issuer_key();
    let skew = i64::try_from(h.state().client_assertion_skew().as_secs()).expect("skew fits i64");
    let exp = 3600_i64;

    // Advance to EXACTLY exp + skew: the last instant the assertion is still valid.
    let boundary = u64::try_from(exp + skew).expect("boundary fits u64");
    h.clock().advance(Duration::from_secs(boundary));
    let at_boundary = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        exp,
        "jti-boundary-ok",
    );
    let (status, _h, body) = present(&h, &client_id, &at_boundary).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exp exactly at exp+skew is accepted: {body}"
    );

    // Advance one more second: now exceeds exp + skew, so a fresh assertion (distinct
    // jti, so this is an EXPIRY rejection, not a replay) is expired.
    h.clock().advance(Duration::from_secs(1));
    let past_boundary = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        exp,
        "jti-boundary-past",
    );
    let (status, _h, body) = present(&h, &client_id, &past_boundary).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "one second past exp+skew is rejected: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_invalid"),
        "the past-boundary expiry is diagnosed as an invalid assertion"
    );
}

#[tokio::test]
async fn an_assertion_missing_sub_is_rejected_with_invalid_grant() {
    // FIX 3: RFC 7523 3 REQUIRES `sub`. An assertion that VERIFIES (good signature,
    // iss/aud/exp present) but carries NO `sub`, or an empty `sub`, is rejected
    // invalid_grant at the grant level: the JOSE layer treats `sub` as optional, and
    // the grant is what enforces its presence (never issuing a token with no subject).
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    let key = issuer_key();

    // Every REQUIRED claim EXCEPT sub.
    let no_sub = sign_assertion(
        &key,
        &serde_json::json!({
            "iss": EXTERNAL_ISSUER, "aud": h.issuer(), "exp": 3600, "iat": 0, "jti": "jti-no-sub",
        }),
    );
    let (status, _h, body) = present(&h, &client_id, &no_sub).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a missing sub rejects: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_invalid"),
        "a missing sub is diagnosed as an invalid assertion"
    );

    // An empty/whitespace sub is rejected the same way.
    let empty_sub = sign_assertion(
        &key,
        &serde_json::json!({
            "iss": EXTERNAL_ISSUER, "sub": "   ", "aud": h.issuer(),
            "exp": 3600, "iat": 0, "jti": "jti-empty-sub",
        }),
    );
    let (status, _h, body) = present(&h, &client_id, &empty_sub).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an empty sub rejects: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
}

/// Start an in-process loopback HTTP server that serves `body` as a JSON JWKS to
/// every request, returning its address (mirrors the #25 client-assertion test).
async fn start_jwks_server(body: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0_u8; 2048];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}
