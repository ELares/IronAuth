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

/// An assertion string that is not a JWT at all, so every request carrying it fails
/// at the very first step of assertion validation whatever else it asks for.
const GARBAGE_ASSERTION: &str = "not.a.jwt";

/// Set the PRESENTING (harness) client's per-client scope allowlist (issue #98).
///
/// Through the CONTROL plane, because migration 0096 grants the column-scoped
/// `UPDATE (allowed_scopes)` to `ironauth_control` alone: the plane that mints the
/// token cannot widen what that token may carry, so there is no data-plane door to
/// write through even in a test.
async fn set_allowlist(h: &Harness, allowed: Option<&[String]>) {
    h.db()
        .control_store()
        .management()
        .acting(
            h.db().test_actor(h.env()),
            ironauth_store::CorrelationId::generate(h.env()),
        )
        .client_scope_policies(h.scope())
        .set(h.env(), h.client_id(), allowed)
        .await
        .expect("set the presenting client's scope allowlist");
}

/// Present a jwt-bearer request carrying `assertion` and `scope`.
async fn present_with_scope(
    h: &Harness,
    client_id: &str,
    assertion: &str,
    scope: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let body = form(&[
        ("grant_type", JWT_BEARER_GRANT),
        ("assertion", assertion),
        ("client_id", client_id),
        ("scope", scope),
    ]);
    h.token(&body).await
}

#[tokio::test]
async fn the_presenting_clients_scope_allowlist_governs_this_grant_too() {
    // Issue #98: the allowlist that applies on this grant is the PRESENTING client's,
    // which is the client the token is minted for. Enforcement, then the wire answer,
    // then the ordering property the answer depends on.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    set_allowlist(&h, Some(&["read:orders".to_owned()])).await;
    let key = issuer_key();

    // Inside the allowlist: issued, and the granted scope is echoed.
    let inside = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-allow-inside",
    );
    let (status, _h, resp) = present_with_scope(&h, &client_id, &inside, "read:orders").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an allowlisted scope issues: {resp}"
    );
    assert_eq!(json(&resp)["scope"], "read:orders");

    // Outside it: refused. The wire answer is this grant's UNIFORM invalid_grant, NOT
    // invalid_scope, because a public presenting client reaches this check with no
    // credential at all (`a_public_presenting_client_cannot_enumerate_the_scope_allowlist`
    // is the adversarial half). The specific reason goes out of band instead.
    let outside = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-allow-outside",
    );
    let (status, _h, resp) = present_with_scope(&h, &client_id, &outside, "admin").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a scope outside the allowlist is refused: {resp}"
    );
    assert_eq!(
        json(&resp)["error"],
        "invalid_grant",
        "the refusal is this grant's uniform answer, not invalid_scope: {resp}"
    );
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "scope_not_allowlisted"),
        "the operator still learns the specific reason, out of band"
    );

    // And the refusal ran BEFORE the assertion was touched, so it did not spend the
    // single-use jti: the SAME assertion still redeems for an allowlisted scope.
    let (status, _h, resp) = present_with_scope(&h, &client_id, &outside, "read:orders").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused request never spent the assertion's jti: {resp}"
    );

    // Clearing the allowlist restores the pre-#98 behaviour: anything the floor allows.
    set_allowlist(&h, None).await;
    let cleared = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-allow-cleared",
    );
    let (status, _h, resp) = present_with_scope(&h, &client_id, &cleared, "admin").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "with no allowlist configured `admin` is fine again: {resp}"
    );
}

#[tokio::test]
async fn a_public_presenting_client_cannot_enumerate_the_scope_allowlist() {
    // The adversarial half, and the reason the refusal above is invalid_grant.
    //
    // This grant deliberately permits a PUBLIC (`none`) presenting client, because the
    // ASSERTION is the authorization grant rather than a client secret, and it runs the
    // scope check BEFORE the assertion is touched so an out-of-policy request cannot
    // spend a single-use jti. Together those mean a caller holding NO credential and a
    // garbage assertion reaches the allowlist check. While an allowlist refusal answered
    // invalid_scope and everything downstream answered invalid_grant, that caller could
    // separate an allowlisted scope from a non-allowlisted one ONE REQUEST AT A TIME and
    // read operator-written configuration off the wire.
    //
    // The proof is a differential: the SAME garbage assertion, two scopes that the
    // server demonstrably treats differently (the diagnostics below prove it took two
    // different paths), and a BYTE-IDENTICAL response.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    set_allowlist(&h, Some(&["read:orders".to_owned()])).await;

    let (allowed_status, allowed_headers, allowed_body) =
        present_with_scope(&h, &client_id, GARBAGE_ASSERTION, "read:orders").await;
    let (refused_status, refused_headers, refused_body) =
        present_with_scope(&h, &client_id, GARBAGE_ASSERTION, "admin").await;

    assert_eq!(
        allowed_status, refused_status,
        "the status must not separate an allowlisted scope from a rejected one"
    );
    assert_eq!(
        allowed_body, refused_body,
        "the body must not separate them either: {allowed_body} vs {refused_body}"
    );
    assert_eq!(
        allowed_headers, refused_headers,
        "and no header may separate them"
    );
    assert_eq!(
        json(&allowed_body)["error"],
        "invalid_grant",
        "both are the uniform invalid_grant: {allowed_body}"
    );

    // The server DID take two different paths, so the equality above is uniformity and
    // not an accident of both requests failing the same way. Out of band, where only an
    // operator can read it, the two are fully distinguished.
    let reasons: Vec<String> = h
        .client_auth_diagnostics(&client_id)
        .await
        .iter()
        .map(|d| d.failure_reason.clone())
        .collect();
    assert!(
        reasons.iter().any(|r| r == "scope_not_allowlisted"),
        "the non-allowlisted scope is diagnosed as such: {reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r == "assertion_issuer_untrusted"),
        "the allowlisted scope got past the allowlist and died on the assertion: {reasons:?}"
    );
}

#[tokio::test]
async fn the_denylist_floor_still_answers_invalid_scope_on_this_grant() {
    // The ONE deliberate exception to the uniformity above, pinned so it cannot be
    // widened by accident. `DISALLOWED_M2M_SCOPES` is a PUBLIC compile-time constant,
    // identical for every client and every deployment, so the spec-exact invalid_scope
    // discloses nothing; it predates the per-client allowlist and stays. What must not
    // happen is the floor answer leaking onto the per-client half, so this asserts the
    // floor answers invalid_scope EVEN WHEN the same request would also miss a
    // configured allowlist, and even when the allowlist NAMES the floor value.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    set_allowlist(&h, Some(&["read:orders".to_owned()])).await;

    for scope in ["openid", "offline_access"] {
        let (status, _h, resp) = present_with_scope(&h, &client_id, GARBAGE_ASSERTION, scope).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "scope `{scope}`: {resp}");
        assert_eq!(
            json(&resp)["error"],
            "invalid_scope",
            "the public floor keeps its spec-exact answer for `{scope}`: {resp}"
        );
    }

    // An allowlist that NAMES a floor value still refuses it, and still as the floor.
    set_allowlist(&h, Some(&["openid".to_owned()])).await;
    let (status, _h, resp) = present_with_scope(&h, &client_id, GARBAGE_ASSERTION, "openid").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert_eq!(
        json(&resp)["error"],
        "invalid_scope",
        "the floor runs first and answers first: {resp}"
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

/// The external `sub` a mapping to a LIFECYCLE-BEARING user principal is keyed on, kept
/// distinct from [`EXTERNAL_SUBJECT`] so a single harness can carry a user mapping and a
/// workload mapping from the SAME trusted issuer at once.
const EXTERNAL_HUMAN_SUBJECT: &str = "https://idp.partner.test/employees/e-4471";

/// Register the standard trusted issuer with TWO mappings from the same issuer: the
/// workload subject onto the opaque [`MAPPED_PRINCIPAL`], and `EXTERNAL_HUMAN_SUBJECT`
/// onto a freshly seeded real `usr_` account. Returns `(client_id, user_subject)`.
///
/// Both populations in ONE deployment is the point. The lifecycle fence has to refuse one
/// and pass the other on the same request path, against the same issuer trust, so a test
/// that seeded only the population it was interested in could not tell a working
/// discriminator from a fence that was simply off (or simply on).
async fn seed_user_and_workload_trust(h: &Harness, identifier: &str) -> (String, String) {
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
    let user_subject = h
        .seed_user(identifier, "correct-horse-battery-staple")
        .await;
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        None,
        None,
        &user_subject,
    )
    .await;
    (h.client_id().to_string(), user_subject)
}

#[tokio::test]
async fn a_fenced_mapped_user_principal_mints_no_jwt_bearer_token() {
    // The issue #52 invariant on the path that had NO fence of any kind (issue #241): a
    // blocked, disabled, or deleted user obtains no new tokens by ANY path, and a
    // TRUSTED EXTERNAL ISSUER holding a valid assertion is a path.
    //
    // It is a different threat model from the refresh grant's and narrower, which is why
    // it was deferred rather than shipped with #52. The fenced user holds no credential
    // here; a federated issuer the operator chose to trust does, and it keeps signing
    // fresh assertions on its own schedule. Nothing else in the request stops it. There
    // is no session to cascade (this grant never authenticates a human) and no refresh
    // family to re-check, so before this the ONLY thing standing between a terminated
    // employee's account and an indefinite stream of access tokens was an operator
    // remembering to also delete the mapping rule.
    let h = Harness::start().await;
    let (client_id, subject) = seed_user_and_workload_trust(&h, "fenced-human@example.test").await;

    // The control. While the account is ACTIVE the mapped assertion mints, and the token
    // carries the user's own subject. Without this the refusals below would be consistent
    // with the mapping never having worked at all.
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        h.issuer(),
        3600,
        "jti-human-active",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::OK, "active mapped user: {body}");
    let token = json(&body)["access_token"]
        .as_str()
        .expect("an active mapped user mints an access token")
        .to_owned();
    assert_eq!(
        jwt_payload(&token)["sub"],
        subject,
        "the token is minted under the mapped user's own subject"
    );

    // BLOCKED, the reversible fence. Fresh `jti`: the assertion is otherwise identical,
    // so the only thing that changed between a 200 and this refusal is the account state.
    h.set_user_state(&subject, ironauth_store::UserState::Blocked)
        .await;
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        h.issuer(),
        3600,
        "jti-human-blocked",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "blocked principal: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        json(&body).get("access_token").is_none(),
        "a blocked mapped user mints no access token"
    );
    // The wire is the uniform invalid_grant every other mapping failure answers, so the
    // operator's only channel is the out-of-band diagnostic, and it must distinguish a
    // FENCED account from a MISSING mapping. Told to go add a rule that already exists,
    // an operator would be debugging the wrong system.
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "principal_not_authenticatable"),
        "a fenced principal is diagnosed as fenced, not as unmapped"
    );

    // UNBLOCKED: the fence is a live read of current state rather than a latch, so
    // restoring the account restores the grant. This is also what makes the refusal above
    // attributable to `state_for_subject` and not to the spent `jti` or a poisoned
    // mapping.
    h.set_user_state(&subject, ironauth_store::UserState::Active)
        .await;
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        h.issuer(),
        3600,
        "jti-human-unblocked",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::OK, "unblocked principal: {body}");
    assert!(json(&body)["access_token"].is_string());

    // DELETED, the irreversible one. A soft-delete tombstone reads as absent, and absent
    // is fail CLOSED rather than "no state to check".
    h.delete_user(&subject).await;
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        h.issuer(),
        3600,
        "jti-human-deleted",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "deleted principal: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        json(&body).get("access_token").is_none(),
        "a deleted mapped user mints no access token"
    );
}

#[tokio::test]
async fn a_workload_principal_still_mints_while_a_user_principal_is_fenced() {
    // THE OUTAGE GUARD. This grant is the substrate under workload identity federation
    // (SPIRE JWT-SVIDs, Kubernetes projected tokens, GitHub Actions OIDC, issue #26),
    // where the mapped principal is a service account or a workload id and there is no
    // `users` row for it anywhere. `UserRepo::state_for_subject` queries the `users`
    // table, so a lifecycle re-check applied to a workload principal finds nothing and
    // FAILS CLOSED, refusing every legitimate workload assertion in the deployment. That
    // is a production outage in the shape of a hardening, and it is the failure this test
    // exists to make loud rather than the one the sibling test covers.
    //
    // The two mappings are deliberately in ONE harness, from ONE trusted issuer, on ONE
    // request path. So this is not "a workload mints" (which would stay green with the
    // fence deleted entirely, and would prove nothing); it is "a workload mints AT THE
    // SAME MOMENT a user principal is being refused", which is only true if the
    // discriminator is doing real work.
    let h = Harness::start().await;
    let (client_id, subject) = seed_user_and_workload_trust(&h, "fenced-peer@example.test").await;

    // Fence the human. The workload's mapping, issuer trust, and client are untouched.
    h.set_user_state(&subject, ironauth_store::UserState::Disabled)
        .await;
    let human = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        h.issuer(),
        3600,
        "jti-both-human",
    );
    let (status, _h, body) = present(&h, &client_id, &human).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the disabled user principal is refused: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    let fenced_before = fence_diagnostics(&h, &client_id).await;
    assert_eq!(
        fenced_before, 1,
        "the human refusal recorded exactly one fence diagnostic"
    );

    // The workload, in the same deployment, at the same instant, through the same code.
    let workload = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-both-workload",
    );
    let (status, _h, body) = present(&h, &client_id, &workload).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a workload principal carries no lifecycle and must still mint: {body}"
    );
    let token = json(&body)["access_token"]
        .as_str()
        .expect("a workload assertion mints an access token")
        .to_owned();
    assert_eq!(
        jwt_payload(&token)["sub"],
        MAPPED_PRINCIPAL,
        "the workload token is minted under the workload principal"
    );
    // The workload exchange recorded NO new fence diagnostic. It did not merely survive
    // the lifecycle read, it never performed one: a `users` lookup that happened to
    // succeed would be a latent outage waiting on the first deployment whose workload
    // principal is not also a user id.
    assert_eq!(
        fence_diagnostics(&h, &client_id).await,
        fenced_before,
        "the workload exchange performed no lifecycle read and recorded no fence"
    );
}

/// How many `principal_not_authenticatable` diagnostics this client has accumulated.
async fn fence_diagnostics(h: &Harness, client_id: &str) -> usize {
    h.client_auth_diagnostics(client_id)
        .await
        .iter()
        .filter(|d| d.failure_reason == "principal_not_authenticatable")
        .count()
}

#[tokio::test]
async fn a_mapped_user_principal_from_another_scope_is_refused_rather_than_treated_as_a_workload() {
    // The edge a two-valued discriminator gets wrong. "Does the principal parse as a
    // UserId in THIS scope" has three answers, not two: a well-formed user id belonging
    // to ANOTHER tenant or environment fails that parse for exactly the same reason an
    // opaque workload string does. Told apart by a single boolean, it lands in the
    // workload branch and mints a USER-BOUND token with no lifecycle check at all, for a
    // subject whose state this scope cannot even read (RLS and the tenant/environment SQL
    // filter both stop it). Unfenceable and unfenced is the exact combination issue #241
    // exists to prevent, so `MappedPrincipal::ForeignUser` refuses it.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;

    // A real, ACTIVE user id minted in another scope. Active on purpose: the refusal must
    // come from the principal being unreachable here, never from it happening to be
    // fenced over there.
    let foreign_scope = h.provision_foreign_scope().await;
    let foreign_subject = ironauth_store::UserId::generate(h.env(), &foreign_scope).to_string();
    h.create_subject_mapping(
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        None,
        None,
        &foreign_subject,
    )
    .await;

    let client_id = h.client_id().to_string();
    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_HUMAN_SUBJECT,
        h.issuer(),
        3600,
        "jti-foreign-principal",
    );
    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a cross-scope user principal is refused: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        json(&body).get("access_token").is_none(),
        "an unfenceable user-bound principal mints nothing"
    );
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "principal_not_authenticatable"),
        "a cross-scope user principal is diagnosed as not authenticatable"
    );
}

/// A per-issuer audience allowlist NARROWS the shared policy (issue #126 criterion 3).
///
/// Criterion 3 asks for per-issuer trust policies over "audience, algorithm, and
/// subject-claim constraints". Algorithm and subject-claim were already per-issuer; audience
/// came from the ONE deployment-wide policy, so an assertion addressed to that audience was
/// acceptable from ANY registered issuer. A GitHub Actions token and a Kubernetes projected
/// token land at the same audience, and a trust anchor that should only ever speak to one
/// could present assertions addressed to another's.
///
/// Three cases, because the rule is a narrowing and one case cannot state it:
///
/// * an issuer whose allowlist CONTAINS the audience still exchanges -- the narrowing must
///   not break the issuer it was configured for;
/// * an issuer whose allowlist EXCLUDES it is refused, which is the constraint itself;
/// * an issuer with NO allowlist is unaffected, which is what keeps every issuer registered
///   before this column existed behaving exactly as it did.
#[tokio::test]
async fn a_per_issuer_audience_allowlist_narrows_the_shared_policy() {
    let key = issuer_key();
    let jwks = jwks_json(&key);

    // The audience the shared policy permits, which this deployment's assertions use.
    let harness = Harness::start().await;
    let permitted = harness.state().token_endpoint_url();

    // CASE 1: the allowlist contains the audience -> still exchanges.
    let allowed_issuer = "https://allowed.issuer.test";
    harness
        .register_external_issuer_with_audiences(
            allowed_issuer,
            Some(&jwks),
            None,
            None,
            Some(&permitted),
            true,
        )
        .await;
    harness
        .create_subject_mapping(
            allowed_issuer,
            EXTERNAL_SUBJECT,
            None,
            None,
            MAPPED_PRINCIPAL,
        )
        .await;
    let client_id = harness.client_id().to_string();
    let ok = assertion(
        &key,
        allowed_issuer,
        EXTERNAL_SUBJECT,
        &permitted,
        3600,
        "jti-aud-allowed",
    );
    let (status, _h, body) = present(&harness, &client_id, &ok).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an issuer whose allowlist contains the audience must still exchange: {body}"
    );

    // CASE 2: the allowlist EXCLUDES the audience -> refused, even though the shared policy
    // permits it and the assertion is otherwise valid.
    let fenced_issuer = "https://fenced.issuer.test";
    harness
        .register_external_issuer_with_audiences(
            fenced_issuer,
            Some(&jwks),
            None,
            None,
            Some("https://someone.elses.audience.test"),
            true,
        )
        .await;
    harness
        .create_subject_mapping(
            fenced_issuer,
            EXTERNAL_SUBJECT,
            None,
            None,
            MAPPED_PRINCIPAL,
        )
        .await;
    let fenced = assertion(
        &key,
        fenced_issuer,
        EXTERNAL_SUBJECT,
        &permitted,
        3600,
        "jti-aud-fenced",
    );
    let (status, _h, body) = present(&harness, &client_id, &fenced).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an issuer may not address an audience outside its own allowlist: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");

    // CASE 3: no allowlist -> the shared policy applies unchanged.
    let open_issuer = "https://open.issuer.test";
    harness
        .register_external_issuer(open_issuer, Some(&jwks), None, None, true)
        .await;
    harness
        .create_subject_mapping(open_issuer, EXTERNAL_SUBJECT, None, None, MAPPED_PRINCIPAL)
        .await;
    let open = assertion(
        &key,
        open_issuer,
        EXTERNAL_SUBJECT,
        &permitted,
        3600,
        "jti-aud-open",
    );
    let (status, _h, body) = present(&harness, &client_id, &open).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an issuer with no allowlist keeps the shared policy: {body}"
    );
}

/// A successful federated issuance names the external issuer and subject in the audit
/// stream (issue #126 criterion 5).
///
/// The grant already recorded the MAPPED principal. What the trail could not answer is
/// WHICH trust anchor vouched for it -- so an operator responding to a compromised issuer
/// could not tell which issuances came from it. The audit said a machine principal received
/// a token and not who said it should.
///
/// The assertion itself is deliberately absent from the detail: it is a live credential, and
/// an audit row is a wider audience than the exchange that produced it.
#[tokio::test]
async fn a_successful_issuance_names_the_external_issuer_and_subject_in_the_audit() {
    let harness = Harness::start().await;
    let client_id = seed_trust(&harness).await;
    let key = issuer_key();
    let assertion = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        &harness.state().token_endpoint_url(),
        3600,
        "jti-audit-detail",
    );
    let (status, _h, body) = present(&harness, &client_id, &assertion).await;
    assert_eq!(status, StatusCode::OK, "the exchange succeeds: {body}");

    let rows = harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("read the audit trail");
    let issuance = rows
        .iter()
        .find(|row| row.action == "jwt_bearer_assertion.issue")
        .expect("a successful federated issuance is audited");
    let detail = issuance
        .detail
        .as_deref()
        .expect("the issuance audit row carries a detail");
    let parsed: serde_json::Value = serde_json::from_str(detail).expect("detail is json");
    assert_eq!(
        parsed["external_issuer"], EXTERNAL_ISSUER,
        "the trail must name the trust anchor that vouched: {detail}"
    );
    assert_eq!(
        parsed["external_subject"], EXTERNAL_SUBJECT,
        "and the external subject it asserted: {detail}"
    );
    assert!(
        !detail.contains(&assertion),
        "the assertion is a live credential and must never land in an audit row"
    );
}

/// A GitHub Actions-shaped workload token exchanges under the MAPPED identity, and the
/// subject gate binds the exact repository and ref (issue #126 criterion 1).
///
/// GitHub's `sub` is structured -- `repo:{owner}/{repo}:ref:refs/heads/{branch}` -- and the
/// security value of federating to it is that a workflow on main is a different principal
/// from one on a branch, from a tag of the same name, or from another repository.
///
/// # Which negative closes which comparison, MEASURED
///
/// An earlier version carried five near-misses and asserted in its own doc that each caught
/// something the others did not. That was false: deleting `refs/heads/feature` and
/// `repo:acme/service-staging` changed no mutant outcome at all. They are gone.
///
/// The version after that made a weaker form of the same mistake, twice. It claimed "each
/// entry below names the ONE mutant only it kills", which was true when written and stopped
/// being true as anchors were added, because a later anchor can cover an earlier one's shape
/// by accident. So this section is derived from a measurement that is re-run whenever an
/// anchor changes, and it distinguishes what is uniquely load-bearing from what is not.
///
/// THE MEASUREMENT. Sixteen wrong-comparison shapes over the subject predicate of the
/// mapping lookup (`crates/ironauth-store/src/repository.rs`, `AssertionSubjectMappingRepo::
/// resolve`), each applied alone, verified present in the source before running and restored
/// byte-identically after. ALL SIXTEEN ARE CAUGHT. Then each negative was NEUTRALIZED in
/// turn, against each shape, to find which shapes survive without it:
///
/// | shape | the negative that is its SOLE killer |
/// |---|---|
/// | CASE-INSENSITIVE, `lower(...) = lower(...)` | `refs/heads/Main` |
/// | WHITESPACE-NORMALIZING, `btrim(...) = btrim(...)` | the unpadded form of the stored-padded mapping |
/// | NFKC-NORMALIZING, `normalize(...) = normalize(...)` | `...refs/heads/ma`U+FF49`n` |
/// | TAG/BRANCH conflation, `replace($2, 'refs/tags/', 'refs/heads/') = ...` | `refs/tags/main` |
/// | STORED-PATTERN, `$2 LIKE external_subject` | the wildcard-bearing stored mapping |
/// | PATH-NORMALIZING, `rtrim(...,'/') = rtrim(...,'/')` | `...refs/heads/main/` |
///
/// The other ten shapes (prefix, suffix, substring and all three reverses, the presented-side
/// bare `LIKE`, trailing-component, and the two component-ignoring comparisons) are caught by
/// MORE THAN ONE negative, so no single deletion reveals them. That is not a defect and the
/// redundant anchors stay: what was a defect was claiming a uniqueness the measurement does
/// not support.
///
/// Three of the shapes deserve their reasoning rather than a table row.
///
/// REVERSE-PREFIX is strictly more reachable than any attacker-anchor case on the issuer
/// axis: it needs no registration at all, only a branch name the workflow can mint, and its
/// degenerate form (`repo:`) matches every mapping in the environment. The empty string does
/// not, on this axis: `validate_and_map` rejects an empty `sub` before the lookup.
///
/// The presented-side bare `LIKE` is the one shape where the ATTACKER supplies the pattern,
/// and every anchor here except the wildcard ones is a metacharacter-free literal, so the
/// whole set was blind to it until those were added. `_` and `%` are both legal in a git ref.
///
/// The two NORMALIZING shapes are a different family: every other shape compares the strings
/// AS GIVEN, so a near-miss built by editing characters reaches it, while these compare after
/// a transform, so the difference has to SURVIVE the transform. Both are one function call
/// away in Postgres, and the same class exists on the issuer axis.
///
/// CASE-INSENSITIVE is currently safe only because the column is `text` under a deterministic
/// collation, which nothing else in this tree pins.
#[tokio::test]
// One linear walk over one fixture: the positive, then every negative that closes a
// comparison shape, then the stored-whitespace anchor that needs its own mapping. Splitting
// it would re-seed the same issuer and mapping several times to assert on one string each,
// and the attribution table above is only checkable because all of them share one fixture.
#[allow(clippy::too_many_lines)]
async fn a_github_actions_shaped_workload_token_binds_the_exact_repository_and_ref() {
    const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
    const MAIN_SUBJECT: &str = "repo:acme/service:ref:refs/heads/main";
    // A mapping stored WITH trailing whitespace, for the whitespace-normalizing shape. See
    // the comment at its assertions below for why the anchor has to be on the stored side.
    const PADDED_MAPPING_SUBJECT: &str = "repo:acme/padded:ref:refs/heads/main ";
    // And one stored WITH a LIKE metacharacter, for the shape where the STORED value is the
    // pattern. `_` matches any single character, so under `$2 LIKE external_subject` this
    // row would fire for `repo:acme/wildcard:ref:refs/heads/main`; under `=` it fires for
    // nothing but itself.
    const WILDCARD_MAPPING_SUBJECT: &str = "repo:acme/wildcard:ref:refs/heads/ma_n";

    let harness = Harness::start().await;
    let key = issuer_key();
    let jwks = jwks_json(&key);
    harness
        .register_external_issuer(GITHUB_ISSUER, Some(&jwks), None, None, true)
        .await;
    harness
        .create_subject_mapping(GITHUB_ISSUER, MAIN_SUBJECT, None, None, MAPPED_PRINCIPAL)
        .await;
    let client_id = harness.client_id().to_string();
    let aud = harness.state().token_endpoint_url();

    // The mapped workflow exchanges its ambient token for a token issued under the MAPPED
    // principal. Asserting the `sub` is the point: a 200 alone would still pass if the
    // exchange issued under the EXTERNAL subject, which would mean the mapping did nothing.
    let ok = assertion(
        &key,
        GITHUB_ISSUER,
        MAIN_SUBJECT,
        &aud,
        3600,
        "jti-gha-main",
    );
    let (status, _h, body) = present(&harness, &client_id, &ok).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the mapped workflow must exchange: {body}"
    );
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    assert_eq!(
        jwt_payload(&access)["sub"],
        MAPPED_PRINCIPAL,
        "the token must be issued under the MAPPED principal, not the external subject"
    );

    for (subject, jti) in [
        (
            "repo:acme/service:ref:refs/heads/main-old",
            "jti-gha-extends",
        ),
        ("repo:acme/service:ref:refs/tags/main", "jti-gha-tag"),
        ("Xrepo:acme/service:ref:refs/heads/main", "jti-gha-suffix"),
        ("repo:acme/service:ref:refs/heads/Main", "jti-gha-case"),
        ("repo:acme/other:ref:refs/heads/main", "jti-gha-other-repo"),
        (
            "repo:evil/service:ref:refs/heads/main",
            "jti-gha-other-owner",
        ),
        (
            "repo:acme/service:ref:refs/heads/mai",
            "jti-gha-sub-revprefix",
        ),
        ("refs/heads/main", "jti-gha-sub-revsuffix"),
        (
            "repo:acme/service:ref:refs/heads/ma\u{ff49}n",
            "jti-gha-sub-nfkc",
        ),
    ] {
        let attempt = assertion(&key, GITHUB_ISSUER, subject, &aud, 3600, jti);
        let (status, _h, body) = present(&harness, &client_id, &attempt).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "`{subject}` is not the mapped subject and must be refused: {body}"
        );
        assert_eq!(json(&body)["error"], "invalid_grant", "for `{subject}`");
    }

    // THE COMPARISON IS EXACT ON BOTH SIDES, and getting here took a production change.
    //
    // The obvious anchor for the whitespace-normalizing shape is a presented subject with a
    // trailing space, and on the code this PR started from it EXCHANGED: `validate_and_map`
    // ran `str::trim` over the verified `sub` before the lookup. That is not a coverage gap,
    // it is an open gate, and it is wider than a space. `str::trim` strips the whole Unicode
    // `White_Space` set, so `...refs/heads/main` followed by U+00A0, U+2028, U+202F or
    // U+3000 was each issued the mapped principal, and git forbids none of those in a ref
    // name. About twenty-five distinct subject strings reached every registered mapping.
    //
    // `validate_and_map` now trims only to decide EMPTINESS and passes the signed subject
    // through unchanged, so both sides of the comparison are exact. Three things follow, and
    // all three are pinned below.
    //
    // 1. A mapping stored WITH whitespace fires for exactly that subject and nothing else.
    //    The operator trap is still there (a pasted trailing space makes a mapping that the
    //    provider's real subject will never match) but it is now the ordinary consequence of
    //    an exact comparison rather than a row that can never fire at all.
    // 2. It is the only way to reach `btrim(external_subject) = btrim($2)`, which under the
    //    mutant makes the padded mapping fire for the UNPADDED subject.
    // 3. The Unicode variants are refused, which is what the name of this test claims.
    harness
        .create_subject_mapping(
            GITHUB_ISSUER,
            PADDED_MAPPING_SUBJECT,
            None,
            None,
            MAPPED_PRINCIPAL,
        )
        .await;
    // The stored padded mapping matches its own exact subject, and nothing else.
    let exact_pad = assertion(
        &key,
        GITHUB_ISSUER,
        PADDED_MAPPING_SUBJECT,
        &aud,
        3600,
        "jti-gha-stored-pad-exact",
    );
    let (status, _h, body) = present(&harness, &client_id, &exact_pad).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a mapping stored WITH whitespace must fire for exactly that subject: {body}"
    );
    assert_eq!(
        jwt_payload(json(&body)["access_token"].as_str().expect("access_token"))["sub"],
        MAPPED_PRINCIPAL
    );

    // WILDCARDS AND WHITESPACE, the two families no literal near-miss can reach.
    //
    // Every negative above differs from the mapped subject in its visible characters, so all
    // of them are metacharacter-free literals. Two shapes are invisible to that whole set:
    //
    // * `external_subject LIKE $2` (no concatenation at all), where the ATTACKER supplies
    //   the pattern. `_` and `%` are legal in a git ref name, so `...heads/mai_` is a branch
    //   a workflow can create, and a bare `%` matches every mapping in the environment. This
    //   is the most reachable shape measured against this file, and every anchor here was
    //   blind to it because none of them contains a metacharacter.
    // * `$2 LIKE external_subject`, the mirror, where the STORED value is the pattern. It
    //   behaves identically to `=` for every wildcard-free mapping, so it needs a mapping
    //   that CONTAINS a wildcard to be detectable at all.
    // * the Unicode whitespace family, reachable only because the grant used to normalize.
    harness
        .create_subject_mapping(
            GITHUB_ISSUER,
            WILDCARD_MAPPING_SUBJECT,
            None,
            None,
            MAPPED_PRINCIPAL,
        )
        .await;
    for (subject, jti, why) in [
        (
            "repo:acme/service:ref:refs/heads/mai_",
            "jti-gha-like-underscore",
            "a ref containing a LIKE single-character wildcard",
        ),
        (
            "repo:acme/service:ref:refs/heads/%",
            "jti-gha-like-percent",
            "a ref containing a LIKE any-sequence wildcard",
        ),
        (
            "%",
            "jti-gha-like-bare",
            "a bare LIKE any-sequence wildcard",
        ),
        (
            "repo:acme/wildcard:ref:refs/heads/main",
            "jti-gha-like-stored-pattern",
            "the subject a WILDCARD-BEARING stored mapping would match under LIKE",
        ),
        (
            "repo:acme/service:ref:refs/heads/main\u{a0}",
            "jti-gha-ws-nbsp",
            "a trailing NO-BREAK SPACE, legal in a git ref",
        ),
        (
            "\u{3000}repo:acme/service:ref:refs/heads/main",
            "jti-gha-ws-ideographic",
            "a leading IDEOGRAPHIC SPACE",
        ),
        (
            "repo:acme/service:ref:refs/heads/main\u{2028}",
            "jti-gha-ws-linesep",
            "a trailing LINE SEPARATOR",
        ),
        (
            PADDED_MAPPING_SUBJECT.trim(),
            "jti-gha-stored-pad-trimmed",
            "the UNPADDED form of a mapping stored with a trailing space",
        ),
        (
            "repo:acme/service:ref:refs/heads/main/",
            "jti-gha-trailing-slash",
            "a trailing slash, which a path-normalizing comparison would forgive",
        ),
    ] {
        let attempt = assertion(&key, GITHUB_ISSUER, subject, &aud, 3600, jti);
        let (status, _h, body) = present(&harness, &client_id, &attempt).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{why} must be refused (`{subject}`): {body}"
        );
        assert_eq!(json(&body)["error"], "invalid_grant", "for `{subject}`");
    }
}

/// A mapping registered for ONE issuer does not fire for another (issue #126 criterion 3:
/// per-issuer trust policies).
///
/// This is the gap the first version of these fixtures walked straight past. It registered
/// two providers and put them in SEPARATE harnesses, so nothing ever presented one issuer's
/// subject under the other's identity -- and dropping the issuer predicate from the mapping
/// lookup entirely left the whole suite green.
///
/// The attack it covers is concrete: a deployment federating to both GitHub Actions and a
/// Kubernetes cluster has two trust anchors. If the mapping matched on subject alone, anyone
/// who can mint a token from the WEAKER anchor with the stronger one's subject string gets
/// the stronger one's identity. Federating to a second issuer would silently widen the first.
///
/// # The one shape left OPEN, stated precisely
///
/// An issuer-SUFFIX comparison, `$1 LIKE '%' || issuer`, is not closed. Applying that mutant
/// leaves this binary green. Stating the gap precisely matters, because the obvious statement
/// of it is wrong in the reassuring direction.
///
/// GIVEN THE SCHEME-BEARING ANCHORS THIS TEST REGISTERS, the shape is unreachable: a
/// triggering issuer would have to end with the entire stored string INCLUDING the
/// `https://`, so the anchor would be something like
/// `https://evil.test/https://token.actions.githubusercontent.com`, which nothing publishes.
/// An early draft used `https://evil.test/token.actions.githubusercontent.com`, which LOOKS
/// like it exercises the shape and does not: it lacks the inner scheme, matches nothing, and
/// was decoration.
///
/// That is a fact about THIS ANCHOR, not about the shape, and the difference is the whole
/// point. Nothing makes a stored issuer carry a scheme: `external_assertion_issuers.issuer`
/// is plain `text NOT NULL`
/// (`crates/ironauth-store/migrations/0020_jwt_bearer_assertion.sql`), `register()` parses no
/// URL, and the grant passes the presented `iss` through as an opaque string. Against a
/// scheme-less anchor -- a bare host, or the LEGACY Kubernetes service-account issuer
/// `kubernetes/serviceaccount`, which predates the projected token this file's own fixture
/// uses -- the trigger is an ordinary URL: `https://evil.test/kubernetes/serviceaccount` ends
/// with `kubernetes/serviceaccount`, and a suffix comparison would hand over its principal.
///
/// The shipped query uses `=`, so this is a COVERAGE GAP and not a live defect. It stays open
/// rather than being closed with a second anchor because "should `register()` demand a URL at
/// all" is its own question, and answering it inside a fixture test would bury it.
///
/// Its MIRROR is closed. `issuer LIKE '%' || $1` survived every earlier round and is killed
/// by `ISSUER_A_BARE_HOST` below, which is cheaper to reach than the shape above: it needs
/// only a scheme-less registration, which the paragraph above establishes is possible. Its
/// degenerate form is worse still, since an anchor registered as the empty string makes
/// `issuer LIKE '%'` match every mapping in the environment.
#[tokio::test]
// One fixture, two registered providers, and every adjacent issuer anchor presented against
// it. Splitting it would re-register the same two anchors and re-create the same mapping to
// assert on one issuer string each, and the cross-issuer question is only askable with both
// providers in ONE environment, which is the gap the first version of this file walked past.
#[allow(clippy::too_many_lines)]
async fn a_mapping_for_one_issuer_does_not_fire_for_another() {
    const ISSUER_A: &str = "https://token.actions.githubusercontent.com";
    const ISSUER_B: &str = "https://kubernetes.default.svc.cluster.local";
    // An issuer that EXTENDS ISSUER_A. A domain an attacker can genuinely register, and it
    // extends the real issuer exactly the way a prefix comparison accepts.
    const ISSUER_A_EXTENDED: &str = "https://token.actions.githubusercontent.com.evil.test";
    // And one that is a strict PREFIX of ISSUER_A. `...githubusercontent.co` is a registrable
    // `.co` domain, so this is the same typosquat class in the opposite direction: an issuer
    // comparison written `issuer LIKE $1 || '%'` matches the stored `...com` mapping and
    // hands over its principal.
    const ISSUER_A_TRUNCATED: &str = "https://token.actions.githubusercontent.co";
    // And one differing only in CASE. DNS is case-insensitive, so an operator can register
    // this as a distinct row while it addresses the same host.
    const ISSUER_A_CASED: &str = "https://Token.Actions.GitHubUserContent.com";
    // A SUFFIX of the mapped issuer: the bare host, with no scheme. Closes the mirror of the
    // gap in this test's doc comment; see there for why a scheme-less anchor is registrable.
    const ISSUER_A_BARE_HOST: &str = "token.actions.githubusercontent.com";
    // And two that differ from ISSUER_A only under a TRANSFORM, not in their visible
    // characters. Every anchor above is built by editing the string, so none of them can
    // reach a comparison that normalizes before comparing -- the difference has to survive
    // the transform. `btrim` and `normalize(..., NFKC)` are both one function call away in
    // Postgres, and an operator pasting an issuer URL out of a console is exactly how a
    // trailing space gets into a registration in the first place.
    const ISSUER_A_PADDED: &str = "https://token.actions.githubusercontent.com ";
    // U+FF43 is the FULLWIDTH LATIN SMALL LETTER C; NFKC maps it onto plain `c`, so this
    // normalizes to ISSUER_A while being a different string of bytes. A homoglyph domain is
    // registrable, which makes this the same typosquat class as the two above it.
    const ISSUER_A_FULLWIDTH: &str = "https://token.actions.githubusercontent.\u{ff43}om";
    // And one differing only by a TRAILING SLASH. An issuer URL written with and without one
    // is an everyday normalization question, `rtrim(issuer, '/') = rtrim($1, '/')` is one
    // function call away, and an operator registering both variants is the same reachability
    // class as the cased anchor above.
    const ISSUER_A_TRAILING_SLASH: &str = "https://token.actions.githubusercontent.com/";
    // An issuer containing a LIKE metacharacter. `_` matches any single character, so under
    // `issuer LIKE $1` (where the PRESENTED value is the pattern) this matches the stored
    // `...com`, and under `$1 LIKE issuer` (where the STORED value is the pattern) the
    // mapping registered for it below matches a presented `...com`. Every other anchor here
    // is a metacharacter-free literal and is blind to both.
    const ISSUER_A_LIKE_PATTERN: &str = "https://token.actions.githubusercontent.co_";
    // The subject that mapping carries, distinct from every other in this test so the only
    // way to reach it is through the issuer comparison.
    const PATTERN_ISSUER_SUBJECT: &str = "repo:acme/patternissuer:ref:refs/heads/main";
    // And one differing from ISSUER_A only in SCHEME, for a comparison that comes down to
    // the host. `http` against `https` is the difference that matters most here, since the
    // whole trust anchor is the origin.
    const ISSUER_A_HTTP: &str = "http://token.actions.githubusercontent.com";
    const SHARED_SUBJECT: &str = "repo:acme/service:ref:refs/heads/main";

    let harness = Harness::start().await;
    let key = issuer_key();
    let jwks = jwks_json(&key);
    // BOTH anchors registered in ONE environment, which is the arrangement that makes the
    // cross-issuer question askable at all.
    for issuer in [ISSUER_A, ISSUER_B] {
        harness
            .register_external_issuer(issuer, Some(&jwks), None, None, true)
            .await;
    }
    // The mapping exists for A only.
    harness
        .create_subject_mapping(ISSUER_A, SHARED_SUBJECT, None, None, MAPPED_PRINCIPAL)
        .await;
    let client_id = harness.client_id().to_string();
    let aud = harness.state().token_endpoint_url();

    // Control: under A it exchanges, so the refusal below cannot be a broken fixture.
    let under_a = assertion(&key, ISSUER_A, SHARED_SUBJECT, &aud, 3600, "jti-xiss-a");
    let (status, _h, body) = present(&harness, &client_id, &under_a).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the mapped issuer exchanges: {body}"
    );
    assert_eq!(
        jwt_payload(json(&body)["access_token"].as_str().expect("access_token"))["sub"],
        MAPPED_PRINCIPAL,
        "the control must pin the IDENTITY too: without this it is the one positive that \
         would still pass under a resolver that ignores the mapping entirely"
    );

    // The same subject, signed by the same key, presented under the OTHER registered issuer.
    // Only the mapping's issuer binding can refuse this.
    let under_b = assertion(&key, ISSUER_B, SHARED_SUBJECT, &aud, 3600, "jti-xiss-b");
    let (status, _h, body) = present(&harness, &client_id, &under_b).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a mapping registered for one issuer must not fire for another: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");

    // SEVEN ADJACENT ANCHORS, each registered as its own enabled issuer with no mapping of
    // its own, so only the mapping lookup's exact `=` on the issuer can refuse it. The
    // anchors mirror the comparisons a reader could plausibly write, in both directions.
    //
    // NOT "one anchor closes exactly one shape". That claim was here and is false, in the
    // same way and for the same reason it was false on the subject axis: a later anchor can
    // cover an earlier one's shape by accident. Measured, `ISSUER_A_PADDED` starts with the
    // stored issuer, so it kills the PREFIX and SUBSTRING shapes as well as the whitespace
    // one, and `ISSUER_A_EXTENDED` therefore uniquely closes nothing. The per-shape
    // attribution is in the table on `a_github_actions_shaped_workload_token_...` for the
    // subject axis; on this axis the honest statement is that all seven are kept, every
    // issuer shape measured is caught, and no anchor here is claimed to be the sole killer
    // of anything.
    //
    // Reaching any of them requires an operator to have registered that anchor as enabled,
    // which is the multi-anchor deployment criterion 3 contemplates.
    for (issuer, jti, shape) in [
        // `token.actions.githubusercontent.com.evil.test` is a domain an attacker can
        // genuinely register, and it extends the real issuer exactly the way a prefix
        // comparison accepts.
        (
            ISSUER_A_EXTENDED,
            "jti-xiss-ext",
            "EXTENDS the mapped issuer (a prefix comparison)",
        ),
        // The opposite direction: a comparison written the other way round survives the
        // extended anchor.
        (
            ISSUER_A_TRUNCATED,
            "jti-xiss-trunc",
            "is a PREFIX of the mapped issuer (a reverse-prefix comparison)",
        ),
        (
            ISSUER_A_CASED,
            "jti-xiss-case",
            "differs from the mapped issuer only in CASE",
        ),
        (
            ISSUER_A_BARE_HOST,
            "jti-xiss-bare-host",
            "is a SUFFIX of the mapped issuer (the mirror of the gap noted below)",
        ),
        (
            ISSUER_A_PADDED,
            "jti-xiss-padded",
            "equals the mapped issuer after btrim",
        ),
        (
            ISSUER_A_FULLWIDTH,
            "jti-xiss-nfkc",
            "equals the mapped issuer after NFKC normalization",
        ),
        (
            ISSUER_A_TRAILING_SLASH,
            "jti-xiss-slash",
            "equals the mapped issuer after a trailing slash is stripped",
        ),
        (
            ISSUER_A_LIKE_PATTERN,
            "jti-xiss-like-pattern",
            "matches the mapped issuer when read as a LIKE pattern",
        ),
        (
            ISSUER_A_HTTP,
            "jti-xiss-scheme",
            "differs from the mapped issuer only in scheme",
        ),
    ] {
        harness
            .register_external_issuer(issuer, Some(&jwks), None, None, true)
            .await;
        let attempt = assertion(&key, issuer, SHARED_SUBJECT, &aud, 3600, jti);
        let (status, _h, body) = present(&harness, &client_id, &attempt).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an issuer that {shape} must not inherit its mappings: {body}"
        );
        assert_eq!(json(&body)["error"], "invalid_grant", "for `{issuer}`");
    }

    // THE MIRROR, where the STORED issuer is the pattern. `$1 LIKE issuer` behaves exactly
    // like `=` for every metacharacter-free mapping, so it needs a mapping whose ISSUER
    // carries a wildcard to be detectable at all. Its subject is unique to this mapping, so
    // presenting it under ISSUER_A can only succeed by way of the issuer comparison.
    harness
        .create_subject_mapping(
            ISSUER_A_LIKE_PATTERN,
            PATTERN_ISSUER_SUBJECT,
            None,
            None,
            MAPPED_PRINCIPAL,
        )
        .await;
    let via_pattern = assertion(
        &key,
        ISSUER_A,
        PATTERN_ISSUER_SUBJECT,
        &aud,
        3600,
        "jti-xiss-stored-pattern",
    );
    let (status, _h, body) = present(&harness, &client_id, &via_pattern).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a mapping stored against a WILDCARD-BEARING issuer must not fire for an issuer \
         that merely matches it as a pattern: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
}

/// A Kubernetes projected service-account token exchanges through the same model (issue #126
/// criterion 2).
///
/// Deliberately modest about what this proves. There is no code path that branches on subject
/// SHAPE -- the subject travels as an opaque string into a SQL equality -- and this file
/// already exercises a third shape (`spiffe://...`) across many tests. So this is not
/// evidence that "a second shape needs no special case"; it is a provider-shaped fixture for
/// criterion 2, which asks for one by name.
#[tokio::test]
async fn a_kubernetes_projected_token_exchanges_under_the_mapped_identity() {
    const K8S_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
    const K8S_SUBJECT: &str = "system:serviceaccount:payments:checkout";

    let harness = Harness::start().await;
    let key = issuer_key();
    let jwks = jwks_json(&key);
    harness
        .register_external_issuer(K8S_ISSUER, Some(&jwks), None, None, true)
        .await;
    harness
        .create_subject_mapping(K8S_ISSUER, K8S_SUBJECT, None, None, MAPPED_PRINCIPAL)
        .await;
    let client_id = harness.client_id().to_string();
    let aud = harness.state().token_endpoint_url();

    let ok = assertion(&key, K8S_ISSUER, K8S_SUBJECT, &aud, 3600, "jti-k8s-ok");
    let (status, _h, body) = present(&harness, &client_id, &ok).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a projected token must exchange: {body}"
    );
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    assert_eq!(jwt_payload(&access)["sub"], MAPPED_PRINCIPAL);

    // A different service account in the same namespace is a different principal.
    let other = assertion(
        &key,
        K8S_ISSUER,
        "system:serviceaccount:payments:refunds",
        &aud,
        3600,
        "jti-k8s-other",
    );
    let (status, _h, body) = present(&harness, &client_id, &other).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "another service account in the same namespace must be refused: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
}
