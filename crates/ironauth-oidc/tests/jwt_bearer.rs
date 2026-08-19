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
use std::time::{Duration, SystemTime};

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

/// A JWKS server that answers 200 ONCE and then 500 to every later request.
///
/// Lets a test prime the cache from a healthy upstream and then make the rotation refetch
/// fail, which is the only way to observe the fallback: the recording dialer cannot be
/// retargeted mid-test.
async fn start_jwks_server_failing_after_first(body: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let mut buf = [0_u8; 2048];
                let _ = socket.read(&mut buf).await;
                let n = served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let response = if n == 0 {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                };
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

/// Build a resolver over a recording dialer serving `jwks`, returning both so a test can
/// count outbound fetches. DB-free: this exercises `ClientKeyResolver` directly.
async fn counting_resolver(
    jwks: String,
    ttl: Duration,
) -> (
    Arc<ironauth_oidc::ClientKeyResolver>,
    Arc<RecordingDialer>,
    String,
) {
    let server = start_jwks_server(jwks).await;
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = Arc::new(ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        ttl,
    ));
    (resolver, dialer, "http://jwks.test/keys".to_owned())
}

/// An unknown `kid` triggers exactly ONE refetch however many times it is presented, and a
/// known `kid` triggers none (issue #126 criterion 4).
///
/// Both halves matter and neither alone is sufficient. Without the second, an implementation
/// that refetched on EVERY request would pass the first. Without the first, an implementation
/// where the whole feature is inert would pass the second -- which is exactly the state the
/// review found: two mutants, "delete the rate limit" and "make the feature inert", both
/// survived the entire suite because nothing counted fetches.
///
/// All requests are made at the SAME instant, deep inside the 30s window, so this measures
/// the bound and not the clock.
#[tokio::test]
async fn an_unknown_kid_refetches_once_and_a_known_kid_never_does() {
    let key = issuer_key();
    let (resolver, dialer, uri) =
        counting_resolver(jwks_json(&key), Duration::from_secs(300)).await;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    // Prime the cache.
    let keys = resolver.resolve(now, &uri).await;
    assert!(!keys.is_empty(), "the fixture must serve a usable key set");
    assert_eq!(dialer.requested().len(), 1, "priming is one fetch");

    // A KNOWN kid is answered from cache: no outbound request at all.
    let known = keys[0]
        .kid()
        .expect("the fixture key carries a kid")
        .to_owned();
    for _ in 0..5 {
        resolver.resolve_for_kid(now, &uri, Some(&known)).await;
    }
    assert_eq!(
        dialer.requested().len(),
        1,
        "a kid already in the cached set must never cause a fetch"
    );

    // TEN forged kids at the same instant cost ONE fetch between them. Before the rework
    // this measured 11 -- `store()` reset the rate-limit marker the refetch had just set, so
    // every forged kid fetched again.
    for i in 0..10 {
        resolver
            .resolve_for_kid(now, &uri, Some(&format!("forged-{i}")))
            .await;
    }
    assert_eq!(
        dialer.requested().len(),
        2,
        "a burst of unknown kids must cost exactly one refetch, not one each"
    );
}

/// A refetch whose upstream fails falls back to the still-valid cached set (issue #126
/// criterion 4: no outage window).
///
/// The refetch exists to make rotation seamless. If a failing upstream turned a working
/// issuer into a failing one, the optimisation would have made availability WORSE than not
/// having it -- and `federation_jwks.rs` already gets this right for the same kid-miss
/// refetch, so the house pattern was there to follow.
#[tokio::test]
async fn a_failed_rotation_refetch_falls_back_to_the_cached_keys() {
    let key = issuer_key();
    let server = start_jwks_server_failing_after_first(jwks_json(&key)).await;
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let primed = resolver.resolve(now, "http://jwks.test/keys").await;
    assert_eq!(primed.len(), 1, "the first fetch must succeed and prime");

    // The refetch now hits a 500.
    let after = resolver
        .resolve_for_kid(now, "http://jwks.test/keys", Some("unknown-kid"))
        .await;
    assert_eq!(
        after.len(),
        1,
        "a failed refetch must return the CACHED keys, not nothing -- otherwise a transient \
         upstream outage turns a working issuer into a failing one"
    );
    assert_eq!(dialer.requested().len(), 2, "it did attempt the refetch");
}

/// A kid-less key set is bounded by the rate limit, NOT exempted from refetching.
///
/// `ironauth-jose` deliberately supports keys with no `kid` (the RFC 8037 A.4 vector). For
/// such a set every named kid is "absent" forever, so an earlier version of this code treated
/// it as satisfied by definition, to avoid refetching on every request.
///
/// That exemption was wrong twice over. The traffic it feared is already bounded -- five
/// requests naming an unknown kid cost ONE refetch, not five, because the rate limit holds.
/// And exempting the set meant an issuer that rotates FROM a kid-less set TO a kid-bearing
/// one would never be refetched, leaving the new key undiscovered for a full TTL: criterion
/// 4's outage, reintroduced by the guard meant to protect availability.
///
/// So this asserts the bound rather than an exemption.
#[tokio::test]
async fn a_kidless_key_set_is_bounded_by_the_rate_limit_not_exempted() {
    // Built by HAND, because `jwks_json` always emits a `kid` -- an earlier version of this
    // test used it and the guard below caught the fixture proving nothing.
    let key = SigningKey::ed25519_from_seed(Some("k-drop".to_owned()), &[0x33; 32]).expect("key");
    let mut doc: serde_json::Value =
        serde_json::from_str(&jwks_json(&key)).expect("jwks json parses");
    for jwk in doc["keys"].as_array_mut().expect("keys array") {
        jwk.as_object_mut().expect("jwk object").remove("kid");
    }
    let (resolver, dialer, uri) =
        counting_resolver(doc.to_string(), Duration::from_secs(300)).await;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let keys = resolver.resolve(now, &uri).await;
    assert!(!keys.is_empty());
    assert!(
        keys.iter().all(|k| k.kid().is_none()),
        "this fixture must serve a kid-less set for the test to mean anything"
    );
    for _ in 0..5 {
        resolver.resolve_for_kid(now, &uri, Some("any-kid")).await;
    }
    assert_eq!(
        dialer.requested().len(),
        2,
        "five requests naming an unknown kid must cost ONE refetch between them -- bounded, \
         not exempted"
    );
}
