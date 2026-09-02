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
    // different public key) is invalid_grant with an assertion_bad_signature diagnostic.
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
            .any(|d| d.failure_reason == "assertion_bad_signature"),
        "a bad signature is diagnosed AS a bad signature. It collapsed into the coarse \
         `assertion_invalid` until the federated path started sharing the classifier its \
         `private_key_jwt` sibling has used since #91."
    );
}

#[tokio::test]
async fn an_expired_assertion_is_rejected_with_invalid_grant_and_a_diagnostic() {
    // AC2: an expired assertion (exp before now-skew, at the frozen epoch clock) is
    // invalid_grant with an assertion_expired diagnostic.
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
            .any(|d| d.failure_reason == "assertion_expired"),
        "an expired assertion is diagnosed AS expired, which is what tells an operator to \
         look at a clock rather than at key material"
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
            .any(|d| d.failure_reason == "assertion_expired"),
        "the past-boundary expiry is diagnosed as EXPIRED rather than as the coarse bucket"
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

    // An empty/whitespace sub is rejected the same way, and for the same STATED reason.
    let invalid_before = assertion_invalid_count(&h, &client_id).await;
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
    // AND IT WAS REFUSED AS AN INVALID ASSERTION, not as an unmapped subject.
    //
    // 400 + `invalid_grant` alone does not pin the trim. Without it, a whitespace `sub` is
    // not empty, so it survives this check and is refused further down as
    // `assertion_subject_unmapped`, which is also 400 + `invalid_grant` and passes the two
    // assertions above. Measured: deleting `.trim()` from the emptiness test leaves the
    // whole binary green without this line. The diagnostic is the only thing that separates
    // "rejected for the stated reason" from "rejected by luck further along".
    // AND IT WAS THIS ATTEMPT that was diagnosed so. A COUNT DELTA, not `any`: the
    // missing-sub attempt above already left an `assertion_invalid` row on this same client,
    // so `any` is satisfied before the whitespace assertion is ever presented and passes
    // under the mutant too. Measured, both ways round.
    //
    // Not the newest row either. `for_client` orders by `occurred_at`, the two attempts can
    // land in the same microsecond, and reading the tie the wrong way is how an earlier fix
    // in this file introduced a flake. A delta is ordering-independent.
    let invalid_after = assertion_invalid_count(&h, &client_id).await;
    assert_eq!(
        invalid_after,
        invalid_before + 1,
        "an all-whitespace sub is diagnosed as an invalid assertion, not as an unmapped \
         subject further down the grant: both refuse with 400 + invalid_grant, so the \
         diagnostic is the only thing that tells them apart"
    );
}

/// How many attempts on `client_id` were refused as an invalid assertion.
///
/// Extracted so the two readings around a single presentation are literally the same query.
async fn assertion_invalid_count(h: &common::Harness, client_id: &str) -> usize {
    h.client_auth_diagnostics(client_id)
        .await
        .iter()
        .filter(|d| d.failure_reason == "assertion_invalid")
        .count()
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

/// A JWKS server that answers the FIRST request and then stops listening entirely.
///
/// Its sibling `start_jwks_server_failing_after_first` fails at the HTTP layer, with a 500.
/// This one fails at the TRANSPORT layer: the listener is dropped after one request, so a later connect is refused. That is
/// a different arm of `resolve_for_kid` (`Err` from the fetcher rather than a non-success
/// status) and it is the more common upstream failure, covering a connection refused, a
/// timeout, and every `FetchError::Blocked` the SSRF fetcher raises.
async fn start_jwks_server_closing_after_first(body: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0_u8; 2048];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        }
        // The listener drops here, so every later connect is REFUSED rather than answered.
        drop(listener);
    });
    addr
}

/// A JWKS server that answers the first request `before`, then answers `after` with a NON-2xx
/// status and a fully parseable body.
///
/// The distinction this exists for is invisible to every other fixture here. A 500 whose body
/// is empty is refused twice over: once by the status check and once by the empty-document
/// check, so deleting the status check changes nothing and the guard is unmeasured. A 500
/// carrying a VALID key set is refused only by the status check, and if it were not it would
/// be cached as authoritative.
async fn start_jwks_server_non_2xx_with_keys(before: String, after: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let before = before.clone();
            let after = after.clone();
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let mut buf = [0_u8; 2048];
                let _ = socket.read(&mut buf).await;
                let n = served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let response = if n == 0 {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{before}",
                        before.len()
                    )
                } else {
                    format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{after}",
                        after.len()
                    )
                };
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
///
/// This doc was detached from its function for a while, and the way it happened is worth a
/// line. A later commit inserted a new helper BETWEEN the comment and the fn it described,
/// so the comment silently became the first of two stacked blocks above the wrong function
/// and this one was left with none. Nothing warns about it: both still compile, and the
/// summary line simply describes a function 60 lines away.
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

/// A JWKS server that answers by PATH: `/a.json` gets `a`, anything else gets `b`.
///
/// The point is to make the URI observable. `RecordingDialer` forwards every connection to
/// one fixed address and records a `SocketAddr`, so two `jwks_uri` values pointing at the
/// same loopback server are indistinguishable to it and a resolver that fetched the WRONG
/// registered URI would look identical. Routing on the path puts the difference in the
/// RESPONSE instead, where an assertion can see it.
async fn start_path_routed_jwks_server(a: String, b: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let a = a.clone();
            let b = b.clone();
            tokio::spawn(async move {
                let mut buf = [0_u8; 2048];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]).into_owned();
                let body = if request.contains("/a.json") { a } else { b };
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

/// A JWKS server that serves `before` to the FIRST request and `after` to every later one.
///
/// This is an upstream ROTATION: the key set genuinely changes between two fetches, which is
/// the situation the kid-aware refetch exists for and the only way to observe it end to end.
/// The recording dialer cannot be retargeted mid-test, so the change has to happen behind one
/// address.
async fn start_rotating_jwks_server(before: String, after: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let before = before.clone();
            let after = after.clone();
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let mut buf = [0_u8; 2048];
                let _ = socket.read(&mut buf).await;
                let n = served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = if n == 0 { before } else { after };
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

/// A refetch whose upstream is UNREACHABLE falls back too, not only one that answers 500.
///
/// The sibling above drives an HTTP 500, which is the `!is_success()` arm. Measured: making
/// the `Err` arm return an empty set instead of the cached one left the entire
/// `ironauth-oidc` suite green, so the more common upstream failure -- a connection refused,
/// a timeout, or any `FetchError::Blocked` from the SSRF fetcher -- was the unmeasured half
/// of a guarantee this PR advertises in three places.
#[tokio::test]
async fn a_refetch_whose_upstream_is_unreachable_falls_back_to_the_cached_keys() {
    let key = issuer_key();
    let server = start_jwks_server_closing_after_first(jwks_json(&key)).await;
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let uri = "http://gone.test/keys";

    let primed = resolver.resolve(now, uri).await;
    assert_eq!(
        primed.len(),
        1,
        "the first fetch must succeed and prime, or the rest of this test proves nothing"
    );

    // The listener is gone, so this refetch cannot connect at all.
    let after = resolver
        .resolve_for_kid(now, uri, Some("unknown-kid"))
        .await;
    assert_eq!(
        after.len(),
        1,
        "a refetch that cannot REACH the upstream must return the cached keys, not nothing: \
         a transport failure is the common case and it must not be worse than a 500"
    );
}

/// A NON-2xx carrying a valid key set is refused on its STATUS, and never cached.
///
/// Every other non-success fixture in this file answers with an empty body, so it is refused
/// twice over: once by the status check and once by the empty-document check. Measured:
/// deleting the status check entirely left all three suites green, because nothing
/// distinguished the two reasons. An error page that happens to parse as a JWK Set would
/// then be stored as authoritative for a whole TTL.
#[tokio::test]
async fn a_non_2xx_answer_is_refused_on_its_status_even_when_its_body_parses() {
    let good = SigningKey::ed25519_from_seed(Some("k-good".to_owned()), &[0x11; 32]).expect("key");
    let usurper =
        SigningKey::ed25519_from_seed(Some("k-usurper".to_owned()), &[0x22; 32]).expect("key");
    let server = start_jwks_server_non_2xx_with_keys(jwks_json(&good), jwks_json(&usurper)).await;
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let uri = "http://five-hundred.test/keys";

    let primed = resolver.resolve(now, uri).await;
    assert_eq!(
        primed
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["k-good"],
        "the first fetch must prime with the good key set"
    );

    // The refetch receives a 500 whose body is a perfectly valid JWK Set naming a DIFFERENT
    // key. Only the status check stands between it and the cache.
    let after = resolver
        .resolve_for_kid(now, uri, Some("unknown-kid"))
        .await;
    assert_eq!(
        after
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["k-good"],
        "a non-2xx must be refused on its STATUS, whatever its body parses to"
    );

    // And it must not have been stored: an ordinary resolve, which cannot trigger a refetch,
    // still answers with the primed set rather than the usurper's.
    assert_eq!(
        resolver
            .resolve(now, uri)
            .await
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["k-good"],
        "the error page's key set must never have been cached"
    );
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
    for attempt in 0..5 {
        let answered = resolver.resolve_for_kid(now, &uri, Some("any-kid")).await;
        // Bounded, not BROKEN. The four calls the rate limit refuses must still be answered
        // from the cache: a refusal that returned an empty set would fail-close every
        // request naming an unfamiliar kid, and would change the #91 diagnostic from
        // `AssertionKidUnknown` to `AssertionInvalid` for all of them.
        assert!(
            !answered.is_empty(),
            "attempt {attempt}: a rate-limited refetch must answer from the cache, not with \
             nothing"
        );
    }
    assert_eq!(
        dialer.requested().len(),
        2,
        "five requests naming an unknown kid must cost ONE refetch between them -- bounded, \
         not exempted"
    );
}

/// An upstream document that names NO usable key is never cached, and the caller falls back
/// to the still-valid set.
///
/// The module doc promises exactly this ("A failed or empty fetch is NEVER cached"), and it
/// was promised without a test: deleting the `keys.is_empty()` branch left all sixty-three
/// tests in these three files green. What the deletion costs is not subtle. The empty set
/// would be stored under the URI, so every client on it fails closed for a full TTL, and
/// because an empty set contains no kid the "is this kid present" check answers `false`
/// forever -- so the ONE refetch per 30s the rate limit allows is the only path out, and
/// every request in between is refused.
///
/// An empty document is the realistic shape of a partial upstream failure: a CDN serving a
/// stale-but-valid JSON skeleton, or a key server mid-rotation with nothing published.
#[tokio::test]
async fn an_empty_upstream_document_is_never_cached_and_falls_back() {
    let key = SigningKey::ed25519_from_seed(Some("k-empty".to_owned()), &[0x5a; 32]).expect("key");
    // Valid first, then a well-formed JWK Set naming nothing. `start_rotating_jwks_server`
    // serves `before` to the first request and `after` to every later one.
    let server = start_rotating_jwks_server(jwks_json(&key), "{\"keys\":[]}".to_owned()).await;
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let uri = "http://empty.test/keys";

    let primed = resolver.resolve(now, uri).await;
    assert_eq!(
        primed
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["k-empty"],
        "the first fetch must succeed and prime, or the rest of this test proves nothing"
    );

    // The refetch now receives `{"keys":[]}`.
    let after = resolver
        .resolve_for_kid(now, uri, Some("unknown-kid"))
        .await;
    assert_eq!(
        after
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["k-empty"],
        "an empty document must fall back to the cached set, not replace it"
    );
    assert_eq!(dialer.requested().len(), 2, "it did attempt the refetch");

    // And the cache itself must be UNPOISONED: an ordinary resolve, which cannot trigger a
    // refetch at all, still answers with the primed set.
    assert_eq!(
        resolver
            .resolve(now, uri)
            .await
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["k-empty"],
        "the empty document must not have been stored"
    );
    assert_eq!(
        dialer.requested().len(),
        2,
        "and that answer came from the cache, not from a third fetch"
    );
}

/// A ROTATED upstream key is accepted at `/token`, inside the cache TTL (issue #126
/// criterion 4).
///
/// # Why this test exists, and why the three that preceded it were not enough
///
/// The other rotation tests call `ClientKeyResolver::resolve_for_kid` directly. They prove
/// the resolver, and they proved it well: the bound holds, the fallback works, the kid-less
/// exemption is gone. What none of them touched is the WIRING -- whether the grant actually
/// hands the presented `kid` to the resolver.
///
/// Measured: replacing `let kid = ironauth_jose::compact_jws_kid(assertion);` in
/// `jwt_bearer.rs` with `let kid: Option<String> = None;` -- the feature disconnected from
/// the grant entirely -- left the whole suite green. A feature can be correct, tested, and
/// reachable by nothing, and this file had all three of those and called it done.
///
/// So this drives the real `/token` endpoint. The TTL is 300 seconds and nothing advances a
/// clock, so the cache CANNOT expire during the test: the only thing that can make the
/// second exchange succeed is the kid-miss refetch firing through the grant.
#[tokio::test]
// One rotation, followed in a single walk: prime, rotate, refetch, forge, and the
// known-kid arm that separates "the presented kid travels" from "a kid travels".
// Each arm depends on the dial count the previous one left behind, so splitting them
// would mean re-priming a fresh server per arm and asserting on counts that no longer
// compose.
#[allow(clippy::too_many_lines)]
async fn a_rotated_upstream_key_is_accepted_at_the_token_endpoint_inside_the_ttl() {
    // Two keys with DISTINCT kids. The kid is the whole hint: with one kid the presented
    // assertion would name a key the cache already claims to hold, and no refetch is due.
    // MIXED CASE deliberately. `kid` is an opaque JSON string and JWK matching is exact, so
    // a hint that lowercased it on the way through would silently miss every key a real
    // issuer publishes with capitals. All-lowercase fixtures cannot see that.
    let before = SigningKey::ed25519_from_seed(Some("Rot-Before".to_owned()), &[11_u8; 32])
        .expect("before key");
    let after = SigningKey::ed25519_from_seed(Some("Rot-After".to_owned()), &[22_u8; 32])
        .expect("after key");

    // The upstream rotates between the two fetches, which is the event under test.
    let server = start_rotating_jwks_server(jwks_json(&before), jwks_json(&after)).await;
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = Arc::new(ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        // LONG, deliberately. If this were short the second exchange could succeed by
        // ordinary cache expiry and the test would measure nothing about the kid path.
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

    // PRIME. One fetch, and the cache now holds `rot-before` only.
    let first = assertion(
        &before,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-rot-1",
    );
    let (status, _h, body) = present(&h, &client_id, &first).await;
    assert_eq!(status, StatusCode::OK, "the pre-rotation exchange: {body}");
    assert_eq!(dialer.requested().len(), 1, "primed with one fetch");

    // THE ROTATION. The workload now signs with the new key, whose `kid` the cached set
    // does not contain. Inside the TTL, so nothing but the kid-miss refetch can save it.
    let second = assertion(
        &after,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-rot-2",
    );
    let (status, _h, body) = present(&h, &client_id, &second).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a rotated upstream key must be accepted inside the TTL, which is the whole point \
         of the kid-aware refetch: {body}"
    );
    assert_eq!(
        jwt_payload(json(&body)["access_token"].as_str().expect("access_token"))["sub"],
        MAPPED_PRINCIPAL,
        "and it must still issue under the MAPPED principal"
    );
    assert_eq!(
        dialer.requested().len(),
        2,
        "exactly one refetch: the rotation, not a fetch per request"
    );

    // AND THE BOUND STILL HOLDS through the grant. A third exchange naming a kid nothing
    // publishes must not buy another fetch, or the wiring would have turned the endpoint
    // into an amplifier for anyone who can post a forged header.
    let forged = SigningKey::ed25519_from_seed(Some("Rot-Forged".to_owned()), &[33_u8; 32])
        .expect("forged key");
    let third = assertion(
        &forged,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-rot-3",
    );
    let (status, _h, _body) = present(&h, &client_id, &third).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a forged kid is refused");
    assert_eq!(
        dialer.requested().len(),
        2,
        "the rate limit holds at the endpoint too: a forged kid buys no third fetch"
    );

    // FINALLY: the kid that travels is the PRESENTED one, not merely some kid.
    //
    // Without this arm the test is satisfied by a grant that hands the resolver a constant
    // string, because a constant unknown kid also refetches once and also lands on the
    // rotated set. Measured: that mutant survived every assertion above.
    //
    // The clock is advanced past the refetch rate limit first, which is what makes the two
    // hypotheses separable. With the window open, an assertion naming a kid the cache now
    // HOLDS must buy no fetch; a constant unknown kid would buy one.
    h.clock().advance(Duration::from_secs(120));
    let known_again = assertion(
        &after,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-rot-4",
    );
    let (status, _h, body) = present(&h, &client_id, &known_again).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the rotated key still works: {body}"
    );
    assert_eq!(
        dialer.requested().len(),
        2,
        "a kid the cache already holds must never refetch, even with the rate-limit window \
         open -- which is only true if the PRESENTED kid is what reaches the resolver"
    );
}

/// The refetch interval is THIRTY seconds, at its boundary (issue #126 criterion 4).
///
/// # Why this test had to exist
///
/// Every other count assertion in this file is made at one frozen instant, which any
/// positive interval satisfies. So both of these mutants passed the whole suite:
///
/// * `Duration::from_secs(30)` to `from_secs(1)` -- a thirty-fold amplifier at a
///   third-party host, driven by an unverified header, which is the exact thing the bound
///   exists to prevent;
/// * `Duration::from_secs(30)` to `from_secs(3600)` -- a rotated key undiscovered for an
///   hour, which is criterion 4's outage back again wearing a different number.
///
/// A constant nothing can move is a constant nobody is measuring. Both sides are asserted
/// here, so either direction fails.
#[tokio::test]
async fn the_refetch_interval_is_thirty_seconds_at_its_boundary() {
    let key = issuer_key();
    let (resolver, dialer, uri) =
        counting_resolver(jwks_json(&key), Duration::from_secs(86_400)).await;
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    // The TTL is a day, so ordinary cache expiry cannot explain any fetch below. Only the
    // interval can.
    resolver.resolve(t0, &uri).await;
    assert_eq!(dialer.requested().len(), 1, "priming is one fetch");

    resolver.resolve_for_kid(t0, &uri, Some("unknown-a")).await;
    assert_eq!(
        dialer.requested().len(),
        2,
        "the first unknown kid claims the one refetch the window allows"
    );

    resolver
        .resolve_for_kid(t0 + Duration::from_secs(29), &uri, Some("unknown-b"))
        .await;
    assert_eq!(
        dialer.requested().len(),
        2,
        "one second INSIDE the window buys nothing: an interval shorter than 30s fails here"
    );

    resolver
        .resolve_for_kid(t0 + Duration::from_secs(30), &uri, Some("unknown-c"))
        .await;
    assert_eq!(
        dialer.requested().len(),
        3,
        "exactly AT the window the next refetch is allowed: an interval longer than 30s \
         fails here"
    );

    // And the window restarts from the refetch, not from the prime. Without this a
    // reading of "at most one per 30s counted from the first request ever" would pass.
    resolver
        .resolve_for_kid(t0 + Duration::from_secs(59), &uri, Some("unknown-d"))
        .await;
    assert_eq!(
        dialer.requested().len(),
        3,
        "the window is measured from the last refetch, so 29s after it buys nothing"
    );
}

/// The bound holds under CONCURRENCY (issue #126 criterion 4).
///
/// A `Barrier` rather than a plain spawn: without it the tasks would almost certainly run
/// one after another and this would measure the sequential case a second time.
///
/// # What this test does and does NOT catch, stated because the difference matters
///
/// It catches a gross regression: anything that makes the refetch per-caller rather than
/// per-URI fails here immediately, and that is the shape a rewrite is most likely to
/// introduce.
///
/// It does NOT reliably catch the SUBTLE one. Splitting `begin_rotation_refetch` into
/// check-then-act with the lock released between the two halves survives this test in most
/// trials, MEASURED: a 256-way burst on 16 worker threads with that mutation applied still
/// reported 2 fetches. The window between the two lock acquisitions is a handful of
/// instructions with no await in it, so the interleaving that would expose it is rare, and
/// an assertion that fails in a minority of trials is a flake generator rather than a test.
///
/// So the single lock acquisition in `begin_rotation_refetch` is guaranteed by CONSTRUCTION
/// and not by this test, and that is worth writing down rather than leaving a reader to
/// infer a coverage this file does not have.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_concurrent_burst_of_unknown_kids_still_costs_one_refetch() {
    const BURST: usize = 64;

    let key = issuer_key();
    let (resolver, dialer, uri) =
        counting_resolver(jwks_json(&key), Duration::from_secs(86_400)).await;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    resolver.resolve(now, &uri).await;
    assert_eq!(dialer.requested().len(), 1, "priming is one fetch");

    let gate = Arc::new(tokio::sync::Barrier::new(BURST));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..BURST {
        let resolver = Arc::clone(&resolver);
        let gate = Arc::clone(&gate);
        let uri = uri.clone();
        tasks.spawn(async move {
            // Every task waits here, so they are released into the resolver together.
            gate.wait().await;
            resolver
                .resolve_for_kid(now, &uri, Some(&format!("forged-{i}")))
                .await;
        });
    }
    while tasks.join_next().await.is_some() {}

    assert_eq!(
        dialer.requested().len(),
        2,
        "{BURST} concurrent unknown kids must cost ONE refetch between them, not one each"
    );
}

/// Two URIs are two cache entries, each fetched from its own path (issue #126 criterion 4).
///
/// # What this proves, and what it does NOT
///
/// It proves the RESOLVER keeps two `jwks_uri` values apart: the `FetchRequest` carries the
/// URI it was given, and the cache is keyed per URI rather than on something coarser (two
/// issuers cost two fetches, not one). Both calls run against a cold cache, so `cached()`
/// returns `None` and the kid guard is never entered -- the `kid` arguments below are there
/// to show they do not change the answer, not to exercise the rotation path. An earlier
/// version of this doc claimed they did; a probe panic placed inside the guard block proved
/// otherwise while the test still passed.
///
/// It does NOT prove that `jwt_bearer.rs` passes the REGISTERED URI, because it never calls
/// `jwt_bearer.rs`. That is the whole point of the finding this test was written for, and
/// pinning the `uri` argument to a constant survives it. The test below,
/// `an_assertion_is_verified_against_its_own_issuers_registered_jwks_uri`, is what closes
/// that, by driving `/token` with two registered issuers whose URIs differ only in path.
#[tokio::test]
async fn each_issuers_rotation_is_answered_from_its_own_jwks_uri() {
    let key_a =
        SigningKey::ed25519_from_seed(Some("uri-a".to_owned()), &[44_u8; 32]).expect("key a");
    let key_b =
        SigningKey::ed25519_from_seed(Some("uri-b".to_owned()), &[55_u8; 32]).expect("key b");
    let server = start_path_routed_jwks_server(jwks_json(&key_a), jwks_json(&key_b)).await;

    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(86_400),
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let uri_a = "http://issuer-a.test/a.json";
    let uri_b = "http://issuer-b.test/b.json";

    // Each URI is asked for a kid only the OTHER one publishes, so a resolver that fetched
    // the wrong URI would satisfy the request instead of refusing it.
    let from_first = resolver.resolve_for_kid(now, uri_a, Some("uri-b")).await;
    assert_eq!(
        from_first
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["uri-a"],
        "issuer A's uri must answer with A's key set, whatever kid was asked for"
    );

    let from_second = resolver.resolve_for_kid(now, uri_b, Some("uri-a")).await;
    assert_eq!(
        from_second
            .iter()
            .filter_map(ironauth_jose::TrustedKey::kid)
            .collect::<Vec<_>>(),
        vec!["uri-b"],
        "and issuer B's uri with B's, so one issuer's key can never mint under the other's \
         mappings"
    );

    // Two URIs, two entries, two fetches. One fetch would mean the cache is keyed on
    // something coarser than the URI, which is the same confusion arriving by another route.
    assert_eq!(
        dialer.requested().len(),
        2,
        "the cache is keyed per URI: two distinct issuers cost two fetches, not one"
    );
}

/// The rotation-refetch bound is PER URI, so one issuer's rotation cannot starve another's
/// (issue #126 criterion 4).
///
/// # Why the test above cannot cover this, and why that mattered
///
/// `each_issuers_rotation_is_answered_from_its_own_jwks_uri` runs both calls against a COLD
/// cache, which its own doc says: `cached()` returns `None` and the kid guard is never
/// entered. The per-URI property lives INSIDE that guard, in `begin_rotation_refetch`, so no
/// cold-cache test can reach it however many URIs it uses.
///
/// Review measured the consequence. Rekeying the marker to a constant, which makes the bound
/// global, leaves the whole binary green at 42 passed. The guarantee was stated in three
/// places (the `client_keys.rs` doc, the CHANGELOG, and a THREAT-MODEL denial-of-service
/// row) and pinned in none, which is the shape this PR exists to fix one level up.
///
/// So this test PRIMES both URIs first, putting each in the cache, and only then presents an
/// unknown `kid` to each. Both must refetch. Under a global bound the first refetch consumes
/// the only permit inside the 30s interval and the second issuer is refused: measured
/// 3 requests then 3, against 3 then 4 on the shipped code.
#[tokio::test]
async fn a_rotation_refetch_bound_is_per_uri_so_one_issuer_cannot_starve_another() {
    let key_a =
        SigningKey::ed25519_from_seed(Some("uri-a".to_owned()), &[44_u8; 32]).expect("key a");
    let key_b =
        SigningKey::ed25519_from_seed(Some("uri-b".to_owned()), &[55_u8; 32]).expect("key b");
    let server = start_path_routed_jwks_server(jwks_json(&key_a), jwks_json(&key_b)).await;

    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = ironauth_oidc::ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(86_400),
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let uri_a = "http://issuer-a.test/a.json";
    let uri_b = "http://issuer-b.test/b.json";

    // PRIME. Each URI is asked for the kid it publishes, so the answer is served and cached
    // without entering the rotation guard. Two fetches.
    let _ = resolver.resolve_for_kid(now, uri_a, Some("uri-a")).await;
    let _ = resolver.resolve_for_kid(now, uri_b, Some("uri-b")).await;
    let after_priming = dialer.requested().len();
    assert_eq!(
        after_priming, 2,
        "priming must cost one fetch per URI, or the rest of this test is measuring something \
         else"
    );

    // Issuer A rotates: a kid it does not have yet. This consumes A's permit.
    let _ = resolver
        .resolve_for_kid(now, uri_a, Some("rotated-a"))
        .await;
    let after_a = dialer.requested().len();
    assert_eq!(
        after_a, 3,
        "an unknown kid on a PRIMED uri must refetch, or this test never enters the guard it \
         is about"
    );

    // Issuer B rotates in the same interval. Its permit is its own.
    let _ = resolver
        .resolve_for_kid(now, uri_b, Some("rotated-b"))
        .await;
    assert_eq!(
        dialer.requested().len(),
        4,
        "the refetch bound is PER URI: issuer A having just spent its permit must not starve \
         issuer B's rotation, which is the DoS mitigation the threat model claims"
    );
}

/// An assertion is verified against ITS OWN issuer's registered `jwks_uri`, driven through
/// the live `/token` endpoint (issue #126 criterion 4).
///
/// # Why this is the test that had to exist
///
/// The one above proves the resolver keeps two URIs apart. It calls the resolver directly,
/// so no assertion in it can observe the argument `jwt_bearer.rs` actually passes -- and
/// measurement bore that out: pinning that argument to a constant
/// (`resolve_for_kid(state.now(), "http://wrong.test/keys", kid)`) left the whole
/// `ironauth-oidc` suite green. Proving the layer while leaving the call into it unproven is
/// the same defect this PR was opened to fix one level up, so answering it with another
/// direct-call test would have been answering it with the defect.
///
/// # What a mixup costs
///
/// A trust confusion, not a slow path. With two registered assertion issuers, verifying A's
/// assertion against B's key set means whoever holds B's signing key mints tokens under A's
/// subject mappings. Both issuers here are legitimately registered and enabled; the only
/// thing separating them is which URI is fetched for which.
///
/// The two URIs differ ONLY in path, and the server answers a different key set per path, so
/// the difference lands in the response where an assertion can see it. `RecordingDialer`
/// forwards every connection to one address, so nothing coarser than the response body can
/// tell the two apart.
#[tokio::test]
async fn an_assertion_is_verified_against_its_own_issuers_registered_jwks_uri() {
    const ISSUER_A: &str = "https://a.workload.test";
    const ISSUER_B: &str = "https://b.workload.test";
    let key_a =
        SigningKey::ed25519_from_seed(Some("e2e-uri-a".to_owned()), &[0x66; 32]).expect("key a");
    let key_b =
        SigningKey::ed25519_from_seed(Some("e2e-uri-b".to_owned()), &[0x77; 32]).expect("key b");
    let server = start_path_routed_jwks_server(jwks_json(&key_a), jwks_json(&key_b)).await;

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
    // `/a.json` serves A's key set; every other path serves B's. So a resolver fetching any
    // URI other than the one registered for A gets B's keys.
    h.register_external_issuer(ISSUER_A, None, Some("http://jwks.test/a.json"), None, true)
        .await;
    h.register_external_issuer(ISSUER_B, None, Some("http://jwks.test/b.json"), None, true)
        .await;
    h.create_subject_mapping(ISSUER_A, EXTERNAL_SUBJECT, None, None, MAPPED_PRINCIPAL)
        .await;
    let client_id = h.client_id().to_string();

    // A's assertion, signed with A's key. This is the direction the constant-URI mutant
    // breaks: under it the grant fetches some other path, gets B's key set, and A's genuine
    // signature no longer verifies.
    let own = assertion(
        &key_a,
        ISSUER_A,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-own-uri",
    );
    let (status, _hdrs, body) = present(&h, &client_id, &own).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "issuer A's assertion must verify against the key set at A's REGISTERED jwks_uri: \
         {body}"
    );
    assert_eq!(
        jwt_payload(json(&body)["access_token"].as_str().expect("access token"))["sub"],
        MAPPED_PRINCIPAL
    );

    // And B's key must not verify an assertion CLAIMING to be A. Without this the test
    // above would still pass if every issuer resolved to A's URI, which is the same mixup
    // in the opposite direction.
    let forged = assertion(
        &key_b,
        ISSUER_A,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-cross-uri",
    );
    let (status, _hdrs, body) = present(&h, &client_id, &forged).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the OTHER issuer's key must not verify an assertion claiming issuer A: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
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
/// # The issuer-SUFFIX shape, and the two sites it has to be read at
///
/// An issuer-suffix comparison, `$1 LIKE '%' || issuer`, behaves DIFFERENTLY at the two
/// places an issuer string is compared, and an earlier version of this block reported one
/// site's result as if it were the whole answer. Both are measured here.
///
/// AT THE MAPPING LOOKUP (`external_assertion_subject_mappings`, `repository.rs`) the shape
/// is CLOSED. `ISSUER_A_LIKE_PATTERN` below is the stored issuer
/// `https://token.actions.githubusercontent.co_`, and the presented `ISSUER_A` ends with
/// `...co` plus one character, so `_` matches `m` and the wildcard-bearing anchor's mapping
/// fires for an issuer that merely resembles it. Applying that mutant turns this binary red
/// at the assertion below: 30 passed, 1 failed,
/// `a_mapping_for_one_issuer_does_not_fire_for_another`.
///
/// AT THE ISSUER LOOKUP (`external_assertion_issuers`, `by_issuer`) the same mutant leaves
/// the binary GREEN, ten runs out of ten, and stays green even when the query is forced to
/// hand back a non-exact match first (`ORDER BY (issuer = $1) ASC`, so row order cannot be
/// what is carrying it). That is not a coverage gap. A loose issuer lookup fails CLOSED,
/// because the record it returns is then handed to `VerificationPolicy`, which enforces
/// `iss == record.issuer` exactly; a wrongly-matched issuer record is rejected there rather
/// than minting anything. The second gate is what makes it inert, so no anchor is needed and
/// adding one would pin a property the code does not depend on.
///
/// WHAT REMAINS TRUE about scheme-less registration, which is why the anchors matter at all:
/// nothing makes a stored issuer carry a scheme. `external_assertion_issuers.issuer` is plain
/// `text NOT NULL` (`crates/ironauth-store/migrations/0020_jwt_bearer_assertion.sql`),
/// `register()` parses no URL, and the grant passes the presented `iss` through as an opaque
/// string. So a suffix comparison at a site with no second gate would be reachable with an
/// ordinary URL: against the LEGACY Kubernetes service-account issuer
/// `kubernetes/serviceaccount`, `https://evil.test/kubernetes/serviceaccount` ends with the
/// stored string. The mapping lookup is such a site, which is why the anchor above is kept.
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

    // NINE ADJACENT ANCHORS, each registered as its own enabled issuer with no mapping of
    // its own, so only the mapping lookup's exact `=` on the issuer can refuse it. The
    // anchors mirror the comparisons a reader could plausibly write, in both directions.
    //
    // NOT "one anchor closes exactly one shape". That claim was here and is false, in the
    // same way and for the same reason it was false on the subject axis: a later anchor can
    // cover an earlier one's shape by accident. Measured, `ISSUER_A_PADDED` starts with the
    // stored issuer, so it kills the PREFIX and SUBSTRING shapes as well as the whitespace
    // one, and `ISSUER_A_EXTENDED` therefore uniquely closes nothing. The per-shape
    // attribution is in the table on `a_github_actions_shaped_workload_token_...` for the
    // subject axis; on this axis the honest statement is that all nine are kept, every
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

#[tokio::test]
async fn a_per_issuer_algorithm_pin_refuses_an_algorithm_the_deployment_otherwise_accepts() {
    // Issue #126 criterion 3, the algorithm clause, driven at the LIVE endpoint.
    //
    // `allowed_algs` has unit tests over the record, but nothing registered an issuer with a
    // pin and presented an assertion at `/token`. The two are different claims: the unit test
    // says the narrowing function computes the right set, and this says the set it computes is
    // the one `verify_external_assertion` is actually handed. A pin parsed correctly and then
    // dropped on the floor passes the first and fails this.
    //
    // The assertion here is signed with EdDSA, which this deployment accepts by default and
    // every other test in this file relies on. The pin names ES256 instead, so the refusal is
    // specifically the ISSUER's narrowing rather than an algorithm the core cannot verify or a
    // signature that does not check out. Both of those have their own tests, and an
    // unsupported-algorithm fixture would be refused by the shared floor whether the pin
    // worked or not.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, Some("ES256"), true)
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
        "jti-alg-pinned-out",
    );

    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        json(&body)["error"],
        "invalid_grant",
        "the wire error is the opaque one every assertion refusal uses, so the pin is not an \
         oracle for which algorithms an issuer allows: {body}"
    );
    // The PRECISE reason, not the coarse catch-all. An algorithm refused by this issuer's pin
    // is `assertion_algorithm_disallowed`, which is what makes the diagnostic actionable: an
    // operator seeing it knows to look at the pin rather than at the key material, the clock,
    // or the audience. Before the federated path shared the classifier its `private_key_jwt`
    // sibling has used since #91, every refusal here collapsed into `assertion_invalid`.
    assert!(
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "assertion_algorithm_disallowed"),
        "the diagnostic names the pin as the cause: {:?}",
        h.client_auth_diagnostics(&client_id)
            .await
            .iter()
            .map(|d| d.failure_reason.clone())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn the_same_assertion_is_accepted_once_the_pin_names_its_algorithm() {
    // The positive control for the test above, and the reason that one means anything. A
    // refusal assertion passes for any number of reasons that have nothing to do with the pin:
    // a broken fixture, an unseeded mapping, a mistyped issuer. This drives the same fixture
    // against an issuer whose only difference is a pin that includes EdDSA. The `jti` differs,
    // because it must: the grant records single use, and reusing one would refuse as a replay
    // and prove nothing about the pin. Every claim the pin decision reads is identical.
    let h = Harness::start().await;
    let jwks = jwks_json(&issuer_key());
    h.register_external_issuer(
        EXTERNAL_ISSUER,
        Some(&jwks),
        None,
        Some("EdDSA ES256"),
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
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-alg-pinned-in",
    );

    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a pin that NAMES the assertion's algorithm accepts it: {body}"
    );
}

#[tokio::test]
async fn each_federated_refusal_is_diagnosed_distinctly_behind_one_opaque_wire_error() {
    // Issue #126's error-handling clause: unknown issuer, audience mismatch and unmapped
    // subject each produce a DISTINCT audited failure, while the wire says the same thing
    // every time.
    //
    // Both halves matter and they pull against each other. A caller must not be able to use
    // the error to probe which issuers are registered or what audience a deployment expects,
    // so the wire is uniformly `invalid_grant`. An operator debugging a broken federation
    // needs to know which of those it is, so the out-of-band diagnostic is specific. A test
    // that checked only the wire would pass on a system that diagnosed nothing, and one that
    // checked only the diagnostics would pass on a system that leaked the reason to callers.
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
    let client_id = h.client_id().to_string();
    let key = issuer_key();

    // An issuer nobody registered.
    let unknown = assertion(
        &key,
        "https://unregistered.example",
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-unknown-iss",
    );
    // A registered issuer, but addressed to somewhere this deployment does not accept.
    let wrong_audience = assertion(
        &key,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        "https://not-this-deployment.example",
        3600,
        "jti-wrong-aud",
    );
    // A registered issuer and an acceptable audience, but a subject with no mapping.
    let unmapped = assertion(
        &key,
        EXTERNAL_ISSUER,
        "spiffe://cluster.test/ns/prod/sa/nobody",
        h.issuer(),
        3600,
        "jti-unmapped-distinct",
    );

    // PER ATTEMPT, with a count delta. Collecting the whole trail into a set at the end and
    // asserting the three reasons appear cannot tell one-reason-per-attempt from
    // all-three-per-attempt: the set is the same either way. The delta is what pins that each
    // refusal contributes exactly its own reason and nothing else, which is what "distinct"
    // means here. A delta rather than the newest row because `for_client` orders by
    // `occurred_at` and two attempts can land in the same microsecond.
    for (asrt, expected) in [
        (&unknown, "assertion_issuer_untrusted"),
        (&wrong_audience, "assertion_audience_mismatch"),
        (&unmapped, "assertion_subject_unmapped"),
    ] {
        let before = reason_counts(&h, &client_id).await;
        let (status, _h, body) = present(&h, &client_id, asrt).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{expected}: {body}");
        assert_eq!(
            json(&body)["error"],
            "invalid_grant",
            "every refusal is the SAME opaque wire error, so the response is not an oracle \
             for which issuers exist or which audiences are accepted: {expected}"
        );

        let after = reason_counts(&h, &client_id).await;
        let added: Vec<(String, usize)> = after
            .iter()
            .filter(|(reason, count)| before.get(*reason).copied().unwrap_or(0) < **count)
            .map(|(reason, count)| {
                (
                    reason.clone(),
                    count - before.get(reason).copied().unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(
            added,
            vec![(expected.to_owned(), 1)],
            "this attempt added exactly its own reason and no other: {added:?}"
        );
    }
}

/// Every diagnostic reason recorded for `client_id`, counted.
///
/// A COUNT per reason rather than a set, so a caller can take a delta across one attempt. A
/// set answers "did this reason ever appear", which is satisfied by an earlier attempt in the
/// same harness and cannot see a second occurrence at all.
async fn reason_counts(h: &Harness, client_id: &str) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for diagnostic in h.client_auth_diagnostics(client_id).await {
        *counts.entry(diagnostic.failure_reason.clone()).or_insert(0) += 1;
    }
    counts
}

#[tokio::test]
async fn an_issuer_that_rotated_past_the_resolved_jwks_is_diagnosed_as_an_unknown_kid() {
    // Issue #126's stale-JWKS clause, and the reason it is CLOSED rather than remaining.
    //
    // The canonical symptom is a rotation the resolved key set has not caught up with: the
    // issuer signs with a new key while this deployment still holds the old one. That set is
    // NOT empty, so it never reaches the no-usable-key path; it reaches the verifier, whose
    // `select_keys` refuses a header `kid` that names none of the trusted keys, and the
    // classifier records `assertion_kid_unknown`.
    //
    // Worth pinning because it is easy to reason about wrongly in both directions. An earlier
    // revision of this PR's changelog said a stale JWKS still fell to the coarse bucket, which
    // confuses "stale" (a non-empty set that no longer holds the signing key) with
    // "unresolvable" (an empty set, which genuinely does fall to the coarse bucket and is the
    // narrower residue). Only the second is still indistinct.
    let h = Harness::start().await;
    // The deployment holds the OLD key; the issuer has moved on to the new one. Different
    // `kid`s, which is what makes this a rotation rather than a bad signature: with the same
    // `kid` the verifier would select the key and fail the signature instead.
    let held = issuer_key();
    let rotated = SigningKey::ed25519_from_seed(Some("wk-2".to_owned()), &[9_u8; 32])
        .expect("the issuer's rotated key");
    h.register_external_issuer(EXTERNAL_ISSUER, Some(&jwks_json(&held)), None, None, true)
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
        &rotated,
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-rotated",
    );

    let (status, _h, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    let reasons: Vec<String> = h
        .client_auth_diagnostics(&client_id)
        .await
        .iter()
        .map(|d| d.failure_reason.clone())
        .collect();
    assert!(
        reasons.contains(&"assertion_kid_unknown".to_owned()),
        "a rotated-past key set is diagnosed as an unknown kid, which tells an operator to \
         re-resolve the issuer's JWKS rather than to suspect the assertion: {reasons:?}"
    );
    assert!(
        !reasons.contains(&"assertion_invalid".to_owned()),
        "and NOT as the coarse bucket, which is what it recorded before this change: {reasons:?}"
    );
}

/// THE JWT BEARER GRANT runs the hook (issue #113 criterion 1, which names it explicitly).
///
/// It builds a `ClientCredentialsMintRequest`, so before the criterion-1 audit it reached
/// neither the client's declarative mapping nor its deployed hook. The `MappedAccessClaims`
/// fence lives on `MintRequest`'s field and could not ask this door the question.
///
/// The test is HERE rather than in `token_hook_at_issuance.rs` because that is where it was
/// written, and there is no reason to move it. NOT because the scaffolding is local: an earlier
/// version of this sentence said so, and it is false. `register_external_issuer` and
/// `create_subject_mapping` are methods on the shared harness, and `tests/lifecycle_fence.rs`
/// stands the whole trusted-issuer and subject-mapping setup up without this file. What IS local
/// is the four assertion helpers at the top of this file, and a copy that reimplemented those
/// would be measuring its own copy of them -- which is a smaller claim than the one that stood
/// here, and the one that survived being checked.
#[cfg(feature = "wasm-hooks")]
#[tokio::test]
async fn the_jwt_bearer_grant_runs_the_hook() {
    let h = Harness::start_with_hook_engine(std::sync::Arc::new(
        ironauth_hooks::HookEngine::new().expect("build the engine"),
    ))
    .await;
    let client_id = seed_trust(&h).await;
    h.deploy_token_hook(h.client_id(), ironauth_hooks::fixtures::ECHO_REQUEST, 1)
        .await;

    let asrt = assertion(
        &issuer_key(),
        EXTERNAL_ISSUER,
        EXTERNAL_SUBJECT,
        h.issuer(),
        3600,
        "jti-hook",
    );
    let (status, _headers, body) = present(&h, &client_id, &asrt).await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");

    let access = json(&body)["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    let claims = jwt_payload(&access);
    // ECHO_REQUEST rather than GOOD, and this asserts the VALUE. Criterion 1 asks that the
    // grant be identified in the payload, and every door passes that string as a literal, so a
    // door that copied its neighbour's would be invisible to a test that only asked whether a
    // hook ran. A hook gating on the grant type is a first-class use of this contract.
    assert_eq!(
        claims["echo_grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "the guest was told which grant this is, or a hook cannot gate on it: {claims}"
    );
    // AND WHICH SUBJECT. Round 2 closed this at `client_credentials` and left the sibling:
    // review measured that setting the subject argument to `None` here, and separately to an
    // empty string, left all 85 tests green. `echo_subject` crosses in the ID-token list,
    // which this grant discards, so `echo_access_subject` is the only way to see it.
    assert_eq!(
        claims["echo_access_subject"], MAPPED_PRINCIPAL,
        "the guest was told whose token this is, and it is the mapped principal: {claims}"
    );
    // `sub` is asserted as a FIXTURE check, not as a property of the seam. Review pointed out
    // that it cannot fail: the mint writes `sub` into its own JSON literal from a separate
    // struct field, and it is then refused three more times on the way back in (mapping
    // `validate`, `filter_hook_claims`, and the mint's own protected-name skip). "The fold did
    // nothing at all" satisfies it.
    //
    // The identical assertion in `token_exchange.rs` was rewritten to say so and this one was
    // not, which is the same fix-one-site-and-leave-the-sibling this whole issue keeps
    // producing. What it is good for is confirming the exchange resolved the principal it
    // meant to, so the grant assertion above describes the right token.
    assert_eq!(
        claims["sub"], MAPPED_PRINCIPAL,
        "the assertion above describes a token for the mapped principal: {claims}"
    );
}

// ---------------------------------------------------------------------------------------------
// IDENTITY CHAINING / ID-JAG, the RECEIVING side (issue #133, PROTOTYPE).
//
// These live in THIS file rather than beside the module's own unit suite, and the reason is the
// property they exist to prove. `tests/identity_chaining.rs` drives `admit` directly and answers
// what the three checks accept; it cannot answer whether the grant reaches them, nor whether the
// grant's OTHER controls still fire once it does. Layering a prototype onto a live grant is
// exactly where a control gets routed around, and it happened here: the first draft handed the
// mint the assertion's own scope claim, which the machine-grant floor and the presenting
// client's allowlist had never seen.
// ---------------------------------------------------------------------------------------------

/// The ID-JAG media type, spelled here rather than imported, so a rename of the constant does
/// not silently move what these tests present. The wire is the contract.
const ID_JAG_MEDIA_TYPE: &str = "oauth-id-jag+jwt";

/// Sign an ID-JAG-shaped assertion: an ordinary RFC 7523 assertion PLUS the media type in the
/// header, the presenting client in `client_id`, and the authorized `scope`.
fn id_jag(
    key: &SigningKey,
    aud: &str,
    jti: &str,
    client_id: &str,
    scope: Option<&str>,
    typ: &str,
) -> String {
    let mut claims = serde_json::json!({
        "iss": EXTERNAL_ISSUER, "sub": EXTERNAL_SUBJECT, "aud": aud,
        "exp": 3600, "iat": 0, "jti": jti, "client_id": client_id,
    });
    if let Some(scope) = scope {
        claims["scope"] = serde_json::json!(scope);
    }
    let payload = serde_json::to_vec(&claims).expect("serialize claims");
    sign_jws(key, &payload, &EmissionOptions::new().with_typ(typ)).expect("sign assertion") // invariant-allow: typ-via-declaration -- a FOREIGN issuer's media type from an IETF draft, not an IronAuth token profile
}

#[tokio::test]
async fn an_id_jag_assertion_is_an_ordinary_assertion_until_the_prototype_is_armed() {
    // THE UNARMED POSTURE, and it is the honest one rather than a convenient one. `typ` is not
    // a separator the ordinary path reads, so on a deployment that has not opted in, an
    // assertion carrying the ID-JAG media type is exactly what it is on main today: an ordinary
    // bearer assertion from a trusted issuer. None of the three checks apply -- and that is
    // precisely why the flag exists, because those checks are the whole difference between an
    // identity assertion and a bearer one.
    let h = Harness::start().await;
    let client_id = seed_trust(&h).await;

    // Naming ANOTHER client, and with no scope: two things the armed side refuses outright.
    let token = id_jag(
        &issuer_key(),
        h.issuer(),
        "jti-idjag-unarmed",
        "cli_somebody_else",
        None,
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unarmed, the media type means nothing and the ordinary grant issues: {resp}"
    );
}

#[tokio::test]
async fn an_armed_deployment_admits_an_honest_identity_assertion_and_refuses_the_three_attacks() {
    let mut h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    h.install_identity_chaining();
    let key = issuer_key();

    // ADMITTED, and the token carries the scope the AUTHORITATIVE domain authorized rather than
    // anything this deployment chose.
    let honest = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-honest",
        &client_id,
        Some("read:orders"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &honest).await;
    assert_eq!(status, StatusCode::OK, "an honest assertion issues: {resp}");
    assert_eq!(
        json(&resp)["scope"],
        "read:orders",
        "the issued scope is the assertion's, not the client's default: {resp}"
    );
    let claims = jwt_payload(json(&resp)["access_token"].as_str().expect("a token"));
    assert_eq!(
        claims["sub"], MAPPED_PRINCIPAL,
        "and it still speaks for the LOCALLY mapped principal: {claims}"
    );

    // THE INTERCEPTION: the same assertion, naming another client. Refused, with this grant's
    // uniform answer -- the ID-JAG refusals join the existing wire contract rather than
    // introducing a new error an attacker could use to tell them apart.
    let stolen = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-stolen",
        "cli_somebody_else",
        Some("read:orders"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &stolen).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert_eq!(json(&resp)["error"], "invalid_grant", "{resp}");

    // THE MISSING CEILING: an assertion with no scope authorizes nothing, so there is nothing to
    // issue against. Treating it as "whatever the local mapping allows" is the widening the
    // ceiling exists to stop.
    let scopeless = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-scopeless",
        &client_id,
        None,
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &scopeless).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert_eq!(json(&resp)["error"], "invalid_grant", "{resp}");

    // THE OVERREACH: a request wider than the assertion. Refused rather than quietly narrowed,
    // because a client that asked for `admin` and received `read:orders` has been told it holds
    // something it does not.
    let honest_again = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-overreach",
        &client_id,
        Some("read:orders"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) =
        present_with_scope(&h, &client_id, &honest_again, "read:orders admin").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert_eq!(json(&resp)["error"], "invalid_grant", "{resp}");
}

#[tokio::test]
async fn the_assertions_scope_is_not_a_way_past_the_floor_or_the_allowlist() {
    // THE BYPASS THIS PROTOTYPE INTRODUCED AND CLOSED. When the client asks for nothing, the
    // assertion's ceiling becomes the granted scope -- and that string is written by a FOREIGN
    // issuer. If it went to the mint unexamined, an identity assertion would be a way to obtain
    // scopes the very same client is refused when it asks plainly. Both of this grant's scope
    // controls are driven through the assertion rather than through `scope`.
    let mut h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    h.install_identity_chaining();
    set_allowlist(&h, Some(&["read:orders".to_owned()])).await;
    let key = issuer_key();

    // THE ALLOWLIST (issue #98). The client may only ever hold `read:orders`; an assertion
    // authorizing `admin` does not change that.
    let past_allowlist = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-allowlist",
        &client_id,
        Some("admin"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &past_allowlist).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the assertion must not carry the client past its own allowlist: {resp}"
    );
    assert_eq!(
        json(&resp)["error"],
        "invalid_grant",
        "and it is refused with the same uniform answer a plain request gets: {resp}"
    );

    // THE MACHINE-GRANT FLOOR (issue #23). `openid` and `offline_access` are out of policy on
    // every machine grant because there is no interactive user; a foreign issuer asserting them
    // does not create one.
    let past_floor = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-floor",
        &client_id,
        Some("read:orders openid"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &past_floor).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the floor still applies to a scope the assertion authorized: {resp}"
    );
    assert_eq!(
        json(&resp)["error"],
        "invalid_scope",
        "the floor answers invalid_scope, exactly as it does for a plainly requested one: {resp}"
    );

    // And the control case: within BOTH, it issues. Without this, every assertion above could be
    // failing for a reason unrelated to scope.
    let allowed = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-allowed",
        &client_id,
        Some("read:orders"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &allowed).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(json(&resp)["scope"], "read:orders", "{resp}");
}

#[tokio::test]
async fn every_ordinary_jwt_bearer_refusal_still_fires_on_an_identity_assertion() {
    // The layering claim, stated as a test. An identity assertion is checked by the ID-JAG rules
    // IN ADDITION TO the grant's own, never instead of them -- so an assertion that is perfect
    // by ID-JAG's lights and broken by RFC 7523's is still refused. Each case is the honest
    // assertion with exactly one ordinary property broken.
    let mut h = Harness::start().await;
    let client_id = seed_trust(&h).await;
    h.install_identity_chaining();
    let key = issuer_key();

    // A BAD SIGNATURE: signed by a key the registered JWKS does not hold.
    let forged = id_jag(
        &wrong_key(),
        h.issuer(),
        "jti-idjag-forged",
        &client_id,
        Some("read:orders"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &forged).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a forged signature: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_grant", "{resp}");

    // THE WRONG AUDIENCE: an assertion minted for somewhere else.
    let misaudienced = id_jag(
        &key,
        "https://another.deployment.test",
        "jti-idjag-aud",
        &client_id,
        Some("read:orders"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &misaudienced).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a wrong audience: {resp}");
    assert_eq!(json(&resp)["error"], "invalid_grant", "{resp}");

    // A REPLAY: the single-use `jti` is spent by the first presentation, and carrying the ID-JAG
    // media type does not exempt an assertion from that.
    let once = id_jag(
        &key,
        h.issuer(),
        "jti-idjag-replay",
        &client_id,
        Some("read:orders"),
        ID_JAG_MEDIA_TYPE,
    );
    let (status, _h, resp) = present(&h, &client_id, &once).await;
    assert_eq!(status, StatusCode::OK, "the first presentation: {resp}");
    let (status, _h, resp) = present(&h, &client_id, &once).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the replay: {resp}");
    assert_eq!(json(&resp)["error"], "invalid_grant", "{resp}");

    // AN UNREGISTERED SUBJECT: no mapping, so no local principal to speak for. An identity
    // assertion does not auto-provision one -- if it did, a trusted issuer could create
    // identities here by asserting them.
    let unmapped_claims = serde_json::json!({
        "iss": EXTERNAL_ISSUER, "sub": "spiffe://cluster.test/ns/prod/sa/nobody",
        "aud": h.issuer(), "exp": 3600, "iat": 0, "jti": "jti-idjag-unmapped",
        "client_id": client_id, "scope": "read:orders",
    });
    let payload = serde_json::to_vec(&unmapped_claims).expect("serialize");
    let unmapped = sign_jws(
        &key,
        &payload,
        &EmissionOptions::new().with_typ(ID_JAG_MEDIA_TYPE),
    ) // invariant-allow: typ-via-declaration -- see `id_jag` above
    .expect("sign");
    let (status, _h, resp) = present(&h, &client_id, &unmapped).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unmapped subject: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_grant", "{resp}");
}
