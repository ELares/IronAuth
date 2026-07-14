// SPDX-License-Identifier: MIT OR Apache-2.0

//! Live wiring of per-environment issuers, JWKS serving, and signing into the
//! data plane (issue #194), against a real Postgres.
//!
//! The registry here is STORE-BACKED: the environment's signing key is provisioned
//! into the database, and the same lazy `IssuerRegistry` both the mint and the
//! mounted JWKS surface read loads it through the RLS-forced scoped store. These
//! tests drive the capstone acceptance criteria end to end:
//!
//! - AC #1: a booted instance serves a live per-environment JWKS (not 404), honors
//!   a conditional request with `304`, and its `Cache-Control` max-age reflects the
//!   configured `oidc.jwks_cache_max_age_secs`.
//! - AC #2 / AC #6: a token is signed with a per-environment key loaded from the
//!   store; its `kid` is present in the served JWKS; and it verifies
//!   cryptographically against the keys reconstructed from that PUBLISHED JWKS.
//! - AC #3: an ES256-only environment emits only ES256 tokens (the live policy is
//!   derived from exactly the loaded keys).
//! - AC #4: the served JWKS `Cache-Control` reflects a NON-default configured
//!   window (the config knob reaches the mounted surface). The single-source-of-
//!   truth half of AC #4 is structural: the mint and the JWKS read the ONE
//!   registry, asserted here by the token `kid` being present in the served JWKS.
//! - AC #5: a request that names this environment under a DIFFERENT tenant is a
//!   uniform `404`, never a self-consistent bogus 200.
//! - Discovery reconciliation: the LIVE discovery document, served over the SAME
//!   store-backed registry the mint and the JWKS read, advertises each
//!   environment's REAL signing algorithm (an ES256-only environment advertises
//!   `ES256`, never the `EdDSA` default), so discovery, JWKS, and the minted tokens
//!   cannot diverge; and a cross-tenant scope 404s on every well-known form exactly
//!   like the JWKS surface, never a self-consistent bogus 200.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    Harness, ISSUER_BASE, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json,
    location_param,
};
use ironauth_config::OidcConfig;
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};
use ironauth_store::Scope;

/// Drive the register-less bootstrap flow (authenticated, consenting subject ->
/// authorization code -> token endpoint) and return the issued `(access, id)`
/// token pair. This is the same flow the existing DB tests use; no dynamic client
/// registration is involved.
async fn issue_tokens(harness: &Harness, nonce: &str) -> (String, String) {
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&nonce={nonce}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize should redirect: {body}"
    );
    let code = location_param(&headers, "code").expect("code in redirect");

    let token_form = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _, body) = harness.token(&token_form).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let access = value["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let id = value["id_token"].as_str().expect("id_token").to_owned();
    (access, id)
}

/// The decoded protected header of a compact JWS.
fn token_header(token: &str) -> serde_json::Value {
    let header_b64 = token.split('.').next().expect("header segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("base64url header");
    serde_json::from_slice(&bytes).expect("json header")
}

/// The `kid` from a compact JWS protected header.
fn token_kid(token: &str) -> String {
    token_header(token)["kid"]
        .as_str()
        .expect("kid in header")
        .to_owned()
}

/// The `alg` from a compact JWS protected header.
fn token_alg(token: &str) -> String {
    token_header(token)["alg"]
        .as_str()
        .expect("alg in header")
        .to_owned()
}

/// Fetch a scope's JWKS from the mounted issuer router, returning status, the
/// `Cache-Control` value, the `ETag`, and the body.
async fn get_jwks(
    harness: &Harness,
    scope: &Scope,
    if_none_match: Option<&str>,
) -> (StatusCode, Option<String>, Option<String>, String) {
    let uri = format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment());
    let mut builder = Request::builder().method("GET").uri(&uri);
    if let Some(etag) = if_none_match {
        builder = builder.header(header::IF_NONE_MATCH, etag);
    }
    let (status, headers, body) = harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await;
    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let etag = headers
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    (status, cache_control, etag, body)
}

/// The published `kid`s in a JWK Set document.
fn published_kids(jwks: &serde_json::Value) -> Vec<String> {
    jwks["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .filter_map(|k| k["kid"].as_str().map(str::to_owned))
        .collect()
}

/// Reconstruct the trusted verifying keys from a PUBLISHED JWK Set (every key is
/// the Ed25519 OKP key this environment is provisioned with), so verification
/// depends only on what the JWKS surface actually serves.
fn trusted_from_published_jwks(jwks: &serde_json::Value) -> Vec<TrustedKey> {
    jwks["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .map(|k| {
            assert_eq!(k["kty"].as_str(), Some("OKP"), "environment key is Ed25519");
            let kid = k["kid"].as_str().map(str::to_owned);
            let x = URL_SAFE_NO_PAD
                .decode(k["x"].as_str().expect("x member"))
                .expect("base64url x");
            TrustedKey::ed25519(kid, &x).expect("published JWK yields a trusted key")
        })
        .collect()
}

#[tokio::test]
async fn live_registry_signs_with_a_stored_key_and_publishes_it_for_verification() {
    // A booted, store-backed instance: the signing key lives in the database and
    // the mint + JWKS both read the one lazy registry.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let client_id = harness.client_id().to_string();

    // AC #6 / register-less issuance: drive the bootstrap flow to a token.
    let (access_token, id_token) = issue_tokens(&harness, "n-194").await;

    // AC #1: the live per-environment JWKS is served (not 404), with an explicit
    // Cache-Control max-age and a strong ETag.
    let (status, cache_control, etag, body) = get_jwks(&harness, &scope, None).await;
    assert_eq!(status, StatusCode::OK, "live JWKS is served: {body}");
    let cache_control = cache_control.expect("Cache-Control present");
    assert!(
        cache_control.contains("max-age="),
        "Cache-Control carries max-age: {cache_control}"
    );
    let etag = etag.expect("ETag present");
    let jwks = json(&body);
    let kids = published_kids(&jwks);
    assert_eq!(kids.len(), 1, "one provisioned key is published: {kids:?}");

    // AC #2: both tokens' kid is present in the served JWKS (they were signed by a
    // key loaded from the store, and the JWKS the registry serves is the SAME
    // registry entry, so they cannot diverge).
    let access_kid = token_kid(&access_token);
    let id_kid = token_kid(&id_token);
    assert!(
        kids.contains(&access_kid),
        "access token kid {access_kid} is in the JWKS {kids:?}"
    );
    assert_eq!(id_kid, access_kid, "both tokens share the environment key");

    // AC #6: verify BOTH tokens cryptographically against the keys reconstructed
    // from the PUBLISHED JWKS, through the one hardened verify path.
    let trusted = trusted_from_published_jwks(&jwks);
    let access_policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        trusted.clone(),
        harness.issuer().to_owned(),
        client_id.clone(),
    )
    .expect("access policy builds");
    let verified = verify(&access_token, &access_policy, &common::verify_clock())
        .expect("access token verifies against the published JWKS");
    assert_eq!(verified.claims().issuer(), harness.issuer());
    assert!(harness.issuer().starts_with(ISSUER_BASE));

    let id_policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        trusted,
        harness.issuer().to_owned(),
        client_id.clone(),
    )
    .expect("id policy builds");
    let verified_id = verify(&id_token, &id_policy, &common::verify_clock())
        .expect("id token verifies against the published JWKS");
    assert_eq!(
        verified_id.claims().get("nonce").and_then(|v| v.as_str()),
        Some("n-194"),
        "bound nonce is echoed into the ID token"
    );

    // AC #1: a conditional request with the served ETag returns 304 with no body.
    let (status, _, _, body) = get_jwks(&harness, &scope, Some(&etag)).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty(), "304 carries no body: {body:?}");
}

#[tokio::test]
async fn served_jwks_cache_control_reflects_the_configured_window() {
    // AC #4: a non-default configured window (777s, within the 300..=900 range)
    // reaches the mounted JWKS surface's Cache-Control max-age, proving the config
    // knob is wired into the registry the JWKS reads (not the default 600).
    let harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        jwks_cache_max_age_secs: 777,
        ..OidcConfig::default()
    })
    .await;
    let (status, cache_control, _, body) = get_jwks(&harness, &harness.scope(), None).await;
    assert_eq!(status, StatusCode::OK, "JWKS served: {body}");
    let cache_control = cache_control.expect("Cache-Control present");
    assert!(
        cache_control.contains("max-age=777"),
        "the configured window reaches the served header: {cache_control}"
    );
}

#[tokio::test]
async fn an_environment_under_the_wrong_tenant_is_a_uniform_not_found() {
    // AC #5: env-to-tenant binding. A foreign scope (a DIFFERENT tenant's
    // environment) is provisioned with its OWN key, so it resolves 200 under its
    // own tenant.
    let harness = Harness::start_store_backed().await;
    let foreign = harness.provision_foreign_scope().await;

    // Warm the foreign environment under its OWN tenant: served (200). This also
    // proves the cross-tenant probe below cannot be a stale cache hit.
    let (status, _, _, body) = get_jwks(&harness, &foreign, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "foreign env serves under its tenant: {body}"
    );
    assert_eq!(published_kids(&json(&body)).len(), 1);

    // The SAME environment id under the HARNESS's (different) tenant: RLS finds no
    // rows, so the key set is empty and the response is a uniform 404, never a
    // self-consistent bogus 200 serving the foreign scope's keys.
    let bogus = Scope::new(harness.scope().tenant(), foreign.environment());
    let (status, _, _, _) = get_jwks(&harness, &bogus, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an environment named under the wrong tenant fails closed"
    );

    // And the harness's own environment named under the foreign tenant is likewise
    // a 404 (the binding holds both directions).
    let bogus_reverse = Scope::new(foreign.tenant(), harness.scope().environment());
    let (status, _, _, _) = get_jwks(&harness, &bogus_reverse, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_es256_only_environment_never_emits_a_non_es256_token() {
    // AC #3: the environment is provisioned with an ES256-ONLY key. The live
    // registry derives the policy from exactly the keys it loads, so the policy is
    // {ES256} and the mint (through sign_jws_with_policy) can emit nothing else: a
    // non-ES256 key is neither present nor policy-permitted.
    let harness = Harness::start_store_backed_es256().await;
    let client_id = harness.client_id().to_string();

    let (access_token, id_token) = issue_tokens(&harness, "n-es256").await;

    // Both tokens are signed ES256, never EdDSA (the deployment default algorithm).
    assert_eq!(token_alg(&access_token), "ES256", "access token is ES256");
    assert_eq!(token_alg(&id_token), "ES256", "id token is ES256");

    // The published JWKS is the matching EC P-256 key, and the token's kid is in it.
    let (status, _, _, body) = get_jwks(&harness, &harness.scope(), None).await;
    assert_eq!(status, StatusCode::OK, "JWKS served: {body}");
    let jwks = json(&body);
    let jwk = &jwks["keys"].as_array().expect("keys")[0];
    assert_eq!(jwk["kty"].as_str(), Some("EC"), "published key is EC");
    assert_eq!(
        jwk["crv"].as_str(),
        Some("P-256"),
        "published curve is P-256"
    );
    assert!(
        published_kids(&jwks).contains(&token_kid(&access_token)),
        "the ES256 token's kid is published"
    );

    // Verify the ES256 access token against the EC key reconstructed from the
    // published JWKS, restricting the allowed algorithms to ES256.
    let kid = jwk["kid"].as_str().map(str::to_owned);
    let x = URL_SAFE_NO_PAD
        .decode(jwk["x"].as_str().expect("x"))
        .expect("x bytes");
    let y = URL_SAFE_NO_PAD
        .decode(jwk["y"].as_str().expect("y"))
        .expect("y bytes");
    let trusted = TrustedKey::ecdsa_p256(kid, &x, &y).expect("published EC key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::Es256],
        vec![trusted],
        harness.issuer().to_owned(),
        client_id,
    )
    .expect("policy builds");
    let verified = verify(&access_token, &policy, &common::verify_clock())
        .expect("ES256 token verifies against the published EC key");
    assert_eq!(verified.algorithm(), JwsAlgorithm::Es256);
}

/// Fetch a discovery document from a mounted well-known route, returning the status
/// and the body.
async fn get_discovery(harness: &Harness, uri: &str) -> (StatusCode, String) {
    let (status, _headers, body) = harness
        .send(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    (status, body)
}

/// The `id_token_signing_alg_values_supported` array from a discovery document.
fn advertised_algs(doc: &serde_json::Value) -> Vec<String> {
    doc["id_token_signing_alg_values_supported"]
        .as_array()
        .expect("alg array")
        .iter()
        .map(|v| v.as_str().expect("alg string").to_owned())
        .collect()
}

#[tokio::test]
async fn live_discovery_advertises_the_environments_real_signing_alg() {
    // Discovery used to advertise the EdDSA default for EVERY environment, even one
    // provisioned with ES256 keys, so a conforming RP that honors
    // id_token_signing_alg_values_supported would reject the environment's ES256
    // id_token. Now discovery resolves the per-environment policy from the SAME
    // store-backed registry the mint and the JWKS read, so an ES256-only environment
    // advertises ES256 (its real, minted, published algorithm), never the EdDSA
    // default.
    let harness = Harness::start_store_backed_es256().await;
    let scope = harness.scope();

    // Every well-known form the router serves reflects the loaded ES256 key (MCP
    // clients probe the host-inserted forms, so assert all three).
    for uri in [
        format!(
            "/t/{}/e/{}/.well-known/openid-configuration",
            scope.tenant(),
            scope.environment()
        ),
        format!(
            "/.well-known/oauth-authorization-server/t/{}/e/{}",
            scope.tenant(),
            scope.environment()
        ),
        format!(
            "/.well-known/openid-configuration/t/{}/e/{}",
            scope.tenant(),
            scope.environment()
        ),
    ] {
        let (status, body) = get_discovery(&harness, &uri).await;
        assert_eq!(status, StatusCode::OK, "discovery form {uri}: {body}");
        let doc = json(&body);
        let algs = advertised_algs(&doc);
        assert!(
            algs.contains(&"ES256".to_owned()),
            "discovery advertises the loaded ES256 key on {uri}: {algs:?}"
        );
        assert_ne!(
            algs,
            vec!["EdDSA".to_owned(), "RS256".to_owned()],
            "discovery does not fall back to the EdDSA default on {uri}: {algs:?}"
        );
        assert!(
            !algs.contains(&"EdDSA".to_owned()),
            "an ES256-only environment never advertises EdDSA on {uri}: {algs:?}"
        );
        // The advertised issuer still exact-matches the tokens' issuer.
        assert_eq!(doc["issuer"].as_str(), Some(harness.issuer()), "{uri}");
    }
}

#[tokio::test]
async fn cross_tenant_discovery_is_a_uniform_not_found() {
    // Because discovery never consulted the store, a cross-tenant scope rendered a
    // self-consistent 200 while the JWKS path for the SAME scope correctly 404'd.
    // Now discovery resolves through the SAME RLS-scoped registry, so a foreign
    // environment named under the harness's tenant loads zero rows and 404s on every
    // well-known form, exactly like the JWKS surface.
    let harness = Harness::start_store_backed().await;
    let foreign = harness.provision_foreign_scope().await;

    // Under its OWN tenant the foreign environment's discovery resolves (200),
    // proving the 404s below are the cross-tenant binding, not a missing document.
    let own = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        foreign.tenant(),
        foreign.environment()
    );
    let (status, body) = get_discovery(&harness, &own).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "foreign env discovery resolves under its tenant: {body}"
    );

    // The foreign environment id named under the HARNESS's (different) tenant: RLS
    // finds no rows, so every discovery form is a uniform 404, never a
    // self-consistent bogus 200 serving the foreign scope's metadata.
    let bogus_tenant = harness.scope().tenant();
    for uri in [
        format!(
            "/t/{}/e/{}/.well-known/openid-configuration",
            bogus_tenant,
            foreign.environment()
        ),
        format!(
            "/.well-known/oauth-authorization-server/t/{}/e/{}",
            bogus_tenant,
            foreign.environment()
        ),
        format!(
            "/.well-known/openid-configuration/t/{}/e/{}",
            bogus_tenant,
            foreign.environment()
        ),
    ] {
        let (status, _) = get_discovery(&harness, &uri).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant discovery fails closed on {uri}"
        );
    }
}
