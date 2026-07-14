// SPDX-License-Identifier: MIT OR Apache-2.0

//! JWT (RFC 9068) and opaque access tokens with per-resource-server format
//! selection (issue #29), over a real database (`DATABASE_URL`).
//!
//! Covers the six acceptance criteria: the per-resource-server format choice from
//! one environment (the selection seam), RFC 9068 conformance of the at+jwt (typ
//! and required claims), `acr`/`auth_time` from an authenticated flow, opaque
//! tokens that cannot be validated offline and resolve only via the internal store
//! function (with no replayable stored material), the documented prefix/regex, and
//! `EdDSA`/`ES256` signature verification for the at+jwt.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Harness, PKCE_VERIFIER, REDIRECT_URI, form, json, verify_clock};
use ironauth_config::{OidcConfig, TokenFormat as ConfigTokenFormat};
use ironauth_jose::{JwsAlgorithm, VerificationPolicy, verify};
use ironauth_oidc::OPAQUE_ACCESS_TOKEN_PREFIX;
use ironauth_store::{
    ActorRef, CorrelationId, NewResourceServer, ResourceServerId, ServiceId, TokenFormat,
};

/// The token-endpoint form for a PKCE public-client exchange.
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Read a field from a compact JWS protected header (unverified), for asserting
/// the `typ`/`alg` the mint emitted.
fn jose_header_field(token: &str, field: &str) -> String {
    let header_b64 = token.split('.').next().expect("header segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("base64url header");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json header");
    value
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("header has no {field}"))
        .to_owned()
}

/// Whether `token` matches the documented opaque-access-token scanner regex
/// `ira_at_[A-Za-z0-9_-]{43}` (docs/design/TOKEN-FORMATS.md).
fn matches_opaque_access_regex(token: &str) -> bool {
    let Some(body) = token.strip_prefix("ira_at_") else {
        return false;
    };
    body.len() == 43
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Register a resource server in the harness scope.
async fn register_resource_server(
    harness: &Harness,
    audience: &str,
    format: TokenFormat,
    ttl: Option<i64>,
) -> ResourceServerId {
    let env = harness.env();
    let id = ResourceServerId::generate(env, &harness.scope());
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: format,
                access_token_ttl_secs: ttl,
            },
        )
        .await
        .expect("register resource server");
    id
}

/// AC #1: one registered resource server receives at+jwt, another receives
/// opaque, from the SAME environment; no resource server falls back to the
/// environment default with the client id as the audience.
#[tokio::test]
async fn per_resource_server_format_choice_from_one_environment() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let client = harness.client_id().to_string();

    register_resource_server(
        &harness,
        "https://api.example/reports",
        TokenFormat::AtJwt,
        None,
    )
    .await;
    register_resource_server(
        &harness,
        "https://api.example/orders",
        TokenFormat::Opaque,
        Some(120),
    )
    .await;

    // The at+jwt resource server: its audience, at+jwt, and (no override) the
    // environment access-token lifetime.
    let jwt = harness
        .state()
        .resolve_access_token_target(&scope, Some("https://api.example/reports"), &client)
        .await;
    assert_eq!(jwt.format, TokenFormat::AtJwt);
    assert_eq!(jwt.audience, "https://api.example/reports");
    assert_eq!(jwt.ttl, harness.state().access_token_ttl());

    // The opaque resource server: its audience, opaque, and its own 120s lifetime.
    let opaque = harness
        .state()
        .resolve_access_token_target(&scope, Some("https://api.example/orders"), &client)
        .await;
    assert_eq!(opaque.format, TokenFormat::Opaque);
    assert_eq!(opaque.audience, "https://api.example/orders");
    assert_eq!(opaque.ttl, Duration::from_secs(120));

    // No resource server targeted: the environment default (at+jwt) with the client
    // id as the audience, so UserInfo keeps working.
    let default = harness
        .state()
        .resolve_access_token_target(&scope, None, &client)
        .await;
    assert_eq!(default.format, TokenFormat::AtJwt);
    assert_eq!(default.audience, client);

    // An unregistered resource likewise falls back to the environment default (the
    // #29 behavior; RFC 8707 resource semantics are #28).
    let unknown = harness
        .state()
        .resolve_access_token_target(&scope, Some("https://api.example/unregistered"), &client)
        .await;
    assert_eq!(unknown.format, TokenFormat::AtJwt);
    assert_eq!(unknown.audience, client);
}

/// AC #2 and (`EdDSA` half of) AC #6: the issued at+jwt validates against RFC 9068
/// (typ and every required claim) and verifies against the environment JWKS under
/// the `EdDSA` default.
#[tokio::test]
async fn at_jwt_access_token_conforms_to_rfc9068_and_verifies_under_eddsa() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let access_token = value["access_token"].as_str().expect("access_token");

    // typ = at+jwt (RFC 9068 section 2.1), signed under the EdDSA default.
    assert_eq!(jose_header_field(access_token, "typ"), "at+jwt");
    assert_eq!(jose_header_field(access_token, "alg"), "EdDSA");

    // Verifies through the ONE hardened verify path against the environment key and
    // the client audience (the no-resource case).
    let verified = verify(access_token, &harness.policy(&client), &verify_clock())
        .expect("at+jwt verifies under EdDSA");
    let claims = verified.claims();

    // Every RFC 9068 section 2.2 required claim is present and well formed.
    assert_eq!(claims.issuer(), harness.issuer());
    assert_eq!(
        claims.get("aud").and_then(|v| v.as_str()),
        Some(client.as_str()),
        "aud is the client id (so UserInfo keeps working)"
    );
    assert_eq!(
        claims.get("client_id").and_then(|v| v.as_str()),
        Some(client.as_str())
    );
    assert!(claims.subject().is_some(), "sub present");
    assert!(claims.get("jti").and_then(|v| v.as_str()).is_some());
    assert!(
        claims
            .get("iat")
            .and_then(serde_json::Value::as_i64)
            .is_some()
    );
    assert!(
        claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .is_some()
    );
    // acr is derived from the authentication event (the code flow), always present.
    assert!(claims.get("acr").and_then(|v| v.as_str()).is_some());

    // Claims hygiene: no PII beyond the protocol claims.
    for pii in ["email", "name", "given_name", "phone_number", "address"] {
        assert!(
            claims.get(pii).is_none(),
            "{pii} must not be in the payload"
        );
    }
}

/// AC #3: `acr` and `auth_time` appear in the at+jwt from an authenticated user
/// flow (here a client that registered `require_auth_time`, so the authentication
/// instant is frozen onto the code as due).
#[tokio::test]
async fn at_jwt_carries_acr_and_auth_time_from_an_authenticated_flow() {
    let harness = Harness::start().await;
    let client = harness
        .create_client_requiring_auth_time()
        .await
        .to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let access_token = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    let verified =
        verify(&access_token, &harness.policy(&client), &verify_clock()).expect("at+jwt verifies");
    let claims = verified.claims();
    assert!(
        claims.get("acr").and_then(|v| v.as_str()).is_some(),
        "acr appears from the authenticated flow"
    );
    // The harness session records auth_time at the epoch, and require_auth_time
    // freezes it onto the code, so it is emitted truthfully (0 seconds).
    assert_eq!(
        claims.get("auth_time").and_then(serde_json::Value::as_i64),
        Some(0),
        "auth_time appears from the authenticated flow"
    );
}

/// The `ES256` half of AC #6: an `ES256`-only environment emits an at+jwt signed with
/// `ES256` that verifies against that environment's key, so per-environment
/// algorithm negotiation holds for the access token (the RS256 floor and the
/// per-client negotiation share this one signing path).
#[tokio::test]
async fn at_jwt_access_token_verifies_under_an_es256_environment() {
    let harness = Harness::start_store_backed_es256().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let access_token = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    assert_eq!(jose_header_field(&access_token, "typ"), "at+jwt");
    assert_eq!(jose_header_field(&access_token, "alg"), "ES256");

    // Verify with an ES256 policy trusting the environment's published key.
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::Es256],
        vec![harness.verifying_key()],
        harness.issuer().to_owned(),
        client.clone(),
    )
    .expect("es256 policy builds");
    let verified = verify(&access_token, &policy, &verify_clock()).expect("ES256 at+jwt verifies");
    assert_eq!(
        verified.claims().get("client_id").and_then(|v| v.as_str()),
        Some(client.as_str())
    );
}

/// AC #4 and AC #5: an opaque access token (the environment default flipped to
/// `opaque`) is prefix-scannable, cannot be validated offline, resolves only via
/// the internal store function, and no stored/derived material can be replayed.
#[tokio::test]
async fn opaque_access_token_scans_resolves_and_reveals_no_replayable_material() {
    let config = OidcConfig {
        default_access_token_format: ConfigTokenFormat::Opaque,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let scope = harness.scope();
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    assert_eq!(value["token_type"], "Bearer");
    let access_token = value["access_token"].as_str().expect("access_token");

    // AC #5: the documented prefix and scanner regex match the issued token.
    assert!(
        access_token.starts_with(OPAQUE_ACCESS_TOKEN_PREFIX),
        "opaque tokens carry the ira_at_ prefix"
    );
    assert!(
        matches_opaque_access_regex(access_token),
        "the published scanner regex matches the issued opaque token"
    );
    // AC #4 (offline): an opaque token is not a JWS, so there is nothing to verify
    // offline; it has no dot-separated segments.
    assert_eq!(
        access_token.matches('.').count(),
        0,
        "an opaque token cannot be validated offline"
    );

    // AC #4 (resolve): the internal store function resolves it to its live claims.
    let active = harness
        .store()
        .scoped(scope)
        .authorization()
        .resolve_opaque_access_token(access_token, 0)
        .await
        .expect("resolve")
        .expect("active");
    assert_eq!(active.client_id, client);
    assert_eq!(
        active.audience, client,
        "the no-resource audience is the client"
    );
    assert!(active.subject.starts_with("usr_"));

    // AC #4 (dump safety): the stored material is a digest and metadata; presenting
    // the digest, the jti, the audience, the subject, or the client id as a token
    // never resolves. Only the original plaintext, never stored, resolves.
    let digest = ironauth_store::opaque_access_token_digest(access_token);
    let replay_candidates = [
        digest.as_str(),
        active.jti.as_str(),
        active.audience.as_str(),
        active.subject.as_str(),
        active.client_id.as_str(),
    ];
    for candidate in replay_candidates {
        assert!(
            harness
                .store()
                .scoped(scope)
                .authorization()
                .resolve_opaque_access_token(candidate, 0)
                .await
                .expect("resolve")
                .is_none(),
            "a stored/derived value ({candidate}) must not resolve as a valid token"
        );
    }
}
