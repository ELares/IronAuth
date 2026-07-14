// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dynamic Client Registration and configuration management (issue #30), over a
//! real database.
//!
//! Drives the RFC 7591 registration endpoint and the RFC 7592 read/update/delete
//! endpoints through the live merged router (as `main.rs` mounts it): omitted
//! metadata takes the per-spec defaults, an update rotates the registration access
//! token and rejects the old one, native-client redirects follow RFC 8252, the RP
//! Metadata Choices negotiation prefers `EdDSA` (else `RS256`) and records the choice,
//! and a `jwks_uri` is fetched through the SSRF-hardened fetcher (so a
//! private-address destination is rejected). Cross-scope isolation and the
//! secret/token-at-rest posture are exercised alongside.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Harness, ISSUER_BASE, REDIRECT_URI, form, json as json_body};
use ironauth_config::OidcConfig;
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::{JwkSet, SigningKey};
use ironauth_oidc::ClientKeyResolver;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A config with the DCR endpoint enabled and confidential PKCE relaxed (the
/// harness default), so the tests drive registration directly.
fn dcr_config() -> OidcConfig {
    OidcConfig {
        registration_enabled: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    }
}

/// The per-environment registration endpoint path for the harness scope.
fn register_path(h: &Harness) -> String {
    format!(
        "/t/{}/e/{}/connect/register",
        h.scope().tenant(),
        h.scope().environment()
    )
}

/// Strip the deployment origin from a `registration_client_uri`, yielding the path
/// the in-process router is driven with.
fn to_path(uri: &str) -> String {
    uri.strip_prefix(ISSUER_BASE)
        .expect("registration_client_uri is under the issuer base")
        .to_owned()
}

/// Parse a response body as JSON, or `Null` for an empty body (a 204/401).
fn parse_or_null(text: &str) -> Value {
    if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(text).unwrap_or(Value::Null)
    }
}

/// `POST` a JSON metadata document to the registration endpoint.
async fn post_json(h: &Harness, path: &str, body: Value) -> (StatusCode, Value) {
    send_json(h, "POST", path, None, Some(body)).await
}

/// Drive a JSON request (optionally Bearer-authenticated) through the router.
async fn send_json(
    h: &Harness,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request builds");
    let (status, _headers, text) = h.send(request).await;
    (status, parse_or_null(&text))
}

/// A published Ed25519 JWK Set JSON, exactly what an RP hosts at its `jwks_uri`.
fn published_jwks(seed: u8) -> String {
    let key = SigningKey::ed25519_from_seed(Some("rp".to_owned()), &[seed; 32]).expect("ed25519");
    JwkSet::from_signing_keys([&key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json")
}

/// The `alg` from a compact JWS's protected header (the first segment), for
/// asserting the algorithm a token was actually signed under.
fn jws_header_alg(jws: &str) -> String {
    let header_segment = jws.split('.').next().expect("jws has a header segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(header_segment)
        .expect("jws header is base64url");
    let header: Value = serde_json::from_slice(&bytes).expect("jws header is json");
    header["alg"]
        .as_str()
        .expect("jws header has an alg")
        .to_owned()
}

#[tokio::test]
async fn omitted_metadata_gets_the_per_spec_defaults() {
    // AC2: client_secret_basic auth, response_types ["code"], application_type web.
    // The omitted id_token_signed_response_alg records the ENVIRONMENT's actual
    // default signing algorithm (EdDSA in this eddsa-only harness), the algorithm the
    // mint will sign this client's ID tokens with, not the abstract RS256 spec
    // default the environment could not honor (FIX 1).
    let h = Harness::start_with(dcr_config()).await;
    let (status, body) = post_json(
        &h,
        &register_path(&h),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(body["response_types"], json!(["code"]));
    assert_eq!(body["grant_types"], json!(["authorization_code"]));
    assert_eq!(body["id_token_signed_response_alg"], "EdDSA");
    assert_eq!(body["application_type"], "web");
    assert!(body["client_id"].is_string(), "a client id is returned");
    assert!(
        body["client_secret"].is_string(),
        "a confidential (basic) client is issued a secret once"
    );
    assert!(body["registration_access_token"].is_string());
    assert!(body["registration_client_uri"].is_string());
}

#[tokio::test]
async fn an_update_rotates_the_registration_access_token_and_rejects_the_old_one() {
    // AC3: an RFC 7592 update rotates the token; the old token is rejected next call.
    let h = Harness::start_with(dcr_config()).await;
    let (status, reg) = post_json(
        &h,
        &register_path(&h),
        json!({ "redirect_uris": ["https://rp.example/cb"], "client_name": "before" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let uri = to_path(reg["registration_client_uri"].as_str().expect("uri"));
    let first_token = reg["registration_access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    // Update with the first token: it succeeds and returns a NEW token.
    let (status, updated) = send_json(
        &h,
        "PUT",
        &uri,
        Some(&first_token),
        Some(json!({ "redirect_uris": ["https://rp.example/cb2"], "client_name": "after" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    let second_token = updated["registration_access_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();
    assert_ne!(first_token, second_token, "the token rotated");
    assert_eq!(updated["client_name"], "after", "the update took effect");

    // The superseded (first) token is rejected immediately.
    let (status, _) = send_json(
        &h,
        "PUT",
        &uri,
        Some(&first_token),
        Some(json!({ "redirect_uris": ["https://rp.example/cb"] })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the old token must be rejected"
    );

    // The new token still authenticates a read.
    let (status, read) = send_json(&h, "GET", &uri, Some(&second_token), None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["client_name"], "after");
}

#[tokio::test]
async fn a_downgrade_to_a_secretless_method_clears_the_stored_secret_hash() {
    // FIX 3: a PUT that transitions the client to a method needing no secret (`none`)
    // NULLs any stored secret_hash, so no dead credential material lingers.
    let h = Harness::start_with(dcr_config()).await;
    // Register a confidential (client_secret_basic) client, which stores a secret hash.
    let (status, reg) = post_json(
        &h,
        &register_path(&h),
        json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_basic"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let client_id = reg["client_id"].as_str().expect("client_id").to_owned();
    let uri = to_path(reg["registration_client_uri"].as_str().expect("uri"));
    let token = reg["registration_access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    let id = h
        .store()
        .scoped(h.scope())
        .clients()
        .parse_id(&client_id)
        .expect("client id parses");
    let before = h
        .store()
        .scoped(h.scope())
        .clients()
        .auth_record(&id)
        .await
        .expect("auth record");
    assert!(
        before.secret_hash.is_some(),
        "a client_secret_basic client stores a secret hash"
    );

    // PUT downgrading to the public (none) method: no secret is needed anymore.
    let (status, _updated) = send_json(
        &h,
        "PUT",
        &uri,
        Some(&token),
        Some(json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let after = h
        .store()
        .scoped(h.scope())
        .clients()
        .auth_record(&id)
        .await
        .expect("auth record");
    assert_eq!(after.auth_method, "none");
    assert!(
        after.secret_hash.is_none(),
        "the stale secret hash is cleared on downgrade to a secretless method"
    );
}

#[tokio::test]
async fn native_client_registrations_enforce_rfc8252() {
    // AC4: loopback allowed, private-use validated, dangerous schemes rejected.
    let h = Harness::start_with(dcr_config()).await;
    let path = register_path(&h);

    // Native: an http loopback IP literal and a reverse-domain private-use scheme.
    let (status, body) = post_json(
        &h,
        &path,
        json!({
            "application_type": "native",
            "token_endpoint_auth_method": "none",
            "redirect_uris": [
                "http://127.0.0.1:52000/cb",
                "http://[::1]/cb",
                "com.example.app:/oauth2redirect"
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["application_type"], "native");

    // A dangerous scheme is rejected for a native client.
    let (status, body) = post_json(
        &h,
        &path,
        json!({
            "application_type": "native",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["javascript:alert(1)"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_redirect_uri");

    // A web client may not register a private-use scheme (native-only).
    let (status, body) = post_json(
        &h,
        &path,
        json!({
            "application_type": "web",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["com.example.app:/cb"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_redirect_uri");

    // A web client may not register an http loopback redirect (native-only).
    let (status, body) = post_json(
        &h,
        &path,
        json!({
            "application_type": "web",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["http://127.0.0.1/cb"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn metadata_choices_select_eddsa_when_offered_and_rs256_otherwise() {
    // AC5 (corrected, FIX 1): the negotiation is constrained to the algorithms the
    // ENVIRONMENT can actually sign with, so a recorded id_token_signed_response_alg
    // is always the algorithm the OP will sign this client's ID tokens with. A dual
    // EdDSA + RS256 environment, so both are truthfully signable and the "RS256
    // otherwise" path is exercised against a real RS256 key (never the RS256
    // discovery floor with no key behind it).
    let h = Harness::start_dual_signing(dcr_config()).await;
    let path = register_path(&h);

    // EdDSA preferred when offered alongside RS256.
    let (status, body) = post_json(
        &h,
        &path,
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "id_token_signed_response_alg": ["RS256", "EdDSA"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["id_token_signed_response_alg"], "EdDSA",
        "EdDSA is preferred when offered"
    );

    // Only RS256 offered, and the environment can sign it: RS256 recorded (the
    // plural RP Metadata Choices name works too). This is truthful because a real
    // RS256 key exists; the token endpoint will honor it at mint.
    let (status, body) = post_json(
        &h,
        &path,
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "id_token_signed_response_alg_values": ["RS256"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["id_token_signed_response_alg"], "RS256",
        "RS256 is recorded when it is the only offered algorithm the env can sign"
    );

    // Only ES256 offered: the environment has NO ES256 key, so the request is
    // REJECTED rather than recording (and echoing) an algorithm the OP would never
    // sign this client's ID tokens with.
    let (status, body) = post_json(
        &h,
        &path,
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "id_token_signed_response_alg": ["ES256"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn a_negotiated_id_token_alg_is_the_alg_the_mint_actually_signs_with() {
    // FIX 1 proof-of-invariant: register a DCR client that negotiates a NON-default
    // algorithm (RS256 in a dual EdDSA + RS256 environment whose default is EdDSA),
    // then mint an ID token for it through the REAL token endpoint, and assert the
    // JWS header `alg` equals the value DCR recorded and echoed. The recorded
    // algorithm can never diverge from the algorithm the mint actually signs with;
    // this test fails if the recorded alg is ever a decorative, unhonored value.
    let h = Harness::start_dual_signing(dcr_config()).await;

    // Register a confidential (client_secret_post) DCR client with the harness
    // redirect URI (so the authorize flow accepts it), offering only RS256.
    let (status, reg) = post_json(
        &h,
        &register_path(&h),
        json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_post",
            "id_token_signed_response_alg": ["RS256"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    assert_eq!(
        reg["id_token_signed_response_alg"], "RS256",
        "the registration records and echoes RS256"
    );
    let client_id = reg["client_id"].as_str().expect("client_id").to_owned();
    let secret = reg["client_secret"].as_str().expect("secret").to_owned();

    // Drive a real code exchange for this DCR client (no PKCE: confidential PKCE is
    // relaxed in the harness config), so the ID token is minted through the token
    // endpoint's real mint path.
    let code = h.issue_authenticated_code(&client_id).await;
    let token_form = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let (status, _headers, body) = h.token(&token_form).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let response = json_body(&body);
    let id_token = response["id_token"].as_str().expect("id_token");

    // The minted ID token's JWS header alg is the recorded RS256, NOT the
    // environment default EdDSA: the mint honored the per-client algorithm.
    assert_eq!(
        jws_header_alg(id_token),
        "RS256",
        "the id_token is signed under the recorded/echoed algorithm, not the env default"
    );
}

#[tokio::test]
async fn non_default_metadata_persists_across_a_read() {
    // FIX 2: a GET reads the client back from the DATABASE and every non-default
    // metadata field round-trips faithfully (never a masked default): a native
    // application_type, a non-default token_endpoint_auth_method, and a non-default
    // id_token_signed_response_alg (EdDSA is non-default here only vs the abstract
    // RS256 spec default the read no longer substitutes). The dual environment can
    // sign RS256, so the recorded RS256 is genuine and must survive the round-trip.
    let h = Harness::start_dual_signing(dcr_config()).await;
    let (status, reg) = post_json(
        &h,
        &register_path(&h),
        json!({
            "application_type": "native",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["http://127.0.0.1:52000/cb"],
            "id_token_signed_response_alg": ["RS256"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    assert_eq!(reg["id_token_signed_response_alg"], "RS256");
    let uri = to_path(reg["registration_client_uri"].as_str().expect("uri"));
    let token = reg["registration_access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    let (status, read) = send_json(&h, "GET", &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(
        read["application_type"], "native",
        "application_type round-trips from the database"
    );
    assert_eq!(
        read["token_endpoint_auth_method"], "none",
        "token_endpoint_auth_method round-trips from the database"
    );
    assert_eq!(
        read["id_token_signed_response_alg"], "RS256",
        "the non-default id_token_signed_response_alg round-trips, not a masked default"
    );
}

#[tokio::test]
async fn client_secret_jwt_and_unknown_methods_are_rejected() {
    // The registered auth method is validated against the implemented suite (#25):
    // client_secret_jwt is inert and unadvertised, so DCR refuses it.
    let h = Harness::start_with(dcr_config()).await;
    let path = register_path(&h);
    for method in ["client_secret_jwt", "tls_client_auth"] {
        let (status, body) = post_json(
            &h,
            &path,
            json!({
                "redirect_uris": ["https://rp.example/cb"],
                "token_endpoint_auth_method": method
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method}: {body}");
        assert_eq!(body["error"], "invalid_client_metadata", "{method}");
    }
}

#[tokio::test]
async fn private_key_jwt_with_inline_jwks_registers_and_gets_no_secret() {
    let h = Harness::start_with(dcr_config()).await;
    let jwks: Value = serde_json::from_str(&published_jwks(5)).expect("jwks value");
    let (status, body) = post_json(
        &h,
        &register_path(&h),
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(
        body["client_secret"].is_null(),
        "a private_key_jwt client gets no secret"
    );
    assert!(body["jwks"].is_object(), "the jwks is echoed");
}

#[tokio::test]
async fn jwks_and_jwks_uri_are_mutually_exclusive() {
    let h = Harness::start_with(dcr_config()).await;
    let (status, body) = post_json(
        &h,
        &register_path(&h),
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": { "keys": [] },
            "jwks_uri": "https://client.test/jwks.json"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn jwks_uri_registration_goes_through_the_hardened_fetcher() {
    // AC6 (positive): a reachable jwks_uri that yields keys registers, fetched
    // through the SSRF-hardened fetcher (a public sentinel resolution, dialed to an
    // in-process loopback JWKS server).
    let server = start_jwks_server(published_jwks(3)).await;
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, dialer);
    let resolver = Arc::new(ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    ));
    let h = Harness::start_with_resolver(dcr_config(), resolver).await;

    let (status, body) = post_json(
        &h,
        &register_path(&h),
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "http://client.test/jwks.json"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["jwks_uri"], "http://client.test/jwks.json");
}

#[tokio::test]
async fn jwks_uri_at_a_private_address_is_rejected_by_the_fetcher() {
    // AC6 (SSRF): a jwks_uri that resolves to the cloud-metadata link-local address
    // is blocked by the hardened fetcher, so the registration is refused. No detail
    // about the internal host leaks; the error is the uniform invalid_client_metadata.
    let dialer = Arc::new(RecordingDialer::new("127.0.0.1:9".parse().expect("addr")));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([
        169, 254, 169, 254,
    ])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, dialer);
    let resolver = Arc::new(ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    ));
    let h = Harness::start_with_resolver(dcr_config(), resolver).await;

    let (status, body) = post_json(
        &h,
        &register_path(&h),
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://client.test/jwks.json"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn the_registration_endpoint_is_absent_when_disabled() {
    // Default-off posture: with registration_enabled unset the routes are not
    // mounted, so a registration attempt is a uniform 404 (the #31 gating owns the
    // real policy; the endpoint simply does not exist here).
    let h = Harness::start().await;
    let (status, _) = post_json(
        &h,
        &register_path(&h),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn read_update_delete_require_the_token_and_delete_removes_the_client() {
    let h = Harness::start_with(dcr_config()).await;
    let (status, reg) = post_json(
        &h,
        &register_path(&h),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let uri = to_path(reg["registration_client_uri"].as_str().expect("uri"));
    let token = reg["registration_access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    // A wrong or missing token is a uniform 401 (no existence oracle).
    let (status, _) = send_json(&h, "GET", &uri, Some("not-the-token"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send_json(&h, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The correct token reads the metadata, and the secret is NEVER re-returned.
    let (status, read) = send_json(&h, "GET", &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert!(
        read["client_secret"].is_null(),
        "a read never returns the client secret"
    );
    assert!(
        read["registration_access_token"].is_null(),
        "a read never re-returns the registration token (only the hash is stored)"
    );

    // Delete, then the client is gone (a subsequent read is a uniform 401).
    let (status, _) = send_json(&h, "DELETE", &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send_json(&h, "GET", &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the client was deleted");
}

#[tokio::test]
async fn a_registration_is_not_reachable_under_another_tenants_scope() {
    // Cross-tenant isolation: the client_id embeds its own scope, so presenting it
    // under a DIFFERENT (provisioned) tenant/environment path fails closed.
    let h = Harness::start_with(dcr_config()).await;
    let (status, reg) = post_json(
        &h,
        &register_path(&h),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let client_id = reg["client_id"].as_str().expect("client_id").to_owned();
    let token = reg["registration_access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    let foreign = h.provision_foreign_scope().await;
    let cross = format!(
        "/t/{}/e/{}/connect/register/{}",
        foreign.tenant(),
        foreign.environment(),
        client_id
    );
    let (status, _) = send_json(&h, "GET", &cross, Some(&token), None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a client is not reachable through another tenant's scope"
    );
}

/// Start an in-process loopback HTTP server that serves `body` as a JSON JWKS to
/// every request, returning its address. The fetcher's injected dialer forwards to
/// this address, so the fetch exercises the real hardened dispatcher over plaintext
/// http without a public network (the same pattern as the #25 client-assertion test).
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
