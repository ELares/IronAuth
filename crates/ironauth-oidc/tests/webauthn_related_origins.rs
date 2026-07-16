// SPDX-License-Identifier: MIT OR Apache-2.0

//! WebAuthn Related Origin Requests end to end (issue #67), through the real OIDC
//! router against a real database, driven by a software (virtual) authenticator.
//!
//! This is the HTTP-layer stand-in for a browser + WebDriver/CDP harness with two
//! origins mapped to the test server. It proves the acceptance behaviour:
//!
//! - `GET /.well-known/webauthn` serves the `{"origins": [...]}` document with
//!   `application/json` and cache headers, generated from config (a different config
//!   yields a different document), and 404s when the feature is unconfigured.
//! - A passkey registered on the serving origin asserts successfully from a LISTED
//!   related origin (the one RP ID spanning two origins).
//! - An origin absent from the document fails: at the cross-site CSRF guard, and,
//!   past it, with the non-enumerating ceremony error from the WebAuthn origin
//!   algorithm (the RP-ID-hash, signature, and single-use-challenge checks unchanged).

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value};
use common::{Harness, ISSUER_BASE};
use ironauth_config::OidcConfig;
use ironauth_jose::webauthn::test_util;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

const RP_ID: &str = "issuer.test"; // host of ISSUER_BASE (https://issuer.test)
const RELATED_ORIGIN: &str = "https://related.example";
const SEED: [u8; 32] = [23_u8; 32];
const CRED_ID: &[u8] = b"related-origin-credential";

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn cose_key() -> Vec<u8> {
    let public_key = test_util::ed25519_public_key_from_seed(&SEED);
    cbor(&Value::Map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(1)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(-8)),
        ),
        (
            Value::Integer(Integer::from(-1)),
            Value::Integer(Integer::from(6)),
        ),
        (Value::Integer(Integer::from(-2)), Value::Bytes(public_key)),
    ]))
}

/// clientDataJSON with an explicit origin, so a ceremony can be crafted as if it ran
/// on the serving origin OR on a related origin.
fn client_data(ceremony_type: &str, challenge_b64: &str, origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony_type}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

/// Authenticator data. The RP ID hash is ALWAYS the serving RP ID (`issuer.test`):
/// a related-origin assertion is against the same RP ID, only the clientData origin
/// differs.
fn auth_data(flags: u8, sign_count: u32, attested: bool) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&sha256(RP_ID.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if attested {
        data.extend_from_slice(&[0xEF; 16]);
        data.extend_from_slice(&u16::try_from(CRED_ID.len()).unwrap().to_be_bytes());
        data.extend_from_slice(CRED_ID);
        data.extend_from_slice(&cose_key());
    }
    data
}

fn config_with_related() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        webauthn_related_origins: vec![RELATED_ORIGIN.to_owned()],
        ..OidcConfig::default()
    }
}

async fn post(
    harness: &Harness,
    path: &str,
    cookie: Option<&str>,
    origin: &str,
    body: &Json,
) -> (StatusCode, Json) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", origin);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let (status, _headers, response) = harness
        .send(
            builder
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if response.is_empty() {
        Json::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Json::Null)
    };
    (status, parsed)
}

fn webauthn_base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/webauthn", scope.tenant(), scope.environment())
}

/// Register a passkey on the SERVING origin for `cookie`'s user.
async fn register_on_serving_origin(harness: &Harness, cookie: &str) {
    let base = webauthn_base(harness);
    let (status, opts) = post(
        harness,
        &format!("{base}/register/options"),
        Some(cookie),
        ISSUER_BASE,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register options: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();

    let attestation_object = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data(0b0101_1101, 0, true)), // UP|UV|BE|BS|AT
        ),
    ]));
    let credential = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client_data("webauthn.create", &challenge_b64, ISSUER_BASE)),
            "attestationObject": b64(&attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });
    let (status, body) = post(
        harness,
        &format!("{base}/register/verify"),
        Some(cookie),
        ISSUER_BASE,
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register verify: {body}");
}

/// Fetch an authenticate/options challenge from `origin`.
async fn authenticate_options(harness: &Harness, origin: &str) -> (StatusCode, Json) {
    let base = webauthn_base(harness);
    post(
        harness,
        &format!("{base}/authenticate/options"),
        None,
        origin,
        &json!({}),
    )
    .await
}

#[tokio::test]
async fn well_known_webauthn_serves_the_related_origins_document() {
    let harness = Harness::start_with(config_with_related()).await;
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/webauthn")
        .body(Body::empty())
        .expect("request builds");
    let (status, headers, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    // Cacheable with a strong validator, like the other well-known surfaces.
    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        cache_control.contains("max-age="),
        "cache-control: {cache_control}"
    );
    assert!(headers.get(header::ETAG).is_some(), "a strong ETag is set");

    let doc: Json = serde_json::from_str(&body).unwrap();
    let origins: Vec<&str> = doc["origins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    // The serving origin plus the configured related origin, serving origin first.
    assert_eq!(origins, vec![ISSUER_BASE, RELATED_ORIGIN]);

    // A matching If-None-Match revalidates to 304 with no body (cheap refetch).
    let etag = headers
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let conditional = Request::builder()
        .method("GET")
        .uri("/.well-known/webauthn")
        .header(header::IF_NONE_MATCH, etag)
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, body) = harness.send(conditional).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
}

#[tokio::test]
async fn well_known_webauthn_is_generated_from_config_not_baked() {
    // The document is generated from live config at request time, not a static asset:
    // a deployment configured with a DIFFERENT related origin serves a DIFFERENT
    // document, and one with none 404s. This is what lets an operator change the
    // origin list without a code redeploy.
    let other = OidcConfig {
        require_pkce_for_confidential_clients: false,
        webauthn_related_origins: vec!["https://other-brand.example".to_owned()],
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(other).await;
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/webauthn")
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK);
    let doc: Json = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["origins"][1], "https://other-brand.example");

    // A deployment with no related origins configured serves no document (404), so an
    // unconfigured domain discloses nothing.
    let bare = OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(bare).await;
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/webauthn")
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, _body) = harness.send(request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_passkey_registered_on_the_serving_origin_asserts_from_a_related_origin() {
    let harness = Harness::start_with(config_with_related()).await;
    let subject = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // Register on the serving origin.
    register_on_serving_origin(&harness, &cookie).await;

    // Now sign in FROM THE RELATED ORIGIN: both the HTTP Origin header and the signed
    // clientData origin are the related origin, and the credential resolves through
    // its stored subject. No cookie (this IS the sign-in).
    let base = webauthn_base(&harness);
    let (status, opts) = authenticate_options(&harness, RELATED_ORIGIN).await;
    assert_eq!(status, StatusCode::OK, "authenticate options: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();

    let authenticator_data = auth_data(0b0001_1101, 1, false); // UP|UV|BE|BS
    let client = client_data("webauthn.get", &challenge_b64, RELATED_ORIGIN);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(&SEED, &signed);
    let credential = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client),
            "authenticatorData": b64(&authenticator_data),
            "signature": b64(&signature),
            "userHandle": b64(subject.as_bytes()),
        },
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("{base}/authenticate/verify"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", RELATED_ORIGIN)
        .body(Body::from(
            json!({ "challengeId": challenge_id, "credential": credential }).to_string(),
        ))
        .expect("request builds");
    let (status, headers, response) = harness.send(request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a passkey asserts from the related origin: {response}"
    );
    let body: Json = serde_json::from_str(&response).unwrap();
    assert_eq!(
        body["acr"], "phr",
        "the passkey sign-in is phishing-resistant"
    );
    assert!(
        headers.get_all(header::SET_COOKIE).iter().count() >= 1,
        "the related-origin sign-in sets a session cookie"
    );
}

#[tokio::test]
async fn an_unlisted_origin_is_refused_at_the_cross_site_guard() {
    let harness = Harness::start_with(config_with_related()).await;
    // authenticate/options from an origin absent from the document is a cross-site CSRF
    // 403 (the Origin is not in the operator allowlist).
    let (status, _body) = authenticate_options(&harness, "https://evil.example").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_unlisted_client_data_origin_fails_the_ceremony_without_enumerating() {
    // Past the CSRF guard (the HTTP Origin header is a LISTED origin), a crafted
    // assertion whose SIGNED clientData origin is UNLISTED still fails with the uniform
    // non-enumerating ceremony error: the WebAuthn origin algorithm rejects it. This is
    // the security boundary that does not depend on the browser-set Origin header.
    let harness = Harness::start_with(config_with_related()).await;
    let subject = harness
        .seed_user("carol@example.test", "yet another one")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    register_on_serving_origin(&harness, &cookie).await;

    let base = webauthn_base(&harness);
    let (status, opts) = authenticate_options(&harness, RELATED_ORIGIN).await;
    assert_eq!(status, StatusCode::OK, "{opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();

    // The signed clientData origin is an UNLISTED origin, though the HTTP Origin header
    // is the listed related origin (so the request clears the CSRF guard).
    let unlisted = "https://not-in-the-document.example";
    let authenticator_data = auth_data(0b0001_1101, 1, false);
    let client = client_data("webauthn.get", &challenge_b64, unlisted);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(&SEED, &signed);
    let credential = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client),
            "authenticatorData": b64(&authenticator_data),
            "signature": b64(&signature),
            "userHandle": b64(subject.as_bytes()),
        },
    });
    let (status, body) = post(
        &harness,
        &format!("{base}/authenticate/verify"),
        None,
        RELATED_ORIGIN,
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await;
    // The uniform ceremony error (never a 200 session, never an origin oracle).
    assert_ne!(
        status,
        StatusCode::OK,
        "an unlisted origin never signs in: {body}"
    );
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "the uniform non-enumerating ceremony error, got {status}: {body}"
    );
}

// --- RP-ID continuity across a serving-host cutover (acceptance criterion 5) ---

// The RP ID stays the stable registrable domain across the cutover; the two serving
// hosts are DIFFERENT subdomains under it, both valid registrable suffixes. The RP ID
// equals the existing `RP_ID` constant, so `auth_data`'s RP-ID-hash (sha256(RP_ID)) is
// already the stable hash both ceremonies present.
const CUTOVER_HOST_A: &str = "https://a.issuer.test";
const CUTOVER_HOST_B: &str = "https://b.issuer.test";

/// Config for the cutover test: the RP ID is pinned to the stable registrable domain
/// (`issuer.test`), independent of whichever serving host is live.
fn config_cutover() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        webauthn_rp_id: Some(RP_ID.to_owned()),
        ..OidcConfig::default()
    }
}

/// POST a JSON body through a specific router (a given serving host), returning the
/// status and parsed JSON.
async fn post_through(
    router: &Router,
    path: &str,
    cookie: Option<&str>,
    origin: &str,
    body: &Json,
) -> (StatusCode, Json) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", origin);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let (status, _headers, response) = common::send_through(
        router.clone(),
        builder
            .body(Body::from(body.to_string()))
            .expect("request builds"),
    )
    .await;
    let parsed = if response.is_empty() {
        Json::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Json::Null)
    };
    (status, parsed)
}

#[tokio::test]
async fn a_passkey_survives_a_serving_host_cutover_under_a_stable_rp_id() {
    // Acceptance criterion 5 (issue #67): a domain-cutover test proving passkeys survive
    // a hostname change under a stable RP ID, at the CEREMONY layer (not just config
    // load). The authData RP-ID-hash is sha256(rp_id), independent of the serving host,
    // so a passkey registered while the server is host A verifies after the server cuts
    // over to host B (a different registrable suffix of the same stable RP ID).
    let harness = Harness::start_with(config_cutover()).await;
    let subject = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let base = webauthn_base(&harness);

    // Host A is live: register a passkey. The clientData origin is host A; the authData
    // RP-ID-hash is sha256(issuer.test), the STABLE RP ID.
    let router_a = harness.serving_router(&config_cutover(), CUTOVER_HOST_A);
    let (status, opts) = post_through(
        &router_a,
        &format!("{base}/register/options"),
        Some(&cookie),
        CUTOVER_HOST_A,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register options on host A: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();

    let attestation_object = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data(0b0101_1101, 0, true)), // UP|UV|BE|BS|AT
        ),
    ]));
    let credential = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client_data("webauthn.create", &challenge_b64, CUTOVER_HOST_A)),
            "attestationObject": b64(&attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });
    let (status, body) = post_through(
        &router_a,
        &format!("{base}/register/verify"),
        Some(&cookie),
        CUTOVER_HOST_A,
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "register verify on host A: {body}"
    );

    // CUT OVER: the serving host is now host B, same stable RP ID, same shared database
    // (the credential persists). Sign in from host B with the passkey registered on A.
    let router_b = harness.serving_router(&config_cutover(), CUTOVER_HOST_B);
    let (status, opts) = post_through(
        &router_b,
        &format!("{base}/authenticate/options"),
        None,
        CUTOVER_HOST_B,
        &json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "authenticate options on host B: {opts}"
    );
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();

    // The assertion's clientData origin is host B; the authData RP-ID-hash is STILL
    // sha256(issuer.test), the stable RP ID the passkey was registered against.
    let authenticator_data = auth_data(0b0001_1101, 1, false); // UP|UV|BE|BS
    let client = client_data("webauthn.get", &challenge_b64, CUTOVER_HOST_B);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(&SEED, &signed);
    let credential = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client),
            "authenticatorData": b64(&authenticator_data),
            "signature": b64(&signature),
            "userHandle": b64(subject.as_bytes()),
        },
    });
    let (status, body) = post_through(
        &router_b,
        &format!("{base}/authenticate/verify"),
        None,
        CUTOVER_HOST_B,
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the passkey registered on host A still verifies after the cutover to host B: {body}"
    );
    assert_eq!(
        body["acr"], "phr",
        "the surviving passkey sign-in is still phishing-resistant"
    );
}
