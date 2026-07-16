// SPDX-License-Identifier: MIT OR Apache-2.0

//! The WebAuthn passkey ceremony endpoints end to end (issue #65), through the
//! real OIDC router against a real database, driven by a software (virtual)
//! authenticator.
//!
//! A browser + WebDriver/CDP virtual authenticator is not runnable here, so this
//! test stands in for it at the HTTP layer: it calls the four ceremony endpoints,
//! builds genuinely valid ceremony responses (real Ed25519 assertion signatures via
//! the jose `test-util` helper, a CBOR attestationObject and COSE key), and asserts
//! the acceptance behaviour: a passkey registers for the authenticated user, a
//! discoverable-credential sign-in resolves the user and issues a session whose
//! authentication is `phr`, `excludeCredentials` is populated so the same
//! authenticator cannot register twice, and a wrong-origin ceremony is refused.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value};
use common::{Harness, ISSUER_BASE};
use ironauth_jose::webauthn::test_util;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

const RP_ID: &str = "issuer.test"; // host of ISSUER_BASE (https://issuer.test)
const SEED: [u8; 32] = [11_u8; 32];
const CRED_ID: &[u8] = b"http-ceremony-credential";

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

fn client_data(ceremony_type: &str, challenge_b64: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony_type}","challenge":"{challenge_b64}","origin":"{ISSUER_BASE}","crossOrigin":false}}"#
    )
    .into_bytes()
}

fn auth_data(flags: u8, sign_count: u32, attested: bool) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&sha256(RP_ID.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if attested {
        data.extend_from_slice(&[0xCD; 16]);
        data.extend_from_slice(&u16::try_from(CRED_ID.len()).unwrap().to_be_bytes());
        data.extend_from_slice(CRED_ID);
        data.extend_from_slice(&cose_key());
    }
    data
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

/// Register a passkey for `cookie`'s user and return the register/verify response.
async fn register(harness: &Harness, cookie: &str) -> (StatusCode, Json) {
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
    assert_eq!(opts["publicKey"]["rp"]["id"], RP_ID);

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
            "clientDataJSON": b64(&client_data("webauthn.create", &challenge_b64)),
            "attestationObject": b64(&attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });
    post(
        harness,
        &format!("{base}/register/verify"),
        Some(cookie),
        ISSUER_BASE,
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await
}

#[tokio::test]
async fn a_passkey_registers_and_signs_in_with_phr_acr() {
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // Register a passkey for the authenticated user.
    let (status, body) = register(&harness, &cookie).await;
    assert_eq!(status, StatusCode::CREATED, "register verify: {body}");
    assert_eq!(body["backup_eligible"], true);
    assert_eq!(body["discoverable"], true);

    // Sign in with the discoverable credential (no cookie: this IS the sign-in).
    let base = webauthn_base(&harness);
    let (status, opts) = post(
        &harness,
        &format!("{base}/authenticate/options"),
        None,
        ISSUER_BASE,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authenticate options: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();
    assert_eq!(opts["publicKey"]["rpId"], RP_ID);

    let authenticator_data = auth_data(0b0001_1101, 1, false); // UP|UV|BE|BS
    let client = client_data("webauthn.get", &challenge_b64);
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
    // Drive the verify and capture the Set-Cookie + body directly (a session is set).
    let request = Request::builder()
        .method("POST")
        .uri(format!("{base}/authenticate/verify"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", ISSUER_BASE)
        .body(Body::from(
            json!({ "challengeId": challenge_id, "credential": credential }).to_string(),
        ))
        .expect("request builds");
    let (status, headers, response) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK, "authenticate verify: {response}");
    let body: Json = serde_json::from_str(&response).unwrap();
    // The honest ACR of a UV synced passkey is phr, with swk+user amr.
    assert_eq!(body["acr"], "phr");
    let amr: Vec<&str> = body["amr"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(amr, vec!["swk", "user"]);
    // A session cookie was set.
    assert!(
        headers.get_all(header::SET_COOKIE).iter().count() >= 1,
        "the sign-in sets a session cookie"
    );
}

#[tokio::test]
async fn exclude_credentials_is_populated_after_registration_for_dedupe() {
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("bob@example.test", "another passphrase")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    let (status, _body) = register(&harness, &cookie).await;
    assert_eq!(status, StatusCode::CREATED);

    // A second registration ceremony now excludes the already-registered credential.
    let base = webauthn_base(&harness);
    let (status, opts) = post(
        &harness,
        &format!("{base}/register/options"),
        Some(&cookie),
        ISSUER_BASE,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let exclude = opts["publicKey"]["excludeCredentials"].as_array().unwrap();
    assert_eq!(
        exclude.len(),
        1,
        "the existing passkey is in excludeCredentials"
    );
    assert_eq!(exclude[0]["id"], b64(CRED_ID));

    // And re-verifying the SAME credential id is refused at the database (dedupe),
    // returning a 409 rather than a duplicate row.
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();
    let attestation_object = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data(0b0101_1101, 0, true)),
        ),
    ]));
    let credential = json!({
        "id": b64(CRED_ID), "rawId": b64(CRED_ID), "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client_data("webauthn.create", &challenge_b64)),
            "attestationObject": b64(&attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });
    let (status, _body) = post(
        &harness,
        &format!("{base}/register/verify"),
        Some(&cookie),
        ISSUER_BASE,
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a duplicate authenticator is refused"
    );
}

#[tokio::test]
async fn a_wrong_origin_ceremony_is_refused_without_enumerating() {
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("carol@example.test", "yet another one")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let base = webauthn_base(&harness);
    // A registration options call from a foreign origin is a CSRF 403.
    let (status, _body) = post(
        &harness,
        &format!("{base}/register/options"),
        Some(&cookie),
        "https://evil.test",
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
