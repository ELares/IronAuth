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

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value};
use common::{Harness, ISSUER_BASE};
use ironauth_config::OidcConfig;
use ironauth_jose::webauthn::test_util;
use ironauth_store::{
    AbuseBanId, AbuseSubject, ActorRef, AuthPath, CorrelationId, NewBan, ServiceId,
};
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
    // The honest ACR of a UV synced passkey is phr; the amr is swk+user (presence)
    // plus mfa, since user verification was performed on this assertion.
    assert_eq!(body["acr"], "phr");
    let amr: Vec<&str> = body["amr"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(amr, vec!["swk", "user", "mfa"]);
    // A session cookie was set.
    assert!(
        headers.get_all(header::SET_COOKIE).iter().count() >= 1,
        "the sign-in sets a session cookie"
    );
}

// The linear lifecycle (signup options -> verify -> DB assertions -> discoverable login)
// reads best as one test; splitting it would scatter the single flow it pins.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn passkey_only_signup_creates_no_password_row_then_logs_in_with_phr() {
    // The passkey-only (passwordless) lifecycle end to end (issue #66): signup mints an
    // account with NO password code path, and login/recovery are password-independent.
    // No account exists yet, so signup requires no session.
    let harness = Harness::start().await;
    let base = webauthn_base(&harness);
    let scope = harness.scope();
    let identifier = "passkey-only@example.test";

    // 1. signup/options: mint the subject and a UV-required registration challenge.
    let (status, opts) = post(
        &harness,
        &format!("{base}/signup/options"),
        None,
        ISSUER_BASE,
        &json!({ "identifier": identifier }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signup options: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();
    // The options advertise UV as REQUIRED for a passkey-only account.
    assert_eq!(
        opts["publicKey"]["authenticatorSelection"]["userVerification"], "required",
        "passkey-only signup forces user verification"
    );

    // 2. signup/verify: a valid UV registration (UP|UV|BE|BS|AT) creates the account and
    // establishes the HONEST passkey session that resumes the authorization request.
    let attestation_object = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data(0b0101_1101, 0, true)),
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
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let request = Request::builder()
        .method("POST")
        .uri(format!("{base}/signup/verify"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", ISSUER_BASE)
        .body(Body::from(
            json!({
                "challengeId": challenge_id,
                "returnTo": return_to,
                "identifier": identifier,
                "credential": credential,
            })
            .to_string(),
        ))
        .expect("request builds");
    let (status, headers, response) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK, "signup verify: {response}");
    let body: Json = serde_json::from_str(&response).unwrap();
    // The acr is the HONEST phishing-resistant passkey value, NEVER a fabricated pwd.
    assert_eq!(body["acr"], "phr", "a passkey-only signup logs in as phr");
    let amr: Vec<&str> = body["amr"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        !amr.contains(&"pwd"),
        "the amr never claims a password: {amr:?}"
    );
    assert_eq!(amr, vec!["swk", "user", "mfa"]);
    assert!(
        headers.get_all(header::SET_COOKIE).iter().count() >= 1,
        "signup establishes the session"
    );

    // 3. The stored account is passkey-only: NO non-sentinel password hash EVER existed.
    let user = harness
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .expect("lookup")
        .expect("the account was created");
    let stored = harness
        .store()
        .scoped(scope)
        .users()
        .password_hash_for_subject(&user.id)
        .await
        .expect("hash");
    assert_eq!(
        stored.as_deref(),
        Some("!"),
        "the passkey-only account holds only the unusable password sentinel"
    );
    assert_eq!(
        harness
            .store()
            .scoped(scope)
            .users()
            .is_passwordless(&user.id)
            .await
            .expect("is_passwordless"),
        Some(true)
    );

    // 4. Login (and the recovery-redemption path) are password-independent: the same
    // discoverable-credential sign-in resolves the passkey-only subject with an honest
    // phr, never touching a password. This is the login and recovery seam for a
    // passkey-only account (the full M8 recovery subsystem is out of scope).
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
    let authenticator_data = auth_data(0b0001_1101, 1, false);
    let client = client_data("webauthn.get", &challenge_b64);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(&SEED, &signed);
    let assertion = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client),
            "authenticatorData": b64(&authenticator_data),
            "signature": b64(&signature),
            "userHandle": b64(user.id.to_string().as_bytes()),
        },
    });
    let (status, login) = post(
        &harness,
        &format!("{base}/authenticate/verify"),
        None,
        ISSUER_BASE,
        &json!({ "challengeId": challenge_id, "credential": assertion }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "passkey-only login: {login}");
    assert_eq!(login["acr"], "phr", "the passkey-only login is honest phr");
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

// --- Authenticator-data flag divergence and the credential-management surface. ---
//
// These exercise the acr/amr truthfulness fixes (the assurance is pinned to the
// STORED backup-eligible flag, a BE flip is refused and audited, and the amr
// reflects whether user verification actually happened) and the authenticated,
// IDOR-safe passkey list/rename/remove surface, all through the real router.

// Authenticator-data flag bytes (bit0 UP, bit2 UV, bit3 BE, bit4 BS, bit6 AT).
const REG_SYNCED_UV: u8 = 0b0101_1101; // UP|UV|BE|BS|AT (a synced passkey)
const REG_DEVICE_UV: u8 = 0b0100_0101; // UP|UV|AT       (a device-bound passkey)
const ASSERT_SYNCED_UV: u8 = 0b0001_1101; // UP|UV|BE|BS
const ASSERT_DEVICE_UV: u8 = 0b0000_0101; // UP|UV
const ASSERT_SYNCED_UP_ONLY: u8 = 0b0001_1001; // UP|BE|BS (no UV: user presence only)

/// A COSE Ed25519 public-key document for an explicit seed.
fn cose_key_from(seed: &[u8; 32]) -> Vec<u8> {
    let public_key = test_util::ed25519_public_key_from_seed(seed);
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

/// Authenticator data for an explicit credential/seed and flag byte.
fn auth_data_for(
    cred_id: &[u8],
    seed: &[u8; 32],
    flags: u8,
    sign_count: u32,
    attested: bool,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&sha256(RP_ID.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if attested {
        data.extend_from_slice(&[0xCD; 16]);
        data.extend_from_slice(&u16::try_from(cred_id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(cred_id);
        data.extend_from_slice(&cose_key_from(seed));
    }
    data
}

/// Register a passkey with explicit credential material and registration flags.
async fn register_flags(
    harness: &Harness,
    cookie: &str,
    seed: &[u8; 32],
    cred_id: &[u8],
    reg_flags: u8,
) -> (StatusCode, Json) {
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
            Value::Bytes(auth_data_for(cred_id, seed, reg_flags, 0, true)),
        ),
    ]));
    let credential = json!({
        "id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key",
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

/// Drive an assertion with explicit flags. `user_handle` overrides the userHandle
/// sent (`None` sends none). Returns the raw status, headers, and body string.
async fn authenticate_flags(
    harness: &Harness,
    seed: &[u8; 32],
    cred_id: &[u8],
    user_handle: Option<&[u8]>,
    flags: u8,
    sign_count: u32,
) -> (StatusCode, HeaderMap, String) {
    let base = webauthn_base(harness);
    let (status, opts) = post(
        harness,
        &format!("{base}/authenticate/options"),
        None,
        ISSUER_BASE,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authenticate options: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();
    let authenticator_data = auth_data_for(cred_id, seed, flags, sign_count, false);
    let client = client_data("webauthn.get", &challenge_b64);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(seed, &signed);
    let mut response = json!({
        "clientDataJSON": b64(&client),
        "authenticatorData": b64(&authenticator_data),
        "signature": b64(&signature),
    });
    if let Some(handle) = user_handle {
        response["userHandle"] = Json::String(b64(handle));
    }
    let credential = json!({
        "id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key",
        "response": response,
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("{base}/authenticate/verify"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", ISSUER_BASE)
        .body(Body::from(
            json!({ "challengeId": challenge_id, "credential": credential }).to_string(),
        ))
        .expect("request builds");
    harness.send(request).await
}

/// A GET with an optional session cookie.
async fn get(harness: &Harness, path: &str, cookie: Option<&str>) -> (StatusCode, Json) {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let (status, _headers, response) = harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await;
    let parsed = if response.is_empty() {
        Json::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Json::Null)
    };
    (status, parsed)
}

#[tokio::test]
async fn a_backup_eligibility_flip_is_refused_and_audited_and_never_upgrades_acr() {
    // The security HIGH: a synced passkey (stored BE=1, honest acr phr) must not be
    // able to claim the device-bound phrh by presenting a cleared BE bit. The flip is
    // a spec violation (WebAuthn L3 7.2: BE is immutable), so it is refused and
    // audited, and the assurance is always pinned to the STORED BE.
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("dora@example.test", "correct horse")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let seed = [21_u8; 32];
    let cred = b"be-flip-credential";

    let (status, body) = register_flags(&harness, &cookie, &seed, cred, REG_SYNCED_UV).await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    assert_eq!(body["backup_eligible"], true, "registered synced (BE=1)");

    // Assert with the BE bit CLEARED (claiming device-bound). Refused, no session.
    let (status, headers, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_DEVICE_UV,
        1,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a BE flip must be refused with the non-enumerating error: {resp}"
    );
    assert_eq!(
        headers.get_all(header::SET_COOKIE).iter().count(),
        0,
        "a refused BE flip establishes no session"
    );
    assert_eq!(
        harness
            .count_audit_action("webauthn.backup_eligibility.mismatch")
            .await,
        1,
        "the BE-flip security event is audited"
    );

    // A matching (unflipped) assertion still signs in, and the acr is the STORED
    // synced value phr, never the device-bound phrh.
    let (status, _headers, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        2,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "honest assertion signs in: {resp}");
    let body: Json = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        body["acr"], "phr",
        "the acr is pinned to the stored synced BE"
    );
}

#[tokio::test]
async fn a_device_bound_passkey_signs_in_with_phrh() {
    // The other half of the distinction: a genuinely device-bound passkey (stored
    // BE=0) earns phrh, from the STORED registration-time BE.
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("evan@example.test", "battery staple")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let seed = [31_u8; 32];
    let cred = b"device-bound-credential";

    let (status, body) = register_flags(&harness, &cookie, &seed, cred, REG_DEVICE_UV).await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    assert_eq!(
        body["backup_eligible"], false,
        "registered device-bound (BE=0)"
    );

    let (status, _headers, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_DEVICE_UV,
        1,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign in: {resp}");
    let body: Json = serde_json::from_str(&resp).unwrap();
    assert_eq!(body["acr"], "phrh", "a device-bound passkey earns phrh");
    let amr: Vec<&str> = body["amr"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(amr, vec!["hwk", "user", "mfa"], "UV device-bound amr");
}

#[tokio::test]
async fn a_presence_only_passkey_amr_omits_the_verification_factor() {
    // With user verification NOT required, a user-presence-only assertion (UV=0)
    // still signs in and stays phishing-resistant (phr), but its amr must NOT claim a
    // verification factor: `user` (presence) stays, `mfa` is absent.
    let harness = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        webauthn_require_user_verification: false,
        ..OidcConfig::default()
    })
    .await;
    let subject = harness.seed_user("faye@example.test", "hunter two").await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let seed = [41_u8; 32];
    let cred = b"presence-only-credential";

    let (status, body) = register_flags(&harness, &cookie, &seed, cred, REG_SYNCED_UV).await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");

    let (status, _headers, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UP_ONLY,
        1,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "presence-only sign in: {resp}");
    let body: Json = serde_json::from_str(&resp).unwrap();
    assert_eq!(body["acr"], "phr", "phishing-resistant even without UV");
    let amr: Vec<&str> = body["amr"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        amr,
        vec!["swk", "user"],
        "presence kept, no verification factor"
    );
    assert!(
        !amr.contains(&"mfa"),
        "UP-only must not imply a verification factor"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_user_lists_renames_and_removes_only_their_own_passkey() {
    // The credential-management surface (acceptance criterion 3), IDOR-safe.
    let harness = Harness::start().await;
    let alice = harness.seed_user("alice@example.test", "alice pass").await;
    let (_a, alice_cookie) = harness.session_with_id(&alice, "pwd", 0).await;
    let bob = harness.seed_user("bobby@example.test", "bob pass").await;
    let (_b, bob_cookie) = harness.session_with_id(&bob, "pwd", 0).await;

    // Alice and Bob each register a passkey (distinct credential material).
    let (status, alice_reg) = register_flags(
        &harness,
        &alice_cookie,
        &[51_u8; 32],
        b"alice-cred",
        REG_SYNCED_UV,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "alice register: {alice_reg}");
    let alice_pky = alice_reg["id"].as_str().unwrap().to_owned();
    let (status, bob_reg) = register_flags(
        &harness,
        &bob_cookie,
        &[52_u8; 32],
        b"bob-cred",
        REG_DEVICE_UV,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bob register: {bob_reg}");
    let bob_pky = bob_reg["id"].as_str().unwrap().to_owned();

    let base = webauthn_base(&harness);

    // Alice lists her OWN passkeys with live BE/BS; Bob's is never present.
    let (status, listed) = get(
        &harness,
        &format!("{base}/credentials"),
        Some(&alice_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list: {listed}");
    let passkeys = listed["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1, "alice sees exactly her own passkey");
    assert_eq!(passkeys[0]["id"], alice_pky);
    assert_eq!(passkeys[0]["backup_eligible"], true, "live BE readable");
    assert_eq!(passkeys[0]["backup_state"], true, "live BS readable");
    assert!(
        !passkeys.iter().any(|p| p["id"] == bob_pky.as_str()),
        "alice never sees bob's passkey"
    );

    // The unified /account/credentials view also shows the passkey.
    let account = format!(
        "/t/{}/e/{}/account/credentials",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, creds) = get(&harness, &account, Some(&alice_cookie)).await;
    assert_eq!(status, StatusCode::OK, "account credentials: {creds}");
    assert!(
        creds["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == alice_pky.as_str() && c["type"] == "passkey"),
        "the passkey appears in the unified account credential list"
    );

    // Alice renames her OWN passkey.
    let (status, renamed) = post(
        &harness,
        &format!("{base}/credentials/rename"),
        Some(&alice_cookie),
        ISSUER_BASE,
        &json!({ "credentialId": alice_pky, "nickname": "Alice work laptop" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rename: {renamed}");
    assert_eq!(renamed["nickname"], "Alice work laptop");

    // Alice CANNOT rename or remove Bob's passkey: the uniform not-found.
    let (status, _b) = post(
        &harness,
        &format!("{base}/credentials/rename"),
        Some(&alice_cookie),
        ISSUER_BASE,
        &json!({ "credentialId": bob_pky, "nickname": "pwned" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cannot rename another user's passkey"
    );
    let (status, _b) = post(
        &harness,
        &format!("{base}/credentials/remove"),
        Some(&alice_cookie),
        ISSUER_BASE,
        &json!({ "credentialId": bob_pky }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cannot remove another user's passkey"
    );

    // Bob's passkey is untouched (still listable by Bob).
    let (status, bob_list) = get(&harness, &format!("{base}/credentials"), Some(&bob_cookie)).await;
    assert_eq!(status, StatusCode::OK, "bob list: {bob_list}");
    assert_eq!(bob_list["passkeys"].as_array().unwrap().len(), 1);

    // Alice removes her OWN passkey; it is gone.
    let (status, removed) = post(
        &harness,
        &format!("{base}/credentials/remove"),
        Some(&alice_cookie),
        ISSUER_BASE,
        &json!({ "credentialId": alice_pky }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remove: {removed}");
    let (status, after) = get(
        &harness,
        &format!("{base}/credentials"),
        Some(&alice_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        after["passkeys"].as_array().unwrap().is_empty(),
        "alice's passkey is gone after removal"
    );
    assert_eq!(
        harness
            .count_audit_action("webauthn.credential.rename")
            .await,
        1,
        "the rename is audited"
    );
    assert_eq!(
        harness
            .count_audit_action("webauthn.credential.remove")
            .await,
        1,
        "the remove is audited"
    );
}

#[tokio::test]
async fn a_regressing_sign_count_with_block_policy_denies_the_signin() {
    // Clone-detection BLOCK path (only the warn path was integration-tested before):
    // a regressing counter under block policy returns 403 and establishes no session.
    let harness = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        webauthn_clone_detection_block: true,
        ..OidcConfig::default()
    })
    .await;
    let subject = harness.seed_user("gwen@example.test", "sign count").await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let seed = [61_u8; 32];
    let cred = b"clone-detect-credential";

    let (status, _body) = register_flags(&harness, &cookie, &seed, cred, REG_SYNCED_UV).await;
    assert_eq!(status, StatusCode::CREATED);

    // Advance the counter to 5.
    let (status, headers, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        5,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first assertion: {resp}");
    assert!(headers.get_all(header::SET_COOKIE).iter().count() >= 1);

    // A REGRESSING counter (3 < 5) under block policy is denied with no session.
    let (status, headers, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        3,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a clone under block policy is denied: {resp}"
    );
    assert_eq!(
        headers.get_all(header::SET_COOKIE).iter().count(),
        0,
        "a blocked clone establishes no session"
    );
    assert_eq!(
        harness.count_audit_action("webauthn.clone.detected").await,
        1,
        "the clone-detection event is audited"
    );
}

#[tokio::test]
async fn a_mismatched_user_handle_is_refused() {
    // Defensive userHandle check (WebAuthn L3 7.2): a userHandle that does not match
    // the credential's stored subject is refused, even though resolution is by
    // credential id.
    let harness = Harness::start().await;
    let subject = harness.seed_user("hank@example.test", "user handle").await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let seed = [71_u8; 32];
    let cred = b"user-handle-credential";

    let (status, _body) = register_flags(&harness, &cookie, &seed, cred, REG_SYNCED_UV).await;
    assert_eq!(status, StatusCode::CREATED);

    // A crafted userHandle (not the stored subject) is refused.
    let (status, _headers, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(b"usr_someone-else"),
        ASSERT_SYNCED_UV,
        1,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a mismatched userHandle is refused: {resp}"
    );

    // The matching userHandle still works.
    let (status, _headers, _resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        2,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the correct userHandle signs in");
}

#[tokio::test]
async fn a_passwordless_user_is_blocked_from_removing_their_last_passkey() {
    // The passwordless self-lockout guard end to end: a passkey-only account (no
    // password ever provisioned) cannot remove its only login factor, but can with
    // the recovery acknowledgment. This mirrors the #61 account-credential guardrail.
    let harness = Harness::start().await;
    let subject = harness.seed_passwordless_user("lockout@example.test").await;
    let (_id, cookie) = harness.session_with_id(&subject, "passkey", 0).await;
    let seed = [81_u8; 32];
    let cred = b"lockout-credential";

    let (status, reg) = register_flags(&harness, &cookie, &seed, cred, REG_SYNCED_UV).await;
    assert_eq!(status, StatusCode::CREATED, "register: {reg}");
    let pky = reg["id"].as_str().unwrap().to_owned();
    let base = webauthn_base(&harness);

    // Removing the last usable login factor is blocked (409 last_credential).
    let (status, body) = post(
        &harness,
        &format!("{base}/credentials/remove"),
        Some(&cookie),
        ISSUER_BASE,
        &json!({ "credentialId": pky }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "blocked: {body}");
    assert_eq!(body["error"], "last_credential");

    // The passkey is untouched (a blocked removal deletes nothing).
    let (status, listed) = get(&harness, &format!("{base}/credentials"), Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["passkeys"].as_array().unwrap().len(), 1);

    // With the explicit acknowledgment, the removal proceeds.
    let (status, removed) = post(
        &harness,
        &format!("{base}/credentials/remove"),
        Some(&cookie),
        ISSUER_BASE,
        &json!({ "credentialId": pky, "acknowledgeRecovery": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "acknowledged removal: {removed}");
    assert_eq!(removed["removed"], true);
    let (status, after) = get(&harness, &format!("{base}/credentials"), Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(after["passkeys"].as_array().unwrap().is_empty());
}

// --- Passkey-path regulation (issue #64 MEDIUM-2) ---

/// The current clock-seam time in microseconds since the Unix epoch.
fn now_micros(harness: &Harness) -> i64 {
    i64::try_from(
        harness
            .env()
            .clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Place an operator ban on `subject` for `path` through the audited store repository, as
/// the CLI/admin ban surface would.
async fn place_ban(harness: &Harness, subject: &AbuseSubject, path: AuthPath) {
    let env = harness.env();
    let scope = harness.scope();
    let id = AbuseBanId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::from_seed_bytes([7_u8; 16]));
    harness
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .abuse()
        .ban(
            env,
            NewBan {
                id: &id,
                subject,
                auth_path: path,
                reason: "test ban",
                expires_at_unix_micros: None,
            },
            now_micros(harness),
        )
        .await
        .expect("place ban");
}

/// Register a synced UV passkey for the seeded `identifier` and return its subject, the
/// authenticator seed, and the credential id, ready to drive a discoverable sign-in.
async fn enrolled_passkey(
    harness: &Harness,
    identifier: &str,
    seed: [u8; 32],
    cred: &'static [u8],
) -> String {
    let subject = harness.seed_user(identifier, "correct horse battery").await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let (status, body) = register_flags(harness, &cookie, &seed, cred, REG_SYNCED_UV).await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    subject
}

#[tokio::test]
async fn a_passkey_ban_blocks_a_passkey_sign_in() {
    // A passkey-path ban is ENFORCED on the passkey ceremony (issue #64 MEDIUM-2): the
    // account is governed on its OWN passkey path, so an operator-placed passkey ban refuses
    // the sign-in with the uniform throttle rather than doing nothing.
    let harness = Harness::start().await;
    let seed = [41_u8; 32];
    let cred = b"passkey-ban-cred";
    let subject = enrolled_passkey(&harness, "ada@example.test", seed, cred).await;

    // Sanity: without a ban the passkey signs in.
    let (status, _h, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        1,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "baseline passkey sign-in: {resp}");

    // Place a passkey-path ban on the account, then a fresh sign-in is refused (429).
    place_ban(
        &harness,
        &AbuseSubject::account(subject.clone()),
        AuthPath::Passkey,
    )
    .await;
    let (status, _h, _resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        2,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a passkey ban must block the passkey sign-in"
    );
}

#[tokio::test]
async fn an_all_ban_blocks_a_passkey_sign_in() {
    // An `all`-path ban spans every path, so it blocks the passkey ceremony too (issue #64
    // MEDIUM-2).
    let harness = Harness::start().await;
    let seed = [42_u8; 32];
    let cred = b"passkey-all-ban-cred";
    let subject = enrolled_passkey(&harness, "bru@example.test", seed, cred).await;

    place_ban(
        &harness,
        &AbuseSubject::account(subject.clone()),
        AuthPath::All,
    )
    .await;
    let (status, _h, _resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        1,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "an `all` ban must block the passkey sign-in"
    );
}

#[tokio::test]
async fn a_password_path_ban_does_not_block_the_passkey_path() {
    // Path INDEPENDENCE (issue #64 MEDIUM-2, the account-DoS safeguard): the passkey path is
    // governed independently of the password path, so a PASSWORD-path ban on the account
    // (the most severe state a failed-password spray can reach under hard lockout) does NOT
    // throttle or block the owner's passkey sign-in.
    let harness = Harness::start().await;
    let seed = [43_u8; 32];
    let cred = b"passkey-independence-cred";
    let subject = enrolled_passkey(&harness, "cyd@example.test", seed, cred).await;

    // A password-path ban is placed on the account (what a spray under hard lockout yields).
    place_ban(
        &harness,
        &AbuseSubject::account(subject.clone()),
        AuthPath::Password,
    )
    .await;
    // The password path IS banned...
    let subjects = [AbuseSubject::account(subject.clone())];
    assert!(
        harness
            .store()
            .scoped(harness.scope())
            .abuse()
            .active_ban(&subjects, AuthPath::Password, now_micros(&harness))
            .await
            .expect("ban check")
            .is_some(),
        "the password path is banned"
    );
    // ...but the passkey sign-in still succeeds: the password ban does not govern passkey.
    let (status, _h, resp) = authenticate_flags(
        &harness,
        &seed,
        cred,
        Some(subject.as_bytes()),
        ASSERT_SYNCED_UV,
        1,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a password-path ban must NOT block the passkey path: {resp}"
    );
}

/// An authenticated GET carrying the session cookie, returning status and body.
async fn get_with_cookie(harness: &Harness, path: &str, cookie: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, body) = harness.send(request).await;
    (status, body)
}

/// Issue #73: with the Signal API enabled, the signal-data endpoint returns the
/// authenticated caller's accepted credential id list and details; with it off, the
/// endpoint is a uniform not-found (fully inert).
#[tokio::test]
async fn signal_data_returns_the_accepted_credential_list_and_is_flag_gated() {
    let harness = Harness::start_with(OidcConfig {
        webauthn_signal_api_enabled: true,
        ..OidcConfig::default()
    })
    .await;
    let subject = harness.seed_user("sig@example.test", "correct horse").await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let (status, body) = register(&harness, &cookie).await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");

    let base = webauthn_base(&harness);
    let (status, body) = get_with_cookie(&harness, &format!("{base}/signal"), &cookie).await;
    assert_eq!(status, StatusCode::OK, "signal data: {body}");
    let data: Json = serde_json::from_str(&body).expect("signal json");
    assert_eq!(data["rpId"], RP_ID);
    let accepted: Vec<String> = data["acceptedCredentialIds"]
        .as_array()
        .expect("accepted list")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        accepted,
        vec![b64(CRED_ID)],
        "the accepted list is exactly the registered credential id"
    );
    assert!(
        data["userDetails"]["name"].is_string(),
        "user details carry a name"
    );

    // Flag OFF (the default): the endpoint is a uniform not-found.
    let off = Harness::start().await;
    let off_subject = off.seed_user("sig2@example.test", "battery staple").await;
    let (_id, off_cookie) = off.session_with_id(&off_subject, "pwd", 0).await;
    let off_base = webauthn_base(&off);
    let (status, _) = get_with_cookie(&off, &format!("{off_base}/signal"), &off_cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "signal is inert when off");
}

/// Issue #73: the hosted management page emits the feature-detected signal script only
/// when the flag is on, and no signal JavaScript when off (no page change).
#[tokio::test]
async fn manage_page_emits_signal_script_only_when_the_flag_is_on() {
    let on = Harness::start_with(OidcConfig {
        webauthn_signal_api_enabled: true,
        ..OidcConfig::default()
    })
    .await;
    let subject = on.seed_user("mng@example.test", "correct horse").await;
    let (_id, cookie) = on.session_with_id(&subject, "pwd", 0).await;
    let base = webauthn_base(&on);
    let (status, body) = get_with_cookie(&on, &format!("{base}/manage"), &cookie).await;
    assert_eq!(status, StatusCode::OK, "manage page: {body}");
    assert!(
        body.contains("signalAllAcceptedCredentials"),
        "emits the signal JS"
    );
    assert!(body.contains("signalCurrentUserDetails"));

    // Flag OFF: the page renders but carries no signal JavaScript.
    let off = Harness::start().await;
    let off_subject = off.seed_user("mng2@example.test", "battery staple").await;
    let (_id, off_cookie) = off.session_with_id(&off_subject, "pwd", 0).await;
    let off_base = webauthn_base(&off);
    let (status, body) = get_with_cookie(&off, &format!("{off_base}/manage"), &off_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("signalAllAcceptedCredentials"),
        "no signal JS when off"
    );
    assert!(!body.contains("<script"), "no script at all when off");
}
