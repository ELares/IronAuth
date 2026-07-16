// SPDX-License-Identifier: MIT OR Apache-2.0

//! Direct-mode passkey attestation end to end (issue #66 PR B), through the real
//! OIDC router against a real database, driven by a software authenticator.
//!
//! The pure attestation verifier (packed statement, X.509 chain, MDS3 blob) is unit
//! covered in `ironauth-webauthn`; this exercises the GLUE the OIDC registration path
//! wires together: attestation mode = `direct`, the AAGUID-rule disposition lookup,
//! the `mds3_blob_cache` read/parse, the packed-format dispatch, and the row
//! stamping. It proves acceptance criterion #1 end to end: with mode `direct`, an
//! allow-listed AAGUID, and a verified attestation root in the cache, a valid packed
//! attestation registers with `attestation_verified` + `attestation_type`/`fmt`
//! stamped on the credential row, and a subsequent login reaches the
//! `attested_passkey` acr. The negative half: a non-allow-listed AAGUID under
//! `direct` is a fail-closed reject that stamps nothing.
//!
//! The fixture PKI is a self-contained minimal DER encoder (the mirror of the
//! webauthn crate's own `testpki`, which is private to that crate): a self-signed
//! attestation root and an end-entity leaf carrying the FIDO AAGUID extension,
//! signed with Ed25519 through the jose `test-util` helper (the one crate allowed to
//! name `ring`), so this test never names `ring` either.

// The DER encoder mirrors the webauthn crate's own testpki, which carries the same
// allows: the byte casts are deliberate small-value truncations, and the WebAuthn
// abbreviations in the docs are spelled out here already.
#![allow(clippy::cast_possible_truncation, clippy::doc_markdown)]

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value};
use common::{Harness, ISSUER_BASE};
use ironauth_jose::webauthn::test_util;
use ironauth_store::{CorrelationId, Scope};
use ironauth_webauthn::mds3::{Mds3Entry, Mds3Payload};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

const RP_ID: &str = "issuer.test"; // host of ISSUER_BASE (https://issuer.test)
const CRED_SEED: [u8; 32] = [11_u8; 32]; // the created credential's key
const ROOT_SEED: [u8; 32] = [1_u8; 32]; // the attestation root's key
const LEAF_SEED: [u8; 32] = [2_u8; 32]; // the attestation leaf's (signer) key
const CRED_ID: &[u8] = b"attested-passkey-credential";
/// The allow-listed authenticator model. Matches the AAGUID stamped into the
/// authenticator data AND the leaf certificate's FIDO extension.
const AAGUID: [u8; 16] = [0xCD; 16];
/// A DIFFERENT, non-allow-listed model, for the fail-closed negative case.
const OTHER_AAGUID: [u8; 16] = [0xEE; 16];
/// A synced, user-verified passkey registration flag byte: UP|UV|BE|BS|AT.
const REG_SYNCED_UV: u8 = 0b0101_1101;
/// The matching assertion flag byte: UP|UV|BE|BS.
const ASSERT_SYNCED_UV: u8 = 0b0001_1101;
/// The attested-passkey acr the strongest rung achieves (issue #66 PR B).
const ACR_ATTESTED: &str = "urn:ironauth:acr:attested_passkey";
const FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01.

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

// ---- The credential's COSE key and the authenticator data. ----

fn cose_key(seed: &[u8; 32]) -> Vec<u8> {
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

fn client_data(ceremony_type: &str, challenge_b64: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony_type}","challenge":"{challenge_b64}","origin":"{ISSUER_BASE}","crossOrigin":false}}"#
    )
    .into_bytes()
}

/// Authenticator data with an attested-credential block carrying `aaguid`.
fn auth_data(flags: u8, sign_count: u32, aaguid: &[u8; 16], attested: bool) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&sha256(RP_ID.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if attested {
        data.extend_from_slice(aaguid);
        data.extend_from_slice(&u16::try_from(CRED_ID.len()).unwrap().to_be_bytes());
        data.extend_from_slice(CRED_ID);
        data.extend_from_slice(&cose_key(&CRED_SEED));
    }
    data
}

// ---- A minimal DER X.509 encoder for the fixture PKI (mirrors testpki). ----

mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const CONTEXT_CONSTRUCTED: u8 = 0xA0;
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

fn tlv(tag_byte: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag_byte];
    out.extend_from_slice(&der_len(contents.len()));
    out.extend_from_slice(contents);
    out
}

fn seq(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &elements.concat())
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut stack = Vec::new();
        let mut v = arc;
        stack.push((v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            stack.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        stack.reverse();
        body.extend_from_slice(&stack);
    }
    tlv(tag::OID, &body)
}

fn int(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(tag::INTEGER, &bytes)
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![0x00];
    body.extend_from_slice(bytes);
    tlv(tag::BIT_STRING, &body)
}

fn generalized_time(unix: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = unix_to_civil(unix);
    let text = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
    tlv(tag::GENERALIZED_TIME, text.as_bytes())
}

fn ed25519_alg_id() -> Vec<u8> {
    seq(&[oid(&[1, 3, 101, 112])])
}

fn name_cn(cn: &str) -> Vec<u8> {
    let atv = seq(&[oid(&[2, 5, 4, 3]), tlv(tag::UTF8_STRING, cn.as_bytes())]);
    let rdn = tlv(tag::SET, &atv);
    seq(&[rdn])
}

fn ed25519_spki(public_key: &[u8]) -> Vec<u8> {
    seq(&[ed25519_alg_id(), bit_string(public_key)])
}

fn aaguid_extension(aaguid: &[u8; 16]) -> Vec<u8> {
    let inner = tlv(tag::OCTET_STRING, aaguid);
    let ext_value = tlv(tag::OCTET_STRING, &inner);
    seq(&[oid(&[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4]), ext_value])
}

/// A critical `basicConstraints` `CA:TRUE` extension (for the self-signed root).
fn basic_constraints_ca() -> Vec<u8> {
    let ext_value = tlv(tag::OCTET_STRING, &seq(&[tlv(tag::BOOLEAN, &[0xFF])]));
    seq(&[oid(&[2, 5, 29, 19]), tlv(tag::BOOLEAN, &[0xFF]), ext_value])
}

struct CertSpec<'a> {
    subject_cn: &'a str,
    issuer_cn: &'a str,
    subject_seed: [u8; 32],
    issuer_seed: [u8; 32],
    is_ca: bool,
    aaguid: Option<[u8; 16]>,
}

fn build_cert(spec: &CertSpec<'_>) -> Vec<u8> {
    let subject_pub = test_util::ed25519_public_key_from_seed(&spec.subject_seed);
    let mut tbs_elements = vec![
        tlv(tag::CONTEXT_CONSTRUCTED, &int(2)), // [0] version v3
        int(1),                                 // serialNumber
        ed25519_alg_id(),                       // signature alg
        name_cn(spec.issuer_cn),
        seq(&[generalized_time(0), generalized_time(FAR_FUTURE)]),
        name_cn(spec.subject_cn),
        ed25519_spki(&subject_pub),
    ];
    let mut extensions: Vec<Vec<u8>> = Vec::new();
    if spec.is_ca {
        extensions.push(basic_constraints_ca());
    }
    if let Some(aaguid) = spec.aaguid {
        extensions.push(aaguid_extension(&aaguid));
    }
    if !extensions.is_empty() {
        tbs_elements.push(tlv(tag::CONTEXT_CONSTRUCTED | 3, &seq(&extensions)));
    }
    let tbs = seq(&tbs_elements);
    let signature = test_util::ed25519_sign(&spec.issuer_seed, &tbs);
    seq(&[tbs, ed25519_alg_id(), bit_string(&signature)])
}

fn unix_to_civil(unix: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, secs / 3_600, (secs % 3_600) / 60, secs % 60)
}

/// The self-signed attestation root DER and the end-entity leaf DER whose key
/// signs the packed attestation. The leaf carries `aaguid` and is CA:FALSE.
fn fixture_pki(aaguid: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
    let root = build_cert(&CertSpec {
        subject_cn: "Model Attestation Root",
        issuer_cn: "Model Attestation Root",
        subject_seed: ROOT_SEED,
        issuer_seed: ROOT_SEED,
        is_ca: true,
        aaguid: None,
    });
    let leaf = build_cert(&CertSpec {
        subject_cn: "Model Attestation Signer",
        issuer_cn: "Model Attestation Root",
        subject_seed: LEAF_SEED,
        issuer_seed: ROOT_SEED,
        is_ca: false,
        aaguid: Some(aaguid),
    });
    (root, leaf)
}

/// The packed attestationObject: fmt `packed`, an EdDSA `sig` over
/// `authData || clientDataHash` by the leaf key, and the leaf `x5c`.
fn packed_attestation_object(
    auth_data: &[u8],
    client_data_json: &[u8],
    leaf_der: &[u8],
) -> Vec<u8> {
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&sha256(client_data_json));
    let sig = test_util::ed25519_sign(&LEAF_SEED, &signed);
    cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("packed".into())),
        (
            Value::Text("attStmt".into()),
            Value::Map(vec![
                (
                    Value::Text("alg".into()),
                    Value::Integer(Integer::from(-8)), // EdDSA
                ),
                (Value::Text("sig".into()), Value::Bytes(sig)),
                (
                    Value::Text("x5c".into()),
                    Value::Array(vec![Value::Bytes(leaf_der.to_vec())]),
                ),
            ]),
        ),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]))
}

// ---- Store seeding and request drivers. ----

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

/// Configure `direct` attestation, allow-list `AAGUID`, and seed the verified MDS3
/// cache with `root_der` as the model's attestation root.
async fn seed_direct_mode(harness: &Harness, root_der: &[u8]) {
    let env = harness.env();
    let scope = harness.scope();
    let actor = harness.db().test_actor(env);
    let acting = || {
        harness
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(env))
    };
    acting()
        .attestation_config()
        .set(env, "direct")
        .await
        .expect("set direct mode");
    acting()
        .aaguid_rules()
        .set(env, &AAGUID, "allow")
        .await
        .expect("allow the aaguid");

    let payload = Mds3Payload {
        no: 1,
        next_update: FAR_FUTURE,
        entries: vec![Mds3Entry {
            aaguid: AAGUID,
            attestation_root_certs: vec![root_der.to_vec()],
        }],
    };
    let payload_json = serde_json::to_value(&payload).expect("payload serializes");
    let now = now_micros(harness);
    acting()
        .mds3_blob_cache()
        .upsert(
            env,
            payload.no,
            payload.next_update.saturating_mul(1_000_000),
            &payload_json,
            b"fixture-digest",
            now,
            now,
        )
        .await
        .expect("seed mds3 cache");
}

async fn post(
    harness: &Harness,
    path: &str,
    cookie: Option<&str>,
    body: &Json,
) -> (StatusCode, Json) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", ISSUER_BASE);
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

/// Register a passkey presenting a packed attestation over `aaguid`.
async fn register_packed(harness: &Harness, cookie: &str, aaguid: [u8; 16]) -> (StatusCode, Json) {
    let base = webauthn_base(harness);
    let (status, opts) = post(
        harness,
        &format!("{base}/register/options"),
        Some(cookie),
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register options: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();

    let (_root, leaf) = fixture_pki(aaguid);
    let authenticator_data = auth_data(REG_SYNCED_UV, 0, &aaguid, true);
    let client = client_data("webauthn.create", &challenge_b64);
    let attestation_object = packed_attestation_object(&authenticator_data, &client, &leaf);
    let credential = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client),
            "attestationObject": b64(&attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });
    post(
        harness,
        &format!("{base}/register/verify"),
        Some(cookie),
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await
}

/// Drive a discoverable sign-in with the registered credential and return the raw
/// status and parsed body.
async fn sign_in(harness: &Harness, subject: &str) -> (StatusCode, Json) {
    let base = webauthn_base(harness);
    let (status, opts) = post(
        harness,
        &format!("{base}/authenticate/options"),
        None,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authenticate options: {opts}");
    let challenge_id = opts["challengeId"].as_str().unwrap().to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();

    let authenticator_data = auth_data(ASSERT_SYNCED_UV, 1, &AAGUID, false);
    let client = client_data("webauthn.get", &challenge_b64);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(&CRED_SEED, &signed);
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
    post(
        harness,
        &format!("{base}/authenticate/verify"),
        None,
        &json!({ "challengeId": challenge_id, "credential": credential }),
    )
    .await
}

/// The stamped attestation facts on the single credential row, read directly.
async fn stamped_attestation(harness: &Harness, scope: Scope) -> Option<(String, bool, String)> {
    let row = sqlx::query(
        "SELECT attestation_type, attestation_verified, attestation_fmt \
         FROM webauthn_credentials WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_optional(harness.db().owner_pool())
    .await
    .expect("query credential row");
    row.map(|row| {
        (
            row.get::<String, _>("attestation_type"),
            row.get::<bool, _>("attestation_verified"),
            row.get::<String, _>("attestation_fmt"),
        )
    })
}

#[tokio::test]
async fn direct_mode_stamps_attestation_and_login_reaches_the_attested_rung() {
    let harness = Harness::start().await;
    let (root_der, _leaf) = fixture_pki(AAGUID);
    seed_direct_mode(&harness, &root_der).await;

    let subject = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // (a) A valid packed attestation over the allow-listed AAGUID registers, and the
    // attestation facts are stamped on the credential row.
    let (status, body) = register_packed(&harness, &cookie, AAGUID).await;
    assert_eq!(status, StatusCode::CREATED, "attested register: {body}");

    let stamped = stamped_attestation(&harness, harness.scope())
        .await
        .expect("a credential row exists");
    assert_eq!(
        stamped,
        ("basic".to_owned(), true, "packed".to_owned()),
        "attestation_type/verified/fmt are stamped from the verified packed attestation"
    );

    // (b) A subsequent discoverable login reaches the attested_passkey rung, which is
    // derived SOLELY from the stored attestation_verified fact.
    let (status, body) = sign_in(&harness, &subject).await;
    assert_eq!(status, StatusCode::OK, "attested sign-in: {body}");
    assert_eq!(
        body["acr"], ACR_ATTESTED,
        "an attested passkey login reaches the attested_passkey acr"
    );
}

#[tokio::test]
async fn direct_mode_rejects_a_non_allow_listed_aaguid_and_stamps_nothing() {
    let harness = Harness::start().await;
    let (root_der, _leaf) = fixture_pki(AAGUID);
    seed_direct_mode(&harness, &root_der).await;

    let subject = harness
        .seed_user("bob@example.test", "another passphrase")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // A registration presenting a DIFFERENT, non-allow-listed AAGUID under `direct`
    // is a fail-closed reject (the uniform ceremony error), and no row is stamped.
    let (status, body) = register_packed(&harness, &cookie, OTHER_AAGUID).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-allow-listed AAGUID under direct mode is rejected: {body}"
    );
    assert!(
        stamped_attestation(&harness, harness.scope())
            .await
            .is_none(),
        "a rejected direct-mode registration stamps no credential row"
    );
}
