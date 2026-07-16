// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end ceremony tests driven by a software (virtual) authenticator.
//!
//! A real browser + WebDriver/CDP virtual-authenticator harness is not runnable
//! in this environment, so these tests stand in for it at the API layer: they
//! craft genuinely valid ceremony responses (real Ed25519 assertion signatures
//! via the jose `test-util` helper) and drive [`verify_registration`] and
//! [`verify_authentication`]. They cover the registration -> authentication round
//! trip, BE/BS persistence and update, sign-count clone detection, the RP ID /
//! origin / challenge checks, and that a failed ceremony yields no credential.
//!
//! A browser-driven CI harness would additionally prove the conditional-UI
//! autofill mediation and the real navigator.credentials plumbing; that is noted
//! in the issue report.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value};
use ironauth_jose::webauthn::test_util;
use ironauth_webauthn::{
    AssertionOutcome, AuthenticationResponse, CeremonyError, RegisteredCredential,
    RegistrationResponse, SignCountVerdict, StoredCredential, VerificationParams,
    verify_authentication, verify_registration,
};
use sha2::{Digest, Sha256};

const RP_ID: &str = "auth.example.test";
const ORIGIN: &str = "https://auth.example.test";
const SEED: [u8; 32] = [7_u8; 32];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// The Ed25519 `COSE_Key` for the virtual authenticator's credential.
fn cose_key() -> Vec<u8> {
    let public_key = test_util::ed25519_public_key_from_seed(&SEED);
    cbor(&Value::Map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(1)),
        ), // kty OKP
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(-8)),
        ), // alg EdDSA
        (
            Value::Integer(Integer::from(-1)),
            Value::Integer(Integer::from(6)),
        ), // crv Ed25519
        (Value::Integer(Integer::from(-2)), Value::Bytes(public_key)),
    ]))
}

fn client_data(ceremony_type: &str, challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony_type}","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        b64(challenge)
    )
    .into_bytes()
}

/// Build authenticator data. `at` includes attested credential data (registration).
fn authenticator_data(flags: u8, sign_count: u32, cred_id: &[u8], at: bool) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&sha256(RP_ID.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if at {
        data.extend_from_slice(&[0xAB; 16]); // aaguid
        data.extend_from_slice(&u16::try_from(cred_id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(cred_id);
        data.extend_from_slice(&cose_key());
    }
    data
}

fn registration(challenge: &[u8], flags: u8, cred_id: &[u8], rk: bool) -> RegistrationResponse {
    let auth_data = authenticator_data(flags, 0, cred_id, true);
    let attestation_object = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]));
    let value = serde_json::json!({
        "id": b64(cred_id),
        "rawId": b64(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client_data("webauthn.create", challenge)),
            "attestationObject": b64(&attestation_object),
            "transports": ["internal", "hybrid"],
        },
        "clientExtensionResults": { "credProps": { "rk": rk } },
    });
    serde_json::from_value(value).unwrap()
}

fn assertion(
    challenge: &[u8],
    flags: u8,
    sign_count: u32,
    cred_id: &[u8],
) -> AuthenticationResponse {
    let auth_data = authenticator_data(flags, sign_count, cred_id, false);
    let client = client_data("webauthn.get", challenge);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(&SEED, &signed);
    let value = serde_json::json!({
        "id": b64(cred_id),
        "rawId": b64(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client),
            "authenticatorData": b64(&auth_data),
            "signature": b64(&signature),
            "userHandle": b64(b"user-handle"),
        },
    });
    serde_json::from_value(value).unwrap()
}

fn params<'a>(challenge: &'a [u8], origins: &'a [String]) -> VerificationParams<'a> {
    VerificationParams {
        rp_id: RP_ID,
        allowed_origins: origins,
        expected_challenge: challenge,
        require_user_verification: true,
    }
}

fn register(challenge: &[u8], flags: u8, cred_id: &[u8], rk: bool) -> RegisteredCredential {
    let origins = vec![ORIGIN.to_string()];
    verify_registration(
        &registration(challenge, flags, cred_id, rk),
        &params(challenge, &origins),
    )
    .expect("registration verifies")
}

// Flag bytes.
const REG_FLAGS_SYNCED: u8 = 0b0101_1101; // UP|UV|BE|BS|AT
const ASSERT_FLAGS_SYNCED: u8 = 0b0001_1101; // UP|UV|BE|BS
const REG_FLAGS_DEVICE_BOUND: u8 = 0b0100_0101; // UP|UV|AT (no BE/BS)

#[test]
fn registration_then_authentication_round_trip() {
    let cred_id = b"credential-id-abc";
    let reg = register(b"reg-challenge", REG_FLAGS_SYNCED, cred_id, true);
    assert_eq!(reg.credential_id, cred_id);
    assert!(reg.backup_eligible, "a synced passkey is backup-eligible");
    assert!(reg.backup_state);
    assert!(reg.user_verified);
    assert_eq!(reg.discoverable, Some(true), "credProps.rk stored");
    assert_eq!(reg.transports, vec!["internal", "hybrid"]);
    assert_eq!(reg.aaguid, [0xAB; 16]);

    let origins = vec![ORIGIN.to_string()];
    let challenge = b"auth-challenge";
    let outcome = verify_authentication(
        &assertion(challenge, ASSERT_FLAGS_SYNCED, 1, cred_id),
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: reg.sign_count,
        },
        &params(challenge, &origins),
    )
    .expect("assertion verifies with a real signature");
    assert_eq!(outcome.sign_count_verdict, SignCountVerdict::Ok);
    assert!(outcome.user_verified);
    assert!(outcome.backup_eligible);
}

#[test]
fn a_device_bound_passkey_records_no_backup_flags() {
    let reg = register(b"c", REG_FLAGS_DEVICE_BOUND, b"device-cred", false);
    assert!(
        !reg.backup_eligible,
        "device-bound key is not backup-eligible"
    );
    assert!(!reg.backup_state);
    assert_eq!(reg.discoverable, Some(false));
}

#[test]
fn backup_state_update_is_surfaced_on_assertion() {
    // Registered while not yet synced (BE set, BS clear), later asserts synced.
    let cred_id = b"cred-be-only";
    let reg = register(b"c", 0b0100_1101, cred_id, true); // UP|UV|BE|AT, no BS
    assert!(reg.backup_eligible);
    assert!(!reg.backup_state);

    let origins = vec![ORIGIN.to_string()];
    let challenge = b"later";
    let outcome = verify_authentication(
        &assertion(challenge, 0b0001_1101, 1, cred_id), // now BE|BS set
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 0,
        },
        &params(challenge, &origins),
    )
    .unwrap();
    assert!(
        outcome.backup_state,
        "the newly-synced state is surfaced to persist"
    );
}

#[test]
fn sign_count_regression_is_flagged_for_clone_detection() {
    let cred_id = b"cred-counter";
    let reg = register(b"c", REG_FLAGS_SYNCED, cred_id, true);
    let origins = vec![ORIGIN.to_string()];

    // First assertion advances the counter to 5: normal.
    let challenge = b"a1";
    let first = verify_authentication(
        &assertion(challenge, ASSERT_FLAGS_SYNCED, 5, cred_id),
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 0,
        },
        &params(challenge, &origins),
    )
    .unwrap();
    assert_eq!(first.sign_count_verdict, SignCountVerdict::Ok);
    assert_eq!(first.sign_count, 5);

    // A cloned authenticator presents a counter of 3 while 5 is stored.
    let challenge = b"a2";
    let cloned = verify_authentication(
        &assertion(challenge, ASSERT_FLAGS_SYNCED, 3, cred_id),
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 5,
        },
        &params(challenge, &origins),
    )
    .unwrap();
    assert_eq!(
        cloned.sign_count_verdict,
        SignCountVerdict::Regressed {
            stored: 5,
            presented: 3
        }
    );
}

#[test]
fn zero_counter_synced_passkey_never_trips_clone_detection() {
    let cred_id = b"cred-zero";
    let reg = register(b"c", REG_FLAGS_SYNCED, cred_id, true);
    let origins = vec![ORIGIN.to_string()];
    // Both stored and presented counters are zero across repeated assertions.
    for challenge in [b"z1".as_slice(), b"z2".as_slice()] {
        let outcome = verify_authentication(
            &assertion(challenge, ASSERT_FLAGS_SYNCED, 0, cred_id),
            &StoredCredential {
                cose_public_key: &reg.cose_public_key,
                sign_count: 0,
            },
            &params(challenge, &origins),
        )
        .unwrap();
        assert_eq!(outcome.sign_count_verdict, SignCountVerdict::NotSupported);
    }
}

#[test]
fn a_tampered_signature_is_rejected() {
    let cred_id = b"cred-tamper";
    let reg = register(b"c", REG_FLAGS_SYNCED, cred_id, true);
    let origins = vec![ORIGIN.to_string()];
    let challenge = b"a";
    let mut bad = assertion(challenge, ASSERT_FLAGS_SYNCED, 1, cred_id);
    // Corrupt the signature.
    bad.response.signature = b64(&[0_u8; 64]);
    let err = verify_authentication(
        &bad,
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 0,
        },
        &params(challenge, &origins),
    )
    .unwrap_err();
    assert_eq!(err, CeremonyError::BadSignature);
}

#[test]
fn a_replayed_or_wrong_challenge_is_rejected() {
    let cred_id = b"cred-chal";
    let reg = register(b"c", REG_FLAGS_SYNCED, cred_id, true);
    let origins = vec![ORIGIN.to_string()];
    // The assertion was made for "real-challenge" but the server expects another.
    let err = verify_authentication(
        &assertion(b"real-challenge", ASSERT_FLAGS_SYNCED, 1, cred_id),
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 0,
        },
        &params(b"a-different-expected-challenge", &origins),
    )
    .unwrap_err();
    assert_eq!(err, CeremonyError::ChallengeMismatch);
}

#[test]
fn a_foreign_origin_is_rejected() {
    let cred_id = b"cred-origin";
    let reg = register(b"c", REG_FLAGS_SYNCED, cred_id, true);
    let origins = vec!["https://not-this-origin.example.test".to_string()];
    let challenge = b"a";
    let err = verify_authentication(
        &assertion(challenge, ASSERT_FLAGS_SYNCED, 1, cred_id),
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 0,
        },
        &params(challenge, &origins),
    )
    .unwrap_err();
    assert_eq!(err, CeremonyError::OriginMismatch);
}

#[test]
fn a_missing_user_verification_is_rejected_when_required() {
    let cred_id = b"cred-uv";
    let reg = register(b"c", REG_FLAGS_SYNCED, cred_id, true);
    let origins = vec![ORIGIN.to_string()];
    let challenge = b"a";
    // Assertion with UP only (0x01|0x08|0x10 = BE/BS but no UV bit 0x04).
    let err = verify_authentication(
        &assertion(challenge, 0b0001_1001, 1, cred_id),
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 0,
        },
        &params(challenge, &origins),
    )
    .unwrap_err();
    assert_eq!(err, CeremonyError::UserVerificationMissing);
}

#[test]
fn registration_rejects_a_wrong_rp_id_hash() {
    // Craft authenticator data whose rpIdHash is for a different RP ID.
    let cred_id = b"cred-rp";
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&sha256(b"evil.example.test"));
    auth_data.push(REG_FLAGS_SYNCED);
    auth_data.extend_from_slice(&0_u32.to_be_bytes());
    auth_data.extend_from_slice(&[0xAB; 16]);
    auth_data.extend_from_slice(&u16::try_from(cred_id.len()).unwrap().to_be_bytes());
    auth_data.extend_from_slice(cred_id);
    auth_data.extend_from_slice(&cose_key());
    let attestation_object = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]));
    let challenge = b"c";
    let value = serde_json::json!({
        "id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client_data("webauthn.create", challenge)),
            "attestationObject": b64(&attestation_object),
            "transports": [],
        },
    });
    let response: RegistrationResponse = serde_json::from_value(value).unwrap();
    let origins = vec![ORIGIN.to_string()];
    assert_eq!(
        verify_registration(&response, &params(challenge, &origins)).unwrap_err(),
        CeremonyError::RpIdMismatch
    );
}

#[test]
fn cross_authenticator_signature_does_not_verify() {
    // A credential registered by SEED, but an assertion signed by a DIFFERENT
    // seed (a different authenticator) must not verify against the stored key.
    let cred_id = b"cred-x";
    let reg = register(b"c", REG_FLAGS_SYNCED, cred_id, true);
    let origins = vec![ORIGIN.to_string()];
    let challenge = b"a";
    // Build an assertion but sign with a different seed.
    let auth_data = authenticator_data(ASSERT_FLAGS_SYNCED, 1, cred_id, false);
    let client = client_data("webauthn.get", challenge);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&client));
    let signature = test_util::ed25519_sign(&[9_u8; 32], &signed); // wrong key
    let value = serde_json::json!({
        "id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client),
            "authenticatorData": b64(&auth_data),
            "signature": b64(&signature),
        },
    });
    let response: AuthenticationResponse = serde_json::from_value(value).unwrap();
    let outcome: Result<AssertionOutcome, _> = verify_authentication(
        &response,
        &StoredCredential {
            cose_public_key: &reg.cose_public_key,
            sign_count: 0,
        },
        &params(challenge, &origins),
    );
    assert_eq!(outcome.unwrap_err(), CeremonyError::BadSignature);
}
