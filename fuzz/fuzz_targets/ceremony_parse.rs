// SPDX-License-Identifier: MIT OR Apache-2.0

//! libFuzzer target for the WebAuthn ceremony response parsers (issue #65).
//!
//! Feeds arbitrary bytes through every byte-facing parser: the CBOR
//! attestationObject, the authenticator data (including the variable-length COSE
//! key slice), the COSE credential public key, and the clientDataJSON via the
//! full registration and authentication verify paths. The invariant is that no
//! input panics and no allocation is unbounded. Run with a nightly toolchain:
//! `cargo +nightly fuzz run ceremony_parse`.
//!
//! It also covers the DER and X.509 parsers behind `x509::parse_certificate`
//! (issue #419). Those run on bytes the CALLER does not control and BEFORE the
//! signature that would establish trust in them: a `packed` attestation statement's
//! `x5c` chain is parsed before its signature and chain checks, and an MDS3 BLOB's
//! `x5c` chain is parsed before the JWS signature check. Neither is reachable by
//! handing the fuzzer's bytes to a top-level entry point, so the target BUILDS the
//! two carriers (a CBOR attestation statement and a JWS header) around them.

#![no_main]

use base64::Engine as _;
use ciborium::value::Value;
use libfuzzer_sys::fuzz_target;

/// A fixed instant for the validity checks; the parsers under test are pure.
const NOW: i64 = 1_700_000_000;

fuzz_target!(|data: &[u8]| {
    // Raw binary / CBOR parsers.
    let _ = ironauth_webauthn::extract_auth_data(data);
    let _ = ironauth_webauthn::parse_authenticator_data(data);
    let _ = ironauth_webauthn::parse_cose_key(data);

    // Split the input into two halves and drive the full verify paths with the
    // halves as the base64url-carried clientDataJSON / attestationObject and
    // authenticatorData / signature fields.
    let mid = data.len() / 2;
    let (a, b) = data.split_at(mid);
    let origins = vec!["https://auth.example.test".to_string()];
    let params = ironauth_webauthn::VerificationParams {
        rp_id: "auth.example.test",
        allowed_origins: &origins,
        expected_challenge: b"expected",
        require_user_verification: true,
    };

    let reg_json = serde_json::json!({
        "response": {
            "clientDataJSON": ironauth_webauthn::b64_encode(a),
            "attestationObject": ironauth_webauthn::b64_encode(b),
            "transports": [],
        }
    });
    if let Ok(response) =
        serde_json::from_value::<ironauth_webauthn::RegistrationResponse>(reg_json)
    {
        let _ = ironauth_webauthn::verify_registration(&response, &params);
    }

    let auth_json = serde_json::json!({
        "response": {
            "clientDataJSON": ironauth_webauthn::b64_encode(a),
            "authenticatorData": ironauth_webauthn::b64_encode(b),
            "signature": ironauth_webauthn::b64_encode(a),
        }
    });
    if let Ok(response) =
        serde_json::from_value::<ironauth_webauthn::AuthenticationResponse>(auth_json)
    {
        let stored = ironauth_webauthn::StoredCredential {
            cose_public_key: b,
            sign_count: 0,
        };
        let _ = ironauth_webauthn::verify_authentication(&response, &stored, &params);
    }

    // The X.509 / DER parsers, reached the two ways a caller's bytes reach them.
    certificate_parsers(a, b);
});

/// Drive `x509::parse_certificate` (and the DER reader and time parser under it) on
/// `chain`, through both paths that parse a chain BEFORE verifying anything about it.
fn certificate_parsers(chain: &[u8], other: &[u8]) {
    // 1. A `packed` attestation statement. `verify_attestation` parses every `x5c`
    //    entry (and every trust anchor) before the signature, AAGUID, and chain
    //    checks. The passkey signup ceremony reaches it with no session at all, on a
    //    tenant whose attestation mode is `direct`.
    let statement = Value::Map(vec![
        (Value::Text("alg".into()), Value::Integer((-8_i64).into())),
        (Value::Text("sig".into()), Value::Bytes(other.to_vec())),
        (
            Value::Text("x5c".into()),
            Value::Array(vec![Value::Bytes(chain.to_vec())]),
        ),
    ]);
    let object = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("packed".into())),
        (Value::Text("attStmt".into()), statement),
        (Value::Text("authData".into()), Value::Bytes(other.to_vec())),
    ]);
    let mut encoded = Vec::new();
    if ciborium::into_writer(&object, &mut encoded).is_ok() {
        if let Ok(attestation) = ironauth_webauthn::parse_attestation_object(&encoded) {
            let credential_key = ironauth_webauthn::WebauthnKey::Ed25519 {
                public_key: vec![0; 32],
            };
            // The anchors go through the same parser, so they carry the bytes too.
            let anchors = vec![chain.to_vec()];
            let _ = ironauth_webauthn::verify_attestation(
                &attestation,
                &[0; 32],
                &credential_key,
                &[0; 16],
                &anchors,
                NOW,
            );
        }
    }

    // 2. An MDS3 BLOB. `verify_blob` parses the header's `x5c` chain BEFORE the JWS
    //    signature check, so a chain that never had a valid signature still reaches
    //    the certificate parser.
    let header = format!(
        r#"{{"alg":"EdDSA","typ":"JWT","x5c":["{}"]}}"#,
        base64::engine::general_purpose::STANDARD.encode(chain)
    );
    let blob = format!(
        "{}.{}.{}",
        ironauth_webauthn::b64_encode(header.as_bytes()),
        ironauth_webauthn::b64_encode(other),
        ironauth_webauthn::b64_encode(chain),
    );
    let _ = ironauth_webauthn::mds3::verify_blob(&blob, other, NOW);
}
