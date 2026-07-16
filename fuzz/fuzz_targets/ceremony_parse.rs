// SPDX-License-Identifier: MIT OR Apache-2.0

//! libFuzzer target for the WebAuthn ceremony response parsers (issue #65).
//!
//! Feeds arbitrary bytes through every byte-facing parser: the CBOR
//! attestationObject, the authenticator data (including the variable-length COSE
//! key slice), the COSE credential public key, and the clientDataJSON via the
//! full registration and authentication verify paths. The invariant is that no
//! input panics and no allocation is unbounded. Run with a nightly toolchain:
//! `cargo +nightly fuzz run ceremony_parse`.

#![no_main]

use libfuzzer_sys::fuzz_target;

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
});
