// SPDX-License-Identifier: MIT OR Apache-2.0

//! A stable-toolchain fuzz harness for the ceremony parsers.
//!
//! The dedicated libFuzzer target (`fuzz/`) needs a nightly toolchain and runs
//! in its own CI lane; this test provides the same no-panic, bounded guarantee
//! on the stable toolchain that the normal gate runs. It drives a large volume
//! of deterministically generated, mostly-malformed inputs through every
//! byte-facing parser (the CBOR attestationObject, the authenticator data, the
//! COSE key, and the clientDataJSON via the full registration/authentication
//! verify path) and asserts only that they never panic and never return an
//! oversized allocation. Correctness of the happy path is covered by the
//! virtual-authenticator suite.

use ironauth_webauthn::{
    AuthenticationResponse, RegistrationResponse, VerificationParams, b64_encode,
    extract_auth_data, parse_authenticator_data, parse_cose_key, verify_authentication,
    verify_registration,
};

/// A tiny deterministic xorshift PRNG so the corpus is reproducible.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let span = u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1);
        let len = usize::try_from(self.next_u64() % span).unwrap_or(0);
        (0..len)
            .map(|_| u8::try_from(self.next_u64() & 0xff).unwrap_or(0))
            .collect()
    }
}

#[test]
fn parsers_never_panic_on_arbitrary_bytes() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..20_000 {
        let raw = rng.bytes(256);

        // Raw CBOR / binary parsers.
        if let Ok(auth_data) = extract_auth_data(&raw) {
            assert!(auth_data.len() <= raw.len());
        }
        if let Ok(parsed) = parse_authenticator_data(&raw) {
            if let Some(attested) = parsed.attested_credential {
                assert!(attested.credential_id.len() <= raw.len());
                assert!(attested.cose_public_key.len() <= raw.len());
            }
        }
        let _ = parse_cose_key(&raw);
    }
}

#[test]
fn verify_paths_never_panic_on_arbitrary_response_fields() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let origins = vec!["https://auth.example.test".to_string()];
    for _ in 0..10_000 {
        let params = VerificationParams {
            rp_id: "auth.example.test",
            allowed_origins: &origins,
            expected_challenge: b"expected",
            require_user_verification: true,
        };

        // Registration: random base64url fields for clientDataJSON /
        // attestationObject.
        let reg_json = serde_json::json!({
            "response": {
                "clientDataJSON": b64_encode(&rng.bytes(128)),
                "attestationObject": b64_encode(&rng.bytes(200)),
                "transports": [],
            }
        });
        if let Ok(response) = serde_json::from_value::<RegistrationResponse>(reg_json) {
            let _ = verify_registration(&response, &params);
        }

        // Authentication: random fields including a random stored COSE key.
        let auth_json = serde_json::json!({
            "response": {
                "clientDataJSON": b64_encode(&rng.bytes(128)),
                "authenticatorData": b64_encode(&rng.bytes(128)),
                "signature": b64_encode(&rng.bytes(80)),
            }
        });
        let stored_key = rng.bytes(160);
        if let Ok(response) = serde_json::from_value::<AuthenticationResponse>(auth_json) {
            let _ = verify_authentication(
                &response,
                &ironauth_webauthn::StoredCredential {
                    cose_public_key: &stored_key,
                    sign_count: 0,
                },
                &params,
            );
        }
    }
}
