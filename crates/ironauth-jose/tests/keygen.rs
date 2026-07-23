// SPDX-License-Identifier: MIT OR Apache-2.0

//! Day-one asymmetric key GENERATION (issue #93).
//!
//! `ES256` and `RS256` day-one keys are generated with the `RustCrypto` `p256`/`rsa`
//! crates seeded off the entropy seam, then LOADED and signed exclusively through
//! `ring`. These tests prove the generated DER round-trips through `ring`'s
//! loaders and the one hardened verify path, and that generation is deterministic
//! under a fixed entropy source (the determinism seam).

mod common;

use ironauth_env::FixedEntropy;
use ironauth_jose::{
    EmissionOptions, JwsAlgorithm, SigningKey, VerificationPolicy, generate_ecdsa_p256_pkcs8_der,
    generate_rsa_pkcs1_der, sign_jws, verify,
};

/// A generated ES256 key loads through `ring` and mints a token the one verify
/// path accepts.
#[test]
fn generated_es256_key_round_trips_through_ring() {
    let entropy = FixedEntropy::new(101);
    let der = generate_ecdsa_p256_pkcs8_der(&entropy).expect("generate ES256");
    let key = SigningKey::ecdsa_p256_from_pkcs8(Some("es256-day-one".to_owned()), &der)
        .expect("ring loads the generated PKCS#8");
    assert_eq!(key.algorithm(), JwsAlgorithm::Es256);
    round_trip(&key, JwsAlgorithm::Es256);
}

/// A generated RS256 key loads through `ring` (2048-bit, above the floor) and
/// mints a token the one verify path accepts.
#[test]
fn generated_rs256_key_round_trips_through_ring() {
    let entropy = FixedEntropy::new(202);
    let der = generate_rsa_pkcs1_der(&entropy).expect("generate RS256");
    let key =
        SigningKey::rsa_from_pkcs1_der(Some("rs256-day-one".to_owned()), JwsAlgorithm::Rs256, &der)
            .expect("ring loads the generated PKCS#1 (2048-bit passes the floor)");
    assert_eq!(key.algorithm(), JwsAlgorithm::Rs256);
    round_trip(&key, JwsAlgorithm::Rs256);
}

/// Generation is deterministic: the same fixed entropy seed yields byte-identical
/// DER for both algorithms (the determinism seam).
#[test]
fn generation_is_deterministic_under_fixed_entropy() {
    let es_a = generate_ecdsa_p256_pkcs8_der(&FixedEntropy::new(7)).expect("es a");
    let es_b = generate_ecdsa_p256_pkcs8_der(&FixedEntropy::new(7)).expect("es b");
    assert_eq!(
        es_a, es_b,
        "ES256 keygen is reproducible under a fixed seed"
    );

    let rs_a = generate_rsa_pkcs1_der(&FixedEntropy::new(9)).expect("rs a");
    let rs_b = generate_rsa_pkcs1_der(&FixedEntropy::new(9)).expect("rs b");
    assert_eq!(
        rs_a, rs_b,
        "RS256 keygen is reproducible under a fixed seed"
    );

    // Different seeds diverge.
    let es_c = generate_ecdsa_p256_pkcs8_der(&FixedEntropy::new(8)).expect("es c");
    assert_ne!(es_a, es_c, "a different seed yields a different key");
}

/// Sign the standard claim set with `key` and prove the one verify path accepts it
/// under a single-algorithm, single-key policy built from the key's own public
/// half.
fn round_trip(key: &SigningKey, alg: JwsAlgorithm) {
    let clock = common::now_clock();
    let payload = common::standard_claims().into_bytes();
    let token = sign_jws(key, &payload, &EmissionOptions::new()).expect("sign");
    let trusted = key.verifying_key().expect("public projection");
    let policy = VerificationPolicy::new(vec![alg], vec![trusted], common::ISS, common::AUD)
        .expect("valid policy");
    let verified = verify(&token, &policy, &clock).expect("verify accepts the minted token");
    assert_eq!(verified.algorithm(), alg);
    assert_eq!(verified.claims().issuer(), common::ISS);
    assert_eq!(verified.key_id(), key.kid());
}
