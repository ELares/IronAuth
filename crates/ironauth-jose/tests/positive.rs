// SPDX-License-Identifier: MIT OR Apache-2.0

//! Positive vectors: a valid token of every supported algorithm verifies and
//! returns its claims. Ed25519 is signed deterministically at test time; the
//! ECDSA and RSA families come from committed offline-signed vectors.

mod common;

use common::vectors;
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};

/// Verify a static token against a single trusted key and assert the claims.
fn assert_verifies(alg: JwsAlgorithm, token: &str, key: TrustedKey, expect_kid: &str) {
    let policy = VerificationPolicy::new(vec![alg], vec![key], common::ISS, common::AUD)
        .expect("valid policy");
    let verified = verify(token, &policy, &common::now_clock())
        .unwrap_or_else(|e| panic!("{alg:?} should verify: {:?}", e.reason()));
    assert_eq!(verified.algorithm(), alg);
    assert_eq!(verified.key_id(), Some(expect_kid));
    assert_eq!(verified.claims().issuer(), common::ISS);
    assert_eq!(verified.claims().subject(), Some("user-123"));
    assert!(
        verified
            .claims()
            .audiences()
            .iter()
            .any(|a| a == common::AUD)
    );
}

#[test]
fn eddsa_verifies() {
    let signer = common::Ed25519Signer::new();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, common::ED25519_KID);
    let token = common::signed_ed25519(&signer, &header, &common::standard_claims());
    let key = TrustedKey::ed25519(Some(common::ED25519_KID.into()), signer.public_key())
        .expect("valid key");
    assert_verifies(JwsAlgorithm::EdDsa, &token, key, common::ED25519_KID);
}

#[test]
fn es256_verifies() {
    let key = TrustedKey::ecdsa_p256_point(Some("es256-1".into()), vectors::ES256_POINT)
        .expect("valid key");
    assert_verifies(JwsAlgorithm::Es256, vectors::ES256_TOKEN, key, "es256-1");
}

#[test]
fn es384_verifies() {
    let key = TrustedKey::ecdsa_p384_point(Some("es384-1".into()), vectors::ES384_POINT)
        .expect("valid key");
    assert_verifies(JwsAlgorithm::Es384, vectors::ES384_TOKEN, key, "es384-1");
}

#[test]
fn rs256_verifies() {
    let key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    assert_verifies(JwsAlgorithm::Rs256, vectors::RS256_TOKEN, key, "rsa-1");
}

#[test]
fn rs384_verifies() {
    let key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    assert_verifies(JwsAlgorithm::Rs384, vectors::RS384_TOKEN, key, "rsa-1");
}

#[test]
fn rs512_verifies() {
    let key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    assert_verifies(JwsAlgorithm::Rs512, vectors::RS512_TOKEN, key, "rsa-1");
}

#[test]
fn ps256_verifies() {
    let key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    assert_verifies(JwsAlgorithm::Ps256, vectors::PS256_TOKEN, key, "rsa-1");
}

#[test]
fn ps384_verifies() {
    let key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    assert_verifies(JwsAlgorithm::Ps384, vectors::PS384_TOKEN, key, "rsa-1");
}

#[test]
fn ps512_verifies() {
    let key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    assert_verifies(JwsAlgorithm::Ps512, vectors::PS512_TOKEN, key, "rsa-1");
}

#[test]
fn rsa_key_rejects_all_zero_exponent() {
    // A zero exponent strips to empty and is not a valid RSA public exponent;
    // the check is on the STRIPPED value, so `[0x00]` is refused.
    assert!(TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, &[0x00]).is_err());
    assert!(TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, &[0x00, 0x00]).is_err());
    // A normal exponent (65537 = 0x01 0x00 0x01) is still accepted.
    assert!(TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, &[0x01, 0x00, 0x01]).is_ok());
}

#[test]
fn ecdsa_coordinates_constructor_matches_point_constructor() {
    // The x,y coordinate constructor and the SEC1-point constructor accept the
    // same P-256 key (0x04 || x || y).
    let point = vectors::ES256_POINT;
    let x = &point[1..33];
    let y = &point[33..65];
    let key = TrustedKey::ecdsa_p256(Some("es256-1".into()), x, y).expect("valid key");
    assert_verifies(JwsAlgorithm::Es256, vectors::ES256_TOKEN, key, "es256-1");
}

#[test]
fn kid_selects_among_multiple_trusted_keys() {
    // A rotation set: several trusted keys, and the token's kid picks the right
    // one. The wrong-family and wrong-kid keys are ignored, not confused.
    let signer = common::Ed25519Signer::new();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, common::ED25519_KID);
    let token = common::signed_ed25519(&signer, &header, &common::standard_claims());

    let keys = vec![
        // A decoy Ed25519 key under a different kid.
        TrustedKey::ed25519(Some("old-ed".into()), &[7u8; 32]).expect("valid key"),
        // The correct key.
        TrustedKey::ed25519(Some(common::ED25519_KID.into()), signer.public_key())
            .expect("valid key"),
    ];
    let policy = VerificationPolicy::new(vec![JwsAlgorithm::EdDsa], keys, common::ISS, common::AUD)
        .expect("valid policy");
    let verified = verify(&token, &policy, &common::now_clock()).expect("should verify");
    assert_eq!(verified.key_id(), Some(common::ED25519_KID));
}

#[test]
fn verifies_without_kid_when_single_key() {
    // No kid in the header: with one trusted key of the right family, it is used.
    let signer = common::Ed25519Signer::new();
    let token = common::signed_ed25519(&signer, r#"{"alg":"EdDSA"}"#, &common::standard_claims());
    let key = TrustedKey::ed25519(None, signer.public_key()).expect("valid key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy");
    let verified = verify(&token, &policy, &common::now_clock()).expect("should verify");
    assert_eq!(verified.key_id(), None);
    assert_eq!(verified.claims().issuer(), common::ISS);
}

#[test]
fn array_audience_membership_is_accepted() {
    // aud as a JSON array containing the expected value verifies.
    let signer = common::Ed25519Signer::new();
    let claims = common::claims_with(
        common::ISS,
        r#"["someone-else","client-abc","third-party"]"#,
        i64::try_from(common::NOW).unwrap() + 3600,
        i64::try_from(common::NOW).unwrap() - 60,
        i64::try_from(common::NOW).unwrap() - 60,
    );
    let token = common::signed_ed25519(&signer, r#"{"alg":"EdDSA"}"#, &claims);
    let key = TrustedKey::ed25519(None, signer.public_key()).expect("valid key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy");
    let verified = verify(&token, &policy, &common::now_clock()).expect("array aud should verify");
    assert!(
        verified
            .claims()
            .audiences()
            .iter()
            .any(|a| a == common::AUD)
    );
}
