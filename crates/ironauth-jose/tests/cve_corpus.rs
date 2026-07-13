// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CVE regression corpus: the 2025-2026 JOSE wave encoded as vectors that
//! MUST be rejected on every build. Each test asserts both that the token is
//! rejected and the exact internal [`RejectReason`], so a regression that starts
//! accepting one of these, or starts rejecting it for the wrong reason, fails
//! here. Positive vectors live in `positive.rs`.

mod common;

use common::vectors;
use ironauth_jose::{
    JwsAlgorithm, RejectReason, TrustedKey, VerificationCaps, VerificationPolicy, verify,
};

/// A policy trusting the deterministic Ed25519 key, allowing `EdDSA`.
fn ed25519_policy(signer: &common::Ed25519Signer) -> VerificationPolicy {
    let key = TrustedKey::ed25519(Some(common::ED25519_KID.into()), signer.public_key())
        .expect("valid key");
    VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy")
}

/// Assert a token is rejected with an exact reason under an Ed25519 policy.
fn assert_rejected(token: &str, expected: RejectReason) {
    let signer = common::Ed25519Signer::new();
    let policy = ed25519_policy(&signer);
    assert_rejected_with(token, &policy, expected);
}

fn assert_rejected_with(token: &str, policy: &VerificationPolicy, expected: RejectReason) {
    match verify(token, policy, &common::now_clock()) {
        Ok(_) => panic!("token was accepted but must be rejected ({expected:?})"),
        Err(err) => assert_eq!(err.reason(), expected, "rejected, but for the wrong reason"),
    }
}

// --------------------------------------------------------------------------
// alg:none, in every variant. Always rejected, no config to permit it.
// --------------------------------------------------------------------------

#[test]
fn alg_none_lowercase() {
    // A non-empty (but irrelevant) signature segment, so the token reaches the
    // header stage rather than being rejected as structurally unsecured.
    let token = common::assemble(r#"{"alg":"none"}"#, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::AlgNone);
}

#[test]
fn alg_none_case_variants() {
    for name in ["None", "NONE", "nOnE", "nonE"] {
        let header = format!(r#"{{"alg":"{name}"}}"#);
        // Even with a plausible-looking non-empty signature segment, still none.
        let token = common::assemble(&header, &common::standard_claims(), b"AAAA");
        assert_rejected(&token, RejectReason::AlgNone);
    }
}

#[test]
fn alg_empty_and_whitespace() {
    for name in ["", " ", "   "] {
        let header = format!(r#"{{"alg":"{name}"}}"#);
        let token = common::assemble(&header, &common::standard_claims(), b"sig");
        assert_rejected(&token, RejectReason::AlgNone);
    }
    // A JSON tab escape decodes to a whitespace-only alg, also `none`.
    let token = common::assemble(r#"{"alg":"\t"}"#, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::AlgNone);
}

#[test]
fn alg_absent_is_rejected() {
    let token = common::assemble(r#"{"kid":"x"}"#, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::AlgNone);
}

#[test]
fn alg_null_is_rejected() {
    let token = common::assemble(r#"{"alg":null}"#, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::AlgNone);
}

// --------------------------------------------------------------------------
// RS/HS key confusion. HS is unsupported and the key family is checked.
// --------------------------------------------------------------------------

#[test]
fn rs_hs_confusion_hmac_with_rsa_public_key() {
    // The classic attack: sign HS256 using the victim's RSA public key bytes as
    // the HMAC secret, and present it against a policy that trusts that RSA key.
    // It must fail: HS256 is not a supported algorithm at all.
    let header = r#"{"alg":"HS256","kid":"rsa-1"}"#;
    let claims = common::standard_claims();
    let signing_input = format!(
        "{}.{}",
        common::b64(header.as_bytes()),
        common::b64(claims.as_bytes())
    );
    let forged = common::hmac_sha256(vectors::RSA_PUB_PKCS1_DER, signing_input.as_bytes());
    let token = format!("{signing_input}.{}", common::b64(&forged));

    let rsa_key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    // Allowlist RS256 (what the issuer really uses); the token claims HS256.
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::Rs256],
        vec![rsa_key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy");
    assert_rejected_with(&token, &policy, RejectReason::UnsupportedAlg);
}

#[test]
fn hs256_is_unsupported_even_if_allowlist_were_bypassed() {
    // Any HS* alg is unsupported regardless of the rest of the token.
    for name in ["HS256", "HS384", "HS512"] {
        let header = format!(r#"{{"alg":"{name}"}}"#);
        let token = common::assemble(&header, &common::standard_claims(), b"sig");
        assert_rejected(&token, RejectReason::UnsupportedAlg);
    }
}

#[test]
fn alg_key_family_mismatch_is_rejected() {
    // A token claiming RS256 presented against a policy whose only trusted key
    // is EC: the family check fires before any signature work.
    let ec_key = TrustedKey::ecdsa_p256_point(Some("rsa-1".into()), vectors::ES256_POINT)
        .expect("valid key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::Rs256, JwsAlgorithm::Es256],
        vec![ec_key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy");
    // RS256 token (a real RSA-signed one) but only an EC key is trusted.
    assert_rejected_with(vectors::RS256_TOKEN, &policy, RejectReason::KeyTypeMismatch);
}

// --------------------------------------------------------------------------
// Algorithm allowlist: a supported alg outside the allowlist is rejected,
// regardless of whether its signature would verify.
// --------------------------------------------------------------------------

#[test]
fn supported_alg_outside_allowlist_is_rejected() {
    // A genuinely valid RS256 token, but the allowlist only permits EdDSA.
    let signer = common::Ed25519Signer::new();
    let rsa_key =
        TrustedKey::rsa(Some("rsa-1".into()), vectors::RSA_N, vectors::RSA_E).expect("valid key");
    let ed_key = TrustedKey::ed25519(Some(common::ED25519_KID.into()), signer.public_key())
        .expect("valid key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![rsa_key, ed_key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy");
    assert_rejected_with(vectors::RS256_TOKEN, &policy, RejectReason::AlgNotAllowed);
}

// --------------------------------------------------------------------------
// In-token key injection: jwk / jku / x5u / x5c. Fail closed.
// --------------------------------------------------------------------------

#[test]
fn embedded_jwk_injection_is_rejected() {
    // A token self-signed with an attacker key, carrying that key in `jwk`.
    // Even though the token verifies against its OWN embedded key, that key is
    // never trusted; the header is rejected before any signature check.
    let attacker = common::Ed25519Signer::new();
    let jwk = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
        common::b64(attacker.public_key())
    );
    let header = format!(r#"{{"alg":"EdDSA","jwk":{jwk}}}"#);
    let token = common::signed_ed25519(&attacker, &header, &common::standard_claims());
    // Trust a DIFFERENT out-of-band key; the token must not smuggle its own.
    let trusted = TrustedKey::ed25519(None, &[9u8; 32]).expect("valid key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![trusted],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy");
    assert_rejected_with(&token, &policy, RejectReason::EmbeddedKeyInjection);
}

#[test]
fn jku_reference_is_rejected() {
    let header = r#"{"alg":"EdDSA","jku":"https://attacker.example/keys.json"}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::EmbeddedKeyInjection);
}

#[test]
fn x5u_reference_is_rejected() {
    let header = r#"{"alg":"EdDSA","x5u":"https://attacker.example/cert.pem"}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::EmbeddedKeyInjection);
}

#[test]
fn x5c_chain_is_rejected() {
    let header = r#"{"alg":"EdDSA","x5c":["MIIB..."]}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::EmbeddedKeyInjection);
}

// --------------------------------------------------------------------------
// crit: unknown, malformed, duplicate.
// --------------------------------------------------------------------------

#[test]
fn unknown_crit_extension_is_rejected() {
    let header = r#"{"alg":"EdDSA","crit":["my-ext"],"my-ext":true}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::UnknownCrit);
}

#[test]
fn crit_not_an_array_is_rejected() {
    let header = r#"{"alg":"EdDSA","crit":"my-ext"}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::MalformedCrit);
}

#[test]
fn crit_empty_array_is_rejected() {
    let header = r#"{"alg":"EdDSA","crit":[]}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::MalformedCrit);
}

#[test]
fn crit_duplicate_member_is_rejected() {
    let header = r#"{"alg":"EdDSA","crit":["ext","ext"],"ext":1}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::MalformedCrit);
}

#[test]
fn crit_naming_registered_param_is_rejected() {
    // crit MUST NOT list registered header parameters (RFC 7515 4.1.11).
    let header = r#"{"alg":"EdDSA","crit":["alg"]}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::MalformedCrit);
}

#[test]
fn crit_non_string_member_is_rejected() {
    let header = r#"{"alg":"EdDSA","crit":[42]}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::MalformedCrit);
}

// --------------------------------------------------------------------------
// Decompression bombs and JWE: zip, enc, 5-segment JWE, PBES2.
// --------------------------------------------------------------------------

#[test]
fn zip_compression_header_is_rejected_before_inflation() {
    let header = r#"{"alg":"EdDSA","zip":"DEF"}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::CompressionPresent);
}

#[test]
fn bare_b64_header_member_is_rejected() {
    // RFC 7797: a bare `b64` (not in crit) steers payload encoding and must not
    // be silently ignored.
    let header = r#"{"alg":"EdDSA","b64":false}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::UnsupportedHeaderParam);
}

#[test]
fn five_segment_jwe_is_rejected_structurally() {
    // A JWE has five dot-separated segments; rejected before any field is read.
    let token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.encrypted_key.iv.ciphertext.tag";
    assert_rejected(token, RejectReason::MalformedStructure);
}

#[test]
fn enc_header_indicates_jwe_and_is_rejected() {
    let header = r#"{"alg":"EdDSA","enc":"A128GCM"}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::EncryptionPresent);
}

#[test]
fn pbes2_parameters_are_rejected() {
    // p2c/p2s indicate PBES2 key derivation (excluded). Rejected at the header.
    let header = r#"{"alg":"EdDSA","p2c":100000,"p2s":"c2FsdA"}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::Pbes2Present);
}

#[test]
fn pbes2_iteration_bomb_is_rejected_cheaply() {
    // An enormous p2c is rejected without doing any derivation work.
    let header = r#"{"alg":"EdDSA","p2c":1000000000}"#;
    let token = common::assemble(header, &common::standard_claims(), b"sig");
    assert_rejected(&token, RejectReason::Pbes2Present);
}

// --------------------------------------------------------------------------
// Size cap: oversized input rejected before any decode/parse/crypto.
// --------------------------------------------------------------------------

#[test]
fn oversized_token_is_rejected_before_work() {
    let signer = common::Ed25519Signer::new();
    let key = TrustedKey::ed25519(Some(common::ED25519_KID.into()), signer.public_key())
        .expect("valid key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy")
    .with_caps(VerificationCaps {
        max_token_bytes: 512,
        ..VerificationCaps::DEFAULT
    });
    let big = "a".repeat(4096);
    let token = format!("{big}.{big}.{big}");
    assert_rejected_with(&token, &policy, RejectReason::TokenTooLarge);
}

#[test]
fn oversized_header_segment_is_rejected() {
    let signer = common::Ed25519Signer::new();
    let policy = ed25519_policy(&signer);
    // A header segment over the 4 KiB decoded-header cap (about 5.4 K base64
    // chars) but with the whole token still under the 16 KiB token cap, so the
    // per-segment cap fires rather than the total-size cap.
    let huge_header = "a".repeat(6000);
    let token = format!("{huge_header}.eyJhIjoxfQ.c2ln");
    assert_rejected_with(&token, &policy, RejectReason::SegmentTooLarge);
}

// --------------------------------------------------------------------------
// Tampering and malformed structure.
// --------------------------------------------------------------------------

#[test]
fn tampered_signature_is_rejected() {
    let signer = common::Ed25519Signer::new();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, common::ED25519_KID);
    let token = common::signed_ed25519(&signer, &header, &common::standard_claims());
    // Flip the FIRST character of the signature segment (a full 6-bit code point,
    // so the segment stays valid base64url) to corrupt the signature without
    // tripping the base64 decoder: this must fail the crypto check itself.
    let (rest, sig) = token.rsplit_once('.').expect("three segments");
    let mut chars: Vec<char> = sig.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    let token = format!("{rest}.{tampered}");
    assert_rejected(&token, RejectReason::SignatureInvalid);
}

#[test]
fn tampered_payload_breaks_signature() {
    // Keep the original signature but swap the payload for different claims.
    let signer = common::Ed25519Signer::new();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, common::ED25519_KID);
    let good = common::signed_ed25519(&signer, &header, &common::standard_claims());
    let sig_segment = good.rsplit('.').next().expect("sig");
    let header_b64 = common::b64(header.as_bytes());
    let evil_payload = common::b64(
        common::claims_with(
            common::ISS,
            r#""client-abc""#,
            i64::try_from(common::NOW).unwrap() + 99_999,
            i64::try_from(common::NOW).unwrap() - 60,
            i64::try_from(common::NOW).unwrap() - 60,
        )
        .as_bytes(),
    );
    let token = format!("{header_b64}.{evil_payload}.{sig_segment}");
    assert_rejected(&token, RejectReason::SignatureInvalid);
}

#[test]
fn two_segment_token_is_rejected() {
    let token = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ4In0";
    assert_rejected(token, RejectReason::MalformedStructure);
}

#[test]
fn empty_signature_segment_is_rejected() {
    // The unsecured-JWS shape "header.payload." is rejected structurally.
    let header_b64 = common::b64(r#"{"alg":"EdDSA"}"#.as_bytes());
    let payload_b64 = common::b64(common::standard_claims().as_bytes());
    let token = format!("{header_b64}.{payload_b64}.");
    assert_rejected(&token, RejectReason::MalformedStructure);
}

#[test]
fn non_base64_header_is_rejected() {
    let token = "!!!not base64!!!.eyJhIjoxfQ.sig";
    assert_rejected(token, RejectReason::Base64Malformed);
}

#[test]
fn header_not_an_object_is_rejected() {
    let header_b64 = common::b64(b"[1,2,3]");
    let payload_b64 = common::b64(common::standard_claims().as_bytes());
    let token = format!("{header_b64}.{payload_b64}.{}", common::b64(b"sig"));
    assert_rejected(&token, RejectReason::HeaderMalformed);
}

#[test]
fn duplicate_header_key_is_rejected() {
    // Two `alg` members: a strict parser must not silently pick one.
    let header_b64 = common::b64(br#"{"alg":"EdDSA","alg":"none"}"#);
    let payload_b64 = common::b64(common::standard_claims().as_bytes());
    let token = format!("{header_b64}.{payload_b64}.{}", common::b64(b"sig"));
    assert_rejected(&token, RejectReason::HeaderMalformed);
}

#[test]
fn unknown_kid_names_no_trusted_key() {
    let signer = common::Ed25519Signer::new();
    let token = common::signed_ed25519(
        &signer,
        r#"{"alg":"EdDSA","kid":"ghost"}"#,
        &common::standard_claims(),
    );
    assert_rejected(&token, RejectReason::UnknownKid);
}
