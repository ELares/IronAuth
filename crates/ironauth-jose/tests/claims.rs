// SPDX-License-Identifier: MIT OR Apache-2.0

//! Claim enforcement edges: exp/nbf/iat within a bounded skew, and EXACT
//! iss/aud matching (OIDC Core 3.1.3.7). Substring and prefix near-misses must
//! NOT match. Every token here is genuinely signed, so the claim check is what
//! decides the outcome.

mod common;

use std::time::Duration;

use ironauth_jose::{JwsAlgorithm, RejectReason, TrustedKey, VerificationPolicy, verify};

const NOW_I: i64 = 1_700_000_000;

/// Build a policy over the deterministic Ed25519 key with a given skew.
fn policy_with_skew(signer: &common::Ed25519Signer, skew: Duration) -> VerificationPolicy {
    let key = TrustedKey::ed25519(None, signer.public_key()).expect("valid key");
    VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy")
    .with_skew(skew)
}

/// Sign a token with the given raw claims JSON.
fn token(signer: &common::Ed25519Signer, claims: &str) -> String {
    common::signed_ed25519(signer, r#"{"alg":"EdDSA"}"#, claims)
}

fn outcome(claims: &str, skew: Duration) -> Result<(), RejectReason> {
    let signer = common::Ed25519Signer::new();
    let policy = policy_with_skew(&signer, skew);
    let tok = token(&signer, claims);
    verify(&tok, &policy, &common::now_clock())
        .map(|_| ())
        .map_err(|e| e.reason())
}

fn aud_claims(iss: &str, aud_json: &str) -> String {
    common::claims_with(iss, aud_json, NOW_I + 3600, NOW_I - 60, NOW_I - 60)
}

// ---- exp ----

#[test]
fn expired_beyond_skew_is_rejected() {
    // exp is 120s in the past; skew is 60s -> expired.
    let claims = common::claims_with(
        common::ISS,
        r#""client-abc""#,
        NOW_I - 120,
        NOW_I - 600,
        NOW_I - 600,
    );
    assert_eq!(
        outcome(&claims, Duration::from_secs(60)),
        Err(RejectReason::Expired)
    );
}

#[test]
fn expired_within_skew_is_accepted() {
    // exp is 30s in the past; skew is 60s -> still valid.
    let claims = common::claims_with(
        common::ISS,
        r#""client-abc""#,
        NOW_I - 30,
        NOW_I - 600,
        NOW_I - 600,
    );
    assert_eq!(outcome(&claims, Duration::from_secs(60)), Ok(()));
}

#[test]
fn exp_exactly_at_skew_boundary_is_accepted() {
    // now == exp + skew: not yet strictly past, so accepted.
    let claims = common::claims_with(
        common::ISS,
        r#""client-abc""#,
        NOW_I - 60,
        NOW_I - 600,
        NOW_I - 600,
    );
    assert_eq!(outcome(&claims, Duration::from_secs(60)), Ok(()));
}

#[test]
fn missing_exp_is_rejected_by_default() {
    let claims = format!(
        r#"{{"iss":"{}","aud":"{}","nbf":{},"iat":{}}}"#,
        common::ISS,
        common::AUD,
        NOW_I - 60,
        NOW_I - 60
    );
    assert_eq!(
        outcome(&claims, Duration::from_secs(60)),
        Err(RejectReason::ClaimMissing)
    );
}

// ---- nbf ----

#[test]
fn not_yet_valid_beyond_skew_is_rejected() {
    // nbf is 120s in the future; skew 60s -> not yet valid.
    let claims = common::claims_with(
        common::ISS,
        r#""client-abc""#,
        NOW_I + 3600,
        NOW_I + 120,
        NOW_I - 60,
    );
    assert_eq!(
        outcome(&claims, Duration::from_secs(60)),
        Err(RejectReason::NotYetValid)
    );
}

#[test]
fn nbf_within_skew_is_accepted() {
    let claims = common::claims_with(
        common::ISS,
        r#""client-abc""#,
        NOW_I + 3600,
        NOW_I + 30,
        NOW_I - 60,
    );
    assert_eq!(outcome(&claims, Duration::from_secs(60)), Ok(()));
}

// ---- iat ----

#[test]
fn issued_in_future_beyond_skew_is_rejected() {
    let claims = common::claims_with(
        common::ISS,
        r#""client-abc""#,
        NOW_I + 3600,
        NOW_I - 60,
        NOW_I + 120,
    );
    assert_eq!(
        outcome(&claims, Duration::from_secs(60)),
        Err(RejectReason::IssuedInFuture)
    );
}

#[test]
fn iat_within_skew_is_accepted() {
    let claims = common::claims_with(
        common::ISS,
        r#""client-abc""#,
        NOW_I + 3600,
        NOW_I - 60,
        NOW_I + 30,
    );
    assert_eq!(outcome(&claims, Duration::from_secs(60)), Ok(()));
}

#[test]
fn require_iat_rejects_when_absent() {
    let signer = common::Ed25519Signer::new();
    let key = TrustedKey::ed25519(None, signer.public_key()).expect("valid key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy")
    .require_iat(true);
    let claims = format!(
        r#"{{"iss":"{}","aud":"{}","exp":{},"nbf":{}}}"#,
        common::ISS,
        common::AUD,
        NOW_I + 3600,
        NOW_I - 60
    );
    let tok = token(&signer, &claims);
    let reason = verify(&tok, &policy, &common::now_clock())
        .err()
        .map(|e| e.reason());
    assert_eq!(reason, Some(RejectReason::ClaimMissing));
}

// ---- iss: exact match, near-misses rejected ----

#[test]
fn issuer_exact_match_is_accepted() {
    assert_eq!(
        outcome(
            &aud_claims(common::ISS, r#""client-abc""#),
            Duration::from_secs(60)
        ),
        Ok(())
    );
}

#[test]
fn issuer_substring_near_miss_is_rejected() {
    // Expected "https://issuer.example.test"; token has a suffix appended.
    for imposter in [
        "https://issuer.example.test.attacker.com",
        "https://issuer.example.tes",
        "https://ISSUER.example.test",
        "http://issuer.example.test",
        " https://issuer.example.test",
        "https://issuer.example.test ",
    ] {
        assert_eq!(
            outcome(
                &aud_claims(imposter, r#""client-abc""#),
                Duration::from_secs(60)
            ),
            Err(RejectReason::IssuerMismatch),
            "issuer {imposter:?} must not match",
        );
    }
}

#[test]
fn missing_issuer_is_rejected() {
    let claims = format!(
        r#"{{"aud":"{}","exp":{},"nbf":{},"iat":{}}}"#,
        common::AUD,
        NOW_I + 3600,
        NOW_I - 60,
        NOW_I - 60
    );
    assert_eq!(
        outcome(&claims, Duration::from_secs(60)),
        Err(RejectReason::ClaimMissing)
    );
}

// ---- aud: exact match / exact array membership, near-misses rejected ----

#[test]
fn audience_string_exact_match_is_accepted() {
    assert_eq!(
        outcome(
            &aud_claims(common::ISS, r#""client-abc""#),
            Duration::from_secs(60)
        ),
        Ok(())
    );
}

#[test]
fn audience_substring_near_miss_is_rejected() {
    for imposter in [
        r#""client-abc-extra""#,
        r#""client-ab""#,
        r#""CLIENT-ABC""#,
        r#"" client-abc""#,
    ] {
        assert_eq!(
            outcome(&aud_claims(common::ISS, imposter), Duration::from_secs(60)),
            Err(RejectReason::AudienceMismatch),
            "aud {imposter:?} must not match",
        );
    }
}

#[test]
fn audience_array_without_expected_member_is_rejected() {
    let claims = aud_claims(common::ISS, r#"["someone","client-abcd","else"]"#);
    assert_eq!(
        outcome(&claims, Duration::from_secs(60)),
        Err(RejectReason::AudienceMismatch)
    );
}

#[test]
fn audience_array_with_exact_member_is_accepted() {
    let claims = aud_claims(common::ISS, r#"["someone","client-abc","else"]"#);
    assert_eq!(outcome(&claims, Duration::from_secs(60)), Ok(()));
}

#[test]
fn missing_audience_is_rejected() {
    let claims = format!(
        r#"{{"iss":"{}","exp":{},"nbf":{},"iat":{}}}"#,
        common::ISS,
        NOW_I + 3600,
        NOW_I - 60,
        NOW_I - 60
    );
    assert_eq!(
        outcome(&claims, Duration::from_secs(60)),
        Err(RejectReason::ClaimMissing)
    );
}

// ---- policy construction cannot opt out of iss/aud ----

#[test]
fn policy_requires_issuer_and_audience() {
    let signer = common::Ed25519Signer::new();
    let key = || TrustedKey::ed25519(None, signer.public_key()).expect("valid key");
    assert!(
        VerificationPolicy::new(vec![JwsAlgorithm::EdDsa], vec![key()], "", common::AUD).is_err()
    );
    assert!(
        VerificationPolicy::new(vec![JwsAlgorithm::EdDsa], vec![key()], common::ISS, "").is_err()
    );
    assert!(VerificationPolicy::new(vec![], vec![key()], common::ISS, common::AUD).is_err());
    assert!(
        VerificationPolicy::new(vec![JwsAlgorithm::EdDsa], vec![], common::ISS, common::AUD)
            .is_err()
    );
}
