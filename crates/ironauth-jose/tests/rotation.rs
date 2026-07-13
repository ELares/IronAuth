// SPDX-License-Identifier: MIT OR Apache-2.0

//! JWKS serving discipline and per-environment signing policy.
//!
//! Drives the [`ironauth_jose::KeySet`] and [`ironauth_jose::SigningPolicy`]
//! primitives against a deterministic clock reading to prove the choreography the
//! issuer model requires: a next key is pre-published a full lead before its first
//! use, a retired key is retained until the last token it signed has expired,
//! tokens verify across the rotation boundary, the signing policy is enforced at
//! mint, and the published JWKS is filtered by policy with the RS256 downgrade key
//! always retained.

mod common;

use std::time::{Duration, SystemTime};

use ironauth_env::ManualClock;
use ironauth_jose::{
    EmissionOptions, JwsAlgorithm, KeySet, RotationParams, SignError, SigningKey, SigningPolicy,
    VerificationPolicy, sign_jws, sign_jws_with_policy, verify,
};
use serde_json::json;

use common::signing_keys;

/// A base instant far enough past the epoch that a pre-publish lead never
/// underflows.
const BASE_SECS: u64 = 1_700_000_000;

/// The issuer and audience the verification policies expect.
const ISS: &str = "https://issuer.example.test/t/ten_x/e/env_y";
const AUD: &str = "cli_client";

/// A `SystemTime` `secs` seconds past the Unix epoch.
fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// A `ManualClock` frozen at `secs` seconds past the Unix epoch.
fn clock_at(secs: u64) -> ManualClock {
    ManualClock::new(at(secs))
}

/// A deterministic Ed25519 signing key from a one-byte seed fill, with `kid`.
fn ed25519(kid: &str, seed_byte: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed_byte; 32]).expect("ed25519 key")
}

/// The fixture ES256 key with `kid`.
fn es256(kid: &str) -> SigningKey {
    SigningKey::ecdsa_p256_from_pkcs8(Some(kid.to_owned()), signing_keys::ES256_PKCS8)
        .expect("es256 key")
}

/// The fixture RS256 key with `kid`.
fn rs256(kid: &str) -> SigningKey {
    SigningKey::rsa_from_pkcs1_der(
        Some(kid.to_owned()),
        JwsAlgorithm::Rs256,
        signing_keys::RSA_PKCS1,
    )
    .expect("rs256 key")
}

/// Minimal claims valid at `now_secs` with the given lifetime.
fn claims(iat_secs: u64, exp_secs: u64) -> Vec<u8> {
    json!({
        "iss": ISS,
        "sub": "user-123",
        "aud": AUD,
        "iat": iat_secs,
        "exp": exp_secs,
    })
    .to_string()
    .into_bytes()
}

/// Standard rotation parameters: 300s cache, 300s max token lifetime, 60s buffer.
/// The pre-publish lead is therefore 660s and retention 300s.
fn params() -> RotationParams {
    RotationParams {
        cache_ttl: Duration::from_secs(300),
        max_token_lifetime: Duration::from_secs(300),
        prepublish_buffer: Duration::from_secs(60),
    }
}

#[test]
fn prepublish_lead_and_retention_follow_the_formula() {
    let p = params();
    assert_eq!(p.prepublish_lead(), Duration::from_secs(660));
    assert_eq!(p.retention_after_retire(), Duration::from_secs(300));
}

/// Acceptance criterion 3: a clock-driven rotation. The next key is pre-published
/// a full lead before first use, the retired key is retained until the last token
/// it signed expires, and tokens verify across the rotation boundary.
#[test]
fn rotation_prepublishes_retains_and_verifies_across_the_boundary() {
    let policy = SigningPolicy::eddsa_default();
    let p = params();
    let lead = p.prepublish_lead().as_secs(); // 660
    let retain = p.retention_after_retire().as_secs(); // 300

    let t0 = BASE_SECS;
    let activate = t0 + 100_000; // k2 activates well in the future
    let publish_next = activate - lead; // k2 is pre-published here

    // Genesis key k1 active from t0; rotate in k2 at `activate`.
    let k1 = ed25519("k1", 0x11);
    let k1_pub = k1.verifying_key().expect("k1 public");
    let mut keyset = KeySet::bootstrap(k1, at(t0));

    let k2 = ed25519("k2", 0x22);
    let k2_pub = k2.verifying_key().expect("k2 public");
    keyset
        .rotate(k2, at(activate), p)
        .expect("monotonic rotation");

    // Before the pre-publish instant, only k1 is published and k1 signs.
    let before = publish_next - 10;
    assert_eq!(keyset.published_kids(at(before), &policy), vec!["k1"]);
    assert_eq!(keyset.active_kid(at(before)), Some("k1"));

    // At the pre-publish instant, k2 joins the JWKS (pre-published) but k1 still
    // signs: the new key is in every cache a full lead before its first use.
    assert_eq!(
        keyset.published_kids(at(publish_next), &policy),
        vec!["k1", "k2"]
    );
    assert_eq!(keyset.active_kid(at(publish_next)), Some("k1"));

    // Just before activation, a token is signed by k1 with a full-lifetime exp.
    let sign_time = activate - 10;
    let k1_signer = keyset
        .active_signer_for(at(sign_time), JwsAlgorithm::EdDsa)
        .expect("k1 active");
    assert_eq!(k1_signer.kid(), Some("k1"));
    let token_exp = sign_time + p.max_token_lifetime.as_secs();
    let k1_token = sign_jws(
        k1_signer,
        &claims(sign_time, token_exp),
        &EmissionOptions::new().with_typ("JWT"),
    )
    .expect("sign with k1");

    // At activation the active signer flips to k2, but k1 is RETAINED in the JWKS
    // (its token is still in flight).
    assert_eq!(keyset.active_kid(at(activate)), Some("k2"));
    assert_eq!(
        keyset.published_kids(at(activate), &policy),
        vec!["k1", "k2"]
    );

    // Across the boundary (k2 active), the k1-signed token still verifies: a
    // relying party trusting the published JWKS (both keys) selects k1 by kid.
    let rp_policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![k1_pub.clone(), k2_pub.clone()],
        ISS,
        AUD,
    )
    .expect("policy");
    let verified = verify(&k1_token, &rp_policy, &clock_at(activate + 50));
    assert!(
        verified.is_ok(),
        "k1 token must verify after k2 becomes active: {:?}",
        verified.err()
    );

    // k1 is retained until the last token it signed can have expired: retire is at
    // `activate`, so retention lasts until activate + retain.
    let retire_deadline = activate + retain;
    assert_eq!(
        keyset.published_kids(at(retire_deadline - 1), &policy),
        vec!["k1", "k2"],
        "k1 retained while its tokens may still be valid"
    );
    // The k1 token's own exp is within that retention window.
    assert!(
        token_exp < retire_deadline,
        "token outlives its key's retention"
    );

    // Once past the retention deadline, k1 is withdrawn and only k2 remains.
    assert_eq!(
        keyset.published_kids(at(retire_deadline), &policy),
        vec!["k2"]
    );
    assert_eq!(keyset.active_kid(at(retire_deadline)), Some("k2"));
}

/// A rotation whose activation is not strictly after the current key is refused.
#[test]
fn non_monotonic_rotation_is_refused() {
    let mut keyset = KeySet::bootstrap(ed25519("k1", 0x11), at(BASE_SECS + 1000));
    let err = keyset
        .rotate(ed25519("k2", 0x22), at(BASE_SECS + 1000), params())
        .expect_err("same activation instant is refused");
    assert_eq!(err, ironauth_jose::RotationError::NonMonotonicActivation);
}

/// Acceptance criterion 4: kids are unique across the full key history.
#[test]
fn kids_are_unique_across_full_history() {
    let mut keyset = KeySet::bootstrap(ed25519("k1", 0x11), at(BASE_SECS));
    keyset
        .rotate(ed25519("k2", 0x22), at(BASE_SECS + 100_000), params())
        .expect("rotate k2");
    keyset
        .rotate(ed25519("k3", 0x33), at(BASE_SECS + 200_000), params())
        .expect("rotate k3");
    assert_eq!(keyset.all_kids(), vec!["k1", "k2", "k3"]);
    assert!(keyset.kids_are_unique());
}

/// Acceptance criterion 7: an ES256-only policy never produces an `EdDSA` token,
/// and an `EdDSA`-only policy never produces an ES256 token. Enforced at mint.
#[test]
fn policy_is_enforced_at_signing_both_ways() {
    let es_only = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("policy");
    let eddsa_only = SigningPolicy::eddsa_default();

    let eddsa_key = ed25519("ed", 0x11);
    let es256_key = es256("es");
    let payload = claims(BASE_SECS, BASE_SECS + 300);
    let opts = EmissionOptions::new().with_typ("JWT");

    // ES256-only policy refuses to sign with the EdDSA key, but signs with ES256.
    assert_eq!(
        sign_jws_with_policy(&es_only, &eddsa_key, &payload, &opts),
        Err(SignError::AlgorithmNotPermitted)
    );
    let es256_token =
        sign_jws_with_policy(&es_only, &es256_key, &payload, &opts).expect("es256 signs");
    assert_eq!(header_alg(&es256_token), "ES256");
    assert_ne!(header_alg(&es256_token), "EdDSA");

    // EdDSA-only policy refuses ES256 but signs EdDSA.
    assert_eq!(
        sign_jws_with_policy(&eddsa_only, &es256_key, &payload, &opts),
        Err(SignError::AlgorithmNotPermitted)
    );
    let eddsa_token =
        sign_jws_with_policy(&eddsa_only, &eddsa_key, &payload, &opts).expect("eddsa signs");
    assert_eq!(header_alg(&eddsa_token), "EdDSA");
}

/// A key set's policy-aware signer never selects a banned algorithm, even when its
/// key is still published (the retained RS256 downgrade key).
#[test]
fn policy_signer_selection_skips_banned_algorithms() {
    let now = at(BASE_SECS);
    let mut keyset = KeySet::bootstrap(ed25519("ed", 0x11), now);
    keyset.add(es256("es"), now);
    keyset.add(rs256("rs"), now);

    // ES256-only policy: the signer is the ES256 key even though EdDSA and RS256
    // keys are active/published.
    let policy = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("policy");
    let signer = keyset.signer_for_policy(now, &policy).expect("a signer");
    assert_eq!(signer.algorithm(), JwsAlgorithm::Es256);
    assert_eq!(signer.kid(), Some("es"));
}

/// Acceptance criterion 8: an ES256-only tenant's JWKS publishes no Ed25519 key,
/// retains its RS256 key (the downgrade covenant), and contains its ES256 key.
#[test]
fn es256_only_jwks_drops_ed25519_retains_rs256_keeps_es256() {
    let now = at(BASE_SECS);
    let mut keyset = KeySet::bootstrap(ed25519("ed", 0x11), now);
    keyset.add(es256("es"), now);
    keyset.add(rs256("rs"), now);

    let policy = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("policy");
    let jwks = keyset.published_jwks(now, &policy).expect("jwks");

    let algs: Vec<&str> = jwks
        .keys()
        .iter()
        .filter_map(ironauth_jose::Jwk::alg)
        .collect();
    let kids: Vec<&str> = jwks
        .keys()
        .iter()
        .filter_map(ironauth_jose::Jwk::kid)
        .collect();

    assert!(kids.contains(&"es"), "ES256 signing key present: {kids:?}");
    assert!(
        kids.contains(&"rs"),
        "RS256 downgrade key retained: {kids:?}"
    );
    assert!(!kids.contains(&"ed"), "Ed25519 key withdrawn: {kids:?}");
    assert!(!algs.contains(&"EdDSA"), "no EdDSA in JWKS: {algs:?}");
    assert!(algs.contains(&"ES256"));
    assert!(algs.contains(&"RS256"));
    // No Ed25519/OKP key type slips through the filter.
    assert!(
        jwks.keys().iter().all(|jwk| jwk.kty() != Some("OKP")),
        "no OKP key in an ES256-only JWKS"
    );
}

/// The header `alg` of a compact JWS.
fn header_alg(token: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = token.split('.').next().expect("header segment");
    let bytes = URL_SAFE_NO_PAD.decode(header_b64).expect("base64 header");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json header");
    value["alg"].as_str().expect("alg string").to_owned()
}
