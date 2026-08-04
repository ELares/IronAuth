// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signing-core integration tests.
//!
//! Every mint here round-trips through the one hardened [`ironauth_jose::verify`]
//! path, so signing is proven to respect the same allowlists and exclusions. The
//! suites cover the full algorithm matrix, the RFC 8037 Ed25519 byte vectors, the
//! fully-specified emission toggle, the restricted `HS*` client-secret contexts,
//! the generalized RFC 7800 confirmation model across both binding types, the
//! per-environment key store with its day-one multi-key JWKS and downgrade flip,
//! the pluggable seams, the pre-signature compact-length arithmetic, and the
//! redaction of secret material.

mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::FixedEntropy;
use ironauth_jose::seams::{ClientAuthMethod, GrantType, TokenBindingMethod};
use ironauth_jose::{
    ClientSecret, ClientSecretContext, Confirmation, EmissionOptions, EnvironmentKeyStore, Jwk,
    JwkSet, JwsAlgorithm, MacAlgorithm, RejectReason, SigningKey, SigningPolicy, TokenTyp,
    TrustedKey, VerificationPolicy, b64_no_pad_len, compact_len, protected_header, sign_jws,
    sign_jws_with_policy, verify,
};
use serde_json::{Map, Value, json};

use common::signing_keys;

/// The full asymmetric signing matrix, `EdDSA` first (the default).
const MATRIX: [JwsAlgorithm; 9] = [
    JwsAlgorithm::EdDsa,
    JwsAlgorithm::Es256,
    JwsAlgorithm::Es384,
    JwsAlgorithm::Rs256,
    JwsAlgorithm::Rs384,
    JwsAlgorithm::Rs512,
    JwsAlgorithm::Ps256,
    JwsAlgorithm::Ps384,
    JwsAlgorithm::Ps512,
];

/// The standard valid-at-`NOW` claim set, as payload bytes.
fn claims_payload() -> Vec<u8> {
    common::standard_claims().into_bytes()
}

/// Build a signing key for `alg` from the committed test fixtures. Ed25519 uses
/// a fixed seed, ECDSA loads a fixture PKCS#8, and every RSA algorithm shares one
/// fixture RSA key bound to that algorithm.
fn signing_key_for(alg: JwsAlgorithm) -> SigningKey {
    let kid = Some(format!("{}-key", alg.as_jose_name().to_lowercase()));
    match alg {
        JwsAlgorithm::EdDsa => SigningKey::ed25519_from_seed(kid, &[9_u8; 32]),
        JwsAlgorithm::Es256 => SigningKey::ecdsa_p256_from_pkcs8(kid, signing_keys::ES256_PKCS8),
        JwsAlgorithm::Es384 => SigningKey::ecdsa_p384_from_pkcs8(kid, signing_keys::ES384_PKCS8),
        JwsAlgorithm::Rs256
        | JwsAlgorithm::Rs384
        | JwsAlgorithm::Rs512
        | JwsAlgorithm::Ps256
        | JwsAlgorithm::Ps384
        | JwsAlgorithm::Ps512 => SigningKey::rsa_from_pkcs1_der(kid, alg, signing_keys::RSA_PKCS1),
        _ => unreachable!("test matrix covers every supported algorithm"),
    }
    .expect("fixture key material is valid")
}

/// A single-key, single-algorithm verification policy.
fn policy_for(alg: JwsAlgorithm, key: TrustedKey) -> VerificationPolicy {
    VerificationPolicy::new(
        vec![alg],
        vec![key],
        common::ISS,
        common::AUD,
        common::TYP_NOT_UNDER_TEST,
    )
    .expect("valid policy")
}

/// Decode the `alg` header parameter from a compact JWS.
fn header_alg(token: &str) -> String {
    let header_b64 = token.split('.').next().expect("has a header segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("valid base64url header");
    let value: Value = serde_json::from_slice(&bytes).expect("valid JSON header");
    value
        .get("alg")
        .and_then(Value::as_str)
        .expect("alg present")
        .to_owned()
}

/// A base claim set as a mutable JSON object, for tests that add a `cnf`.
fn base_claims_object() -> Map<String, Value> {
    let value = json!({
        "iss": common::ISS,
        "sub": "user-123",
        "aud": common::AUD,
        "exp": common::NOW + 3600,
        "nbf": common::NOW - 60,
        "iat": common::NOW - 60,
    });
    value.as_object().expect("object").clone()
}

/// Reconstruct a trusted verification key purely from a PUBLISHED JWK, proving
/// the JWKS is sufficient to verify (no private-side shortcut).
fn trusted_from_jwk(jwk: &Jwk) -> TrustedKey {
    let kid = jwk.kid().map(str::to_owned);
    let member = |name: &str| -> Vec<u8> {
        let encoded = jwk
            .get(name)
            .and_then(Value::as_str)
            .expect("member present");
        URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("valid base64url member")
    };
    match jwk.kty().expect("kty present") {
        "OKP" => TrustedKey::ed25519(kid, &member("x")),
        "EC" => match jwk.get("crv").and_then(Value::as_str).expect("crv present") {
            "P-256" => TrustedKey::ecdsa_p256(kid, &member("x"), &member("y")),
            _ => TrustedKey::ecdsa_p384(kid, &member("x"), &member("y")),
        },
        _ => TrustedKey::rsa(kid, &member("n"), &member("e")),
    }
    .expect("published JWK yields a trusted key")
}

#[test]
fn full_matrix_signs_and_round_trips_through_verify() {
    let clock = common::now_clock();
    for alg in MATRIX {
        let key = signing_key_for(alg);
        let token = sign_jws(&key, &claims_payload(), &EmissionOptions::new())
            .unwrap_or_else(|e| panic!("{alg:?} should sign: {e}"));
        let trusted = key.verifying_key().expect("verifying key");
        let policy = policy_for(alg, trusted);
        let verified = verify(&token, &policy, &clock)
            .unwrap_or_else(|e| panic!("{alg:?} should verify: {:?}", e.reason()));
        assert_eq!(verified.algorithm(), alg, "{alg:?} algorithm mismatch");
        assert_eq!(verified.claims().issuer(), common::ISS);
        assert_eq!(verified.claims().subject(), Some("user-123"));
        assert_eq!(verified.key_id(), key.kid());
    }
}

/// The three emission shapes that give a protected header three different byte
/// lengths, so the length arithmetic is not proven against one header only.
fn emission_shapes() -> [EmissionOptions; 3] {
    [
        EmissionOptions::new(),
        EmissionOptions::new().with_token_typ(TokenTyp::AccessToken),
        EmissionOptions::new()
            .fully_specified(true)
            .with_token_typ(TokenTyp::IdToken),
    ]
}

/// The RSA fixture moduli the length arithmetic is proven over, each with the raw
/// signature width it must produce.
///
/// TWO sizes and not one. The loader's 2048-bit modulus is a MINIMUM rather than a
/// fixed size, so against a single 2048-bit fixture a hardcoded 256 would be
/// indistinguishable from the shipped per-key modulus width, while under-predicting
/// a 3072-bit deployment's compact token by 128 bytes.
const RSA_FIXTURES: [(&str, &[u8], usize); 2] = [
    ("rsa2048", signing_keys::RSA_PKCS1, 256),
    ("rsa3072", signing_keys::RSA_3072_PKCS1, 384),
];

/// Every key the length arithmetic must hold for at `alg`, labelled and paired
/// with the raw signature width it is required to produce. Only RSA contributes
/// more than one key, one per fixture modulus size.
fn keys_and_widths(alg: JwsAlgorithm) -> Vec<(String, SigningKey, usize)> {
    match alg {
        JwsAlgorithm::EdDsa | JwsAlgorithm::Es256 | JwsAlgorithm::Es384 => {
            let width = if alg == JwsAlgorithm::Es384 { 96 } else { 64 };
            vec![(
                alg.as_jose_name().to_lowercase(),
                signing_key_for(alg),
                width,
            )]
        }
        _ => RSA_FIXTURES
            .iter()
            .map(|(label, der, width)| {
                let kid = Some(format!("{}-{label}-key", alg.as_jose_name().to_lowercase()));
                let key = SigningKey::rsa_from_pkcs1_der(kid, alg, der)
                    .expect("fixture RSA key material is valid");
                ((*label).to_owned(), key, *width)
            })
            .collect(),
    }
}

/// The raw signature bytes of a compact JWS, decoded from its third segment.
fn signature_bytes(token: &str) -> Vec<u8> {
    let segment = token
        .rsplit('.')
        .next()
        .expect("a compact JWS has 3 segments");
    URL_SAFE_NO_PAD
        .decode(segment)
        .expect("segment is base64url")
}

#[test]
fn b64_no_pad_len_matches_the_encoder_at_every_residue() {
    // Every `n % 3` residue, including 0 bytes, over a range wide enough that a
    // constant offset and a wrong rounding rule both show up.
    for n in 0_usize..=512 {
        let bytes = vec![0xa5_u8; n];
        assert_eq!(
            b64_no_pad_len(n),
            URL_SAFE_NO_PAD.encode(&bytes).len(),
            "{n} bytes (residue {})",
            n % 3
        );
    }
}

#[test]
fn compact_len_is_exact_for_every_algorithm_and_every_payload_residue() {
    for alg in MATRIX {
        for (label, key, _) in keys_and_widths(alg) {
            for options in emission_shapes() {
                let header = protected_header(&key, &options).expect("protected header");
                // The header this predicts is byte-identical to the one the mint
                // emits, so the prediction is not merely the same LENGTH by
                // coincidence.
                let minted_header = sign_jws(&key, b"{}", &options).expect("sign");
                let first = minted_header.split('.').next().expect("first segment");
                assert_eq!(
                    first,
                    URL_SAFE_NO_PAD.encode(&header),
                    "{alg:?}/{label} header bytes"
                );

                for n in 0_usize..=32 {
                    let payload = vec![b'x'; n];
                    let token = sign_jws(&key, &payload, &options).expect("sign");
                    assert_eq!(
                        compact_len(&header, &payload, key.signature_len()),
                        token.len(),
                        "{alg:?}/{label} payload {n} bytes (residue {})",
                        n % 3
                    );
                }
            }
        }
    }
}

#[test]
fn compact_len_is_exact_through_the_policy_wrapper_the_mint_uses() {
    // The real caller (`ironauth_oidc`'s access-token mint) signs through
    // `sign_jws_with_policy`, so the exactness is proven against THAT wrapper too
    // and not only against the inner `sign_jws` the tests above reach for.
    for alg in MATRIX {
        let key = signing_key_for(alg);
        let policy = SigningPolicy::new(vec![alg]).expect("single-algorithm policy");
        let options = EmissionOptions::new().with_token_typ(TokenTyp::AccessToken);
        let header = protected_header(&key, &options).expect("protected header");
        for n in [0_usize, 1, 2, 31] {
            let payload = vec![b'x'; n];
            let token =
                sign_jws_with_policy(&policy, &key, &payload, &options).expect("policy permits");
            assert_eq!(
                compact_len(&header, &payload, key.signature_len()),
                token.len(),
                "{alg:?} payload {n} bytes through the policy wrapper"
            );
        }
    }
}

#[test]
fn a_key_with_no_kid_predicts_its_own_shorter_header() {
    // Every matrix fixture carries a kid, so without this the `kid: None` arm of
    // the header builder is never reached THROUGH `protected_header`, and a
    // prediction that always assumed a kid would stay green.
    let keyless = SigningKey::ed25519_from_seed(None, &[9_u8; 32]).expect("valid seed");
    let keyed = signing_key_for(JwsAlgorithm::EdDsa);
    assert_eq!(keyless.kid(), None, "the fixture is deliberately kid-less");
    for options in emission_shapes() {
        let header = protected_header(&keyless, &options).expect("protected header");
        let decoded: Value = serde_json::from_slice(&header).expect("valid JSON header");
        assert!(
            decoded.get("kid").is_none(),
            "a key with no kid must emit no kid member"
        );
        let with_kid = protected_header(&keyed, &options).expect("protected header");
        assert!(
            header.len() < with_kid.len(),
            "the kid-less header is genuinely a different length"
        );

        let payload = claims_payload();
        let token = sign_jws(&keyless, &payload, &options).expect("sign");
        assert_eq!(
            token.split('.').next().expect("header segment"),
            URL_SAFE_NO_PAD.encode(&header),
            "the minted header is the predicted one"
        );
        assert_eq!(
            compact_len(&header, &payload, keyless.signature_len()),
            token.len(),
            "kid-less compact length"
        );
    }
}

#[test]
fn signature_len_equals_the_observed_signature_width_for_every_algorithm() {
    for alg in MATRIX {
        // Over BOTH RSA fixture moduli, so the RSA arm is proven to return the
        // key's own modulus width rather than a constant that happens to match
        // the 2048-bit floor. See RSA_FIXTURES.
        for (label, key, expected) in keys_and_widths(alg) {
            let token = sign_jws(&key, &claims_payload(), &EmissionOptions::new()).expect("sign");
            assert_eq!(
                key.signature_len(),
                signature_bytes(&token).len(),
                "{alg:?}/{label} signature width"
            );
            // The documented widths, pinned so a future key-type edit cannot
            // quietly change one and stay green.
            assert_eq!(
                key.signature_len(),
                expected,
                "{alg:?}/{label} documented width"
            );
        }
    }
}

#[test]
fn every_signature_width_is_fixed_across_repeated_signing() {
    // What the REPETITION buys, stated precisely, because the obvious hazard is
    // not the one that needs it.
    //
    // A switch to ring's ASN.1 DER ECDSA signing is NOT the reason for the rounds.
    // Measured over 2000 P-256 DER signings the lengths ran 69, 70, 71, 72 and
    // never 64, so a DER encoder is caught at round 0 with probability 1 and is
    // already caught by the single-signature width test above.
    //
    // The hazard that needs the rounds is a leading-zero-STRIPPING `R || S`
    // encoder. Its MODAL width is still the correct 64, so it agrees with a
    // one-shot check almost every time, and it deviates exactly when `R` or `S`
    // has a leading zero byte. Measured rate: 1547 of 200000 P-256 signatures,
    // 0.77%, which is the 1 minus (255/256)^2 the byte distribution predicts. One
    // round would catch it with probability 0.008; 512 rounds catch it with
    // probability 0.98.
    //
    // Both ECDSA algorithms and all three PSS algorithms draw fresh randomness per
    // signature, so repeating the SAME payload genuinely samples that
    // distribution. Ed25519 and the three PKCS1-v1_5 algorithms are deterministic
    // and produce one signature however often they are asked, so for those four
    // this pins the width rather than sampling it.
    const ROUNDS: usize = 512;
    for alg in MATRIX {
        let key = signing_key_for(alg);
        let expected = key.signature_len();
        for round in 0..ROUNDS {
            let token = sign_jws(&key, &claims_payload(), &EmissionOptions::new()).expect("sign");
            assert_eq!(
                signature_bytes(&token).len(),
                expected,
                "{alg:?} round {round}: signature width varied"
            );
        }
    }
}

#[test]
fn rfc8037_ed25519_vectors_cross_verify() {
    // Build the exact RFC 8037 A.1 key from its published seed.
    let seed = URL_SAFE_NO_PAD
        .decode(signing_keys::RFC8037_D_B64URL)
        .expect("valid base64url seed");
    let key = SigningKey::ed25519_from_seed(None, &seed).expect("valid seed");

    // The public key matches RFC 8037 `x`, read through the published JWK.
    let jwks = JwkSet::from_signing_keys([&key]).expect("jwks");
    let published_x = jwks.keys()[0].get("x").and_then(Value::as_str).expect("x");
    assert_eq!(published_x, signing_keys::RFC8037_X_B64URL);

    // Ed25519 is deterministic, so the whole compact JWS reproduces A.4 exactly.
    let token = sign_jws(
        &key,
        signing_keys::RFC8037_PAYLOAD.as_bytes(),
        &EmissionOptions::new(),
    )
    .expect("sign");
    assert_eq!(token, signing_keys::RFC8037_JWS);
}

#[test]
fn fully_specified_toggle_emits_the_ed25519_alias_and_still_verifies() {
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let clock = common::now_clock();

    // Toggle on: EdDSA is emitted as the fully-specified `Ed25519`.
    let options = EmissionOptions::new().fully_specified(true);
    let token = sign_jws(&key, &claims_payload(), &options).expect("sign");
    assert_eq!(header_alg(&token), "Ed25519");

    // The verifier accepts the alias and reports the polymorphic algorithm.
    let policy = policy_for(JwsAlgorithm::EdDsa, key.verifying_key().expect("vk"));
    let verified = verify(&token, &policy, &clock).expect("alias verifies");
    assert_eq!(verified.algorithm(), JwsAlgorithm::EdDsa);

    // Default emission stays polymorphic.
    let default_token = sign_jws(&key, &claims_payload(), &EmissionOptions::new()).expect("sign");
    assert_eq!(header_alg(&default_token), "EdDSA");
}

#[test]
fn hs_signing_is_reachable_only_through_a_client_secret_context() {
    let secret = ClientSecret::new("top-secret-client-value");
    let payload = claims_payload();
    for (context, mac) in [
        (ClientSecretContext::IdTokenHs, MacAlgorithm::Hs256),
        (ClientSecretContext::ClientSecretJwt, MacAlgorithm::Hs384),
    ] {
        let jws = context.sign_jws(mac, &secret, &payload, &EmissionOptions::new());
        assert_eq!(jws.context(), context);
        assert_eq!(header_alg(jws.compact()), mac.as_jose_name());
    }
}

#[test]
fn hs_signed_token_is_rejected_by_the_asymmetric_verify_core() {
    let secret = ClientSecret::new("top-secret");
    let jws = ClientSecretContext::IdTokenHs.sign_jws(
        MacAlgorithm::Hs256,
        &secret,
        &claims_payload(),
        &EmissionOptions::new(),
    );
    // The verify core has no HMAC path, so the HS token's alg is simply
    // unsupported, whatever asymmetric policy is presented.
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let policy = policy_for(JwsAlgorithm::EdDsa, key.verifying_key().expect("vk"));
    let err = verify(jws.compact(), &policy, &common::now_clock()).expect_err("HS must not verify");
    assert_eq!(err.reason(), RejectReason::UnsupportedAlg);
}

#[test]
fn hs_algorithms_cannot_name_an_asymmetric_default() {
    // No `JwsAlgorithm` value spells an HS algorithm, so a tenant/environment
    // default (typed `JwsAlgorithm`) and a verify allowlist can never contain one.
    for name in ["HS256", "HS384", "HS512"] {
        assert!(
            JwsAlgorithm::from_jose_name(name).is_none(),
            "{name} leaked in"
        );
    }
}

#[test]
fn both_cnf_binding_types_traverse_identical_issuance_and_verification() {
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let policy = policy_for(JwsAlgorithm::EdDsa, key.verifying_key().expect("vk"));
    let clock = common::now_clock();

    // Two binding methods (DPoP -> jkt, mTLS -> x5t#S256) via the seam, each run
    // through the SAME embed -> mint -> verify -> extract path.
    let bindings: Vec<(Box<dyn TokenBindingMethod>, &str)> = vec![
        (Box::new(DpopBinding), "jkt-thumbprint-abc"),
        (Box::new(MtlsBinding), "x5t-thumbprint-xyz"),
    ];
    for (binding, thumbprint) in bindings {
        let confirmation = binding.confirmation(thumbprint);

        // Issuance path.
        let mut claims = base_claims_object();
        confirmation.embed_in_claims(&mut claims);
        let payload = serde_json::to_vec(&Value::Object(claims)).expect("serialize claims");
        let token = sign_jws(&key, &payload, &EmissionOptions::new()).expect("sign");

        // Verification path.
        let verified = verify(&token, &policy, &clock).expect("verify");
        let recovered = Confirmation::from_claims(verified.claims())
            .expect("cnf parses")
            .expect("cnf present");
        assert_eq!(recovered, confirmation);
        assert_eq!(recovered.value(), thumbprint);
        assert_eq!(
            recovered.member_name(),
            binding.confirmation(thumbprint).member_name()
        );
    }
}

#[test]
fn confirmation_absence_and_malformed_shapes_are_handled() {
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let policy = policy_for(JwsAlgorithm::EdDsa, key.verifying_key().expect("vk"));
    let token = sign_jws(&key, &claims_payload(), &EmissionOptions::new()).expect("sign");
    let verified = verify(&token, &policy, &common::now_clock()).expect("verify");
    // No cnf claim: absence is not an error.
    assert!(
        Confirmation::from_claims(verified.claims())
            .expect("ok")
            .is_none()
    );
    // A cnf that is not an object is a parse error.
    assert!(Confirmation::from_cnf_object(&json!("not-an-object")).is_err());
}

#[test]
fn fresh_environment_publishes_three_families_and_the_flip_is_config_only() {
    let mut store: EnvironmentKeyStore<&str> = EnvironmentKeyStore::new();
    let entropy = FixedEntropy::new(0xA5A5);
    store.insert(
        "prod",
        SigningKey::generate_ed25519(Some("prod-ed".to_owned()), &entropy).expect("ed"),
    );
    store.insert(
        "prod",
        SigningKey::ecdsa_p256_from_pkcs8(Some("prod-es256".to_owned()), signing_keys::ES256_PKCS8)
            .expect("es256"),
    );
    store.insert(
        "prod",
        SigningKey::rsa_from_pkcs1_der(
            Some("prod-rs256".to_owned()),
            JwsAlgorithm::Rs256,
            signing_keys::RSA_PKCS1,
        )
        .expect("rs256"),
    );

    // All three public keys are published from day one.
    let jwks = store.public_jwks(&"prod").expect("jwks");
    assert_eq!(jwks.len(), 3);
    let mut ktys: Vec<&str> = jwks.keys().iter().filter_map(Jwk::kty).collect();
    ktys.sort_unstable();
    assert_eq!(ktys, ["EC", "OKP", "RSA"]);
    assert_eq!(
        store.published_algorithms(&"prod"),
        vec![
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Rs256
        ]
    );

    // A client on EdDSA verifies via the published JWKS; flipping it to RS256 is
    // a pure configuration change, the key is already provisioned and published.
    mint_and_verify_via_published_jwks(&store, JwsAlgorithm::EdDsa);
    mint_and_verify_via_published_jwks(&store, JwsAlgorithm::Rs256);
}

/// Mint with the environment's key for `alg`, then verify using ONLY the
/// published JWKS to reconstruct the trusted key.
fn mint_and_verify_via_published_jwks(store: &EnvironmentKeyStore<&str>, alg: JwsAlgorithm) {
    let signer = store
        .signer_for_alg(&"prod", alg)
        .expect("key present from day one");
    let token = sign_jws(signer, &claims_payload(), &EmissionOptions::new()).expect("sign");

    let jwks = store.public_jwks(&"prod").expect("jwks");
    let jwk = jwks
        .keys()
        .iter()
        .find(|k| k.alg().and_then(JwsAlgorithm::from_jose_name) == Some(alg))
        .expect("algorithm published");
    let policy = policy_for(alg, trusted_from_jwk(jwk));
    let verified = verify(&token, &policy, &common::now_clock()).expect("verify via jwks");
    assert_eq!(verified.algorithm(), alg);
}

#[test]
fn ed25519_generation_is_deterministic_under_fixed_entropy() {
    let a = SigningKey::generate_ed25519(Some("k".to_owned()), &FixedEntropy::new(99)).expect("a");
    let b = SigningKey::generate_ed25519(Some("k".to_owned()), &FixedEntropy::new(99)).expect("b");
    let c = SigningKey::generate_ed25519(Some("k".to_owned()), &FixedEntropy::new(100)).expect("c");
    let x = |key: &SigningKey| -> Value {
        JwkSet::from_signing_keys([key]).expect("jwks").keys()[0]
            .get("x")
            .cloned()
            .expect("x")
    };
    // Same seed -> same key; different seed -> different key.
    assert_eq!(x(&a), x(&b));
    assert_ne!(x(&a), x(&c));
}

#[test]
fn pluggable_seams_accept_sample_implementations() {
    let auth: Box<dyn ClientAuthMethod> = Box::new(ClientSecretBasic);
    assert_eq!(auth.method_name(), "client_secret_basic");

    let grant: Box<dyn GrantType> = Box::new(AuthorizationCodeGrant);
    assert_eq!(grant.grant_type(), "authorization_code");

    let binding: Box<dyn TokenBindingMethod> = Box::new(DpopBinding);
    assert_eq!(binding.binding_name(), "DPoP");
    assert_eq!(binding.confirmation("t"), Confirmation::Jkt("t".to_owned()));
}

#[test]
fn signing_keys_and_client_secrets_do_not_leak_through_debug() {
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let rendered = format!("{key:?}");
    assert!(rendered.contains("SigningKey"));
    assert!(rendered.contains("EdDsa"));

    let secret = ClientSecret::new("hunter2-do-not-log");
    let rendered_secret = format!("{secret:?}");
    assert!(
        !rendered_secret.contains("hunter2-do-not-log"),
        "secret leaked: {rendered_secret}"
    );
    assert!(rendered_secret.contains("[redacted]"));
}

// --------------------------------------------------------------------------
// Test-only sample implementations of the pluggable seams. These stand in for
// the future drafts that will land as real implementations; here they only
// prove each seam is implementable and wire the token-binding seam to the cnf
// model.
// --------------------------------------------------------------------------

struct ClientSecretBasic;
impl ClientAuthMethod for ClientSecretBasic {
    fn method_name(&self) -> &'static str {
        "client_secret_basic"
    }
}

struct AuthorizationCodeGrant;
impl GrantType for AuthorizationCodeGrant {
    fn grant_type(&self) -> &'static str {
        "authorization_code"
    }
}

struct DpopBinding;
impl TokenBindingMethod for DpopBinding {
    fn binding_name(&self) -> &'static str {
        "DPoP"
    }
    fn confirmation(&self, thumbprint: &str) -> Confirmation {
        Confirmation::Jkt(thumbprint.to_owned())
    }
}

struct MtlsBinding;
impl TokenBindingMethod for MtlsBinding {
    fn binding_name(&self) -> &'static str {
        "mTLS"
    }
    fn confirmation(&self, thumbprint: &str) -> Confirmation {
        Confirmation::X5tS256(thumbprint.to_owned())
    }
}

/// Issue #188: a published JWK always carries a set-unique `kid`.
mod thumbprint_kid {
    use super::{JwkSet, JwsAlgorithm, SigningKey, signing_keys};

    fn keyless(alg: JwsAlgorithm) -> SigningKey {
        match alg {
            JwsAlgorithm::EdDsa => SigningKey::ed25519_from_seed(None, &[5_u8; 32]),
            JwsAlgorithm::Es256 => {
                SigningKey::ecdsa_p256_from_pkcs8(None, signing_keys::ES256_PKCS8)
            }
            _ => SigningKey::rsa_from_pkcs1_der(None, alg, signing_keys::RSA_PKCS1),
        }
        .expect("key material")
    }

    #[test]
    fn a_key_published_without_a_kid_carries_its_thumbprint() {
        // The key itself stays kid-less, which is what keeps the RFC 8037 A.4
        // vector reproducible; the PUBLISHED document is where the ambiguity was.
        let key = keyless(JwsAlgorithm::EdDsa);
        assert_eq!(key.kid(), None, "the key itself is untouched");

        let set = JwkSet::from_signing_keys([&key]).expect("jwk set");
        let published = set.keys()[0]
            .kid()
            .expect("a published JWK always has a kid");
        assert_eq!(
            published,
            key.derive_kid().expect("thumbprint"),
            "the published kid is the key's own RFC 7638 thumbprint"
        );
    }

    #[test]
    fn an_explicit_kid_is_never_overwritten() {
        // The other direction: deriving must not clobber what a caller chose, or
        // every existing deployment's published kids would change under it.
        let key =
            SigningKey::ed25519_from_seed(Some("chosen".to_owned()), &[5_u8; 32]).expect("ed25519");
        let set = JwkSet::from_signing_keys([&key]).expect("jwk set");
        assert_eq!(set.keys()[0].kid(), Some("chosen"));
    }

    #[test]
    fn the_day_one_algorithms_get_distinct_and_stable_thumbprint_kids() {
        // The issue's own acceptance. DISTINCT is the collision property; STABLE is
        // what makes a kid usable for selection at all, since a kid that changed
        // per process would strand every cached JWKS.
        let algs = [
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Rs256,
        ];
        let kids: Vec<String> = algs
            .iter()
            .map(|alg| keyless(*alg).derive_kid().expect("thumbprint"))
            .collect();

        let mut unique = kids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "the three day-one kids collide: {kids:?}");

        for (alg, kid) in algs.iter().zip(&kids) {
            assert_eq!(
                &keyless(*alg).derive_kid().expect("thumbprint"),
                kid,
                "a thumbprint kid must be stable across constructions"
            );
        }
    }

    #[test]
    fn a_published_kid_is_that_documents_own_rfc7638_thumbprint() {
        // There is ONE RFC 7638 canonicalization in this crate, the same routine that
        // produces a DPoP proof key's `jkt`. Running the PUBLISHED document back
        // through it closes the loop: if a second canonicalization were introduced
        // for kids, the two could disagree about member ordering or whitespace and
        // nothing else would notice.
        for alg in [
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Rs256,
        ] {
            let key = keyless(alg);
            let set = JwkSet::from_signing_keys([&key]).expect("jwk set");
            let published = &set.keys()[0];
            assert_eq!(
                published.kid().expect("a published JWK always has a kid"),
                ironauth_jose::jwk_thumbprint(published).expect("thumbprint"),
                "the published kid must be this JWK's own thumbprint for {alg:?}"
            );
        }
    }
}
