// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Rust verifier against the cross-language conformance corpus (issue #118).
//!
//! Until now the corpus at `packages/ironauth-sdk/vectors/verify-vectors.json` was consumed by
//! TypeScript only, twice: the SDK core and the copy-paste `WebCrypto` snippet. Two JavaScript
//! implementations agreeing is worth something, and it is not the "cross-language" claim issue
//! #118 makes. This is the first consumer in another language, and it is the one that turns
//! that claim into a measured fact.
//!
//! The corpus is negative-heavy by design: twelve of its sixteen vectors are refusals,
//! including `alg: none`, an HS256 forgery keyed with the public key, a token signed by a
//! published-but-wrong key, and a sibling environment's issuer. Those are the cases where two
//! implementations actually diverge; agreeing on a happy path proves very little.
//!
//! # Two honest scope limits, stated rather than hidden
//!
//! **ES256 is not verified here.** [`TrustedKey`] supports Ed25519 and RSA; it has no P-256
//! constructor. So the Rust verifier CANNOT verify the corpus's ES256 vector, and rather than
//! quietly skipping it this test asserts that Rust refuses it as a disallowed algorithm. That
//! is a real capability difference between the implementations, and a conformance suite that
//! hid it would be worse than one that never ran.
//!
//! **`typ` is not enforced.** The corpus mints ordinary `typ: JWT` tokens, because it exists to
//! be run by six verifiers in five languages, none of which share IronAuth's media types. The
//! policy therefore uses [`ExpectedTyp::ForeignIssuer`]. IronAuth's own tokens are verified with
//! `ExpectedTyp::Required` everywhere in production, and the suites covering that are unchanged;
//! what this file tests is the algorithm, key, signature and claim discipline the corpus is
//! about.
//!
//! # The reason mapping IS the interoperability contract
//!
//! The two implementations do not share an error vocabulary: the TypeScript core reports eight
//! coarse reasons, the Rust verifier reports far more precise ones. Mapping them is not
//! bookkeeping, it is the statement of what "these agree" means. The mapping is deliberately
//! MANY-TO-ONE and explicit, so a Rust refusal for the right reason under a different name
//! passes, and a refusal for the WRONG reason does not.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use ironauth_env::ManualClock;
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, RejectReason, TrustedKey, VerificationPolicy, verify,
};
use serde_json::Value;

/// Load the corpus from the SDK package. One file, six verifiers.
fn corpus() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/ironauth-sdk/vectors/verify-vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read the corpus at {}: {error}", path.display()));
    serde_json::from_str(&text).expect("the corpus is JSON")
}

/// Decode a base64url string into bytes.
fn b64(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .expect("base64url")
}

/// The trusted keys published in the corpus JWKS that this verifier can represent.
///
/// Ed25519 AND RSA. The ES256 key is skipped because there is no P-256 constructor; those
/// vectors are handled by the algorithm allowlist instead, which is the honest way to express
/// "this implementation does not do that".
///
/// The RSA key matters more than it looks. Without it the only vector both languages ACCEPT is
/// the Ed25519 one, so the cross-language agreement would rest on a single algorithm and a
/// verifier that had broken RSA entirely would still pass this suite.
fn trusted_keys(corpus: &Value) -> Vec<TrustedKey> {
    corpus["jwks"]["keys"]
        .as_array()
        .expect("a key array")
        .iter()
        .filter_map(|key| {
            let kid = key["kid"].as_str().map(str::to_owned);
            match key["kty"].as_str() {
                Some("OKP") if key["crv"] == "Ed25519" => {
                    let x = key["x"].as_str().expect("an x coordinate");
                    Some(TrustedKey::ed25519(kid, &b64(x)).expect("a valid Ed25519 key"))
                }
                Some("RSA") => {
                    let n = key["n"].as_str().expect("a modulus");
                    let e = key["e"].as_str().expect("an exponent");
                    Some(TrustedKey::rsa(kid, &b64(n), &b64(e)).expect("a valid RSA key"))
                }
                _ => None,
            }
        })
        .collect()
}

/// The Rust reject reasons that satisfy one TypeScript reason.
///
/// Many-to-one on purpose. The TypeScript core says `malformed` where the Rust verifier
/// distinguishes a bad structure from an oversized segment from unparseable header JSON; all
/// three are the same answer to the question the corpus asks, and collapsing them here is what
/// lets a more precise implementation still be judged conformant.
fn acceptable(name: &str, expected: &str) -> &'static [RejectReason] {
    // ONE per-vector override, narrow on purpose.
    //
    // The corpus's `alg_none` token is `header.payload.` with an EMPTY signature segment,
    // because that is what the attack actually looks like on the wire. The Rust verifier splits
    // structurally BEFORE it reads `alg`, so it refuses this as `MalformedStructure` where the
    // TypeScript core refuses it as `algorithm_not_allowed`.
    //
    // Both refuse, which is the security property, and Rust refuses EARLIER and for a more
    // fundamental defect. Widening the general `algorithm_not_allowed` mapping to accept
    // `MalformedStructure` would be the lazy fix and would let any malformed refusal satisfy an
    // algorithm expectation for every other vector. So the exception is named, scoped to this
    // one vector, and both acceptable reasons are listed.
    if name == "alg_none" {
        return &[RejectReason::AlgNone, RejectReason::MalformedStructure];
    }
    // The second named exception, and the more interesting one.
    //
    // TypeScript refuses the embedded-JWK injection as `bad_signature`: it resolves the key
    // from the published set, ignores the header's `jwk` entirely, and the attacker's signature
    // then fails against the real key. Rust refuses it as `EmbeddedKeyInjection`, structurally,
    // BEFORE any signature is checked, because a `jwk` in the header of a token verified
    // against a trusted key set has no legitimate purpose.
    //
    // Rust's refusal is strictly STRONGER: it would still refuse even if an attacker somehow
    // produced a signature that validated. Both are correct and the difference is worth
    // recording rather than flattening, which is why this is a named exception listing both
    // rather than `SignatureInvalid` being quietly widened everywhere.
    if name == "embedded_jwk_key_injection" {
        return &[
            RejectReason::EmbeddedKeyInjection,
            RejectReason::SignatureInvalid,
        ];
    }
    match expected {
        "malformed" => &[
            RejectReason::MalformedStructure,
            RejectReason::Base64Malformed,
            RejectReason::HeaderMalformed,
            RejectReason::SegmentTooLarge,
            RejectReason::TokenTooLarge,
            RejectReason::ClaimsMalformed,
            RejectReason::UnknownCrit,
            RejectReason::MalformedCrit,
        ],
        // `alg: none` has its own Rust variant, which is more precise than the TypeScript
        // reason and still the same refusal.
        "algorithm_not_allowed" => &[
            RejectReason::AlgNone,
            RejectReason::AlgNotAllowed,
            RejectReason::UnsupportedAlg,
            RejectReason::KeyTypeMismatch,
        ],
        "unknown_key" => &[RejectReason::UnknownKid],
        "bad_signature" => &[RejectReason::SignatureInvalid],
        "wrong_issuer" => &[RejectReason::IssuerMismatch],
        "wrong_audience" => &[RejectReason::AudienceMismatch],
        "expired" => &[RejectReason::Expired],
        "not_yet_valid" => &[RejectReason::NotYetValid],
        other => panic!("the corpus expects `{other}`, which this mapping does not cover"),
    }
}

/// Whether a vector names ES256 in its header.
///
/// Decodes WITHOUT panicking: the corpus deliberately contains a vector whose segments are not
/// base64 at all, and a helper that panicked on it would take the suite down while classifying
/// the very case it exists to classify.
fn is_es256(token: &str) -> bool {
    use base64::Engine as _;
    let Some(header_b64) = token.split('.').next() else {
        return false;
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    header["alg"] == "ES256"
}

#[test]
fn the_rust_verifier_agrees_with_the_conformance_corpus() {
    let corpus = corpus();
    let now = corpus["now"].as_u64().expect("an evaluation instant");
    let issuer = corpus["issuer"].as_str().expect("an issuer");
    let audience = corpus["audience"].as_str().expect("an audience");
    let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(now));

    // EdDSA and RS256: this verifier has no P-256 key type, so ES256 is genuinely not allowed
    // here rather than merely untested. RS256 IS supported, and including it means the
    // cross-language agreement rests on two algorithms rather than one.
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa, JwsAlgorithm::Rs256],
        trusted_keys(&corpus),
        issuer,
        audience,
        ExpectedTyp::ForeignIssuer,
    )
    .expect("a valid policy")
    .with_skew(Duration::from_secs(0));

    let cases = corpus["cases"].as_array().expect("cases");
    assert!(
        cases.len() >= 16,
        "the corpus shrank to {} vectors; this suite is only as good as the list",
        cases.len()
    );
    let mut refusals = 0_usize;
    let mut accepts = 0_usize;

    for case in cases {
        let name = case["name"].as_str().expect("a name");
        let token = case["token"].as_str().expect("a token");
        let expect = case["expect"].as_str().expect("an expectation");
        let why = case["why"].as_str().expect("a reason");
        let outcome = verify(token, &policy, &clock);

        // The ES256 vectors are the documented capability gap: whatever the corpus expects of a
        // verifier that supports P-256, THIS one must refuse them on the allowlist.
        if is_es256(token) {
            let Err(error) = outcome else {
                panic!("{name}: an ES256 token must be refused by an EdDSA-only policy");
            };
            let reason = error.reason();
            assert!(
                matches!(
                    reason,
                    RejectReason::AlgNotAllowed | RejectReason::UnsupportedAlg
                ),
                "{name}: expected an allowlist refusal for ES256, got {reason:?}"
            );
            continue;
        }

        if expect == "accept" {
            accepts += 1;
            assert!(
                outcome.is_ok(),
                "{name} must verify ({why}), got {:?}",
                outcome.err()
            );
            continue;
        }

        refusals += 1;
        let Err(error) = outcome else {
            panic!("{name} must be refused as {expect} ({why}), but it verified");
        };
        let reason = error.reason();
        let permitted = acceptable(name, expect);
        assert!(
            permitted.contains(&reason),
            "{name}: TypeScript refuses this as `{expect}` and Rust refused it as {reason:?}, \
             which is not among {permitted:?}. {why}"
        );
    }

    // The corpus must not have been quietly emptied of the cases that matter. A conformance
    // suite that iterates a list is exactly as good as the list.
    assert!(
        refusals >= 10,
        "only {refusals} refusal vectors reached the verifier; the corpus is the test"
    );
    assert!(
        accepts >= 3,
        "only {accepts} accepted vectors, so a refuse-everything verifier would pass"
    );
}

/// The corpus's own reason vocabulary must stay covered by the mapping.
///
/// A vector added with a new expectation would otherwise panic deep inside the loop above with
/// an unhelpful message, or worse, be silently mapped to something adjacent. This fails fast
/// and names the gap.
#[test]
fn every_corpus_reason_is_mapped_to_rust_reasons() {
    let corpus = corpus();
    for case in corpus["cases"].as_array().expect("cases") {
        let expect = case["expect"].as_str().expect("an expectation");
        if expect == "accept" {
            continue;
        }
        let name = case["name"].as_str().expect("a name");
        let mapped = acceptable(name, expect);
        assert!(
            !mapped.is_empty(),
            "`{expect}` maps to no Rust reason, so the vector could never be judged"
        );
    }
}
