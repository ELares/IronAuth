// SPDX-License-Identifier: MIT OR Apache-2.0

//! Property tests over the public verify entry point, run on every build.
//!
//! They use a fixed-seed deterministic generator (a small `SplitMix64`) instead
//! of a proptest dependency, so the input space is covered on the stable lanes
//! with no extra crates in the graph and no OS entropy. The same input space is
//! deepened by the nightly cargo-fuzz target in `fuzz/`.

mod common;

use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};
use serde_json::json;

/// A deterministic `SplitMix64` stream for reproducible pseudo-random inputs.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xFF).expect("masked to one byte")
    }

    /// A pseudo-random index in `0..modulus`.
    fn index(&mut self, modulus: usize) -> usize {
        let m = u64::try_from(modulus).expect("modulus fits u64");
        usize::try_from(self.next_u64() % m).expect("remainder below modulus fits usize")
    }

    /// A pseudo-random string of `len` bytes drawn from a printable-ish set that
    /// includes JOSE-relevant characters (dots, base64url, quotes, braces).
    fn ascii_string(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.={}\"none HS256";
        (0..len)
            .map(|_| ALPHABET[self.index(ALPHABET.len())] as char)
            .collect()
    }
}

fn eddsa_policy(signer: &common::Ed25519Signer) -> VerificationPolicy {
    let key = TrustedKey::ed25519(None, signer.public_key()).expect("valid key");
    VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
    )
    .expect("valid policy")
}

/// Property: no arbitrary `alg` string ever verifies when the signature is not a
/// genuine `EdDSA` signature over the exact header the token carries. This is the
/// "algorithm selection provably ignores token headers" invariant: a token
/// cannot verify by claiming a favorable `alg`.
#[test]
fn arbitrary_alg_never_verifies_with_forged_signature() {
    let signer = common::Ed25519Signer::new();
    let policy = eddsa_policy(&signer);
    let clock = common::now_clock();
    let mut rng = SplitMix64::new(0xA11CE);

    // A curated adversarial set, then many random strings.
    let mut algs: Vec<String> = vec![
        "none",
        "None",
        "NONE",
        "nOnE",
        "",
        " ",
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "ES256",
        "PS256",
        "EdDSA",
        "eddsa",
        "RS1",
        "ES512",
        "Ed448",
        "PBES2-HS256+A128KW",
        "RSA1_5",
        "dir",
        "A128KW",
        "\u{1f600}",
        "RS256 ",
        " RS256",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    for _ in 0..2000 {
        let len = 1 + (rng.byte() as usize % 24);
        algs.push(rng.ascii_string(len));
    }

    for alg in algs {
        // Build a well-formed header carrying the arbitrary alg, and a random
        // (non-genuine) signature. serde_json escapes the alg safely.
        let header = json!({ "alg": alg }).to_string();
        let sig: Vec<u8> = (0..64).map(|_| rng.byte()).collect();
        let token = common::assemble(&header, &common::standard_claims(), &sig);
        assert!(
            verify(&token, &policy, &clock).is_err(),
            "alg {alg:?} with a forged signature must never verify",
        );
    }
}

/// Property: swapping the `alg` of a genuinely signed `EdDSA` token to any other
/// string always breaks verification (the header is part of the signed input and
/// the guards fire regardless).
#[test]
fn alg_swap_on_a_valid_token_always_fails() {
    let signer = common::Ed25519Signer::new();
    let policy = eddsa_policy(&signer);
    let clock = common::now_clock();

    let good = common::signed_ed25519(&signer, r#"{"alg":"EdDSA"}"#, &common::standard_claims());
    let payload_and_sig = good.split_once('.').expect("has header").1;

    let mut rng = SplitMix64::new(0xBEEF);
    for _ in 0..1000 {
        let len = 1 + (rng.byte() as usize % 16);
        let alg = rng.ascii_string(len);
        let header = json!({ "alg": alg }).to_string();
        let token = format!("{}.{}", common::b64(header.as_bytes()), payload_and_sig);
        assert!(
            verify(&token, &policy, &clock).is_err(),
            "swapping alg to {alg:?} must break verification",
        );
    }
}

/// Property: arbitrary input never panics and never verifies. Total over random
/// byte strings, including ones shaped like tokens (with dots).
#[test]
fn arbitrary_input_never_panics_and_never_verifies() {
    let signer = common::Ed25519Signer::new();
    let policy = eddsa_policy(&signer);
    let clock = common::now_clock();
    let mut rng = SplitMix64::new(0xD00D);

    for _ in 0..5000 {
        let len = rng.byte() as usize % 200;
        let raw: String = rng.ascii_string(len);
        // verify must return (not panic); random input is never a valid token.
        assert!(verify(&raw, &policy, &clock).is_err());
    }
}

/// Property: raw non-UTF8-shaped byte segments never cause a panic through the
/// base64 and JSON stages.
#[test]
fn random_three_segment_tokens_never_panic() {
    let signer = common::Ed25519Signer::new();
    let policy = eddsa_policy(&signer);
    let clock = common::now_clock();
    let mut rng = SplitMix64::new(0xFEED);

    for _ in 0..5000 {
        let seg = |rng: &mut SplitMix64| -> String {
            let len = rng.byte() as usize % 64;
            common::b64(&(0..len).map(|_| rng.byte()).collect::<Vec<u8>>())
        };
        let token = format!("{}.{}.{}", seg(&mut rng), seg(&mut rng), seg(&mut rng));
        assert!(verify(&token, &policy, &clock).is_err());
    }
}
