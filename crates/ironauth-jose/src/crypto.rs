// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signature primitive: the ONLY module that calls `ring::signature`.
//!
//! Everything here is `pub(crate)` and reached only from the private verify
//! orchestration, so Rust module visibility alone makes a raw signature check
//! unreachable from outside the crate. The lint `scripts/jose-audit.sh` is the
//! second net: it fails the build if any crate other than `ironauth-jose` names
//! `ring::signature` (or any JOSE verify primitive) in source or depends on a
//! JOSE/JWT crate.
//!
//! The function is total and constant in shape: given an algorithm, a trusted
//! key, the signing input, and the signature bytes, it returns whether the
//! signature verifies, and nothing else. The algorithm and key come from the
//! caller's policy; this module never inspects the token.

use ring::digest;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey, VerificationAlgorithm};

use crate::policy::{JwsAlgorithm, KeyMaterial};

/// The SHA-256 digest of `bytes`, as the raw 32-byte hash.
///
/// This is the one place SHA-256 is computed, so the "only `crypto.rs` touches
/// `ring`" invariant holds: the RFC 7638 JWK thumbprint (`dpop::jwk_thumbprint`)
/// hashes its canonical JWK through here rather than reaching for `ring` itself.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Verify `signature` over `signing_input` with `key` under `alg`.
///
/// Returns `Ok(())` only on a valid signature. The caller has already checked
/// that `alg` is allowlisted and that `key`'s family matches `alg`; this
/// function trusts those invariants and would simply fail to verify if they
/// were violated. Any ring error collapses to `Err(())`, carrying no detail.
pub(crate) fn verify_signature(
    alg: JwsAlgorithm,
    key: &KeyMaterial,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), ()> {
    match (alg, key) {
        (JwsAlgorithm::EdDsa, KeyMaterial::Ed25519(pk)) => {
            verify_asymmetric(&signature::ED25519, pk, signing_input, signature)
        }
        (JwsAlgorithm::Es256, KeyMaterial::EcP256(point)) => verify_asymmetric(
            &signature::ECDSA_P256_SHA256_FIXED,
            point,
            signing_input,
            signature,
        ),
        (JwsAlgorithm::Es384, KeyMaterial::EcP384(point)) => verify_asymmetric(
            &signature::ECDSA_P384_SHA384_FIXED,
            point,
            signing_input,
            signature,
        ),
        (JwsAlgorithm::Rs256, KeyMaterial::Rsa { n, e }) => verify_rsa(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            n,
            e,
            signing_input,
            signature,
        ),
        (JwsAlgorithm::Rs384, KeyMaterial::Rsa { n, e }) => verify_rsa(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            n,
            e,
            signing_input,
            signature,
        ),
        (JwsAlgorithm::Rs512, KeyMaterial::Rsa { n, e }) => verify_rsa(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            n,
            e,
            signing_input,
            signature,
        ),
        (JwsAlgorithm::Ps256, KeyMaterial::Rsa { n, e }) => verify_rsa(
            &signature::RSA_PSS_2048_8192_SHA256,
            n,
            e,
            signing_input,
            signature,
        ),
        (JwsAlgorithm::Ps384, KeyMaterial::Rsa { n, e }) => verify_rsa(
            &signature::RSA_PSS_2048_8192_SHA384,
            n,
            e,
            signing_input,
            signature,
        ),
        (JwsAlgorithm::Ps512, KeyMaterial::Rsa { n, e }) => verify_rsa(
            &signature::RSA_PSS_2048_8192_SHA512,
            n,
            e,
            signing_input,
            signature,
        ),
        // Any (alg, key) family mismatch never verifies. The caller filters
        // these out first; this arm is the belt-and-braces backstop.
        _ => Err(()),
    }
}

fn verify_asymmetric(
    alg: &'static dyn VerificationAlgorithm,
    key_bytes: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), ()> {
    UnparsedPublicKey::new(alg, key_bytes)
        .verify(signing_input, signature)
        .map_err(|_| ())
}

fn verify_rsa(
    params: &signature::RsaParameters,
    n: &[u8],
    e: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), ()> {
    let components = RsaPublicKeyComponents { n, e };
    components
        .verify(params, signing_input, signature)
        .map_err(|_| ())
}
