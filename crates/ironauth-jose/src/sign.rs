// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signature-production primitive: the ONLY module that calls `ring` to
//! SIGN, and the only place the process draws `ring`'s signing RNG.
//!
//! It mirrors the verify side's private `crypto` module. Everything here is
//! `pub(crate)` and reached only from the [`crate::mint`] orchestration, so a
//! raw signing call is unreachable from outside the crate, exactly as a raw
//! verify call is. `scripts/jose-audit.sh` is the second net: no crate other
//! than `ironauth-jose` may name a `ring` signature primitive.
//!
//! # Why `ring` uses constant-time RSA signing here, and why that is safe
//!
//! `ring`'s RSA signing is constant time. JWS performs only RSA SIGNING and
//! VERIFICATION (public/private key operations over a message), never RSA
//! DECRYPTION, so there is no PKCS#1 v1.5 decryption step and therefore no
//! Bleichenbacher / Marvin padding-oracle surface in this core. That is the
//! reason the whole matrix rides on the single `ring` backend the verify core
//! already uses, with no second crypto backend added.
//!
//! # The signing RNG and the determinism seam
//!
//! Ed25519 signing is deterministic and takes no RNG, so it flows cleanly.
//! ECDSA signing (its per-signature nonce), RSA-PSS signing (its salt), RSA
//! blinding, and ECDSA key loading all require ring's own `SecureRandom`, a
//! SEALED trait that no `ironauth-env` `Entropy`-backed type can implement. The
//! RNG here influences only the nonce/salt/blinding, never the key material or
//! the verification outcome, so determinism-under-test is preserved by asserting
//! sign+verify round-trips (and by using deterministic Ed25519 for the exact
//! RFC 8037 byte vectors) rather than by pinning ECDSA/RSA signature bytes. This
//! is the one sanctioned `entropy-via-env` exception in the workspace, isolated
//! to this module, taken on the import line below.

use ring::rand::SystemRandom; // invariant-allow: entropy-via-env (ring's signing RNG is a sealed trait; see module docs)
use ring::signature::{
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
    RSA_PSS_SHA512, RsaEncoding,
};

use crate::mint::MacAlgorithm;
use crate::policy::JwsAlgorithm;
use crate::signing_key::{KeyInner, SigningKey};

/// A fresh handle to the OS-backed secure RNG `ring` requires for ECDSA/RSA
/// signing and ECDSA key loading. Centralized here so the whole crate has a
/// single `ring` RNG touch point.
pub(crate) fn secure_random() -> SystemRandom {
    SystemRandom::new()
}

/// The type [`secure_random`] returns, so a caller can hold one without naming `ring`.
///
/// A helper elsewhere in this crate that needs to KEEP an RNG (rather than make one per call)
/// would otherwise have to name the backend's RNG type in its own struct, which is a second
/// `entropy-via-env` exception with no argument behind it. This alias is how it borrows the one
/// argument that already exists here.
// BEHIND THE FEATURE THAT USES IT. `xmldsig::test_util` is the only consumer, and it is
// `#[cfg(feature = "test-util")]`, so in a build without that feature this alias is dead code.
// The workspace gate never showed it because it runs `--all-features`; a crate that depends on
// this one WITHOUT test-util -- which is every one of them -- turns it into a `-D warnings`
// failure. Found while building `ironauth-store` alone.
#[cfg(feature = "test-util")]
pub(crate) type SecureRandom = SystemRandom;

/// Sign `signing_input` with `key` under the key's declared algorithm.
///
/// Returns the raw signature bytes in the JWS-expected form (the fixed-width
/// `R || S` for ECDSA, the modulus-width octet string for RSA, the 64-byte
/// signature for Ed25519). Any `ring` failure collapses to `Err(())`, carrying
/// no detail, matching the verify side's opaque primitive.
/// Sign an arbitrary octet string with `key`, for a protocol that is not JOSE.
///
/// # Why this exists beside the JWS mint
///
/// SAML's HTTP-Redirect binding (OASIS Bindings 3.4.4.1) signs a URL-ENCODED QUERY STRING, not a
/// JWS signing input: there is no header, no base64url segments, and no `alg` to confuse with a
/// key. The bytes are ours, assembled by us, and what comes back is the raw signature the
/// binding puts in its `Signature` parameter.
///
/// IT ROUTES TO THE SAME PRIMITIVE the mint uses, which is the point of putting it here rather
/// than letting another crate reach for `ring` on its own. A second signing path is a second
/// place for an algorithm to be chosen from something other than the key, and closing that is
/// what this crate is for.
///
/// # Errors
///
/// [`DetachedError`] if the key's declared algorithm and its material disagree, or if the
/// primitive fails -- carrying no detail, matching the verify side.
pub fn sign_detached(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>, DetachedError> {
    sign_asymmetric(key, message).map_err(|()| DetachedError)
}

/// A detached signature could not be produced or did not verify.
///
/// ONE VARIANT, CARRYING NOTHING, which is the same opacity the verify path already practises:
/// a caller learns that the operation failed and nothing about which step or which byte. There
/// is no branch a caller could usefully take on a finer answer, and a finer answer is an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachedError;

impl core::fmt::Display for DetachedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the detached signature operation failed")
    }
}

impl std::error::Error for DetachedError {}

/// Verify a signature made by [`sign_detached`].
///
/// THE ALGORITHM COMES FROM THE CALLER, never from anything travelling with the message, which
/// is the rule this whole crate exists to enforce. SAML's redirect binding puts a `SigAlg`
/// parameter on the wire beside the signature, and a verifier that read the algorithm out of it
/// would be letting the sender pick -- the same shape as a JWS `alg` header. A caller compares
/// `SigAlg` against what it expects and passes its OWN expectation here.
///
/// # Errors
///
/// [`DetachedError`] if the signature does not verify, or if the key and algorithm disagree.
pub fn verify_detached(
    key: &crate::TrustedKey,
    algorithm: JwsAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), DetachedError> {
    crate::crypto::verify_signature(algorithm, key.material(), message, signature)
        .map_err(|()| DetachedError)
}

pub(crate) fn sign_asymmetric(key: &SigningKey, signing_input: &[u8]) -> Result<Vec<u8>, ()> {
    match (key.algorithm(), &key.inner) {
        (JwsAlgorithm::EdDsa, KeyInner::Ed25519(k)) => Ok(k.sign(signing_input).as_ref().to_vec()),
        (JwsAlgorithm::Es256, KeyInner::EcdsaP256(k))
        | (JwsAlgorithm::Es384, KeyInner::EcdsaP384(k)) => {
            let sig = k.sign(&secure_random(), signing_input).map_err(|_| ())?;
            Ok(sig.as_ref().to_vec())
        }
        (JwsAlgorithm::Rs256, KeyInner::Rsa(k)) => rsa_sign(k, &RSA_PKCS1_SHA256, signing_input),
        (JwsAlgorithm::Rs384, KeyInner::Rsa(k)) => rsa_sign(k, &RSA_PKCS1_SHA384, signing_input),
        (JwsAlgorithm::Rs512, KeyInner::Rsa(k)) => rsa_sign(k, &RSA_PKCS1_SHA512, signing_input),
        (JwsAlgorithm::Ps256, KeyInner::Rsa(k)) => rsa_sign(k, &RSA_PSS_SHA256, signing_input),
        (JwsAlgorithm::Ps384, KeyInner::Rsa(k)) => rsa_sign(k, &RSA_PSS_SHA384, signing_input),
        (JwsAlgorithm::Ps512, KeyInner::Rsa(k)) => rsa_sign(k, &RSA_PSS_SHA512, signing_input),
        // The mint checks the algorithm/key family before calling; this arm is
        // the belt-and-braces backstop, matching the verify primitive.
        _ => Err(()),
    }
}

fn rsa_sign(
    key: &ring::signature::RsaKeyPair,
    padding: &'static dyn RsaEncoding,
    signing_input: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut signature = vec![0_u8; key.public().modulus_len()];
    key.sign(padding, &secure_random(), signing_input, &mut signature)
        .map_err(|_| ())?;
    Ok(signature)
}

/// Produce an HMAC signature for the restricted client-secret contexts.
///
/// Symmetric signing exists ONLY here, keyed from a client secret, and only the
/// [`crate::mint`] client-secret entry point can reach it. There is no HMAC key
/// type and no way to put an `HS*` algorithm into an environment key store, so
/// this can never be an environment or tenant default.
pub(crate) fn sign_hmac(mac: MacAlgorithm, secret: &[u8], signing_input: &[u8]) -> Vec<u8> {
    let algorithm = match mac {
        MacAlgorithm::Hs256 => ring::hmac::HMAC_SHA256,
        MacAlgorithm::Hs384 => ring::hmac::HMAC_SHA384,
        MacAlgorithm::Hs512 => ring::hmac::HMAC_SHA512,
    };
    let key = ring::hmac::Key::new(algorithm, secret);
    ring::hmac::sign(&key, signing_input).as_ref().to_vec()
}
