// SPDX-License-Identifier: MIT OR Apache-2.0

//! WebAuthn (FIDO2) assertion and registration signature verification.
//!
//! This module exists inside `ironauth-jose` for one structural reason: this is
//! the only crate permitted to name `ring::signature` (enforced by
//! `scripts/jose-audit.sh`). A WebAuthn ceremony signature is NOT a JWS: the
//! signed message is `authenticatorData || SHA-256(clientDataJSON)`, the ECDSA
//! signature is ASN.1 DER (not the fixed `r||s` a JWS carries), and the public
//! key comes from a COSE key rather than a JWK. So the JWS [`crate::verify`]
//! path cannot be reused; this is a separate, narrowly scoped primitive.
//!
//! The `ironauth-webauthn` crate owns all ceremony parsing (CBOR, COSE,
//! authenticator data, clientDataJSON) and never touches `ring`; it constructs a
//! [`WebauthnKey`] of already-parsed public-key material and hands the message
//! and signature here for the one cryptographic check.
//!
//! Like the rest of this crate, verification carries no oracle: every failure
//! collapses to the single opaque [`WebauthnSignatureError`], so a caller cannot
//! learn WHICH check failed.

use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey, VerificationAlgorithm};

/// The byte length of a P-256 affine coordinate.
const P256_COORD_LEN: usize = 32;
/// The byte length of an Ed25519 public key (a compressed point).
const ED25519_KEY_LEN: usize = 32;

/// A COSE public key parsed from a WebAuthn credential, in the three algorithms
/// IronAuth accepts.
///
/// This is public key material, never secret: it is safe to store as a `bytea`
/// column and to reconstruct from storage. The three variants are exactly the
/// COSE algorithms the ceremony layer advertises in `pubKeyCredParams`
/// (`-7` ES256, `-8` `EdDSA`, `-257` RS256), matching the asymmetric matrix the
/// JWS verify core already supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebauthnKey {
    /// COSE algorithm `-7` (ES256): ECDSA on the NIST P-256 curve with SHA-256.
    ///
    /// `x` and `y` are the 32-byte big-endian affine coordinates of the public
    /// point.
    Es256 {
        /// The big-endian x coordinate (32 bytes).
        x: Vec<u8>,
        /// The big-endian y coordinate (32 bytes).
        y: Vec<u8>,
    },
    /// COSE algorithm `-8` (`EdDSA` over the Ed25519 curve).
    ///
    /// `public_key` is the 32-byte compressed Edwards point.
    Ed25519 {
        /// The 32-byte compressed public key.
        public_key: Vec<u8>,
    },
    /// COSE algorithm `-257` (RS256): RSASSA-PKCS1-v1_5 with SHA-256.
    ///
    /// `n` and `e` are the big-endian modulus and public exponent.
    Rs256 {
        /// The big-endian modulus.
        n: Vec<u8>,
        /// The big-endian public exponent.
        e: Vec<u8>,
    },
}

/// The single, opaque error a WebAuthn signature verification failure collapses
/// into.
///
/// It renders one fixed string regardless of the underlying cause (a malformed
/// key, a length mismatch, or a genuine bad signature), so the value carries no
/// oracle a caller could probe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WebauthnSignatureError;

impl core::fmt::Debug for WebauthnSignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WebauthnSignatureError")
    }
}

impl core::fmt::Display for WebauthnSignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("webauthn signature verification failed")
    }
}

impl std::error::Error for WebauthnSignatureError {}

/// Verify a WebAuthn ceremony signature over `signed_message` with `signature`
/// under `key`.
///
/// `signed_message` is the concatenation the WebAuthn spec defines for both the
/// registration attestation and the authentication assertion:
/// `authenticatorData || SHA-256(clientDataJSON)`. The caller computes that
/// concatenation; this function performs only the cryptographic check.
///
/// Returns `Ok(())` only on a valid signature. The ECDSA path uses ring's
/// ASN.1-DER verifier (`ECDSA_P256_SHA256_ASN1`), because WebAuthn ECDSA
/// signatures are DER-encoded, unlike the fixed-width form a JWS uses. The RSA
/// path rejects moduli below 2048 bits (ring's floor). Any error, including a
/// malformed key, collapses to [`WebauthnSignatureError`].
///
/// # Errors
///
/// Returns [`WebauthnSignatureError`] if the key material is malformed (wrong
/// coordinate or key length) or the signature does not verify.
pub fn verify_webauthn_signature(
    key: &WebauthnKey,
    signed_message: &[u8],
    signature: &[u8],
) -> Result<(), WebauthnSignatureError> {
    match key {
        WebauthnKey::Es256 { x, y } => {
            if x.len() != P256_COORD_LEN || y.len() != P256_COORD_LEN {
                return Err(WebauthnSignatureError);
            }
            let mut point = Vec::with_capacity(1 + 2 * P256_COORD_LEN);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            verify_asymmetric(
                &signature::ECDSA_P256_SHA256_ASN1,
                &point,
                signed_message,
                signature,
            )
        }
        WebauthnKey::Ed25519 { public_key } => {
            if public_key.len() != ED25519_KEY_LEN {
                return Err(WebauthnSignatureError);
            }
            verify_asymmetric(&signature::ED25519, public_key, signed_message, signature)
        }
        WebauthnKey::Rs256 { n, e } => {
            let components = RsaPublicKeyComponents { n, e };
            components
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    signed_message,
                    signature,
                )
                .map_err(|_| WebauthnSignatureError)
        }
    }
}

fn verify_asymmetric(
    alg: &'static dyn VerificationAlgorithm,
    key_bytes: &[u8],
    signed_message: &[u8],
    signature: &[u8],
) -> Result<(), WebauthnSignatureError> {
    UnparsedPublicKey::new(alg, key_bytes)
        .verify(signed_message, signature)
        .map_err(|_| WebauthnSignatureError)
}

/// Verify a JWS/JWT compact-serialization signature over `signing_input` (the
/// ASCII `base64url(header) || "." || base64url(payload)`) with `signature`
/// (the raw, already-base64url-decoded signature bytes) under `key` (issue #66).
///
/// This is the SIBLING of [`verify_webauthn_signature`] for the FIDO Metadata
/// Service BLOB, which is a JWS, NOT a WebAuthn ceremony signature. The ONLY
/// difference is the ECDSA encoding: a JWS ES256 signature is the fixed-width
/// `r || s` (64 bytes) of JWA (RFC 7518 section 3.4), where a WebAuthn ECDSA
/// signature is ASN.1 DER. `EdDSA` and RSA PKCS1-v1_5 are byte-identical between
/// the two forms, so those arms mirror [`verify_webauthn_signature`] exactly.
///
/// It lives here (not in the JWS [`crate::verify`] core) on purpose: [`crate::verify`]
/// deliberately REJECTS the `x5c` header the MDS3 BLOB carries (in-token key
/// material is fail-closed there), so the MDS3 chain verifier parses and pins the
/// x5c chain to the compiled-in FIDO root out of band and then calls this one
/// narrow primitive for the leaf-key signature check. Like its sibling it carries
/// no oracle: every failure collapses to [`WebauthnSignatureError`].
///
/// # Errors
///
/// Returns [`WebauthnSignatureError`] if the key material is malformed or the
/// signature does not verify.
pub fn verify_jws_signature(
    key: &WebauthnKey,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), WebauthnSignatureError> {
    match key {
        WebauthnKey::Es256 { x, y } => {
            if x.len() != P256_COORD_LEN || y.len() != P256_COORD_LEN {
                return Err(WebauthnSignatureError);
            }
            let mut point = Vec::with_capacity(1 + 2 * P256_COORD_LEN);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            // The JWA fixed-width `r || s` verifier, NOT the ASN.1-DER one.
            verify_asymmetric(
                &signature::ECDSA_P256_SHA256_FIXED,
                &point,
                signing_input,
                signature,
            )
        }
        WebauthnKey::Ed25519 { public_key } => {
            if public_key.len() != ED25519_KEY_LEN {
                return Err(WebauthnSignatureError);
            }
            verify_asymmetric(&signature::ED25519, public_key, signing_input, signature)
        }
        WebauthnKey::Rs256 { n, e } => {
            let components = RsaPublicKeyComponents { n, e };
            components
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    signing_input,
                    signature,
                )
                .map_err(|_| WebauthnSignatureError)
        }
    }
}

/// Test-only WebAuthn software-authenticator crypto helpers.
///
/// Compiled only under the `test-util` feature. A downstream integration test
/// (`ironauth-webauthn`) uses these to act as a virtual authenticator: it derives
/// an Ed25519 credential key from a fixed seed and produces genuinely valid
/// assertion signatures, so the ceremony verifier can be exercised end to end
/// without a browser. This is signing only; it introduces no verification path,
/// and `ring` stays contained in this crate.
#[cfg(feature = "test-util")]
pub mod test_util {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Derive the raw 32-byte Ed25519 public key from a 32-byte seed.
    ///
    /// # Panics
    ///
    /// Panics if `ring` rejects the seed, which cannot happen for a 32-byte seed.
    #[must_use]
    pub fn ed25519_public_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .expect("a 32-byte seed is a valid Ed25519 seed");
        key_pair.public_key().as_ref().to_vec()
    }

    /// Sign `message` with the Ed25519 key derived from `seed`, returning the raw
    /// 64-byte signature (the same encoding WebAuthn uses).
    ///
    /// # Panics
    ///
    /// Panics if `ring` rejects the seed, which cannot happen for a 32-byte seed.
    #[must_use]
    pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .expect("a 32-byte seed is a valid Ed25519 seed");
        key_pair.sign(message).as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256_rejects_wrong_coordinate_length() {
        let key = WebauthnKey::Es256 {
            x: vec![0_u8; 31],
            y: vec![0_u8; 32],
        };
        assert!(verify_webauthn_signature(&key, b"message", &[0_u8; 64]).is_err());
    }

    #[test]
    fn ed25519_rejects_wrong_key_length() {
        let key = WebauthnKey::Ed25519 {
            public_key: vec![0_u8; 31],
        };
        assert!(verify_webauthn_signature(&key, b"message", &[0_u8; 64]).is_err());
    }

    #[test]
    fn a_zero_key_never_verifies() {
        // A structurally valid but bogus key must fail, not panic.
        let key = WebauthnKey::Es256 {
            x: vec![0_u8; 32],
            y: vec![0_u8; 32],
        };
        assert!(verify_webauthn_signature(&key, b"message", &[0_u8; 72]).is_err());
    }

    #[test]
    fn error_display_is_uniform() {
        assert_eq!(
            WebauthnSignatureError.to_string(),
            "webauthn signature verification failed"
        );
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn jws_ed25519_signature_verifies_and_rejects_tampering() {
        // The MDS3 BLOB JWS primitive: an EdDSA signature is byte-identical between the
        // JWS and WebAuthn forms, so a genuine Ed25519 signature over the signing input
        // verifies and any tamper of the input or signature is rejected.
        let seed = [7_u8; 32];
        let public_key = super::test_util::ed25519_public_key_from_seed(&seed);
        let key = WebauthnKey::Ed25519 { public_key };
        let signing_input = b"eyJhbGciOiJFZERTQSJ9.eyJubyI6MX0";
        let sig = super::test_util::ed25519_sign(&seed, signing_input);
        assert!(verify_jws_signature(&key, signing_input, &sig).is_ok());
        // A flipped signature byte fails.
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        assert!(verify_jws_signature(&key, signing_input, &bad_sig).is_err());
        // A tampered signing input fails.
        assert!(verify_jws_signature(&key, b"eyJhbGciOiJFZERTQSJ9.TAMPERED", &sig).is_err());
    }

    #[test]
    fn jws_es256_uses_fixed_width_not_der() {
        // A DER-encoded (WebAuthn-form) signature must NOT verify through the JWS path,
        // which expects the fixed-width r||s: this proves the two primitives use distinct
        // ECDSA encodings and cannot be confused.
        let key = WebauthnKey::Es256 {
            x: vec![0_u8; 32],
            y: vec![0_u8; 32],
        };
        // A 64-byte all-zero "fixed" signature never verifies against a bogus key.
        assert!(verify_jws_signature(&key, b"msg", &[0_u8; 64]).is_err());
        // A wrong coordinate length is rejected up front.
        let short = WebauthnKey::Es256 {
            x: vec![0_u8; 31],
            y: vec![0_u8; 32],
        };
        assert!(verify_jws_signature(&short, b"msg", &[0_u8; 64]).is_err());
    }
}
