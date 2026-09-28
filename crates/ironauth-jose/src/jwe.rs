// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scoped JWE surface (issue #158).
//!
//! # The curated suite, and what is refused
//!
//! JWE is shipped only where real demand exists, with a curated algorithm suite
//! and two NEVER-implemented families:
//!
//! | Use | Algorithms |
//! |---|---|
//! | Key agreement | `ECDH-ES` (direct: the agreed key IS the content key, P-256) |
//! | Content encryption | `A256GCM` (12-byte IV, 16-byte tag) |
//!
//! `RSA1_5` (the Bleichenbacher-class RSAES-PKCS1-v1_5) and the PBKDF2-based
//! JWE algorithms are REFUSED here: the parse refuses their names, and no code
//! path implements them, so they cannot ship by accident. `RSA-OAEP-256` (the
//! legacy-RP wrapping) and X25519 ECDH-ES are the follow-ups: ring 0.17 cannot
//! import a static agreement key, and the `rsa` crate's decryption is the
//! Marvin-scoped-ignored path the workspace keeps unreachable - both need a
//! backend decision before they ship.
//!
//! # The ECDH-ES Concat KDF
//!
//! The JWE Concat KDF (NIST SP 800-56A) derives the content key from the agreed
//! key `Z`: SHA-256 over `Z || round(4 bytes) || Z-length(4 bytes) || Z ||
//! AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo`. For
//! `ECDH-ES` the derived key IS the CEK; the `alg` in the AlgorithmID is the
//! content-encryption algorithm (`A256GCM`), per RFC 7518 section 4.6.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::EncodedPoint;
use ring::aead::{AES_256_GCM, Aad as RingAad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SystemRandom;

use crate::crypto::sha256;

/// The refused JWE algorithm families: RSA1_5 (Bleichenbacher class) and the
/// PBKDF2-based algorithms. Refused at the PARSE, never implemented.
pub const REFUSED_JWE_ALGORITHMS: &[&str] = &[
    "RSA1_5",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
];

/// Whether a JWE `alg` name is in the refused set (issue #158).
#[must_use]
pub fn jwe_algorithm_is_refused(alg: &str) -> bool {
    REFUSED_JWE_ALGORITHMS.contains(&alg)
}

/// The negotiated content-encryption algorithm (only A256GCM ships).
const CONTENT_ENC: &str = "A256GCM";

/// A JWE processing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JweError {
    /// The algorithm is refused or unsupported (RSA1_5, the PBKDF2 family, or
    /// anything outside the curated suite).
    UnsupportedAlgorithm,
    /// The ciphertext does not decrypt (a wrong key, a tampered compact form, or
    /// a truncated tag).
    Decryption,
    /// The key material cannot be used (a malformed recipient key).
    InvalidKey,
}

/// The P-256 ECDH-ES encrypt (issue #158): an ephemeral P-256 key agrees with
/// the recipient's static public key (uncompressed 65-byte point), the agreed
/// secret derives the A256GCM content key, and the compact serialization is
/// `header.epk.iv.ciphertext.tag` (the encrypted-key segment is empty for direct
/// agreement).
///
/// # Errors
///
/// [`JweError::UnsupportedAlgorithm`] if `alg` is not `ECDH-ES`;
/// [`JweError::InvalidKey`] if the recipient key does not parse.
pub fn encrypt_ecdh_es(
    alg: &str,
    recipient_public_key: &[u8],
    plaintext: &[u8],
    entropy: &dyn ironauth_env::Entropy,
) -> Result<String, JweError> {
    if alg != "ECDH-ES" {
        return Err(JweError::UnsupportedAlgorithm);
    }
    let public = p256::PublicKey::from_sec1_bytes(recipient_public_key)
        .map_err(|_| JweError::InvalidKey)?;
    let mut rng = ironauth_env::keygen_rng(entropy);
    let ephemeral = EphemeralSecret::random(&mut rng);
    let shared = ephemeral.diffie_hellman(&public);
    let cek = concat_kdf(shared.raw_secret_bytes(), CONTENT_ENC, 32);
    let epk: p256::EncodedPoint = ephemeral.public_key().into();
    let header = serde_json::json!({
        "alg": alg,
        "enc": CONTENT_ENC,
        "epk": {
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(epk.x().ok_or(JweError::InvalidKey)?.as_slice()),
            "y": URL_SAFE_NO_PAD.encode(epk.y().ok_or(JweError::InvalidKey)?.as_slice()),
        },
    });
    encrypt_with_cek(&header, &cek, &[], plaintext)
}

/// Decrypt a compact ECDH-ES JWE with the recipient's STATIC P-256 private key
/// (the raw 32-byte scalar).
///
/// # Errors
///
/// [`JweError`] for every failure, uniformly.
pub fn decrypt_ecdh_es(
    alg: &str,
    compact: &str,
    recipient_private_key: &[u8],
) -> Result<Vec<u8>, JweError> {
    if alg != "ECDH-ES" {
        return Err(JweError::UnsupportedAlgorithm);
    }
    let (header_b64, _enc_key_b64, iv_b64, ciphertext_b64, tag_b64) =
        split_compact(compact).ok_or(JweError::Decryption)?;
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| JweError::Decryption)?,
    )
    .map_err(|_| JweError::Decryption)?;
    let epk = header.get("epk").ok_or(JweError::Decryption)?;
    let x = epk.get("x").and_then(|v| v.as_str()).ok_or(JweError::Decryption)?;
    let y = epk.get("y").and_then(|v| v.as_str()).ok_or(JweError::Decryption)?;
    let x_bytes = URL_SAFE_NO_PAD.decode(x).map_err(|_| JweError::Decryption)?;
    let y_bytes = URL_SAFE_NO_PAD.decode(y).map_err(|_| JweError::Decryption)?;
    let mut encoded = vec![0x04];
    encoded.extend_from_slice(&x_bytes);
    encoded.extend_from_slice(&y_bytes);
    let peer = p256::PublicKey::from_sec1_bytes(&encoded).map_err(|_| JweError::Decryption)?;
    let secret = p256::SecretKey::from_slice(recipient_private_key)
        .map_err(|_| JweError::InvalidKey)?;
    let scalar = secret.to_nonzero_scalar();
    let shared = p256::ecdh::diffie_hellman(&scalar, peer.as_ref());
    let cek = concat_kdf(shared.raw_secret_bytes(), CONTENT_ENC, 32);
    decrypt_with_cek(&cek, iv_b64, ciphertext_b64, tag_b64)
}

/// The five-segment split of a compact JWE.
fn split_compact(compact: &str) -> Option<(&str, &str, &str, &str, &str)> {
    let mut parts = compact.split('.');
    let header = parts.next()?;
    let encrypted_key = parts.next()?;
    let iv = parts.next()?;
    let ciphertext = parts.next()?;
    let tag = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((header, encrypted_key, iv, ciphertext, tag))
}

/// The JWE Concat KDF (NIST SP 800-56A, RFC 7518 section 4.6): derive `key_len`
/// bytes from the agreed key `z` for the content-encryption `alg`.
fn concat_kdf(z: &[u8], alg: &str, key_len: usize) -> Vec<u8> {
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&1_u32.to_be_bytes());
    hash_input.extend_from_slice(&(z.len() as u32).to_be_bytes());
    hash_input.extend_from_slice(z);
    hash_input.extend_from_slice(&(alg.len() as u32).to_be_bytes());
    hash_input.extend_from_slice(alg.as_bytes());
    // The empty PartyUInfo/PartyVInfo and the empty SuppPrivInfo are the default
    // (no apu/apv supplied); SuppPubInfo is the key-length bits.
    hash_input.extend_from_slice(&[0, 0, 0, 0]);
    hash_input.extend_from_slice(&((key_len * 8) as u32).to_be_bytes());
    hash_input.extend_from_slice(&[0, 0, 0, 0]);
    sha256(&hash_input)[..key_len].to_vec()
}

/// Encrypt with the CEK: `header.payload.encrypted_key.iv.ciphertext.tag`.
fn encrypt_with_cek(
    header: &serde_json::Value,
    cek: &[u8],
    encrypted_key: &[u8],
    plaintext: &[u8],
) -> Result<String, JweError> {
    let unbound = UnboundKey::new(&AES_256_GCM, cek).map_err(|_| JweError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);
    let mut iv = [0_u8; 12];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut iv)
        .map_err(|_| JweError::InvalidKey)?;
    let mut in_out = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            RingAad::empty(),
            &mut in_out,
        )
        .map_err(|_| JweError::InvalidKey)?;
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(header).map_err(|_| JweError::InvalidKey)?);
    Ok(format!(
        "{header_b64}.{}.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(encrypted_key),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(&in_out),
        URL_SAFE_NO_PAD.encode(tag.as_ref()),
    ))
}

/// Decrypt with the CEK, verifying the tag.
fn decrypt_with_cek(
    cek: &[u8],
    iv_b64: &str,
    ciphertext_b64: &str,
    tag_b64: &str,
) -> Result<Vec<u8>, JweError> {
    let iv = URL_SAFE_NO_PAD
        .decode(iv_b64)
        .map_err(|_| JweError::Decryption)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext_b64)
        .map_err(|_| JweError::Decryption)?;
    let tag = URL_SAFE_NO_PAD
        .decode(tag_b64)
        .map_err(|_| JweError::Decryption)?;
    let unbound = UnboundKey::new(&AES_256_GCM, cek).map_err(|_| JweError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = ciphertext;
    in_out.extend_from_slice(&tag);
    key.open_in_place(
        Nonce::try_assume_unique_for_key(&iv).map_err(|_| JweError::Decryption)?,
        RingAad::empty(),
        &mut in_out,
    )
    .map_err(|_| JweError::Decryption)?;
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh P-256 keypair: the static private scalar + the uncompressed public
    /// point, drawn off the determinism-seam bridge (the same rng the keygen uses).
    fn p256_keypair(entropy: &dyn ironauth_env::Entropy) -> ([u8; 32], Vec<u8>) {
        let mut rng = ironauth_env::keygen_rng(entropy);
        let private = p256::SecretKey::random(&mut rng);
        let public_point = private.public_key().to_encoded_point(false);
        (private.to_bytes().into(), public_point.as_bytes().to_vec())
    }

    /// A fixed entropy source for the deterministic tests.
    fn fixed_entropy() -> ironauth_env::Env {
        ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 7).0
    }

    #[test]
    fn the_refused_algorithm_names_are_refused() {
        for name in REFUSED_JWE_ALGORITHMS {
            assert!(jwe_algorithm_is_refused(name), "{name}");
        }
        assert!(!jwe_algorithm_is_refused("ECDH-ES"));
    }

    #[test]
    fn ecdh_es_p256_round_trips() {
        let env = fixed_entropy();
        let (private, public) = p256_keypair(&env);
        let compact = encrypt_ecdh_es("ECDH-ES", &public, b"the id token", &env).expect("encrypt");
        let plain = decrypt_ecdh_es("ECDH-ES", &compact, &private).expect("decrypt");
        assert_eq!(plain, b"the id token");
    }

    #[test]
    fn a_wrong_key_does_not_decrypt() {
        let env = fixed_entropy();
        let (public, _) = p256_keypair(&env);
        let (other_private, _) = p256_keypair(&env);
        let compact = encrypt_ecdh_es("ECDH-ES", &public, b"secret", &env).expect("encrypt");
        assert!(decrypt_ecdh_es("ECDH-ES", &compact, &other_private).is_err());
    }

    #[test]
    fn tampering_fails_the_tag() {
        let env = fixed_entropy();
        let (private, public) = p256_keypair(&env);
        let compact = encrypt_ecdh_es("ECDH-ES", &public, b"secret", &env).expect("encrypt");
        let tampered = format!("{}x", compact);
        assert!(decrypt_ecdh_es("ECDH-ES", &tampered, &private).is_err());
    }

    #[test]
    fn a_refused_algorithm_is_never_accepted() {
        let env = fixed_entropy();
        let (_, public) = p256_keypair(&env);
        assert!(encrypt_ecdh_es("RSA1_5", &public, b"x", &env).is_err());
        assert!(encrypt_ecdh_es("PBES2-HS256+A128KW", &public, b"x", &env).is_err());
    }
}