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
//! key `Z`: SHA-256 over `round(4 bytes) || Z ||
//! AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo`. For
//! `ECDH-ES` the derived key IS the CEK; the `alg` in the `AlgorithmID` is the
//! content-encryption algorithm (`A256GCM`), per RFC 7518 section 4.6.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdh::EphemeralSecret;
use ring::aead::{AES_256_GCM, Aad as RingAad, LessSafeKey, Nonce, UnboundKey};

use crate::crypto::sha256;

/// The refused JWE algorithm families: `RSA1_5` (Bleichenbacher class) and the
/// `PBKDF2`-based algorithms. Refused at the PARSE, never implemented.
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
    /// The algorithm is refused or unsupported (`RSA1_5`, the `PBKDF2` family, or
    /// anything outside the curated suite).
    UnsupportedAlgorithm,
    /// The ciphertext does not decrypt (a wrong key, a tampered compact form, or
    /// a truncated tag).
    Decryption,
    /// The key material cannot be used (a malformed recipient key).
    InvalidKey,
}

/// Read a usable public P-256 recipient key for the shipped ECDH-ES suite.
/// Signing-only keys, private material and incompatible key operations are refused.
#[must_use]
pub fn encryption_recipient_key(jwk: &serde_json::Value) -> Option<Vec<u8>> {
    if jwk.get("kty")?.as_str()? != "EC"
        || jwk.get("crv")?.as_str()? != "P-256"
        || jwk.get("d").is_some()
        || jwk.get("use").is_some_and(|v| v.as_str() != Some("enc"))
        || jwk
            .get("alg")
            .is_some_and(|v| v.as_str() != Some("ECDH-ES"))
    {
        return None;
    }
    if let Some(operations) = jwk.get("key_ops") {
        let operations = operations.as_array()?;
        if operations.is_empty()
            || !operations
                .iter()
                .all(|v| matches!(v.as_str(), Some("deriveKey" | "deriveBits")))
        {
            return None;
        }
    }
    let x = URL_SAFE_NO_PAD.decode(jwk.get("x")?.as_str()?).ok()?;
    let y = URL_SAFE_NO_PAD.decode(jwk.get("y")?.as_str()?).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut point = vec![4];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&point).ok()?;
    Some(point)
}

/// The P-256 ECDH-ES encrypt (issue #158): an ephemeral P-256 key agrees with
/// the recipient's static public key (uncompressed 65-byte point), the agreed
/// secret derives the A256GCM content key, and the compact serialization is
/// `header.encrypted_key.iv.ciphertext.tag` (the encrypted-key segment is empty for direct
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
    let public =
        p256::PublicKey::from_sec1_bytes(recipient_public_key).map_err(|_| JweError::InvalidKey)?;
    let mut rng = ironauth_env::keygen_rng(entropy);
    let ephemeral = EphemeralSecret::random(&mut rng);
    let shared = ephemeral.diffie_hellman(&public);
    let cek = concat_kdf(shared.raw_secret_bytes(), CONTENT_ENC, 32, &[], &[])?;
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
    encrypt_with_cek(&header, &cek, &[], plaintext, entropy)
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
    let (header_b64, enc_key_b64, iv_b64, ciphertext_b64, tag_b64) =
        split_compact(compact).ok_or(JweError::Decryption)?;
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| JweError::Decryption)?,
    )
    .map_err(|_| JweError::Decryption)?;
    if !enc_key_b64.is_empty()
        || header.get("alg").and_then(serde_json::Value::as_str) != Some("ECDH-ES")
        || header.get("enc").and_then(serde_json::Value::as_str) != Some(CONTENT_ENC)
        || header.get("crit").is_some()
        || header.get("zip").is_some()
    {
        return Err(JweError::Decryption);
    }
    let epk = header.get("epk").ok_or(JweError::Decryption)?;
    if epk.get("kty").and_then(serde_json::Value::as_str) != Some("EC")
        || epk.get("crv").and_then(serde_json::Value::as_str) != Some("P-256")
        || epk.get("d").is_some()
    {
        return Err(JweError::Decryption);
    }
    let party_u = party_info(&header, "apu")?;
    let party_v = party_info(&header, "apv")?;
    let x = epk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(JweError::Decryption)?;
    let y = epk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(JweError::Decryption)?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| JweError::Decryption)?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| JweError::Decryption)?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(JweError::Decryption);
    }
    let mut encoded = vec![0x04];
    encoded.extend_from_slice(&x_bytes);
    encoded.extend_from_slice(&y_bytes);
    let peer = p256::PublicKey::from_sec1_bytes(&encoded).map_err(|_| JweError::Decryption)?;
    let secret =
        p256::SecretKey::from_slice(recipient_private_key).map_err(|_| JweError::InvalidKey)?;
    let scalar = secret.to_nonzero_scalar();
    let shared = p256::ecdh::diffie_hellman(&scalar, peer.as_ref());
    let cek = concat_kdf(
        shared.raw_secret_bytes(),
        CONTENT_ENC,
        32,
        &party_u,
        &party_v,
    )?;
    decrypt_with_cek(&cek, header_b64, iv_b64, ciphertext_b64, tag_b64)
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
fn concat_kdf(
    z: &[u8],
    alg: &str,
    key_len: usize,
    party_u: &[u8],
    party_v: &[u8],
) -> Result<Vec<u8>, JweError> {
    // The curated suite needs only one SHA-256 round.
    if key_len == 0 || key_len > 32 {
        return Err(JweError::InvalidKey);
    }
    let key_bits = u32::try_from(key_len * 8).map_err(|_| JweError::InvalidKey)?;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&1_u32.to_be_bytes());
    hash_input.extend_from_slice(z);
    for data in [alg.as_bytes(), party_u, party_v] {
        let len = u32::try_from(data.len()).map_err(|_| JweError::Decryption)?;
        hash_input.extend_from_slice(&len.to_be_bytes());
        hash_input.extend_from_slice(data);
    }
    hash_input.extend_from_slice(&key_bits.to_be_bytes());
    // SuppPrivInfo is empty, with no length prefix (RFC 7518 section 4.6.2).
    Ok(sha256(&hash_input)[..key_len].to_vec())
}

fn party_info(header: &serde_json::Value, name: &str) -> Result<Vec<u8>, JweError> {
    match header.get(name) {
        None => Ok(Vec::new()),
        Some(serde_json::Value::String(value)) => URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| JweError::Decryption),
        Some(_) => Err(JweError::Decryption),
    }
}

/// Encrypt with the CEK: `header.encrypted_key.iv.ciphertext.tag`.
fn encrypt_with_cek(
    header: &serde_json::Value,
    cek: &[u8],
    encrypted_key: &[u8],
    plaintext: &[u8],
    entropy: &dyn ironauth_env::Entropy,
) -> Result<String, JweError> {
    let unbound = UnboundKey::new(&AES_256_GCM, cek).map_err(|_| JweError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);
    let mut iv = [0_u8; 12];
    entropy.fill_bytes(&mut iv);
    let header_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).map_err(|_| JweError::InvalidKey)?);
    let mut in_out = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            RingAad::from(header_b64.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| JweError::InvalidKey)?;
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
    header_b64: &str,
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
    if iv.len() != 12 || tag.len() != 16 {
        return Err(JweError::Decryption);
    }
    let unbound = UnboundKey::new(&AES_256_GCM, cek).map_err(|_| JweError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = ciphertext;
    in_out.extend_from_slice(&tag);
    let plaintext_len = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(&iv).map_err(|_| JweError::Decryption)?,
            RingAad::from(header_b64.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| JweError::Decryption)?
        .len();
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

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
    fn encryption_keys_reject_signing_use_private_material_and_invalid_points() {
        let key = serde_json::json!({
            "kty": "EC", "crv": "P-256", "use": "enc",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        });
        assert!(super::encryption_recipient_key(&key).is_some());
        for (field, value) in [
            ("use", serde_json::json!("sig")),
            ("d", serde_json::json!("private")),
            ("alg", serde_json::json!("ES256")),
            ("crv", serde_json::json!("P-384")),
            ("x", serde_json::json!("AA")),
            ("key_ops", serde_json::json!(["verify"])),
        ] {
            let mut invalid = key.clone();
            invalid[field] = value;
            assert!(
                super::encryption_recipient_key(&invalid).is_none(),
                "{field}"
            );
        }
    }

    #[test]
    fn concat_kdf_matches_rfc7518_appendix_c() {
        let z = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let key = concat_kdf(&z, "A128GCM", 16, b"Alice", b"Bob").expect("KDF");
        assert_eq!(URL_SAFE_NO_PAD.encode(key), "VqqN6vgjbSBcIijNcacQGg");
    }

    #[test]
    fn decrypts_independent_cryptography_vectors_with_and_without_party_info() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/ecdh_es_a256gcm.json"))
                .expect("fixture");
        let private = URL_SAFE_NO_PAD
            .decode(fixture["recipient_private"].as_str().unwrap())
            .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let compact = vector["compact"].as_str().unwrap();
            let expected = URL_SAFE_NO_PAD
                .decode(vector["plaintext"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                decrypt_ecdh_es("ECDH-ES", compact, &private).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn every_protected_header_byte_is_authenticated() {
        let env = fixed_entropy();
        let (private, public) = p256_keypair(env.entropy());
        let compact = encrypt_ecdh_es("ECDH-ES", &public, b"secret", env.entropy()).unwrap();
        let (header, key, iv, ciphertext, tag) = split_compact(&compact).unwrap();
        let mut decoded: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        decoded["kid"] = serde_json::json!("changed");
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&decoded).unwrap());
        let tampered = format!("{header}.{key}.{iv}.{ciphertext}.{tag}");
        assert_eq!(
            decrypt_ecdh_es("ECDH-ES", &tampered, &private),
            Err(JweError::Decryption)
        );
        let (_, _, iv, ciphertext, tag) = split_compact(&compact).unwrap();
        let original_header = compact.split('.').next().unwrap();
        let nonempty_key = format!("{original_header}.AA.{iv}.{ciphertext}.{tag}");
        assert_eq!(
            decrypt_ecdh_es("ECDH-ES", &nonempty_key, &private),
            Err(JweError::Decryption)
        );
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
        let (private, public) = p256_keypair(env.entropy());
        let compact =
            encrypt_ecdh_es("ECDH-ES", &public, b"the id token", env.entropy()).expect("encrypt");
        let plain = decrypt_ecdh_es("ECDH-ES", &compact, &private).expect("decrypt");
        assert_eq!(plain, b"the id token");
    }

    #[test]
    fn decryption_returns_exact_plaintext_without_the_authentication_tag() {
        let env = fixed_entropy();
        let (private, public) = p256_keypair(env.entropy());
        for payload in [b"".as_slice(), &[0, 255, 128, 0, 1, 2, 3][..]] {
            let compact =
                encrypt_ecdh_es("ECDH-ES", &public, payload, env.entropy()).expect("encrypt");
            let plaintext = decrypt_ecdh_es("ECDH-ES", &compact, &private).expect("decrypt");
            assert_eq!(plaintext, payload);
            assert_eq!(plaintext.len(), payload.len());
        }
    }

    #[test]
    fn encryption_iv_uses_the_callers_entropy_seam() {
        let key_env = fixed_entropy();
        let (_, public) = p256_keypair(key_env.entropy());
        let first_env = fixed_entropy();
        let replay_env = fixed_entropy();
        let first = encrypt_ecdh_es("ECDH-ES", &public, b"owned fixture", first_env.entropy())
            .expect("encrypt");
        let replay = encrypt_ecdh_es("ECDH-ES", &public, b"owned fixture", replay_env.entropy())
            .expect("replay");
        assert_eq!(
            first, replay,
            "every random input comes from the supplied seam"
        );
        let second = encrypt_ecdh_es("ECDH-ES", &public, b"owned fixture", first_env.entropy())
            .expect("next encrypt");
        let (_, _, first_iv, _, _) = split_compact(&first).expect("first compact");
        let (_, _, second_iv, _, _) = split_compact(&second).expect("next compact");
        assert_ne!(first_iv, second_iv, "each encryption consumes a fresh IV");
        assert_eq!(URL_SAFE_NO_PAD.decode(first_iv).expect("IV").len(), 12);
    }

    #[test]
    fn a_wrong_key_does_not_decrypt() {
        let env = fixed_entropy();
        let (_, public) = p256_keypair(env.entropy());
        let (other_private, _) = p256_keypair(env.entropy());
        let compact =
            encrypt_ecdh_es("ECDH-ES", &public, b"secret", env.entropy()).expect("encrypt");
        assert!(decrypt_ecdh_es("ECDH-ES", &compact, &other_private).is_err());
    }

    #[test]
    fn tampering_fails_the_tag() {
        let env = fixed_entropy();
        let (private, public) = p256_keypair(env.entropy());
        let compact =
            encrypt_ecdh_es("ECDH-ES", &public, b"secret", env.entropy()).expect("encrypt");
        let tampered = format!("{compact}x");
        assert!(decrypt_ecdh_es("ECDH-ES", &tampered, &private).is_err());
    }

    #[test]
    fn a_refused_algorithm_is_never_accepted() {
        let env = fixed_entropy();
        let (_, public) = p256_keypair(env.entropy());
        assert!(encrypt_ecdh_es("RSA1_5", &public, b"x", env.entropy()).is_err());
        assert!(encrypt_ecdh_es("PBES2-HS256+A128KW", &public, b"x", env.entropy()).is_err());
    }
}
