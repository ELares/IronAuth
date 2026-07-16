// SPDX-License-Identifier: MIT OR Apache-2.0

//! `COSE_Key` (RFC 8152) parsing for the WebAuthn credential public key.
//!
//! The credential public key inside the attested credential data is a CBOR
//! `COSE_Key` map. This module walks that map into a [`ironauth_jose::WebauthnKey`]
//! for the three algorithms IronAuth advertises in `pubKeyCredParams`: ES256
//! (COSE EC2 / P-256), `EdDSA` (COSE OKP / Ed25519), and RS256 (COSE RSA). It
//! never performs a cryptographic operation; the signature check lives in the
//! ring-backed JOSE core.

use ciborium::value::Value;
use ironauth_jose::WebauthnKey;

use crate::error::CeremonyError;

// COSE_Key common parameter labels (RFC 8152 table 3/4).
const LABEL_KTY: i128 = 1;
const LABEL_ALG: i128 = 3;
const LABEL_CRV: i128 = -1;
const LABEL_EC_X: i128 = -2;
const LABEL_EC_Y: i128 = -3;
const LABEL_OKP_X: i128 = -2;
const LABEL_RSA_N: i128 = -1;
const LABEL_RSA_E: i128 = -2;

// Key types (RFC 8152 table 21).
const KTY_OKP: i128 = 1;
const KTY_EC2: i128 = 2;
const KTY_RSA: i128 = 3;

// Algorithms (COSE algorithm registry).
const ALG_ES256: i128 = -7;
const ALG_EDDSA: i128 = -8;
const ALG_RS256: i128 = -257;

// Curves (RFC 8152 table 22).
const CRV_P256: i128 = 1;
const CRV_ED25519: i128 = 6;

/// The byte length of a P-256 affine coordinate.
const P256_COORD_LEN: usize = 32;
/// The byte length of an Ed25519 public key.
const ED25519_KEY_LEN: usize = 32;
/// The minimum RSA modulus size (bits) `ring` will verify: a smaller key
/// registers but can never be used, so it is refused at registration.
const RSA_MIN_MODULUS_BITS: u32 = 2048;
/// The maximum RSA modulus size (bits) `ring` will verify.
const RSA_MAX_MODULUS_BITS: u32 = 8192;

/// The significant bit length of a big-endian RSA modulus: leading zero bytes are
/// ignored, then the position of the most significant set bit gives the exact bit
/// count. An all-zero (or empty) modulus is zero bits.
fn rsa_modulus_bits(modulus: &[u8]) -> u32 {
    let first = modulus.iter().position(|&byte| byte != 0);
    match first {
        None => 0,
        Some(index) => {
            let significant = &modulus[index..];
            let top = u32::from(significant[0]);
            let top_bits = 32 - top.leading_zeros();
            let lower_bytes = u32::try_from(significant.len() - 1).unwrap_or(u32::MAX);
            lower_bytes.saturating_mul(8).saturating_add(top_bits)
        }
    }
}

/// Parse a `COSE_Key` CBOR document into a [`WebauthnKey`].
///
/// # Errors
///
/// Returns [`CeremonyError::UnsupportedOrMalformedKey`] if the bytes are not a
/// COSE map, the algorithm/key-type/curve combination is not one of the three
/// supported, or a coordinate has the wrong length.
pub fn parse_cose_key(cose_bytes: &[u8]) -> Result<WebauthnKey, CeremonyError> {
    let value: Value =
        ciborium::from_reader(cose_bytes).map_err(|_| CeremonyError::UnsupportedOrMalformedKey)?;
    let map = value
        .as_map()
        .ok_or(CeremonyError::UnsupportedOrMalformedKey)?;

    let kty = get_int(map, LABEL_KTY).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
    let alg = get_int(map, LABEL_ALG).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;

    match (kty, alg) {
        (KTY_EC2, ALG_ES256) => {
            let crv = get_int(map, LABEL_CRV).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
            if crv != CRV_P256 {
                return Err(CeremonyError::UnsupportedOrMalformedKey);
            }
            let x = get_bytes(map, LABEL_EC_X).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
            let y = get_bytes(map, LABEL_EC_Y).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
            if x.len() != P256_COORD_LEN || y.len() != P256_COORD_LEN {
                return Err(CeremonyError::UnsupportedOrMalformedKey);
            }
            Ok(WebauthnKey::Es256 { x, y })
        }
        (KTY_OKP, ALG_EDDSA) => {
            let crv = get_int(map, LABEL_CRV).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
            if crv != CRV_ED25519 {
                return Err(CeremonyError::UnsupportedOrMalformedKey);
            }
            let public_key =
                get_bytes(map, LABEL_OKP_X).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
            if public_key.len() != ED25519_KEY_LEN {
                return Err(CeremonyError::UnsupportedOrMalformedKey);
            }
            Ok(WebauthnKey::Ed25519 { public_key })
        }
        (KTY_RSA, ALG_RS256) => {
            let n = get_bytes(map, LABEL_RSA_N).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
            let e = get_bytes(map, LABEL_RSA_E).ok_or(CeremonyError::UnsupportedOrMalformedKey)?;
            if n.is_empty() || e.is_empty() {
                return Err(CeremonyError::UnsupportedOrMalformedKey);
            }
            // Reject a modulus outside 2048..=8192 bits at REGISTRATION. ring rejects
            // it at verify time, so a sub-2048 (or >8192) key would register but be
            // permanently unusable, a dead-credential foot-gun: refuse it up front.
            let bits = rsa_modulus_bits(&n);
            if !(RSA_MIN_MODULUS_BITS..=RSA_MAX_MODULUS_BITS).contains(&bits) {
                return Err(CeremonyError::UnsupportedOrMalformedKey);
            }
            Ok(WebauthnKey::Rs256 { n, e })
        }
        _ => Err(CeremonyError::UnsupportedOrMalformedKey),
    }
}

/// Find a map entry with the given integer key and read it as an integer.
fn get_int(map: &[(Value, Value)], key: i128) -> Option<i128> {
    let value = find(map, key)?;
    value.as_integer().map(i128::from)
}

/// Find a map entry with the given integer key and read it as a byte string.
fn get_bytes(map: &[(Value, Value)], key: i128) -> Option<Vec<u8>> {
    let value = find(map, key)?;
    value.as_bytes().cloned()
}

/// Find the value for an integer-keyed COSE map entry.
fn find(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter().find_map(|(k, v)| {
        let candidate = i128::from(k.as_integer()?);
        (candidate == key).then_some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Integer;

    fn encode(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(value, &mut out).unwrap();
        out
    }

    fn ec2_key(x: Vec<u8>, y: Vec<u8>) -> Value {
        Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-7)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(1)),
            ),
            (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
            (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
        ])
    }

    #[test]
    fn parses_a_valid_es256_key() {
        let bytes = encode(&ec2_key(vec![1_u8; 32], vec![2_u8; 32]));
        let key = parse_cose_key(&bytes).unwrap();
        assert_eq!(
            key,
            WebauthnKey::Es256 {
                x: vec![1_u8; 32],
                y: vec![2_u8; 32]
            }
        );
    }

    #[test]
    fn parses_a_valid_ed25519_key() {
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(1)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-8)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(6)),
            ),
            (
                Value::Integer(Integer::from(-2)),
                Value::Bytes(vec![7_u8; 32]),
            ),
        ]);
        let key = parse_cose_key(&encode(&value)).unwrap();
        assert_eq!(
            key,
            WebauthnKey::Ed25519 {
                public_key: vec![7_u8; 32]
            }
        );
    }

    /// A genuine 2048-bit modulus: 256 bytes with the most significant bit set (a
    /// real RSA modulus is odd and has its top bit set), so it is exactly 2048 bits.
    fn modulus_2048() -> Vec<u8> {
        let mut n = vec![9_u8; 256];
        n[0] = 0x80;
        n
    }

    #[test]
    fn parses_a_valid_rs256_key() {
        let n = modulus_2048();
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(3)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-257)),
            ),
            (Value::Integer(Integer::from(-1)), Value::Bytes(n.clone())),
            (
                Value::Integer(Integer::from(-2)),
                Value::Bytes(vec![1, 0, 1]),
            ),
        ]);
        let key = parse_cose_key(&encode(&value)).unwrap();
        assert_eq!(
            key,
            WebauthnKey::Rs256 {
                n,
                e: vec![1, 0, 1]
            }
        );
    }

    #[test]
    fn rejects_sub_2048_bit_rsa_modulus() {
        // A 1024-bit modulus (128 bytes, top bit set) registers cleanly but ring
        // rejects it at verify, a dead-credential foot-gun; refuse it up front.
        let mut short = vec![9_u8; 128];
        short[0] = 0x80;
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(3)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-257)),
            ),
            (Value::Integer(Integer::from(-1)), Value::Bytes(short)),
            (
                Value::Integer(Integer::from(-2)),
                Value::Bytes(vec![1, 0, 1]),
            ),
        ]);
        assert_eq!(
            parse_cose_key(&encode(&value)),
            Err(CeremonyError::UnsupportedOrMalformedKey)
        );
    }

    #[test]
    fn rsa_modulus_bits_counts_significant_bits() {
        assert_eq!(rsa_modulus_bits(&[]), 0);
        assert_eq!(rsa_modulus_bits(&[0, 0]), 0);
        assert_eq!(rsa_modulus_bits(&[0x01]), 1);
        assert_eq!(rsa_modulus_bits(&[0x80]), 8);
        // Leading zero bytes are ignored (a big-endian encoding may carry them).
        assert_eq!(rsa_modulus_bits(&[0x00, 0x80]), 8);
        assert_eq!(rsa_modulus_bits(&modulus_2048()), 2048);
    }

    #[test]
    fn rejects_wrong_coordinate_length() {
        let bytes = encode(&ec2_key(vec![1_u8; 31], vec![2_u8; 32]));
        assert_eq!(
            parse_cose_key(&bytes),
            Err(CeremonyError::UnsupportedOrMalformedKey)
        );
    }

    #[test]
    fn rejects_mismatched_curve() {
        // EC2 + ES256 but crv claims Ed25519.
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-7)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(6)),
            ),
            (
                Value::Integer(Integer::from(-2)),
                Value::Bytes(vec![1_u8; 32]),
            ),
            (
                Value::Integer(Integer::from(-3)),
                Value::Bytes(vec![2_u8; 32]),
            ),
        ]);
        assert_eq!(
            parse_cose_key(&encode(&value)),
            Err(CeremonyError::UnsupportedOrMalformedKey)
        );
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            // ES384 is not advertised.
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-35)),
            ),
        ]);
        assert_eq!(
            parse_cose_key(&encode(&value)),
            Err(CeremonyError::UnsupportedOrMalformedKey)
        );
    }

    #[test]
    fn rejects_non_cbor() {
        assert_eq!(
            parse_cose_key(&[0xff, 0xff, 0xff]),
            Err(CeremonyError::UnsupportedOrMalformedKey)
        );
    }
}
