// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hashing helpers: management-key hashing, request fingerprints, and a
//! constant-time comparison for the bootstrap operator token.

use sha2::{Digest, Sha256};

/// The hex SHA-256 of `bytes`. Used for the stored management-key hash and the
/// Idempotency-Key request fingerprint.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether two secrets are equal, in time independent of where they first
/// differ and of their lengths.
///
/// Both inputs are hashed to a fixed 32 bytes first, so the comparison length is
/// constant and a length difference does not leak through timing; the digests
/// are then compared with an XOR accumulation that always inspects all 32 bytes.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let da = Sha256::digest(a);
    let db = Sha256::digest(b);
    let mut diff = 0_u8;
    for (x, y) in da.iter().zip(db.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_stable_and_hex() {
        let h = sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
        assert!(!constant_time_eq(b"secret-token", b"secret-toker"));
        assert!(!constant_time_eq(b"short", b"a-much-longer-value"));
    }
}
