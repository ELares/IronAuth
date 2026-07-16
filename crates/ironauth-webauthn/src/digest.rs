// SPDX-License-Identifier: MIT OR Apache-2.0

//! SHA-256, used for the RP ID hash comparison and the clientDataJSON hash that
//! forms the WebAuthn signed message. This is a plain digest (not a signature
//! primitive), so it does not belong in the ring-gated JOSE core.

use sha2::{Digest, Sha256};

/// The SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer() {
        // SHA-256("abc")
        let out = sha256(b"abc");
        assert_eq!(
            out,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }
}
