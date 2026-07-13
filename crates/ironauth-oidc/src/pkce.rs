// SPDX-License-Identifier: MIT OR Apache-2.0

//! PKCE (RFC 7636) code-verifier verification, S256 only.
//!
//! This is the minimal correct bind-and-verify the code-grant needs: at
//! authorization time the `code_challenge` is bound to the code (in the store),
//! and at redemption the presented `code_verifier` is checked against it here.
//! Only the S256 transform is implemented; `plain` is unrepresentable (see
//! [`crate::registry::PkceMethod`]). Making PKCE MANDATORY for every client and
//! enforcing S256-only across the board is the #13 hardening; this module is the
//! seam it will build on.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Verify a `code_verifier` against a bound S256 `code_challenge`.
///
/// Computes `BASE64URL(SHA256(code_verifier))` and compares it to the challenge
/// in constant time (the comparison is over the public challenge, but a
/// constant-time check costs nothing and keeps the habit). Returns `true` only on
/// an exact match.
#[must_use]
pub fn verify_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    constant_time_eq(computed.as_bytes(), code_challenge.as_bytes())
}

/// A length-then-content constant-time byte comparison. Unequal lengths are not
/// constant time against each other (length is not secret here), but equal-length
/// inputs are compared without early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_matches_the_rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B: verifier and its S256 challenge.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_s256(verifier, challenge));
    }

    #[test]
    fn s256_rejects_a_wrong_verifier() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_s256("not-the-verifier", challenge));
        assert!(!verify_s256("", challenge));
    }
}
