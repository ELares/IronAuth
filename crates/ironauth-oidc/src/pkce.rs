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
/// an exact match of a WELL-FORMED verifier: a verifier that violates the RFC 7636
/// 4.1 format (43 to 128 unreserved characters) is rejected outright, so a client
/// cannot slip below the RFC's entropy floor even with a self-consistent challenge.
#[must_use]
pub fn verify_s256(code_verifier: &str, code_challenge: &str) -> bool {
    if !code_verifier_is_well_formed(code_verifier) {
        return false;
    }
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    constant_time_eq(computed.as_bytes(), code_challenge.as_bytes())
}

/// Whether a `code_verifier` meets the RFC 7636 4.1 format: 43 to 128 characters
/// of the unreserved set `[A-Za-z0-9-._~]`. The length is the RFC's entropy floor
/// (43 characters is 256 bits of base64url); the charset keeps it transport-safe.
#[must_use]
pub fn code_verifier_is_well_formed(code_verifier: &str) -> bool {
    // The charset is ASCII, so byte length equals character count.
    (43..=128).contains(&code_verifier.len())
        && code_verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Whether a `code_challenge` is a well-formed S256 challenge: exactly 43
/// base64url characters with no padding, which is what `BASE64URL(SHA256(v))`
/// always produces (RFC 7636 4.2). Rejecting a malformed challenge at
/// authorization time turns a later verify failure into an immediate, honest
/// `invalid_request`.
#[must_use]
pub fn code_challenge_is_well_formed(code_challenge: &str) -> bool {
    code_challenge.len() == 43
        && code_challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
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
    fn s256_rejects_a_wellformed_but_wrong_verifier() {
        // A verifier that IS well-formed (43 unreserved chars) but is not the one
        // the challenge was derived from: rejected on the hash mismatch, not the
        // format gate. This is the core PKCE property.
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let wrong = "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(wrong.len(), 43);
        assert!(code_verifier_is_well_formed(wrong));
        assert!(!verify_s256(wrong, challenge));
    }

    #[test]
    fn s256_rejects_a_malformed_verifier_before_hashing() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        // Too short (below the 43-char / 256-bit entropy floor).
        assert!(!verify_s256("short", challenge));
        assert!(!verify_s256("", challenge));
        // 42 chars: one under the floor.
        assert!(!verify_s256(&"a".repeat(42), challenge));
        // 129 chars: one over the ceiling.
        assert!(!verify_s256(&"a".repeat(129), challenge));
        // Illegal characters (space, plus, slash are outside the unreserved set).
        assert!(!verify_s256(&format!("{}a a", "a".repeat(40)), challenge));
        assert!(!code_verifier_is_well_formed(&format!(
            "{}+/=",
            "a".repeat(40)
        )));
    }

    #[test]
    fn verifier_wellformedness_honors_the_rfc7636_bounds() {
        assert!(code_verifier_is_well_formed(&"a".repeat(43)));
        assert!(code_verifier_is_well_formed(&"a".repeat(128)));
        assert!(code_verifier_is_well_formed(
            "aA0-._~aA0-._~aA0-._~aA0-._~aA0-._~aA0-._~aA0"
        ));
        assert!(!code_verifier_is_well_formed(&"a".repeat(42)));
        assert!(!code_verifier_is_well_formed(&"a".repeat(129)));
    }

    #[test]
    fn s256_challenge_shape_matches_the_appendix_b_digest() {
        // The Appendix B challenge is a real S256 digest and must be well-formed.
        assert!(code_challenge_is_well_formed(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        // A real digest is what verify_s256 emits, so round-trip agreement holds.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let digest = Sha256::digest(verifier.as_bytes());
        assert!(code_challenge_is_well_formed(
            &URL_SAFE_NO_PAD.encode(digest)
        ));
    }

    #[test]
    fn challenge_wellformedness_rejects_bad_shapes() {
        // Wrong length (42 / 44), padding, and out-of-charset all rejected.
        assert!(!code_challenge_is_well_formed(&"a".repeat(42)));
        assert!(!code_challenge_is_well_formed(&"a".repeat(44)));
        assert!(!code_challenge_is_well_formed(&format!(
            "{}=",
            "a".repeat(42)
        ))); // padding
        assert!(!code_challenge_is_well_formed(&format!(
            "{}~",
            "a".repeat(42)
        ))); // '~' is not base64url
        assert!(!code_challenge_is_well_formed("")); // plain (unrepresentable) / empty
    }
}
