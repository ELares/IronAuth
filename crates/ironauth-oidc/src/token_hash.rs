// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OIDC `at_hash` and `c_hash` computation and its hash-function selection
//! across the signing matrix (issue #14).
//!
//! Both hashes follow the same rule (OIDC Core 3.1.3.6 / 3.3.2.11): hash the
//! ASCII octets of the value (the access token for `at_hash`, the authorization
//! code for `c_hash`) with the digest that pairs with the ID token's signing
//! `alg`, take the LEFT-MOST HALF of the digest, and base64url-encode it (no
//! padding). Only the input differs, so one primitive
//! ([`left_half_hash`](self::left_half_hash)) serves both.
//!
//! # Hash selection
//!
//! The digit-suffix rule pairs `RS256`/`ES256`/`PS256` with SHA-256,
//! `RS384`/`ES384`/`PS384` with SHA-384, and `RS512`/`PS512` with SHA-512.
//! `EdDSA` (Ed25519) has no digit suffix; it is paired with SHA-512, matching
//! the curve's internal hash and the OpenID Connect conformance suite / ecosystem
//! convention. `EdDSA` is the IronAuth default signer, so this is the case that
//! runs by default.
//!
//! # Staged for the front channel
//!
//! The token endpoint issues the ID token WITHOUT an access token in the same
//! response and never carries `at_hash`; the hybrid/implicit response types that
//! carry `at_hash`/`c_hash` from the AUTHORIZATION endpoint are issue #17. This
//! module provides the computation so that front-channel path can consume it; it
//! is not emitted from the token endpoint (see [`crate::tokens`]).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_jose::JwsAlgorithm;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The digest that pairs with an ID token signing algorithm for `at_hash` and
/// `c_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    /// SHA-256 (a `*256` alg).
    Sha256,
    /// SHA-384 (a `*384` alg).
    Sha384,
    /// SHA-512 (a `*512` alg, and `EdDSA`).
    Sha512,
}

impl HashKind {
    /// The `at_hash`/`c_hash` digest for an ID token signing algorithm.
    ///
    /// The `*256`/`*384`/`*512` families follow the digit suffix; `EdDSA`
    /// (Ed25519) uses SHA-512, matching the curve's internal hash and the
    /// conformance-suite convention.
    #[must_use]
    // The explicit `*512`/`EdDSA` arm is kept for documentation even though it
    // shares SHA-512 with the wildcard: `JwsAlgorithm` is `#[non_exhaustive]`, so
    // the wildcard is REQUIRED, and it deliberately mirrors the strongest-digest
    // default. Naming the current algorithms keeps the pairing legible and forces
    // a reviewer to add an explicit arm when a new algorithm lands.
    #[allow(clippy::match_same_arms)]
    pub fn for_alg(alg: JwsAlgorithm) -> Self {
        match alg {
            JwsAlgorithm::Es256 | JwsAlgorithm::Rs256 | JwsAlgorithm::Ps256 => HashKind::Sha256,
            JwsAlgorithm::Es384 | JwsAlgorithm::Rs384 | JwsAlgorithm::Ps384 => HashKind::Sha384,
            JwsAlgorithm::Rs512 | JwsAlgorithm::Ps512 | JwsAlgorithm::EdDsa => HashKind::Sha512,
            // A future algorithm defaults to the strongest digest and MUST be
            // given an explicit arm above when it is added.
            _ => HashKind::Sha512,
        }
    }

    /// The full digest length in bytes (32, 48, or 64). The hash claim is the
    /// left-most half of this.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            HashKind::Sha256 => 32,
            HashKind::Sha384 => 48,
            HashKind::Sha512 => 64,
        }
    }

    /// The digest of `value`'s ASCII octets under this hash.
    fn digest(self, value: &str) -> Vec<u8> {
        match self {
            HashKind::Sha256 => Sha256::digest(value.as_bytes()).to_vec(),
            HashKind::Sha384 => Sha384::digest(value.as_bytes()).to_vec(),
            HashKind::Sha512 => Sha512::digest(value.as_bytes()).to_vec(),
        }
    }
}

/// The OIDC left-half hash of `value` under the digest paired with `alg`: the
/// base64url-no-pad encoding of the LEFT-MOST HALF of the digest.
///
/// This is the shared primitive behind [`at_hash`] and [`c_hash`]; callers use
/// those semantic wrappers rather than this directly.
#[must_use]
pub fn left_half_hash(alg: JwsAlgorithm, value: &str) -> String {
    let kind = HashKind::for_alg(alg);
    let digest = kind.digest(value);
    // The left-most half. digest_len is always even, so the split is exact.
    let half = &digest[..digest.len() / 2];
    URL_SAFE_NO_PAD.encode(half)
}

/// The `at_hash` for an access token, under the ID token's signing `alg`.
///
/// Emitted ONLY in a front-channel ID token issued alongside an access token
/// (issue #17); a token-endpoint ID token never carries it.
#[must_use]
pub fn at_hash(alg: JwsAlgorithm, access_token: &str) -> String {
    left_half_hash(alg, access_token)
}

/// The `c_hash` for an authorization code, under the ID token's signing `alg`.
///
/// Emitted ONLY in a hybrid-flow ID token issued from the authorization
/// endpoint (issue #17); the code flow's ID token never carries it.
#[must_use]
pub fn c_hash(alg: JwsAlgorithm, code: &str) -> String {
    left_half_hash(alg, code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::{Entropy, FixedEntropy};

    /// Every signing algorithm in the matrix, so the selection table is covered
    /// exhaustively (a new algorithm forces this list to change too).
    const MATRIX: [(JwsAlgorithm, HashKind); 9] = [
        (JwsAlgorithm::EdDsa, HashKind::Sha512),
        (JwsAlgorithm::Es256, HashKind::Sha256),
        (JwsAlgorithm::Es384, HashKind::Sha384),
        (JwsAlgorithm::Rs256, HashKind::Sha256),
        (JwsAlgorithm::Rs384, HashKind::Sha384),
        (JwsAlgorithm::Rs512, HashKind::Sha512),
        (JwsAlgorithm::Ps256, HashKind::Sha256),
        (JwsAlgorithm::Ps384, HashKind::Sha384),
        (JwsAlgorithm::Ps512, HashKind::Sha512),
    ];

    #[test]
    fn hash_selection_matches_the_signing_matrix() {
        for (alg, expected) in MATRIX {
            assert_eq!(
                HashKind::for_alg(alg),
                expected,
                "{} pairs with the wrong digest",
                alg.as_jose_name()
            );
        }
    }

    #[test]
    fn eddsa_default_uses_sha512() {
        // The default signer: EdDSA over Ed25519 hashes with SHA-512.
        assert_eq!(HashKind::for_alg(JwsAlgorithm::EdDsa), HashKind::Sha512);
    }

    #[test]
    fn digit_suffix_algorithms_use_the_matching_sha() {
        assert_eq!(HashKind::for_alg(JwsAlgorithm::Rs256), HashKind::Sha256);
        assert_eq!(HashKind::for_alg(JwsAlgorithm::Es256), HashKind::Sha256);
    }

    /// An independent reference: the base64url-no-pad of the left half of the
    /// named digest, computed separately from the module under test.
    fn reference_left_half(kind: HashKind, value: &str) -> String {
        let full = match kind {
            HashKind::Sha256 => Sha256::digest(value.as_bytes()).to_vec(),
            HashKind::Sha384 => Sha384::digest(value.as_bytes()).to_vec(),
            HashKind::Sha512 => Sha512::digest(value.as_bytes()).to_vec(),
        };
        URL_SAFE_NO_PAD.encode(&full[..full.len() / 2])
    }

    #[test]
    fn property_at_hash_and_c_hash_across_the_signers() {
        // Drive many random token/code values from the entropy seam and check,
        // for RS256, ES256, and EdDSA (the acceptance-named signers) plus the
        // rest of the matrix, that at_hash/c_hash equal the independent
        // reference and have the digest's half length. at_hash and c_hash share
        // the primitive, so an equal input yields an equal hash.
        let entropy = FixedEntropy::new(0xA7);
        for round in 0..512_u32 {
            let mut bytes = [0_u8; 24];
            entropy.fill_bytes(&mut bytes);
            let value = format!("token-{round}-{}", URL_SAFE_NO_PAD.encode(bytes));
            for (alg, kind) in MATRIX {
                let expected = reference_left_half(kind, &value);
                let at = at_hash(alg, &value);
                let ch = c_hash(alg, &value);
                assert_eq!(at, expected, "at_hash mismatch for {}", alg.as_jose_name());
                assert_eq!(ch, expected, "c_hash mismatch for {}", alg.as_jose_name());
                // The half-digest byte length round-trips through base64url: the
                // encoded length is ceil(half_len / 3) * 4 minus padding.
                let half_len = kind.digest_len() / 2;
                let decoded = URL_SAFE_NO_PAD.decode(at.as_bytes()).expect("base64url");
                assert_eq!(decoded.len(), half_len, "wrong half length for {kind:?}");
            }
        }
    }

    #[test]
    fn eddsa_at_hash_is_32_bytes_and_rs256_is_16() {
        // A concrete SHA-512 (EdDSA) at_hash decodes to 32 bytes; SHA-256
        // (RS256) to 16. A regression here would mean the wrong digest was used.
        let token = "an.example.access.token";
        let ed = at_hash(JwsAlgorithm::EdDsa, token);
        let rs = at_hash(JwsAlgorithm::Rs256, token);
        assert_eq!(URL_SAFE_NO_PAD.decode(ed.as_bytes()).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(rs.as_bytes()).unwrap().len(), 16);
        assert_ne!(ed, rs, "different digests yield different hashes");
    }
}
