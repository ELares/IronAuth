// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pairwise subject derivation (OIDC Core 1.0 sections 8 and 8.1).
//!
//! A pairwise `sub` gives each client a different, stable, opaque identifier for
//! the same end user, so two clients cannot correlate a user by comparing `sub`
//! values. The privacy guarantee only holds if the derivation is DETERMINISTIC
//! and if every surface that returns a `sub` (the ID token, `UserInfo`, and any
//! future introspection response) returns the SAME value. Half-implementations
//! that return one `sub` from the ID token and another from `UserInfo` fail
//! certification, so this module exposes exactly one derivation function,
//! [`resolve_subject`], and every surface calls it.
//!
//! Derivation, per OIDC Core 8.1, hashes the sector identifier, the local (per
//! user) account identifier, and a per-environment salt:
//!
//! ```text
//! sub = base64url( SHA-256( sector || 0x00 || local_subject || 0x00 || salt ) )
//! ```
//!
//! The `0x00` separators make the concatenation unambiguous (so `("ab", "c")` and
//! `("a", "bc")` never collide). The salt is per environment, so the same user
//! and sector yield different `sub`s in different environments, keeping issuers
//! isolated. A [`SubjectCache`] memoizes derivations so repeated lookups (across
//! the ID token, `UserInfo`, and introspection paths) return the identical value
//! and re-derivation is stable.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Entropy;
use sha2::{Digest, Sha256};

/// How an end user's `sub` is presented to a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectType {
    /// The same `sub` for every client: the local account identifier verbatim.
    Public,
    /// A per-client `sub`: a salted hash over the client's sector identifier, so
    /// two clients cannot correlate the user by `sub`.
    Pairwise,
}

impl SubjectType {
    /// The OIDC metadata value (`public` or `pairwise`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectType::Public => "public",
            SubjectType::Pairwise => "pairwise",
        }
    }
}

/// A per-environment pairwise salt.
///
/// Kept out of logs: its `Debug` renders `<redacted>`, since knowing the salt
/// plus a sector and a candidate account identifier would let an attacker confirm
/// a guessed `sub`.
#[derive(Clone, PartialEq, Eq)]
pub struct PairwiseSalt(Vec<u8>);

impl PairwiseSalt {
    /// The recommended salt length in bytes (256 bits).
    pub const RECOMMENDED_LEN: usize = 32;

    /// Wrap raw salt bytes provisioned out of band.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Generate a fresh 256-bit salt from the entropy seam.
    #[must_use]
    pub fn generate(entropy: &dyn Entropy) -> Self {
        let mut bytes = vec![0_u8; Self::RECOMMENDED_LEN];
        entropy.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The salt bytes, for the derivation.
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for PairwiseSalt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairwiseSalt(<redacted>)")
    }
}

/// The subject configuration for one client: whether its `sub` is public or
/// pairwise, and (for pairwise) the sector identifier the derivation is keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectConfig {
    subject_type: SubjectType,
    sector_identifier: String,
}

impl SubjectConfig {
    /// A public subject: every client sees the local account identifier.
    #[must_use]
    pub fn public() -> Self {
        Self {
            subject_type: SubjectType::Public,
            sector_identifier: String::new(),
        }
    }

    /// A pairwise subject keyed on `sector_identifier` (a host, per OIDC Core
    /// 8.1: either the `sector_identifier_uri` host, or the common host of the
    /// client's redirect URIs).
    #[must_use]
    pub fn pairwise(sector_identifier: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::Pairwise,
            sector_identifier: sector_identifier.into(),
        }
    }

    /// The subject type.
    #[must_use]
    pub fn subject_type(&self) -> SubjectType {
        self.subject_type
    }

    /// The sector identifier (empty for a public subject).
    #[must_use]
    pub fn sector_identifier(&self) -> &str {
        &self.sector_identifier
    }
}

/// Derive the `sub` for a client, the SINGLE shared derivation every surface
/// uses.
///
/// For [`SubjectType::Public`] the `sub` is `local_subject` verbatim. For
/// [`SubjectType::Pairwise`] it is the salted SHA-256 hash described in the module
/// documentation. The result is deterministic in all inputs, so the ID token,
/// `UserInfo`, and introspection paths cannot diverge as long as they call THIS
/// function.
#[must_use]
pub fn resolve_subject(config: &SubjectConfig, local_subject: &str, salt: &PairwiseSalt) -> String {
    match config.subject_type {
        SubjectType::Public => local_subject.to_owned(),
        SubjectType::Pairwise => {
            let mut hasher = Sha256::new();
            hasher.update(config.sector_identifier.as_bytes());
            hasher.update([0x00]);
            hasher.update(local_subject.as_bytes());
            hasher.update([0x00]);
            hasher.update(salt.bytes());
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        }
    }
}

/// A memoizing cache over [`resolve_subject`].
///
/// Once a `sub` has been derived for a `(subject_type, sector, local_subject)`
/// triple it is returned verbatim on every later lookup, so re-derivation is
/// stable and every surface that consults the cache agrees. The cache is keyed on
/// the derivation inputs (never the salt, which is fixed per environment), so a
/// switch to pairwise recomputes once and then memoizes.
#[derive(Debug, Default)]
pub struct SubjectCache {
    // Keyed by (subject_type discriminant, sector identifier, local subject).
    memo: Mutex<HashMap<(SubjectType, String, String), String>>,
}

impl SubjectCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The memoized `sub` for `(config, local_subject)`, deriving it once through
    /// [`resolve_subject`] on first sight.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned, which happens after a panic
    /// on another thread while the lock was held.
    #[must_use]
    pub fn resolve(
        &self,
        config: &SubjectConfig,
        local_subject: &str,
        salt: &PairwiseSalt,
    ) -> String {
        let key = (
            config.subject_type,
            config.sector_identifier.clone(),
            local_subject.to_owned(),
        );
        let mut memo = self.memo.lock().expect("subject cache lock poisoned");
        if let Some(existing) = memo.get(&key) {
            return existing.clone();
        }
        let derived = resolve_subject(config, local_subject, salt);
        memo.insert(key, derived.clone());
        derived
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::FixedEntropy;

    fn salt() -> PairwiseSalt {
        PairwiseSalt::new(vec![7_u8; 32])
    }

    #[test]
    fn public_subject_is_the_local_account_id() {
        let config = SubjectConfig::public();
        assert_eq!(resolve_subject(&config, "user-123", &salt()), "user-123");
    }

    #[test]
    fn pairwise_subject_is_deterministic_and_opaque() {
        let config = SubjectConfig::pairwise("client.example.test");
        let a = resolve_subject(&config, "user-123", &salt());
        let b = resolve_subject(&config, "user-123", &salt());
        assert_eq!(a, b, "same inputs derive the same sub");
        assert_ne!(a, "user-123", "pairwise sub is not the local id");
    }

    #[test]
    fn pairwise_differs_by_sector_local_and_salt() {
        let s = salt();
        let base = resolve_subject(&SubjectConfig::pairwise("a.test"), "user", &s);
        assert_ne!(
            base,
            resolve_subject(&SubjectConfig::pairwise("b.test"), "user", &s),
            "different sector, different sub"
        );
        assert_ne!(
            base,
            resolve_subject(&SubjectConfig::pairwise("a.test"), "other", &s),
            "different user, different sub"
        );
        let other_salt = PairwiseSalt::new(vec![9_u8; 32]);
        assert_ne!(
            base,
            resolve_subject(&SubjectConfig::pairwise("a.test"), "user", &other_salt),
            "different environment salt, different sub"
        );
    }

    #[test]
    fn cache_memoizes_and_stays_stable() {
        let cache = SubjectCache::new();
        let config = SubjectConfig::pairwise("client.example.test");
        let first = cache.resolve(&config, "user-123", &salt());
        // A second lookup returns the memoized value, even with a DIFFERENT salt:
        // once derived, the sub never changes underneath an already-issued token.
        let other_salt = PairwiseSalt::new(vec![1_u8; 32]);
        let second = cache.resolve(&config, "user-123", &other_salt);
        assert_eq!(first, second, "memoized sub is stable");
    }

    #[test]
    fn generated_salt_uses_the_entropy_seam() {
        let salt = PairwiseSalt::generate(&FixedEntropy::new(1));
        assert_eq!(salt.bytes().len(), PairwiseSalt::RECOMMENDED_LEN);
        // Redaction: the Debug never prints the bytes.
        assert_eq!(format!("{salt:?}"), "PairwiseSalt(<redacted>)");
    }
}
