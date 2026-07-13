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
//! [`resolve_subject`]. The ID token path routes through it today; the `UserInfo`
//! and introspection surfaces arrive in later issues and must call the same
//! function (a single shared derivation, held by convention until those surfaces
//! exist).
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
//! isolated. A [`SubjectCache`] memoizes PAIRWISE derivations, partitioned by the
//! per-environment salt, so repeated lookups within an environment return the
//! identical value while different environments stay isolated. Public subjects are
//! returned directly (the value is just the local identifier, nothing to cache).

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Entropy;
use sha2::{Digest, Sha256};

/// The maximum length of a `sub` claim, in ASCII characters (OIDC Core 1.0
/// errata set 2, section 2, caps `sub` at 255 ASCII characters).
///
/// IronAuth enforces this at ISSUANCE and fails closed: a subject over the cap
/// is never truncated (truncation could collide two distinct users onto one
/// `sub`), it is refused. Both derivations this module produces are far under
/// it by construction (a `usr_` public id is ~68 characters, a base64url
/// pairwise hash is 43), so the cap is a fail-closed backstop, not a routine
/// limit.
pub const MAX_SUBJECT_LEN: usize = 255;

/// Whether `sub` is within the 255 ASCII-character cap: pure ASCII and at most
/// [`MAX_SUBJECT_LEN`] characters. The issuance path checks this and refuses a
/// violating subject rather than truncating it (OIDC Core errata set 2 §2).
#[must_use]
pub fn subject_within_cap(sub: &str) -> bool {
    sub.is_ascii() && sub.len() <= MAX_SUBJECT_LEN
}

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

/// A non-reversible fingerprint of a per-environment salt.
///
/// Used only to PARTITION the memo so two environments (which hold different
/// salts) never share a cache entry. Fingerprinting rather than storing the salt
/// keeps the secret out of the map key, and the fingerprint is domain-separated
/// from [`resolve_subject`] so it can never coincide with a derived `sub`.
fn salt_fingerprint(salt: &PairwiseSalt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ironauth.pairwise.salt.fingerprint.v1");
    hasher.update(salt.bytes());
    hasher.finalize().into()
}

/// A memoizing cache over [`resolve_subject`] for PAIRWISE subjects.
///
/// Once a pairwise `sub` has been derived for a `(salt, sector, local_subject)`
/// triple it is returned verbatim on every later lookup within that environment,
/// so re-derivation is stable and every surface that consults the cache agrees.
/// The key includes a fingerprint of the per-environment salt, so two environments
/// deriving a `sub` for the same `(sector, local_subject)` never collide: each
/// environment's salt is a distinct partition, preserving per-environment
/// isolation. Public subjects are not cached (the value is the local identifier
/// verbatim, so there is nothing to memoize).
#[derive(Debug, Default)]
pub struct SubjectCache {
    // Keyed by (per-environment salt fingerprint, sector identifier, local
    // subject). Only pairwise subjects are stored.
    memo: Mutex<HashMap<MemoKey, String>>,
}

/// The memo key: a per-environment salt fingerprint, the sector identifier, and
/// the local subject. Two environments (different salts) never share an entry.
type MemoKey = ([u8; 32], String, String);

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
        // A public sub is the local account identifier verbatim, so there is
        // nothing to memoize; caching it would only grow the map by one entry per
        // end user for no benefit. Only pairwise derivations (an actual hash) are
        // cached.
        if config.subject_type == SubjectType::Public {
            return resolve_subject(config, local_subject, salt);
        }
        // Partition the memo by a fingerprint of the per-environment salt, so two
        // environments deriving a sub for the same (sector, local_subject) never
        // collide on one entry. Without the salt in the key, a second environment
        // would inherit the first environment's salt-derived value, breaking the
        // per-environment isolation the salt exists to provide.
        let key = (
            salt_fingerprint(salt),
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
    fn cache_memoizes_within_a_salt_and_isolates_across_salts() {
        let cache = SubjectCache::new();
        let config = SubjectConfig::pairwise("client.example.test");
        let env_a = salt();
        let first = cache.resolve(&config, "user-123", &env_a);
        // Same salt and inputs: the memoized value is returned unchanged.
        let repeat = cache.resolve(&config, "user-123", &env_a);
        assert_eq!(first, repeat, "same salt memoizes to a stable sub");
        // A different per-environment salt is a distinct partition, so the sub must
        // differ: two environments never share a pairwise sub for one user+sector.
        let env_b = PairwiseSalt::new(vec![1_u8; 32]);
        let across = cache.resolve(&config, "user-123", &env_b);
        assert_ne!(
            first, across,
            "a different environment salt derives a different sub"
        );
        assert_eq!(
            across,
            resolve_subject(&config, "user-123", &env_b),
            "and the cached value matches the pure derivation for that salt"
        );
    }

    #[test]
    fn public_subjects_are_not_cached() {
        // A public subject returns the local id verbatim through the cache, but the
        // cache must not retain an entry for it (it would grow per end user).
        let cache = SubjectCache::new();
        let config = SubjectConfig::public();
        assert_eq!(cache.resolve(&config, "user-123", &salt()), "user-123");
        assert!(
            cache.memo.lock().expect("lock").is_empty(),
            "public subjects leave no cache entry"
        );
    }

    #[test]
    fn subject_cap_admits_both_derivations_and_refuses_overlength() {
        // Both derivations this module produces are within the cap.
        let public = resolve_subject(&SubjectConfig::public(), "usr_abc", &salt());
        assert!(subject_within_cap(&public));
        let pairwise = resolve_subject(&SubjectConfig::pairwise("a.test"), "usr_abc", &salt());
        assert!(subject_within_cap(&pairwise));

        // Exactly 255 ASCII characters is admitted; 256 is refused; non-ASCII is
        // refused even under the length cap.
        assert!(subject_within_cap(&"a".repeat(MAX_SUBJECT_LEN)));
        assert!(!subject_within_cap(&"a".repeat(MAX_SUBJECT_LEN + 1)));
        assert!(!subject_within_cap("café"));
    }

    #[test]
    fn generated_salt_uses_the_entropy_seam() {
        let salt = PairwiseSalt::generate(&FixedEntropy::new(1));
        assert_eq!(salt.bytes().len(), PairwiseSalt::RECOMMENDED_LEN);
        // Redaction: the Debug never prints the bytes.
        assert_eq!(format!("{salt:?}"), "PairwiseSalt(<redacted>)");
    }
}
