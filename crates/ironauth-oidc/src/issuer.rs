// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment issuers: the registry that ties an environment to its signing
//! keys, its algorithm policy, its JWKS, and its discovery document.
//!
//! Every tenant and environment gets its OWN issuer URL and `jwks_uri` with an
//! independent key set (issue #19). This module holds the in-memory view a
//! request handler consults: an [`IssuerRegistry`] maps an [`EnvironmentId`] to an
//! [`IssuerEntry`] (its [`KeySet`], its [`SigningPolicy`], and its pairwise salt),
//! and derives the per-scope issuer string, the published JWKS (rotation-aware and
//! policy-filtered), and the discovery metadata.
//!
//! Keys are LOADED from the persistence layer's per-environment `signing_keys`
//! rows (see [`load_signing_key`]) into the [`KeySet`]s here, so the isolation the
//! store enforces (a key row is reachable only within its own scope) carries
//! straight into the serving path.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use ironauth_jose::{
    JwsAlgorithm, KeyFamily, KeySet, SigningKey, SigningKeyError, SigningPolicy,
    includes_downgrade_key,
};
use ironauth_store::{EnvironmentId, Scope, SigningKeyMaterialKind, SigningKeyRecord};

use crate::subject::PairwiseSalt;

/// The JWKS cache window advertised on every JWKS response, bounded to the
/// 300-to-900-second range OIDC operational discipline requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwksCacheWindow {
    max_age: Duration,
}

impl JwksCacheWindow {
    /// The minimum permitted `max-age` (5 minutes).
    pub const MIN_SECS: u64 = 300;
    /// The maximum permitted `max-age` (15 minutes).
    pub const MAX_SECS: u64 = 900;

    /// A window with an explicit `max-age`.
    ///
    /// # Errors
    ///
    /// [`JwksCacheError::OutOfRange`] if `max_age_secs` is outside
    /// `MIN_SECS..=MAX_SECS`.
    pub fn new(max_age_secs: u64) -> Result<Self, JwksCacheError> {
        if !(Self::MIN_SECS..=Self::MAX_SECS).contains(&max_age_secs) {
            return Err(JwksCacheError::OutOfRange {
                value: max_age_secs,
            });
        }
        Ok(Self {
            max_age: Duration::from_secs(max_age_secs),
        })
    }

    /// A window with `max_age_secs` clamped into the permitted range.
    #[must_use]
    pub fn clamped(max_age_secs: u64) -> Self {
        let secs = max_age_secs.clamp(Self::MIN_SECS, Self::MAX_SECS);
        Self {
            max_age: Duration::from_secs(secs),
        }
    }

    /// The `max-age` as a duration.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// The `max-age` in whole seconds (for the `Cache-Control` header).
    #[must_use]
    pub fn max_age_secs(&self) -> u64 {
        self.max_age.as_secs()
    }
}

impl Default for JwksCacheWindow {
    fn default() -> Self {
        // 10 minutes: the midpoint of the permitted range.
        Self {
            max_age: Duration::from_secs(600),
        }
    }
}

/// An out-of-range JWKS cache window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwksCacheError {
    /// The `max-age` was outside the 300-to-900-second range.
    OutOfRange {
        /// The rejected value.
        value: u64,
    },
}

impl std::fmt::Display for JwksCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwksCacheError::OutOfRange { value } => write!(
                f,
                "JWKS cache max-age {value}s is outside the required {}..={} range",
                JwksCacheWindow::MIN_SECS,
                JwksCacheWindow::MAX_SECS
            ),
        }
    }
}

impl std::error::Error for JwksCacheError {}

/// One environment's issuer state: its keys, its algorithm policy, and its
/// pairwise salt.
pub struct IssuerEntry {
    keyset: KeySet,
    policy: SigningPolicy,
    salt: PairwiseSalt,
}

impl IssuerEntry {
    /// Build an entry from a key set, an algorithm policy, and a pairwise salt.
    #[must_use]
    pub fn new(keyset: KeySet, policy: SigningPolicy, salt: PairwiseSalt) -> Self {
        Self {
            keyset,
            policy,
            salt,
        }
    }

    /// The environment's key set.
    #[must_use]
    pub fn keyset(&self) -> &KeySet {
        &self.keyset
    }

    /// The environment's algorithm policy.
    #[must_use]
    pub fn policy(&self) -> &SigningPolicy {
        &self.policy
    }

    /// The environment's pairwise salt.
    #[must_use]
    pub fn salt(&self) -> &PairwiseSalt {
        &self.salt
    }

    /// The active signer at `now` under the environment's policy, if any.
    #[must_use]
    pub fn signer(&self, now: SystemTime) -> Option<&SigningKey> {
        self.keyset.signer_for_policy(now, &self.policy)
    }
}

/// The registry of per-environment issuers.
///
/// Keyed by [`EnvironmentId`]; every lookup is by environment, so an entry can
/// never be reached for the wrong tenant/environment pair. Build it at
/// composition time from the persisted keys and policies.
pub struct IssuerRegistry {
    issuer_base: String,
    cache: JwksCacheWindow,
    entries: HashMap<EnvironmentId, IssuerEntry>,
}

impl IssuerRegistry {
    /// An empty registry over `issuer_base` (the deployment's externally visible
    /// base URL) with the given JWKS cache window.
    #[must_use]
    pub fn new(issuer_base: impl Into<String>, cache: JwksCacheWindow) -> Self {
        Self {
            issuer_base: issuer_base.into(),
            cache,
            entries: HashMap::new(),
        }
    }

    /// Register an environment's issuer entry.
    pub fn insert(&mut self, environment: EnvironmentId, entry: IssuerEntry) {
        self.entries.insert(environment, entry);
    }

    /// The JWKS cache window.
    #[must_use]
    pub fn cache(&self) -> JwksCacheWindow {
        self.cache
    }

    /// The entry for `environment`, if registered.
    #[must_use]
    pub fn entry(&self, environment: &EnvironmentId) -> Option<&IssuerEntry> {
        self.entries.get(environment)
    }

    /// The per-environment issuer string for `scope`. Two environments never share
    /// an issuer.
    #[must_use]
    pub fn issuer_for(&self, scope: &Scope) -> String {
        format!(
            "{}/t/{}/e/{}",
            self.issuer_base.trim_end_matches('/'),
            scope.tenant(),
            scope.environment()
        )
    }

    /// The `jwks_uri` for `scope`.
    #[must_use]
    pub fn jwks_uri_for(&self, scope: &Scope) -> String {
        format!("{}/jwks.json", self.issuer_for(scope))
    }

    /// The published JWKS JSON for `scope`'s environment at `now`, filtered by the
    /// environment's policy. `None` if the environment is not registered.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError`] if a published key's public projection cannot be formed.
    #[must_use]
    pub fn jwks_json(
        &self,
        scope: &Scope,
        now: SystemTime,
    ) -> Option<Result<String, SigningKeyError>> {
        let entry = self.entry(&scope.environment())?;
        Some(
            entry
                .keyset
                .published_jwks(now, &entry.policy)
                .and_then(|jwks| jwks.to_json()),
        )
    }

    /// The OIDC discovery document JSON for `scope` at `now`. `None` if the
    /// environment is not registered.
    #[must_use]
    pub fn discovery_json(&self, scope: &Scope, now: SystemTime) -> Option<String> {
        let entry = self.entry(&scope.environment())?;
        let issuer = self.issuer_for(scope);
        let base = self.issuer_base.trim_end_matches('/');

        // The algorithms this issuer will SIGN id tokens with are the policy's,
        // in preference order. The retained RS256 downgrade key may still be
        // PUBLISHED without being advertised as a signing option, unless the
        // policy also permits it.
        let signing_algs: Vec<&str> = entry
            .policy
            .allowed()
            .iter()
            .map(|alg| alg.as_jose_name())
            .collect();

        let published = entry.keyset.published_kids(now, &entry.policy);
        let published_algs: Vec<JwsAlgorithm> = entry
            .keyset
            .published_jwks(now, &entry.policy)
            .ok()
            .map(|jwks| {
                jwks.keys()
                    .iter()
                    .filter_map(|jwk| jwk.alg().and_then(JwsAlgorithm::from_jose_name))
                    .collect()
            })
            .unwrap_or_default();

        let document = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": self.jwks_uri_for(scope),
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": signing_algs,
            "code_challenge_methods_supported": ["S256"],
            // A diagnostic aid: whether the zero-friction RS256 downgrade key is
            // present in the published JWKS (the covenant), even if the policy no
            // longer signs with it.
            "ironauth_downgrade_key_published": includes_downgrade_key(&published_algs),
            "ironauth_published_kids": published,
        });
        Some(document.to_string())
    }
}

/// Reconstruct a live [`SigningKey`] from a persisted [`SigningKeyRecord`].
///
/// The record's `id` becomes the key's `kid`, and `material_kind` selects the
/// loader. This is the one place stored key bytes re-enter the signing core.
///
/// # Errors
///
/// [`IssuerError::UnknownAlgorithm`] if the record's algorithm name is not a
/// known JOSE algorithm; [`IssuerError::MaterialMismatch`] if the material kind
/// does not match the algorithm family; [`IssuerError::KeyMaterial`] if the
/// signing core rejects the material.
pub fn load_signing_key(record: &SigningKeyRecord) -> Result<SigningKey, IssuerError> {
    let kid = Some(record.id.to_string());
    let algorithm =
        JwsAlgorithm::from_jose_name(&record.algorithm).ok_or(IssuerError::UnknownAlgorithm)?;
    let material = record.material.expose();
    let key = match (record.material_kind, algorithm) {
        (SigningKeyMaterialKind::Ed25519Seed, JwsAlgorithm::EdDsa) => {
            SigningKey::ed25519_from_seed(kid, material)
        }
        (SigningKeyMaterialKind::EcdsaPkcs8, JwsAlgorithm::Es256) => {
            SigningKey::ecdsa_p256_from_pkcs8(kid, material)
        }
        (SigningKeyMaterialKind::EcdsaPkcs8, JwsAlgorithm::Es384) => {
            SigningKey::ecdsa_p384_from_pkcs8(kid, material)
        }
        (SigningKeyMaterialKind::RsaPkcs1Der, alg) if alg.key_family() == KeyFamily::Rsa => {
            SigningKey::rsa_from_pkcs1_der(kid, alg, material)
        }
        _ => return Err(IssuerError::MaterialMismatch),
    };
    key.map_err(IssuerError::KeyMaterial)
}

/// Why loading a persisted signing key failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum IssuerError {
    /// The stored algorithm name is not a known JOSE algorithm.
    UnknownAlgorithm,
    /// The stored material kind does not match the algorithm family.
    MaterialMismatch,
    /// The signing core rejected the stored key material.
    KeyMaterial(SigningKeyError),
}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerError::UnknownAlgorithm => f.write_str("stored signing key algorithm is unknown"),
            IssuerError::MaterialMismatch => {
                f.write_str("stored signing key material kind does not match its algorithm")
            }
            IssuerError::KeyMaterial(err) => {
                write!(f, "stored signing key material rejected: {err}")
            }
        }
    }
}

impl std::error::Error for IssuerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IssuerError::KeyMaterial(err) => Some(err),
            _ => None,
        }
    }
}
