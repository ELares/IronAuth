// SPDX-License-Identifier: MIT OR Apache-2.0

//! A polymorphic signing-key store, scoped per environment.
//!
//! Keys live under an environment key `E`, mirroring the persistence layer's
//! tenant-and-environment isolation substrate (`crates/ironauth-store`). The
//! store is generic over `E` ON PURPOSE: the crypto core must not depend on the
//! persistence stack (and its database driver) just to name an environment, so a
//! caller at the composition layer instantiates
//! `EnvironmentKeyStore<ironauth_store::EnvironmentId>` while this crate stays
//! lean. Any `Eq + Hash` key works, so tests can scope by a simple string.
//!
//! The store holds [`SigningKey`] values, which are always asymmetric. There is
//! no HMAC key type, so `signer_for_alg` is keyed by [`JwsAlgorithm`] (which has
//! no `HS*` member): an environment or tenant default can never be a MAC
//! algorithm. Restricted `HS*` signing lives entirely in
//! [`crate::ClientSecretContext`], keyed from a client secret, never from here.
//!
//! It is "polymorphic" in both axes the issue asks for: over the environment key
//! type, and over the [`SigningKey`] key type (Ed25519, ECDSA, RSA today, and
//! whatever `#[non_exhaustive]` future variants are added), so new key types drop
//! in without changing the store.

use std::collections::HashMap;
use std::hash::Hash;

use crate::jwks::JwkSet;
use crate::policy::JwsAlgorithm;
use crate::signing_key::{SigningKey, SigningKeyError};

/// An environment-scoped set of signing keys.
///
/// Construct it, insert one or more [`SigningKey`] per environment, then select a
/// signer by algorithm (the environment/tenant default path) or by `kid` (the
/// rotation-selection path), and publish the public half with
/// [`EnvironmentKeyStore::public_jwks`].
pub struct EnvironmentKeyStore<E> {
    keys: HashMap<E, Vec<SigningKey>>,
}

impl<E> EnvironmentKeyStore<E>
where
    E: Eq + Hash,
{
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a signing key to an environment.
    ///
    /// Keys are appended, so an environment can hold several (for example one per
    /// published algorithm, or several of one algorithm during a rotation). The
    /// caller MUST give each key in an environment a set-unique, present `kid`:
    /// the published JWKS and `kid`-based selection are ambiguous otherwise (an
    /// availability concern; see [`crate::JwkSet::from_signing_keys`]).
    pub fn insert(&mut self, environment: E, key: SigningKey) {
        self.keys.entry(environment).or_default().push(key);
    }

    /// The first key in `environment` whose declared algorithm is `algorithm`.
    ///
    /// This is the default-signer lookup: an environment or client configured to
    /// sign with, say, `RS256` resolves the already-provisioned `RS256` key with
    /// no key generation.
    ///
    /// It selects a STABLE key (the first inserted for the algorithm), so during
    /// a same-algorithm rotation a newly inserted key does not automatically
    /// become the alg-default until the old one is removed. Until an active-key
    /// marker lands (rotation-milestone work, out of scope here), select the new
    /// key explicitly by `kid` via [`EnvironmentKeyStore::signer_for_kid`].
    #[must_use]
    pub fn signer_for_alg(&self, environment: &E, algorithm: JwsAlgorithm) -> Option<&SigningKey> {
        self.keys_for(environment)
            .iter()
            .find(|key| key.algorithm() == algorithm)
    }

    /// The key in `environment` answering to `kid`.
    #[must_use]
    pub fn signer_for_kid(&self, environment: &E, kid: &str) -> Option<&SigningKey> {
        self.keys_for(environment)
            .iter()
            .find(|key| key.kid() == Some(kid))
    }

    /// All signing keys in `environment` (empty if the environment is unknown).
    #[must_use]
    pub fn keys_for(&self, environment: &E) -> &[SigningKey] {
        self.keys.get(environment).map_or(&[], Vec::as_slice)
    }

    /// The algorithms `environment` can sign with, in insertion order.
    ///
    /// Every element is a [`JwsAlgorithm`], so by type this list can never
    /// contain a MAC algorithm.
    #[must_use]
    pub fn published_algorithms(&self, environment: &E) -> Vec<JwsAlgorithm> {
        self.keys_for(environment)
            .iter()
            .map(SigningKey::algorithm)
            .collect()
    }

    /// The public JWK Set for `environment`, ready to publish at `jwks_uri`.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError::MalformedPublicKey`] if any key's public projection
    /// cannot be formed, indicating corrupt key material.
    pub fn public_jwks(&self, environment: &E) -> Result<JwkSet, SigningKeyError> {
        JwkSet::from_signing_keys(self.keys_for(environment))
    }
}

impl<E> Default for EnvironmentKeyStore<E>
where
    E: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<E> std::fmt::Debug for EnvironmentKeyStore<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render environment keys or key material: only shape counts.
        let total: usize = self.keys.values().map(Vec::len).sum();
        f.debug_struct("EnvironmentKeyStore")
            .field("environments", &self.keys.len())
            .field("keys", &total)
            .finish()
    }
}
