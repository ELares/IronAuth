// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provisioning an environment's day-one signing key (issue #42).
//!
//! Creating an environment provisions its own signing key in the same
//! transaction, so a fresh environment serves discovery with its own issuer and a
//! disjoint JWKS immediately (the per-environment issuer machinery from M2, issue
//! #19). The key is the environment's IDENTITY (classified environment-identity,
//! issue #41), so it is never copied into another environment by a promotion.
//!
//! The default day-one key is `EdDSA` over Ed25519 (IronAuth's default algorithm):
//! a 32-byte seed drawn from the entropy seam. Generation lives in the management
//! API (which owns the entropy seam), and the store persists the seed verbatim,
//! exactly as the manual signing-key provision path does.

use ironauth_env::Env;
use ironauth_store::{NewSigningKey, Scope, SigningKeyId, SigningKeyMaterialKind};

/// A freshly generated day-one signing key: its `sik_` identifier (also the JOSE
/// `kid`) and its private Ed25519 seed. The seed is secret key material; this type
/// deliberately has no `Debug`, so it can never reach a log line.
pub struct DayOneSigningKey {
    id: SigningKeyId,
    seed: [u8; ED25519_SEED_BYTES],
}

/// The length of an Ed25519 private seed.
const ED25519_SEED_BYTES: usize = 32;

impl DayOneSigningKey {
    /// Generate an `EdDSA` day-one key for `scope`, drawing both the identifier and
    /// the seed from the environment's entropy seam. The identifier is minted under
    /// `scope`, so it is in scope by construction.
    #[must_use]
    pub fn generate(env: &Env, scope: &Scope) -> Self {
        let id = SigningKeyId::generate(env, scope);
        let mut seed = [0_u8; ED25519_SEED_BYTES];
        env.entropy().fill_bytes(&mut seed);
        Self { id, seed }
    }

    /// Borrow this key as a [`NewSigningKey`] to provision, live (published and
    /// active) from `activate_at_micros` (the environment's creation instant), so
    /// it signs and appears in the JWKS the moment the environment exists.
    #[must_use]
    pub fn as_new(&self, activate_at_micros: i64) -> NewSigningKey<'_> {
        NewSigningKey {
            id: &self.id,
            algorithm: "EdDSA",
            material_kind: SigningKeyMaterialKind::Ed25519Seed,
            material: &self.seed,
            publish_at_micros: activate_at_micros,
            activate_at_micros,
            retire_at_micros: None,
            expire_at_micros: None,
        }
    }
}
