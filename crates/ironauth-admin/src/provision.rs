// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provisioning an environment's day-one signing keys (issues #42, #93).
//!
//! Creating an environment provisions its signing keys in the same transaction,
//! so a fresh environment serves discovery with its own issuer and a disjoint JWKS
//! immediately (the per-environment issuer machinery from M2, issue #19). The keys
//! are the environment's IDENTITY (classified environment-identity, issue #41), so
//! they are never copied into another environment by a promotion.
//!
//! Every environment provisions ALL THREE JWKS signing algorithms from day one
//! (issue #93): `EdDSA` (IronAuth's default), `ES256`, and `RS256`. Provisioning
//! all three at creation is what makes the compatibility wizard's per-algorithm
//! recommendations actually SIGNABLE: an environment can mint an `RS256` (or
//! `ES256`) token the moment a relying party needs it, with no lazy provisioning
//! on the serving path. `EdDSA` stays the DEFAULT signer (the issuer's canonical
//! preference order pins it); the other two are published, active, and selectable
//! per algorithm.
//!
//! Each key is generated here, in the management API (which owns the entropy seam),
//! and the store persists its private material verbatim, exactly as the manual
//! signing-key provision path does:
//!
//! - `EdDSA`: a 32-byte Ed25519 seed drawn from the entropy seam.
//! - `ES256`: an ECDSA P-256 key generated with `RustCrypto` `p256` (seeded off the
//!   entropy seam through the `ChaCha20` bridge) and exported to PKCS#8 DER.
//! - `RS256`: a 2048-bit RSA key generated with `RustCrypto` `rsa` (seeded the same
//!   way) and exported to PKCS#1 DER.
//!
//! Generation is deterministic under a fixed test entropy source, so a day-one key
//! set (and every token it signs, and the published JWKS) is reproducible in tests.
//! Signing and verification stay entirely on `ring`: the generated material is
//! loaded and signed only through the issuer's `ring`-backed loader.

use ironauth_env::Env;
use ironauth_store::{NewSigningKey, Scope, SigningKeyId, SigningKeyMaterialKind};

/// The length of an Ed25519 private seed.
const ED25519_SEED_BYTES: usize = 32;

/// One freshly generated day-one signing key: its `sik_` identifier (also the JOSE
/// `kid`), its algorithm and material encoding, and its private key material. The
/// material is secret; this type deliberately has NO `Debug`, so it can never reach
/// a log line.
struct DayOneKey {
    id: SigningKeyId,
    algorithm: &'static str,
    material_kind: SigningKeyMaterialKind,
    material: Vec<u8>,
}

impl DayOneKey {
    /// Borrow this key as a [`NewSigningKey`] to provision, live (published and
    /// active) from `activate_at_micros`.
    fn as_new(&self, activate_at_micros: i64) -> NewSigningKey<'_> {
        NewSigningKey {
            id: &self.id,
            algorithm: self.algorithm,
            material_kind: self.material_kind,
            material: &self.material,
            publish_at_micros: activate_at_micros,
            activate_at_micros,
            retire_at_micros: None,
            expire_at_micros: None,
        }
    }
}

/// The full set of an environment's day-one signing keys: one per JWKS algorithm
/// (`EdDSA`, `ES256`, `RS256`), each its own `sik_` key with its own material. No
/// `Debug` (each member holds secret key material).
pub struct DayOneSigningKeys {
    keys: Vec<DayOneKey>,
}

/// Why generating a day-one signing key set failed. Only asymmetric key GENERATION
/// (ES256/RS256) can fail; the Ed25519 seed draw cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionError {
    /// Fresh ES256 or RS256 key generation (or its DER export) failed.
    KeyGeneration,
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionError::KeyGeneration => f.write_str("day-one signing key generation failed"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl DayOneSigningKeys {
    /// Generate the full day-one key set for `scope`: an `EdDSA`, an `ES256`, and
    /// an `RS256` key, each with its own identifier minted under `scope` (so each
    /// is in scope by construction) and its own private material drawn from the
    /// environment's entropy seam.
    ///
    /// The keys are generated in a FIXED order (`EdDSA`, then `ES256`, then
    /// `RS256`), each drawing from the seam in turn, so the whole set is reproducible
    /// under a fixed test entropy source.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::KeyGeneration`] if the `ES256` or `RS256` key generation
    /// fails (it does not in practice; surfaced for completeness).
    pub fn generate(env: &Env, scope: &Scope) -> Result<Self, ProvisionError> {
        // EdDSA (the default signer): a raw 32-byte Ed25519 seed off the seam.
        let eddsa_id = SigningKeyId::generate(env, scope);
        let mut seed = [0_u8; ED25519_SEED_BYTES];
        env.entropy().fill_bytes(&mut seed);
        let eddsa = DayOneKey {
            id: eddsa_id,
            algorithm: "EdDSA",
            material_kind: SigningKeyMaterialKind::Ed25519Seed,
            material: seed.to_vec(),
        };

        // ES256: a P-256 PKCS#8 DER, generated off the seam, loaded/signed via ring.
        let es256_id = SigningKeyId::generate(env, scope);
        let es256_der = ironauth_jose::generate_ecdsa_p256_pkcs8_der(env.entropy())
            .map_err(|_| ProvisionError::KeyGeneration)?;
        let es256 = DayOneKey {
            id: es256_id,
            algorithm: "ES256",
            material_kind: SigningKeyMaterialKind::EcdsaPkcs8,
            material: es256_der,
        };

        // RS256: a 2048-bit RSA PKCS#1 DER, generated off the seam, loaded/signed
        // via ring.
        let rs256_id = SigningKeyId::generate(env, scope);
        let rs256_der = ironauth_jose::generate_rsa_pkcs1_der(env.entropy())
            .map_err(|_| ProvisionError::KeyGeneration)?;
        let rs256 = DayOneKey {
            id: rs256_id,
            algorithm: "RS256",
            material_kind: SigningKeyMaterialKind::RsaPkcs1Der,
            material: rs256_der,
        };

        Ok(Self {
            keys: vec![eddsa, es256, rs256],
        })
    }

    /// Borrow the whole set as [`NewSigningKey`] rows to provision, each live
    /// (published and active) from `activate_at_micros` (the environment's creation
    /// instant), so all three sign and appear in the JWKS the moment the environment
    /// exists. The order is `EdDSA`, `ES256`, `RS256`.
    #[must_use]
    pub fn as_new(&self, activate_at_micros: i64) -> Vec<NewSigningKey<'_>> {
        self.keys
            .iter()
            .map(|key| key.as_new(activate_at_micros))
            .collect()
    }
}
