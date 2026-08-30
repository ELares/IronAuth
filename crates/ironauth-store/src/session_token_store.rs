// SPDX-License-Identifier: MIT OR Apache-2.0

//! The persistence types for SESSION TOKENIZER templates (issue #119).
//!
//! A template converts a valid opaque DB-backed session into a short-lived JWT. It carries an
//! audience, a TTL, a claims mapper, and its OWN Ed25519 key, published at its own JWKS URL so
//! the token verifies with no database call.
//!
//! # What this module does NOT do
//!
//! It does not know what a mapping rule is. The `rules` document travels through here as an
//! opaque JSON string, exactly as `claims_mappings.rules` does, because `ironauth-store` cannot
//! depend on `ironauth-oidc` and a rule shape defined here would be a SECOND definition of one
//! wire format. `ironauth_oidc::claims_mapping` owns the shape and the validator; the write path
//! validates against it before anything reaches this layer.

use std::fmt;

use crate::id::SessionTokenKeyId;

/// The JOSE algorithm every tokenizer template signs with.
///
/// One value, matching the table CHECK. See migration 0173 for why a template's key set admits
/// one algorithm where every other signing surface admits four: the template, its key, its
/// audience and its consumers are configured by one operator at one time, so there is no foreign
/// verifier whose requirements IronAuth does not get to choose.
pub const SESSION_TOKEN_ALGORITHM: &str = "EdDSA";

/// The stored `material_kind` of every tokenizer template key.
pub const SESSION_TOKEN_MATERIAL_KIND: &str = "ed25519_seed";

/// The length of an Ed25519 seed, which the table also CHECKs.
pub const SESSION_TOKEN_SEED_LEN: usize = 32;

/// A tokenizer template as stored, without its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTokenTemplateRecord {
    /// The name a tokenize request selects this template by.
    pub name: String,
    /// The `aud` every token minted from this template carries.
    pub audience: String,
    /// How long a minted token lives, in seconds. Also the exact width of the window in which a
    /// revoked session's already-minted token still verifies.
    pub ttl_seconds: i32,
    /// The claims mapper, as the JSON encoding of `Vec<MappingRule>`. Opaque here.
    pub rules_json: String,
}

/// A tokenizer template to write, with the key minted alongside it.
#[derive(Clone, Copy)]
pub struct NewSessionTokenTemplate<'a> {
    /// The template name.
    pub name: &'a str,
    /// The audience.
    pub audience: &'a str,
    /// The token lifetime in seconds.
    pub ttl_seconds: i32,
    /// The claims mapper document, ALREADY VALIDATED by the caller against
    /// `ironauth_oidc::claims_mapping::validate`.
    pub rules_json: &'a str,
}

impl fmt::Debug for NewSessionTokenTemplate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The rules document is not rendered. A refused document is precisely the thing not to
        // copy onto a log line, and an accepted one is operator configuration rather than
        // debugging output.
        f.debug_struct("NewSessionTokenTemplate")
            .field("name", &self.name)
            .field("audience", &self.audience)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

/// The Ed25519 seed of a template key, wrapped so it never prints or logs.
///
/// The same treatment `SigningKeyMaterial` gives an issuer key, for the same reason and with the
/// same single exposure point.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTokenKeyMaterial(Vec<u8>);

impl SessionTokenKeyMaterial {
    /// Wrap raw seed bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw seed, for reconstructing a signing key.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SessionTokenKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTokenKeyMaterial")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// One template key read back, always within scope.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTokenKeyRecord {
    /// The `stk_` identifier, which is also the JOSE `kid`.
    pub id: SessionTokenKeyId,
    /// The Ed25519 seed.
    pub material: SessionTokenKeyMaterial,
    /// When the key first appears in the template's JWKS, in epoch microseconds.
    pub publish_at_unix_micros: i64,
    /// When the key first signs, in epoch microseconds.
    pub activate_at_unix_micros: i64,
    /// When a successor took over, in epoch microseconds (absent while head).
    pub retire_at_unix_micros: Option<i64>,
    /// When the key is withdrawn from the JWKS, in epoch microseconds (absent while not
    /// retired).
    pub expire_at_unix_micros: Option<i64>,
}

impl fmt::Debug for SessionTokenKeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTokenKeyRecord")
            .field("id", &self.id)
            .field("publish_at_unix_micros", &self.publish_at_unix_micros)
            .field("activate_at_unix_micros", &self.activate_at_unix_micros)
            .field("retire_at_unix_micros", &self.retire_at_unix_micros)
            .field("expire_at_unix_micros", &self.expire_at_unix_micros)
            .finish_non_exhaustive()
    }
}

/// A template key to write. The lifecycle instants are epoch microseconds from the application
/// clock seam, never the database clock.
#[derive(Clone, Copy)]
pub struct NewSessionTokenKey<'a> {
    /// The `stk_` identifier, minted under this scope.
    pub id: &'a SessionTokenKeyId,
    /// The Ed25519 seed.
    pub seed: &'a [u8],
    /// When the key first appears in the template's JWKS.
    pub publish_at_micros: i64,
    /// When the key first signs.
    pub activate_at_micros: i64,
}

impl fmt::Debug for NewSessionTokenKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSessionTokenKey")
            .field("id", &self.id)
            .field("publish_at_micros", &self.publish_at_micros)
            .field("activate_at_micros", &self.activate_at_micros)
            .finish_non_exhaustive()
    }
}
