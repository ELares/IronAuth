// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public JWK Set builder (RFC 7517, RFC 7518, RFC 8037).
//!
//! A [`JwkSet`] is the public half of an environment's signing keys, ready to
//! publish at `jwks_uri`. Because a fresh environment holds an Ed25519, an
//! ECDSA P-256, and an RSA key from day one (see [`crate::EnvironmentKeyStore`]),
//! their public JWKs are all published from the start: switching a client from
//! `EdDSA` to `RS256` is then a configuration flip that takes effect on the next
//! mint, with no key generation and no JWKS propagation delay.
//!
//! Only PUBLIC key material is ever emitted here. The values come from
//! [`SigningKey`]'s public projection; the private material never leaves the
//! key.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::signing_key::{PublicComponents, SigningKey, SigningKeyError};

/// A single public JSON Web Key.
///
/// Held as its raw JSON object so the exact RFC members (`kty`, `crv`, `x`, `y`,
/// `n`, `e`, `use`, `alg`, `kid`) round-trip verbatim. Serializes as that object.
#[derive(Clone, Debug, Serialize)]
pub struct Jwk(Map<String, Value>);

impl Jwk {
    /// Build the public JWK for a signing key.
    fn from_signing_key(key: &SigningKey) -> Result<Self, SigningKeyError> {
        let mut jwk = Map::new();
        jwk.insert("use".to_owned(), Value::String("sig".to_owned()));
        jwk.insert(
            "alg".to_owned(),
            Value::String(key.algorithm().as_jose_name().to_owned()),
        );
        if let Some(kid) = key.kid() {
            jwk.insert("kid".to_owned(), Value::String(kid.to_owned()));
        }
        match key.public_components()? {
            PublicComponents::Okp { x } => {
                jwk.insert("kty".to_owned(), Value::String("OKP".to_owned()));
                jwk.insert("crv".to_owned(), Value::String("Ed25519".to_owned()));
                jwk.insert("x".to_owned(), b64(&x));
            }
            PublicComponents::Ec { crv, x, y } => {
                jwk.insert("kty".to_owned(), Value::String("EC".to_owned()));
                jwk.insert("crv".to_owned(), Value::String(crv.to_owned()));
                jwk.insert("x".to_owned(), b64(&x));
                jwk.insert("y".to_owned(), b64(&y));
            }
            PublicComponents::Rsa { n, e } => {
                jwk.insert("kty".to_owned(), Value::String("RSA".to_owned()));
                jwk.insert("n".to_owned(), b64(&n));
                jwk.insert("e".to_owned(), b64(&e));
            }
        }
        Ok(Self(jwk))
    }

    /// The `kid` member, if present.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.0.get("kid").and_then(Value::as_str)
    }

    /// The `kty` (key type) member.
    #[must_use]
    pub fn kty(&self) -> Option<&str> {
        self.0.get("kty").and_then(Value::as_str)
    }

    /// The `alg` member.
    #[must_use]
    pub fn alg(&self) -> Option<&str> {
        self.0.get("alg").and_then(Value::as_str)
    }

    /// A member by name, for reading `x`, `y`, `n`, `e`, `crv`, and the rest.
    #[must_use]
    pub fn get(&self, member: &str) -> Option<&Value> {
        self.0.get(member)
    }
}

/// A JWK Set: the public keys an environment publishes.
///
/// Serializes as the standard `{"keys":[...]}` document.
#[derive(Clone, Debug, Serialize)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Build a JWK Set from public projections of the given signing keys.
    ///
    /// The caller MUST supply keys with set-unique, present `kid`s: a `kid`
    /// selects among trusted keys on the verify side, so two keys sharing a
    /// `kid` (or both `None`) publish an ambiguous JWKS and make `kid`-based
    /// selection non-deterministic. This is an availability concern, not a
    /// forgery one, and it is the caller's responsibility until a `kid`
    /// derivation default lands (tracked as a separate follow-up).
    ///
    /// # Errors
    ///
    /// [`SigningKeyError::MalformedPublicKey`] if any key's public projection
    /// cannot be formed, indicating corrupt key material.
    pub fn from_signing_keys<'a, I>(keys: I) -> Result<Self, SigningKeyError>
    where
        I: IntoIterator<Item = &'a SigningKey>,
    {
        let keys = keys
            .into_iter()
            .map(Jwk::from_signing_key)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    /// The keys in the set.
    #[must_use]
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The number of keys in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Serialize the set to a JSON string.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError::MalformedPublicKey`] if serialization fails, which does
    /// not happen for well-formed JWK objects and is surfaced for completeness.
    pub fn to_json(&self) -> Result<String, SigningKeyError> {
        serde_json::to_string(self).map_err(|_| SigningKeyError::MalformedPublicKey)
    }
}

/// base64url-encode without padding, as JOSE requires for JWK members.
fn b64(bytes: &[u8]) -> Value {
    Value::String(URL_SAFE_NO_PAD.encode(bytes))
}
