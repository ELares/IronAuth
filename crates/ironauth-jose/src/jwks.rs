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

use crate::policy::TrustedKey;
use crate::signing_key::{PublicComponents, SigningKey, SigningKeyError};

/// A single public JSON Web Key.
///
/// Held as its raw JSON object so the exact RFC members (`kty`, `crv`, `x`, `y`,
/// `n`, `e`, `use`, `alg`, `kid`) round-trip verbatim. Serializes as that object.
#[derive(Clone, Debug, Serialize)]
pub struct Jwk(Map<String, Value>);

impl Jwk {
    /// Wrap a raw JSON object as a [`Jwk`], for a JWK read from somewhere other
    /// than a [`SigningKey`] (an inbound JWKS entry, or the `jwk` protected
    /// header of a `DPoP` proof). No validation happens here; the accessors and the
    /// [`trusted_key_from_jwk`] mapping do the checking.
    pub(crate) fn from_object(object: Map<String, Value>) -> Self {
        Self(object)
    }

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

/// Parse an inbound JWK Set document into the trusted keys it names.
///
/// This is the INBOUND counterpart of the outbound [`JwkSet`] builder: it turns a
/// relying party's or client's published `{"keys":[...]}` document (fetched from a
/// `jwks_uri` through the SSRF-hardened fetcher, or supplied inline) into
/// [`TrustedKey`]s a [`VerificationPolicy`](crate::VerificationPolicy) can trust to
/// verify a client assertion (RFC 7523, OIDC Core `private_key_jwt`).
///
/// It is deliberately CONSERVATIVE, so an inbound document can never smuggle in a
/// trust it should not have:
///
/// - a JWK whose `kty`/`crv` this core cannot represent (an `OKP` that is not
///   `Ed25519`, an `EC` `P-521` key, which is the excluded ES512 family, or any
///   other type) is SKIPPED, never trusted;
/// - a JWK whose material is malformed (a bad base64url member, a wrong-length
///   coordinate, an RSA modulus below the 2048-bit floor) is SKIPPED, since the
///   [`TrustedKey`] constructor refuses it;
/// - a malformed document (not JSON, or with no `keys` array) yields an EMPTY set.
///
/// An empty result is a fail-closed outcome for the caller: a policy cannot be
/// built without at least one trusted key, so a document that names no usable key
/// verifies nothing. Only the PUBLIC members (`kty`, `crv`, `x`, `y`, `n`, `e`,
/// `kid`) are read; nothing in the document selects an algorithm or reaches trust
/// beyond producing a candidate public key.
#[must_use]
pub fn trusted_keys_from_jwks(json: &[u8]) -> Vec<TrustedKey> {
    let Ok(value) = serde_json::from_slice::<Value>(json) else {
        return Vec::new();
    };
    let Some(keys) = value.get("keys").and_then(Value::as_array) else {
        return Vec::new();
    };
    keys.iter()
        .filter_map(Value::as_object)
        .filter_map(|object| trusted_key_from_jwk(&Jwk::from_object(object.clone())))
        .collect()
}

/// Turn one [`Jwk`] into a [`TrustedKey`], or [`None`] for a type, curve, or
/// material this core cannot represent (so it is never trusted).
///
/// This is the ONE JWK to verifying-key mapping shared by the inbound JWKS parser
/// ([`trusted_keys_from_jwks`]) and the `DPoP` proof path
/// (`crate::dpop::validate_dpop_proof`), so a key admitted by one path is admitted
/// by the other under identical rules.
pub(crate) fn trusted_key_from_jwk(jwk: &Jwk) -> Option<TrustedKey> {
    let kid = jwk.kid().map(str::to_owned);
    match jwk.kty()? {
        "OKP" => {
            // Only Ed25519 among OKP curves; Ed448/X25519/X448 are not represented.
            if jwk.get("crv").and_then(Value::as_str)? != "Ed25519" {
                return None;
            }
            let x = jwk_b64(jwk, "x")?;
            TrustedKey::ed25519(kid, &x).ok()
        }
        "EC" => {
            let x = jwk_b64(jwk, "x")?;
            let y = jwk_b64(jwk, "y")?;
            match jwk.get("crv").and_then(Value::as_str)? {
                "P-256" => TrustedKey::ecdsa_p256(kid, &x, &y).ok(),
                "P-384" => TrustedKey::ecdsa_p384(kid, &x, &y).ok(),
                // P-521 is the ES512 family, excluded in M1; any other curve is
                // likewise unrepresented. Never trusted.
                _ => None,
            }
        }
        "RSA" => {
            let n = jwk_b64(jwk, "n")?;
            let e = jwk_b64(jwk, "e")?;
            TrustedKey::rsa(kid, &n, &e).ok()
        }
        // oct (symmetric) and every unknown type are never a verify key here.
        _ => None,
    }
}

/// Read and base64url-decode a JWK member, or [`None`] if absent or malformed.
fn jwk_b64(jwk: &Jwk, member: &str) -> Option<Vec<u8>> {
    let encoded = jwk.get(member)?.as_str()?;
    URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_published_jwk_set_round_trips_back_into_trusted_keys() {
        // Build the public JWK for an Ed25519 signing key from a fixed seed,
        // serialize the set, and prove the inbound parser recovers a usable trusted
        // key with the same kid (the material verification will trust).
        use crate::signing_key::SigningKey;

        let seed = [7_u8; 32];
        let ed = SigningKey::ed25519_from_seed(Some("ed".to_owned()), &seed).expect("ed25519");
        let set = JwkSet::from_signing_keys([&ed]).expect("jwk set");
        let json = set.to_json().expect("json");

        let keys = trusted_keys_from_jwks(json.as_bytes());
        assert_eq!(keys.len(), 1, "the one published key parses back");
        assert_eq!(keys[0].kid(), Some("ed"));
    }

    #[test]
    fn unsupported_types_and_curves_and_malformed_entries_are_skipped() {
        // A P-521 EC key (the excluded ES512 family), an oct (symmetric) key, and a
        // structurally broken EC key are all skipped; a good Ed25519 remains.
        let json = br#"{"keys":[
            {"kty":"EC","crv":"P-521","x":"AA","y":"AA","kid":"es512"},
            {"kty":"oct","k":"AAAA","kid":"sym"},
            {"kty":"EC","crv":"P-256","x":"!!bad!!","y":"AA","kid":"broken"},
            {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"ok"}
        ]}"#;
        let keys = trusted_keys_from_jwks(json);
        assert_eq!(keys.len(), 1, "only the Ed25519 key is usable");
        assert_eq!(keys[0].kid(), Some("ok"));
    }

    #[test]
    fn a_malformed_document_yields_no_keys_fail_closed() {
        assert!(trusted_keys_from_jwks(b"not json").is_empty());
        assert!(trusted_keys_from_jwks(b"{}").is_empty());
        assert!(trusted_keys_from_jwks(br#"{"keys":"nope"}"#).is_empty());
    }
}
