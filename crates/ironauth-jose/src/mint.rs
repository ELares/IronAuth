// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one place a compact JWS is assembled and signed.
//!
//! [`sign_jws`] is the asymmetric mint: it builds the protected header from the
//! key's own algorithm and kid (never from caller-supplied trust), signs the
//! `header.payload` input through the private [`crate::sign`] primitive, and
//! returns the compact serialization. Every token IronAuth issues is expected to
//! round-trip through [`crate::verify`]; the header this module emits is exactly
//! what that verifier re-reads and matches against a policy, so signing respects
//! the same allowlist and the same exclusions (no `HS*`, no `none`, no embedded
//! key material) by construction.
//!
//! Symmetric `HS*` signing is separated into [`ClientSecretContext::sign_jws`]
//! and is reachable ONLY through one of the two client-secret contexts OIDC
//! permits. There is no HMAC signing key type and no way to place an `HS*`
//! algorithm into an environment key store, so a tenant or environment default
//! can never be `HS*`: the illegal state is unrepresentable, not merely
//! rejected.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use crate::redact::Redacted;
use crate::sign;
use crate::signing_key::SigningKey;
use crate::signing_policy::SigningPolicy;

/// Options that steer how a protected header is EMITTED (not what is trusted).
///
/// Defaults are the polymorphic, widely interoperable choices; the toggles exist
/// so a deployment can opt into stricter emission without a code change.
#[derive(Clone, Debug, Default)]
pub struct EmissionOptions {
    fully_specified: bool,
    typ: Option<String>,
}

impl EmissionOptions {
    /// The default emission: the polymorphic `alg` name (for example `EdDSA`)
    /// and no `typ`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit fully-specified algorithm names
    /// (draft-ietf-jose-fully-specified-algorithms): `EdDSA` becomes `Ed25519`.
    ///
    /// OFF by default. The rest of the matrix is already fully specified, so this
    /// changes only the `EdDSA` header. IronAuth's own verifier accepts `Ed25519`
    /// as an alias regardless, so a token minted either way still verifies here.
    ///
    /// Enabling it is an interop-NARROWING choice: a strict external verifier
    /// that only recognizes the polymorphic `EdDSA` name will reject a token
    /// spelled `Ed25519`. Leave it off unless every consumer is known to accept
    /// the fully-specified name.
    #[must_use]
    pub fn fully_specified(mut self, on: bool) -> Self {
        self.fully_specified = on;
        self
    }

    /// Set the `typ` header (for example `JWT`, `at+jwt`, `logout+jwt`).
    #[must_use]
    pub fn with_typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }

    /// The `alg` header name to emit for `algorithm` under these options.
    fn alg_name(&self, algorithm: crate::JwsAlgorithm) -> &'static str {
        if self.fully_specified {
            algorithm.fully_specified_name()
        } else {
            algorithm.as_jose_name()
        }
    }
}

/// Sign `payload` as a compact JWS using `key` and the key's own algorithm/kid.
///
/// The `payload` is the raw protected content (for a JWT, the serialized claims
/// bytes); this core signs bytes and does not impose a claim shape, which is a
/// separate token-format concern. On success the returned string is a compact
/// `header.payload.signature` serialization that [`crate::verify`] can check
/// against a policy trusting [`SigningKey::verifying_key`].
///
/// # Errors
///
/// [`SignError::Backend`] if the `ring` signing operation fails, or
/// [`SignError::Header`] if the protected header cannot be serialized (which
/// does not happen for the fixed header shape and is surfaced for completeness).
pub fn sign_jws(
    key: &SigningKey,
    payload: &[u8],
    options: &EmissionOptions,
) -> Result<String, SignError> {
    let alg_name = options.alg_name(key.algorithm());
    let header = build_header(alg_name, key.kid(), options.typ.as_deref())?;
    let signing_input = signing_input(&header, payload);
    let signature =
        sign::sign_asymmetric(key, signing_input.as_bytes()).map_err(|()| SignError::Backend)?;
    Ok(assemble(&signing_input, &signature))
}

/// Sign `payload` as a compact JWS, but only if `key`'s algorithm is permitted by
/// `policy`.
///
/// This is the mint-side enforcement of an environment's [`SigningPolicy`]: an
/// `ES256`-only environment can never emit an `EdDSA`-signed token, because a key
/// whose algorithm the policy does not permit is refused BEFORE any signing
/// happens. Selecting the signer is the caller's job; this closes the gap where a
/// wrong-algorithm key is somehow reached.
///
/// # Errors
///
/// [`SignError::AlgorithmNotPermitted`] if `policy` does not permit `key`'s
/// algorithm; otherwise the same errors as [`sign_jws`].
pub fn sign_jws_with_policy(
    policy: &SigningPolicy,
    key: &SigningKey,
    payload: &[u8],
    options: &EmissionOptions,
) -> Result<String, SignError> {
    if !policy.permits(key.algorithm()) {
        return Err(SignError::AlgorithmNotPermitted);
    }
    sign_jws(key, payload, options)
}

/// A JOSE MAC algorithm, usable ONLY for restricted client-secret signing.
///
/// There is deliberately no conversion from [`MacAlgorithm`] to the asymmetric
/// [`crate::JwsAlgorithm`] and no [`SigningKey`] variant for it, so an `HS*`
/// algorithm cannot flow into an environment or tenant default.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum MacAlgorithm {
    /// HMAC using SHA-256.
    Hs256,
    /// HMAC using SHA-384.
    Hs384,
    /// HMAC using SHA-512.
    Hs512,
}

impl MacAlgorithm {
    /// The JOSE `alg` name (RFC 7518) for this MAC algorithm.
    #[must_use]
    pub fn as_jose_name(self) -> &'static str {
        match self {
            MacAlgorithm::Hs256 => "HS256",
            MacAlgorithm::Hs384 => "HS384",
            MacAlgorithm::Hs512 => "HS512",
        }
    }
}

/// A client secret, wrapped so it never prints, logs, or serializes.
///
/// It is the HMAC key for the two restricted client-secret contexts and enters
/// signing only through [`ClientSecretContext::sign_jws`].
#[derive(Debug)]
pub struct ClientSecret(Redacted<Vec<u8>>);

impl ClientSecret {
    /// Wrap raw client-secret bytes (per OIDC Core 10.1, the UTF-8 bytes of the
    /// `client_secret` are the MAC key).
    #[must_use]
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self(Redacted::new(secret.into()))
    }
}

/// The two, and only two, contexts in which IronAuth signs with a client secret.
///
/// This enum is the type-level gate on `HS*` signing: HMAC signing is a method
/// ON this enum, so producing an `HS*` token structurally requires naming one of
/// these OIDC-sanctioned contexts. No other code path can reach symmetric
/// signing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ClientSecretContext {
    /// OIDC Core 10.1: an ID Token whose `id_token_signed_response_alg` is `HS*`,
    /// keyed from the registered `client_secret`.
    IdTokenHs,
    /// The `client_secret_jwt` client authentication method (a client assertion
    /// signed with the `client_secret` as the HMAC key).
    ClientSecretJwt,
}

impl ClientSecretContext {
    /// Sign `payload` as a compact JWS with `client_secret` under `mac`, in this
    /// client-secret context.
    ///
    /// The returned [`ClientSecretJws`] carries the context alongside the token
    /// so an audit or introspection layer can record which restricted context
    /// minted it. HMAC signing cannot fail, so this is infallible.
    #[must_use]
    pub fn sign_jws(
        self,
        mac: MacAlgorithm,
        client_secret: &ClientSecret,
        payload: &[u8],
        options: &EmissionOptions,
    ) -> ClientSecretJws {
        // A client-secret JWS is keyed by the shared secret, not by a published
        // kid, so no `kid` is emitted; `typ` is honored.
        let header = build_header(mac.as_jose_name(), None, options.typ.as_deref())
            .unwrap_or_else(|_| unreachable!("fixed HS header always serializes"));
        let signing_input = signing_input(&header, payload);
        let signature = sign::sign_hmac(mac, client_secret.0.expose(), signing_input.as_bytes());
        ClientSecretJws {
            context: self,
            compact: assemble(&signing_input, &signature),
        }
    }
}

/// A compact JWS minted in a client-secret context, tagged with that context.
#[derive(Clone, Debug)]
pub struct ClientSecretJws {
    context: ClientSecretContext,
    compact: String,
}

impl ClientSecretJws {
    /// The restricted context this token was minted in.
    #[must_use]
    pub fn context(&self) -> ClientSecretContext {
        self.context
    }

    /// The compact JWS serialization.
    #[must_use]
    pub fn compact(&self) -> &str {
        &self.compact
    }

    /// Consume the wrapper and return the compact serialization.
    #[must_use]
    pub fn into_compact(self) -> String {
        self.compact
    }
}

/// Build the protected-header JSON bytes for `alg_name`, with an optional `kid`
/// and `typ`. Keys serialize in a stable (sorted) order.
fn build_header(
    alg_name: &str,
    kid: Option<&str>,
    typ: Option<&str>,
) -> Result<Vec<u8>, SignError> {
    let mut map = Map::new();
    map.insert("alg".to_owned(), Value::String(alg_name.to_owned()));
    if let Some(kid) = kid {
        map.insert("kid".to_owned(), Value::String(kid.to_owned()));
    }
    if let Some(typ) = typ {
        map.insert("typ".to_owned(), Value::String(typ.to_owned()));
    }
    serde_json::to_vec(&Value::Object(map)).map_err(|_| SignError::Header)
}

/// The JWS signing input: `base64url(header) || '.' || base64url(payload)`.
fn signing_input(header: &[u8], payload: &[u8]) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

/// Assemble the compact serialization from the signing input and signature.
fn assemble(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// A failure to mint a token.
///
/// Signing is a server-side operation, not an attacker-facing surface, so unlike
/// the verify side's uniform error these name their cause.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SignError {
    /// The `ring` signing operation failed.
    Backend,
    /// The protected header could not be serialized.
    Header,
    /// The environment's signing policy does not permit this key's algorithm.
    AlgorithmNotPermitted,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignError::Backend => "signature backend failed to sign",
            SignError::Header => "protected header could not be serialized",
            SignError::AlgorithmNotPermitted => {
                "the environment signing policy does not permit this key's algorithm"
            }
        })
    }
}

impl std::error::Error for SignError {}
