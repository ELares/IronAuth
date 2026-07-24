// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth hardened JOSE verification and signing core.
//!
//! Every token surface IronAuth will ever ship inherits its verification
//! security from this one crate. There is a single public path to verify a
//! JWS/JWT, [`verify`], and the primitives beneath it (the raw `ring` signature
//! calls, the header and segment parsing) are module-private, so no call site
//! outside this crate can assemble a second, subtly different verifier. That is
//! the structural answer to the 2025-2026 JOSE CVE wave, whose recurring classes
//! all come from letting attacker-controlled token headers influence trust.
//!
//! The same crate holds the mint side, so signing and verification share one
//! backend and one algorithm vocabulary. See the signing section below.
//!
//! # Trust comes only from the policy
//!
//! [`verify`] takes a caller-supplied [`VerificationPolicy`] and trusts nothing
//! else. The algorithm comes from the policy's allowlist; the key comes from the
//! policy's trusted set; the expected issuer, audience, skew, and caps come from
//! the policy. The token's own headers are read only to be matched against the
//! policy, never followed outside it:
//!
//! - **`alg`** is compared against the allowlist and must map to the trusted
//!   key's family. It never selects the algorithm or key on its own.
//! - **`alg: none`** (in any case or whitespace variant, and the absent/empty
//!   forms) is always rejected. There is no configuration to permit it, not even
//!   for the OIDC Core code-flow case.
//! - **`kid`** may only select among already-trusted keys. A `kid` that names no
//!   trusted key is a rejection; it can never introduce a key.
//! - **`jwk`, `jku`, `x5u`, `x5c`** (in-token or by-reference key material) are
//!   rejected outright. Trust always comes from out-of-band keys, so their
//!   presence is fail-closed, never silently ignored.
//! - **`crit`** naming any extension is rejected: this core understands no
//!   critical extensions, and a malformed or duplicate `crit` is rejected too.
//!
//! # No HMAC in the verify core, by design
//!
//! The supported VERIFY algorithms are all asymmetric: `EdDSA` (Ed25519),
//! ES256/ES384 (ECDSA P-256/P-384), RS256/RS384/RS512 (RSA PKCS1-v1_5), and
//! PS256/PS384/PS512 (RSA-PSS). HMAC (`HS*`) is intentionally absent from
//! [`verify`]. With no symmetric verification path in the core, the classic
//! "present an `RS256` token as `HS256` and have it verified with the RSA public
//! key as the HMAC secret" confusion is not merely blocked but inexpressible, and
//! a claimed algorithm whose family does not match the trusted key is rejected
//! before any signature check. The excluded algorithms and their reasons are in
//! `docs/WILL-NOT-IMPLEMENT.md`; the design rationale is in
//! `docs/adr/0004-jose-verification.md`.
//!
//! # Signing
//!
//! The mint side signs the full asymmetric matrix through [`sign_jws`], with
//! `EdDSA` the default for new environments and clients. A [`SigningKey`] carries
//! secret material (never printed or serialized) and hands out its matching
//! [`TrustedKey`] via [`SigningKey::verifying_key`], so every mint round-trips
//! through this crate's one [`verify`] path. Keys live in an
//! [`EnvironmentKeyStore`] scoped per environment; a fresh environment publishes
//! its Ed25519, ES256, and RS256 public keys from day one through the [`JwkSet`]
//! builder, so moving a client between them is a configuration flip with no key
//! generation. `Ed25519` is accepted as a fully-specified alias of `EdDSA`, and
//! [`EmissionOptions`] carries the fully-specified emission toggle (default off).
//!
//! Symmetric `HS*` signing exists ONLY through [`ClientSecretContext`], keyed
//! from a [`ClientSecret`], for exactly the two OIDC client-secret cases. There
//! is no HMAC signing-key type and no way to place an `HS*` algorithm into an
//! environment default, so a tenant or environment can never be configured to
//! sign `HS*`: the illegal state is unrepresentable.
//!
//! Token-to-key binding uses one generalized confirmation model
//! ([`Confirmation`], RFC 7800), shared across issuance and verification, with
//! `jkt` (`DPoP`) and `x5t#S256` (mTLS) as the initial binding types. The evolving
//! protocol surfaces (client-auth methods, grant types, token-binding methods)
//! are fixed as traits in [`seams`] so future drafts land as implementations.
//!
//! # Caps before crypto
//!
//! [`VerificationCaps`] bound the work an attacker can force before any base64,
//! JSON, or signature work happens: a maximum token size (checked first of all),
//! per-segment decoded-size caps, a decompression-ratio guard, and a PBES2
//! iteration cap. Compressed (`zip`) and PBES2 inputs are rejected at the header
//! stage before anything can expand. The caps are configurable with safe
//! defaults; the structural rejections are not.
//!
//! # Uniform errors
//!
//! Every failure returns the single opaque [`VerifyError`], so a caller (and an
//! attacker) cannot tell which check failed. The precise, bounded-cardinality
//! [`RejectReason`] is available through [`VerifyError::reason`] for server-side
//! logs and metrics only.
//!
//! # Example
//!
//! ```
//! use std::time::{Duration, SystemTime};
//! use ironauth_env::ManualClock;
//! use ironauth_jose::{verify, JwsAlgorithm, TrustedKey, VerificationPolicy};
//!
//! # fn demo(token: &str, public_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
//! let policy = VerificationPolicy::new(
//!     vec![JwsAlgorithm::EdDsa],
//!     vec![TrustedKey::ed25519(Some("key-1".into()), public_key)?],
//!     "https://issuer.example.test",
//!     "client-abc",
//! )?
//! .with_skew(Duration::from_secs(30));
//!
//! let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
//! match verify(token, &policy, &clock) {
//!     Ok(verified) => {
//!         assert_eq!(verified.claims().issuer(), "https://issuer.example.test");
//!     }
//!     Err(err) => {
//!         // Uniform on the wire; the reason is for internal diagnostics only.
//!         tracing_reason(err.reason());
//!     }
//! }
//! # Ok(()) }
//! # fn tracing_reason(_r: ironauth_jose::RejectReason) {}
//! ```

mod claims;
mod cnf;
mod crypto;
mod dpop;
pub mod envelope;
mod error;
mod header;
mod json;
mod jwks;
mod keystore;
mod mint;
mod policy;
mod redact;
mod rotation;
mod sign;
mod signing_key;
mod signing_policy;
pub mod totp;
mod verify;
pub mod webauthn;

pub mod seams;

pub use claims::VerifiedClaims;
pub use cnf::{CnfError, Confirmation};
/// Test-only `DPoP` proof-minting helpers (the `test-util` feature), for a
/// downstream crate to exercise the token endpoint's issuance path end to end.
/// The `dpop` module itself stays private; only this helper surface is exposed.
#[cfg(feature = "test-util")]
pub use dpop::test_util as dpop_test_util;
pub use dpop::{DpopError, DpopExpectations, DpopProof, jwk_thumbprint, validate_dpop_proof};
pub use envelope::{
    Aad, AadBuilder, BlindIndex, Dek, EnvelopeError, KEY_LEN, Kek, MasterKey, NONCE_BYTES, Sealed,
};
pub use error::{RejectReason, VerifyError};
pub use jwks::{Jwk, JwkSet, trusted_keys_from_jwks};
pub use keystore::EnvironmentKeyStore;
pub use mint::{
    ClientSecret, ClientSecretContext, ClientSecretJws, EmissionOptions, MacAlgorithm, SignError,
    sign_jws, sign_jws_with_policy,
};
pub use policy::{
    JwsAlgorithm, KeyError, KeyFamily, PolicyError, TrustedKey, VerificationCaps,
    VerificationPolicy,
};
pub use redact::Redacted;
pub use rotation::{KeySet, RotationError, RotationParams, includes_downgrade_key};
pub use signing_key::{
    SigningKey, SigningKeyError, generate_ecdsa_p256_pkcs8_der, generate_rsa_pkcs1_der,
};
pub use signing_policy::{SigningPolicy, SigningPolicyError};
pub use totp::{
    Base32Error, TotpAlgorithm, TotpParams, TotpParamsError, base32_decode, base32_encode, code_at,
    grouped_secret, provisioning_uri, verify as verify_totp,
};
pub use verify::{VerifiedToken, compact_jws_kid, verify};
pub use webauthn::{
    WebauthnKey, WebauthnSignatureError, verify_jws_signature, verify_webauthn_signature,
};
