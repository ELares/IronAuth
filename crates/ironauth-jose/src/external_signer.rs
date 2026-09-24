// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pluggable external-signer interface (issue #161).
//!
//! # The trait, and what it refuses to carry
//!
//! A [`ExternalSigner`] signs: given a kid, an algorithm, and the raw signing
//! input, it returns the signature. Key material NEVER passes through the trait -
//! for a remote backend (KMS, HSM, Vault) the private key lives in the backend's
//! boundary, and for the local backend the key is loaded inside the implementation
//! from the environment's key store. Verification continues against the published
//! JWKS, so only signing is delegated.
//!
//! # The `PureEdDSA` input-size ceiling
//!
//! RFC 8037 section 3.1: the `EdDSA` JOSE algorithm is `PureEdDSA` - there is no
//! JOSE-valid pre-hash variant, so the backend must receive the FULL signing input.
//! AWS KMS caps raw signing at 4096 bytes; without a guard, an oversized token
//! fails deep in the backend with an opaque error. The guard here is the loud,
//! early failure the issue demands:
//!
//! - a signing input over [`WARN_RAW_INPUT_BYTES`] (3 KB) logs a warning and
//!   increments the `ironauth_signing_input_oversized_total` metric;
//! - a signing input over the BACKEND's declared ceiling fails BEFORE dispatch
//!   with [`ExternalSignerError::InputTooLarge`] naming the limit and the size.
//!
//! The ceilings are per-backend declarations ([`ExternalSigner::max_raw_signing_input_bytes`]),
//! not a baked-in constant, so an AWS KMS backend declares 4096 while a local
//! key can declare none.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::JwsAlgorithm;

/// The warning threshold for a raw signing input: 3 KB (issue #161). The mint's
/// signing inputs are compact JWS inputs (a protected header + payload); a token
/// payload above this is unusual and worth an operator's look.
pub const WARN_RAW_INPUT_BYTES: usize = 3 * 1024;

/// The metric name for an oversized signing input (the warning half).
pub const SIGNING_INPUT_OVERSIZED_METRIC: &str = "ironauth_signing_input_oversized_total";

/// A backend's signing failure, mapped at the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSignerError {
    /// The backend timed out. Retryable.
    Timeout,
    /// The backend throttled the request. Retryable, with backoff.
    Throttled,
    /// The signing input exceeds the backend's raw-signing ceiling: the guard
    /// refuses BEFORE dispatch, so this is never an opaque backend failure.
    InputTooLarge {
        /// The backend's declared ceiling, in bytes.
        limit: usize,
        /// The offending input size, in bytes.
        size: usize,
    },
    /// The backend refused or failed for an opaque reason. Not retryable without
    /// an operator's attention.
    Backend,
}

/// The pluggable async signer (issue #161): sign `input` for `kid` under `alg`.
///
/// The trait is object-safe (`Send + Sync + 'static`), so a deployment selects a
/// backend at boot and the mint calls it without knowing which one it is. Key
/// material never appears on this interface.
pub trait ExternalSigner: Send + Sync + 'static {
    /// The backend's raw-signing input ceiling in bytes, or [`None`] when the
    /// backend imposes none (a local key). The guard hard-fails above it.
    fn max_raw_signing_input_bytes(&self) -> Option<usize>;

    /// Sign `input` for `kid` under `alg`, returning the raw signature bytes.
    ///
    /// # Errors
    ///
    /// [`ExternalSignerError`] on any failure, mapped at the boundary.
    fn sign(
        &self,
        kid: &str,
        alg: JwsAlgorithm,
        input: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ExternalSignerError>> + Send + '_>>;
}

/// Whether `input` exceeds the warning threshold ([`WARN_RAW_INPUT_BYTES`]): the
/// caller logs the warning and increments the [`SIGNING_INPUT_OVERSIZED_METRIC`]
/// metric (this crate carries no metrics dependency; the seam is the return).
#[must_use]
pub fn input_exceeds_warn_threshold(input: &[u8]) -> bool {
    input.len() > WARN_RAW_INPUT_BYTES
}

/// The size-ceiling guard (issue #161): hard-fail over the backend's declared
/// ceiling BEFORE dispatch, so an oversized token never fails deep in a remote
/// backend with an opaque error. The 3 KB warning is the caller's ([`input_exceeds_warn_threshold`]).
///
/// # Errors
///
/// [`ExternalSignerError::InputTooLarge`] when `input` exceeds the backend's
/// ceiling, naming the limit and the size.
pub fn guard_signing_input_size(
    input: &[u8],
    backend_ceiling: Option<usize>,
) -> Result<(), ExternalSignerError> {
    if let Some(limit) = backend_ceiling {
        if input.len() > limit {
            return Err(ExternalSignerError::InputTooLarge {
                limit,
                size: input.len(),
            });
        }
    }
    Ok(())
}

/// The LOCAL backend (issue #161): the existing encrypted-at-rest key, adapted
/// behind the trait. The key's material lives in the loaded [`crate::SigningKey`]
/// and never leaves it; this wrapper is the trait's local arm and the baseline
/// every conformance test runs against.
pub struct LocalSigner {
    key: Arc<crate::SigningKey>,
}

impl LocalSigner {
    /// A local backend over an already-loaded signing key.
    #[must_use]
    pub fn new(key: crate::SigningKey) -> Self {
        Self { key: Arc::new(key) }
    }

    /// The wrapped key.
    #[must_use]
    pub fn key(&self) -> &Arc<crate::SigningKey> {
        &self.key
    }
}

impl ExternalSigner for LocalSigner {
    fn max_raw_signing_input_bytes(&self) -> Option<usize> {
        // A local key signs anything its algorithm accepts: no ceiling.
        None
    }

    fn sign(
        &self,
        _kid: &str,
        _alg: JwsAlgorithm,
        input: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ExternalSignerError>> + Send + '_>> {
        let key = Arc::clone(&self.key);
        let input = input.to_vec();
        Box::pin(async move {
            crate::sign::sign_asymmetric(&key, &input).map_err(|()| ExternalSignerError::Backend)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_signer() -> LocalSigner {
        let key = crate::SigningKey::ed25519_from_seed(Some("kid_test".to_owned()), &[7_u8; 32])
            .expect("the key loads from a fixed seed");
        LocalSigner::new(key)
    }

    /// The conformance round-trip (issue #161): sign with the trait, verify with
    /// the published public half through the crate's JWS verify.
    #[test]
    fn local_backend_signs_and_the_jwks_verifies() {
        let signer = local_signer();
        // Build the signing input exactly as the mint does: protected header +
        // payload, the full input PureEdDSA demands.
        let header = br#"{"alg":"EdDSA","kid":"kid_test","typ":"at+jwt"}"#;
        let claims = br#"{"iss":"https://issuer.example.test","aud":"client-abc","sub":"usr_test","exp":1900000000,"iat":1800000000}"#;
        let signing_input = format!("{}.{}", base64_url(header), base64_url(claims));
        let sig = signer
            .sign("kid_test", JwsAlgorithm::EdDsa, signing_input.as_bytes())
            .now_or_never_ok()
            .expect("the local backend signs")
            .expect("the signature succeeds");
        let jws = format!("{signing_input}.{}", base64_url(&sig));
        // The public half verifies it (RFC 8037: the verification side).
        let trusted = signer.key().verifying_key().expect("the trusted key");
        let clock = ironauth_env::ManualClock::new(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
        );
        let policy = crate::VerificationPolicy::new(
            vec![JwsAlgorithm::EdDsa],
            vec![trusted],
            "https://issuer.example.test",
            "client-abc",
            crate::ExpectedTyp::Required(crate::TokenTyp::AccessToken),
        )
        .expect("policy");
        let verified = crate::verify::verify(&jws, &policy, &clock);
        assert!(verified.is_ok(), "the public half verifies: {verified:?}");
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// THE SIZE CEILING (issue #161): the guard warns over 3 KB and hard-fails
    /// over the backend's declared ceiling before any dispatch.
    #[test]
    fn the_size_ceiling_guards_before_dispatch() {
        let under = vec![0_u8; 3 * 1024];
        let over_warn = vec![0_u8; 3 * 1024 + 1];
        let over_limit = vec![0_u8; 5000];

        assert!(guard_signing_input_size(&under, Some(4096)).is_ok());
        // Over the warning threshold but under the backend limit: allowed, and the
        // warn seam says so (the caller's metric lives there).
        assert!(guard_signing_input_size(&over_warn, Some(4096)).is_ok());
        assert!(!input_exceeds_warn_threshold(&under));
        assert!(input_exceeds_warn_threshold(&over_warn));
        // Over the backend ceiling: refused before dispatch, naming both numbers.
        let err = guard_signing_input_size(&over_limit, Some(4096)).expect_err("refused");
        assert_eq!(
            err,
            ExternalSignerError::InputTooLarge {
                limit: 4096,
                size: 5000
            }
        );
    }

    trait NowOrNever {
        fn now_or_never_ok(self) -> Option<Result<Vec<u8>, ExternalSignerError>>;
    }
    impl NowOrNever
        for Pin<Box<dyn Future<Output = Result<Vec<u8>, ExternalSignerError>> + Send + '_>>
    {
        fn now_or_never_ok(self) -> Option<Result<Vec<u8>, ExternalSignerError>> {
            futures_util::FutureExt::now_or_never(self)
        }
    }
}
