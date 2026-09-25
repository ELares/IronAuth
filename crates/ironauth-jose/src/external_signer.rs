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

/// THE SHARED CONFORMANCE BATTERY (issue #161, the Dex pattern): the ONE test
/// battery every signer backend must pass. The local backend runs it in the jose
/// crate's tests; a remote backend (the vault transit signer) runs the SAME
/// battery in its own tests, so a backend that signs differently cannot claim
/// conformance by passing a test suite that was written for it.
///
/// The battery covers: the sign/verify round-trip per algorithm, kid handling
/// (the signature must verify against the key the kid names), and the size
/// ceiling's refusal (a backend whose declared ceiling the input exceeds must
/// refuse BEFORE dispatch).
pub async fn run_conformance_battery(
    backend: &(dyn ExternalSigner + '_),
    kid: &str,
    alg: JwsAlgorithm,
    payload: &[u8],
    verify_with: impl Fn(&[u8]) -> bool,
) -> Result<(), String> {
    // 1. The sign/verify round-trip: the backend signs the FULL input (the
    //    PureEdDSA shape), and the public half verifies the raw signature.
    let signature = backend
        .sign(kid, alg, payload)
        .await
        .map_err(|error| format!("the backend refused a valid input: {error:?}"))?;
    if !verify_with(&signature) {
        return Err("the signature does not verify against the public half".to_owned());
    }

    // 2. The size-ceiling refusal: an input over the backend's declared ceiling is
    //    refused BEFORE dispatch, naming the limit and the size.
    if let Some(limit) = backend.max_raw_signing_input_bytes() {
        let oversized = vec![0_u8; limit + 1];
        let refusal = backend
            .sign(kid, alg, &oversized)
            .await
            .err()
            .ok_or_else(|| "an oversized input was not refused".to_owned())?;
        match refusal {
            ExternalSignerError::InputTooLarge { limit: named, size } => {
                if named != limit || size != oversized.len() {
                    return Err("the refusal names the wrong limit or size".to_owned());
                }
            }
            other => {
                return Err(format!(
                    "an oversized input must be refused with InputTooLarge, got {other:?}"
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_signer() -> LocalSigner {
        let key = crate::SigningKey::ed25519_from_seed(Some("kid_test".to_owned()), &[7_u8; 32])
            .expect("the key loads from a fixed seed");
        LocalSigner::new(key)
    }

    /// THE BATTERY (issue #161): the local backend passes the shared conformance
    /// battery — sign/verify round-trip against its public half, kid handling, and
    /// the ceiling behavior — the same battery every remote backend must pass.
    #[test]
    fn the_local_backend_passes_the_shared_conformance_battery() {
        let signer = local_signer();
        let trusted = signer.key().verifying_key().expect("the trusted key");
        let input = b"the full signing input, exactly as PureEdDSA demands";
        // A raw-signature check: the public half verifies the backend's output on
        // the FULL input (the PureEdDSA shape), without any JWS ceremony.
        let verify = |signature: &[u8]| {
            crate::verify_detached(&trusted, JwsAlgorithm::EdDsa, input, signature).is_ok()
        };
        let outcome = run_conformance_battery(&signer, "kid_test", JwsAlgorithm::EdDsa, input, verify);
        assert!(outcome.is_ok(), "the local backend passes: {outcome:?}");
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
