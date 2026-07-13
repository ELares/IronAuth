// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment signing-algorithm policy.
//!
//! An environment's policy is the closed allowlist of [`JwsAlgorithm`]s it may
//! sign with. It is the mint-side twin of the verify-side allowlist in
//! [`crate::VerificationPolicy`]: signing consults it so a FIPS-constrained
//! environment can be pinned to `ES256` while a modern one runs `EdDSA`, and the
//! same policy filters the published JWKS so a policy-banned algorithm's key is
//! withdrawn from the issuer's key set.
//!
//! Two rules make the policy safe by construction:
//!
//! - Every member is a [`JwsAlgorithm`], which has no `HS*` variant, so a policy
//!   can never admit a symmetric algorithm.
//! - The `RS256` key is ALWAYS retained in the published JWKS regardless of the
//!   policy ([`SigningPolicy::retains_in_jwks`]). That preserves the zero-friction
//!   downgrade covenant: a relying party that only understands `RS256` can always
//!   find that key, even in an environment whose policy has otherwise moved on.
//!
//! Resolution follows the issue's tenant-default-with-environment-override model
//! ([`SigningPolicy::resolve`]): an explicit environment value wins, else the
//! tenant default, else the built-in `EdDSA` default.

use crate::policy::JwsAlgorithm;

/// The allowed signing algorithms for one environment.
///
/// Construct it through [`SigningPolicy::new`] (which rejects an empty allowlist
/// and de-duplicates while preserving order) or [`SigningPolicy::eddsa_default`].
/// The order is preserved so the FIRST entry can act as the environment's
/// preferred algorithm when several keys are provisioned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningPolicy {
    allowed: Vec<JwsAlgorithm>,
}

impl SigningPolicy {
    /// Build a policy from an allowlist.
    ///
    /// Duplicates are dropped, preserving first-seen order.
    ///
    /// # Errors
    ///
    /// [`SigningPolicyError::EmptyAllowlist`] if `allowed` is empty: an
    /// environment that permits no algorithm could never sign a token.
    pub fn new(allowed: Vec<JwsAlgorithm>) -> Result<Self, SigningPolicyError> {
        if allowed.is_empty() {
            return Err(SigningPolicyError::EmptyAllowlist);
        }
        let mut deduped: Vec<JwsAlgorithm> = Vec::with_capacity(allowed.len());
        for alg in allowed {
            if !deduped.contains(&alg) {
                deduped.push(alg);
            }
        }
        Ok(Self { allowed: deduped })
    }

    /// The IronAuth default policy: `EdDSA` only.
    #[must_use]
    pub fn eddsa_default() -> Self {
        Self {
            allowed: vec![JwsAlgorithm::EdDsa],
        }
    }

    /// The permitted algorithms, in preference order.
    #[must_use]
    pub fn allowed(&self) -> &[JwsAlgorithm] {
        &self.allowed
    }

    /// The environment's preferred signing algorithm (the first allowlist entry).
    #[must_use]
    pub fn preferred(&self) -> JwsAlgorithm {
        // The allowlist is non-empty by construction, so `first` is always Some.
        self.allowed.first().copied().unwrap_or(JwsAlgorithm::EdDsa)
    }

    /// Whether `algorithm` may be used to SIGN under this policy.
    #[must_use]
    pub fn permits(&self, algorithm: JwsAlgorithm) -> bool {
        self.allowed.contains(&algorithm)
    }

    /// Whether a key of `algorithm` is RETAINED in the published JWKS under this
    /// policy.
    ///
    /// A policy-permitted algorithm is retained. Additionally the `RS256` key is
    /// always retained regardless of the policy, preserving the zero-friction
    /// downgrade covenant (a relying party that only understands `RS256` must
    /// always find its key). This is intentionally NOT the same as
    /// [`SigningPolicy::permits`]: a banned `RS256` key stays PUBLISHED but is
    /// never SELECTED to sign.
    #[must_use]
    pub fn retains_in_jwks(&self, algorithm: JwsAlgorithm) -> bool {
        self.permits(algorithm) || algorithm == JwsAlgorithm::Rs256
    }

    /// Resolve the effective policy from an optional tenant default and an
    /// optional environment override.
    ///
    /// An explicit environment override wins; otherwise the tenant default
    /// applies; otherwise the built-in [`SigningPolicy::eddsa_default`]. This is
    /// the "explicit environment value overrides the tenant default" rule the
    /// issuer model requires.
    #[must_use]
    pub fn resolve(
        tenant_default: Option<&SigningPolicy>,
        environment_override: Option<&SigningPolicy>,
    ) -> SigningPolicy {
        environment_override
            .or(tenant_default)
            .cloned()
            .unwrap_or_else(SigningPolicy::eddsa_default)
    }
}

impl Default for SigningPolicy {
    fn default() -> Self {
        Self::eddsa_default()
    }
}

/// A caller-side error building a [`SigningPolicy`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SigningPolicyError {
    /// The allowlist was empty; an environment must permit at least one
    /// algorithm.
    EmptyAllowlist,
}

impl std::fmt::Display for SigningPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningPolicyError::EmptyAllowlist => {
                f.write_str("signing policy has an empty algorithm allowlist")
            }
        }
    }
}

impl std::error::Error for SigningPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_is_rejected() {
        assert_eq!(
            SigningPolicy::new(Vec::new()),
            Err(SigningPolicyError::EmptyAllowlist)
        );
    }

    #[test]
    fn duplicates_are_dropped_preserving_order() {
        let policy = SigningPolicy::new(vec![
            JwsAlgorithm::Es256,
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
        ])
        .expect("non-empty");
        assert_eq!(
            policy.allowed(),
            &[JwsAlgorithm::Es256, JwsAlgorithm::EdDsa]
        );
        assert_eq!(policy.preferred(), JwsAlgorithm::Es256);
    }

    #[test]
    fn permits_only_listed_algorithms() {
        let policy = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("non-empty");
        assert!(policy.permits(JwsAlgorithm::Es256));
        assert!(!policy.permits(JwsAlgorithm::EdDsa));
    }

    #[test]
    fn rs256_is_always_retained_in_jwks_even_when_banned() {
        let policy = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("non-empty");
        // Not permitted to sign, but retained in the published JWKS (covenant).
        assert!(!policy.permits(JwsAlgorithm::Rs256));
        assert!(policy.retains_in_jwks(JwsAlgorithm::Rs256));
        // A different banned algorithm is neither signed nor published.
        assert!(!policy.retains_in_jwks(JwsAlgorithm::EdDsa));
        // The permitted algorithm is retained.
        assert!(policy.retains_in_jwks(JwsAlgorithm::Es256));
    }

    #[test]
    fn resolve_prefers_environment_then_tenant_then_default() {
        let tenant = SigningPolicy::new(vec![JwsAlgorithm::Rs256]).expect("non-empty");
        let environment = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("non-empty");

        assert_eq!(
            SigningPolicy::resolve(Some(&tenant), Some(&environment)),
            environment
        );
        assert_eq!(SigningPolicy::resolve(Some(&tenant), None), tenant);
        assert_eq!(
            SigningPolicy::resolve(None, None),
            SigningPolicy::eddsa_default()
        );
    }
}
