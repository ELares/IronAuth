// SPDX-License-Identifier: MIT OR Apache-2.0

//! The FAPI 2.0 hardened-mode enforcement (issue #156).
//!
//! A hardened environment enforces the FAPI 2.0 Security Profile (Final) end to
//! end. The environment's `fapi_hardened` flag is the switch; THIS module is the
//! enforcement, called from the request paths so the same check answers the same
//! way everywhere:
//!
//! - **PAR mandatory** (FAPI 2.0 §6.2): an authorization request without a valid
//!   PAR `request_uri` is rejected with `invalid_request_object`.
//! - **PKCE S256 only** (§6.5.2): a plain (or absent) `code_challenge_method` is
//!   rejected.
//! - **Sender-constrained tokens** (§6.4): an exchange that proves neither a DPoP
//!   proof key nor an mTLS certificate binding is rejected before issuance.
//! - **Client authentication restricted** (§6.1): a client whose registered
//!   method is neither `private_key_jwt` nor an mTLS method cannot exist in a
//!   hardened environment - enforced at registration and at the token endpoint.
//! - **The signing set** (§6.7): `PS256`, `ES256`, and `EdDSA` only; `RS256`
//!   signing is refused (it stays LISTED in discovery's
//!   `id_token_signing_alg_values_supported` per OIDC Discovery section 3, the
//!   canonical exception).
//!
//! The checks are pure functions over what the request paths already resolved, so
//! a hardened environment cannot be admitted by an un-checked branch.

use ironauth_jose::JwsAlgorithm;
use ironauth_store::Scope;

/// The signing algorithms a hardened environment permits (FAPI 2.0 §6.7).
pub const HARDENED_SIGNING_ALGS: &[JwsAlgorithm] =
    &[JwsAlgorithm::Ps256, JwsAlgorithm::Es256, JwsAlgorithm::EdDsa];

/// The client-authentication methods a hardened environment permits (FAPI 2.0
/// §6.1): `private_key_jwt` or the two RFC 8705 mTLS methods. A public client
/// cannot exist in a hardened environment.
pub const HARDENED_CLIENT_AUTH_METHODS: &[&str] = &[
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
];

/// Whether `algorithm` is in the hardened signing set.
#[must_use]
pub fn hardened_permits_algorithm(algorithm: JwsAlgorithm) -> bool {
    HARDENED_SIGNING_ALGS.contains(&algorithm)
}

/// Whether `method` (the wire string) is a hardened-permitted client-auth method.
#[must_use]
pub fn hardened_permits_client_auth_method(method: &str) -> bool {
    HARDENED_CLIENT_AUTH_METHODS.contains(&method)
}

/// Whether a PKCE challenge is hardened-conformant (FAPI 2.0 §6.5.2): the method
/// must be `S256`. A plain or absent method is refused.
#[must_use]
pub fn hardened_pkce_conformant(code_challenge_method: Option<&str>) -> bool {
    matches!(code_challenge_method, Some("S256"))
}

/// Whether an authorization request is hardened-conformant (FAPI 2.0 §6.2): PAR
/// mandatory means the request must arrive via a PAR `request_uri`.
#[must_use]
pub fn hardened_par_conformant(has_par_request_uri: bool) -> bool {
    has_par_request_uri
}

/// Whether an exchange proves sender constraint (FAPI 2.0 §6.4): a DPoP proof
/// key (a `jkt` binding) or an mTLS certificate binding must be present.
#[must_use]
pub fn hardened_sender_constrained(dpop_jkt: Option<&str>, mtls_thumbprint: Option<&str>) -> bool {
    dpop_jkt.is_some() || mtls_thumbprint.is_some()
}

/// The refusal message for a non-hardened-conformant client-auth method, naming
/// the permitted set.
#[must_use]
pub fn hardened_auth_method_refusal(method: &str) -> String {
    format!(
        "a hardened (FAPI 2.0) environment permits only private_key_jwt or an mTLS \
         method, not {method:?}"
    )
}

/// Whether `scope`'s environment is hardened - the request-path check that gates
/// every enforcement call. The store read is the single source of the flag.
pub async fn is_hardened(
    state: &crate::OidcState,
    scope: Scope,
) -> Result<bool, ironauth_store::StoreError> {
    state
        .store()
        .scoped(scope)
        .environment_guardrails()
        .hardened()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signing_set_excludes_rs256_but_keeps_the_three_permits() {
        assert!(hardened_permits_algorithm(JwsAlgorithm::Ps256));
        assert!(hardened_permits_algorithm(JwsAlgorithm::Es256));
        assert!(hardened_permits_algorithm(JwsAlgorithm::EdDsa));
        assert!(!hardened_permits_algorithm(JwsAlgorithm::Rs256));
        assert!(!hardened_permits_algorithm(JwsAlgorithm::Rs384));
        assert!(!hardened_permits_algorithm(JwsAlgorithm::Rs512));
        assert!(!hardened_permits_algorithm(JwsAlgorithm::Ps384));
        assert!(!hardened_permits_algorithm(JwsAlgorithm::Ps512));
    }

    #[test]
    fn the_client_auth_set_permits_private_key_jwt_and_mtls_only() {
        assert!(hardened_permits_client_auth_method("private_key_jwt"));
        assert!(hardened_permits_client_auth_method("tls_client_auth"));
        assert!(hardened_permits_client_auth_method("self_signed_tls_client_auth"));
        assert!(!hardened_permits_client_auth_method("client_secret_basic"));
        assert!(!hardened_permits_client_auth_method("client_secret_post"));
        assert!(!hardened_permits_client_auth_method("none"));
    }

    #[test]
    fn pkce_s256_only_and_par_mandatory() {
        assert!(hardened_pkce_conformant(Some("S256")));
        assert!(!hardened_pkce_conformant(Some("plain")));
        assert!(!hardened_pkce_conformant(None));
        assert!(hardened_par_conformant(true));
        assert!(!hardened_par_conformant(false));
    }

    #[test]
    fn sender_constraint_requires_a_binding() {
        assert!(hardened_sender_constrained(Some("jkt"), None));
        assert!(hardened_sender_constrained(None, Some("x5t")));
        assert!(hardened_sender_constrained(Some("jkt"), Some("x5t")));
        assert!(!hardened_sender_constrained(None, None));
    }
}