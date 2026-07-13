// SPDX-License-Identifier: MIT OR Apache-2.0

//! Documented extension seams for the protocol surfaces that grow by draft.
//!
//! OAuth and OIDC accrete client-authentication methods, grant types, and
//! token-binding mechanisms over time (each new RFC or draft adds one). To keep
//! those additions as new implementations rather than refactors of existing
//! code, IronAuth fixes the shape of each family as a trait here. A future
//! `attest_jwt_client_auth`, a future grant, or a future binding is a new `impl`
//! of the relevant trait; nothing that consumes the trait has to change.
//!
//! These are the stable contracts only. The signing core ships no production
//! implementations of them in M1 (the features that would implement them, such
//! as full `DPoP` and mTLS, are out of scope); the crate's tests carry sample
//! implementations that prove each seam is implementable and wire the
//! token-binding seam to the shared [`Confirmation`] model.

use crate::cnf::Confirmation;

/// A client-authentication method (the registered `token_endpoint_auth_method`).
///
/// Implementations name themselves and, in a fuller build, would verify a
/// presented credential; the M1 contract fixes the identity so registrations and
/// metadata can enumerate methods uniformly.
///
/// # Examples
///
/// ```
/// use ironauth_jose::seams::ClientAuthMethod;
///
/// struct ClientSecretBasic;
/// impl ClientAuthMethod for ClientSecretBasic {
///     fn method_name(&self) -> &'static str {
///         "client_secret_basic"
///     }
/// }
/// assert_eq!(ClientSecretBasic.method_name(), "client_secret_basic");
/// ```
pub trait ClientAuthMethod {
    /// The registered `token_endpoint_auth_method` name, for example
    /// `client_secret_basic`, `private_key_jwt`, or `tls_client_auth`.
    ///
    /// A registered protocol identifier, so it is a `'static` string.
    fn method_name(&self) -> &'static str;
}

/// An OAuth grant type (the `grant_type` value the token endpoint dispatches on).
///
/// A future grant lands as a new implementation; the dispatcher keys off
/// [`GrantType::grant_type`] rather than a hardcoded match that every new grant
/// would have to edit.
pub trait GrantType {
    /// The grant-type identifier, for example
    /// `authorization_code`, `client_credentials`, or a URN grant.
    ///
    /// A registered protocol identifier, so it is a `'static` string.
    fn grant_type(&self) -> &'static str;
}

/// A token-binding method: how a token is bound to a key its holder must prove
/// possession of.
///
/// This is the seam the two shipped binding types (`DPoP` and mTLS) plug into, and
/// it ties directly to the shared [`Confirmation`] model: a binding method turns
/// a presented thumbprint into the RFC 7800 confirmation to embed. A future
/// binding type is a new implementation returning a new [`Confirmation`] variant.
pub trait TokenBindingMethod {
    /// A human/RFC name for the binding, for example `DPoP` or `mTLS`.
    ///
    /// A fixed identifier, so it is a `'static` string.
    fn binding_name(&self) -> &'static str;

    /// The RFC 7800 confirmation for a token bound with `thumbprint`.
    ///
    /// `thumbprint` is the already-computed key or certificate thumbprint (this
    /// seam does not compute it; DPoP/mTLS do). The returned [`Confirmation`]
    /// flows through the one issuance and verification path in [`crate::cnf`].
    fn confirmation(&self, thumbprint: &str) -> Confirmation;
}
