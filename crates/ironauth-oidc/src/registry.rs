// SPDX-License-Identifier: MIT OR Apache-2.0

//! The grant-type, response-type, and PKCE-method registries.
//!
//! These three closed enums are how IronAuth structurally EXCLUDES the forbidden
//! flows (OAuth 2.1 posture, RFC 9700). The exclusion is not a disabled config
//! knob and not a runtime rejection layered on top of a broader parser: the
//! illegal states are unrepresentable, because the enums have no variant for
//! them and the parsers map every forbidden spelling to `None`.
//!
//! - [`GrantType`] has exactly one variant, [`GrantType::AuthorizationCode`].
//!   There is no `Password` variant, so the resource-owner-password-credentials
//!   (ROPC) grant has no value to match and no handler to route to: it is absent,
//!   not disabled.
//! - [`ResponseType`] has exactly one variant, [`ResponseType::Code`]. There is
//!   no `Token` or `IdToken` variant, so the implicit flow (an access token, or
//!   an ID token, issued straight from the authorization endpoint) cannot be
//!   expressed. The authorization endpoint can only ever mint a code.
//! - [`PkceMethod`] has exactly one variant, [`PkceMethod::S256`]. There is no
//!   `Plain` variant, so `code_challenge_method=plain` can never be represented.
//!
//! A structural test (`tests/structural.rs`) enumerates each registry's full
//! variant set and asserts every forbidden spelling parses to `None`, so a future
//! edit that reintroduced a forbidden variant would fail the build.

/// The OAuth grant types IronAuth's token endpoint can service.
///
/// Closed on purpose: the only member is the authorization-code grant. ROPC
/// (`password`), the client-credentials grant, and every other grant are simply
/// absent, so there is no way to name one at this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    /// The `authorization_code` grant (RFC 6749 4.1.3).
    AuthorizationCode,
}

impl GrantType {
    /// Every grant type this build can express. Exactly one, by design.
    pub const ALL: &'static [GrantType] = &[GrantType::AuthorizationCode];

    /// The wire `grant_type` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
        }
    }

    /// Parse a wire `grant_type`. Returns `None` for every value that is not the
    /// authorization-code grant, so `password` (ROPC) and the rest never resolve
    /// to a handler.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            _ => None,
        }
    }
}

/// The OAuth response types the authorization endpoint can service.
///
/// Closed on purpose: the only member is `code`. The implicit-flow response types
/// (`token`, `id_token`, and their combinations) are absent, so the authorization
/// endpoint cannot return an access token or an ID token directly: it can only
/// ever issue a code to be exchanged at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    /// The `code` response type (the authorization-code flow).
    Code,
}

impl ResponseType {
    /// Every response type this build can express. Exactly one, by design.
    pub const ALL: &'static [ResponseType] = &[ResponseType::Code];

    /// The wire `response_type` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseType::Code => "code",
        }
    }

    /// Parse a wire `response_type`. Returns `None` for every value that is not
    /// `code`, so `token`, `id_token`, and the hybrid combinations never resolve
    /// to an authorization-endpoint response.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "code" => Some(ResponseType::Code),
            _ => None,
        }
    }
}

/// The PKCE code-challenge methods IronAuth accepts.
///
/// Closed on purpose: the only member is `S256`. `plain` is absent, so a downgrade
/// to plain PKCE cannot be represented at this layer. (Requiring PKCE and
/// enforcing S256-only for every client is the #13 hardening; here the method is
/// merely bound and verified when present, and `plain` is already unrepresentable.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    /// `S256`: `code_challenge = BASE64URL(SHA256(code_verifier))` (RFC 7636).
    S256,
}

impl PkceMethod {
    /// Every PKCE method this build can express. Exactly one, by design.
    pub const ALL: &'static [PkceMethod] = &[PkceMethod::S256];

    /// The wire `code_challenge_method` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PkceMethod::S256 => "S256",
        }
    }

    /// Parse a wire `code_challenge_method`. Returns `None` for every value that
    /// is not `S256`, so `plain` never resolves to a method.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "S256" => Some(PkceMethod::S256),
            _ => None,
        }
    }
}
