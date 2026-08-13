// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8693 `requested_token_type` negotiation (issue #125).
//!
//! Issue #125 asks for "`requested_token_type` negotiation for access tokens (JWT and opaque);
//! refresh tokens are issued from an exchange only when explicit per-client config allows it".
//! This is that decision, purely.
//!
//! # A refresh token from an exchange is a different thing to ask for
//!
//! Every other type here trades one short-lived credential for another short-lived credential.
//! A refresh token is not that: it is a LONG-LIVED credential that mints more tokens, so
//! granting one converts a bounded delegation into a standing one. A service handed a
//! five-minute access token to complete one call, which exchanges it for a refresh token, now
//! holds indefinite access to the subject's account without the subject present.
//!
//! That is occasionally what an operator wants and it is never what they want by ACCIDENT, so
//! it requires explicit per-client configuration and is refused by default.
//!
//! # An unrecognised type is refused, not defaulted
//!
//! RFC 8693 section 2.1 permits omitting `requested_token_type`, and this treats that as "an
//! access token of the server's preferred format", which is the reading the RFC invites.
//!
//! A type that is PRESENT but unrecognised is a different case, and it is refused. Defaulting it
//! to an access token would mean a client asking for something this server does not implement
//! silently receives something else, and then discovers the mismatch at the point of use,
//! usually in another service. `invalid_request` at the exchange is the cheaper failure by a
//! wide margin.

/// The RFC 8693 token type URIs this server understands.
///
/// The URIs are the wire form and are matched exactly. RFC 8693 section 3 defines them, and a
/// near-miss (a trailing slash, the `urn:ietf:params:oauth:token-type:jwt` generic form) is an
/// unrecognised type rather than a guess at what was meant.
pub mod type_uri {
    /// A generic access token, format chosen by the server.
    pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    /// A refresh token. Requires explicit per-client configuration.
    pub const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
    /// A JWT, which for this server means an `at+jwt` access token.
    pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
}

/// What an exchange will issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuedTokenType {
    /// An `at+jwt` access token: self-contained, verifiable without a round trip.
    AccessTokenJwt,
    /// An opaque access token, resolved by introspection.
    AccessTokenOpaque,
    /// A refresh token. Only reachable with explicit configuration.
    RefreshToken,
}

/// Why a requested type was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDenial {
    /// A refresh token was requested and this client is not configured to receive one.
    RefreshNotAllowed,
    /// The type URI is present but not one this server implements.
    UnsupportedType(String),
}

impl TypeDenial {
    /// A stable, value-free description. The URI is carried for the admin log but this text
    /// never quotes it, so a caller need not decide whether it was safe to echo.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RefreshNotAllowed => {
                "a refresh token was requested and this client is not configured for one"
            }
            Self::UnsupportedType(_) => "the requested token type is not implemented here",
        }
    }
}

/// The server's default access-token format for a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAccessFormat {
    /// Issue `at+jwt`.
    Jwt,
    /// Issue an opaque token.
    Opaque,
}

/// Decide what an exchange issues.
///
/// `requested` is the `requested_token_type` parameter, or [`None`] when omitted.
/// `refresh_allowed` is the per-client configuration; `default_format` is what a generic access
/// token means for this client.
///
/// # Errors
///
/// [`TypeDenial`] when a refresh token is requested without configuration, or the type is not
/// implemented.
pub fn negotiate_type(
    requested: Option<&str>,
    refresh_allowed: bool,
    default_format: DefaultAccessFormat,
) -> Result<IssuedTokenType, TypeDenial> {
    let access = match default_format {
        DefaultAccessFormat::Jwt => IssuedTokenType::AccessTokenJwt,
        DefaultAccessFormat::Opaque => IssuedTokenType::AccessTokenOpaque,
    };
    match requested {
        // Omitted, or an explicit generic access token: both mean the client's configured
        // format. RFC 8693 2.1 permits omitting it and leaves the choice to the server, and
        // "the server chooses" and "give me whatever an access token is here" are the same
        // request, so they share an arm rather than coinciding by accident.
        None | Some(type_uri::ACCESS_TOKEN) => Ok(access),
        // An explicit JWT request overrides the client's default format, because the caller has
        // said it needs a token it can verify without a round trip and that is a real
        // requirement rather than a preference.
        Some(type_uri::JWT) => Ok(IssuedTokenType::AccessTokenJwt),
        Some(type_uri::REFRESH_TOKEN) => {
            if refresh_allowed {
                Ok(IssuedTokenType::RefreshToken)
            } else {
                // Default deny. Granting this turns a bounded delegation into a standing one.
                Err(TypeDenial::RefreshNotAllowed)
            }
        }
        // Present but unrecognised. Refused rather than defaulted, so the mismatch surfaces
        // here instead of in whichever service tries to use the wrong kind of token.
        Some(other) => Err(TypeDenial::UnsupportedType(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::{DefaultAccessFormat, IssuedTokenType, TypeDenial, negotiate_type, type_uri};

    #[test]
    fn an_omitted_type_uses_the_clients_default_format() {
        assert_eq!(
            negotiate_type(None, false, DefaultAccessFormat::Jwt).expect("permitted"),
            IssuedTokenType::AccessTokenJwt
        );
        assert_eq!(
            negotiate_type(None, false, DefaultAccessFormat::Opaque).expect("permitted"),
            IssuedTokenType::AccessTokenOpaque
        );
    }

    #[test]
    fn a_generic_access_token_request_uses_the_default_format() {
        assert_eq!(
            negotiate_type(
                Some(type_uri::ACCESS_TOKEN),
                false,
                DefaultAccessFormat::Opaque
            )
            .expect("permitted"),
            IssuedTokenType::AccessTokenOpaque
        );
    }

    /// An explicit JWT request OVERRIDES an opaque default, because the caller has said it needs
    /// a token it can verify without a round trip, which is a requirement rather than taste.
    #[test]
    fn an_explicit_jwt_request_overrides_an_opaque_default() {
        assert_eq!(
            negotiate_type(Some(type_uri::JWT), false, DefaultAccessFormat::Opaque)
                .expect("permitted"),
            IssuedTokenType::AccessTokenJwt
        );
    }

    /// THE default-deny: a refresh token converts a bounded delegation into a standing one.
    ///
    /// A service handed a five-minute access token to complete one call, exchanging it for a
    /// refresh token, would hold indefinite access to the subject's account with the subject
    /// long gone.
    #[test]
    fn a_refresh_token_is_refused_unless_configured() {
        assert_eq!(
            negotiate_type(
                Some(type_uri::REFRESH_TOKEN),
                false,
                DefaultAccessFormat::Jwt
            )
            .unwrap_err(),
            TypeDenial::RefreshNotAllowed
        );
        // The identical request with the policy enabled succeeds, so the refusal is the policy
        // and not something else in the fixture.
        assert_eq!(
            negotiate_type(
                Some(type_uri::REFRESH_TOKEN),
                true,
                DefaultAccessFormat::Jwt
            )
            .expect("permitted"),
            IssuedTokenType::RefreshToken
        );
    }

    /// Enabling refresh must not change anything else, so the flag is scoped to the one type it
    /// is about.
    #[test]
    fn allowing_refresh_does_not_affect_the_other_types() {
        for requested in [None, Some(type_uri::ACCESS_TOKEN), Some(type_uri::JWT)] {
            assert_eq!(
                negotiate_type(requested, false, DefaultAccessFormat::Jwt),
                negotiate_type(requested, true, DefaultAccessFormat::Jwt),
                "{requested:?} must not depend on the refresh policy"
            );
        }
    }

    /// A present-but-unrecognised type is REFUSED, never defaulted.
    ///
    /// Defaulting would mean a client asking for something unimplemented silently receives
    /// something else, then discovers the mismatch at the point of use in another service.
    /// Failing at the exchange is cheaper by a wide margin.
    #[test]
    fn an_unrecognised_type_is_refused_rather_than_defaulted() {
        for requested in [
            "urn:ietf:params:oauth:token-type:saml2",
            "urn:ietf:params:oauth:token-type:id_token",
            "urn:example:something-else",
            "",
        ] {
            assert_eq!(
                negotiate_type(Some(requested), true, DefaultAccessFormat::Jwt).unwrap_err(),
                TypeDenial::UnsupportedType(requested.to_owned()),
                "{requested:?} must be refused"
            );
        }
    }

    /// Type URIs are matched EXACTLY. A near-miss is unrecognised rather than a guess at intent.
    ///
    /// Accepting a trailing slash or different case would mean two spellings of "the same" type
    /// behave identically here and differently at any conformant peer.
    #[test]
    fn a_near_miss_uri_is_not_silently_accepted() {
        for near in [
            "urn:ietf:params:oauth:token-type:access_token/",
            " urn:ietf:params:oauth:token-type:access_token",
            "URN:IETF:PARAMS:OAUTH:TOKEN-TYPE:ACCESS_TOKEN",
            "urn:ietf:params:oauth:token-type:access-token",
        ] {
            assert!(
                negotiate_type(Some(near), false, DefaultAccessFormat::Jwt).is_err(),
                "{near:?} must not be accepted as the access-token type"
            );
        }
    }

    /// A refused refresh reports the REFRESH reason, not "unsupported", even though both are
    /// refusals. An operator reading the admin log needs to know a configuration flag would fix
    /// one and nothing would fix the other.
    #[test]
    fn the_two_denials_are_not_interchangeable() {
        let refresh = negotiate_type(
            Some(type_uri::REFRESH_TOKEN),
            false,
            DefaultAccessFormat::Jwt,
        )
        .unwrap_err();
        let unsupported =
            negotiate_type(Some("urn:example:other"), false, DefaultAccessFormat::Jwt).unwrap_err();
        assert_ne!(refresh, unsupported);
        assert_ne!(refresh.as_str(), unsupported.as_str());
        assert!(refresh.as_str().len() > 20 && unsupported.as_str().len() > 20);
    }
}
