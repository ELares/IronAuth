// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structural exclusion of the forbidden flows (OAuth 2.1 posture, RFC 9700).
//!
//! The grant-type, response-type, and PKCE-method registries CANNOT express:
//!
//! - ROPC (the `password` grant): there is no `GrantType` variant for it, so it
//!   has no value and no handler.
//! - an access token (or ID token) from the authorization endpoint (the implicit
//!   flow): there is no `ResponseType` variant other than `code`.
//! - plain PKCE (`code_challenge_method=plain`): there is no `PkceMethod` variant
//!   other than `S256`.
//!
//! These tests enumerate each registry's ENTIRE variant set and assert every
//! forbidden spelling parses to `None`, so a future edit that reintroduced a
//! forbidden variant would fail the build. This is database-free and runs on
//! every lane.

use ironauth_oidc::{GrantType, PkceMethod, ResponseType};

#[test]
fn grant_type_registry_only_expresses_authorization_code() {
    // The whole registry is exactly one variant: the authorization-code grant.
    assert_eq!(GrantType::ALL, &[GrantType::AuthorizationCode]);
    assert_eq!(GrantType::ALL.len(), 1);

    // The authorization-code grant round-trips.
    assert_eq!(
        GrantType::parse("authorization_code"),
        Some(GrantType::AuthorizationCode)
    );

    // Every forbidden or unknown grant type is unrepresentable: it parses to
    // None, so it can never resolve to a handler. ROPC is the headline case.
    for forbidden in [
        "password",           // ROPC: structurally excluded.
        "client_credentials", // not offered here.
        "implicit",
        "refresh_token", // M3, not this issue.
        "urn:ietf:params:oauth:grant-type:device_code",
        "",
        "Authorization_Code", // casing is exact.
    ] {
        assert!(
            GrantType::parse(forbidden).is_none(),
            "grant_type {forbidden:?} must be unrepresentable"
        );
    }
}

#[test]
fn response_type_registry_only_expresses_code() {
    // The whole registry is exactly one variant: code. No token, no id_token, no
    // hybrid: the authorization endpoint can never emit an access or ID token
    // directly (the implicit flow is structurally absent).
    assert_eq!(ResponseType::ALL, &[ResponseType::Code]);
    assert_eq!(ResponseType::ALL.len(), 1);

    assert_eq!(ResponseType::parse("code"), Some(ResponseType::Code));

    for forbidden in [
        "token",          // implicit: access token from /authorize.
        "id_token",       // ID token from /authorize.
        "id_token token", // hybrid.
        "code token",     // hybrid.
        "code id_token",  // hybrid.
        "none",           // #17, not this issue.
        "",
    ] {
        assert!(
            ResponseType::parse(forbidden).is_none(),
            "response_type {forbidden:?} must be unrepresentable"
        );
    }
}

#[test]
fn pkce_method_registry_only_expresses_s256() {
    // The whole registry is exactly one variant: S256. plain is unrepresentable.
    assert_eq!(PkceMethod::ALL, &[PkceMethod::S256]);
    assert_eq!(PkceMethod::ALL.len(), 1);

    assert_eq!(PkceMethod::parse("S256"), Some(PkceMethod::S256));

    for forbidden in [
        "plain", // the downgrade this excludes.
        "s256",  // casing is exact.
        "S512", "",
    ] {
        assert!(
            PkceMethod::parse(forbidden).is_none(),
            "code_challenge_method {forbidden:?} must be unrepresentable"
        );
    }
}
