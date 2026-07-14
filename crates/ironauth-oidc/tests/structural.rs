// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structural exclusion of the forbidden flows (OAuth 2.1 posture, RFC 9700).
//!
//! The grant-type, response-type, and PKCE-method registries CANNOT express:
//!
//! - ROPC (the `password` grant): there is no `GrantType` variant for it, so it
//!   has no value and no handler. (The client-credentials grant IS offered, issue
//!   #23, but ROPC and every non-serviced grant stay unrepresentable.)
//! - an ACCESS TOKEN from the authorization endpoint (the implicit/hybrid
//!   token-bearing flows): there is no access-token component anywhere in
//!   `ResponseType`, so `token`, `code token`, `id_token token`, and
//!   `code id_token token` are all unrepresentable, in every order.
//! - plain PKCE (`code_challenge_method=plain`): there is no `PkceMethod` variant
//!   other than `S256`.
//!
//! These tests enumerate each registry's ENTIRE variant set and assert every
//! forbidden spelling parses to `None`, so a future edit that reintroduced a
//! forbidden variant would fail the build. This is database-free and runs on
//! every lane.

use ironauth_oidc::{GrantType, PkceMethod, ResponseMode, ResponseType};

#[test]
fn grant_type_registry_expresses_the_five_serviced_grants_and_no_ropc() {
    // The whole registry is exactly five variants: the authorization-code grant, the
    // refresh-token grant (issue #21), the client-credentials grant (issue #23), the
    // JWT bearer assertion grant (issue #26), and the RFC 8628 device-code grant
    // (issue #24). No other grant type is representable (ROPC has no variant at all,
    // and RFC 8693 token exchange is a separate M13 grant).
    assert_eq!(
        GrantType::ALL,
        &[
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::JwtBearer,
            GrantType::DeviceCode,
        ]
    );
    assert_eq!(GrantType::ALL.len(), 5);

    // Every offered grant round-trips through its exact wire spelling.
    assert_eq!(
        GrantType::parse("authorization_code"),
        Some(GrantType::AuthorizationCode)
    );
    assert_eq!(
        GrantType::parse("refresh_token"),
        Some(GrantType::RefreshToken)
    );
    assert_eq!(
        GrantType::parse("client_credentials"),
        Some(GrantType::ClientCredentials)
    );
    // The JWT bearer assertion grant uses its long URN wire spelling (RFC 7521 / 7523).
    assert_eq!(
        GrantType::parse("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        Some(GrantType::JwtBearer)
    );
    // The device grant uses its long URN wire spelling (RFC 8628).
    assert_eq!(
        GrantType::parse("urn:ietf:params:oauth:grant-type:device_code"),
        Some(GrantType::DeviceCode)
    );
    assert_eq!(
        GrantType::DeviceCode.as_str(),
        "urn:ietf:params:oauth:grant-type:device_code"
    );

    // Every forbidden or unknown grant type is unrepresentable: it parses to
    // None, so it can never resolve to a handler. ROPC is the headline case.
    for forbidden in [
        "password", // ROPC: structurally excluded.
        "implicit",
        // RFC 8693 token exchange is a separate M13 grant, not serviced here.
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "device_code", // the bare spelling is NOT the serviced URN.
        "",
        "Authorization_Code", // casing is exact.
        "Refresh_Token",      // casing is exact.
        "Client_Credentials", // casing is exact.
        "clientcredentials",
        "jwt-bearer", // the bare token is not the URN.
    ] {
        assert!(
            GrantType::parse(forbidden).is_none(),
            "grant_type {forbidden:?} must be unrepresentable"
        );
    }
}

#[test]
fn response_type_registry_is_the_four_token_free_members_only() {
    // The whole registry is EXACTLY these four members, in this order (issue #17):
    // code, code id_token, id_token, none. There is NO access-token component
    // anywhere, so no token-bearing response type can be expressed. A future edit
    // that added `token`, `code token`, `id_token token`, or `code id_token token`
    // would have to grow ALL and fail this exact-set assertion.
    assert_eq!(
        ResponseType::ALL,
        &[
            ResponseType::Code,
            ResponseType::CodeIdToken,
            ResponseType::IdToken,
            ResponseType::None,
        ]
    );
    assert_eq!(ResponseType::ALL.len(), 4);
    // The always-on base is only `code`; the rest are per-environment legacy types.
    assert_eq!(ResponseType::DEFAULT, &[ResponseType::Code]);

    // Every representable member decomposes into ONLY the token-free components
    // {code, id_token, none}: the access-token component `token` is in none of
    // them, and each round-trips through its own wire spelling.
    for rt in ResponseType::ALL {
        for component in rt.as_str().split(' ') {
            assert!(
                matches!(component, "code" | "id_token" | "none"),
                "{rt:?} decomposes into a forbidden component {component:?}"
            );
        }
        assert_eq!(ResponseType::parse(rt.as_str()), Some(*rt));
    }

    // response_type is an order-insensitive SET: the hybrid parses either way.
    assert_eq!(
        ResponseType::parse("code id_token"),
        Some(ResponseType::CodeIdToken)
    );
    assert_eq!(
        ResponseType::parse("id_token code"),
        Some(ResponseType::CodeIdToken)
    );

    // Every token-bearing spelling, in every order, is unrepresentable: it has no
    // variant and parses to None, so it can never resolve to a handler. `none`
    // combined with anything, and the empty value, are invalid too.
    for forbidden in [
        "token",      // implicit: access token from /authorize.
        "code token", // hybrid with an access token.
        "token code",
        "id_token token", // implicit id_token + access token.
        "token id_token",
        "code id_token token", // full hybrid with an access token.
        "token code id_token",
        "none code", // none does not combine.
        "code none",
        "",
    ] {
        assert!(
            ResponseType::parse(forbidden).is_none(),
            "response_type {forbidden:?} must be unrepresentable"
        );
    }
}

#[test]
fn response_mode_registry_has_no_token_leaking_mode_and_parses_its_three() {
    // The three modes: query, fragment, form_post. Each round-trips; the always-on
    // base is query only (fragment and form_post are per-environment, issue #17).
    assert_eq!(
        ResponseMode::ALL,
        &[
            ResponseMode::Query,
            ResponseMode::Fragment,
            ResponseMode::FormPost,
        ]
    );
    assert_eq!(ResponseMode::DEFAULT, &[ResponseMode::Query]);
    for mode in ResponseMode::ALL {
        assert_eq!(ResponseMode::parse(mode.as_str()), Some(*mode));
    }
    // The JARM `jwt` response mode is M16, not representable here.
    assert!(ResponseMode::parse("jwt").is_none());
    assert!(ResponseMode::parse("").is_none());
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
