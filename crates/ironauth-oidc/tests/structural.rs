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
fn grant_type_registry_expresses_the_seven_serviced_grants_and_no_ropc() {
    // The whole registry is exactly seven variants: the authorization-code grant, the
    // refresh-token grant (issue #21), the client-credentials grant (issue #23), the
    // JWT bearer assertion grant (issue #26), the RFC 8628 device-code grant
    // (issue #24), the RFC 8693 token-exchange grant (issue #125), and the CIBA poll
    // grant (issue #131). No other grant type is representable, and ROPC has no variant
    // at all.
    //
    // The count is a deliberate checkpoint, not bookkeeping: a grant added here is a new
    // minting path, and this list is what makes adding one a decision somebody has to
    // write down rather than something that happens.
    assert_eq!(
        GrantType::ALL,
        &[
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::JwtBearer,
            GrantType::DeviceCode,
            GrantType::TokenExchange,
            GrantType::Ciba,
        ]
    );
    assert_eq!(GrantType::ALL.len(), 7);

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
    // The token-exchange grant likewise uses its long URN wire spelling (RFC 8693).
    assert_eq!(
        GrantType::parse("urn:ietf:params:oauth:grant-type:token-exchange"),
        Some(GrantType::TokenExchange)
    );
    assert_eq!(
        GrantType::TokenExchange.as_str(),
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );

    // CIBA's URN is in the OPENID namespace, not the IETF one every other grant here uses.
    // Spelled out rather than referenced through the constant, because a test that asserts
    // `CIBA_URN` round-trips to `CIBA_URN` would pass with the wrong namespace baked in, and
    // the wrong namespace is a grant no client ever reaches.
    assert_eq!(
        GrantType::parse("urn:openid:params:grant-type:ciba"),
        Some(GrantType::Ciba)
    );
    assert_eq!(
        GrantType::Ciba.as_str(),
        "urn:openid:params:grant-type:ciba"
    );
    assert_eq!(
        GrantType::parse("urn:ietf:params:oauth:grant-type:ciba"),
        None,
        "the IETF spelling is not CIBA's and must not resolve to a handler"
    );

    // Every forbidden or unknown grant type is unrepresentable: it parses to
    // None, so it can never resolve to a handler. ROPC is the headline case.
    for forbidden in [
        "password", // ROPC: structurally excluded.
        "implicit",
        "device_code",    // the bare spelling is NOT the serviced URN.
        "token-exchange", // likewise: the bare token is not the serviced URN.
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

/// Every door that mints a machine token also runs the AGENT GATE (issue #130).
///
/// The gate bounds what an agent may ask for. A gate on one door is not a gate: the other
/// doors stay an unenforced path to the same token, so the property that matters is not
/// "`client_credentials` checks" but "EVERY minting site checks". That is a property of the
/// SET of call sites, which no behavioural test of one door can express.
///
/// This is a source scan, so be clear about what it does and does not prove. It proves the
/// call is PRESENT in every module that builds the mint request, which is exactly the
/// regression the reviewer of this change described: delete the call from two of the three
/// and every behavioural test still passes. It does NOT prove the call is reached on every
/// path through those modules; the behavioural suite in `agent_issuance.rs` does that for
/// the client-credentials door, and the other two doors have no behavioural coverage yet.
///
/// The expected set is pinned EXACTLY rather than as a floor, so a scan that stopped finding
/// anything fails loudly instead of passing vacuously.
#[test]
fn every_machine_token_door_runs_the_agent_gate() {
    /// Every module in this crate that could build a mint request, whether or not it does.
    ///
    /// Read by the FOURTH-DOOR check at the end: the request is built in exactly the three
    /// doors plus the type's own file and its inline tests, so a new module constructing it
    /// is a new ungated path until it joins `DOORS`.
    const CRATE_SOURCES: &[(&str, &str)] = &[
        ("authorize.rs", include_str!("../src/authorize.rs")),
        ("device.rs", include_str!("../src/device.rs")),
        ("token.rs", include_str!("../src/token.rs")),
        ("backchannel.rs", include_str!("../src/backchannel.rs")),
    ];
    const DOORS: &[(&str, &str)] = &[
        (
            "client_credentials.rs",
            include_str!("../src/client_credentials.rs"),
        ),
        ("jwt_bearer.rs", include_str!("../src/jwt_bearer.rs")),
        (
            "token_exchange.rs",
            include_str!("../src/token_exchange.rs"),
        ),
    ];

    for (name, source) in DOORS {
        assert!(
            source.contains("ClientCredentialsMintRequest {"),
            "{name} is pinned as a minting door but no longer builds the mint request; either \
             it stopped minting, in which case remove it here, or this scan has stopped \
             reading the source and is checking nothing"
        );
        assert!(
            source.contains("gate_agent_issuance("),
            "{name} mints a machine token without running the agent gate, so an agent bound \
             to that client can obtain a token outside its declared tool set through it"
        );
    }

    // And no FOURTH door appeared without being added here. The mint request is built in
    // exactly these three modules plus the type's own file and its inline tests; a new
    // module constructing it is a new ungated path until it joins the list above.
    for (name, source) in CRATE_SOURCES {
        assert!(
            !source.contains("ClientCredentialsMintRequest {"),
            "{name} builds the machine mint request but is not a pinned door, so nothing \
             asserts it runs the agent gate; add it to DOORS above and gate it"
        );
    }

    // AND `token_exchange.rs` HAS TWO MINTING PATHS, each of which must run the gate for
    // itself: the ordinary one through `issue()` and the transaction-token branch (issue #133),
    // which returns before `issue()` is reached. The file-level check above cannot express
    // that -- it is satisfied by either call alone, which is exactly why the branch shipped
    // ungated and this scan stayed green.
    //
    // A COUNT rather than a set of file names, because the property is "how many minting paths
    // gate themselves", and the transaction-token request is BUILT in `transaction_tokens.rs`
    // while the gate belongs to its CALLER. Listing that module beside the doors would assert
    // the gate lives where it must not.
    let exchange = include_str!("../src/token_exchange.rs");
    assert_eq!(
        exchange.matches("gate_agent_issuance(").count(),
        2,
        "token_exchange.rs has two minting paths -- the ordinary one through `issue()` and the \
         transaction-token branch -- and each must run the agent gate for itself"
    );
}

/// Every ID-JAG grant test carries the substring the CI lane filters on (issue #133).
///
/// # Why this exists
///
/// `scripts/experimental-prototypes.sh` selects the identity-chaining grant tests with the
/// libtest filter `id_jag`. The first version of that line matched exactly ONE of the four --
/// the unarmed-posture test, which is the only one that still passes with the entire prototype
/// deleted. So the lane whose whole purpose is "this prototype works at its pinned revision"
/// ran green having exercised none of the three checks, nor the floor-and-allowlist fix.
///
/// A filter and a naming convention are two artifacts describing each other with nothing in
/// between. This is the thing in between: name an ID-JAG test without the substring and it
/// fails here rather than being silently dropped from the lane.
///
/// The section is delimited in the source, so this measures what is actually in the file
/// rather than a list somebody remembered to update.
#[test]
fn every_id_jag_grant_test_is_reachable_by_the_lane_filter() {
    const FILTER: &str = "id_jag";
    const MARKER: &str =
        "// IDENTITY CHAINING / ID-JAG, the RECEIVING side (issue #133, PROTOTYPE).";
    let source = include_str!("jwt_bearer.rs");

    let (_, section) = source
        .split_once(MARKER)
        .expect("the ID-JAG section marker is in tests/jwt_bearer.rs");
    // Only items ATTRIBUTED as tests. The first version scanned every `async fn` in the
    // section and counted the two local helpers as tests, which is a guard failing on
    // something it was never measuring -- and worse, a guard that would have pushed a helper
    // to be renamed to satisfy it.
    let mut names: Vec<&str> = Vec::new();
    let mut attributed = false;
    for line in section.lines() {
        let line = line.trim();
        if line == "#[tokio::test]" || line == "#[test]" {
            attributed = true;
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("async fn ")
            .or_else(|| line.strip_prefix("fn "))
        {
            if attributed {
                if let Some(name) = rest.split('(').next() {
                    names.push(name);
                }
            }
            attributed = false;
        } else if !line.is_empty() && !line.starts_with("//") && !line.starts_with('#') {
            attributed = false;
        }
    }

    // A scan that found nothing must fail rather than pass vacuously: zero tests trivially
    // satisfy "every test contains the filter", which is the exact shape of a guard that
    // stopped measuring.
    assert!(
        names.len() >= 4,
        "the ID-JAG section names {} tests; the scan found nothing to check, which is a broken \
         scan rather than a clean result: {names:?}",
        names.len()
    );

    let unreachable: Vec<&&str> = names.iter().filter(|n| !n.contains(FILTER)).collect();
    assert!(
        unreachable.is_empty(),
        "these ID-JAG tests do not contain `{FILTER}`, so the experimental-prototypes lane \
         would not run them: {unreachable:?}"
    );

    // And the lane really does filter on that string. Pinning only the test names would leave
    // the other half of the pair free to move.
    let lane = include_str!("../../../scripts/experimental-prototypes.sh");
    assert!(
        lane.contains(&format!("--test jwt_bearer {FILTER}")),
        "the lane no longer filters `--test jwt_bearer {FILTER}`; this guard is pinning the \
         wrong string and the tests above prove nothing about what CI runs"
    );
}
