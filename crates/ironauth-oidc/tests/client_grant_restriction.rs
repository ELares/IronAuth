// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ONE shared client grant-restriction seam (issue #763). Over a real database
//! (`DATABASE_URL`).
//!
//! # The failure this closes
//!
//! `clients.grant_types` has documented itself since migration 0021 as "the list of
//! OAuth grant types the client is permitted", and exactly one handler honoured it: the
//! device grant. A client registered for `authorization_code` alone could still obtain
//! tokens through `client_credentials`, `jwt_bearer`, and `refresh_token`.
//!
//! That is the Dex `AllowedConnectors` shape, which #125 names by name: a restriction
//! enforced in some grant handlers and not others, where the gap is found by whoever
//! uses it rather than by a test.
//!
//! # Why enforcement is opt-in
//!
//! 0021 defaults the column to `authorization_code` for every client that predates it,
//! so unconditional enforcement would refuse every refresh, client-credentials, and
//! JWT-bearer request from most clients on any existing deployment at once. Off by
//! default makes the safe state reachable without a flag day; the
//! `grant_types_would_refuse` diagnostics tell an operator which clients to widen
//! first.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, REDIRECT_URI, enc, form, json};
use ironauth_config::OidcConfig;
use ironauth_oidc::{ClientAuthMethod, GrantType};
use ironauth_store::ClientId;

/// A harness that ENFORCES the registered allowlist.
async fn enforcing_harness() -> Harness {
    Harness::start_with(OidcConfig {
        enforce_client_grant_types: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await
}

/// Register `grant_types` on a client (the space-separated RFC 7591 list).
async fn set_grants(harness: &Harness, client: &ClientId, grant_types: &str) {
    harness.set_client_grant_types(client, grant_types).await;
}

/// A confidential client and its secret, registered for exactly `grant_types`.
async fn client_registered_for(harness: &Harness, grant_types: &str) -> (ClientId, String) {
    let (id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    set_grants(harness, &id, grant_types).await;
    (id, secret)
}

fn basic(client_id: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// Drive the `client_credentials` grant, which needs no user interaction and so is the
/// cheapest probe of whether a grant is permitted.
async fn client_credentials(harness: &Harness, client: &str, secret: &str) -> (StatusCode, String) {
    let body = form(&[("grant_type", "client_credentials")]);
    let (status, _, body) = harness
        .token_with_auth(&body, Some(&basic(client, secret)))
        .await;
    (status, body)
}

/// THE criterion: a client not registered for a grant is refused it.
#[tokio::test]
async fn a_grant_the_client_is_not_registered_for_is_refused() {
    let harness = enforcing_harness().await;
    // Registered for the code grant ONLY, which is exactly 0021's default.
    let (client, secret) = client_registered_for(&harness, "authorization_code").await;

    let (status, body) = client_credentials(&harness, &client.to_string(), &secret).await;
    assert_ne!(status, StatusCode::OK, "must be refused: {body}");
    // RFC 6749 5.2: the authenticated client is not authorized for this grant type.
    assert_eq!(json(&body)["error"], "unauthorized_client");
}

/// The same client, once REGISTERED for the grant, succeeds.
///
/// Without this the refusal above could be any unrelated failure in the fixture.
#[tokio::test]
async fn registering_the_grant_permits_it() {
    let harness = enforcing_harness().await;
    let (client, secret) =
        client_registered_for(&harness, "authorization_code client_credentials").await;

    let (status, body) = client_credentials(&harness, &client.to_string(), &secret).await;
    assert_eq!(status, StatusCode::OK, "registered grant succeeds: {body}");
}

/// `unauthorized_client` is DISTINCT from `unsupported_grant_type`.
///
/// One says the server does not implement the grant; the other says it does and this
/// client may not use it. The remedies differ (add a feature vs widen a registration),
/// so collapsing them would send an integrator hunting for a server capability that is
/// already present.
#[tokio::test]
async fn a_refused_grant_is_not_reported_as_unsupported() {
    let harness = enforcing_harness().await;
    let (client, secret) = client_registered_for(&harness, "authorization_code").await;

    let (_, refused) = client_credentials(&harness, &client.to_string(), &secret).await;
    assert_eq!(json(&refused)["error"], "unauthorized_client");

    // A grant this build genuinely does not implement.
    let body = form(&[("grant_type", "password")]);
    let (_, _, unsupported) = harness
        .token_with_auth(&body, Some(&basic(&client.to_string(), &secret)))
        .await;
    assert_eq!(json(&unsupported)["error"], "unsupported_grant_type");
}

/// With enforcement OFF (the shipped default) nothing changes.
///
/// The regression guard, and the reason this can ship at all: 0021's default would
/// otherwise refuse most grants for most clients on every existing deployment.
#[tokio::test]
async fn the_default_configuration_enforces_nothing() {
    assert!(
        !OidcConfig::default().enforce_client_grant_types,
        "the shipped default must not enforce"
    );

    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    // Registered for the code grant only, exactly as 0021 leaves it.
    set_grants(&harness, &client, "authorization_code").await;

    let (status, body) = client_credentials(&harness, &client.to_string(), &secret).await;
    assert_eq!(status, StatusCode::OK, "unchanged by default: {body}");
}

/// EVERY grant handler consults the shared seam.
///
/// The acceptance criterion asks for exactly this: an enumeration over every
/// `GrantType` variant, so a grant added without a call to the seam fails a test that
/// walks the variant list rather than silently skipping the check.
///
/// Each grant is driven far enough to reach its own client authentication, which is
/// where the seam sits. A grant whose OTHER preconditions fail first (a missing code, a
/// missing assertion) still must not return `unauthorized_client`, and the assertion is
/// written that way round: the seam is proven present by the REFUSAL appearing when the
/// registration omits the grant.
#[tokio::test]
async fn every_grant_handler_consults_the_shared_seam() {
    let harness = enforcing_harness().await;
    // Registered for the two grants whose credential the handler resolves BEFORE it
    // authenticates the client, so real credentials can be minted first. Stripped to
    // nothing below, after which every grant must be refused by the seam.
    let (client_id, secret) =
        client_registered_for(&harness, "authorization_code refresh_token").await;
    let client = client_id.to_string();
    let auth = basic(&client, &secret);

    // The code and refresh grants resolve their CREDENTIAL before authenticating the
    // client, so a bogus value fails with invalid_grant before the seam is reached.
    // That ordering predates this work and is correct (the code carries the client
    // binding), so the fixture supplies REAL credentials rather than the test asserting
    // something weaker.
    let seed_code = harness.issue_authenticated_code(&client).await;
    let (status, _, body) = harness
        .token_with_auth(
            &form(&[
                ("grant_type", "authorization_code"),
                ("code", &seed_code),
                ("redirect_uri", REDIRECT_URI),
            ]),
            Some(&auth),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed exchange: {body}");
    let real_refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();
    let real_code = harness.issue_authenticated_code(&client).await;

    // A well-formed device-code handle in this scope (see the device arm below).
    let device_code_handle = harness.mint_device_code_handle();
    let auth_req_handle = harness.mint_auth_req_id_handle();

    // NOW strip the registration.
    set_grants(&harness, &client_id, "").await;

    let mut checked = 0_usize;
    for grant in GrantType::ALL {
        // Minimal parameters: enough to reach client authentication and the seam.
        let pairs: Vec<(&str, &str)> = match grant {
            GrantType::AuthorizationCode => vec![
                ("grant_type", grant.as_str()),
                ("code", real_code.as_str()),
                ("redirect_uri", REDIRECT_URI),
            ],
            GrantType::RefreshToken => vec![
                ("grant_type", grant.as_str()),
                ("refresh_token", real_refresh.as_str()),
            ],
            GrantType::ClientCredentials => vec![("grant_type", grant.as_str())],
            GrantType::JwtBearer => {
                vec![("grant_type", grant.as_str()), ("assertion", "irrelevant")]
            }
            // The device code's SCOPE is recovered from the code itself before the
            // client is authenticated, so the handle has to be well formed in this
            // scope to reach the seam. It need not name a live flow: the seam runs
            // immediately after authentication and before any poll state is touched.
            GrantType::DeviceCode => vec![
                ("grant_type", grant.as_str()),
                ("device_code", device_code_handle.as_str()),
            ],
            // The exchange runs the seam immediately after client authentication and
            // BEFORE it revalidates either presented token, so the subject token here
            // need only be present and well-typed. That ordering is the point: a client
            // not registered for this grant is refused without the server telling it
            // anything about the token it sent.
            // CIBA recovers its scope from the `auth_req_id` before the client is
            // authenticated, exactly as the device grant does, so the handle must be well
            // formed in this scope to reach the seam. It need not name a live request: the
            // seam runs right after authentication and before any poll state is touched.
            GrantType::Ciba => vec![
                ("grant_type", grant.as_str()),
                ("auth_req_id", auth_req_handle.as_str()),
            ],
            GrantType::TokenExchange => vec![
                ("grant_type", grant.as_str()),
                ("subject_token", "ira_at_not_a_real_token"),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
            ],
        };
        let (_, _, body) = harness.token_with_auth(&form(&pairs), Some(&auth)).await;
        let error = json(&body)["error"].as_str().unwrap_or_default().to_owned();
        assert_ne!(
            error,
            "unsupported_grant_type",
            "{} is not dispatched at all",
            grant.as_str()
        );
        checked += 1;
        // The seam refuses before any grant-specific validation, so an unregistered
        // grant reads as unauthorized_client and never as invalid_grant.
        assert_eq!(
            error,
            "unauthorized_client",
            "{} did not pass through the shared seam (got {error:?}): {body}",
            grant.as_str()
        );
    }
    assert_eq!(checked, GrantType::ALL.len(), "every variant was exercised");
}

/// The device grant enforces its allowlist even with the token-endpoint setting OFF.
///
/// It has always done so, and RFC 8628 requires the grant be enabled per client. Routing
/// it through the shared seam must not weaken a shipped check into an opt-in one.
#[tokio::test]
async fn the_device_grant_still_enforces_with_the_setting_off() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    // The seeded client is registered for authorization_code only.
    let (status, _, body) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri("/device_authorization")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[
                    ("client_id", client.as_str()),
                    ("scope", &enc("openid")),
                ])))
                .expect("request builds"),
        )
        .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the device allowlist is unconditional: {body}"
    );
}
