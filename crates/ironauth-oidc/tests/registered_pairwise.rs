// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real code/refresh/UserInfo/introspection paths with persisted client policy.
//! Policies are seeded through the repository; registration API coverage remains separate.
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_config::{OidcConfig, TokenFormat};
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{ClientId, ClientSubjectPolicy};
use serde_json::Value;

async fn set_policy(h: &Harness, client: &ClientId, policy: &ClientSubjectPolicy) {
    let current = h
        .store()
        .scoped(h.scope())
        .clients()
        .subject_policy(client)
        .await
        .unwrap();
    let (actor, corr) = h.seeding_actor();
    h.store()
        .scoped(h.scope())
        .acting(actor, corr)
        .clients()
        .set_subject_policy(h.env(), &current, policy, &current.redirect_uris)
        .await
        .unwrap();
}

fn policy(sector: &str) -> ClientSubjectPolicy {
    ClientSubjectPolicy::Pairwise {
        sector_identifier: sector.to_owned(),
        sector_identifier_uri: Some(format!("https://{sector}/redirects.json")),
    }
}

async fn tokens(h: &Harness, client: &ClientId, auth: &str, user: &str) -> Value {
    let cid = client.to_string();
    h.grant_consent_scoped(user, &cid, Some("openid profile offline_access"))
        .await;
    let cookie = h.session_cookie(user).await;
    let query = format!(
        "response_type=code&client_id={cid}&redirect_uri={}&scope={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile offline_access")
    );
    let (status, headers, _) = h.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let code = location_param(&headers, "code").unwrap_or_else(|| {
        panic!(
            "authorization refused: error={:?}, description={:?}, redirect_kind={:?}",
            location_param(&headers, "error"),
            location_param(&headers, "error_description"),
            headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| (
                    v.contains("login"),
                    v.contains("consent"),
                    v.contains("select"),
                    v.contains("interaction")
                ))
        )
    });
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _, body) = h.token_with_auth(&exchange, Some(auth)).await;
    assert_eq!(status, StatusCode::OK, "code exchange rejected");
    json(&body)
}

fn id_subject(h: &Harness, client: &ClientId, token: &str) -> String {
    let policy = h.id_token_policy(&client.to_string());
    ironauth_jose::verify(token, &policy, &common::verify_clock())
        .expect("ID token signature, issuer, audience, type and expiry verify")
        .claims()
        .subject()
        .unwrap()
        .to_owned()
}

async fn assert_consumers(h: &Harness, token: &str, auth: &str, expected: &str) {
    let request = Request::builder()
        .uri("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = h.send(request).await;
    assert_eq!(status, StatusCode::OK, "UserInfo rejected");
    assert_eq!(json(&body)["sub"], expected);
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::AUTHORIZATION, auth)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form(&[("token", token)])))
        .unwrap();
    let (status, _, body) = h.send(request).await;
    assert_eq!(status, StatusCode::OK);
    let introspection = json(&body);
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["sub"], expected);
}

async fn exercise(opaque: bool) {
    let mut config = OidcConfig::default();
    if opaque {
        config.default_access_token_format = TokenFormat::Opaque;
    }
    let h = Harness::start_store_backed_with(config.clone()).await;
    let (client, secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let auth = format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")));
    set_policy(&h, &client, &policy("sector.example.test")).await;
    let user = h.seed_unique_user().await;
    let issued = tokens(&h, &client, &auth, &user).await;
    let expected = id_subject(&h, &client, issued["id_token"].as_str().unwrap());
    assert_ne!(expected, user);
    assert_eq!(expected.len(), 43);
    let access = issued["access_token"].as_str().unwrap();
    assert_eq!(access.starts_with("ira_at_"), opaque);
    assert_consumers(&h, access, &auth, &expected).await;
    // A genuinely fresh pool, issuer registry, state and subject cache.
    let restarted = h.restart(&config).await;
    assert_consumers(&restarted, access, &auth, &expected).await;
    let refresh = issued["refresh_token"]
        .as_str()
        .expect("offline refresh credential");
    let (status, _, body) = restarted
        .token_with_auth(
            &form(&[("grant_type", "refresh_token"), ("refresh_token", refresh)]),
            Some(&auth),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "refresh rejected");
    assert_consumers(
        &restarted,
        json(&body)["access_token"].as_str().unwrap(),
        &auth,
        &expected,
    )
    .await;
    // Per-sector derivation remains the same across distinct registered clients.
    let (same_sector, _) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    set_policy(&h, &same_sector, &policy("sector.example.test")).await;
    assert_eq!(
        h.state()
            .resolve_registered_subject(h.scope(), &same_sector.to_string(), &user)
            .await
            .unwrap(),
        expected
    );
    let (different_sector, _) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    set_policy(&h, &different_sector, &policy("other.example.test")).await;
    assert_ne!(
        h.state()
            .resolve_registered_subject(h.scope(), &different_sector.to_string(), &user)
            .await
            .unwrap(),
        expected
    );
}

#[tokio::test]
async fn pairwise_jwt_code_userinfo_introspection_refresh_and_restart_agree() {
    exercise(false).await;
}

#[tokio::test]
async fn pairwise_opaque_code_userinfo_introspection_refresh_and_restart_agree() {
    exercise(true).await;
}

#[tokio::test]
async fn public_code_flow_preserves_its_identity_after_a_policy_switch() {
    let h = Harness::start_store_backed().await;
    let (client, secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let auth = format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")));
    let user = h.seed_unique_user().await;
    let initial = tokens(&h, &client, &auth, &user).await;
    assert_eq!(
        id_subject(&h, &client, initial["id_token"].as_str().unwrap()),
        user
    );
    set_policy(&h, &client, &policy("sector.example.test")).await;
    let after = tokens(&h, &client, &auth, &user).await;
    assert_eq!(
        id_subject(&h, &client, after["id_token"].as_str().unwrap()),
        user
    );
    assert_consumers(&h, after["access_token"].as_str().unwrap(), &auth, &user).await;
    // This proves retained identity, not pairwise privacy for the legacy binding.
}

#[tokio::test]
async fn opaque_machine_introspection_retains_the_service_account_subject() {
    let h = Harness::start_store_backed_with(OidcConfig {
        default_access_token_format: TokenFormat::Opaque,
        ..OidcConfig::default()
    })
    .await;
    let (client, secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let auth = format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")));
    let (status, _, body) = h
        .token_with_auth(
            &form(&[("grant_type", "client_credentials"), ("scope", "read")]),
            Some(&auth),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let issued = json(&body);
    let access = issued["access_token"].as_str().unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::AUTHORIZATION, auth)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form(&[("token", access)])))
        .unwrap();
    let (status, _, body) = h.send(request).await;
    assert_eq!(status, StatusCode::OK);
    let result = json(&body);
    assert_eq!(result["active"], true);
    assert!(
        ironauth_store::ServiceAccountId::parse_in_scope(
            result["sub"].as_str().unwrap(),
            &h.scope()
        )
        .is_ok()
    );
}
