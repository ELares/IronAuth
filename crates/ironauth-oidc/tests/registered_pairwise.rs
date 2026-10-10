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

async fn exchange_across_sectors(opaque: bool) {
    use ironauth_oidc::GrantType;
    const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
    let h = Harness::start_store_backed_with(OidcConfig {
        default_access_token_format: if opaque {
            TokenFormat::Opaque
        } else {
            TokenFormat::AtJwt
        },
        ..OidcConfig::default()
    })
    .await;
    let (source, source_secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let (target, target_secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let source_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{source}:{source_secret}"))
    );
    let target_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{target}:{target_secret}"))
    );
    set_policy(&h, &source, &policy("source.example.test")).await;
    set_policy(&h, &target, &policy("target.example.test")).await;
    h.set_client_grant_types(&target, GrantType::TOKEN_EXCHANGE_URN)
        .await;
    h.set_token_exchange_policy(&target, true, false).await;
    let user = h.seed_unique_user().await;
    let issued = tokens(&h, &source, &source_auth, &user).await;
    let source_subject = id_subject(&h, &source, issued["id_token"].as_str().unwrap());
    let expected = h
        .state()
        .resolve_registered_subject(h.scope(), &target.to_string(), &user)
        .await
        .unwrap();
    assert_ne!(expected, source_subject);
    let exchange_body = form(&[
        ("grant_type", GrantType::TOKEN_EXCHANGE_URN),
        ("subject_token", issued["access_token"].as_str().unwrap()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("scope", "openid"),
    ]);
    let (status, _, body) = h.token_with_auth(&exchange_body, Some(&target_auth)).await;
    assert_eq!(status, StatusCode::OK, "pairwise exchange refused");
    let exchanged = json(&body);
    let access = exchanged["access_token"].as_str().unwrap();
    if !opaque {
        // Exchange inherits the source token's audience when none is requested.
        let verified = ironauth_jose::verify(
            access,
            &h.access_token_policy(&source.to_string()),
            &common::verify_clock(),
        )
        .unwrap();
        assert_eq!(verified.claims().subject(), Some(expected.as_str()));
    }
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::AUTHORIZATION, &target_auth)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form(&[("token", access)])))
        .unwrap();
    let (status, _, body) = h.send(request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["active"], true);
    assert_eq!(json(&body)["sub"], expected);
    // A pairwise wire identifier must not skip the local user's lifecycle fence.
    h.set_user_state(&user, ironauth_store::UserState::Blocked)
        .await;
    let (status, _, body) = h.token_with_auth(&exchange_body, Some(&target_auth)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_grant");
}

#[tokio::test]
async fn pairwise_jwt_exchange_rebinds_to_receiver_and_fences_local_user() {
    exchange_across_sectors(false).await;
}

#[tokio::test]
async fn pairwise_opaque_exchange_rebinds_to_receiver_and_fences_local_user() {
    exchange_across_sectors(true).await;
}

#[tokio::test]
async fn pairwise_code_and_refresh_apply_access_rules_to_the_local_account() {
    use ironauth_config::{AccessActionConfig, AccessRuleConfig, ForwardAuthConfig};
    use ironauth_oidc::{forward_auth_rules::access_rules_from_config, oidc_router};
    let h = Harness::start_store_backed().await;
    let (client, secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let auth = format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")));
    set_policy(&h, &client, &policy("rules.example.test")).await;
    let user = h.seed_unique_user().await;
    let issued = tokens(&h, &client, &auth, &user).await;
    assert_ne!(
        id_subject(&h, &client, issued["id_token"].as_str().unwrap()),
        user
    );
    let cfg = ForwardAuthConfig {
        enabled: true,
        rules: vec![AccessRuleConfig {
            name: "deny-local-account".to_owned(),
            action: AccessActionConfig::Deny,
            subject_is: Some(user.clone()),
            ..AccessRuleConfig::default()
        }],
        ..ForwardAuthConfig::default()
    };
    let router = oidc_router(
        h.state()
            .clone()
            .with_access_rules(access_rules_from_config(&cfg, &[]).unwrap()),
    );
    // Issue the code without rules so this specifically tests the mint's gate.
    let code = h
        .issue_code_for_subject(&client.to_string(), &user, "openid")
        .await;
    for body in [
        form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
        ]),
        form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", issued["refresh_token"].as_str().unwrap()),
        ]),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::AUTHORIZATION, &auth)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let (status, _, body) = common::send_through(router.clone(), request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"], "access_denied");
    }
}

async fn delegated_pairwise_identity(transaction: bool) {
    use ironauth_jose::{ExpectedTyp, TokenTyp};
    use ironauth_oidc::{GrantType, transaction_tokens::TRANSACTION_TOKEN_TYPE};
    const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
    const DOMAIN: &str = "https://transactions.example.test";
    let mut h = Harness::start_store_backed().await;
    if transaction {
        h.install_transaction_token_domain(DOMAIN);
    }
    let (source, source_secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let (target, target_secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let source_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{source}:{source_secret}"))
    );
    let target_auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{target}:{target_secret}"))
    );
    set_policy(&h, &source, &policy("delegator.example.test")).await;
    set_policy(&h, &target, &policy("delegate.example.test")).await;
    h.set_client_grant_types(&target, GrantType::TOKEN_EXCHANGE_URN)
        .await;
    let user = h.seed_unique_user().await;
    let actor = h.seed_unique_user().await;
    let subject_tokens = tokens(&h, &source, &source_auth, &user).await;
    let actor_tokens = tokens(&h, &source, &source_auth, &actor).await;
    let mut params = vec![
        ("grant_type", GrantType::TOKEN_EXCHANGE_URN),
        (
            "subject_token",
            subject_tokens["access_token"].as_str().unwrap(),
        ),
        ("subject_token_type", ACCESS),
        (
            "actor_token",
            actor_tokens["access_token"].as_str().unwrap(),
        ),
        ("actor_token_type", ACCESS),
        ("scope", "openid"),
    ];
    if transaction {
        params.push(("requested_token_type", TRANSACTION_TOKEN_TYPE));
    }
    let body = form(&params);
    let (status, _, response) = h.token_with_auth(&body, Some(&target_auth)).await;
    assert_eq!(status, StatusCode::OK, "pairwise delegation refused");
    let issued = json(&response);
    let policy = if transaction {
        ironauth_jose::VerificationPolicy::new(
            vec![ironauth_jose::JwsAlgorithm::EdDsa],
            vec![h.verifying_key()],
            h.issuer().to_owned(),
            DOMAIN.to_owned(),
            ExpectedTyp::Required(TokenTyp::TransactionToken),
        )
        .unwrap()
    } else {
        h.access_token_policy(&source.to_string())
    };
    let verified = ironauth_jose::verify(
        issued["access_token"].as_str().unwrap(),
        &policy,
        &common::verify_clock(),
    )
    .unwrap();
    let expected_user = h
        .state()
        .resolve_registered_subject(h.scope(), &target.to_string(), &user)
        .await
        .unwrap();
    let expected_actor = h
        .state()
        .resolve_registered_subject(h.scope(), &target.to_string(), &actor)
        .await
        .unwrap();
    assert_eq!(verified.claims().subject(), Some(expected_user.as_str()));
    assert_eq!(verified.claims().get("act").unwrap()["sub"], expected_actor);
    assert_ne!(expected_user, user);
    assert_ne!(expected_actor, actor);
    // Both identities must still pass lifecycle checks using their local IDs.
    h.set_user_state(&actor, ironauth_store::UserState::Blocked)
        .await;
    let (status, _, response) = h.token_with_auth(&body, Some(&target_auth)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&response)["error"], "invalid_grant");
}

#[tokio::test]
async fn pairwise_delegation_rebinds_subject_and_actor_to_receiver() {
    delegated_pairwise_identity(false).await;
}

#[tokio::test]
async fn pairwise_transaction_delegation_rebinds_subject_and_actor_to_receiver() {
    delegated_pairwise_identity(true).await;
}
