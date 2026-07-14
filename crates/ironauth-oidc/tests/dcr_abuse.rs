// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dynamic Client Registration abuse controls (issue #31), over a real database.
//!
//! Drives the registration endpoint through the live router with the #31 controls
//! layered on the #30 create: the exposure switch (`closed` / `token_gated` /
//! `open`), initial access tokens carrying reusable policy chains, the per-primitive
//! policy engine bound at registration AND at RFC 7592 update time, the
//! per-environment client quota and endpoint rate limit (typed error + audit event),
//! and the unverified-client quarantine (consent-always and https-only redirects
//! until an admin verifies the client). Cross-tenant isolation and the
//! diagnosable-out-of-band posture (AC5) are exercised alongside.
//!
//! The five acceptance criteria are annotated inline: AC1 policy chain binds
//! registration and 7592 updates; AC2 quarantine consent-always + restricted
//! redirects until verify lifts both; AC3 quota / rate-limit rejection is a typed
//! error plus an audit event; AC4 closed / `token_gated` refuses unauthorized
//! registration; AC5 policies and rejections are opaque on the wire but diagnosable.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{
    FAR_FUTURE_MICROS, Harness, PKCE_CHALLENGE, REDIRECT_URI, enc, location, location_param,
    send_through,
};
use ironauth_config::{OidcConfig, RegistrationMode};
use ironauth_oidc::{PolicyPrimitive, serialize_chain};
use serde_json::{Value, json};

/// A registration config with a given exposure mode, the endpoint mounted, and
/// confidential PKCE relaxed (so a confidential DCR client can drive the token/
/// authorize path without PKCE).
fn config(mode: RegistrationMode) -> OidcConfig {
    OidcConfig {
        registration_enabled: true,
        registration_mode: mode,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    }
}

/// The per-environment registration endpoint path for the harness scope.
fn register_path(h: &Harness) -> String {
    format!(
        "/t/{}/e/{}/connect/register",
        h.scope().tenant(),
        h.scope().environment()
    )
}

/// Parse a response body as JSON, or `Null` for an empty body.
fn parse_or_null(text: &str) -> Value {
    if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(text).unwrap_or(Value::Null)
    }
}

/// `POST` a JSON metadata document to the registration endpoint, optionally
/// Bearer-authenticated with an initial access token.
async fn register(h: &Harness, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    send_json(h, "POST", &register_path(h), token, Some(body)).await
}

/// Drive a JSON request (optionally Bearer-authenticated) through the router.
async fn send_json(
    h: &Harness,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request builds");
    let (status, _headers, text) = h.send(request).await;
    (status, parse_or_null(&text))
}

/// Strip the deployment origin from a `registration_client_uri`, yielding the path
/// the in-process router is driven with.
fn to_path(uri: &str) -> String {
    uri.strip_prefix(common::ISSUER_BASE)
        .expect("registration_client_uri is under the issuer base")
        .to_owned()
}

/// Parse a `client_id` string from a registration response into a scoped id.
fn client_id_of(h: &Harness, reg: &Value) -> ironauth_store::ClientId {
    h.store()
        .scoped(h.scope())
        .clients()
        .parse_id(reg["client_id"].as_str().expect("client_id"))
        .expect("client id parses")
}

#[tokio::test]
async fn closed_mode_refuses_every_public_registration() {
    // AC4: a `closed` environment refuses public registration whether or not a token
    // is presented; clients are created only through the management API.
    let h = Harness::start_with(config(RegistrationMode::Closed)).await;

    let (status, body) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "access_denied");

    // Even a well-formed-looking token cannot open a closed environment.
    let (status, body) = register(
        &h,
        Some("ira_iat_anything"),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn token_gated_requires_a_valid_token() {
    // AC4: a `token_gated` environment refuses an anonymous or bad-token registration
    // (both a uniform 403 access_denied, so an attacker cannot tell an unknown token
    // from an expired or exhausted one), and accepts one bearing a valid token. A
    // token-vouched client is NOT quarantined.
    let h = Harness::start_with(config(RegistrationMode::TokenGated)).await;

    // Anonymous: refused.
    let (status, body) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "access_denied");

    // A token that was never minted: the same uniform refusal (no oracle).
    let (status, body) = register(
        &h,
        Some("ira_iat_never_minted"),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "access_denied");

    // A valid, unconstrained token: the registration succeeds and the client is
    // trusted (not quarantined).
    h.mint_iat("ira_iat_valid", "[]", FAR_FUTURE_MICROS, None)
        .await;
    let (status, reg) = register(
        &h,
        Some("ira_iat_valid"),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let id = client_id_of(&h, &reg);
    assert!(
        !h.client_quarantined(&id).await,
        "a token-vouched client starts verified, not quarantined"
    );
}

#[tokio::test]
async fn an_initial_access_token_usage_limit_is_enforced() {
    // A single-use token authorizes exactly one registration; the second attempt with
    // the same token is refused (exhausted, indistinguishable from invalid). The
    // consume is atomic, so a usage limit cannot be raced past.
    let h = Harness::start_with(config(RegistrationMode::TokenGated)).await;
    h.mint_iat("ira_iat_once", "[]", FAR_FUTURE_MICROS, Some(1))
        .await;

    let (status, reg) = register(
        &h,
        Some("ira_iat_once"),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");

    let (status, body) = register(
        &h,
        Some("ira_iat_once"),
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn a_policy_chain_binds_registration_and_a_7592_update() {
    // AC1: a token's policy chain applies to the submitted metadata at registration
    // AND rides on the client for its lifetime, so an RFC 7592 update re-applies the
    // SAME chain. A `force` primitive overrides whatever the client submits, at both
    // moments.
    let h = Harness::start_with(config(RegistrationMode::TokenGated)).await;
    let chain = serialize_chain(&[PolicyPrimitive::Force {
        property: "token_endpoint_auth_method".to_owned(),
        value: json!("client_secret_post"),
    }])
    .expect("serialize chain");
    h.mint_iat("ira_iat_force", &chain, FAR_FUTURE_MICROS, None)
        .await;

    // Register submitting client_secret_basic: the forced value wins.
    let (status, reg) = register(
        &h,
        Some("ira_iat_force"),
        json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_basic"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    assert_eq!(
        reg["token_endpoint_auth_method"], "client_secret_post",
        "the force primitive overrides the submitted auth method at registration"
    );
    let uri = to_path(reg["registration_client_uri"].as_str().expect("uri"));
    let token = reg["registration_access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    // A 7592 PUT trying to escape the forced value back to client_secret_basic: the
    // stored chain re-applies, so the forced value still wins.
    let (status, updated) = send_json(
        &h,
        "PUT",
        &uri,
        Some(&token),
        Some(json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_basic"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(
        updated["token_endpoint_auth_method"], "client_secret_post",
        "the SAME policy chain binds the RFC 7592 update, not just the registration"
    );
}

#[tokio::test]
async fn a_rejected_policy_is_opaque_on_the_wire_but_audited() {
    // AC5: a `reject` primitive refuses a submitted property, but the wire response is
    // the GENERIC invalid_client_metadata (it never names the offending property or
    // the operator's policy), while the actionable diagnostic is recorded out of band
    // as a dcr.policy_rejected audit event.
    let h = Harness::start_with(config(RegistrationMode::TokenGated)).await;
    let chain = serialize_chain(&[PolicyPrimitive::Reject {
        property: "jwks_uri".to_owned(),
    }])
    .expect("serialize chain");
    h.mint_iat("ira_iat_reject", &chain, FAR_FUTURE_MICROS, None)
        .await;

    let (status, body) = register(
        &h,
        Some("ira_iat_reject"),
        json!({
            "redirect_uris": ["https://rp.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://rp.example/jwks.json"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_client_metadata",
        "the wire error is the generic metadata error, never the policy detail"
    );
    let wire = body.to_string();
    assert!(
        !wire.contains("jwks_uri") && !wire.contains("policy") && !wire.contains("reject"),
        "the wire response leaks neither the property nor the policy: {wire}"
    );

    // The diagnostic is recoverable out of band.
    assert_eq!(
        h.count_audit_action("dcr.policy_rejected").await,
        1,
        "a dcr.policy_rejected audit event records the rejection"
    );

    // FIX 11: the offending property is recorded as the audit event's DETAIL dimension,
    // so an operator reading the audit table alone (not the structured log) gets the
    // actionable property. It is operator-authored, so it is safe there; the wire
    // response stayed opaque above.
    let rejected = h
        .store()
        .scoped(h.scope())
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .find(|row| row.action == "dcr.policy_rejected")
        .expect("a dcr.policy_rejected audit row");
    assert_eq!(
        rejected.detail.as_deref(),
        Some("jwks_uri"),
        "the audit detail names the offending property"
    );
}

#[tokio::test]
async fn the_per_environment_quota_is_a_typed_refusal_with_an_audit_event() {
    // AC3: at the per-environment registered-client cap, a further registration is a
    // typed 403 access_denied AND a dcr.quota_hit audit event. The cap is enforced
    // atomically under a per-scope advisory lock, so it cannot be raced past.
    let h = Harness::start_with(OidcConfig {
        registration_max_clients: 1,
        ..config(RegistrationMode::Open)
    })
    .await;

    let (status, reg) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");

    let (status, body) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb2"] }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "access_denied");
    assert_eq!(
        h.count_audit_action("dcr.quota_hit").await,
        1,
        "the quota block records a dcr.quota_hit audit event"
    );
}

#[tokio::test]
async fn the_endpoint_rate_limit_is_a_429_with_an_audit_event() {
    // AC3: over the endpoint's fixed-window rate limit, a registration is refused with
    // a 429 temporarily_unavailable AND a dcr.rate_limited audit event.
    let h = Harness::start_with(OidcConfig {
        registration_rate_limit: 1,
        ..config(RegistrationMode::Open)
    })
    .await;

    let (status, reg) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");

    let (status, body) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb2"] }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable");
    assert_eq!(
        h.count_audit_action("dcr.rate_limited").await,
        1,
        "the rate-limit block records a dcr.rate_limited audit event"
    );
}

#[tokio::test]
async fn quarantine_forces_consent_even_with_skip_consent_until_verified() {
    // AC2: an anonymously-registered (open) client starts quarantined, and a
    // quarantined client NEVER gets the first-party consent carve-out: even with
    // skip_consent/implicit set, consent is ALWAYS required, until an admin verifies
    // it (which restores the carve-out).
    let h = Harness::start_with(config(RegistrationMode::Open)).await;
    let (status, reg) = register(&h, None, json!({ "redirect_uris": [REDIRECT_URI] })).await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let client_id = reg["client_id"].as_str().expect("client_id").to_owned();
    let id = client_id_of(&h, &reg);
    assert!(
        h.client_quarantined(&id).await,
        "an anonymous open registration starts quarantined"
    );

    // Turn on the trusted-client carve-out that verification would normally honor.
    h.configure_client_policy(&id, "implicit", true, false, None)
        .await;

    // A fresh, authenticated subject with NO recorded consent: the quarantined client
    // does not skip consent, so no code is issued (the flow diverts to consent).
    let subject = h.seed_unique_user().await;
    let cookie = h.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = h.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    assert!(
        location_param(&headers, "code").is_none(),
        "a quarantined client must not skip consent: no code is issued while quarantined"
    );

    // Verify lifts the quarantine; now the skip_consent carve-out applies again.
    h.verify_client(&id).await;
    assert!(
        !h.client_quarantined(&id).await,
        "verification lifts quarantine"
    );

    let subject2 = h.seed_unique_user().await;
    let cookie2 = h.session_cookie(&subject2).await;
    let (status, headers, body) = h.authorize_with_cookie(&query, &cookie2).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a verified client with skip_consent skips consent and issues a code"
    );
}

#[tokio::test]
async fn quarantine_restricts_redirects_to_https_until_verified() {
    // AC2: a quarantined client's EFFECTIVE redirect set is restricted to its https
    // targets: an https redirect works (subject to consent) but a native/loopback
    // http redirect is refused with a page error, until verification lifts the
    // restriction.
    let h = Harness::start_with(config(RegistrationMode::Open)).await;
    let (status, reg) = register(
        &h,
        None,
        json!({
            "application_type": "native",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["https://rp.example/cb", "http://127.0.0.1:52000/cb"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let client_id = reg["client_id"].as_str().expect("client_id").to_owned();
    let id = client_id_of(&h, &reg);
    assert!(
        h.client_quarantined(&id).await,
        "the client starts quarantined"
    );

    // A public client requires PKCE, so every authorize below carries the S256
    // challenge. Consent is granted so the flow reaches the redirect decision.
    let https = "https://rp.example/cb";
    let loopback = "http://127.0.0.1:52000/cb";
    let authorize = async |redirect: &str, cookie: &str| {
        let query = format!(
            "response_type=code&client_id={client_id}&redirect_uri={}&\
             code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
            enc(redirect)
        );
        h.authorize_with_cookie(&query, cookie).await
    };

    // https redirect, while quarantined: PASSES the redirect restriction (the
    // restricted set includes https), so it reaches the consent gate rather than the
    // redirect-refusal page error the loopback case gets below. A quarantined client
    // still re-prompts consent (FIX 4), so no code is issued yet even with a recorded
    // consent; the point here is that the https redirect was NOT refused.
    let subject = h.seed_unique_user().await;
    h.grant_consent(&subject, &client_id).await;
    let cookie = h.session_cookie(&subject).await;
    let (status, headers, body) = authorize(https, &cookie).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "an https redirect passes the quarantine restriction and reaches consent: {body}"
    );
    assert!(
        location(&headers).is_some(),
        "the https redirect was accepted (a redirect to consent), not refused with a page error"
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "a quarantined client re-prompts consent even for an allowed https redirect (FIX 4)"
    );

    // http loopback redirect, while quarantined: refused with a page error (never a
    // redirect that could be turned into an open redirector).
    let subject2 = h.seed_unique_user().await;
    h.grant_consent(&subject2, &client_id).await;
    let cookie2 = h.session_cookie(&subject2).await;
    let (status, headers, _body) = authorize(loopback, &cookie2).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-https redirect is refused for a quarantined client"
    );
    assert!(
        location(&headers).is_none(),
        "the quarantine redirect refusal is a page error, not a redirect"
    );

    // Verify, then the loopback redirect is accepted.
    h.verify_client(&id).await;
    let subject3 = h.seed_unique_user().await;
    h.grant_consent(&subject3, &client_id).await;
    let cookie3 = h.session_cookie(&subject3).await;
    let (status, headers, body) = authorize(loopback, &cookie3).await;
    assert_eq!(status, StatusCode::FOUND, "loopback after verify: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "verification lifts the redirect restriction"
    );
}

#[tokio::test]
async fn a_registration_is_not_reachable_under_another_tenants_scope() {
    // Cross-tenant isolation: a token minted in one environment cannot be presented
    // against another tenant's registration endpoint (the scope filter finds no token
    // under the foreign scope, so it is the uniform access_denied). Store-backed so the
    // foreign scope's provisioned signing key resolves in the registry and the request
    // actually reaches the scoped token check (rather than a bare not-found).
    let h = Harness::start_store_backed_with(config(RegistrationMode::TokenGated)).await;
    h.mint_iat("ira_iat_scoped", "[]", FAR_FUTURE_MICROS, None)
        .await;
    let foreign = h.provision_foreign_scope().await;

    let cross_path = format!(
        "/t/{}/e/{}/connect/register",
        foreign.tenant(),
        foreign.environment()
    );
    let (status, body) = send_json(
        &h,
        "POST",
        &cross_path,
        Some("ira_iat_scoped"),
        Some(json!({ "redirect_uris": ["https://rp.example/cb"] })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token is not usable under another tenant's scope: {body}"
    );
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn a_quarantined_client_reprompts_consent_even_with_a_prior_recorded_consent() {
    // AC2 / FIX 4: a quarantined client's RECORDED-consent fast path is disabled too.
    // The prior test proves it never SKIPS consent (implicit/skip_consent carve-out);
    // this proves a PRE-RECORDED consent does not auto-authorize it either. Consent is
    // shown on EVERY authorization until an admin verifies it, which then restores the
    // recorded-consent fast path.
    let h = Harness::start_with(config(RegistrationMode::Open)).await;
    let (status, reg) = register(&h, None, json!({ "redirect_uris": [REDIRECT_URI] })).await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    let client_id = reg["client_id"].as_str().expect("client_id").to_owned();
    let id = client_id_of(&h, &reg);
    assert!(
        h.client_quarantined(&id).await,
        "an anonymous open registration starts quarantined"
    );

    // Record a consent for a subject, then authorize as that subject WHILE quarantined:
    // the recorded consent is IGNORED, so no code is issued (the flow diverts to
    // consent). The confidential (client_secret_basic) client needs no PKCE here (the
    // harness relaxes confidential PKCE), so a plain authorize reaches the consent gate.
    let subject = h.seed_unique_user().await;
    h.grant_consent(&subject, &client_id).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}",
        enc(REDIRECT_URI)
    );
    let cookie = h.session_cookie(&subject).await;
    let (status, headers, body) = h.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    assert!(
        location_param(&headers, "code").is_none(),
        "a quarantined client re-prompts consent even with a prior recorded consent"
    );

    // Verify lifts the quarantine; the SAME recorded consent now authorizes the request.
    h.verify_client(&id).await;
    assert!(
        !h.client_quarantined(&id).await,
        "verification lifts quarantine"
    );
    let cookie2 = h.session_cookie(&subject).await;
    let (status, headers, body) = h.authorize_with_cookie(&query, &cookie2).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "after verify, the recorded consent authorizes the request (fast path restored)"
    );
}

#[tokio::test]
async fn an_unauthorized_request_is_a_uniform_403_even_with_a_malformed_body() {
    // FIX 6: the exposure switch is evaluated BEFORE the body is parsed, so a closed
    // environment refuses with the uniform 403 access_denied regardless of body
    // validity. A malformed body must never downgrade the authorization refusal to a
    // 400 that reveals the request got past the exposure check.
    let h = Harness::start_with(config(RegistrationMode::Closed)).await;
    let request = Request::builder()
        .method("POST")
        .uri(register_path(&h))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("this is not json"))
        .expect("request builds");
    let (status, _headers, text) = h.send(request).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a closed environment refuses a malformed-body request with 403, not 400: {text}"
    );
    let body = parse_or_null(&text);
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_registrations_cannot_race_past_the_quota() {
    // AC3 (race proof): with a per-environment quota of K and M > K concurrent
    // registrations fired at once through routers sharing one store pool, EXACTLY K
    // commit (201) and the rest get the typed QuotaExceeded 403. The count+INSERT under
    // the per-scope advisory lock is the only serialization, so this is a faithful
    // stand-in for M stateless nodes racing on the same database.
    const QUOTA: usize = 3;
    const RACERS: usize = 8;

    let h = Harness::start_with(OidcConfig {
        registration_max_clients: u32::try_from(QUOTA).expect("quota fits"),
        ..config(RegistrationMode::Open)
    })
    .await;
    let path = register_path(&h);
    let body = json!({ "redirect_uris": ["https://rp.example/cb"] }).to_string();

    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let router = h.router();
        let path = path.clone();
        let body = body.clone();
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method("POST")
                .uri(&path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("request builds");
            send_through(router, request).await
        }));
    }

    let mut created = 0_usize;
    let mut refused = 0_usize;
    for task in tasks {
        let (status, _headers, text) = task.await.expect("task joins");
        match status {
            StatusCode::CREATED => created += 1,
            StatusCode::FORBIDDEN => {
                let body = parse_or_null(&text);
                assert_eq!(
                    body["error"], "access_denied",
                    "a quota refusal is a typed access_denied: {text}"
                );
                refused += 1;
            }
            other => panic!("unexpected status {other}: {text}"),
        }
    }
    assert_eq!(
        created, QUOTA,
        "exactly the quota's worth of concurrent registrations commit"
    );
    assert_eq!(
        refused,
        RACERS - QUOTA,
        "every concurrent registration past the cap is a typed QuotaExceeded 403"
    );
}

#[tokio::test]
async fn the_rate_limit_window_resets_after_it_elapses() {
    // FIX 8: the fixed-window rate-limit RESET branch. At limit 1 the first
    // registration is allowed and the second (same window, frozen clock) is a 429.
    // Advancing the manual clock PAST the window starts a fresh window, so the next
    // registration is allowed again.
    let h = Harness::start_with(OidcConfig {
        registration_rate_limit: 1,
        ..config(RegistrationMode::Open)
    })
    .await;

    let (status, reg) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");

    // Second registration within the same window: rate limited.
    let (status, body) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb2"] }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    // Advance the clock past the default 60s window; the next registration opens a
    // FRESH window and is allowed again (the reset branch of the counter upsert).
    h.clock().advance(Duration::from_secs(61));

    let (status, body) = register(
        &h,
        None,
        json!({ "redirect_uris": ["https://rp.example/cb3"] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the window reset allows a fresh registration: {body}"
    );
}

#[tokio::test]
async fn a_restrict_policy_rejects_an_out_of_policy_7592_update() {
    // AC1 (rejection side) / FIX 9: a `Restrict` policy binds the 7592 update, and it
    // REJECTS an out-of-policy value rather than silently transforming it. A token
    // whose chain restricts id_token_signed_response_alg to {EdDSA} registers fine with
    // EdDSA; a later 7592 PUT trying to move it to a value OUTSIDE the allowed set is
    // refused with the opaque invalid_client_metadata, and the rejection is audited.
    let h = Harness::start_with(config(RegistrationMode::TokenGated)).await;
    let chain = serialize_chain(&[PolicyPrimitive::Restrict {
        property: "id_token_signed_response_alg".to_owned(),
        allowed: vec![json!("EdDSA")],
    }])
    .expect("serialize chain");
    h.mint_iat("ira_iat_restrict", &chain, FAR_FUTURE_MICROS, None)
        .await;

    // Register with the allowed value: accepted (the EdDSA-only environment signs it).
    let (status, reg) = register(
        &h,
        Some("ira_iat_restrict"),
        json!({
            "redirect_uris": [REDIRECT_URI],
            "id_token_signed_response_alg": "EdDSA"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{reg}");
    assert_eq!(reg["id_token_signed_response_alg"], "EdDSA");
    let uri = to_path(reg["registration_client_uri"].as_str().expect("uri"));
    let token = reg["registration_access_token"]
        .as_str()
        .expect("token")
        .to_owned();

    // A 7592 PUT moving the property OUTSIDE the allowed set: REJECTED (not transformed).
    let (status, body) = send_json(
        &h,
        "PUT",
        &uri,
        Some(&token),
        Some(json!({
            "redirect_uris": [REDIRECT_URI],
            "id_token_signed_response_alg": "RS256"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an out-of-policy 7592 update is rejected: {body}"
    );
    assert_eq!(body["error"], "invalid_client_metadata");
    let wire = body.to_string();
    assert!(
        !wire.contains("id_token_signed_response_alg") && !wire.contains("policy"),
        "the wire response stays opaque (no property, no policy): {wire}"
    );

    // The rejection is recorded out of band, with the offending property as the audit
    // detail (FIX 11) so the update rejection is diagnosable from the audit table.
    let rejected = h
        .store()
        .scoped(h.scope())
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .find(|row| row.action == "dcr.policy_rejected")
        .expect("a dcr.policy_rejected audit row for the update");
    assert_eq!(
        rejected.detail.as_deref(),
        Some("id_token_signed_response_alg"),
        "the update rejection audits the offending property"
    );
}
