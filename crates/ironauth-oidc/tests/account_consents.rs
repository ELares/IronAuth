// SPDX-License-Identifier: MIT OR Apache-2.0

//! The self-service connected-apps (remembered-consent) surface (issue #88), against a
//! real Postgres.
//!
//! The store tests pin the cascade data model; these pin what an authenticated end user
//! experiences through the HTTP surface, and the security properties that make it safe:
//!
//! - a user lists their OWN active grants, enriched with the client's display name and
//!   logo, and auto-grant clients (`implicit` / `skip_consent`) are EXCLUDED (a stored
//!   grant for one is not meaningfully revocable);
//! - a user revokes their OWN grant to a client; the subject is the authenticated
//!   caller (never a body field), so another user's grant to the SAME client is
//!   untouched (an IDOR on self-service consent would be account takeover);
//! - the revoke CASCADES to the (subject, client) refresh families but NEVER to another
//!   client's or another subject's families;
//! - a cross-origin revoke is refused (issue #196) and revokes nothing;
//! - the revoke is audited to the end user and stamps `revoked_at` from the manual
//!   clock (deterministic).

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, NewRefreshFamily,
    RefreshFamilyId, RefreshTokenId, Scope, refresh_token_digest,
};
use serde_json::{Value, json};

/// A far-future family expiry (year 2100) in epoch microseconds.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// The account API base path for the harness scope.
fn base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/account", scope.tenant(), scope.environment())
}

/// GET `path` with an optional session cookie; return the status and parsed JSON body.
async fn get(harness: &Harness, path: &str, cookie: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let (status, _headers, body) = harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await;
    (status, parse(&body))
}

/// POST JSON `body` to `path` with an optional cookie and extra headers.
async fn post_json(
    harness: &Harness,
    path: &str,
    cookie: Option<&str>,
    body: &Value,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    let (status, _headers, response) = harness
        .send(
            builder
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    (status, parse(&response))
}

/// Parse a response body as JSON, or `Value::Null` for an empty body.
fn parse(body: &str) -> Value {
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).unwrap_or(Value::Null)
    }
}

/// Create a client with `display_name` and return its id.
async fn create_client(harness: &Harness, display_name: &str) -> ClientId {
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .clients()
        .create(harness.env(), display_name)
        .await
        .expect("create client")
}

/// Set a client's `logo_uri` directly (the consent flow reads it to render the client
/// identity; the account list surfaces it).
async fn set_logo(harness: &Harness, client_id: &ClientId, logo_uri: &str) {
    sqlx::query("UPDATE clients SET logo_uri = $1 WHERE id = $2")
        .bind(logo_uri)
        .bind(client_id.to_string())
        .execute(harness.db().owner_pool())
        .await
        .expect("set logo");
}

/// Seed a refresh-token family for `(subject, client_id)`, session-bound or offline, and
/// return its id.
async fn seed_family(
    harness: &Harness,
    scope: Scope,
    subject: &str,
    client_id: &str,
    offline: bool,
) -> RefreshFamilyId {
    let env = harness.env();
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let grant_client = ClientId::generate(env, &scope);
    harness
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &code_id,
                grant_id: &grant_id,
                client_id: &grant_client,
                redirect_uri: "https://client.test/cb",
                browserless: false,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject,
                oauth_scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: None,
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("seed grant");
    let family_id = RefreshFamilyId::generate(env, &scope);
    let jti = RefreshTokenId::generate(env, &scope);
    let digest = refresh_token_digest(&format!("ira_rt_{jti}~seed"));
    harness
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(env), CorrelationId::generate(env))
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &jti,
                token_digest: &digest,
                grant_id: &grant_id,
                subject,
                client_id,
                scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_unix_micros: None,
                offline,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
                dpop_jkt: None,
            },
        )
        .await
        .expect("seed family");
    family_id
}

/// Whether the family reads back revoked, via the owner pool.
async fn family_revoked(harness: &Harness, scope: Scope, family: &RefreshFamilyId) -> bool {
    let revoked_at: Option<i64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint FROM refresh_families \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(family.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("family exists");
    revoked_at.is_some()
}

/// Whether the subject still holds an active (non-revoked) consent to the client, via
/// the store's gate read.
async fn consent_active(harness: &Harness, scope: Scope, subject: &str, client_id: &str) -> bool {
    harness
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref")
        .is_some()
}

#[tokio::test]
async fn list_shows_active_grants_with_metadata_and_excludes_auto_grant() {
    let harness = Harness::start().await;
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;

    // A normal (explicit) client with a logo: it MUST appear with its metadata.
    let visible = create_client(&harness, "Acme Analytics").await;
    set_logo(&harness, &visible, "https://acme.test/logo.png").await;
    // An implicit-consent client and a skip_consent client: both auto-grant, so both
    // MUST be filtered out of the list.
    let implicit = create_client(&harness, "Implicit App").await;
    harness
        .configure_client_policy(&implicit, "implicit", false, true, None)
        .await;
    let skipping = create_client(&harness, "Skip App").await;
    harness
        .configure_client_policy(&skipping, "explicit", true, true, None)
        .await;

    for client in [&visible, &implicit, &skipping] {
        harness.grant_consent(&ada, &client.to_string()).await;
    }

    let (status, body) = get(
        &harness,
        &format!("{}/consents", base(&harness)),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let consents = body["consents"].as_array().expect("consents array");
    assert_eq!(
        consents.len(),
        1,
        "only the explicit client is listed; the auto-grant clients are excluded"
    );
    let entry = &consents[0];
    assert_eq!(entry["client_id"], json!(visible.to_string()));
    assert_eq!(entry["display_name"], json!("Acme Analytics"));
    assert_eq!(entry["logo_uri"], json!("https://acme.test/logo.png"));
}

#[tokio::test]
async fn revoke_is_subject_bound_and_never_touches_another_users_grant() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let grace = harness
        .seed_user("grace@example.test", "another passphrase")
        .await;
    let (_ada_id, ada_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let client = create_client(&harness, "Shared App").await;
    let client_str = client.to_string();

    // BOTH users consent to the SAME client.
    harness.grant_consent(&ada, &client_str).await;
    harness.grant_consent(&grace, &client_str).await;

    // Ada revokes her own grant. The subject is her session, never the body.
    let (status, body) = post_json(
        &harness,
        &format!("{}/consents/revoke", base(&harness)),
        Some(&ada_cookie),
        &json!({ "client_id": client_str }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(true));

    assert!(
        !consent_active(&harness, scope, &ada, &client_str).await,
        "ada's grant is revoked"
    );
    assert!(
        consent_active(&harness, scope, &grace, &client_str).await,
        "grace's grant to the same client is UNTOUCHED (subject-bound revoke)"
    );
}

#[tokio::test]
async fn cross_origin_revoke_is_forbidden_and_revokes_nothing() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let client = create_client(&harness, "Acme App").await;
    let client_str = client.to_string();
    harness.grant_consent(&ada, &client_str).await;

    let (status, body) = post_json(
        &harness,
        &format!("{}/consents/revoke", base(&harness)),
        Some(&cookie),
        &json!({ "client_id": client_str }),
        &[("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], json!("forbidden"));
    assert!(
        consent_active(&harness, scope, &ada, &client_str).await,
        "the cross-origin revoke changed nothing"
    );
}

#[tokio::test]
async fn revoke_cascades_to_the_clients_families_not_others() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let grace = harness
        .seed_user("grace@example.test", "another passphrase")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;

    let target = create_client(&harness, "Target App").await;
    let other = create_client(&harness, "Other App").await;
    let target_str = target.to_string();
    let other_str = other.to_string();
    harness.grant_consent(&ada, &target_str).await;

    // Ada's family for the target client (offline, to prove offline is cascaded), plus
    // two decoys: ada's family for another client, and grace's family for the target.
    let ada_target = seed_family(&harness, scope, &ada, &target_str, true).await;
    let ada_other = seed_family(&harness, scope, &ada, &other_str, false).await;
    let grace_target = seed_family(&harness, scope, &grace, &target_str, false).await;

    let (status, body) = post_json(
        &harness,
        &format!("{}/consents/revoke", base(&harness)),
        Some(&cookie),
        &json!({ "client_id": target_str }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(true));
    assert_eq!(
        body["families_revoked"],
        json!(1),
        "exactly ada's family for the target client is revoked"
    );
    assert!(
        family_revoked(&harness, scope, &ada_target).await,
        "ada's target-client family (offline) is revoked"
    );
    assert!(
        !family_revoked(&harness, scope, &ada_other).await,
        "ada's family for a DIFFERENT client survives"
    );
    assert!(
        !family_revoked(&harness, scope, &grace_target).await,
        "grace's family for the SAME client survives (subject-bound)"
    );
}

#[tokio::test]
async fn revoke_is_audited_and_stamps_revoked_at_from_the_manual_clock() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let client = create_client(&harness, "Acme App").await;
    let client_str = client.to_string();
    harness.grant_consent(&ada, &client_str).await;

    // Advance the manual clock to a known instant; the revoke must stamp exactly this.
    harness.clock().advance(Duration::from_secs(5));
    let expected_micros: i64 = 5_000_000;

    let (status, _body) = post_json(
        &harness,
        &format!("{}/consents/revoke", base(&harness)),
        Some(&cookie),
        &json!({ "client_id": client_str }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Exactly one consent.revoke audit row is written for the end user.
    let audit = harness
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit");
    let revokes: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "consent.revoke")
        .collect();
    assert_eq!(revokes.len(), 1, "the revoke is audited exactly once");
    assert_eq!(revokes[0].target_kind, "con", "it targets the consent row");

    // revoked_at was stamped from the clock seam, deterministically.
    let revoked_at: Option<i64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint FROM consents \
         WHERE subject = $1 AND client_id = $2 AND tenant_id = $3 AND environment_id = $4",
    )
    .bind(&ada)
    .bind(&client_str)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("consent row");
    assert_eq!(
        revoked_at,
        Some(expected_micros),
        "revoked_at is stamped from the manual clock, not SystemTime"
    );
}
