// SPDX-License-Identifier: MIT OR Apache-2.0

//! User consent (connected apps) management on the management API (issue #88, PR 5),
//! end to end over a real database.
//!
//! What these prove, driven through the HTTP surface an operator actually calls:
//!
//! - a user's remembered consents are listable by subject, enriched with the client's
//!   display metadata, and auto-grant clients (`implicit` / `skip_consent`) are
//!   EXCLUDED (a stored grant for one is not meaningfully revocable);
//! - a revoke stamps the consent revoked and CASCADES to the (subject, client) refresh
//!   families (session-bound AND offline) in the same transaction, scope-tight so
//!   another subject's or client's families survive;
//! - both the user id and the client id are scope-fenced: a cross-scope id is the
//!   uniform not-found, never an oracle;
//! - the revoke is a security mutation, sudo-gated (a stale privilege is challenged and
//!   executes nothing), and audited.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{ClientId, CorrelationId, RefreshFamilyId, Scope};
use serde_json::Value;

fn body_json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|error| panic!("json body ({error}): {body}"))
}

/// The user-scoped consent base path for `(scope, subject)`.
fn consents_path(scope: Scope, subject: &str) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/users/{subject}/consents",
        scope.tenant(),
        scope.environment()
    )
}

/// The revoke path for `(scope, subject, client)`.
fn revoke_path(scope: Scope, subject: &str, client_id: &str) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/users/{subject}/consents/{client_id}/revoke",
        scope.tenant(),
        scope.environment()
    )
}

/// Create a client with `display_name` in `scope`, through the app-role store, and
/// return its id.
async fn create_client(h: &Harness, scope: Scope, display_name: &str) -> ClientId {
    let env = Env::system();
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, display_name)
        .await
        .expect("create client")
}

/// Configure a client's consent mode and `skip_consent`, so the auto-grant filter can
/// be exercised.
async fn configure_policy(h: &Harness, scope: Scope, client_id: &ClientId, mode: &str, skip: bool) {
    let env = Env::system();
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .configure_policy(&env, client_id, mode, skip, true, None)
        .await
        .expect("configure policy");
}

/// Record `subject`'s consent to `client_id` in `scope`, through the app-role store.
async fn grant_consent(h: &Harness, scope: Scope, subject: &str, client_id: &str) {
    let env = Env::system();
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("grant consent");
}

/// Whether the family reads back revoked, via the owner pool.
async fn family_revoked(h: &Harness, scope: Scope, family: &RefreshFamilyId) -> bool {
    let revoked_at: Option<i64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint FROM refresh_families \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(family.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(h.db().owner_pool())
    .await
    .expect("family exists");
    revoked_at.is_some()
}

#[tokio::test]
async fn list_and_revoke_happy_path_with_cascade() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let subject = Harness::fresh_user_id(scope).to_string();
    let client = create_client(&h, scope, "Acme Analytics").await;
    let client_str = client.to_string();
    grant_consent(&h, scope, &subject, &client_str).await;

    // The consent is listed with its display metadata.
    let (status, _, body) = h.get(&consents_path(scope, &subject)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body_json(&body);
    let items = items["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "the user's one consent is listed");
    assert_eq!(items[0]["client_id"], client_str);
    assert_eq!(items[0]["display_name"], "Acme Analytics");

    // Two families for the (subject, client): one session-bound, one offline.
    let session = h.seed_session(scope, &subject).await;
    let bound = h
        .seed_refresh_family(scope, &subject, &client_str, &session, false)
        .await;
    let offline = h
        .seed_refresh_family(scope, &subject, &client_str, &session, true)
        .await;

    // Revoke: the consent flips and the cascade revokes BOTH families.
    let (status, _, body) = h
        .post(&revoke_path(scope, &subject, &client_str), "r1", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view = body_json(&body);
    assert_eq!(view["client_id"], client_str);
    assert_eq!(view["revoked"], Value::Bool(true));
    assert_eq!(view["families_revoked"], 2, "both families were revoked");
    assert!(
        family_revoked(&h, scope, &bound).await,
        "bound family revoked"
    );
    assert!(
        family_revoked(&h, scope, &offline).await,
        "offline family revoked too"
    );

    // The consent drops out of the list.
    let (_, _, body) = h.get(&consents_path(scope, &subject)).await;
    assert!(
        body_json(&body)["items"]
            .as_array()
            .expect("items")
            .is_empty(),
        "the revoked consent is no longer listed"
    );
}

#[tokio::test]
async fn list_excludes_auto_grant_clients() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let subject = Harness::fresh_user_id(scope).to_string();

    let explicit = create_client(&h, scope, "Explicit App").await;
    let implicit = create_client(&h, scope, "Implicit App").await;
    configure_policy(&h, scope, &implicit, "implicit", false).await;
    let skipping = create_client(&h, scope, "Skip App").await;
    configure_policy(&h, scope, &skipping, "explicit", true).await;
    for client in [&explicit, &implicit, &skipping] {
        grant_consent(&h, scope, &subject, &client.to_string()).await;
    }

    let (status, _, body) = h.get(&consents_path(scope, &subject)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body_json(&body);
    let items = items["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "only the explicit client is listed");
    assert_eq!(items[0]["client_id"], explicit.to_string());
}

#[tokio::test]
async fn cross_scope_user_and_client_are_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let other = h.seed_scope().await;
    let subject = Harness::fresh_user_id(scope).to_string();
    let client = create_client(&h, scope, "Acme").await;
    grant_consent(&h, scope, &subject, &client.to_string()).await;

    // A user id minted in ANOTHER scope does not parse in this scope: 404 on both
    // surfaces, never an oracle.
    let foreign_user = Harness::fresh_user_id(other).to_string();
    let (status, _, _) = h.get(&consents_path(scope, &foreign_user)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "foreign user id lists as 404"
    );
    let (status, _, _) = h
        .post(
            &revoke_path(scope, &foreign_user, &client.to_string()),
            "r1",
            "{}",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "foreign user id revokes as 404"
    );

    // A client id minted in ANOTHER scope does not parse in this scope: 404.
    let foreign_client = Harness::fresh_client_id(other);
    let (status, _, _) = h
        .post(&revoke_path(scope, &subject, &foreign_client), "r2", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "foreign client id revokes as 404"
    );
}

#[tokio::test]
async fn revoke_cascade_is_scope_tight_and_audited() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let subject_a = Harness::fresh_user_id(scope).to_string();
    let subject_b = Harness::fresh_user_id(scope).to_string();
    let client_a = create_client(&h, scope, "Client A").await.to_string();
    let client_b = create_client(&h, scope, "Client B").await.to_string();
    grant_consent(&h, scope, &subject_a, &client_a).await;

    let session_a = h.seed_session(scope, &subject_a).await;
    let session_b = h.seed_session(scope, &subject_b).await;
    let target = h
        .seed_refresh_family(scope, &subject_a, &client_a, &session_a, true)
        .await;
    let other_client = h
        .seed_refresh_family(scope, &subject_a, &client_b, &session_a, false)
        .await;
    let other_subject = h
        .seed_refresh_family(scope, &subject_b, &client_a, &session_b, false)
        .await;

    let (status, _, body) = h
        .post(&revoke_path(scope, &subject_a, &client_a), "r1", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body_json(&body)["families_revoked"], 1);
    assert!(family_revoked(&h, scope, &target).await, "target revoked");
    assert!(
        !family_revoked(&h, scope, &other_client).await,
        "same subject, different client: survives"
    );
    assert!(
        !family_revoked(&h, scope, &other_subject).await,
        "different subject, same client: survives"
    );

    // The revoke is audited (exactly one consent.revoke row).
    let audit = h.store().scoped(scope).audit().list().await.expect("audit");
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "consent.revoke")
            .count(),
        1,
        "the admin revoke is audited exactly once"
    );
}

#[tokio::test]
async fn revoke_requires_fresh_privilege() {
    let (h, _clock) = Harness::start_with_sudo(600).await;
    let scope = h.seed_scope().await;
    let subject = Harness::fresh_user_id(scope).to_string();
    let client = create_client(&h, scope, "Acme").await;
    let client_str = client.to_string();
    grant_consent(&h, scope, &subject, &client_str).await;
    let session = h.seed_session(scope, &subject).await;
    let family = h
        .seed_refresh_family(scope, &subject, &client_str, &session, true)
        .await;

    // A revoke WITHOUT a fresh elevation is challenged (RFC 9470), and executes nothing.
    let (status, _, body) = h
        .post(&revoke_path(scope, &subject, &client_str), "r1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale revoke is challenged: {body}"
    );
    assert!(
        !family_revoked(&h, scope, &family).await,
        "the challenged revoke ran no cascade"
    );
}
