// SPDX-License-Identifier: MIT OR Apache-2.0

//! Session and refresh-family FLEET OPERATIONS on the management API (issue #32),
//! end to end over a real database.
//!
//! What these prove, driven through the HTTP surface an operator actually calls:
//!
//! - sessions and refresh families are SEARCHABLE resources (by user, by client, and
//!   by environment, which is the path scope);
//! - a revoke stops the session resolving IMMEDIATELY on the authentication read path;
//! - the revoke CASCADES to the session-bound refresh families while PRESERVING the
//!   `offline_access` families (issue #21's offline-survives-logout semantic), and the
//!   explicit `hard_kill` flag kills those too;
//! - a BULK revoke is scope-FENCED: a foreign session id in the batch is a no-op;
//! - every surface is cross-tenant isolated and returns the uniform not-found for a
//!   foreign id (never an oracle that confirms the resource exists elsewhere).

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::Scope;
use serde_json::Value;

fn body_json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|error| panic!("json body ({error}): {body}"))
}

/// The fleet-ops base path for a scope.
fn base(scope: Scope) -> String {
    format!(
        "/v1/tenants/{}/environments/{}",
        scope.tenant(),
        scope.environment()
    )
}

/// Whether the family with `id` reads back revoked, through the fleet-ops surface.
async fn family_revoked(h: &Harness, scope: Scope, family: &str) -> bool {
    let path = format!("{}/refresh-families/{family}", base(scope));
    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "inspect family: {body}");
    !body_json(&body)["revoked_at_unix_ms"].is_null()
}

#[tokio::test]
async fn sessions_are_searchable_by_user_and_by_client_and_inspectable_by_id() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let alice = Harness::fresh_user_id(scope).to_string();
    let bob = Harness::fresh_user_id(scope).to_string();
    let alice_session = h.seed_session(scope, &alice).await;
    let bob_session = h.seed_session(scope, &bob).await;
    // Alice holds a refresh family with client `cli_alpha`; Bob holds none.
    h.seed_refresh_family(scope, &alice, "cli_alpha", &alice_session, false)
        .await;

    // Every session in the environment.
    let (status, _, body) = h.get(&format!("{}/sessions", base(scope))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body_json(&body)["items"].as_array().expect("items").len();
    assert_eq!(items, 2, "both sessions of the environment are listed");

    // Searchable by user.
    let (status, _, body) = h
        .get(&format!("{}/sessions?subject={alice}", base(scope)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body_json(&body);
    let items = items["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "only alice's session");
    assert_eq!(items[0]["id"], alice_session.to_string());
    assert_eq!(items[0]["subject"], alice);

    // Inspect one by id: a live session reports no end state.
    let (status, _, body) = h
        .get(&format!("{}/sessions/{alice_session}", base(scope)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view = body_json(&body);
    assert_eq!(view["id"], alice_session.to_string());
    assert!(view["revoked_at_unix_ms"].is_null(), "the session is live");
    assert!(view["ended_at_unix_ms"].is_null());

    // Refresh families are a searchable fleet resource in their own right.
    let (status, _, body) = h
        .get(&format!(
            "{}/refresh-families?client_id=cli_alpha",
            base(scope)
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let families = body_json(&body);
    let families = families["items"].as_array().expect("items");
    assert_eq!(families.len(), 1, "only the cli_alpha family");
    assert_eq!(families[0]["subject"], alice);
    assert_eq!(families[0]["session_ref"], alice_session.to_string());
    assert_eq!(families[0]["offline"], false);

    // Bob's session exists but holds no family.
    let (status, _, body) = h
        .get(&format!("{}/refresh-families?subject={bob}", base(scope)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body_json(&body)["items"]
            .as_array()
            .expect("items")
            .is_empty()
    );
    assert!(h.session_resolves(scope, &bob_session).await);
}

#[tokio::test]
async fn revoking_a_session_stops_it_resolving_and_preserves_offline_access() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let user = Harness::fresh_user_id(scope).to_string();
    let session = h.seed_session(scope, &user).await;
    let bound = h
        .seed_refresh_family(scope, &user, "cli_bound", &session, false)
        .await;
    let offline = h
        .seed_refresh_family(scope, &user, "cli_offline", &session, true)
        .await;

    assert!(h.session_resolves(scope, &session).await, "live to begin");

    let path = format!("{}/sessions/{session}/revoke", base(scope));
    let (status, _, body) = h.post(&path, "revoke-key-1", "{}").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body_json(&body)["revoked"], true);
    assert_eq!(body_json(&body)["hard_kill"], false);

    // IMMEDIATE: the authentication read path refuses it at once. The session's
    // lifetime runs to 2100, so this cannot be expiry.
    assert!(
        !h.session_resolves(scope, &session).await,
        "a revoked session must stop resolving IMMEDIATELY"
    );

    // The cascade reached the session-bound family and SPARED the offline one.
    assert!(family_revoked(&h, scope, &bound.to_string()).await);
    assert!(
        !family_revoked(&h, scope, &offline.to_string()).await,
        "an offline_access family survives a session revoke (issue #21)"
    );

    // The fleet view now reports the terminal end (and no successor, so it is not a
    // rotation).
    let (_, _, body) = h.get(&format!("{}/sessions/{session}", base(scope))).await;
    let view = body_json(&body);
    assert_eq!(view["end_cause"], "revoked");
    assert!(
        view["superseded_by"].is_null(),
        "a revoke is not a rotation"
    );

    // The Idempotency-Key replay returns the original response and re-executes nothing.
    let (status, _, replay) = h.post(&path, "revoke-key-1", "{}").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body_json(&replay), body_json(&body_for_revoked(&session)));
}

/// The deterministic revoke response body for `session` (the post-condition), which is
/// what both the live call and its idempotent replay return.
fn body_for_revoked(session: &ironauth_store::SessionId) -> String {
    serde_json::json!({
        "id": session.to_string(),
        "revoked": true,
        "hard_kill": false,
    })
    .to_string()
}

#[tokio::test]
async fn revoke_everything_for_a_user_cascades_and_the_hard_kill_flag_ends_offline_too() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let victim = Harness::fresh_user_id(scope);
    let user = victim.to_string();
    let bystander = Harness::fresh_user_id(scope).to_string();

    let s1 = h.seed_session(scope, &user).await;
    let s2 = h.seed_session(scope, &user).await;
    let other = h.seed_session(scope, &bystander).await;
    let bound = h
        .seed_refresh_family(scope, &user, "cli_bound", &s1, false)
        .await;
    let offline = h
        .seed_refresh_family(scope, &user, "cli_offline", &s2, true)
        .await;

    // The DEFAULT revoke-everything: every session ends, the session-bound families
    // are revoked, and the offline_access families SURVIVE (a background job holding an
    // offline token keeps working when the browser session is cut).
    let path = format!("{}/users/{user}/sessions/revoke", base(scope));
    let (status, _, body) = h.post(&path, "revoke-all-1", "{}").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body_json(&body)["revoked"], true);
    assert_eq!(body_json(&body)["hard_kill"], false);

    assert!(!h.session_resolves(scope, &s1).await);
    assert!(!h.session_resolves(scope, &s2).await);
    assert!(
        h.session_resolves(scope, &other).await,
        "another user's session is untouched"
    );
    assert!(family_revoked(&h, scope, &bound.to_string()).await);
    assert!(
        !family_revoked(&h, scope, &offline.to_string()).await,
        "offline_access survives the default revoke-everything"
    );

    // The EXPLICIT hard kill also ends the offline_access families.
    let (status, _, body) = h
        .post(&path, "revoke-all-hard", "{\"hard_kill\":true}")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body_json(&body)["hard_kill"], true);
    assert!(
        family_revoked(&h, scope, &offline.to_string()).await,
        "an explicit hard kill ends the offline_access families too"
    );
}

#[tokio::test]
async fn a_bulk_revoke_is_scope_fenced_against_a_smuggled_foreign_session() {
    let h = Harness::start(50).await;
    let scope_a = h.seed_scope().await;
    let scope_b = h.seed_scope().await;
    let user_a = Harness::fresh_user_id(scope_a).to_string();
    let user_b = Harness::fresh_user_id(scope_b).to_string();

    let mine = h.seed_session(scope_a, &user_a).await;
    let victim = h.seed_session(scope_b, &user_b).await;

    // The batch names one of the caller's OWN sessions and one of ANOTHER tenant's.
    let path = format!("{}/sessions/revoke", base(scope_a));
    let body = serde_json::json!({ "session_ids": [mine.to_string(), victim.to_string()] });
    let (status, _, response) = h.post(&path, "bulk-1", &body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        body_json(&response)["sessions_targeted"],
        1,
        "the foreign session is fenced out of the batch, not revoked"
    );

    assert!(
        !h.session_resolves(scope_a, &mine).await,
        "own session ends"
    );
    assert!(
        h.session_resolves(scope_b, &victim).await,
        "a bulk revoke must NEVER reach another tenant's session"
    );
}

#[tokio::test]
async fn every_fleet_surface_returns_the_uniform_not_found_for_a_foreign_id() {
    let h = Harness::start(50).await;
    let scope_a = h.seed_scope().await;
    let scope_b = h.seed_scope().await;
    let user_b = Harness::fresh_user_id(scope_b).to_string();
    let victim = h.seed_session(scope_b, &user_b).await;
    let victim_family = h
        .seed_refresh_family(scope_b, &user_b, "cli_v", &victim, false)
        .await;

    // The baseline: the caller's OWN session IS visible, so the not-found below is
    // really about the scope boundary and not about a broken surface.
    let user_a = Harness::fresh_user_id(scope_a).to_string();
    let mine = h.seed_session(scope_a, &user_a).await;
    let (status, _, body) = h.get(&format!("{}/sessions/{mine}", base(scope_a))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the caller's own session is visible: {body}"
    );

    // Reading a FOREIGN session: the uniform not-found, indistinguishable from absent.
    let (status, _, body) = h.get(&format!("{}/sessions/{victim}", base(scope_a))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a foreign session must be the uniform not-found: {body}"
    );
    let (status, _, _) = h
        .get(&format!(
            "{}/refresh-families/{victim_family}",
            base(scope_a)
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a foreign family too");

    // Listing in scope A never reports scope B's resources.
    let (_, _, body) = h.get(&format!("{}/sessions", base(scope_a))).await;
    let listed = body_json(&body);
    let listed = listed["items"].as_array().expect("items");
    assert!(
        listed.iter().all(|item| item["id"] != victim.to_string()),
        "a foreign session is never listed"
    );

    // Revoking a foreign session: the uniform not-found, and the victim survives.
    let (status, _, body) = h
        .post(
            &format!("{}/sessions/{victim}/revoke", base(scope_a)),
            "cross-1",
            "{}",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(h.session_resolves(scope_b, &victim).await);

    // Revoking everything for a FOREIGN user: likewise the uniform not-found.
    let (status, _, body) = h
        .post(
            &format!("{}/users/{user_b}/sessions/revoke", base(scope_a)),
            "cross-2",
            "{}",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        h.session_resolves(scope_b, &victim).await,
        "the foreign user's sessions are untouched"
    );
}
