// SPDX-License-Identifier: MIT OR Apache-2.0

//! The self-service end-user account API (issue #61), against a real Postgres.
//!
//! The store tests pin the data model; these pin what an authenticated end user
//! actually experiences through the HTTP surface, and the ONE security property that
//! makes it safe: a user can only ever act on their OWN account.
//!
//! - a user lists their OWN sessions (with device metadata and a current-session
//!   marking) and NEVER another user's;
//! - a user revokes one of their OWN sessions and it stops resolving at once; a
//!   session id belonging to ANOTHER user is the uniform not-found and is never
//!   revoked (IDOR on self-service is account takeover);
//! - "sign out everywhere else" ends every other session and keeps the current one;
//! - a password change verifies the CURRENT password, sets a new one (never
//!   returning or logging the hash), and revokes the user's OTHER sessions;
//! - credential enroll / list / remove is subject-bound, a cross-user credential id
//!   is refused, and removing the last usable credential is blocked without the
//!   documented recovery acknowledgment;
//! - every state-changing POST carries the same-origin CSRF check;
//! - an unauthenticated request, and a cookie presented at the WRONG scope, are 401.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_store::{Scope, SessionId};
use serde_json::{Value, json};

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

/// POST JSON `body` to `path` with an optional cookie and extra headers; return the
/// status and parsed JSON body.
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

/// Whether a session still resolves on the authentication read path (issue #32).
async fn session_resolves(harness: &Harness, scope: Scope, id: &SessionId) -> bool {
    harness
        .store()
        .scoped(scope)
        .sessions()
        .get(id, 0, 0)
        .await
        .expect("read session")
        .is_some()
}

#[tokio::test]
async fn a_user_lists_only_their_own_sessions_with_the_current_one_marked() {
    let harness = Harness::start().await;

    // Two users; the caller (ada) is signed in on two devices, the other (grace) on
    // one. The list must show ada's two and never grace's.
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let grace = harness
        .seed_user("grace@example.test", "another passphrase")
        .await;
    let (current, current_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let (second, _second_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let (grace_session, _grace_cookie) = harness.session_with_id(&grace, "pwd", 0).await;

    let path = format!("{}/sessions", base(&harness));
    let (status, body) = get(&harness, &path, Some(&current_cookie)).await;
    assert_eq!(status, StatusCode::OK);
    let sessions = body["sessions"].as_array().expect("sessions array");
    assert_eq!(sessions.len(), 2, "exactly the caller's own two sessions");

    let ids: Vec<&str> = sessions.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&current.to_string().as_str()));
    assert!(ids.contains(&second.to_string().as_str()));
    assert!(
        !ids.contains(&grace_session.to_string().as_str()),
        "another user's session must never appear"
    );

    // The current session is marked, the other is not.
    for entry in sessions {
        let is_current = entry["current"].as_bool().unwrap();
        assert_eq!(
            is_current,
            entry["id"].as_str().unwrap() == current.to_string(),
            "only the requesting session is marked current"
        );
    }
}

#[tokio::test]
async fn a_user_revokes_their_own_session_and_it_stops_resolving() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (current, current_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let (other, _other_cookie) = harness.session_with_id(&ada, "pwd", 0).await;

    let path = format!("{}/sessions/revoke", base(&harness));
    let (status, body) = post_json(
        &harness,
        &path,
        Some(&current_cookie),
        &json!({ "session_id": other.to_string() }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(true));

    assert!(
        !session_resolves(&harness, scope, &other).await,
        "the revoked session stops resolving at once"
    );
    assert!(
        session_resolves(&harness, scope, &current).await,
        "the session the request was made from survives"
    );
}

#[tokio::test]
async fn a_user_cannot_revoke_another_users_session() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let grace = harness
        .seed_user("grace@example.test", "another passphrase")
        .await;
    let (_ada_session, ada_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let (grace_session, _grace_cookie) = harness.session_with_id(&grace, "pwd", 0).await;

    // Ada tries to revoke grace's session by id: uniform not-found, nothing revoked.
    let path = format!("{}/sessions/revoke", base(&harness));
    let (status, body) = post_json(
        &harness,
        &path,
        Some(&ada_cookie),
        &json!({ "session_id": grace_session.to_string() }),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another user's session id is the uniform not-found"
    );
    assert_eq!(body["error"], json!("not_found"));
    assert!(
        session_resolves(&harness, scope, &grace_session).await,
        "the victim's session is untouched"
    );
}

#[tokio::test]
async fn sign_out_everywhere_else_ends_every_other_session_and_keeps_the_current() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (current, current_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let (a, _a) = harness.session_with_id(&ada, "pwd", 0).await;
    let (b, _b) = harness.session_with_id(&ada, "pwd", 0).await;

    let path = format!("{}/sessions/revoke-others", base(&harness));
    let (status, body) = post_json(&harness, &path, Some(&current_cookie), &json!({}), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sessions_revoked"], json!(2));
    // The step-up policy is declared and visible on the sensitive operation.
    assert_eq!(body["step_up"]["max_age_secs"], json!(300));
    assert_eq!(body["step_up"]["enforced"], json!(false));

    assert!(
        session_resolves(&harness, scope, &current).await,
        "current kept"
    );
    assert!(
        !session_resolves(&harness, scope, &a).await,
        "other a ended"
    );
    assert!(
        !session_resolves(&harness, scope, &b).await,
        "other b ended"
    );
}

#[tokio::test]
async fn password_change_verifies_current_sets_new_and_revokes_other_sessions() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let ada = harness
        .seed_user("ada@example.test", "the-current-password")
        .await;
    let (current, current_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let (other, _other) = harness.session_with_id(&ada, "pwd", 0).await;

    let path = format!("{}/password", base(&harness));

    // A wrong current password is refused and changes nothing.
    let (status, body) = post_json(
        &harness,
        &path,
        Some(&current_cookie),
        &json!({ "current_password": "wrong", "new_password": "brand-new-password" }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], json!("invalid_password"));
    assert!(
        session_resolves(&harness, scope, &other).await,
        "a rejected password change revokes nothing"
    );

    // The correct current password succeeds: the hash is never returned, and the
    // OTHER session is revoked while the current one survives.
    let (status, body) = post_json(
        &harness,
        &path,
        Some(&current_cookie),
        &json!({ "current_password": "the-current-password", "new_password": "brand-new-password" }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], json!(true));
    assert_eq!(body["other_sessions_revoked"], json!(1));
    // The response NEVER carries a password or a hash.
    let serialized = body.to_string();
    assert!(
        !serialized.contains("argon2"),
        "no hash in the response: {serialized}"
    );
    assert!(!serialized.contains("password_hash"), "{serialized}");

    assert!(
        session_resolves(&harness, scope, &current).await,
        "current kept"
    );
    assert!(
        !session_resolves(&harness, scope, &other).await,
        "session-fixation defense: the other session is revoked"
    );

    // The new password now verifies against the stored hash.
    let stored = harness
        .store()
        .scoped(scope)
        .users()
        .password_hash_for_subject(
            &ironauth_store::UserId::parse_in_scope(&ada, &scope).expect("subject parses"),
        )
        .await
        .expect("read")
        .expect("user exists");
    assert!(
        ironauth_oidc::verify_password("brand-new-password", &stored),
        "the new password verifies"
    );
    assert!(
        !ironauth_oidc::verify_password("the-current-password", &stored),
        "the old password no longer verifies"
    );
}

#[tokio::test]
async fn credentials_enroll_list_and_remove_through_the_api() {
    let harness = Harness::start().await;
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;

    let credentials = format!("{}/credentials", base(&harness));

    // Enroll a passkey.
    let (status, body) = post_json(
        &harness,
        &credentials,
        Some(&cookie),
        &json!({ "type": "passkey", "friendly_name": "my work laptop" }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let credential_id = body["id"].as_str().expect("id").to_owned();
    assert_eq!(body["usable_for_login"], json!(true));
    assert_eq!(body["step_up"]["max_age_secs"], json!(300));

    // List shows it with its friendly name.
    let (status, body) = get(&harness, &credentials, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["credentials"].as_array().expect("array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["friendly_name"], json!("my work laptop"));

    // Enroll a second passkey, so the first is no longer the last usable one.
    let (status, _second) = post_json(
        &harness,
        &credentials,
        Some(&cookie),
        &json!({ "type": "passkey", "friendly_name": "backup key" }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Remove the first (not the last usable one): allowed without acknowledgment.
    let remove = format!("{}/credentials/remove", base(&harness));
    let (status, body) = post_json(
        &harness,
        &remove,
        Some(&cookie),
        &json!({ "credential_id": credential_id }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["removed"], json!(true));
}

#[tokio::test]
async fn removing_the_last_usable_credential_is_blocked_without_acknowledgment() {
    let harness = Harness::start().await;
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let credentials = format!("{}/credentials", base(&harness));

    let (_status, body) = post_json(
        &harness,
        &credentials,
        Some(&cookie),
        &json!({ "type": "passkey", "friendly_name": "only key" }),
        &[],
    )
    .await;
    let only = body["id"].as_str().expect("id").to_owned();

    // Removing the LAST usable credential without acknowledgment is blocked (409).
    let remove = format!("{}/credentials/remove", base(&harness));
    let (status, body) = post_json(
        &harness,
        &remove,
        Some(&cookie),
        &json!({ "credential_id": only }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], json!("last_credential"));

    // With the documented recovery acknowledgment it succeeds.
    let (status, body) = post_json(
        &harness,
        &remove,
        Some(&cookie),
        &json!({ "credential_id": only, "acknowledge_recovery": true }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["removed"], json!(true));
}

#[tokio::test]
async fn a_user_cannot_remove_another_users_credential() {
    let harness = Harness::start().await;
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let grace = harness
        .seed_user("grace@example.test", "another passphrase")
        .await;
    let (_ada_id, ada_cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let (_grace_id, grace_cookie) = harness.session_with_id(&grace, "pwd", 0).await;
    let credentials = format!("{}/credentials", base(&harness));

    // Grace enrolls a credential.
    let (_status, body) = post_json(
        &harness,
        &credentials,
        Some(&grace_cookie),
        &json!({ "type": "passkey", "friendly_name": "grace key" }),
        &[],
    )
    .await;
    let grace_credential = body["id"].as_str().expect("id").to_owned();

    // Ada (same tenant, different user) tries to remove it: uniform not-found.
    let remove = format!("{}/credentials/remove", base(&harness));
    let (status, body) = post_json(
        &harness,
        &remove,
        Some(&ada_cookie),
        &json!({ "credential_id": grace_credential, "acknowledge_recovery": true }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], json!("not_found"));

    // Grace's credential is untouched (still listed).
    let (_status, body) = get(&harness, &credentials, Some(&grace_cookie)).await;
    assert_eq!(body["credentials"].as_array().unwrap().len(), 1);
    // Ada cannot even see it in her own (empty) list.
    let (_status, body) = get(&harness, &credentials, Some(&ada_cookie)).await;
    assert!(body["credentials"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn state_changing_posts_reject_cross_site_submissions() {
    let harness = Harness::start().await;
    let ada = harness
        .seed_user("ada@example.test", "the-current-password")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;

    // A cross-site revoke-others is refused with a 403 (issue #196), and revokes
    // nothing (there is nothing else to revoke here; the point is the 403 gate).
    let (status, body) = post_json(
        &harness,
        &format!("{}/sessions/revoke-others", base(&harness)),
        Some(&cookie),
        &json!({}),
        &[("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], json!("forbidden"));

    // A cross-site password change is refused too, and never touches the password.
    let (status, _body) = post_json(
        &harness,
        &format!("{}/password", base(&harness)),
        Some(&cookie),
        &json!({ "current_password": "the-current-password", "new_password": "x" }),
        &[("origin", "https://evil.test")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_and_wrong_scope_requests_are_rejected() {
    let harness = Harness::start().await;
    let ada = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let sessions = format!("{}/sessions", base(&harness));

    // No cookie: 401.
    let (status, body) = get(&harness, &sessions, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], json!("unauthenticated"));

    // A cookie for the harness scope presented at a DIFFERENT (foreign) scope's path
    // does not resolve: the session id embeds its scope and parses as not-found under
    // another, so the caller is unauthenticated there.
    let foreign = harness.provision_foreign_scope().await;
    let foreign_path = format!(
        "/t/{}/e/{}/account/sessions",
        foreign.tenant(),
        foreign.environment()
    );
    let (status, _body) = get(&harness, &foreign_path, Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a session cookie is scoped: it does not authenticate at another scope"
    );

    // Sanity: the same cookie DOES authenticate at its own scope.
    let (status, _body) = get(&harness, &sessions, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
}
