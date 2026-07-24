// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DURABLE organization token context end to end, against a real Postgres
//! (issue #94, PR-B1): the `organization` parameter binds a live-and-active org onto
//! the session and the tokens (`org_id` on BOTH the ID token and the access token); a
//! single-org subject auto-selects; a multi-org subject with no parameter gets no
//! `org_id` (the `OrgPicker` is PR-B2); a not-a-member and a disabled org are BOTH
//! refused UNIFORMLY (no oracle); the frozen org is per-session stable (first write
//! wins, so a later conflicting parameter never re-binds); a no-org login is
//! unaffected; and the `org_id` survives a refresh.
//!
//! Every claim is read back through the ONE hardened verify path, so a token that
//! fails to verify fails the test before any claim is inspected. Organizations and
//! memberships are seeded through the CONTROL plane (as production does); the data
//! plane resolves and enforces them under the low-privilege `ironauth_app` role, so
//! the PR-A SELECT grants and this PR's session `org_id` column grant are exercised.

mod common;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_jose::verify;
use ironauth_store::{
    CorrelationId, NewMembership, OrgMembershipId, OrganizationId, OrganizationState, UserId,
};
use serde_json::Value;

/// Create an ACTIVE organization in the harness scope through the control plane and
/// return its id.
async fn create_org(harness: &Harness, display_name: &str) -> OrganizationId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let org_id = OrganizationId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org_id, 1_000_000, display_name, None)
        .await
        .expect("create organization");
    org_id
}

/// Bind `subject` (a `usr_` id string) into `org` as a live member through the control
/// plane.
async fn add_member(harness: &Harness, org: &OrganizationId, subject: &str) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let user_id = UserId::parse_in_scope(subject, &scope).expect("subject parses in scope");
    let membership_id = OrgMembershipId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_memberships(scope)
        .create(
            &env,
            NewMembership {
                id: &membership_id,
                organization_id: org,
                user_id: &user_id,
                metadata: None,
            },
            1_000_000,
            None,
        )
        .await
        .expect("add membership");
}

/// Disable `org` through the control plane (the org still EXISTS, it is merely marked
/// disabled), so the login path must REFUSE it as an org context.
async fn disable_org(harness: &Harness, org: &OrganizationId) {
    let env = harness.env().clone();
    let scope = harness.scope();
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(&env, org, OrganizationState::Disabled)
        .await
        .expect("disable organization");
}

/// The public-client authorization query (PKCE mandatory), with any extra pre-encoded
/// `key=value` fragments (for example `organization=org_...`).
fn authorize_query(client_id: &str, extra: &[&str]) -> String {
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    for fragment in extra {
        query.push('&');
        query.push_str(fragment);
    }
    query
}

/// The public-client token-exchange form (the PKCE verifier the authorize bound a
/// challenge for).
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Drive authorize (with `cookie`) to a code, expecting a redirect.
async fn authorize_to_code(
    harness: &Harness,
    client_id: &str,
    extra: &[&str],
    cookie: &str,
) -> String {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id, extra), cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect: {body}"
    );
    location_param(&headers, "code").expect("code in redirect")
}

/// Exchange `code` and return the verified (ID-token claims, access-token claims).
async fn exchange_claims(harness: &Harness, client_id: &str, code: &str) -> (Value, Value) {
    let (status, _, body) = harness.token(&token_form(code, client_id)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let id_token = value["id_token"].as_str().expect("id_token present");
    let access_token = value["access_token"]
        .as_str()
        .expect("access_token present");
    let policy = harness.policy(client_id);
    let id = verify(id_token, &policy, &common::verify_clock()).expect("id token verifies");
    let at = verify(access_token, &policy, &common::verify_clock()).expect("access token verifies");
    (
        Value::Object(id.claims().raw().clone()),
        Value::Object(at.claims().raw().clone()),
    )
}

/// A cookie for a fresh consenting subject of `client_id`, plus that subject id.
async fn consenting_subject(harness: &Harness, client_id: &str) -> (String, String) {
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    (subject, cookie)
}

#[tokio::test]
async fn organization_param_binds_org_id_onto_both_tokens() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Acme Corp").await;
    add_member(&harness, &org, &subject).await;

    let code = authorize_to_code(
        &harness,
        &client_id,
        &[&format!("organization={}", enc(&org.to_string()))],
        &cookie,
    )
    .await;
    let (id_claims, at_claims) = exchange_claims(&harness, &client_id, &code).await;

    assert_eq!(
        id_claims["org_id"],
        org.to_string(),
        "id token carries org_id"
    );
    assert_eq!(
        at_claims["org_id"],
        org.to_string(),
        "access token carries org_id"
    );
}

#[tokio::test]
async fn a_single_org_subject_auto_selects_with_no_param() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Sole Org").await;
    add_member(&harness, &org, &subject).await;

    // No organization parameter: the sole active membership auto-selects.
    let code = authorize_to_code(&harness, &client_id, &[], &cookie).await;
    let (id_claims, at_claims) = exchange_claims(&harness, &client_id, &code).await;

    assert_eq!(id_claims["org_id"], org.to_string(), "auto-selected org_id");
    assert_eq!(at_claims["org_id"], org.to_string());
}

#[tokio::test]
async fn a_multi_org_subject_with_no_param_gets_no_org_id() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org_a = create_org(&harness, "Org A").await;
    let org_b = create_org(&harness, "Org B").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    // PR-B1: a multi-org subject who names no organization gets NO org_id (the
    // OrgPicker that would let them choose is PR-B2).
    let code = authorize_to_code(&harness, &client_id, &[], &cookie).await;
    let (id_claims, at_claims) = exchange_claims(&harness, &client_id, &code).await;

    assert!(
        id_claims.get("org_id").is_none(),
        "no org_id for multi-org, no param: {id_claims}"
    );
    assert!(at_claims.get("org_id").is_none());
}

#[tokio::test]
async fn a_no_org_login_carries_no_org_id_and_is_unchanged() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_subject, cookie) = consenting_subject(&harness, &client_id).await;

    // A member-less subject who names no organization: no org_id, a plain login.
    let code = authorize_to_code(&harness, &client_id, &[], &cookie).await;
    let (id_claims, at_claims) = exchange_claims(&harness, &client_id, &code).await;

    assert!(
        id_claims.get("org_id").is_none(),
        "no org_id on a no-org login"
    );
    assert!(at_claims.get("org_id").is_none());
}

#[tokio::test]
async fn a_non_member_org_param_is_refused_uniformly_with_no_tokens() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_subject, cookie) = consenting_subject(&harness, &client_id).await;
    // A real, active org the subject is NOT a member of.
    let org = create_org(&harness, "Not Mine").await;

    let (status, headers, body) = harness
        .authorize_with_cookie(
            &authorize_query(
                &client_id,
                &[&format!("organization={}", enc(&org.to_string()))],
            ),
            &cookie,
        )
        .await;
    // The refusal rides the negotiated response mode as access_denied (redirect), and
    // issues NO code.
    assert_eq!(status, StatusCode::SEE_OTHER, "refusal redirects: {body}");
    assert!(location_param(&headers, "code").is_none(), "no code issued");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("access_denied"),
        "uniform access_denied"
    );
}

#[tokio::test]
async fn a_disabled_org_param_is_refused_even_for_a_member() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Disabled Co").await;
    add_member(&harness, &org, &subject).await;
    disable_org(&harness, &org).await;

    let (status, headers, body) = harness
        .authorize_with_cookie(
            &authorize_query(
                &client_id,
                &[&format!("organization={}", enc(&org.to_string()))],
            ),
            &cookie,
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "refusal redirects: {body}");
    assert!(location_param(&headers, "code").is_none(), "no code issued");
    // A DISABLED org (the subject IS a member) refuses with the SAME error as a
    // not-a-member org: no exists/not-member/disabled oracle.
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("access_denied"),
        "uniform access_denied, same as the non-member case"
    );
}

#[tokio::test]
async fn the_org_id_is_per_session_stable_first_write_wins() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org_a = create_org(&harness, "Org A").await;
    let org_b = create_org(&harness, "Org B").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    // First authorize names org_a: the session freezes onto org_a.
    let code_a = authorize_to_code(
        &harness,
        &client_id,
        &[&format!("organization={}", enc(&org_a.to_string()))],
        &cookie,
    )
    .await;
    let (id_a, _) = exchange_claims(&harness, &client_id, &code_a).await;
    assert_eq!(id_a["org_id"], org_a.to_string(), "first bind is org_a");

    // A second authorize on the SAME session names org_b (also a live membership), but
    // first write wins: the session stays bound to org_a, so the new code carries org_a.
    let code_b = authorize_to_code(
        &harness,
        &client_id,
        &[&format!("organization={}", enc(&org_b.to_string()))],
        &cookie,
    )
    .await;
    let (id_b, at_b) = exchange_claims(&harness, &client_id, &code_b).await;
    assert_eq!(
        id_b["org_id"],
        org_a.to_string(),
        "a conflicting param never re-binds"
    );
    assert_eq!(at_b["org_id"], org_a.to_string());
}

#[tokio::test]
async fn a_refreshed_access_token_keeps_the_same_org_id() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (subject, cookie) = consenting_subject(&harness, &client_id).await;
    let org = create_org(&harness, "Refresh Org").await;
    add_member(&harness, &org, &subject).await;

    // The public code flow returns a refresh token (the harness default). The org_id
    // is frozen onto the grant the refresh family is rooted at.
    let code = authorize_to_code(
        &harness,
        &client_id,
        &[&format!("organization={}", enc(&org.to_string()))],
        &cookie,
    )
    .await;
    let (status, _, body) = harness.token(&token_form(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code exchange: {body}");
    let refresh_token = json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh token is issued for the code flow")
        .to_owned();

    // Refresh: the re-minted access token keeps the SAME org_id (read from the grant).
    let refresh_form = form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("client_id", &client_id),
    ]);
    let (status, _, body) = harness.token(&refresh_form).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let refreshed = json(&body);
    let access_token = refreshed["access_token"].as_str().expect("access_token");
    let verified = verify(
        access_token,
        &harness.policy(&client_id),
        &common::verify_clock(),
    )
    .expect("refreshed access token verifies");
    let claims = Value::Object(verified.claims().raw().clone());
    assert_eq!(
        claims["org_id"],
        org.to_string(),
        "refreshed token keeps org_id"
    );
}
