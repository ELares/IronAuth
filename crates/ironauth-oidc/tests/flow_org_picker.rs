// SPDX-License-Identifier: MIT OR Apache-2.0

//! The organization picker IN the login flow, against a real Postgres (issue #94, PR-B2): a
//! multi-organization subject with NO `organization` parameter chooses which live-and-active
//! membership this login binds as its DURABLE org context, the pick is FROZEN onto the session at
//! completion, and PR-B1's frozen-session-wins relay carries it to the tokens' `org_id`.
//!
//! These are the end-to-end pins over a real Postgres for the acceptance criteria the pure unit
//! tests in `flow::org_picker` and the journey `validate` / `builtin_artifacts` tests cover in
//! isolation: a multi-org, no-parameter login RENDERS the picker and a valid pick mints `org_id` on
//! BOTH tokens; a non-member / disabled pick is the UNIFORM refusal with no mint; a single-org, a
//! parameter-carrying, and a no-membership login all SKIP the picker (byte-identical to before);
//! and the frozen pick is per-session stable (a second code carries the same `org_id`).
//!
//! Organizations and memberships are seeded through the CONTROL plane (as production does); the
//! login flow resolves and freezes them under the low-privilege `ironauth_app` role, so PR-A's
//! SELECT grants and PR-B1's session `org_id` column grant are exercised on the live login path.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json};
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_jose::verify;
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};
use ironauth_store::{
    CorrelationId, NewMembership, OrgMembershipId, OrganizationId, OrganizationState, UserId,
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

/// An open, regulation-off, flows-enabled harness with a cheap deterministic Argon2 pool, so the
/// flow login can verify a seeded password without a throttle interfering.
async fn setup() -> Harness {
    let mut harness = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            registration_closed: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    harness.enable_flows();
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    harness
}

/// Create an ACTIVE organization in the harness scope through the control plane.
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

/// Bind `subject` into `org` as a live member through the control plane.
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

/// Disable `org` through the control plane (it still exists, merely marked disabled).
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

/// The public-client `/authorize` query (PKCE mandatory) with any extra pre-encoded `key=value`
/// fragments (for example `organization=org_...`).
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

/// The public-client token-exchange form (the PKCE verifier the authorize bound a challenge for).
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

fn create_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/login",
        scope.tenant(),
        scope.environment()
    )
}

fn submit_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/login/submit",
        scope.tenant(),
        scope.environment()
    )
}

async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, HeaderMap, Value) {
    let (status, headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, headers, parsed)
}

/// Create an API login flow carrying `extra` `/authorize` query fragments as its resume target, so
/// the login resolves the client (and, for the parameter case, the picker sees the `organization`
/// parameter). Returns `(flow_id, submit_token, authorize_query)`.
async fn api_login_create(harness: &Harness, extra: &[&str]) -> (String, String, String) {
    let query = authorize_query(&harness.client_id().to_string(), extra);
    let return_to = format!("/authorize?{query}");
    let (status, _h, create) = post_json(
        harness,
        &create_path(harness),
        &json!({ "return_to": return_to }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    let flow_id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    (flow_id, token, query)
}

/// Submit the primary factor (identifier + password) on an API login flow.
async fn submit_primary(
    harness: &Harness,
    flow_id: &str,
    token: &str,
    identifier: &str,
) -> (StatusCode, HeaderMap, Value) {
    post_json(
        harness,
        &submit_path(harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {"identifier": identifier, "password": PASSWORD},
        }),
    )
    .await
}

/// Submit an organization pick on an API login flow.
async fn submit_pick(
    harness: &Harness,
    flow_id: &str,
    token: &str,
    org: &str,
) -> (StatusCode, HeaderMap, Value) {
    post_json(
        harness,
        &submit_path(harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {"organization": org},
        }),
    )
    .await
}

/// The organization submit controls the picker rendered (each control's `value` is an `org_` id).
fn picker_option_values(flow: &Value) -> Vec<String> {
    flow["ui"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter(|node| node["attributes"]["name"] == "organization")
        .filter_map(|node| node["attributes"]["value"].as_str().map(str::to_owned))
        .collect()
}

/// Extract the `__Host-ironauth_session` cookie (name=value only) from a completion's `Set-Cookie`
/// headers, so the minted session can be presented to `/authorize`.
fn session_cookie_from_headers(headers: &HeaderMap) -> String {
    for value in headers.get_all(header::SET_COOKIE) {
        if let Ok(raw) = value.to_str() {
            if let Some(pair) = raw.split(';').next() {
                if pair.starts_with(SESSION_COOKIE) {
                    return pair.to_owned();
                }
            }
        }
    }
    panic!("the login completion set no session cookie: {headers:?}");
}

/// Follow a minted session's `cookie` through `/authorize` (with `extra` query fragments) to a code,
/// expecting a redirect that carries one.
async fn authorize_to_code(harness: &Harness, cookie: &str, query: &str) -> String {
    let (status, headers, body) = harness.authorize_with_cookie(query, cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect to a code: {body}"
    );
    common::location_param(&headers, "code").expect("code in redirect")
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

/// Seed a fresh user with a password and grant it consent for the harness client, returning the
/// subject id.
async fn seed_consenting_user(harness: &Harness, identifier: &str) -> String {
    let subject = harness.seed_user(identifier, PASSWORD).await;
    harness
        .grant_consent(&subject, &harness.client_id().to_string())
        .await;
    subject
}

#[tokio::test]
async fn a_multi_org_no_param_login_renders_the_picker_and_a_valid_pick_mints_org_id_on_both_tokens()
 {
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    let subject = seed_consenting_user(&harness, "multi@example.test").await;
    let org_a = create_org(&harness, "Acme Corp").await;
    let org_b = create_org(&harness, "Globex").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    // The primary factor succeeds, but a multi-org subject with no parameter HOLDS on the picker.
    let (flow_id, token, query) = api_login_create(&harness, &[]).await;
    let (status, _h, held) = submit_primary(&harness, &flow_id, &token, "multi@example.test").await;
    assert_eq!(status, StatusCode::OK, "primary: {held}");
    assert_ne!(
        held["state"], "completed",
        "the picker holds the mint: {held}"
    );
    assert_eq!(
        held["flow"]["state"], "org_picker",
        "the flow holds on the organization picker: {held}"
    );
    let options = picker_option_values(&held["flow"]);
    assert_eq!(
        options.len(),
        2,
        "both active memberships are offered: {options:?}"
    );
    assert!(options.contains(&org_a.to_string()) && options.contains(&org_b.to_string()));

    // A valid pick mints and freezes org_b onto the session.
    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (status, headers, done) = submit_pick(&harness, &flow_id, &token, &org_b.to_string()).await;
    assert_eq!(status, StatusCode::OK, "pick: {done}");
    assert_eq!(done["state"], "completed", "a valid pick mints: {done}");
    let cookie = session_cookie_from_headers(&headers);

    // PR-B1's relay carries the frozen pick to BOTH tokens' org_id.
    let code = authorize_to_code(&harness, &cookie, &query).await;
    let (id_claims, at_claims) = exchange_claims(&harness, &client_id, &code).await;
    assert_eq!(
        id_claims["org_id"],
        org_b.to_string(),
        "id token carries the picked org_id"
    );
    assert_eq!(
        at_claims["org_id"],
        org_b.to_string(),
        "access token carries the picked org_id"
    );
}

#[tokio::test]
async fn a_non_member_pick_is_refused_uniformly_with_no_mint() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "multi@example.test").await;
    let org_a = create_org(&harness, "Acme Corp").await;
    let org_b = create_org(&harness, "Globex").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;
    // A real, active org the subject is NOT a member of.
    let foreign = create_org(&harness, "Not Mine").await;

    let (flow_id, token, _query) = api_login_create(&harness, &[]).await;
    let (_s, _h, held) = submit_primary(&harness, &flow_id, &token, "multi@example.test").await;
    assert_eq!(
        held["flow"]["state"], "org_picker",
        "the picker holds: {held}"
    );
    let token = held["submit_token"].as_str().expect("token").to_owned();

    // Submitting a non-member org is the UNIFORM invalid-submission refusal: no mint, no cookie.
    let (status, headers, body) =
        submit_pick(&harness, &flow_id, &token, &foreign.to_string()).await;
    assert_ne!(
        body["state"], "completed",
        "a non-member pick does not mint: {body} ({status})"
    );
    assert!(
        headers.get_all(header::SET_COOKIE).iter().next().is_none(),
        "a refused pick sets no session cookie"
    );
}

#[tokio::test]
async fn a_disabled_org_cannot_be_picked() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "multi@example.test").await;
    let org_a = create_org(&harness, "Acme Corp").await;
    let org_b = create_org(&harness, "Globex").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    let (flow_id, token, _query) = api_login_create(&harness, &[]).await;
    let (_s, _h, held) = submit_primary(&harness, &flow_id, &token, "multi@example.test").await;
    assert_eq!(
        held["flow"]["state"], "org_picker",
        "the picker holds: {held}"
    );
    // Disable org_b AFTER the picker rendered it; a client that submits it anyway is refused, the
    // SAME uniform refusal as a non-member (no disabled/non-member oracle).
    disable_org(&harness, &org_b).await;
    let token = held["submit_token"].as_str().expect("token").to_owned();

    let (_status, headers, body) =
        submit_pick(&harness, &flow_id, &token, &org_b.to_string()).await;
    assert_ne!(
        body["state"], "completed",
        "a disabled org cannot be picked: {body}"
    );
    assert!(
        headers.get_all(header::SET_COOKIE).iter().next().is_none(),
        "a refused pick sets no session cookie"
    );
}

#[tokio::test]
async fn a_single_org_subject_skips_the_picker_and_auto_selects() {
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    let subject = seed_consenting_user(&harness, "sole@example.test").await;
    let org = create_org(&harness, "Sole Org").await;
    add_member(&harness, &org, &subject).await;

    // A single active membership: the picker SKIPS and the login mints DIRECTLY on the primary
    // factor (no org_picker state, no picker nodes).
    let (flow_id, token, query) = api_login_create(&harness, &[]).await;
    let (status, headers, done) =
        submit_primary(&harness, &flow_id, &token, "sole@example.test").await;
    assert_eq!(status, StatusCode::OK, "primary: {done}");
    assert_eq!(
        done["state"], "completed",
        "a single-org login mints directly, skipping the picker: {done}"
    );
    let cookie = session_cookie_from_headers(&headers);

    // PR-B1 auto-selects the sole active membership at code-issue, so org_id is present.
    let code = authorize_to_code(&harness, &cookie, &query).await;
    let (id_claims, at_claims) = exchange_claims(&harness, &client_id, &code).await;
    assert_eq!(
        id_claims["org_id"],
        org.to_string(),
        "the sole membership is auto-selected"
    );
    assert_eq!(at_claims["org_id"], org.to_string());
}

#[tokio::test]
async fn a_param_plus_multi_org_skips_the_picker_and_the_param_wins() {
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    let subject = seed_consenting_user(&harness, "multi@example.test").await;
    let org_a = create_org(&harness, "Acme Corp").await;
    let org_b = create_org(&harness, "Globex").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    // The resume target carries organization=org_a: the picker SKIPS (the parameter path resolves
    // the context at code-issue), so the login mints DIRECTLY even though the subject is multi-org.
    let org_a_param = format!("organization={}", enc(&org_a.to_string()));
    let (flow_id, token, query) = api_login_create(&harness, &[&org_a_param]).await;
    let (status, headers, done) =
        submit_primary(&harness, &flow_id, &token, "multi@example.test").await;
    assert_eq!(status, StatusCode::OK, "primary: {done}");
    assert_eq!(
        done["state"], "completed",
        "a parameter skips the picker even for a multi-org subject: {done}"
    );
    let cookie = session_cookie_from_headers(&headers);

    // The parameter wins at code-issue: org_id is org_a.
    let code = authorize_to_code(&harness, &cookie, &query).await;
    let (id_claims, _at) = exchange_claims(&harness, &client_id, &code).await;
    assert_eq!(
        id_claims["org_id"],
        org_a.to_string(),
        "the organization parameter wins"
    );
}

#[tokio::test]
async fn a_no_membership_login_skips_the_picker_and_carries_no_org_id() {
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    seed_consenting_user(&harness, "member-less@example.test").await;

    // No memberships: the picker SKIPS and the login mints directly with no org context.
    let (flow_id, token, query) = api_login_create(&harness, &[]).await;
    let (status, headers, done) =
        submit_primary(&harness, &flow_id, &token, "member-less@example.test").await;
    assert_eq!(status, StatusCode::OK, "primary: {done}");
    assert_eq!(
        done["state"], "completed",
        "a member-less login mints directly: {done}"
    );
    let cookie = session_cookie_from_headers(&headers);

    let code = authorize_to_code(&harness, &cookie, &query).await;
    let (id_claims, at_claims) = exchange_claims(&harness, &client_id, &code).await;
    assert!(
        id_claims.get("org_id").is_none(),
        "no org_id on a member-less login: {id_claims}"
    );
    assert!(at_claims.get("org_id").is_none());
}

#[tokio::test]
async fn the_picked_org_is_per_session_stable_across_a_second_code() {
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    let subject = seed_consenting_user(&harness, "multi@example.test").await;
    let org_a = create_org(&harness, "Acme Corp").await;
    let org_b = create_org(&harness, "Globex").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    // Pick org_a at the picker.
    let (flow_id, token, query) = api_login_create(&harness, &[]).await;
    let (_s, _h, held) = submit_primary(&harness, &flow_id, &token, "multi@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (_s, headers, done) = submit_pick(&harness, &flow_id, &token, &org_a.to_string()).await;
    assert_eq!(done["state"], "completed", "the pick mints: {done}");
    let cookie = session_cookie_from_headers(&headers);

    // The first code carries org_a.
    let code_a = authorize_to_code(&harness, &cookie, &query).await;
    let (id_a, _) = exchange_claims(&harness, &client_id, &code_a).await;
    assert_eq!(id_a["org_id"], org_a.to_string(), "first code is org_a");

    // A second authorize on the SAME session, now naming organization=org_b (also a live
    // membership), still resolves org_a: the frozen pick is per-session stable (first write wins).
    let org_b_param = format!("organization={}", enc(&org_b.to_string()));
    let query_b = authorize_query(&client_id, &[&org_b_param]);
    let code_b = authorize_to_code(&harness, &cookie, &query_b).await;
    let (id_b, at_b) = exchange_claims(&harness, &client_id, &code_b).await;
    assert_eq!(
        id_b["org_id"],
        org_a.to_string(),
        "a conflicting parameter never re-binds the frozen pick"
    );
    assert_eq!(at_b["org_id"], org_a.to_string());
}
