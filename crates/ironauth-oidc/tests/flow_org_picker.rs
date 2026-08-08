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
        .set_state(&env, org, OrganizationState::Disabled, None)
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
    let id_policy = harness.id_token_policy(client_id);
    let access_policy = harness.access_token_policy(client_id);
    let id = verify(id_token, &id_policy, &common::verify_clock()).expect("id token verifies");
    let at = verify(access_token, &access_policy, &common::verify_clock())
        .expect("access token verifies");
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

/// Attach an email identifier to `subject` (issue #96, criterion 5). A VERIFIED one is what makes
/// its domain usable for eligibility; `allowed_email_domains` is an unverified operator assertion,
/// so an unproven address must earn nothing.
async fn add_email(harness: &Harness, subject: &str, raw: &str, verified: bool) {
    let env = harness.env().clone();
    let user = ironauth_store::UserId::parse_in_scope(subject, &harness.scope())
        .expect("a well formed subject");
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .user_identifiers()
        .add(
            &env,
            ironauth_store::NewUserIdentifier {
                id: &ironauth_store::UserIdentifierId::generate(&env, &harness.scope()),
                user_id: &user,
                identifier_type: ironauth_store::IdentifierType::Email,
                raw,
                verified,
                mode: ironauth_store::UniquenessMode::EnvironmentWide,
                org: None,
            },
            None,
        )
        .await
        .expect("add email identifier");
}

/// An organization nobody is a member of that accepts `domain` for just-in-time provisioning.
async fn seed_eligible_org(harness: &Harness, domain: &str) -> OrganizationId {
    harness
        .seed_unjoined_org(ironauth_store::AuthPolicy {
            jit_provisioning: Some(true),
            allowed_email_domains: Some([domain.to_owned()].into_iter().collect()),
            ..ironauth_store::AuthPolicy::default()
        })
        .await
}

/// Whether `subject` is a member of `org`.
async fn is_member(harness: &Harness, org: &OrganizationId, subject: &str) -> bool {
    let user = ironauth_store::UserId::parse_in_scope(subject, &harness.scope())
        .expect("a well formed subject");
    harness
        .store()
        .scoped(harness.scope())
        .org_memberships()
        .exists(org, &user)
        .await
        .expect("membership lookup")
}

/// Criterion 5's list half: the picker offers organizations the subject is ELIGIBLE for, not only
/// ones they already belong to.
///
/// The defect this closes is a first-login one and it is invisible from the second login onwards.
/// Just-in-time provisioning runs inside `establish_session`, which is called at flow COMPLETION,
/// so on a first sign-in the eligible organizations are not memberships yet. A new employee at a
/// verified corporate domain therefore saw no picker at all, was joined silently, and was first
/// offered a choice on their SECOND sign-in.
#[tokio::test]
async fn the_picker_offers_organizations_the_subject_is_only_eligible_for() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "newcomer@jit.test").await;
    add_email(&harness, &subject, "newcomer@jit.test", true).await;

    let first = seed_eligible_org(&harness, "jit.test").await;
    let second = seed_eligible_org(&harness, "jit.test").await;
    assert!(
        !is_member(&harness, &first, &subject).await
            && !is_member(&harness, &second, &subject).await,
        "the fixture must start with NO memberships, or this measures the old behaviour"
    );

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "newcomer@jit.test").await;
    assert_ne!(
        held["state"], "completed",
        "the picker must hold the mint: {held}"
    );
    let mut offered = picker_option_values(&held["flow"]);
    offered.sort();
    let mut expected = vec![first.to_string(), second.to_string()];
    expected.sort();
    assert_eq!(
        offered, expected,
        "a subject with two eligible organizations and no memberships must be asked which one \
         this login is for"
    );
}

/// Picking an eligible organization joins the subject to it and binds it onto the session.
///
/// The join happens through the SAME provisioning path that would have joined them silently, so
/// the pick grants no authority that was not already going to be granted. What it adds is the
/// subject saying WHICH one this login is for.
#[tokio::test]
async fn picking_an_eligible_organization_joins_it_and_binds_it_to_the_session() {
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    let subject = seed_consenting_user(&harness, "joiner@jit.test").await;
    add_email(&harness, &subject, "joiner@jit.test", true).await;
    let chosen = seed_eligible_org(&harness, "jit.test").await;
    let other = seed_eligible_org(&harness, "jit.test").await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "joiner@jit.test").await;
    assert_ne!(
        held["state"], "completed",
        "the picker must hold the mint: {held}"
    );
    // The render issues a FRESH submit token; the create-time one is spent.
    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (status, headers, body) =
        submit_pick(&harness, &flow_id, &token, &chosen.to_string()).await;
    assert_eq!(status, StatusCode::OK, "the pick completes: {body}");

    assert!(
        is_member(&harness, &chosen, &subject).await,
        "picking an eligible organization must leave the subject a member of it"
    );
    // The OTHER eligible organization is joined too, because that is what issue #95's policy
    // says happens at session establishment and this change does not alter it. The pick decides
    // the login's org CONTEXT, not which memberships are earned.
    assert!(
        is_member(&harness, &other, &subject).await,
        "the pick must not suppress provisioning the subject was already entitled to"
    );

    let cookie = session_cookie_from_headers(&headers);
    let code = authorize_to_code(&harness, &cookie, &authorize_query(&client_id, &[])).await;
    let (access, id_token) = exchange_claims(&harness, &client_id, &code).await;
    assert_eq!(
        access["org_id"],
        chosen.to_string(),
        "the access token must carry the PICKED organization"
    );
    assert_eq!(id_token["org_id"], chosen.to_string());
}

/// A single eligible organization still skips the picker. No new prompt for a subject with no
/// choice to make.
///
/// The skip threshold is unchanged; only the set it counts is wider. This is the control that
/// proves widening the set did not turn every first login at a verified domain into a prompt.
#[tokio::test]
async fn a_single_eligible_organization_still_joins_silently_with_no_prompt() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "solo@jit.test").await;
    add_email(&harness, &subject, "solo@jit.test", true).await;
    let only = seed_eligible_org(&harness, "jit.test").await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (st, _, done) = submit_primary(&harness, &flow_id, &token, "solo@jit.test").await;
    assert_eq!(st, StatusCode::OK, "primary: {done}");
    assert_eq!(
        done["state"], "completed",
        "one eligible organization is not a choice, so the login must mint directly exactly as \
         it did before this change: {done}"
    );
    assert!(
        is_member(&harness, &only, &subject).await,
        "the silent just-in-time join must still happen"
    );
}

/// An UNVERIFIED email earns no offer.
///
/// `allowed_email_domains` is an operator assertion about a domain, not proof the subject holds an
/// address in it. Offering on an unproven address would let anyone be shown, and then join, any
/// organization by claiming one of its addresses.
#[tokio::test]
async fn an_unverified_email_domain_is_never_offered() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "unproven@jit.test").await;
    add_email(&harness, &subject, "unproven@jit.test", false).await;
    seed_eligible_org(&harness, "jit.test").await;
    seed_eligible_org(&harness, "jit.test").await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, done) = submit_primary(&harness, &flow_id, &token, "unproven@jit.test").await;
    assert_eq!(
        done["state"], "completed",
        "two eligible organizations were offered on the strength of an UNVERIFIED address: \
         {done}"
    );
}

/// An organization the subject is neither a member of nor eligible for cannot be picked, even
/// though the picker is rendering.
///
/// The acceptance predicate must be exactly the set the offer was built from. A picker that
/// renders two controls but accepts a third id is an org-existence oracle.
#[tokio::test]
async fn an_organization_that_was_not_offered_is_refused_uniformly() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "prober@jit.test").await;
    add_email(&harness, &subject, "prober@jit.test", true).await;
    seed_eligible_org(&harness, "jit.test").await;
    seed_eligible_org(&harness, "jit.test").await;
    // A real, live organization that accepts a DIFFERENT domain, so it exists and is active and
    // is nonetheless not this subject's to pick.
    let foreign = seed_eligible_org(&harness, "elsewhere.test").await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "prober@jit.test").await;
    assert_eq!(picker_option_values(&held["flow"]).len(), 2);

    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (status, _, _) = submit_pick(&harness, &flow_id, &token, &foreign.to_string()).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an organization outside the offered set was accepted"
    );
    assert!(
        !is_member(&harness, &foreign, &subject).await,
        "the refused pick must leave no membership behind"
    );
}

/// An organization the subject is BOTH a member of and eligible for is offered exactly once.
///
/// The two sets overlap in the ordinary steady state: after a first login, every organization the
/// domain made the subject eligible for is also a membership. Without the already-a-member filter
/// the picker renders the same organization twice, and a duplicate submit control is not a
/// cosmetic problem: the two controls carry the same value, so the rendered node list stops being
/// a faithful description of the choice and the golden corpus pins the wrong bytes.
#[tokio::test]
async fn an_organization_that_is_both_a_membership_and_eligible_is_offered_once() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "returning@jit.test").await;
    add_email(&harness, &subject, "returning@jit.test", true).await;

    let overlapping = seed_eligible_org(&harness, "jit.test").await;
    // The membership the first login would have earned.
    add_member(&harness, &overlapping, &subject).await;
    let second = create_org(&harness, "Unrelated").await;
    add_member(&harness, &second, &subject).await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "returning@jit.test").await;
    assert_ne!(
        held["state"], "completed",
        "the picker must hold the mint: {held}"
    );

    let offered = picker_option_values(&held["flow"]);
    assert_eq!(
        offered
            .iter()
            .filter(|id| *id == &overlapping.to_string())
            .count(),
        1,
        "the overlapping organization was offered more than once: {offered:?}"
    );
    assert_eq!(
        offered.len(),
        2,
        "exactly two distinct organizations: {offered:?}"
    );
}

/// Submit a new-organization name on an API login flow (issue #96, criterion 5).
async fn submit_create(
    harness: &Harness,
    flow_id: &str,
    token: &str,
    name: &str,
) -> (StatusCode, HeaderMap, Value) {
    post_json(
        harness,
        &submit_path(harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {"new_organization_name": name},
        }),
    )
    .await
}

/// The node names the picker rendered.
fn node_names(flow: &Value) -> Vec<String> {
    flow["ui"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter_map(|node| node["attributes"]["name"].as_str().map(str::to_owned))
        .collect()
}

/// With the seam NOT installed, which is every deployment by default, nothing changes.
///
/// The capability is absent rather than disabled: no create control renders, and a create
/// submission is the same uniform refusal as a malformed pick, so the setting is not an
/// existence oracle either.
#[tokio::test]
async fn without_the_seam_no_create_control_renders_and_a_create_submission_is_refused() {
    let harness = setup().await;
    let subject = seed_consenting_user(&harness, "nocreate@example.test").await;
    let org_a = create_org(&harness, "Acme").await;
    let org_b = create_org(&harness, "Globex").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "nocreate@example.test").await;
    let names = node_names(&held["flow"]);
    assert!(
        !names.iter().any(|name| name == "new_organization_name"),
        "a create control rendered in a deployment with no provisioning seam: {names:?}"
    );

    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (status, _, body) = submit_create(&harness, &flow_id, &token, "Sneaky Ltd").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a create submission was honoured with no seam installed"
    );
    assert_eq!(
        live_org_count(&harness).await,
        2,
        "the refused submission created an organization anyway"
    );

    // UNIFORM with a malformed pick, byte for byte. This is the property that keeps the setting
    // from being an existence oracle: a client must not be able to tell "this deployment has
    // self-service organizations turned off" from "that was not a valid submission". Asserting
    // only that the status is non-OK does not measure it, and a mutation that changed the
    // refusal to an internal error survived a test that did.
    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "nocreate@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (malformed_status, _, malformed_body) =
        submit_pick(&harness, &flow_id, &token, "not-an-org-id").await;
    assert_eq!(
        (status, body),
        (malformed_status, malformed_body),
        "the no-seam refusal must be indistinguishable from a malformed pick"
    );
}

/// A subject with NO organization is offered creation, and creating one enrolls them and becomes
/// the login's organization context.
///
/// This is the state criterion 5 is really about: a subject with nowhere to go, in a deployment
/// that opted into onboarding at sign-in.
#[tokio::test]
async fn a_subject_with_no_organization_can_create_one_and_is_enrolled_into_it() {
    let mut harness = setup().await;
    harness.enable_self_service_organizations();
    let client_id = harness.client_id().to_string();
    let subject = seed_consenting_user(&harness, "founder@example.test").await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "founder@example.test").await;
    assert_ne!(
        held["state"], "completed",
        "the create step must hold: {held}"
    );
    let names = node_names(&held["flow"]);
    assert!(
        names
            .iter()
            .filter(|name| *name == "new_organization_name")
            .count()
            == 2,
        "the name field and its submit control must both render: {names:?}"
    );
    assert!(
        picker_option_values(&held["flow"]).is_empty(),
        "there is nothing to pick, so no organization control should render"
    );

    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (status, headers, done) = submit_create(&harness, &flow_id, &token, "Founders Inc").await;
    assert_eq!(status, StatusCode::OK, "create: {done}");
    assert_eq!(
        done["state"], "completed",
        "creating completes the login: {done}"
    );

    let created = sole_live_org(&harness).await;
    assert!(
        is_member(&harness, &created, &subject).await,
        "the creator must be enrolled as the organization's first member"
    );

    let cookie = session_cookie_from_headers(&headers);
    let code = authorize_to_code(&harness, &cookie, &authorize_query(&client_id, &[])).await;
    let (access, id_token) = exchange_claims(&harness, &client_id, &code).await;
    assert_eq!(access["org_id"], created.to_string());
    assert_eq!(id_token["org_id"], created.to_string());
}

/// A subject with exactly ONE organization still skips, even with the seam installed.
///
/// Their context is determined. Turning every single-organization login into a prompt is not what
/// the criterion asks for, and it would be the most-hit login shape in a real deployment.
#[tokio::test]
async fn one_organization_still_skips_even_when_creation_is_offered() {
    let mut harness = setup().await;
    harness.enable_self_service_organizations();
    let subject = seed_consenting_user(&harness, "settled@example.test").await;
    let org = create_org(&harness, "Only Org").await;
    add_member(&harness, &org, &subject).await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, done) = submit_primary(&harness, &flow_id, &token, "settled@example.test").await;
    assert_eq!(
        done["state"], "completed",
        "a one-organization login must still mint directly: {done}"
    );
}

/// Every rejected name is refused uniformly and creates nothing.
///
/// This is the one path where an UNPRIVILEGED subject supplies the string, and the name is echoed
/// back in a picker to everyone who later joins the organization.
#[tokio::test]
async fn a_rejected_organization_name_creates_nothing() {
    let mut harness = setup().await;
    harness.enable_self_service_organizations();
    seed_consenting_user(&harness, "namer@example.test").await;

    // A leading tab is NOT in this list. `trim` strips it before the control-character check
    // runs, so "\u{9}tabbed" normalizes to "tabbed" and is a perfectly good name; the first
    // version of this test asserted it was refused and was wrong about its own code. The
    // control-character rule is about characters SURVIVING normalization, which is what the
    // interior newline and NUL below test.
    let over_long = "x".repeat(101);
    for name in [
        "",
        "   ",
        "line\u{a}break",
        "nul\u{0}inside",
        over_long.as_str(),
    ] {
        let (flow_id, token, _) = api_login_create(&harness, &[]).await;
        let (_, _, held) = submit_primary(&harness, &flow_id, &token, "namer@example.test").await;
        let token = held["submit_token"].as_str().expect("token").to_owned();
        let (status, _, _) = submit_create(&harness, &flow_id, &token, name).await;
        assert_ne!(status, StatusCode::OK, "the name {name:?} was accepted");
    }
    assert_eq!(
        live_org_count(&harness).await,
        0,
        "a refused name created an organization"
    );

    // The boundary on the OTHER side, so the bound is measured rather than merely asserted to
    // exist: exactly the maximum is accepted, and surrounding whitespace is NORMALIZED away
    // rather than counted toward the bound or stored.
    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "namer@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();
    let at_limit = format!("  \t{}  ", "y".repeat(100));
    let (status, _, done) = submit_create(&harness, &flow_id, &token, &at_limit).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a name at the limit, with trimmable whitespace around it, must be accepted: {done}"
    );
    assert_eq!(
        live_org_count(&harness).await,
        1,
        "exactly the one accepted name created an organization"
    );
    assert_eq!(
        sole_live_org_name(&harness).await,
        "y".repeat(100),
        "the stored name must be the TRIMMED one, so the bound applies to what is stored"
    );
}

/// A submission carrying BOTH a pick and a create is refused rather than silently treated as one.
///
/// The rendered form cannot produce it, so a client sending both is doing something deliberate
/// and the safe answer is no. Preferring one would let a client pair a valid create with an
/// organization id it wanted the server to look at.
#[tokio::test]
async fn a_submission_carrying_both_a_pick_and_a_create_is_refused() {
    let mut harness = setup().await;
    harness.enable_self_service_organizations();
    let subject = seed_consenting_user(&harness, "both@example.test").await;
    let org_a = create_org(&harness, "Acme").await;
    let org_b = create_org(&harness, "Globex").await;
    add_member(&harness, &org_a, &subject).await;
    add_member(&harness, &org_b, &subject).await;

    let (flow_id, token, _) = api_login_create(&harness, &[]).await;
    let (_, _, held) = submit_primary(&harness, &flow_id, &token, "both@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (status, _, _) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {
                "organization": org_a.to_string(),
                "new_organization_name": "Both At Once",
            },
        }),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a two-control submission was honoured"
    );
    assert_eq!(
        live_org_count(&harness).await,
        2,
        "the refused submission created an organization anyway"
    );
}

/// How many live organizations exist in the harness scope.
async fn live_org_count(harness: &Harness) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM organizations \
         WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL",
    )
    .bind(harness.scope().tenant().to_string())
    .bind(harness.scope().environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count organizations")
}

/// The single live organization in the harness scope.
async fn sole_live_org(harness: &Harness) -> OrganizationId {
    let raw: String = sqlx::query_scalar(
        "SELECT id FROM organizations \
         WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL",
    )
    .bind(harness.scope().tenant().to_string())
    .bind(harness.scope().environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("exactly one organization");
    OrganizationId::parse_in_scope(&raw, &harness.scope()).expect("a well formed org id")
}

/// The display name of the single live organization in the harness scope.
async fn sole_live_org_name(harness: &Harness) -> String {
    sqlx::query_scalar(
        "SELECT display_name FROM organizations \
         WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL",
    )
    .bind(harness.scope().tenant().to_string())
    .bind(harness.scope().environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("exactly one organization")
}
