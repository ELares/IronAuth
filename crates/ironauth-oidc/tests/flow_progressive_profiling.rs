// SPDX-License-Identifier: MIT OR Apache-2.0

//! Progressive profiling on a later login (issue #87, PR 3): a signup form's LATER-LOGIN fields
//! are collected on a SUBSEQUENT login as a HELD login step, injected where a successful primary
//! (plus any second factor) login would otherwise mint the session.
//!
//! These are the end to end pins over a real Postgres for the acceptance criteria the pure unit
//! tests in `flow::profiling` cover in isolation: the trigger (a missing REQUIRED later-login
//! field prompts on the next login), the PROMPT-ON-NEXT-LOGIN-NEVER-BLOCK relaxation (the step
//! is always skippable), the deep-merge persistence (a collected value merges into the identity's
//! existing traits and removing a field never deletes one), the transport-agnostic node set, and
//! the honest amr on the final mint (including the MFA plus profiling combination).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::{CorrelationId, NewSignupForm, SignupFormId, UserId};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

/// The generic "value is too short" signup field error id (issue #87), keyed on the field.
const SIGNUP_FIELD_TOO_SHORT: u64 = 4_270_002;

/// An open-registration, flows-enabled harness with a cheap deterministic Argon2 pool.
async fn setup() -> Harness {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
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
    harness.install_hashing_pool(Arc::clone(&pool));
    harness
}

/// Install and activate an identity trait schema carrying a constrained `nickname` and `age`
/// alongside the identifier `email` trait.
async fn install_schema(harness: &Harness) {
    let schema = json!({
        "type": "object",
        "properties": {
            "email": {"type": "string", "x-ironauth": {"identifier": true, "verification": "email"}},
            "nickname": {"type": "string", "minLength": 3, "maxLength": 20},
            "age": {"type": "integer", "minimum": 0, "maximum": 130}
        }
    })
    .to_string();
    let env = harness.env().clone();
    let scope = harness.scope();
    let (_, version) = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .create_version(&env, &schema, 1_000_000)
        .await
        .expect("create schema version");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .activate_version(&env, version)
        .await
        .expect("activate schema version");
}

/// Install (or replace) a signup form for the harness client with the given field list JSON.
async fn install_form(harness: &Harness, fields_json: &str) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let client = harness.client_id().to_string();
    let id = SignupFormId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .signup_forms()
        .set(
            &env,
            &id,
            1_000_000,
            NewSignupForm {
                client_id: &client,
                fields_json,
            },
        )
        .await
        .expect("set signup form");
}

/// A form with ONE required LATER-LOGIN field on `nickname` (an empty rule, so the trait's own
/// minLength must still enforce).
const NICKNAME_LATER_LOGIN_REQUIRED: &str = r#"[{"trait_pointer":"/nickname","required":true,"order":0,"step":"later_login","rules":{},"label_message_id":1070001}]"#;

/// A `/authorize` resume target for the harness client, so the login flow resolves the client
/// whose signup form the progressive profiling path loads.
fn return_to(harness: &Harness) -> String {
    format!(
        "/authorize?response_type=code&client_id={}&redirect_uri=https://rp.example/cb&scope=openid",
        harness.client_id()
    )
}

fn urlencode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

fn create_path(harness: &Harness, journey: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/{journey}",
        scope.tenant(),
        scope.environment()
    )
}

fn submit_path(harness: &Harness, journey: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/{journey}/submit",
        scope.tenant(),
        scope.environment()
    )
}

fn browser_login_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/flow/login", scope.tenant(), scope.environment())
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

/// Create an API login flow carrying the client resume target, returning `(flow_id, token)`.
async fn api_login_create(harness: &Harness) -> (String, String) {
    let (status, _h, create) = post_json(
        harness,
        &create_path(harness, "login"),
        &json!({"return_to": return_to(harness)}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    let flow_id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    (flow_id, token)
}

/// Submit the primary factor (identifier + password) on an API login flow.
async fn submit_primary(
    harness: &Harness,
    flow_id: &str,
    token: &str,
    identifier: &str,
) -> (StatusCode, Value) {
    let (status, _h, body) = post_json(
        harness,
        &submit_path(harness, "login"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {"identifier": identifier, "password": PASSWORD},
        }),
    )
    .await;
    (status, body)
}

/// Find a node by its input `name` in a flow object's node list.
fn node_named<'a>(flow: &'a Value, name: &str) -> Option<&'a Value> {
    flow["ui"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["attributes"]["name"] == name)
}

/// The subject's decrypted trait document, or [`None`] when it has no traits (read through the
/// app store on the scoped RLS path the engine itself uses).
async fn read_traits(harness: &Harness, subject: &str) -> Option<Value> {
    let scope = harness.scope();
    let user_id = UserId::parse_in_scope(subject, &scope).expect("parse subject");
    harness
        .store()
        .scoped(scope)
        .users()
        .traits(&user_id)
        .await
        .expect("read traits")
        .map(|(_, doc)| doc)
}

#[tokio::test]
async fn a_missing_required_later_login_field_prompts_on_the_next_login() {
    // AC 1: a subsequent login with a missing required later-login field transitions to the
    // progressive profiling state (it does NOT mint on the primary factor alone), and the field
    // renders as a NON-BLOCKING node (required: false, the skippable relaxation).
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    harness.seed_user("member@example.test", PASSWORD).await;

    let (flow_id, token) = api_login_create(&harness).await;
    let (status, body) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    assert_eq!(status, StatusCode::OK, "submit: {body}");
    assert_ne!(
        body["state"], "completed",
        "a login with a missing required later-login field does NOT mint on the primary factor: {body}"
    );
    assert_eq!(
        body["flow"]["state"], "progressive_profiling",
        "the flow holds on the progressive profiling state: {body}"
    );
    let nickname = node_named(&body["flow"], "nickname").expect("the nickname node prompts");
    assert_eq!(nickname["group"], "profile");
    assert_eq!(
        nickname["attributes"]["required"], false,
        "the held field is NON-BLOCKING (the skippable relaxation): {nickname}"
    );
    // The submit control is present so the user can proceed (or skip).
    assert!(
        node_named(&body["flow"], "method").is_some(),
        "the profiling step renders a submit control"
    );
}

#[tokio::test]
async fn a_valid_value_merges_into_the_traits_and_mints() {
    // AC 2: a valid later-login value is deep-merged into the identity's traits and the login
    // mints (the honest amr is unchanged, pwd only, since no second factor ran).
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    let subject = harness.seed_user("member@example.test", PASSWORD).await;

    let (flow_id, token) = api_login_create(&harness).await;
    let (_s, held) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();

    let (status, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"nickname": "zeke"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "profiling submit: {done}");
    assert_eq!(done["state"], "completed", "the valid value mints: {done}");

    let traits = read_traits(&harness, &subject)
        .await
        .expect("traits sealed");
    assert_eq!(
        traits["nickname"], "zeke",
        "the collected value is merged into the identity traits: {traits}"
    );
}

/// Seal a trait document on an existing subject through the control-plane acting path (the same
/// `set_traits` seam progressive profiling writes through), so a test can stage a pre-existing
/// trait before a profiling login.
async fn seed_traits(harness: &Harness, subject: &str, traits_json: &str) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let user_id = UserId::parse_in_scope(subject, &scope).expect("parse subject");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_traits(&env, &user_id, traits_json)
        .await
        .expect("seed traits");
}

#[tokio::test]
async fn the_merge_preserves_a_pre_existing_unrelated_trait() {
    // AC 5b: the deep merge is additive through the full set_traits round-trip. A subject who
    // already carries an unrelated trait (age) keeps it when progressive profiling collects a
    // different one (nickname); the write never drops the pre-existing key.
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    let subject = harness.seed_user("member@example.test", PASSWORD).await;
    seed_traits(&harness, &subject, r#"{"age":42}"#).await;

    let (flow_id, token) = api_login_create(&harness).await;
    let (_s, held) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();

    let (status, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"nickname": "zeke"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "profiling submit: {done}");
    assert_eq!(done["state"], "completed", "the valid value mints: {done}");

    let traits = read_traits(&harness, &subject)
        .await
        .expect("traits sealed");
    assert_eq!(
        traits["nickname"], "zeke",
        "the collected value is merged in: {traits}"
    );
    assert_eq!(
        traits["age"], 42,
        "the pre-existing unrelated trait survives the merge: {traits}"
    );
}

#[tokio::test]
async fn an_all_empty_submit_skips_and_persists_nothing() {
    // AC 3: the step is SKIPPABLE: an all-empty submit mints WITHOUT persisting any traits.
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    let subject = harness.seed_user("member@example.test", PASSWORD).await;

    let (flow_id, token) = api_login_create(&harness).await;
    let (_s, held) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();

    let (status, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"nickname": ""}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(done["state"], "completed", "a skip still mints: {done}");
    assert!(
        read_traits(&harness, &subject).await.is_none(),
        "a skipped profiling step persists no traits"
    );
}

#[tokio::test]
async fn a_non_empty_invalid_value_re_renders_then_a_skip_mints() {
    // AC 4: a NON-EMPTY value that fails trait-authoritative validation re-renders the error
    // with the flow OPEN (not consumed); clearing the field then submitting mints.
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    let subject = harness.seed_user("member@example.test", PASSWORD).await;

    let (flow_id, token) = api_login_create(&harness).await;
    let (_s, held) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();

    // "ab" is below the trait's minLength 3: an Invalid re-render, NOT a mint.
    let (status, _h, invalid) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"nickname": "ab"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        invalid["state"], "completed",
        "an invalid value does not mint: {invalid}"
    );
    assert_eq!(invalid["flow"]["state"], "progressive_profiling");
    let nickname = node_named(&invalid["flow"], "nickname").expect("nickname node");
    assert!(
        nickname["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|m| m["id"].as_u64() == Some(SIGNUP_FIELD_TOO_SHORT)),
        "the too-short error attaches to the nickname node: {nickname}"
    );
    assert!(
        read_traits(&harness, &subject).await.is_none(),
        "the invalid attempt persisted nothing"
    );

    // The escape hatch: clear the field and submit; the skip mints.
    let token = invalid["submit_token"].as_str().expect("token").to_owned();
    let (status, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"nickname": ""}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        done["state"], "completed",
        "clearing then submitting mints: {done}"
    );
}

#[tokio::test]
async fn removing_a_field_from_the_form_does_not_delete_a_collected_trait() {
    // AC 5: once a trait is collected, removing its field from the form never deletes it, and a
    // later login with nothing to collect mints directly with the trait intact.
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    let subject = harness.seed_user("member@example.test", PASSWORD).await;

    // First login: collect the nickname.
    let (flow_id, token) = api_login_create(&harness).await;
    let (_s, held) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    let token = held["submit_token"].as_str().expect("token").to_owned();
    let (_s, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"nickname": "zeke"}}),
    )
    .await;
    assert_eq!(done["state"], "completed");
    assert_eq!(
        read_traits(&harness, &subject).await.expect("traits")["nickname"],
        "zeke"
    );

    // Remove the field from the form (an empty field list).
    install_form(&harness, "[]").await;

    // Second login: nothing to collect, so it mints directly, and the collected trait survives.
    let (flow_id, token) = api_login_create(&harness).await;
    let (status, direct) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        direct["state"], "completed",
        "with the field removed the login mints directly: {direct}"
    );
    assert_eq!(
        read_traits(&harness, &subject).await.expect("traits")["nickname"],
        "zeke",
        "removing the field never deleted the already-collected trait"
    );
}

#[tokio::test]
async fn both_transports_render_the_same_profiling_node_set() {
    // AC 6: the flow object is transport-agnostic, so the profiling node set is the same on the
    // API and the browser transport (the browser adds only the hidden `flow` continuation node).
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    harness.seed_user("member@example.test", PASSWORD).await;

    // API transport: the profiling node set carries the nickname field and the submit control.
    let (flow_id, token) = api_login_create(&harness).await;
    let (_s, held) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    let api_nodes: Vec<String> = held["flow"]["ui"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter_map(|node| node["attributes"]["name"].as_str().map(str::to_owned))
        .collect();
    assert!(api_nodes.iter().any(|n| n == "nickname"));
    assert!(api_nodes.iter().any(|n| n == "method"));
    assert!(
        !api_nodes.iter().any(|n| n == "flow"),
        "the API transport carries no hidden flow node: {api_nodes:?}"
    );

    // Browser transport: GET creates + renders the login page, POST the primary factor, and the
    // held profiling page renders the SAME nickname field and the continue control.
    let (_s, _h, html) = harness
        .get_with_cookie(
            &format!(
                "{}?return_to={}",
                browser_login_path(&harness),
                urlencode(&return_to(&harness))
            ),
            None,
        )
        .await;
    let flow_id = extract_flow_id(&html);
    let form = format!(
        "flow={}&identifier={}&password={}",
        urlencode(&flow_id),
        urlencode("member@example.test"),
        urlencode(PASSWORD),
    );
    let (status, _h, page) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_login_path(&harness))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(form))
                .expect("request builds"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "browser primary submit");
    assert!(
        page.contains("name=\"nickname\""),
        "the browser profiling page renders the same nickname field: {page}"
    );
}

#[tokio::test]
async fn no_missing_required_later_login_field_mints_directly() {
    // AC 7: an OPTIONAL later-login field (or none missing) does NOT trigger the hold; the login
    // mints directly with no profiling state.
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(
        &harness,
        r#"[{"trait_pointer":"/nickname","required":false,"order":0,"step":"later_login","rules":{},"label_message_id":1070001}]"#,
    )
    .await;
    harness.seed_user("member@example.test", PASSWORD).await;

    let (flow_id, token) = api_login_create(&harness).await;
    let (status, direct) = submit_primary(&harness, &flow_id, &token, "member@example.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        direct["state"], "completed",
        "an optional later-login field does not trigger the hold: {direct}"
    );
}

#[tokio::test]
async fn mfa_then_profiling_mints_with_an_honest_combined_amr() {
    // AC 8 (recommended): the held steps compose. A login that steps up to MFA runs the second
    // factor FIRST, THEN the progressive profiling step, and the final mint records the honest
    // combined amr (pwd + totp). The profiling step never re-challenges the already-proven factor.
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness, NICKNAME_LATER_LOGIN_REQUIRED).await;
    let subject = harness.seed_user("mfa-user@example.test", PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;

    // Primary factor: the flow steps up to the MFA challenge (NOT progressive profiling yet).
    let (flow_id, token) = api_login_create(&harness).await;
    let (_s, challenge) = submit_primary(&harness, &flow_id, &token, "mfa-user@example.test").await;
    assert_eq!(
        challenge["flow"]["state"], "mfa_challenge",
        "the primary factor steps up to MFA first: {challenge}"
    );
    let token = challenge["submit_token"]
        .as_str()
        .expect("token")
        .to_owned();

    // Advance to a fresh TOTP step, then submit a real current code: it HOLDS on progressive
    // profiling (it does NOT mint yet, since the later-login field is still missing).
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = code_at(
        &[0x0A; 20],
        TotpParams::authenticator_default(),
        harness
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs(),
    );
    let (status, _h, held) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"code": code}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mfa submit: {held}");
    assert_ne!(
        held["state"], "completed",
        "MFA success holds for profiling: {held}"
    );
    assert_eq!(held["flow"]["state"], "progressive_profiling");
    let token = held["submit_token"].as_str().expect("token").to_owned();

    // Collect the field: the mint now runs, and the amr honestly records pwd + totp.
    let (status, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({"id": flow_id, "submit_token": token, "nodes": {"nickname": "zeke"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "profiling submit: {done}");
    assert_eq!(
        done["state"], "completed",
        "the mint runs after profiling: {done}"
    );

    let methods = latest_session_methods(&harness, &subject).await;
    assert!(
        methods.contains("pwd") && methods.contains("totp"),
        "the final mint records the honest combined amr: {methods}"
    );
    assert_eq!(
        read_traits(&harness, &subject).await.expect("traits")["nickname"],
        "zeke"
    );
}

/// The `auth_methods` recorded on the most recent session for `subject` (owner pool, so
/// row-level security is bypassed).
async fn latest_session_methods(harness: &Harness, subject: &str) -> String {
    use sqlx::Row;
    let pool = harness.db().owner_pool();
    sqlx::query(
        "SELECT auth_methods FROM sessions WHERE subject = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(subject)
    .fetch_one(pool)
    .await
    .expect("session row")
    .get("auth_methods")
}

/// Extract the hidden `flow` field's value from a rendered flow page.
fn extract_flow_id(html: &str) -> String {
    let marker = "name=\"flow\" value=\"";
    let start = html.find(marker).expect("flow hidden field") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("flow value end");
    rest[..end].to_owned()
}
