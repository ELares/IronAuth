// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signup forms as data, the flow contract half (issue #87, PR 2): a configured signup field
//! materializes as a typed profile node on the NEXT created registration flow (immediacy, no
//! redeploy), and a submitted value is validated TRAIT AUTHORITATIVELY, with each failure
//! attaching to the field's node under the SAME generic message id on both the browser and the
//! API transport.
//!
//! These are the end to end pins over a real Postgres for the acceptance criteria the pure unit
//! tests in `flow::signup_fields` cover in isolation: the config to node generation, the trait
//! authoritative validation (an empty form rule still enforces the full trait), and the stable
//! failure to node mapping that is identical across transports because the flow object is
//! transport agnostic.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::{CorrelationId, NewSignupForm, SignupFormId};
use serde_json::{Value, json};
use sqlx::Row;

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

/// Install and activate an identity trait schema that carries a constrained `nickname` trait
/// (a string with a minimum length of 3) alongside the identifier/email trait.
async fn install_schema(harness: &Harness) {
    let schema = json!({
        "type": "object",
        "properties": {
            "email": {"type": "string", "x-ironauth": {"identifier": true, "verification": "email"}},
            "nickname": {"type": "string", "minLength": 3, "maxLength": 20}
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

/// Install a signup form for the harness client with ONE required Signup-step field on the
/// `nickname` trait, carrying an EMPTY rule (so the trait's own minLength must still enforce).
async fn install_form(harness: &Harness) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let client = harness.client_id().to_string();
    let fields = json!([
        {"trait_pointer": "/nickname", "required": true, "order": 0, "step": "signup",
         "rules": {}, "label_message_id": 1_070_001}
    ])
    .to_string();
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
                fields_json: &fields,
            },
        )
        .await
        .expect("set signup form");
}

/// A `/authorize` resume target for the harness client, so the flow resolves the client whose
/// signup form the registration path loads.
fn return_to(harness: &Harness) -> String {
    format!(
        "/authorize?response_type=code&client_id={}&redirect_uri=https://rp.example/cb&scope=openid",
        harness.client_id()
    )
}

/// Percent-encode a value for a query string (the browser create carries the resume target as a
/// query parameter).
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

fn create_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/registration",
        scope.tenant(),
        scope.environment()
    )
}

fn submit_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/registration/submit",
        scope.tenant(),
        scope.environment()
    )
}

fn browser_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/registration",
        scope.tenant(),
        scope.environment()
    )
}

async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, Value) {
    let (status, _h, response) = harness
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
    (status, parsed)
}

/// Create an API registration flow with the client resume target, returning `(flow_id, token,
/// flow_json)`.
async fn api_create(harness: &Harness) -> (String, String, Value) {
    let (status, create) = post_json(
        harness,
        &create_path(harness),
        &json!({"return_to": return_to(harness)}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    let flow_id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    (flow_id, token, create)
}

/// Find a node by its input `name` in a flow object's node list.
fn node_named<'a>(flow: &'a Value, name: &str) -> Option<&'a Value> {
    flow["ui"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["attributes"]["name"] == name)
}

#[tokio::test]
async fn a_configured_field_materializes_on_the_next_created_flow() {
    // Immediacy (AC): a registration flow created BEFORE the form is installed carries no
    // nickname node; after a management write, the very NEXT created flow carries it, with no
    // redeploy (the flow creation reads the live active form).
    let harness = setup().await;
    install_schema(&harness).await;

    let (_id, _token, before) = api_create(&harness).await;
    assert!(
        node_named(&before["flow"], "nickname").is_none(),
        "no signup field before the form is installed"
    );

    install_form(&harness).await;

    let (_id, _token, after) = api_create(&harness).await;
    let nickname = node_named(&after["flow"], "nickname").expect("the nickname node materializes");
    // It is a Profile group text input, required, carrying the effective constraints (the
    // trait's own minLength/maxLength) as a client hint.
    assert_eq!(nickname["group"], "profile");
    assert_eq!(nickname["attributes"]["node_type"], "input");
    assert_eq!(nickname["attributes"]["input_type"], "text");
    assert_eq!(nickname["attributes"]["required"], true);
    let constraints = &nickname["attributes"]["constraints"];
    assert_eq!(constraints["type"], "string");
    assert_eq!(constraints["minLength"], 3);
    assert_eq!(constraints["maxLength"], 20);
    // The label is the generic signup field label with the field pointer in context.
    assert_eq!(nickname["label"]["id"], 1_070_001);
    assert_eq!(nickname["label"]["context"]["field"], "/nickname");
    // The contract version bumped for the constraints carrier.
    assert_eq!(after["flow"]["contract_version"], 2);
}

#[tokio::test]
async fn a_signup_field_error_attaches_to_the_node_identically_on_both_transports() {
    // A value the TRAIT rejects (a 2 char nickname, below the trait's minLength 3) is rejected
    // even though the form rule is EMPTY (trait authoritative), and the failure attaches to the
    // nickname node under the SAME generic id on the API and the browser transport.
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;

    // API transport.
    let (flow_id, token, _create) = api_create(&harness).await;
    let (status, body) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {"identifier": "newcomer@example.test", "password": PASSWORD, "nickname": "ab"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {body}");
    assert_eq!(
        body["flow"]["state"], "registration_details",
        "re-render, not complete"
    );
    let nickname = node_named(&body["flow"], "nickname").expect("nickname node");
    assert!(
        nickname["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|m| m["id"].as_u64() == Some(SIGNUP_FIELD_TOO_SHORT)),
        "the API transport attaches the generic too-short id to the nickname node: {nickname}"
    );

    // Browser transport: the same failure renders the same field error text on the page.
    let (_s, _h, html) = harness
        .get_with_cookie(
            &format!(
                "{}?return_to={}",
                browser_path(&harness),
                urlencode(&return_to(&harness))
            ),
            None,
        )
        .await;
    let flow_id = extract_flow_id(&html);
    assert!(
        html.contains("name=\"nickname\""),
        "the browser page renders the nickname input"
    );
    let form = format!(
        "flow={}&identifier={}&password={}&nickname=ab",
        urlencode(&flow_id),
        urlencode("browser@example.test"),
        urlencode(PASSWORD),
    );
    let (status, _h, page) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_path(&harness))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(form))
                .expect("request builds"),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("This value is too short."),
        "the browser transport renders the SAME field error (id 4270002 localized): {page}"
    );
}

#[tokio::test]
async fn a_valid_signup_persists_the_collected_traits_on_the_created_user() {
    // A submission that satisfies the trait completes registration and seals the collected
    // traits atomically on the created account (traits_schema_version stamped).
    let harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;

    let (flow_id, token, _create) = api_create(&harness).await;
    let (status, done) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {"identifier": "member@example.test", "password": PASSWORD, "nickname": "zeke"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {done}");
    assert_eq!(
        done["state"], "completed",
        "the valid signup completes: {done}"
    );

    let pool = harness.db().owner_pool();
    let row = sqlx::query(
        "SELECT traits_schema_version, traits_sealed IS NOT NULL AS has_traits FROM users",
    )
    .fetch_one(pool)
    .await
    .expect("one user row");
    let schema_version: Option<i32> = row.get("traits_schema_version");
    let has_traits: bool = row.get("has_traits");
    assert!(has_traits, "the collected traits are sealed on the account");
    assert!(
        schema_version.is_some(),
        "the traits schema version is stamped"
    );
}

/// Extract the hidden `flow` field's value from a rendered registration page.
fn extract_flow_id(html: &str) -> String {
    let marker = "name=\"flow\"";
    let idx = html.find(marker).expect("a hidden flow field");
    let after = &html[idx..];
    let value_key = "value=\"";
    let vstart = after.find(value_key).expect("flow value") + value_key.len();
    let rest = &after[vstart..];
    let vend = rest.find('"').expect("flow value end");
    rest[..vend].to_owned()
}
