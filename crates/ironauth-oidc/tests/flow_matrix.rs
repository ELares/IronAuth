// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #84) PR 4: the cross-transport TEST MATRIX, the contract
//! VERSIONING discipline, the published JSON Schema as the normative artifact, the GOLDEN
//! flow-object snapshots, and the consolidated M7 timing harness on the JSON transport.
//!
//! This binary is the acceptance closure for #84. It pins:
//!
//! - THE MATRIX (the issue's "all four journeys render from the flow contract with no
//!   journey-specific client logic" + "integration tests driving all four journeys over both
//!   transports from one test matrix"): ONE generic driver walks EVERY journey (login,
//!   registration, MFA, recovery, and the federation launcher) over BOTH transports by
//!   following the flow object's nodes, with no per-journey client branching. The native-JSON
//!   driver completes every journey with NO HTML parsing.
//! - CROSS-TRANSPORT EQUIVALENCE (the "one type / one state machine / one code path" property):
//!   for every journey/state, the API and browser transports render the SAME flow object once
//!   the two documented mechanical deltas (the transport tag, the `ui.action`, and the browser
//!   only hidden `flow` node) are normalized out.
//! - CONTRACT VERSIONING: the `contract_version` is consistent across every published artifact,
//!   and the golden corpus + the schema/message freshness gates make a breaking change LOUD.
//! - THE GOLDEN CORPUS: the committed `docs/flow-golden.json` reproduces byte-identically from
//!   the engine (a breaking change to any journey's rendered flow fails the diff), and every
//!   golden flow object VALIDATES against the published `docs/flow-schema.json`.
//! - THE M7 TIMING HARNESS on the JSON transport: known vs unknown identifiers are op-count and
//!   body indistinguishable on all three identifier-bearing steps (login, registration
//!   duplicate-address, recovery initiation).

mod common;

use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_oidc::flow::model::CONTRACT_VERSION;
use ironauth_oidc::{Argon2Params, HashingPool, VerificationSender};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

// ==========================================================================================
// The generic driver: ONE walker follows the flow object's nodes for EVERY journey. No
// journey-specific client logic lives here -- the only per-journey input is the server-side
// setup and the answer function that maps a node field name to a value.
// ==========================================================================================

/// The terminal a journey walk reaches.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// A session was minted (login, registration, MFA, recovery).
    Completed,
    /// The flow handed off to an external leg (the federation launcher).
    Redirect,
}

/// An answer function: maps a submittable node field name to the value to submit, or [`None`]
/// to leave it unanswered. Dynamic answers (a delivered recovery code, a live TOTP code) are
/// computed lazily on demand, so the SAME generic walker drives every journey.
type Answerer<'a> = dyn Fn(&str) -> Option<String> + 'a;

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

fn browser_path(harness: &Harness, journey: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/{journey}",
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

/// The submittable field names of a flow object's nodes (issue #84): every enabled input node
/// that is not hidden and not a submit control. This is what the generic driver reads to know
/// what to fill, for ANY journey -- there is no journey-specific field list.
fn submittable_fields(flow: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for node in flow["ui"]["nodes"].as_array().into_iter().flatten() {
        let attrs = &node["attributes"];
        if attrs["node_type"] != "input" {
            continue;
        }
        if attrs["disabled"] == Value::Bool(true) {
            continue;
        }
        let input_type = attrs["input_type"].as_str().unwrap_or_default();
        if matches!(input_type, "hidden" | "submit") {
            continue;
        }
        if let Some(name) = attrs["name"].as_str() {
            names.push(name.to_owned());
        }
    }
    names
}

/// Walk a journey to completion over the NATIVE JSON transport (issue #84), following ONLY the
/// flow object's nodes -- NO HTML is ever parsed. Proves a native client completes every
/// journey via JSON against the same flow object the browser renders.
async fn walk_native(
    harness: &Harness,
    journey: &str,
    create_body: &Value,
    answer: &Answerer<'_>,
) -> Outcome {
    let (status, _h, create) =
        post_json(harness, &create_path(harness, journey), create_body).await;
    assert_eq!(status, StatusCode::OK, "native create {journey}: {create}");
    let mut flow = create["flow"].clone();
    let mut submit_token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    let flow_id = flow["id"].as_str().expect("flow id").to_owned();

    for _step in 0..8 {
        // Build the node values purely from the rendered nodes plus the answer function.
        let mut nodes = serde_json::Map::new();
        for name in submittable_fields(&flow) {
            if let Some(value) = answer(&name) {
                nodes.insert(name, Value::String(value));
            }
        }
        let (status, _h, body) = post_json(
            harness,
            &submit_path(harness, journey),
            &json!({ "id": flow_id, "submit_token": submit_token, "nodes": Value::Object(nodes) }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "native submit {journey}: {body}");
        match body["state"].as_str() {
            Some("completed") => return Outcome::Completed,
            Some("redirect") => return Outcome::Redirect,
            _ => {
                // A re-render: advance to the next flow object with the rotated token.
                flow = body["flow"].clone();
                body["submit_token"]
                    .as_str()
                    .expect("rotated submit token")
                    .clone_into(&mut submit_token);
            }
        }
    }
    panic!("native {journey} did not reach a terminal within the step budget");
}

/// Walk a journey to completion over the BROWSER transport (issue #84), following the rendered
/// form's input nodes with the SAME generic logic (fill the answerable fields, post them back).
/// A completion or a launcher hand-off is a redirect (every journey here carries a resume
/// target), which is the browser terminal.
async fn walk_browser(
    harness: &Harness,
    journey: &str,
    create_query: &str,
    answer: &Answerer<'_>,
) -> Outcome {
    let get_path = format!("{}?{create_query}", browser_path(harness, journey));
    let (status, _h, mut html) = harness.get_with_cookie(&get_path, None).await;
    assert_eq!(status, StatusCode::OK, "browser create {journey}: {html}");
    let flow_id = extract_hidden_flow(&html);

    for _step in 0..8 {
        let mut form = format!("flow={}", urlencode(&flow_id));
        for name in html_input_names(&html) {
            if name == "flow" {
                continue;
            }
            if let Some(value) = answer(&name) {
                form.push('&');
                form.push_str(&name);
                form.push('=');
                form.push_str(&urlencode(&value));
            }
        }
        let (status, headers, body) = harness
            .send(
                Request::builder()
                    .method("POST")
                    .uri(browser_path(harness, journey))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("Sec-Fetch-Site", "same-origin")
                    .body(Body::from(form))
                    .expect("request builds"),
            )
            .await;
        if status.is_redirection() {
            // A federation launcher redirects to the federation authorize leg; every other
            // journey redirects to its resume target on completion. Both are the browser
            // terminal; distinguish by the Location target.
            let location = headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            return if location.contains("/federation/") {
                Outcome::Redirect
            } else {
                Outcome::Completed
            };
        }
        assert_eq!(status, StatusCode::OK, "browser submit {journey}: {body}");
        html = body;
    }
    panic!("browser {journey} did not reach a terminal within the step budget");
}

// ==========================================================================================
// THE MATRIX: every journey x both transports from ONE harness + ONE generic driver.
// ==========================================================================================

/// A flows-enabled, MFA/recovery-capable harness with a recording sender (for the delivered
/// recovery code) and a cheap deterministic Argon2 pool.
async fn matrix_harness() -> (Harness, Arc<RecordingSender>) {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    harness.enable_flows();
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    (harness, sender)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_matrix_drives_every_journey_over_both_transports_from_one_driver() {
    let (harness, sender) = matrix_harness().await;
    // A valid local resume so every completion is a browser 303 (a uniform terminal shape).
    let resume = format!("/authorize?client_id={}", harness.client_id());

    // ---- LOGIN ----
    harness.seed_user("login@example.test", PASSWORD).await;
    let login_answer = |name: &str| match name {
        "identifier" => Some("login@example.test".to_owned()),
        "password" => Some(PASSWORD.to_owned()),
        _ => None,
    };
    assert_eq!(
        walk_native(
            &harness,
            "login",
            &json!({ "return_to": resume }),
            &login_answer
        )
        .await,
        Outcome::Completed,
        "native login completes via JSON"
    );
    assert_eq!(
        walk_browser(
            &harness,
            "login",
            &format!("return_to={}", urlencode(&resume)),
            &login_answer,
        )
        .await,
        Outcome::Completed,
        "browser login completes"
    );

    // ---- REGISTRATION (open mode: a fresh address completes) ----
    let reg_native_id = "reg-native@example.test";
    let reg_browser_id = "reg-browser@example.test";
    let reg_answer = |name: &str| match name {
        // The address differs per transport so each registration is a genuine new account.
        "identifier" => Some(CURRENT_REG_ID.with(|c| c.borrow().clone())),
        "password" => Some(PASSWORD.to_owned()),
        _ => None,
    };
    CURRENT_REG_ID.with(|c| reg_native_id.clone_into(&mut c.borrow_mut()));
    assert_eq!(
        walk_native(
            &harness,
            "registration",
            &json!({ "return_to": resume }),
            &reg_answer,
        )
        .await,
        Outcome::Completed,
        "native registration completes via JSON"
    );
    CURRENT_REG_ID.with(|c| reg_browser_id.clone_into(&mut c.borrow_mut()));
    assert_eq!(
        walk_browser(
            &harness,
            "registration",
            &format!("return_to={}", urlencode(&resume)),
            &reg_answer,
        )
        .await,
        Outcome::Completed,
        "browser registration completes"
    );

    // ---- MFA (login that steps up to a second factor) ----
    let mfa_subject = harness.seed_user("mfa@example.test", PASSWORD).await;
    harness.seed_active_totp(&mfa_subject).await;
    harness.set_tenant_min_class("mfa").await;
    let advanced = Cell::new(false);
    let mfa_answer = |name: &str| match name {
        "identifier" => Some("mfa@example.test".to_owned()),
        "password" => Some(PASSWORD.to_owned()),
        "code" => {
            // Advance to a fresh TOTP step once, distinct from the seeded activation step, so
            // the current code is not refused single-use (well within the 900s flow TTL).
            if !advanced.get() {
                harness.clock().advance(Duration::from_secs(90));
                advanced.set(true);
            }
            Some(code_at(
                &[0x0A; 20],
                TotpParams::authenticator_default(),
                now_secs(&harness),
            ))
        }
        _ => None,
    };
    assert_eq!(
        walk_native(
            &harness,
            "login",
            &json!({ "return_to": resume }),
            &mfa_answer
        )
        .await,
        Outcome::Completed,
        "native login PLUS MFA completes entirely via JSON"
    );
    // A fresh browser MFA walk (advance the guard is per-run; reset it).
    advanced.set(false);
    assert_eq!(
        walk_browser(
            &harness,
            "login",
            &format!("return_to={}", urlencode(&resume)),
            &mfa_answer,
        )
        .await,
        Outcome::Completed,
        "browser login PLUS MFA completes"
    );

    // ---- RECOVERY (identifier -> uniform ack -> delivered code) ----
    harness.seed_user("recover@example.test", PASSWORD).await;
    let recover_answer = |name: &str| match name {
        "identifier" => Some("recover@example.test".to_owned()),
        // The code is delivered on initiation; read the latest one lazily when the ack renders.
        "code" => Some(last_code(&sender, "recover@example.test")),
        _ => None,
    };
    assert_eq!(
        walk_native(
            &harness,
            "recovery",
            &json!({ "return_to": resume }),
            &recover_answer,
        )
        .await,
        Outcome::Completed,
        "native recovery completes via JSON"
    );
    assert_eq!(
        walk_browser(
            &harness,
            "recovery",
            &format!("return_to={}", urlencode(&resume)),
            &recover_answer,
        )
        .await,
        Outcome::Completed,
        "browser recovery completes"
    );

    // ---- FEDERATION (launcher: a redirect to the existing authorize leg) ----
    let fed_answer = |_name: &str| None;
    assert_eq!(
        walk_native(
            &harness,
            "federation",
            &json!({ "connector": "acme-oidc", "return_to": resume }),
            &fed_answer,
        )
        .await,
        Outcome::Redirect,
        "native federation launcher redirects"
    );
    assert_eq!(
        walk_browser(
            &harness,
            "federation",
            &format!("connector=acme-oidc&return_to={}", urlencode(&resume)),
            &fed_answer,
        )
        .await,
        Outcome::Redirect,
        "browser federation launcher redirects"
    );
}

thread_local! {
    /// The registration identifier the current walk should submit (a fresh address per
    /// transport, so each registration creates a genuine new account).
    static CURRENT_REG_ID: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

// ==========================================================================================
// CROSS-TRANSPORT EQUIVALENCE: the API and browser render the SAME flow object.
// ==========================================================================================

/// Normalize a flow object for cross-transport comparison (issue #84): drop the two documented
/// per-transport deltas -- the `transport` tag and the `ui.action` -- and the browser only
/// hidden `flow` node. What remains (the state, journey, node set, groups, message ids, and
/// their deterministic order) MUST be identical between the transports.
fn normalize_for_cross_transport(flow: &Value) -> Value {
    let mut flow = flow.clone();
    let obj = flow.as_object_mut().expect("flow object");
    obj.remove("transport");
    obj.remove("id");
    if let Some(ui) = obj.get_mut("ui").and_then(Value::as_object_mut) {
        ui.remove("action");
        if let Some(nodes) = ui.get_mut("nodes").and_then(Value::as_array_mut) {
            nodes.retain(|node| {
                !(node["attributes"]["node_type"] == "input"
                    && node["attributes"]["name"] == "flow"
                    && node["attributes"]["input_type"] == "hidden")
            });
        }
    }
    flow
}

#[test]
fn every_golden_state_renders_the_same_flow_object_across_both_transports() {
    // The golden corpus carries every journey/state on both transports. For each state, the
    // API and browser goldens must be identical once the two mechanical deltas are normalized
    // out -- the structural proof of "one type / one state machine / one code path".
    let corpus = read_golden_file();
    let flows = corpus["flows"].as_object().expect("flows map");
    let mut checked = 0_usize;
    for (name, api_flow) in flows {
        let Some(base) = name.strip_suffix("_api") else {
            continue;
        };
        let browser_name = format!("{base}_browser");
        let browser_flow = flows
            .get(&browser_name)
            .unwrap_or_else(|| panic!("a browser golden for {base}"));
        assert_eq!(
            normalize_for_cross_transport(api_flow),
            normalize_for_cross_transport(browser_flow),
            "the {base} flow object differs across transports beyond the allowed deltas"
        );
        checked += 1;
    }
    assert!(
        checked >= 10,
        "every state was cross-transport checked: {checked}"
    );
}

#[tokio::test]
async fn the_engine_renders_cross_transport_equivalent_start_states_for_every_journey() {
    use ironauth_oidc::flow::create_flow;
    use ironauth_oidc::flow::model::{Journey, Transport};

    let (harness, _sender) = matrix_harness().await;
    let resume = format!("/authorize?client_id={}", harness.client_id());

    let cases: [(Journey, Option<&str>); 4] = [
        (Journey::Login, None),
        (Journey::Registration, None),
        (Journey::Recovery, None),
        (Journey::Federation, Some("acme-oidc")),
    ];
    for (journey, connector) in cases {
        // The federation launcher requires a resume target; the others accept one too.
        let return_to = Some(resume.as_str());
        let (_id_a, _tok_a, api_flow) = create_flow(
            harness.state(),
            harness.scope(),
            Transport::Api,
            journey,
            return_to,
            None,
            connector,
        )
        .await
        .expect("api create");
        let (_id_b, _tok_b, browser_flow) = create_flow(
            harness.state(),
            harness.scope(),
            Transport::Browser,
            journey,
            return_to,
            None,
            connector,
        )
        .await
        .expect("browser create");
        let api_json = serde_json::to_value(&api_flow).expect("serialize");
        let browser_json = serde_json::to_value(&browser_flow).expect("serialize");
        assert_eq!(
            normalize_for_cross_transport(&api_json),
            normalize_for_cross_transport(&browser_json),
            "the {journey:?} start state differs across transports beyond the allowed deltas"
        );
    }
}

// ==========================================================================================
// THE GOLDEN CORPUS: the committed file reproduces from the engine, and validates against the
// published JSON Schema.
// ==========================================================================================

#[test]
fn the_committed_golden_corpus_reproduces_byte_identically_from_the_engine() {
    // The freshness LOCK: the committed docs/flow-golden.json must equal the engine-generated
    // corpus (modulo the generator's `$comment`). A breaking change to any journey's rendered
    // flow changes this, failing here and the CI diff gate. Additive changes update the file.
    let committed = read_golden_file();
    let generated = ironauth_oidc::flow::golden_corpus();
    assert_eq!(
        committed["contract_version"], generated["contract_version"],
        "the golden corpus contract_version drifted"
    );
    assert_eq!(
        committed["flows"], generated["flows"],
        "docs/flow-golden.json is stale; run scripts/flow-golden.sh and commit it"
    );
}

#[test]
fn every_golden_flow_validates_against_the_published_json_schema() {
    let schema = read_schema_file();
    let defs = schema.get("$defs").cloned().unwrap_or(Value::Null);
    let corpus = read_golden_file();
    for (name, flow) in corpus["flows"].as_object().expect("flows map") {
        // Structural validation against the PUBLISHED artifact.
        if let Err(reason) = schema_validate(&schema, &defs, flow) {
            panic!("golden {name} is not schema-valid: {reason}");
        }
        // And the definitive proof for a schemars-generated schema: the value round-trips
        // through the Rust type the schema mirrors, unchanged.
        let typed: ironauth_oidc::flow::model::Flow =
            serde_json::from_value(flow.clone()).unwrap_or_else(|e| panic!("golden {name}: {e}"));
        let reserialized = serde_json::to_value(&typed).expect("serialize");
        assert_eq!(
            &reserialized, flow,
            "golden {name} does not round-trip through Flow"
        );
    }
}

// ==========================================================================================
// CONTRACT VERSIONING: the version is consistent across every published artifact, so a bump
// must be applied coherently, and any breaking shape change is loud in the golden/schema diff.
// ==========================================================================================

#[test]
fn the_contract_version_is_consistent_across_every_published_artifact() {
    let golden = read_golden_file();
    let messages: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/flow-messages.json"
        ))
        .expect("read docs/flow-messages.json"),
    )
    .expect("parse messages");

    let version = u64::from(CONTRACT_VERSION);
    assert_eq!(
        golden["contract_version"].as_u64(),
        Some(version),
        "docs/flow-golden.json contract_version must equal the CONTRACT_VERSION constant"
    );
    assert_eq!(
        messages["contract_version"].as_u64(),
        Some(version),
        "docs/flow-messages.json contract_version must equal the CONTRACT_VERSION constant"
    );
    // Every golden flow object carries the same version (the wire field the header mirrors).
    for (name, flow) in golden["flows"].as_object().expect("flows map") {
        assert_eq!(
            flow["contract_version"].as_u64(),
            Some(version),
            "golden {name} carries a divergent contract_version"
        );
    }
}

// ==========================================================================================
// THE M7 ADVERSARIAL TIMING HARNESS on the JSON transport: known vs unknown identifiers are
// op-count AND body indistinguishable on ALL THREE identifier-bearing steps.
// ==========================================================================================

/// Create a flow, submit the identifier-bearing step on the JSON transport, and return the
/// status, the response body, and the Argon2-op delta the submit spent.
async fn identifier_step_ops(
    harness: &Harness,
    pool: &HashingPool,
    journey: &str,
    nodes: &Value,
) -> (StatusCode, Value, u64) {
    let (_s, _h, create) = post_json(harness, &create_path(harness, journey), &json!({})).await;
    let flow_id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let submit_token = create["submit_token"].as_str().expect("token").to_owned();
    let before = pool.argon2_ops();
    let (status, _h, body) = post_json(
        harness,
        &submit_path(harness, journey),
        &json!({ "id": flow_id, "submit_token": submit_token, "nodes": nodes }),
    )
    .await;
    (status, body, pool.argon2_ops() - before)
}

#[tokio::test]
async fn the_m7_timing_harness_is_uniform_on_every_identifier_step_on_json() {
    // The registration duplicate-address step needs closed mode (the #64 uniform posture).
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            registration_closed: true,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    harness.enable_flows();
    harness.install_verification_sender(Arc::new(RecordingSender::default()));
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(Arc::clone(&pool));
    harness.seed_user("known@example.test", PASSWORD).await;

    // Each identifier step: the known and the unknown submit must be body-identical (modulo the
    // per-flow id/token, which are outside the shared flow object) AND spend the same Argon2 ops.
    let steps: [(&str, Value, Value); 3] = [
        (
            "login",
            json!({ "identifier": "known@example.test", "password": "wrong-password" }),
            json!({ "identifier": "nobody@example.test", "password": "wrong-password" }),
        ),
        (
            "registration",
            json!({ "identifier": "known@example.test", "password": PASSWORD }),
            json!({ "identifier": "brand-new@example.test", "password": PASSWORD }),
        ),
        (
            "recovery",
            json!({ "identifier": "known@example.test" }),
            json!({ "identifier": "nobody@example.test" }),
        ),
    ];

    for (journey, known_nodes, unknown_nodes) in steps {
        let (known_status, mut known_body, known_ops) =
            identifier_step_ops(&harness, &pool, journey, &known_nodes).await;
        let (unknown_status, mut unknown_body, unknown_ops) =
            identifier_step_ops(&harness, &pool, journey, &unknown_nodes).await;

        assert_eq!(known_status, unknown_status, "{journey}: equal status");
        assert_eq!(
            known_ops, unknown_ops,
            "{journey}: known and unknown identifiers spend the SAME Argon2 ops on JSON"
        );
        let known_ui = known_body["flow"]["ui"].take();
        let unknown_ui = unknown_body["flow"]["ui"].take();
        assert_eq!(
            known_ui, unknown_ui,
            "{journey}: the flow UI is indistinguishable between a known and an unknown identifier"
        );
    }
}

// ==========================================================================================
// A minimal, dependency-free JSON Schema validator covering exactly the constructs schemars
// emits for the flow schema: $ref, type, properties, required, oneOf, const, enum, items.
// ==========================================================================================

/// Validate `instance` against `schema`, resolving `$ref` against `defs` (issue #84). Returns
/// `Ok(())` when the instance conforms, or `Err(reason)` describing the first violation. Covers
/// the JSON Schema subset the schemars-generated flow schema uses; anything it does not model
/// (for example `additionalProperties`, `description`) is intentionally non-constraining.
fn schema_validate(schema: &Value, defs: &Value, instance: &Value) -> Result<(), String> {
    // A `$ref` resolves against `#/$defs/<Name>`.
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or_else(|| format!("unsupported $ref {reference}"))?;
        let target = defs
            .get(name)
            .ok_or_else(|| format!("unknown $ref target {name}"))?;
        return schema_validate(target, defs, instance);
    }
    // `oneOf`: the instance must validate against at least one branch (sufficient for a
    // validity proof; the flow schema's oneOf branches are disjoint const/object unions).
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let matched = branches
            .iter()
            .any(|branch| schema_validate(branch, defs, instance).is_ok());
        if !matched {
            return Err(format!("no oneOf branch matched {instance}"));
        }
        return Ok(());
    }
    // `const`: exact equality.
    if let Some(constant) = schema.get("const") {
        if instance != constant {
            return Err(format!("expected const {constant}, found {instance}"));
        }
    }
    // `enum`: membership.
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.iter().any(|v| v == instance) {
            return Err(format!("{instance} is not in enum"));
        }
    }
    // `type`: JSON type check (schemars may emit a single type or an array of types).
    if let Some(type_field) = schema.get("type") {
        let types: Vec<&str> = match type_field {
            Value::String(single) => vec![single.as_str()],
            Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !types.is_empty() && !types.iter().any(|t| json_type_matches(t, instance)) {
            return Err(format!("{instance} is not of type {types:?}"));
        }
    }
    // `properties` + `required` on an object.
    if let Some(object) = instance.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    return Err(format!("missing required property {key}"));
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (key, subschema) in properties {
                if let Some(child) = object.get(key) {
                    schema_validate(subschema, defs, child)
                        .map_err(|reason| format!("property {key}: {reason}"))?;
                }
            }
        }
    }
    // `items` on an array.
    if let (Some(items), Some(array)) = (schema.get("items"), instance.as_array()) {
        for (index, element) in array.iter().enumerate() {
            schema_validate(items, defs, element)
                .map_err(|reason| format!("item {index}: {reason}"))?;
        }
    }
    Ok(())
}

fn json_type_matches(expected: &str, instance: &Value) -> bool {
    match expected {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "integer" => instance.is_i64() || instance.is_u64(),
        "number" => instance.is_number(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        _ => false,
    }
}

// ==========================================================================================
// Helpers.
// ==========================================================================================

fn read_golden_file() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/flow-golden.json"
        ))
        .expect("read docs/flow-golden.json"),
    )
    .expect("parse docs/flow-golden.json")
}

fn read_schema_file() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/flow-schema.json"
        ))
        .expect("read docs/flow-schema.json"),
    )
    .expect("parse docs/flow-schema.json")
}

/// The current whole-second Unix time on the harness's deterministic clock.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

/// The last non-empty OTP code the recording sender delivered to `recipient`.
fn last_code(sender: &RecordingSender, recipient: &str) -> String {
    sender
        .otp
        .lock()
        .expect("lock")
        .iter()
        .rev()
        .find(|(to, code)| to == recipient && !code.is_empty())
        .map(|(_, code)| code.clone())
        .expect("a code was delivered")
}

/// Extract the hidden `flow` field's value from a rendered flow form.
fn extract_hidden_flow(html: &str) -> String {
    let marker = "name=\"flow\"";
    let idx = html.find(marker).expect("a hidden flow field");
    let after = &html[idx..];
    let value_marker = "value=\"";
    let vidx = after.find(value_marker).expect("a flow value") + value_marker.len();
    let rest = &after[vidx..];
    let end = rest.find('"').expect("value end");
    rest[..end].to_owned()
}

/// Every `<input name="...">` field name in a rendered form (the browser's node view).
fn html_input_names(html: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = html;
    let marker = "name=\"";
    while let Some(idx) = rest.find(marker) {
        let after = &rest[idx + marker.len()..];
        if let Some(end) = after.find('"') {
            names.push(after[..end].to_owned());
            rest = &after[end..];
        } else {
            break;
        }
    }
    names
}

fn urlencode(raw: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in raw.bytes() {
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

/// A recording verification sender: captures every delivered OTP code so the recovery walk can
/// read the code the initiation delivered.
#[derive(Debug, Default)]
struct RecordingSender {
    otp: std::sync::Mutex<Vec<(String, String)>>,
}

impl VerificationSender for RecordingSender {
    fn send(
        &self,
        _scope: ironauth_store::Scope,
        _purpose: ironauth_oidc::VerificationPurpose,
        _recipient: &str,
    ) {
    }

    fn deliver_email_otp(&self, message: &ironauth_oidc::EmailOtpMessage<'_>) {
        self.otp
            .lock()
            .expect("lock")
            .push((message.recipient.to_owned(), message.code.to_owned()));
    }

    fn deliver_magic_link(&self, _message: &ironauth_oidc::MagicLinkMessage<'_>) {}
}
