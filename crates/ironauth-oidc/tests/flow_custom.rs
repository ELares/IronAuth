// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #92) PR 4: the CUSTOM (declarative) journey engine path, against
//! a real Postgres.
//!
//! These pin the acceptance-critical behavior AC1 (a custom identifier-first-conditional-MFA
//! journey executes end to end through BOTH transports) plus the surrounding invariants:
//!
//! - a native JSON client runs a custom journey compiled from a declarative artifact: create ->
//!   identifier + password -> conditional MFA -> completion, with the SAME executor cores the
//!   built-in login journey uses, so the amr is HONEST (`pwd`, or `pwd` + `totp`);
//! - the wire `state` stays the FLAT `custom` for every custom step (the concrete step is server
//!   side); a client renders each step from the `ui.nodes` alone;
//! - a wrong credential re-renders and STAYS on the primary step with the flow OPEN (never a
//!   completion oracle), exactly as the built-in login path;
//! - a decision step routes with NO client round trip (the branch is traversed in-call);
//! - the built-in journeys COEXIST unchanged on the same harness; the flow contract version stays
//!   2 and the journey engine version stays 1.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_journey::{
    CmpOp, FieldRef, FieldSource, JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION, Journey, Literal,
    Predicate, Step, StepKind, Transition, compile,
};
use ironauth_oidc::flow::EmbeddedJourneySource;
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

/// The author-facing custom journey id the AC1 fixture is registered under.
const JOURNEY_ID: &str = "login_conditional_mfa";
/// The synthetic pinned version id the embedded source keys the compiled table by.
const VERSION_ID: &str = "flv_customtest00000000000000000";

// ------------------------------------------------------------------------------------------
// Fixtures: the declarative journeys, built from the ironauth-journey public artifact types.
// ------------------------------------------------------------------------------------------

fn step(id: &str, kind: StepKind, node_group: Option<&str>) -> Step {
    Step {
        id: id.to_owned(),
        kind,
        node_group: node_group.map(str::to_owned),
        subflow: None,
        decision: None,
        comment: None,
    }
}

fn mfa_required_guard(value: bool) -> Predicate {
    Predicate::Cmp {
        field: FieldRef {
            source: FieldSource::Signals,
            pointer: "/mfa_required".to_owned(),
        },
        op: CmpOp::Eq,
        value: Literal::Bool(value),
    }
}

/// The AC1 identifier-first-conditional-MFA journey: primary, then MFA only when required.
fn conditional_mfa_journey() -> Journey {
    Journey {
        schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
        id: JOURNEY_ID.to_owned(),
        engine_version: JOURNEY_ENGINE_VERSION,
        entry: "primary".to_owned(),
        comment: None,
        steps: vec![
            step("primary", StepKind::IdentifierPassword, Some("password")),
            step("mfa", StepKind::MfaChallenge, Some("totp")),
            step("done", StepKind::Terminal, None),
        ],
        transitions: vec![
            Transition {
                from: "primary".to_owned(),
                to: "mfa".to_owned(),
                guard: Some(mfa_required_guard(true)),
                comment: None,
            },
            Transition {
                from: "primary".to_owned(),
                to: "done".to_owned(),
                guard: Some(mfa_required_guard(false)),
                comment: None,
            },
            Transition {
                from: "mfa".to_owned(),
                to: "done".to_owned(),
                guard: None,
                comment: None,
            },
        ],
        subflows: None,
        subflow_definitions: None,
    }
}

/// A journey whose primary step routes through a DECISION step to completion, so a correct
/// password completes in ONE submission (the decision is traversed in-call, no client round trip).
fn decision_journey() -> Journey {
    Journey {
        schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
        id: JOURNEY_ID.to_owned(),
        engine_version: JOURNEY_ENGINE_VERSION,
        entry: "primary".to_owned(),
        comment: None,
        steps: vec![
            step("primary", StepKind::IdentifierPassword, Some("password")),
            Step {
                decision: Some(ironauth_journey::DecisionSpec::Predicate {
                    predicate: Predicate::Always,
                }),
                ..step("gate", StepKind::Decision, None)
            },
            step("done", StepKind::Terminal, None),
        ],
        transitions: vec![
            Transition {
                from: "primary".to_owned(),
                to: "gate".to_owned(),
                guard: Some(Predicate::Cmp {
                    field: FieldRef {
                        source: FieldSource::Signals,
                        pointer: "/primary_verified".to_owned(),
                    },
                    op: CmpOp::Eq,
                    value: Literal::Bool(true),
                }),
                comment: None,
            },
            Transition {
                from: "gate".to_owned(),
                to: "done".to_owned(),
                guard: None,
                comment: None,
            },
        ],
        subflows: None,
        subflow_definitions: None,
    }
}

// ------------------------------------------------------------------------------------------
// Harness setup with the custom journey source installed.
// ------------------------------------------------------------------------------------------

async fn setup_custom(journey: Journey) -> (Harness, Arc<HashingPool>) {
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
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(Arc::clone(&pool));
    let compiled = compile(&journey).expect("the fixture compiles");
    let source = EmbeddedJourneySource::single(JOURNEY_ID, VERSION_ID, compiled);
    harness.install_custom_journey_source(Arc::new(source));
    (harness, pool)
}

fn create_api_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/custom",
        scope.tenant(),
        scope.environment()
    )
}

fn submit_api_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/custom/submit",
        scope.tenant(),
        scope.environment()
    )
}

fn browser_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/custom",
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

/// Create a custom API flow (naming the journey id in the body) and return
/// `(flow_id, submit_token, create_envelope)`.
async fn api_create(harness: &Harness) -> (String, String, Value) {
    let (status, _h, create) = post_json(
        harness,
        &create_api_path(harness),
        &json!({ "journey_id": JOURNEY_ID }),
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

fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

fn has_node(flow: &Value, name: &str) -> bool {
    flow["ui"]["nodes"]
        .as_array()
        .is_some_and(|nodes| nodes.iter().any(|n| n["attributes"]["name"] == name))
}

/// The `auth_methods` on the most recent session for `subject` (owner pool).
async fn latest_session_methods(harness: &Harness, subject: &str) -> String {
    use sqlx::Row;
    let pool = harness.db().owner_pool();
    let row = sqlx::query(
        "SELECT auth_methods FROM sessions WHERE subject = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(subject)
    .fetch_one(pool)
    .await
    .expect("a session row");
    row.get("auth_methods")
}

// ------------------------------------------------------------------------------------------
// AC1 (API): a pwd-only custom journey completes with an honest pwd-only amr.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_custom_journey_completes_on_the_primary_factor_with_an_honest_pwd_amr() {
    let (harness, _pool) = setup_custom(conditional_mfa_journey()).await;
    let subject = harness
        .seed_user("custom-user@example.test", PASSWORD)
        .await;

    // Create: the envelope is a custom journey on the flat custom state, rendering the entry
    // step's identifier + password nodes.
    let (flow_id, token, create) = api_create(&harness).await;
    assert_eq!(create["flow"]["journey"], "custom", "{create}");
    assert_eq!(create["flow"]["state"], "custom", "flat custom wire state");
    assert!(has_node(&create["flow"], "identifier"), "{create}");
    assert!(has_node(&create["flow"], "password"), "{create}");

    // Submit the correct password: with no baseline MFA the plan is Complete, so routing goes
    // straight to the terminal and the flow completes with a pwd-only amr.
    let (status, headers, done) = post_json(
        &harness,
        &submit_api_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "custom-user@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {done}");
    assert_eq!(
        done["state"], "completed",
        "the custom journey completes: {done}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "sets the session cookie"
    );

    let auth_methods = latest_session_methods(&harness, &subject).await;
    assert!(auth_methods.contains("pwd"), "records pwd: {auth_methods}");
    assert!(
        !auth_methods.contains("totp"),
        "no second factor ran: {auth_methods}"
    );
}

// ------------------------------------------------------------------------------------------
// AC1 (API): the conditional MFA branch renders the second factor and completes pwd + otp.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_custom_journey_conditionally_steps_up_and_completes_with_pwd_plus_totp() {
    let (harness, _pool) = setup_custom(conditional_mfa_journey()).await;
    let subject = harness.seed_user("custom-mfa@example.test", PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    // The tenant baseline requires a second factor, so the executor emits mfa_required and the
    // guarded transition routes to the MFA step.
    harness.set_tenant_min_class("mfa").await;

    let (flow_id, token, _create) = api_create(&harness).await;
    let (status, _h, challenge) = post_json(
        &harness,
        &submit_api_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "custom-mfa@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        challenge["state"], "completed",
        "pwd alone does not complete: {challenge}"
    );
    // The wire state stays the flat custom state; the concrete step (mfa) is server side, so the
    // client sees the code node with a rotated submit token.
    assert_eq!(
        challenge["flow"]["state"], "custom",
        "still the flat custom state"
    );
    assert!(
        has_node(&challenge["flow"], "code"),
        "the MFA code node renders: {challenge}"
    );
    let token = challenge["submit_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();

    // Advance to a fresh TOTP step (distinct from the seeded activation), then submit a real code.
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = code_at(
        &[0x0A; 20],
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let (status, headers, done) = post_json(
        &harness,
        &submit_api_path(&harness),
        &json!({ "id": flow_id, "submit_token": token, "nodes": { "code": code } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mfa submit: {done}");
    assert_eq!(
        done["state"], "completed",
        "the real factor completes: {done}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "sets the session cookie"
    );

    // amr HONESTY: both the primary pwd and the genuinely-proven totp, never a fabricated mfa.
    let auth_methods = latest_session_methods(&harness, &subject).await;
    assert!(auth_methods.contains("pwd"), "records pwd: {auth_methods}");
    assert!(
        auth_methods.contains("totp"),
        "records the proven totp: {auth_methods}"
    );
}

// ------------------------------------------------------------------------------------------
// A wrong credential re-renders and STAYS on the primary step with the flow OPEN.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_wrong_credential_stays_on_the_primary_step_open() {
    let (harness, _pool) = setup_custom(conditional_mfa_journey()).await;
    harness
        .seed_user("custom-wrong@example.test", PASSWORD)
        .await;

    let (flow_id, token, _create) = api_create(&harness).await;
    let (status, headers, render) = post_json(
        &harness,
        &submit_api_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "custom-wrong@example.test", "password": "WRONG" },
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a wrong password is a typed render, never a 500: {render}"
    );
    assert_ne!(
        render["state"], "completed",
        "a wrong password never completes: {render}"
    );
    // Still the flat custom state, on the primary step, with the password node re-rendered.
    assert_eq!(render["flow"]["state"], "custom");
    assert!(
        has_node(&render["flow"], "password"),
        "the primary form re-renders: {render}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        !set_cookie.contains(SESSION_COOKIE),
        "no session minted on a wrong password"
    );
}

// ------------------------------------------------------------------------------------------
// A decision step routes with NO client round trip (traversed in-call to completion).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_decision_step_routes_to_completion_with_no_client_round_trip() {
    let (harness, _pool) = setup_custom(decision_journey()).await;
    let subject = harness
        .seed_user("custom-decide@example.test", PASSWORD)
        .await;

    let (flow_id, token, _create) = api_create(&harness).await;
    // ONE submission of the correct password: primary advances, routing crosses the decision step
    // in-call, and the terminal completes without a second submission.
    let (status, headers, done) = post_json(
        &harness,
        &submit_api_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "custom-decide@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {done}");
    assert_eq!(
        done["state"], "completed",
        "the decision routes straight to completion: {done}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "completes in one round trip"
    );
    let auth_methods = latest_session_methods(&harness, &subject).await;
    assert!(auth_methods.contains("pwd"), "records pwd: {auth_methods}");
}

// ------------------------------------------------------------------------------------------
// AC1 (browser): the same conditional-MFA journey end to end through the browser transport.
// ------------------------------------------------------------------------------------------

fn extract_flow_id(html: &str) -> String {
    // The hidden flow field renders as `name="flow" value="flw_..."` (the name/value adjacency
    // the generic renderer preserves).
    let marker = "name=\"flow\" value=\"";
    let start = html.find(marker).expect("hidden flow field") + marker.len();
    let end = html[start..].find('"').expect("value end") + start;
    html[start..end].to_owned()
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

async fn browser_post(harness: &Harness, form: String) -> (StatusCode, HeaderMap, String) {
    harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_path(harness))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(form))
                .expect("request builds"),
        )
        .await
}

#[tokio::test]
async fn a_custom_journey_runs_end_to_end_through_the_browser_transport() {
    let (harness, _pool) = setup_custom(conditional_mfa_journey()).await;
    let subject = harness
        .seed_user("custom-browser@example.test", PASSWORD)
        .await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;

    // GET creates + renders the entry page (the journey id rides the query). A valid local
    // /authorize resume target is threaded so the completion 303-redirects to it (as the built-in
    // login browser path does), rather than rendering the no-resume hardened success notice.
    let resume = format!("/authorize?client_id={}", harness.client_id());
    let (status, _h, page) = harness
        .get_with_cookie(
            &format!(
                "{}?journey_id={}&return_to={}",
                browser_path(&harness),
                JOURNEY_ID,
                urlencode(&resume)
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the custom page renders");
    assert!(
        page.contains("name=\"password\""),
        "the primary form renders: {page}"
    );
    let flow_id = extract_flow_id(&page);

    // POST the password: transitions to the MFA challenge page (still the flat custom state).
    let form = format!(
        "flow={}&identifier={}&password={}",
        urlencode(&flow_id),
        urlencode("custom-browser@example.test"),
        urlencode(PASSWORD),
    );
    let (status, _h, mfa_page) = browser_post(&harness, form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the MFA page renders (no completion yet)"
    );
    assert!(
        mfa_page.contains("name=\"code\""),
        "the MFA code field renders: {mfa_page}"
    );

    // POST a real TOTP code: 303 redirect setting the session cookie.
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = code_at(
        &[0x0A; 20],
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let form = format!("flow={}&code={}", urlencode(&flow_id), urlencode(&code));
    let (status, headers, _body) = browser_post(&harness, form).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "completion 303-redirects");
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "the redirect sets the session cookie"
    );

    let auth_methods = latest_session_methods(&harness, &subject).await;
    assert!(
        auth_methods.contains("pwd") && auth_methods.contains("totp"),
        "honest pwd + totp amr through the browser: {auth_methods}"
    );
}

// ------------------------------------------------------------------------------------------
// Coexistence: the built-in login journey is unchanged on a harness with a custom source, an
// unknown custom journey id is a uniform not found, and the contract versions are unchanged.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_builtin_login_journey_coexists_unchanged() {
    let (harness, _pool) = setup_custom(conditional_mfa_journey()).await;
    harness.seed_user("builtin@example.test", PASSWORD).await;

    // A built-in login flow (journey=login) still completes on the primary factor exactly as
    // before, unperturbed by the installed custom source.
    let scope = harness.scope();
    let create_path = format!(
        "/t/{}/e/{}/flow/api/login",
        scope.tenant(),
        scope.environment()
    );
    let submit_path = format!(
        "/t/{}/e/{}/flow/api/login/submit",
        scope.tenant(),
        scope.environment()
    );
    let (_s, _h, create) = post_json(&harness, &create_path, &json!({})).await;
    assert_eq!(create["flow"]["journey"], "login");
    assert_eq!(
        create["flow"]["state"], "identifier_password",
        "built-in state is unchanged"
    );
    let flow_id = create["flow"]["id"].as_str().expect("id").to_owned();
    let token = create["submit_token"].as_str().expect("token").to_owned();
    let (status, _h, done) = post_json(
        &harness,
        &submit_path,
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "builtin@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        done["state"], "completed",
        "the built-in login is byte-for-byte unchanged: {done}"
    );
}

#[tokio::test]
async fn an_unknown_custom_journey_id_is_a_uniform_not_found() {
    let (harness, _pool) = setup_custom(conditional_mfa_journey()).await;
    let (status, _h, body) = post_json(
        &harness,
        &create_api_path(&harness),
        &json!({ "journey_id": "no-such-journey" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown journey id is a uniform 404: {body}"
    );
}

#[test]
fn the_contract_and_engine_versions_are_unchanged() {
    // PR 4 is additive: the flow contract stays 2 and the journey engine ABI stays 1.
    assert_eq!(ironauth_oidc::flow::model::CONTRACT_VERSION, 2);
    assert_eq!(JOURNEY_ENGINE_VERSION, 1);
}
