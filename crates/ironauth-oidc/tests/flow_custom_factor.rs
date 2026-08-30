// SPDX-License-Identifier: MIT OR Apache-2.0

//! A CUSTOM FACTOR in a real login (issue #114 criterion 6).
//!
//! > The custom challenge define/create/verify sample adds a working custom factor without
//! > modifications to the flow engine.
//!
//! `ironauth-hooks`' own suite proves the triad works against a component. This file proves the
//! sentence: a tenant deploys a component, writes a journey that names it, and a real login runs
//! it -- through the shipped flow API, on a real database, against a real wasmtime sandbox.
//!
//! ## What "without modifications to the flow engine" means, and what this file can show
//!
//! It does not mean no engine code was ever written: the `custom_challenge` step kind and the
//! module that drives the triad are engine code, and they are in this PR. It means adding the
//! SECOND custom factor requires none. What this file demonstrates is the shape of that claim --
//! a factor whose rules, fields, rounds and verdicts live entirely in a component the engine
//! never inspects. The engine here renders fields it cannot interpret, holds a string it cannot
//! read, and asks a question whose answer it cannot compute.
//!
//! ## Why the assertions are about a TOKEN and a SESSION, not about the module's return type
//!
//! A test that called `custom_challenge::drive` directly would prove the module works and nothing
//! about whether a login can reach it. Every assertion below is on what the flow API returned:
//! the rendered nodes, the wire state, and whether a session was minted.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_journey::{
    JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION, Journey, Step, StepKind, Transition,
};
use ironauth_oidc::flow::FlowVersionJourneySource;
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};
use ironauth_store::{ChallengeDeployment, CorrelationId, NewFlowVersion};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";
const JOURNEY_ID: &str = "login_custom_factor";

/// The name the journey references the component by, and the name it is deployed under. The
/// binding between those two is the whole configuration contract this file exercises.
const FACTOR: &str = "wordmark";

/// The tenant's configured word list, held as an environment SECRET the component is granted.
/// The component reads it; the engine never does.
const WORDS: &str = "harbour, lantern, meridian";

/// A journey whose primary factor is followed by a CUSTOM one.
///
/// Three steps and two edges, which is the smallest topology that shows the factor is a step in
/// its own right rather than something bolted onto the login step: control reaches it AFTER the
/// password, and leaves it only for the terminal.
fn custom_factor_journey() -> Journey {
    Journey {
        schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
        id: JOURNEY_ID.to_owned(),
        engine_version: JOURNEY_ENGINE_VERSION,
        entry: "primary".to_owned(),
        comment: None,
        steps: vec![
            Step {
                id: "primary".to_owned(),
                kind: StepKind::IdentifierPassword,
                node_group: Some("password".to_owned()),
                subflow: None,
                decision: None,
                factor: None,
                comment: None,
            },
            Step {
                id: "factor".to_owned(),
                kind: StepKind::CustomChallenge,
                node_group: None,
                subflow: None,
                decision: None,
                // THE ONLY THING THE JOURNEY SAYS ABOUT THE FACTOR: its name. Not its fields, not
                // its rounds, not what makes an answer right.
                factor: Some(FACTOR.to_owned()),
                comment: None,
            },
            Step {
                id: "done".to_owned(),
                kind: StepKind::Terminal,
                node_group: None,
                subflow: None,
                decision: None,
                factor: None,
                comment: None,
            },
        ],
        transitions: vec![
            Transition {
                from: "primary".to_owned(),
                to: "factor".to_owned(),
                guard: None,
                comment: None,
            },
            Transition {
                from: "factor".to_owned(),
                to: "done".to_owned(),
                guard: None,
                comment: None,
            },
        ],
        subflows: None,
        subflow_definitions: None,
    }
}

/// A harness with flows enabled, the journey pinned, the component deployed and its secret
/// granted -- the four things an operator does to add a custom factor.
async fn setup() -> Harness {
    let engine = Arc::new(ironauth_hooks::HookEngine::new().expect("build the hook engine"));
    let runtime = Arc::new(ironauth_oidc::token_hook::HookRuntime::new(Arc::clone(
        &engine,
    )));
    // THE EPOCH DRIVER. A deployment that installs an engine and no driver leaves the deadline
    // frozen, so the only bound actually exercised is fuel. Ticking at the same rate the server
    // does keeps this test measuring the shipped configuration.
    let ticker = Arc::clone(&engine);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(ironauth_oidc::token_hook::EPOCH_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            ticker.tick();
        }
    });

    let mut harness = Harness::start_store_backed_with_hooks(runtime).await;
    harness.enable_flows();
    harness.install_hashing_pool(Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    )));

    let env = harness.env().clone();
    let scope = harness.scope();
    let artifact = serde_json::to_string(&custom_factor_journey()).expect("serialize");
    let record = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .create_next_version(
            &env,
            NewFlowVersion {
                journey_id: JOURNEY_ID,
                artifact_json: &artifact,
            },
            1_000_000,
        )
        .await
        .expect("store the journey");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .flow_versions()
        .pin(&env, JOURNEY_ID, record.version, 1_000_001, None)
        .await
        .expect("pin the journey");

    // THE SECRET FIRST, then the component, then the grant. The order matters only in that the
    // grant needs the component; the secret and the component are independent, which is why the
    // grant table carries no foreign key onto the secret.
    // THE DATA PLANE WRITES IT, not the control plane. A restrictive RLS policy binds the control
    // plane to exactly ONE reserved secret name, so an ordinary secret written there is refused
    // by Postgres before any application logic runs. The GRANT below is a control-plane action
    // (it is a capability change); the VALUE is a data-plane one.
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(
            &env,
            &harness.db().master_key(),
            "wordmark_list",
            WORDS.as_bytes(),
            None,
        )
        .await
        .expect("store the word list");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .deploy(
            &env,
            ChallengeDeployment {
                name: FACTOR,
                component: ironauth_hooks::fixtures::WORDMARK_CHALLENGE,
                payload_version: 1,
                fetch_budget: 0,
            },
        )
        .await
        .expect("deploy the factor");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .grant_secret(&env, FACTOR, "wordmark_list")
        .await
        .expect("grant the word list");

    harness.install_custom_journey_source(Arc::new(FlowVersionJourneySource::new(
        harness.store().clone(),
    )));
    harness
}

fn submit_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/custom/submit",
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
                .expect("request"),
        )
        .await;
    let parsed = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, headers, parsed)
}

async fn create(harness: &Harness) -> (String, String, Value) {
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/flow/api/custom",
        scope.tenant(),
        scope.environment()
    );
    let (status, _, body) = post_json(harness, &path, &json!({ "journey_id": JOURNEY_ID })).await;
    assert_eq!(status, StatusCode::OK, "create: {body}");
    let flow_id = body["flow"]["id"].as_str().expect("a flow id").to_owned();
    let token = body["submit_token"]
        .as_str()
        .expect("a submit token")
        .to_owned();
    (flow_id, token, body)
}

/// Every node name in a rendered flow, in order.
fn node_names(flow: &Value) -> Vec<String> {
    flow["ui"]["nodes"]
        .as_array()
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|node| node["attributes"]["name"].as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// THE EXIT CRITERION: a tenant's own factor gates a real login, over two rounds, and the login
/// completes only after it is satisfied.
#[tokio::test]
async fn a_deployed_custom_factor_gates_a_real_login_and_completes_after_two_rounds() {
    let harness = setup().await;
    let subject = harness
        .seed_user("factor-user@example.test", PASSWORD)
        .await;

    let (flow_id, token, _) = create(&harness).await;
    let (status, _, after_password) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "factor-user@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "primary: {after_password}");

    // THE FACTOR HELD THE LOGIN. A correct password alone does not complete this journey, which
    // is the property that makes everything after it meaningful: without this assertion a factor
    // that never ran would pass the completion check below.
    assert_ne!(
        after_password["state"], "completed",
        "the custom factor must hold the login after a correct password: {after_password}"
    );
    let names = node_names(&after_password["flow"]);
    assert!(
        names.iter().any(|name| name == "wordmark"),
        "the engine rendered the field the COMPONENT named, which it has never heard of: \
         {names:?}"
    );
    // THE TRANSPORT COMES FROM THE FLOW ROW, not from an assumption.
    //
    // `push_flow_hidden` emits the hidden `flow` node ONLY for a browser flow, and this whole
    // file drives the API transport. The submission executor is not handed a transport, so the
    // first version of that arm passed `Transport::Browser` for want of one -- and every test
    // here still passed, because none of them looked. This is the assertion that looks.
    assert!(
        !names.iter().any(|name| name == "flow"),
        "an API flow must not be rendered the browser-only hidden `flow` node: the executor \
         derives the transport from the record rather than assuming one: {names:?}"
    );

    // ROUND ONE. The test knows the word because it configured the secret, which is exactly the
    // knowledge a real user has out of band and the engine does not.
    let words: Vec<&str> = WORDS.split(',').map(str::trim).collect();
    let mut token = after_password["submit_token"]
        .as_str()
        .expect("a submit token")
        .to_owned();
    let (status, _, after_first) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "wordmark": words[0] },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "round one: {after_first}");
    assert_ne!(
        after_first["state"], "completed",
        "this factor wants TWO rounds, so one correct answer must not complete the login -- a \
         factor whose round count the engine decided would complete here: {after_first}"
    );
    let second_round = node_names(&after_first["flow"]);
    assert!(
        second_round.iter().any(|n| n == "wordmark"),
        "and it rendered the second round: {after_first}"
    );
    // THE SUBMISSION RENDER DERIVES ITS TRANSPORT FROM THE FLOW ROW.
    //
    // Asserted HERE and not on the first render, and the difference is the whole point: the
    // entry render is built by the walk, which is handed a transport; the SUBMISSION render is
    // built by the executor, which is not. The first version of that arm passed
    // `Transport::Browser` for want of one, and `push_flow_hidden` emits the hidden `flow` node
    // only for a browser flow -- so an API flow was rendered a node its client never posts back.
    //
    // This assertion started on the FIRST render and the mutant survived, because that render
    // was never wrong. A test of the wrong hop is not a weaker test, it is a different one.
    assert!(
        !second_round.iter().any(|n| n == "flow"),
        "an API flow must not be rendered the browser-only hidden `flow` node: {second_round:?}"
    );

    // ROUND TWO.
    token = after_first["submit_token"]
        .as_str()
        .expect("a submit token")
        .to_owned();
    let (status, headers, done) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "wordmark": words[1] },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "round two: {done}");
    assert_eq!(
        done["state"], "completed",
        "two correct rounds satisfy the factor and the login completes: {done}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "and a session was minted: {set_cookie}"
    );
    assert!(!subject.is_empty(), "the seeded subject exists");
}

/// A WRONG ANSWER DOES NOT MINT A SESSION.
///
/// The direction that matters. The sample factor ends on a wrong answer, so this asserts the
/// login is refused and, critically, that NO session cookie was set -- a factor that logged a
/// refusal and completed anyway would pass a test that only read the rendered state.
#[tokio::test]
async fn a_wrong_answer_to_a_custom_factor_mints_no_session() {
    let harness = setup().await;
    harness
        .seed_user("wrong-answer@example.test", PASSWORD)
        .await;

    let (flow_id, token, _) = create(&harness).await;
    let (_, _, after_password) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "wrong-answer@example.test", "password": PASSWORD },
        }),
    )
    .await;
    let token = after_password["submit_token"]
        .as_str()
        .expect("a submit token")
        .to_owned();

    let (status, headers, refused) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "wordmark": "not-the-word" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the refusal renders: {refused}");
    assert_ne!(
        refused["state"], "completed",
        "a wrong answer must not complete the login: {refused}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        !set_cookie.contains(SESSION_COOKIE),
        "and no session was minted, which is the assertion a state check alone would miss: \
         {set_cookie}"
    );
    assert!(
        !node_names(&refused["flow"])
            .iter()
            .any(|name| name == "wordmark"),
        "the refusal renders NO inputs: a factor that has ended must not invite another answer, \
         and it must look the same whether it ended for a wrong answer, a missing component or a \
         trap: {refused}"
    );
}

/// A JOURNEY NAMING AN UNDEPLOYED FACTOR REFUSES THE LOGIN.
///
/// A journey is meant to be PROMOTABLE into an environment its components have not reached yet,
/// so the reference is deliberately not resolved at load. That makes this state reachable, and
/// the only safe answer is that the user proved nothing: a missing component must never be a
/// factor that passes.
#[tokio::test]
async fn a_journey_naming_an_undeployed_factor_refuses_rather_than_passing() {
    let harness = setup().await;
    harness.seed_user("undeployed@example.test", PASSWORD).await;
    let env = harness.env().clone();
    let scope = harness.scope();

    // REMOVE THE COMPONENT the pinned journey names, leaving the reference dangling.
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .delete(&env, FACTOR)
        .await
        .expect("delete the factor");

    let (flow_id, token, _) = create(&harness).await;
    let (status, headers, after_password) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "undeployed@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "primary: {after_password}");
    assert_ne!(
        after_password["state"], "completed",
        "a missing component must REFUSE, never pass: a login that completed here would mean \
         deleting a factor disabled it rather than closing it: {after_password}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        !set_cookie.contains(SESSION_COOKIE),
        "and no session was minted: {set_cookie}"
    );
}

/// AN UNGRANTED FACTOR REFUSES, RATHER THAN RUNNING WITHOUT ITS SECRET.
///
/// The sample reads its word list from a granted secret and declines without one. Revoking the
/// grant must close the factor rather than open it -- the deny-by-default property, asserted
/// where it decides whether somebody logs in.
#[tokio::test]
async fn revoking_a_factors_secret_closes_it_rather_than_opening_it() {
    let harness = setup().await;
    harness.seed_user("ungranted@example.test", PASSWORD).await;
    let env = harness.env().clone();
    let scope = harness.scope();

    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .challenge_components()
        .revoke_secret(&env, FACTOR, "wordmark_list")
        .await
        .expect("revoke the grant");

    let (flow_id, token, _) = create(&harness).await;
    let (status, headers, after_password) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "ungranted@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "primary: {after_password}");
    assert_ne!(
        after_password["state"], "completed",
        "a factor that cannot read its configuration must refuse: {after_password}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        !set_cookie.contains(SESSION_COOKIE),
        "and no session was minted: {set_cookie}"
    );
}
