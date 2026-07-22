// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #92) PR 8c: the byte-equivalence GATE for the REGISTRATION journey
//! flip onto the compiled-table engine (`orchestration::drive_via_table`), against a real Postgres.
//!
//! PR 8c re-expresses the built-in registration journey (the SIMPLEST mint-family journey: a
//! two-step guard-free machine, details form then a terminal mint) as an EMBEDDED artifact and flips
//! its dispatch from the imperative `drive_registration` onto the table engine. The uniform
//! acknowledgment (`RegistrationAck`) is a RENDER-OVERRIDE the register executor emits while the flow
//! stays OPEN, not a routed step. This binary is Layer B of the three-layer byte-equivalence gate: it
//! DRIVES the flipped registration journey through BOTH transports (browser + API) and asserts the
//! rendered `Flow` byte-equals the committed golden by name.
//!
//! - `registration_details` (the CREATE render) byte-equals its golden on both transports (the
//!   creation path is unflipped; this anchors the sanity of the render);
//! - `registration_ack` (the closed-mode uniform acknowledgment) byte-equals its golden on both
//!   transports, driven through the render-override seam (the KEY flip proof);
//! - a details validation error (open mode, empty password) attaches `REGISTER_PASSWORD_REQUIRED` to
//!   the password node (a node-attached error has no fixed golden; its shape is pinned);
//! - the terminal yields `Continuation::Complete` with a session whose amr HONESTLY records `pwd`
//!   and never a fabricated second factor;
//! - a resubmit after the ack re-renders another ack (the `builtin_step_for` override fold);
//! - an ADVERSARIAL forged `custom` step on a registration row fails closed (no session).
//!
//! Layer A (the `docs/flow-golden.json` freshness lock) and Layer C (the `project_plan` pin in
//! `flow::inspect`) live elsewhere; together they make any drift in wire state, routing target, node
//! builder, or edge order loud.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::HeaderMap;
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::flow::golden::{
    GOLDEN_ENVIRONMENT, GOLDEN_EXPIRES_AT, GOLDEN_FLOW_ID, GOLDEN_TENANT,
};
use ironauth_oidc::flow::model::{Flow, FlowStateTag, Journey, Transport};
use ironauth_oidc::flow::{
    Continuation, FlowError, Submission, TransportAuth, create_flow, drive, golden_flows,
};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::FlowId;
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

/// The message id a missing password attaches to the password node (issue #84), the same id the
/// bootstrap register path and `flow_register_mfa` pin.
const REGISTER_PASSWORD_REQUIRED: i64 = 4_200_002;

// ------------------------------------------------------------------------------------------
// Harness + in-process driving helpers (mirroring flow_login_flip).
// ------------------------------------------------------------------------------------------

/// An OPEN-registration flows-enabled harness with a cheap deterministic Argon2 pool. Regulation is
/// disabled so a known and an unknown submit take the same non-throttled path.
async fn setup() -> Harness {
    setup_with(false).await
}

/// A CLOSED-registration harness (the #64 uniform anti-enumeration posture): a non-empty identifier
/// submit renders the uniform `RegistrationAck` acknowledgment, never creating an account inline.
async fn setup_closed() -> Harness {
    setup_with(true).await
}

async fn setup_with(registration_closed: bool) -> Harness {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            registration_closed,
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

/// Create a registration flow in-process on `transport`, returning the id, the initial submit token,
/// and the rendered start `Flow`.
async fn create_registration(harness: &Harness, transport: Transport) -> (FlowId, String, Flow) {
    create_flow(
        harness.state(),
        harness.scope(),
        transport,
        Journey::Registration,
        None,
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create registration flow")
}

/// The transport-neutral submission for a set of node values.
fn submission(values: &[(&str, &str)]) -> Submission {
    let mut node_values: BTreeMap<String, Value> = BTreeMap::new();
    for (name, value) in values {
        node_values.insert((*name).to_owned(), json!(value));
    }
    Submission {
        node_values,
        transient_payload: None,
    }
}

/// The auth object for a transport: the browser gate ran at the (bypassed) handler edge; the API
/// presents its current submit token.
fn transport_auth(transport: Transport, token: &str) -> TransportAuth {
    match transport {
        Transport::Browser => TransportAuth::Browser,
        Transport::Api => TransportAuth::Api {
            presented_submit_token: token.to_owned(),
        },
    }
}

/// Drive one submission in-process and return the continuation.
async fn submit(
    harness: &Harness,
    flow_id: &FlowId,
    transport: Transport,
    token: &str,
    values: &[(&str, &str)],
) -> Continuation {
    drive(
        harness.state(),
        harness.scope(),
        flow_id,
        transport,
        transport_auth(transport, token),
        submission(values),
        &HeaderMap::new(),
    )
    .await
    .expect("drive one submission")
}

/// Drive one submission, returning the RAW result (so an error path is observable, not unwrapped).
async fn try_submit(
    harness: &Harness,
    flow_id: &FlowId,
    transport: Transport,
    token: &str,
    values: &[(&str, &str)],
) -> Result<Continuation, FlowError> {
    drive(
        harness.state(),
        harness.scope(),
        flow_id,
        transport,
        transport_auth(transport, token),
        submission(values),
        &HeaderMap::new(),
    )
    .await
}

/// The rendered `Flow` and the rotated submit token from a RENDER continuation (never a completion).
fn expect_render(continuation: Continuation) -> (Flow, String) {
    match continuation {
        Continuation::Render { flow, submit_token } => (*flow, submit_token),
        Continuation::Complete { .. } => panic!("expected a render, got a completion"),
        Continuation::Redirect { .. } => panic!("expected a render, got a redirect"),
        Continuation::ConsentDecision { .. } => {
            panic!("expected a render, got a consent decision")
        }
    }
}

// ------------------------------------------------------------------------------------------
// Golden comparison: normalize a live Flow to the golden's fixed id / expiry / scope, then compare
// byte-for-byte to the committed golden by name (mirroring flow_login_flip).
// ------------------------------------------------------------------------------------------

/// The committed golden flow object by name.
fn golden_by_name(name: &str) -> Value {
    golden_flows()
        .into_iter()
        .find(|golden| golden.name == name)
        .unwrap_or_else(|| panic!("golden {name} exists in the corpus"))
        .as_json()
}

/// Normalize a live `Flow` to the golden's fixed substitutions (the per-flow entropy id, the
/// app-clock expiry, and the live scope slugs), directly comparable to `golden_by_name`.
fn normalize_to_golden(flow: &Flow, live_id: &str, tenant: &str, environment: &str) -> Value {
    let raw = serde_json::to_string(flow).expect("serialize flow");
    let subbed = raw
        .replace(live_id, GOLDEN_FLOW_ID)
        .replace(tenant, GOLDEN_TENANT)
        .replace(environment, GOLDEN_ENVIRONMENT);
    let mut value: Value = serde_json::from_str(&subbed).expect("parse normalized flow");
    value["expires_at"] = json!(GOLDEN_EXPIRES_AT);
    value
}

/// Assert a live `Flow` byte-equals the named golden after the fixed-id / expiry / scope
/// normalization.
fn assert_golden(flow: &Flow, name: &str, harness: &Harness, live_id: &str) {
    let tenant = harness.scope().tenant().to_string();
    let environment = harness.scope().environment().to_string();
    let normalized = normalize_to_golden(flow, live_id, &tenant, &environment);
    assert_eq!(
        normalized,
        golden_by_name(name),
        "the flipped registration render does not byte-equal golden {name}"
    );
}

/// Whether the flow's node named `field` carries a message with `message_id` (a node-attached error
/// shape check, since a node-attached error has no fixed golden).
fn node_has_message(flow: &Flow, field: &str, message_id: i64) -> bool {
    let value = serde_json::to_value(flow).expect("serialize flow");
    let nodes = value["ui"]["nodes"].as_array().expect("nodes array");
    nodes
        .iter()
        .filter(|node| node["attributes"]["name"] == field)
        .any(|node| {
            node["messages"]
                .as_array()
                .is_some_and(|messages| messages.iter().any(|m| m["id"] == message_id))
        })
}

/// The `auth_methods` on the MOST RECENT session (any subject): registration creates the account
/// inside the flow, so the subject id is not known up front; a fresh harness mints exactly one.
async fn latest_session_methods(harness: &Harness) -> String {
    use sqlx::Row;
    let pool = harness.db().owner_pool();
    let row = sqlx::query("SELECT auth_methods FROM sessions ORDER BY created_at DESC LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("a session row");
    row.get("auth_methods")
}

/// The count of minted session rows (any subject, any scope): the honest mint counter.
async fn session_count(harness: &Harness) -> i64 {
    use sqlx::Row;
    let pool = harness.db().owner_pool();
    let row = sqlx::query("SELECT COUNT(*) AS n FROM sessions")
        .fetch_one(pool)
        .await
        .expect("count sessions");
    row.get::<i64, _>("n")
}

/// Overwrite a flow row's serialized `state` jsonb directly (a tampered/corrupt row), to prove the
/// flip fails CLOSED rather than open.
async fn tamper_state(harness: &Harness, flow_id: &FlowId, state_json: &str) {
    let pool = harness.db().owner_pool();
    sqlx::query("UPDATE flows SET state = $1::jsonb WHERE id = $2")
        .bind(state_json)
        .bind(flow_id.to_string())
        .execute(pool)
        .await
        .expect("tamper flow state");
}

// ------------------------------------------------------------------------------------------
// The gate: registration_details (the CREATE render) byte-equals its golden on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn registration_details_byte_equals_the_golden_on_both_transports() {
    let harness = setup().await;

    for transport in [Transport::Api, Transport::Browser] {
        let suffix = transport.as_str();
        let (_flow_id, _token, start) = create_registration(&harness, transport).await;
        let live_id = start.id.clone();
        assert_eq!(
            start.journey,
            Journey::Registration,
            "the create render is on registration"
        );
        assert_eq!(
            start.state,
            FlowStateTag::RegistrationDetails,
            "the create render is the details state"
        );
        assert_golden(
            &start,
            &format!("registration_details_{suffix}"),
            &harness,
            &live_id,
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: the closed-mode uniform acknowledgment (the RENDER-OVERRIDE seam, the KEY flip proof)
// byte-equals its golden on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn registration_ack_override_byte_equals_the_golden_on_both_transports() {
    let harness = setup_closed().await;

    for transport in [Transport::Api, Transport::Browser] {
        let suffix = transport.as_str();
        let (flow_id, token, _start) = create_registration(&harness, transport).await;
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[
                ("identifier", "closed@example.test"),
                ("password", PASSWORD),
            ],
        )
        .await;
        let (ack, _rotated) = expect_render(continuation);
        assert_eq!(
            ack.journey,
            Journey::Registration,
            "the ack is on registration"
        );
        assert_eq!(
            ack.state,
            FlowStateTag::RegistrationAck,
            "the render-override advances the wire state to the ack interstitial"
        );
        assert_golden(
            &ack,
            &format!("registration_ack_{suffix}"),
            &harness,
            &ack.id.clone(),
        );
    }
    // The closed-mode ack never creates an account (no session minted).
    assert_eq!(
        session_count(&harness).await,
        0,
        "the closed-mode ack mints no session"
    );
}

// ------------------------------------------------------------------------------------------
// The gate: a details validation error (open mode, empty password) attaches the required-password
// message to the password node. A node-attached error has no fixed golden, so pin its shape.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_details_validation_error_attaches_to_the_password_node() {
    let harness = setup().await;

    for transport in [Transport::Api, Transport::Browser] {
        let (flow_id, token, _start) = create_registration(&harness, transport).await;
        // A non-empty identifier but an EMPTY password: the error attaches to the password node.
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[("identifier", "someone@example.test"), ("password", "")],
        )
        .await;
        let (rendered, _rotated) = expect_render(continuation);
        assert_eq!(
            rendered.journey,
            Journey::Registration,
            "the validation re-render stays on registration"
        );
        assert_eq!(
            rendered.state,
            FlowStateTag::RegistrationDetails,
            "a plain re-render stays on the details state (no override)"
        );
        assert!(
            node_has_message(&rendered, "password", REGISTER_PASSWORD_REQUIRED),
            "the password-required error attaches to the password node ({})",
            transport.as_str()
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: the terminal yields a session with the honest pwd amr (open mode, fresh + valid).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_registration_completes_with_an_honest_pwd_amr() {
    let harness = setup().await;

    assert_eq!(session_count(&harness).await, 0, "no sessions before");

    let (flow_id, token, _start) = create_registration(&harness, Transport::Api).await;
    let continuation = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token,
        &[("identifier", "fresh@example.test"), ("password", PASSWORD)],
    )
    .await;
    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "a genuine account create mints the first session"
    );
    let amr = latest_session_methods(&harness).await;
    assert!(amr.contains("pwd"), "records pwd: {amr}");
    assert!(
        !amr.contains("totp"),
        "registration never fabricates a second factor: {amr}"
    );
}

// ------------------------------------------------------------------------------------------
// The gate: a resubmit after the closed-mode ack re-renders another ack, proving the
// builtin_step_for render-override fold (RegistrationAck -> register) re-runs the executor exactly
// as the imperative driver (which ignores the persisted step) does. Not golden-covered.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_resubmit_after_the_ack_renders_another_ack() {
    let harness = setup_closed().await;
    let (flow_id, token, _start) = create_registration(&harness, Transport::Api).await;

    let first = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token,
        &[("identifier", "closed@example.test")],
    )
    .await;
    let (ack, rotated) = expect_render(first);
    assert_eq!(ack.state, FlowStateTag::RegistrationAck, "the first ack");

    // Resubmit: the persisted RegistrationAck folds back to the register step, re-running the
    // executor, which renders another ack.
    let second = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &rotated,
        &[("identifier", "closed@example.test")],
    )
    .await;
    let (ack_again, _rotated) = expect_render(second);
    assert_eq!(
        ack_again.state,
        FlowStateTag::RegistrationAck,
        "the resubmit-after-ack fold re-renders the ack"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "the ack fold never mints a session"
    );
}

// ------------------------------------------------------------------------------------------
// ADVERSARIAL (H7): a forged flat `custom` step on a REGISTRATION row reverse-maps to the Terminal
// `done` step (Terminal folds to the Custom wire tag), which the executor refuses. It must not mint
// an empty-subject session (fail closed, mirroring the login adversarial probe).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_forged_custom_tag_on_a_registration_row_fails_closed() {
    let harness = setup().await;
    let (flow_id, token, _start) = create_registration(&harness, Transport::Api).await;

    tamper_state(&harness, &flow_id, r#"{"step":"custom"}"#).await;

    let result = try_submit(&harness, &flow_id, Transport::Api, &token, &[]).await;
    assert!(
        !matches!(result, Ok(Continuation::Complete { .. })),
        "CRITICAL: a forced-terminal registration row minted an empty-subject session"
    );
    assert!(
        matches!(result, Err(FlowError::NotFound)),
        "a registration row forced onto the Terminal step must be a uniform not found"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "CRITICAL if nonzero: a forced-terminal registration row minted a session"
    );
}
