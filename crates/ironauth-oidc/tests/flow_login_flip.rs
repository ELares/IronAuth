// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #92) PR 8b: the byte-equivalence GATE for the LOGIN journey flip
//! onto the compiled-table engine (`orchestration::drive_via_table`), against a real Postgres.
//!
//! PR 8b re-expresses the built-in login journey (which subsumes the in-flow MFA challenge / enroll
//! and progressive-profiling holds as substates) as an EMBEDDED artifact and flips its dispatch from
//! the imperative `drive_login` onto the table engine. This binary is Layer B of the three-layer
//! byte-equivalence gate: it DRIVES the flipped login journey through BOTH transports (browser + API)
//! and asserts the rendered `Flow` byte-equals the committed golden by name for every deterministic
//! login/mfa state, plus the terminal yields a session with the honest amr.
//!
//! - `login_start` and `login_incorrect` (the anti-enumeration crux) byte-equal their goldens on
//!   both transports;
//! - `mfa_challenge` byte-equals its golden on both transports (the login journey's step-up hold);
//! - `mfa_enroll` matches its golden in node SHAPE (the per-flow enroll secret is entropy, so the
//!   two display-only provisioning values are redacted before the comparison);
//! - the progressive-profiling hold renders on the LOGIN wire identity (`journey=login`,
//!   `state=progressive_profiling`) with its dynamic field node (no fixed golden exists for the
//!   dynamic form; its bytes are gated by `flow_progressive_profiling`);
//! - the terminal yields `Continuation::Complete` with a session and the honest amr (`pwd`, or
//!   `pwd`+`totp`).
//!
//! Layer A (the `docs/flow-golden.json` freshness lock) and Layer C (the `project_plan` pin in
//! `flow::inspect`) live elsewhere; together they make any drift in wire state, routing target,
//! node builder, or edge order loud.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::HeaderMap;
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_oidc::flow::golden::{
    GOLDEN_ENVIRONMENT, GOLDEN_EXPIRES_AT, GOLDEN_FLOW_ID, GOLDEN_TENANT,
};
use ironauth_oidc::flow::model::{Flow, FlowStateTag, Journey, NodeAttributes, Transport};
use ironauth_oidc::flow::{
    Continuation, Submission, TransportAuth, create_flow, drive, golden_flows,
};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::{CorrelationId, FlowId, NewSignupForm, SignupFormId};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

/// The seed the harness `seed_active_totp` enrolls, so a real code is reproducible.
const TOTP_SEED: [u8; 20] = [0x0A; 20];

// ------------------------------------------------------------------------------------------
// Harness + in-process driving helpers.
// ------------------------------------------------------------------------------------------

/// A flows-enabled harness with a cheap deterministic Argon2 pool. Regulation is disabled so a
/// known and an unknown submit take the same non-throttled path.
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

/// Create a login flow in-process on `transport`, returning the id, the initial submit token, and
/// the rendered start `Flow`.
async fn create_login(
    harness: &Harness,
    transport: Transport,
    return_to: Option<&str>,
) -> (FlowId, String, Flow) {
    create_flow(
        harness.state(),
        harness.scope(),
        transport,
        Journey::Login,
        return_to,
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create login flow")
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
// byte-for-byte to the committed golden by name.
// ------------------------------------------------------------------------------------------

/// The committed golden flow object by name.
fn golden_by_name(name: &str) -> Value {
    golden_flows()
        .into_iter()
        .find(|golden| golden.name == name)
        .unwrap_or_else(|| panic!("golden {name} exists in the corpus"))
        .as_json()
}

/// Normalize a live `Flow` to the golden's fixed substitutions: the per-flow entropy id (both the
/// `id` field and the browser hidden-node value), the app-clock expiry, and the live scope's tenant
/// / environment slugs in the `ui.action`, all replaced with the golden constants. The result is
/// directly comparable to `golden_by_name`.
fn normalize_to_golden(flow: &Flow, live_id: &str, tenant: &str, environment: &str) -> Value {
    // The flow id is a unique, high-entropy string, so a global string substitution over the
    // serialized form cleanly maps both its `id` occurrence and the browser hidden `flow` node's
    // value; the tenant / environment slugs occur only in `ui.action`. The flow id is replaced
    // FIRST (the most specific token) so a scope-embedded id can never leave a partial.
    let raw = serde_json::to_string(flow).expect("serialize flow");
    let subbed = raw
        .replace(live_id, GOLDEN_FLOW_ID)
        .replace(tenant, GOLDEN_TENANT)
        .replace(environment, GOLDEN_ENVIRONMENT);
    let mut value: Value = serde_json::from_str(&subbed).expect("parse normalized flow");
    value["expires_at"] = json!(GOLDEN_EXPIRES_AT);
    value
}

/// Redact the two display-only provisioning values that carry per-flow entropy in the MFA enroll
/// render (the `otpauth://` URI and the grouped secret), so the enroll comparison pins node SHAPE
/// (groups, order, types, names, the code field, the submit control, the hidden flow node) while
/// ignoring the live secret. Applied to BOTH the live and the golden value.
fn redact_enroll_entropy(flow: &mut Value) {
    if let Some(nodes) = flow["ui"]["nodes"].as_array_mut() {
        for node in nodes {
            let name = node["attributes"]["name"].as_str().unwrap_or_default();
            if name == "otpauth_uri" || name == "totp_secret" {
                node["attributes"]["value"] = json!("<redacted-entropy>");
            }
        }
    }
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
        "the flipped login render does not byte-equal golden {name}"
    );
}

/// Whether the flow renders an input node of the given field name.
fn has_input(flow: &Flow, name: &str) -> bool {
    flow.ui.nodes.iter().any(|node| {
        matches!(&node.attributes, NodeAttributes::Input { name: field, .. } if field == name)
    })
}

/// The `auth_methods` on the most recent session for `subject` (owner pool), the honest amr proof.
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
// The gate: login_start + login_incorrect byte-equal their goldens on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn login_start_and_incorrect_byte_equal_the_goldens_on_both_transports() {
    let harness = setup().await;
    harness.seed_user("flip-start@example.test", PASSWORD).await;

    for transport in [Transport::Api, Transport::Browser] {
        let suffix = transport.as_str();
        let (flow_id, token, start) = create_login(&harness, transport, None).await;
        let live_id = start.id.clone();

        // 1. The start render (the identifier + password entry) equals the golden.
        assert_golden(&start, &format!("login_start_{suffix}"), &harness, &live_id);

        // 2. A WRONG identifier/password re-renders and STAYS on the primary step: the uniform
        //    authentication failure (the anti-enumeration crux) equals the golden.
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[
                ("identifier", "flip-start@example.test"),
                ("password", "WRONG"),
            ],
        )
        .await;
        let (incorrect, _rotated) = expect_render(continuation);
        assert_golden(
            &incorrect,
            &format!("login_incorrect_{suffix}"),
            &harness,
            &live_id,
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: the login journey's MFA challenge hold byte-equals its golden on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn mfa_challenge_byte_equals_the_golden_on_both_transports() {
    let harness = setup().await;
    let subject = harness
        .seed_user("flip-challenge@example.test", PASSWORD)
        .await;
    harness.seed_active_totp(&subject).await;
    // The tenant baseline requires a second factor, so a genuine primary success holds on the MFA
    // challenge substate rather than minting.
    harness.set_tenant_min_class("mfa").await;

    for transport in [Transport::Api, Transport::Browser] {
        let suffix = transport.as_str();
        let (flow_id, token, start) = create_login(&harness, transport, None).await;
        let live_id = start.id.clone();
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[
                ("identifier", "flip-challenge@example.test"),
                ("password", PASSWORD),
            ],
        )
        .await;
        let (challenge, _rotated) = expect_render(continuation);
        assert_eq!(
            challenge.journey,
            Journey::Login,
            "the challenge is on login"
        );
        assert_eq!(
            challenge.state,
            FlowStateTag::MfaChallenge,
            "the login wire state"
        );
        assert_golden(
            &challenge,
            &format!("mfa_challenge_{suffix}"),
            &harness,
            &live_id,
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: the login journey's MFA enroll hold matches its golden in node SHAPE on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn mfa_enroll_shape_equals_the_golden_on_both_transports() {
    let harness = setup().await;
    // A subject with NO enrolled factor while the tenant requires MFA steers to enrollment.
    harness
        .seed_user("flip-enroll@example.test", PASSWORD)
        .await;
    harness.set_tenant_min_class("mfa").await;

    for transport in [Transport::Api, Transport::Browser] {
        let suffix = transport.as_str();
        let (flow_id, token, start) = create_login(&harness, transport, None).await;
        let live_id = start.id.clone();
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[
                ("identifier", "flip-enroll@example.test"),
                ("password", PASSWORD),
            ],
        )
        .await;
        let (enroll, _rotated) = expect_render(continuation);
        assert_eq!(
            enroll.journey,
            Journey::Login,
            "the enroll hold is on login"
        );
        assert_eq!(
            enroll.state,
            FlowStateTag::MfaEnroll,
            "the login wire state"
        );

        // The per-flow enroll secret is entropy, so redact the two display-only provisioning values
        // in BOTH the live render and the golden; the rest of the node set must byte-equal.
        let tenant = harness.scope().tenant().to_string();
        let environment = harness.scope().environment().to_string();
        let mut live = normalize_to_golden(&enroll, &live_id, &tenant, &environment);
        let mut golden = golden_by_name(&format!("mfa_enroll_{suffix}"));
        redact_enroll_entropy(&mut live);
        redact_enroll_entropy(&mut golden);
        assert_eq!(
            live, golden,
            "the flipped MFA enroll render does not match the golden node shape ({suffix})"
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: the progressive-profiling hold renders on the LOGIN wire identity (the flip's crux for
// the profiling substate). No fixed golden exists (the profiling form is dynamic per client); its
// bytes are gated by flow_progressive_profiling, so here we pin the wire identity + the field node.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn profiling_hold_renders_on_the_login_wire_identity_on_both_transports() {
    let harness = setup().await;
    install_trait_schema(&harness).await;
    install_signup_form(&harness).await;
    harness
        .seed_user("flip-profile@example.test", PASSWORD)
        .await;
    let resume = return_to(&harness);

    for transport in [Transport::Api, Transport::Browser] {
        let (flow_id, token, _start) = create_login(&harness, transport, Some(&resume)).await;
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[
                ("identifier", "flip-profile@example.test"),
                ("password", PASSWORD),
            ],
        )
        .await;
        let (profiling, _rotated) = expect_render(continuation);
        assert_eq!(
            profiling.journey,
            Journey::Login,
            "profiling holds on login"
        );
        assert_eq!(
            profiling.state,
            FlowStateTag::ProgressiveProfiling,
            "the login progressive-profiling wire state"
        );
        assert!(
            has_input(&profiling, "nickname"),
            "the held later-login field renders ({})",
            transport.as_str()
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: the terminal yields a session with the honest amr (pwd, and pwd + totp).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_direct_login_completes_with_an_honest_pwd_amr() {
    let harness = setup().await;
    let subject = harness.seed_user("flip-pwd@example.test", PASSWORD).await;

    let (flow_id, token, _start) = create_login(&harness, Transport::Api, None).await;
    let continuation = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token,
        &[
            ("identifier", "flip-pwd@example.test"),
            ("password", PASSWORD),
        ],
    )
    .await;
    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "a direct login mints a session"
    );
    let amr = latest_session_methods(&harness, &subject).await;
    assert!(amr.contains("pwd"), "records pwd: {amr}");
    assert!(!amr.contains("totp"), "no second factor ran: {amr}");
}

#[tokio::test]
async fn a_stepped_up_login_completes_with_an_honest_pwd_plus_totp_amr() {
    let harness = setup().await;
    let subject = harness.seed_user("flip-2fa@example.test", PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;

    let (flow_id, token, _start) = create_login(&harness, Transport::Api, None).await;
    // Primary factor: holds on the MFA challenge (no mint yet).
    let continuation = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token,
        &[
            ("identifier", "flip-2fa@example.test"),
            ("password", PASSWORD),
        ],
    )
    .await;
    let (challenge, rotated) = expect_render(continuation);
    assert_eq!(challenge.state, FlowStateTag::MfaChallenge);

    // A real TOTP code (advanced to a fresh step distinct from the seeded activation) mints.
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = code_at(
        &TOTP_SEED,
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let continuation = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &rotated,
        &[("code", &code)],
    )
    .await;
    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "the real second factor completes the login"
    );
    let amr = latest_session_methods(&harness, &subject).await;
    assert!(
        amr.contains("pwd") && amr.contains("totp"),
        "honest pwd + totp amr, never a fabricated factor: {amr}"
    );
}

// ------------------------------------------------------------------------------------------
// Progressive-profiling setup (mirrors flow_progressive_profiling): a trait schema with a
// constrained nickname and a signup form with one required later-login field on it.
// ------------------------------------------------------------------------------------------

/// A form with ONE required LATER-LOGIN field on `nickname`.
const NICKNAME_LATER_LOGIN_REQUIRED: &str = r#"[{"trait_pointer":"/nickname","required":true,"order":0,"step":"later_login","rules":{},"label_message_id":1070001}]"#;

async fn install_trait_schema(harness: &Harness) {
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

async fn install_signup_form(harness: &Harness) {
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
                fields_json: NICKNAME_LATER_LOGIN_REQUIRED,
            },
        )
        .await
        .expect("set signup form");
}

/// A `/authorize` resume target for the harness client, so the login flow resolves the client whose
/// signup form the progressive-profiling path loads.
fn return_to(harness: &Harness) -> String {
    format!(
        "/authorize?response_type=code&client_id={}&redirect_uri=https://rp.example/cb&scope=openid",
        harness.client_id()
    )
}

fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}
