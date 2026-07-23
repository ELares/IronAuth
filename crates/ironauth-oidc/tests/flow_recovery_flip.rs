// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #92) PR 8d: the byte-equivalence GATE for the RECOVERY journey
//! flip onto the compiled-table engine (`orchestration::drive_via_table`), against a real Postgres.
//!
//! PR 8d re-expresses the built-in recovery journey (a passwordless email-OTP identity proof: a
//! three-step guard-free machine, identifier start then code verify then a terminal mint) as an
//! EMBEDDED artifact and flips its dispatch from the imperative `drive_recovery` onto the table
//! engine. Unlike registration, recovery's acknowledgment (`RecoveryAck`) is a REAL routed step: the
//! walk ENTERS the `verify` step and renders the ack + code entry with the flow-level `RECOVERY_ACK`
//! message (the second novel wiring of PR 8d). This binary is Layer B of the three-layer
//! byte-equivalence gate: it DRIVES the flipped recovery journey through BOTH transports (browser +
//! API) and asserts the rendered `Flow` byte-equals the committed golden by name.
//!
//! - `recovery_start` (the CREATE render) byte-equals its golden on both transports (the creation
//!   path is unflipped; this anchors the sanity of the render);
//! - `recovery_ack` (the uniform acknowledgment + code entry) byte-equals its golden on both
//!   transports, driven through the ENTER-verify-with-flow-message path (the KEY flip proof);
//! - an empty-identifier re-render attaches `RECOVERY_IDENTIFIER_REQUIRED` to the identifier node (a
//!   node-attached error has no fixed golden; its shape is pinned);
//! - a wrong-code re-render carries `RECOVERY_CODE_INCORRECT` on the code node with EMPTY flow
//!   messages, byte-equal to the `recovery_ack_code_error` golden (reconciled to the driver in
//!   issue #362, so this is now a full byte-golden compare);
//! - the terminal yields `Continuation::Complete` with a session whose amr HONESTLY records `otp` and
//!   never `pwd` / `totp`;
//! - an ADVERSARIAL forged `custom` step on a recovery row fails closed (no session).
//!
//! Layer A (the `docs/flow-golden.json` freshness lock) and Layer C (the `project_plan` pin in
//! `flow::inspect`) live elsewhere; together they make any drift in wire state, routing target, node
//! builder, or edge order loud.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

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
use ironauth_oidc::{
    Argon2Params, EmailOtpMessage, HashingPool, MagicLinkMessage, VerificationPurpose,
    VerificationSender,
};
use ironauth_store::FlowId;
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";
const KNOWN: &str = "ada@example.test";

/// The message id an empty identifier attaches to the identifier node (issue #84).
const RECOVERY_IDENTIFIER_REQUIRED: i64 = 4_400_001;
/// The uniform incorrect-code message id a wrong code attaches to the code node (issue #84).
const RECOVERY_CODE_INCORRECT: i64 = 4_400_003;

// ------------------------------------------------------------------------------------------
// A recording verification sender (mirroring flow_recovery_federation): captures every delivered
// OTP code so the completion test can read the code the initiation delivered.
// ------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct RecordingSender {
    otp: Mutex<Vec<(String, String)>>,
}

impl VerificationSender for RecordingSender {
    fn send(&self, _scope: ironauth_store::Scope, _purpose: VerificationPurpose, _recipient: &str) {
    }

    fn deliver_email_otp(&self, message: &EmailOtpMessage<'_>) {
        self.otp
            .lock()
            .expect("lock")
            .push((message.recipient.to_owned(), message.code.to_owned()));
    }

    fn deliver_magic_link(&self, _message: &MagicLinkMessage<'_>) {}
}

/// The last OTP code the recording sender delivered to `recipient`.
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

// ------------------------------------------------------------------------------------------
// Harness + in-process driving helpers (mirroring flow_register_flip).
// ------------------------------------------------------------------------------------------

/// A flows-enabled, email-OTP-capable harness with a recording sender and a cheap deterministic
/// Argon2 pool. Regulation is disabled so a known and an unknown submit take the same non-throttled
/// path (the anti-enumeration convergence is proven in `flow_recovery_federation`).
async fn setup() -> (Harness, Arc<RecordingSender>) {
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

/// Create a recovery flow in-process on `transport`, returning the id, the initial submit token, and
/// the rendered start `Flow`.
async fn create_recovery(harness: &Harness, transport: Transport) -> (FlowId, String, Flow) {
    create_flow(
        harness.state(),
        harness.scope(),
        transport,
        Journey::Recovery,
        None,
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create recovery flow")
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
// byte-for-byte to the committed golden by name (mirroring flow_register_flip).
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
        "the flipped recovery render does not byte-equal golden {name}"
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

/// The flow-level messages on the rendered flow (the `ui.messages` array).
fn flow_messages(flow: &Flow) -> Vec<i64> {
    let value = serde_json::to_value(flow).expect("serialize flow");
    value["ui"]["messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .filter_map(|m| m["id"].as_i64())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// The `auth_methods` on the MOST RECENT session (any subject): a fresh harness mints exactly one on
/// the recovery completion.
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
// The gate: recovery_start (the CREATE render) byte-equals its golden on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn recovery_start_byte_equals_the_golden_on_both_transports() {
    let (harness, _sender) = setup().await;

    for transport in [Transport::Api, Transport::Browser] {
        let suffix = transport.as_str();
        let (_flow_id, _token, start) = create_recovery(&harness, transport).await;
        let live_id = start.id.clone();
        assert_eq!(
            start.journey,
            Journey::Recovery,
            "the create render is on recovery"
        );
        assert_eq!(
            start.state,
            FlowStateTag::RecoveryStart,
            "the create render is the identifier start state"
        );
        assert_golden(
            &start,
            &format!("recovery_start_{suffix}"),
            &harness,
            &live_id,
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: the uniform acknowledgment + code entry (the ENTER-verify-with-flow-message path, the
// KEY flip proof) byte-equals its golden on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn recovery_ack_byte_equals_the_golden_on_both_transports() {
    let (harness, _sender) = setup().await;

    for transport in [Transport::Api, Transport::Browser] {
        let suffix = transport.as_str();
        let (flow_id, token, _start) = create_recovery(&harness, transport).await;
        // A non-empty identifier: the RecoveryStart executor Advances (Ack), the walk routes
        // start -> verify, and the dedicated arm renders ack_nodes(false) + [RECOVERY_ACK] on
        // state = RecoveryAck. Known or unknown converge to the SAME bytes; an unknown identifier
        // keeps the completion path out of this render-only proof.
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[("identifier", "someone@example.test")],
        )
        .await;
        let (ack, _rotated) = expect_render(continuation);
        assert_eq!(ack.journey, Journey::Recovery, "the ack is on recovery");
        assert_eq!(
            ack.state,
            FlowStateTag::RecoveryAck,
            "the enter-verify path advances the wire state to the ack + code entry"
        );
        assert_golden(
            &ack,
            &format!("recovery_ack_{suffix}"),
            &harness,
            &ack.id.clone(),
        );
    }
    // The render-only ack never mints a session.
    assert_eq!(
        session_count(&harness).await,
        0,
        "the recovery ack mints no session"
    );
}

// ------------------------------------------------------------------------------------------
// The gate: an empty-identifier re-render attaches the required-identifier message to the identifier
// node and stays on the start state. A node-attached error has no fixed golden, so pin its shape.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_empty_identifier_attaches_to_the_identifier_node() {
    let (harness, _sender) = setup().await;

    for transport in [Transport::Api, Transport::Browser] {
        let (flow_id, token, _start) = create_recovery(&harness, transport).await;
        let continuation =
            submit(&harness, &flow_id, transport, &token, &[("identifier", "")]).await;
        let (rendered, _rotated) = expect_render(continuation);
        assert_eq!(
            rendered.journey,
            Journey::Recovery,
            "the validation re-render stays on recovery"
        );
        assert_eq!(
            rendered.state,
            FlowStateTag::RecoveryStart,
            "an empty-identifier re-render stays on the start state (no advance)"
        );
        assert!(
            node_has_message(&rendered, "identifier", RECOVERY_IDENTIFIER_REQUIRED),
            "the required-identifier error attaches to the identifier node ({})",
            transport.as_str()
        );
    }
}

// ------------------------------------------------------------------------------------------
// The gate: a wrong-code re-render carries the uniform incorrect-code message on the code node with
// EMPTY flow messages. Since issue #362 reconciled the recovery_ack_code_error golden to the driver
// (empty flow messages, not a repeated RECOVERY_ACK), this is now a full byte-golden compare, not a
// shape check.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_wrong_code_re_renders_the_uniform_incorrect_code_shape() {
    let (harness, _sender) = setup().await;
    harness.seed_user(KNOWN, PASSWORD).await;

    let (flow_id, token, _start) = create_recovery(&harness, Transport::Api).await;
    let ack = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token,
        &[("identifier", KNOWN)],
    )
    .await;
    let (ack_flow, rotated) = expect_render(ack);
    assert_eq!(
        ack_flow.state,
        FlowStateTag::RecoveryAck,
        "the ack + code entry"
    );

    // A wrong code: advance_verify returns Invalid -> ack_nodes(true) + EMPTY messages, staying on
    // the ack state.
    let wrong = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &rotated,
        &[("code", "000000")],
    )
    .await;
    let (rendered, _rotated) = expect_render(wrong);
    assert_eq!(
        rendered.state,
        FlowStateTag::RecoveryAck,
        "a wrong code stays on the ack state (the flow stays OPEN)"
    );
    assert!(
        node_has_message(&rendered, "code", RECOVERY_CODE_INCORRECT),
        "the uniform incorrect-code message attaches to the code node"
    );
    assert!(
        flow_messages(&rendered).is_empty(),
        "the wrong-code render carries NO flow message (the incorrect-code error rides the code \
         node): {:?}",
        flow_messages(&rendered)
    );
    // Byte-golden compare: the reconciled recovery_ack_code_error golden (issue #362) now matches
    // this render exactly, so the flip proves byte-equivalence rather than a shape approximation.
    assert_golden(
        &rendered,
        "recovery_ack_code_error_api",
        &harness,
        &rendered.id.clone(),
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "a wrong code mints no session"
    );
}

// ------------------------------------------------------------------------------------------
// The gate: the terminal yields a session with the honest otp amr (a genuine code verification).
// The genuine mint also runs the threaded post_reset (relaxing the recovery-path counters), which is
// best-effort and outside the rendered byte gate; we assert the completion itself here.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_recovery_completes_with_an_honest_otp_amr() {
    let (harness, sender) = setup().await;
    harness.seed_user(KNOWN, PASSWORD).await;

    assert_eq!(session_count(&harness).await, 0, "no sessions before");

    // Initiate: submit the identifier; the recovery code is delivered through the existing send.
    let (flow_id, token0, _start) = create_recovery(&harness, Transport::Api).await;
    let ack = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token0,
        &[("identifier", KNOWN)],
    )
    .await;
    let (ack_flow, token1) = expect_render(ack);
    assert_eq!(ack_flow.state, FlowStateTag::RecoveryAck);
    let code = last_code(&sender, KNOWN);

    // Complete: submit the delivered code. It funnels through email_otp::verify_email_code, which
    // mints the honest email-factor session.
    let continuation = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token1,
        &[("code", &code)],
    )
    .await;
    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "a genuine recovery code mints the session"
    );
    let amr = latest_session_methods(&harness).await;
    assert!(amr.contains("otp"), "records otp: {amr}");
    assert!(
        !amr.contains("pwd"),
        "recovery never fabricates a password factor: {amr}"
    );
    assert!(
        !amr.contains("totp"),
        "recovery never fabricates a second factor: {amr}"
    );
}

// ==========================================================================================
// REVIEW PROBES (adversarial, added by the PR8d review). Not part of the shipped suite.
// ==========================================================================================

/// A regulation-ENABLED harness (high soft threshold so two attempts never throttle), so the
/// recovery-path abuse counter actually climbs and `reset_after_success` is a live op (it early
/// returns when regulation is disabled). Otherwise identical to `setup`.
async fn setup_regulated() -> (Harness, Arc<RecordingSender>) {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: true,
            window_secs: 3600,
            soft_threshold: 1000,
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

/// The summed `count` over the recovery-path IDENTIFIER abuse-counter rows (the only dimension the
/// recovery flow writes to `dcr_rate_counters`; the IP and tenant dimensions are in-memory L1). A
/// positive value means the recovery-path identifier counter is non-relaxed.
async fn recovery_identifier_counter_sum(harness: &Harness) -> i64 {
    use sqlx::Row;
    let pool = harness.db().owner_pool();
    let row = sqlx::query(
        "SELECT COALESCE(SUM(count), 0) AS n FROM dcr_rate_counters \
         WHERE rate_key LIKE 'abuse:recovery:identifier:%'",
    )
    .fetch_one(pool)
    .await
    .expect("sum recovery identifier counters");
    row.get::<i64, _>("n")
}

/// PROBE (crux 1c, the marquee novel bit): the threaded `post_reset` relaxes the recovery-path
/// counter ONLY on a genuine mint, and NEVER on a failed verify. With regulation enabled, every
/// recovery-path attempt climbs the identifier counter; a genuine completion runs
/// `reset_after_success` (zeroing it), and a wrong code returns a Render (never reaching the
/// terminal / `complete_via_table`, so no reset fires).
#[tokio::test]
async fn post_reset_relaxes_the_counter_on_completion_but_not_on_a_failed_verify() {
    let (harness, sender) = setup_regulated().await;
    harness.seed_user(KNOWN, PASSWORD).await;

    // --- Positive: a genuine completion relaxes the counter. ---
    let (flow_id, token0, _start) = create_recovery(&harness, Transport::Api).await;
    let ack = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token0,
        &[("identifier", KNOWN)],
    )
    .await;
    let (_ack_flow, token1) = expect_render(ack);
    // advance_start's regulate_before has recorded one attempt on the recovery identifier counter.
    assert!(
        recovery_identifier_counter_sum(&harness).await >= 1,
        "the recovery-path identifier counter climbed on the initiation"
    );
    let code = last_code(&sender, KNOWN);
    let done = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token1,
        &[("code", &code)],
    )
    .await;
    assert!(
        matches!(done, Continuation::Complete { .. }),
        "the genuine code completes"
    );
    assert_eq!(
        recovery_identifier_counter_sum(&harness).await,
        0,
        "a genuine recovery mint RELAXED the recovery-path identifier counter (post_reset ran)"
    );

    // --- Negative: a failed verify does NOT relax the counter. ---
    let (flow_id2, token2, _start2) = create_recovery(&harness, Transport::Api).await;
    let ack2 = submit(
        &harness,
        &flow_id2,
        Transport::Api,
        &token2,
        &[("identifier", KNOWN)],
    )
    .await;
    let (_ack2_flow, token3) = expect_render(ack2);
    let after_initiate = recovery_identifier_counter_sum(&harness).await;
    assert!(
        after_initiate >= 1,
        "the second initiation climbed the counter again"
    );
    let wrong = submit(
        &harness,
        &flow_id2,
        Transport::Api,
        &token3,
        &[("code", "000000")],
    )
    .await;
    let (rendered, _r) = expect_render(wrong);
    assert_eq!(
        rendered.state,
        FlowStateTag::RecoveryAck,
        "a wrong code stays open"
    );
    assert!(
        recovery_identifier_counter_sum(&harness).await >= after_initiate,
        "a FAILED verify must NOT relax the recovery-path counter (no post_reset on a non-complete): \
         before={after_initiate}, after={}",
        recovery_identifier_counter_sum(&harness).await
    );
}

/// PROBE (crux 3, anti-enumeration on the FLIPPED path): a KNOWN and an UNKNOWN identifier both
/// converge to a byte-identical `RecoveryAck` render, and the unknown identifier has NO deliverable
/// code (the send is suppressed internally). Existence never leaks through the flipped render.
#[tokio::test]
async fn known_and_unknown_identifiers_render_byte_identical_acks() {
    const UNKNOWN: &str = "nobody-here@example.test";
    let (harness, sender) = setup().await;
    harness.seed_user(KNOWN, PASSWORD).await;

    let render_ack = |ident: &'static str| {
        let harness = &harness;
        async move {
            let (flow_id, token, _s) = create_recovery(harness, Transport::Api).await;
            let ack = submit(
                harness,
                &flow_id,
                Transport::Api,
                &token,
                &[("identifier", ident)],
            )
            .await;
            let (flow, _r) = expect_render(ack);
            // Normalize the per-flow id so two distinct flows are directly comparable.
            let json = serde_json::to_string(&flow).expect("serialize");
            json.replace(flow.id.as_str(), "<flow-id>")
        }
    };

    let known_json = render_ack(KNOWN).await;
    let unknown_json = render_ack(UNKNOWN).await;
    assert_eq!(
        known_json, unknown_json,
        "a known and an unknown identifier render BYTE-IDENTICAL acks on the flipped path"
    );
    // The unknown identifier's send is suppressed: no code is deliverable-observable for it.
    let no_unknown_code = sender
        .otp
        .lock()
        .expect("lock")
        .iter()
        .all(|(to, _)| to != UNKNOWN);
    assert!(
        no_unknown_code,
        "no recovery code is delivered to an unknown identifier (suppressed send)"
    );
}

/// PROBE (crux 7, identifier threading fail-closed): a recovery row sitting on the ack state with NO
/// stored `identifier` (a tampered/corrupt row) must fail CLOSED at the verify executor
/// (`scratch.identifier.ok_or(NotFound)`), minting nothing. The identifier can never be absent or
/// client-supplied at verify time.
#[tokio::test]
async fn an_absent_identifier_on_the_ack_row_fails_closed() {
    let (harness, _sender) = setup().await;
    harness.seed_user(KNOWN, PASSWORD).await;
    let (flow_id, token, _start) = create_recovery(&harness, Transport::Api).await;

    // Force the row onto the ack (verify) state with NO identifier stored.
    tamper_state(&harness, &flow_id, r#"{"step":"recovery_ack"}"#).await;

    let result = try_submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token,
        &[("code", "123456")],
    )
    .await;
    assert!(
        matches!(result, Err(FlowError::NotFound)),
        "an ack row with no stored identifier must be a uniform not found (got a non-NotFound)"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "an identifier-less ack row mints no session"
    );
}

// ------------------------------------------------------------------------------------------
// ADVERSARIAL (H11): a forged flat `custom` step on a RECOVERY row reverse-maps to the Terminal
// `done` step (Terminal folds to the Custom wire tag), which the executor refuses. It must not mint
// an empty-subject session (fail closed, mirroring the login / registration adversarial probes).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_forged_custom_tag_on_a_recovery_row_fails_closed() {
    let (harness, _sender) = setup().await;
    let (flow_id, token, _start) = create_recovery(&harness, Transport::Api).await;

    tamper_state(&harness, &flow_id, r#"{"step":"custom"}"#).await;

    let result = try_submit(&harness, &flow_id, Transport::Api, &token, &[]).await;
    assert!(
        !matches!(result, Ok(Continuation::Complete { .. })),
        "CRITICAL: a forced-terminal recovery row minted an empty-subject session"
    );
    assert!(
        matches!(result, Err(FlowError::NotFound)),
        "a recovery row forced onto the Terminal step must be a uniform not found"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "CRITICAL if nonzero: a forced-terminal recovery row minted a session"
    );
}
