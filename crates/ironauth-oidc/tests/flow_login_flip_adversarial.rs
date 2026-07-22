// SPDX-License-Identifier: MIT OR Apache-2.0

//! ADVERSARIAL security probes for the issue #92 PR 8b LOGIN journey flip onto the table engine.
//!
//! These are NOT byte-equivalence checks (that is `flow_login_flip.rs`). Each probe TRIES to break
//! the overriding security property of the flip: the table engine must mint a session ONLY when the
//! imperative path would, with the SAME authentication requirements. A probe that succeeds in
//! minting a session it should not is a CRITICAL finding.
//!
//! - Probe 1: a challenge-required subject cannot mint with only the primary factor by submitting a
//!   WRONG second factor (no mint, zero sessions).
//! - Probe 2: an attacker cannot SPOOF the routing signals from the client submission (extra node
//!   values named `mfa_required` / `step` / `code`) to skip the challenge at primary.
//! - Probe 3 (defense in depth): a TAMPERED persisted step (jumped to `mfa_challenge` with NO proven
//!   subject) fails closed at the subject-proof gate, never mints.
//! - Probe 4 (defense in depth): a TAMPERED persisted step set to the flat `custom` tag on a LOGIN
//!   row reverse-maps to the Terminal step, which the executor refuses, never an empty-subject mint.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::HeaderMap;
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::flow::model::{FlowStateTag, Journey, Transport};
use ironauth_oidc::flow::{Continuation, FlowError, Submission, TransportAuth, create_flow, drive};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::FlowId;
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

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

async fn create_login(harness: &Harness, transport: Transport) -> (FlowId, String) {
    let (id, token, _flow) = create_flow(
        harness.state(),
        harness.scope(),
        transport,
        Journey::Login,
        None,
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create login flow");
    (id, token)
}

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

fn api_auth(token: &str) -> TransportAuth {
    TransportAuth::Api {
        presented_submit_token: token.to_owned(),
    }
}

/// Drive one submission, returning the RAW result (so an error path is observable, not unwrapped).
async fn try_drive(
    harness: &Harness,
    flow_id: &FlowId,
    token: &str,
    values: &[(&str, &str)],
) -> Result<Continuation, FlowError> {
    drive(
        harness.state(),
        harness.scope(),
        flow_id,
        Transport::Api,
        api_auth(token),
        submission(values),
        &HeaderMap::new(),
    )
    .await
}

/// The total number of minted session rows (any subject, any scope): the honest mint counter.
async fn session_count(harness: &Harness) -> i64 {
    use sqlx::Row;
    let pool = harness.db().owner_pool();
    let row = sqlx::query("SELECT COUNT(*) AS n FROM sessions")
        .fetch_one(pool)
        .await
        .expect("count sessions");
    row.get::<i64, _>("n")
}

/// Overwrite a flow row's serialized `state` jsonb directly (an attacker with a tampered/corrupt
/// row): the step is normally server-authoritative, so this simulates a compromised persisted state
/// to prove the flip fails CLOSED rather than open.
async fn tamper_state(harness: &Harness, flow_id: &FlowId, state_json: &str) {
    let pool = harness.db().owner_pool();
    sqlx::query("UPDATE flows SET state = $1::jsonb WHERE id = $2")
        .bind(state_json)
        .bind(flow_id.to_string())
        .execute(pool)
        .await
        .expect("tamper flow state");
}

fn expect_render_state(continuation: &Continuation) -> FlowStateTag {
    match continuation {
        Continuation::Render { flow, .. } => flow.state,
        _ => panic!("expected a render, got a non-render continuation"),
    }
}

/// Whether a drive result is the uniform not-found (the fail-closed outcome), without requiring a
/// `Debug` impl on `Continuation`.
fn is_uniform_not_found(result: &Result<Continuation, FlowError>) -> bool {
    matches!(result, Err(FlowError::NotFound))
}

fn minted_a_session(result: &Result<Continuation, FlowError>) -> bool {
    matches!(result, Ok(Continuation::Complete { .. }))
}

// ------------------------------------------------------------------------------------------
// Probe 1: NO MFA BYPASS. A challenge-required subject cannot mint with only pwd by submitting a
// wrong second factor. The flipped path must HOLD on the challenge and mint nothing.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn challenge_required_subject_does_not_mint_on_a_wrong_second_factor() {
    let harness = setup().await;
    let subject = harness
        .seed_user("adv-challenge@example.test", PASSWORD)
        .await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;

    assert_eq!(session_count(&harness).await, 0, "no sessions before");

    let (flow_id, token) = create_login(&harness, Transport::Api).await;

    // Primary success holds on the MFA challenge (never mints at primary).
    let held = try_drive(
        &harness,
        &flow_id,
        &token,
        &[
            ("identifier", "adv-challenge@example.test"),
            ("password", PASSWORD),
        ],
    )
    .await
    .expect("primary submission drives");
    assert_eq!(
        expect_render_state(&held),
        FlowStateTag::MfaChallenge,
        "a challenge-required subject holds on the challenge, it does not mint at primary"
    );
    let Continuation::Render {
        submit_token: rotated,
        ..
    } = held
    else {
        unreachable!()
    };
    assert_eq!(
        session_count(&harness).await,
        0,
        "no session at the challenge hold"
    );

    // A WRONG second factor must re-render, never mint.
    let after_wrong = try_drive(&harness, &flow_id, &rotated, &[("code", "000000")])
        .await
        .expect("wrong-code submission drives");
    assert!(
        matches!(after_wrong, Continuation::Render { .. }),
        "a wrong second factor re-renders, it never completes"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "CRITICAL if nonzero: a wrong second factor minted a session (MFA bypass)"
    );
}

// ------------------------------------------------------------------------------------------
// Probe 2: SIGNAL SPOOF. The routing signals (mfa_required, ...) are computed server-side by the
// executor; a client submission cannot set them. A challenge-required subject who packs bogus
// signal / step / code fields into the PRIMARY submission must still hold on the challenge.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_client_cannot_spoof_routing_signals_to_skip_the_challenge() {
    let harness = setup().await;
    let subject = harness.seed_user("adv-spoof@example.test", PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;

    let (flow_id, token) = create_login(&harness, Transport::Api).await;

    // Pack every field an attacker might hope routes them straight to the mint: falsified signals,
    // a target step, and a second-factor code, all alongside the genuine primary credentials.
    let held = try_drive(
        &harness,
        &flow_id,
        &token,
        &[
            ("identifier", "adv-spoof@example.test"),
            ("password", PASSWORD),
            ("mfa_required", "false"),
            ("enroll_required", "false"),
            ("profiling_pending", "false"),
            ("primary_verified", "true"),
            ("step", "done"),
            ("code", "000000"),
        ],
    )
    .await
    .expect("spoofed primary submission drives");
    assert_eq!(
        expect_render_state(&held),
        FlowStateTag::MfaChallenge,
        "CRITICAL if not: a spoofed submission skipped the challenge and routed to the mint"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "CRITICAL if nonzero: a spoofed submission minted a session"
    );
}

// ------------------------------------------------------------------------------------------
// Probe 3 (defense in depth): a TAMPERED step jumped to a post-primary state with NO proven subject
// must fail closed at the subject-proof gate, never mint.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_tampered_post_primary_step_without_a_subject_fails_closed() {
    let harness = setup().await;
    harness.seed_user("adv-tamper@example.test", PASSWORD).await;

    let (flow_id, token) = create_login(&harness, Transport::Api).await;

    // Forge the row onto the MFA challenge state WITHOUT ever proving the primary factor: no subject,
    // no method tokens on the scratch.
    tamper_state(&harness, &flow_id, r#"{"step":"mfa_challenge"}"#).await;

    let result = try_drive(&harness, &flow_id, &token, &[("code", "000000")]).await;
    assert!(
        !minted_a_session(&result),
        "CRITICAL: a subjectless tampered step minted a session"
    );
    assert!(
        is_uniform_not_found(&result),
        "a subjectless post-primary step must be a uniform not found"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "CRITICAL if nonzero: a subjectless tampered step minted a session"
    );
}

// ------------------------------------------------------------------------------------------
// Probe 4 (defense in depth): a TAMPERED flat `custom` step on a LOGIN row reverse-maps to the
// Terminal step (Terminal folds to the Custom wire tag), which the executor refuses. It must not
// mint an empty-subject session.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_tampered_custom_tag_on_a_login_row_does_not_ride_the_mint() {
    let harness = setup().await;
    let (flow_id, token) = create_login(&harness, Transport::Api).await;

    // The flat Custom tag on a login row: `builtin_step_for` finds the only step whose wire tag is
    // Custom, which is the Terminal `done` step. Reaching a terminal via a submission must fail.
    tamper_state(&harness, &flow_id, r#"{"step":"custom"}"#).await;

    let result = try_drive(&harness, &flow_id, &token, &[]).await;
    assert!(
        !minted_a_session(&result),
        "CRITICAL: a forced-terminal login row minted an empty-subject session"
    );
    assert!(
        is_uniform_not_found(&result),
        "a login row forced onto the Terminal step must be a uniform not found"
    );
    assert_eq!(
        session_count(&harness).await,
        0,
        "CRITICAL if nonzero: a forced-terminal login row minted an empty-subject session"
    );
}
