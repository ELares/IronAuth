// SPDX-License-Identifier: MIT OR Apache-2.0

//! The admin-approved recovery review queue over HTTP (issue #82, PR 3), driven through the
//! management router against a real database.
//!
//! Pins: the review queue lists the open approvals; an admin APPROVE satisfies the method
//! precondition and completes the recovery THROUGH the #81 delay gate (a flow whose delay has
//! elapsed completes; one whose delay is still in the future is approved but stays HELD),
//! writing an audit row naming the deciding admin actor; a REJECT closes the approval; the
//! routes require a management principal (an end-user with no bearer can never reach a
//! mutation, so no self-approval exists); an approve with no open approval is a 404; and every
//! route is a uniform 404 while the experimental feature is off.

mod common;

use std::time::SystemTime;

use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    CorrelationId, NewRecoveryFlow, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod,
    RecoveryState, Scope, UserId,
};
use serde_json::Value;

/// The bootstrap operator's audit actor id (a service actor).
const OPERATOR_ACTOR_ID: &str = "svc_AAAAAAAAAAAAAAAAAAAAAA";

fn now_micros() -> i64 {
    let env = Env::system();
    i64::try_from(
        ironauth_env::Clock::now_utc(env.clock())
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Seed a HELD admin-approved recovery flow (with `hold_until`) and its pending approval row
/// through the data plane, returning the flow id. `seed_byte` distinguishes the per-flow
/// cancellation-token digest (a scope-wide UNIQUE).
async fn seed_admin_approved_flow(
    h: &Harness,
    scope: Scope,
    hold_until_micros: i64,
    seed_byte: u8,
) -> RecoveryFlowId {
    let env = Env::system();
    let subject = UserId::generate(&env, &scope);
    let flow_id = RecoveryFlowId::generate(&env, &scope);
    let digest = vec![seed_byte; 32];
    let spec = NewRecoveryFlow {
        id: &flow_id,
        subject: &subject,
        entry_point: RecoveryEntryPoint::LostAllFactors,
        recover_acr: "urn:ironauth:acr:pwd",
        cancel_token_digest: &digest,
        recipient: "recover@example.test",
        hold_until_unix_micros: Some(hold_until_micros),
        method: RecoveryMethod::AdminApproved,
    };
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .initiate(&env, spec, 0)
        .await
        .expect("seed the recovery flow");
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .open(&env, &flow_id, &subject)
        .await
        .expect("open the pending approval");
    flow_id
}

/// The recovery flow's state-machine position, read through the control plane.
async fn flow_state(h: &Harness, scope: Scope, flow_id: &RecoveryFlowId) -> RecoveryState {
    h.control_store()
        .scoped(scope)
        .recovery_flows()
        .get(flow_id)
        .await
        .expect("get flow")
        .expect("flow exists")
        .state
}

/// The audit actions recorded in `scope`.
async fn audit_rows(h: &Harness, scope: Scope) -> Vec<(String, String)> {
    h.control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| (row.action, row.actor.id_string()))
        .collect()
}

fn base(scope: Scope) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/recovery-approvals",
        scope.tenant(),
        scope.environment()
    )
}

#[tokio::test]
async fn the_review_queue_lists_approves_and_rejects_through_the_delay_gate_with_actor_audit() {
    let h = Harness::start_with_advanced_recovery(50, true).await;
    let scope = h.seed_scope().await;
    // Flow A: its delay window has ALREADY elapsed (hold_until in the past), so approving
    // completes it. Flow B: its delay is still in the FUTURE, so approving records the approval
    // but the recovery stays HELD (the completion runs through the #81 delay gate). Flow C is
    // rejected.
    let flow_a = seed_admin_approved_flow(&h, scope, now_micros() - 1_000_000, 1).await;
    let flow_b = seed_admin_approved_flow(&h, scope, now_micros() + 3_600_000_000, 2).await;
    let flow_c = seed_admin_approved_flow(&h, scope, now_micros() + 3_600_000_000, 3).await;
    let base = base(scope);

    // LIST shows the three open approvals.
    let (status, _h, body) = h.get(&base).await;
    assert_eq!(status.as_u16(), 200, "list: {body}");
    let list: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(list["items"].as_array().expect("items").len(), 3);
    assert_eq!(list["items"][0]["state"], "pending");

    // APPROVE flow A (delay elapsed): the recovery COMPLETES through the gate.
    let (status, _h, body) = h
        .post(&format!("{base}/{flow_a}/approve"), "ra-approve-a", "")
        .await;
    assert_eq!(status.as_u16(), 200, "approve A: {body}");
    let decision: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(decision["flow_id"], flow_a.to_string());
    assert_eq!(decision["state"], "approved");
    assert_eq!(
        flow_state(&h, scope, &flow_a).await,
        RecoveryState::Completed,
        "an approved recovery whose delay elapsed completes THROUGH the gate"
    );
    // Idempotent replay.
    let (replay_status, _h, replay) = h
        .post(&format!("{base}/{flow_a}/approve"), "ra-approve-a", "")
        .await;
    assert_eq!(replay_status.as_u16(), 200);
    assert_eq!(replay, body, "an idempotent replay returns the same body");

    // APPROVE flow B (delay in the future): approved, but the recovery stays HELD (the delay
    // gate refuses completion until the notified window elapses).
    let (status, _h, body) = h
        .post(&format!("{base}/{flow_b}/approve"), "ra-approve-b", "")
        .await;
    assert_eq!(status.as_u16(), 200, "approve B: {body}");
    assert_eq!(
        flow_state(&h, scope, &flow_b).await,
        RecoveryState::Held,
        "an approved recovery whose delay has NOT elapsed stays held (no delay bypass)"
    );

    // REJECT flow C.
    let (status, _h, body) = h
        .post(&format!("{base}/{flow_c}/reject"), "ra-reject-c", "")
        .await;
    assert_eq!(status.as_u16(), 200, "reject C: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["state"],
        "rejected"
    );

    // Every review action wrote an audit row naming the operator actor.
    let audit = audit_rows(&h, scope).await;
    for action in ["recovery.approved", "recovery.approval.rejected"] {
        assert!(
            audit
                .iter()
                .any(|(a, actor)| a == action && actor == OPERATOR_ACTOR_ID),
            "{action} is audited to the operator actor; got {audit:?}"
        );
    }

    // The approved-and-completed and rejected cases are closed; only flow B's approval (still
    // held) stays surfaced as approved. The list shows the remaining pending, which is none.
    let (_s, _h, body) = h.get(&base).await;
    let open = serde_json::from_str::<Value>(&body).expect("json");
    assert_eq!(
        open["items"].as_array().expect("items").len(),
        0,
        "no PENDING approvals remain (A/C decided, B is approved)"
    );
}

#[tokio::test]
async fn an_end_user_with_no_management_principal_cannot_approve_a_recovery() {
    // Self-approval is structurally impossible: the review routes require a management
    // principal. A request with no bearer (an end-user has none) never reaches the mutation.
    let h = Harness::start_with_advanced_recovery(50, true).await;
    let scope = h.seed_scope().await;
    let flow = seed_admin_approved_flow(&h, scope, now_micros() - 1_000_000, 1).await;
    let base = base(scope);

    let (status, _h, _b) = h
        .post_unauthenticated(&format!("{base}/{flow}/approve"), "")
        .await;
    assert_eq!(
        status.as_u16(),
        401,
        "an unauthenticated (end-user) approve is rejected before any mutation"
    );
    // The recovery is STILL held: no data-plane path completed it.
    assert_eq!(
        flow_state(&h, scope, &flow).await,
        RecoveryState::Held,
        "the recovery stays held: only an admin can approve it"
    );
}

#[tokio::test]
async fn approving_a_flow_with_no_open_approval_is_a_404() {
    let h = Harness::start_with_advanced_recovery(50, true).await;
    let scope = h.seed_scope().await;
    // A recovery flow id that has NO approval row (never opened): approving it is a not-found.
    let orphan = RecoveryFlowId::generate(&Env::system(), &scope);
    let base = base(scope);
    let (status, _h, _b) = h
        .post(&format!("{base}/{orphan}/approve"), "ra-orphan", "")
        .await;
    assert_eq!(
        status.as_u16(),
        404,
        "approving a flow with no open approval is a 404 (completion needs an approval)"
    );
}

#[tokio::test]
async fn every_recovery_approval_route_is_a_uniform_404_when_the_feature_is_off() {
    // Flag OFF (default): the review-queue endpoints answer a uniform 404, so the surface is
    // inert until an operator enables AND acknowledges the experiment.
    let h = Harness::start_with_advanced_recovery(50, false).await;
    let scope = h.seed_scope().await;
    let flow = RecoveryFlowId::generate(&Env::system(), &scope);
    let base = base(scope);

    let (list_status, _h, _b) = h.get(&base).await;
    assert_eq!(
        list_status.as_u16(),
        404,
        "list is 404 when the feature is off"
    );
    for (verb, key) in [("approve", "k1"), ("reject", "k2")] {
        let (status, _h, _b) = h.post(&format!("{base}/{flow}/{verb}"), key, "").await;
        assert_eq!(
            status.as_u16(),
            404,
            "{verb} is 404 when the feature is off"
        );
    }
}
