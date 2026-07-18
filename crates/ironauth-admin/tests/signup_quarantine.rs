// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signup fraud review queue over HTTP (issue #82, PR 2), driven through the management
//! router against a real database.
//!
//! Pins: the review queue lists the open cases; an admin RELEASE clears the quarantine and a
//! REJECT disables the account, each writing an audit row naming the deciding admin actor and
//! honoring Idempotency-Key; an EXTEND bumps the window; the routes require a management
//! principal (an end-user with no bearer can never reach a mutation, so no data-plane
//! self-approval exists); and every route is a uniform 404 while the experimental feature is
//! off.

mod common;

use common::{Harness, OPERATOR_TOKEN};
use ironauth_env::Env;
use ironauth_store::{CorrelationId, Scope, SignupQuarantineReason};
use serde_json::Value;

/// The bootstrap operator's audit actor id (a service actor).
const OPERATOR_ACTOR_ID: &str = "svc_AAAAAAAAAAAAAAAAAAAAAA";

/// Seed a quarantined signup in `scope` through the data plane, returning its subject.
async fn seed_quarantined(harness: &Harness, scope: Scope, identifier: &str) -> String {
    let env = Env::system();
    harness
        .store()
        .scoped(scope)
        .acting(harness.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .register_quarantined(
            &env,
            identifier,
            "$argon2id$dummy",
            SignupQuarantineReason::RiskOutput,
        )
        .await
        .expect("seed a quarantined signup")
        .to_string()
}

/// The audit actions recorded in `scope`.
async fn audit_rows(harness: &Harness, scope: Scope) -> Vec<(String, String)> {
    harness
        .control_store()
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
        "/v1/tenants/{}/environments/{}/signup-quarantine",
        scope.tenant(),
        scope.environment()
    )
}

#[tokio::test]
async fn the_review_queue_lists_releases_rejects_and_extends_with_actor_audit() {
    let h = Harness::start_with_signup_quarantine(50, true).await;
    let scope = h.seed_scope().await;
    let subject = seed_quarantined(&h, scope, "risky@example.test").await;
    let reject_subject = seed_quarantined(&h, scope, "fraud@example.test").await;
    let extend_subject = seed_quarantined(&h, scope, "maybe@example.test").await;
    let base = base(scope);

    // LIST shows the three open cases.
    let (status, _h, body) = h.get(&base).await;
    assert_eq!(status.as_u16(), 200, "list: {body}");
    let list: Value = serde_json::from_str(&body).expect("json");
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 3, "three open cases listed");
    assert!(
        items.iter().any(|c| c["subject"] == subject),
        "the case is bound to its subject"
    );
    assert_eq!(items[0]["reason"], "risk_output");
    assert_eq!(items[0]["state"], "pending");

    // RELEASE clears the quarantine, audits the operator, and is idempotent.
    let (status, _h, body) = h
        .post(&format!("{base}/{subject}/approve"), "sq-approve-1", "")
        .await;
    assert_eq!(status.as_u16(), 200, "approve: {body}");
    let decision: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(decision["subject"], subject);
    assert_eq!(decision["state"], "approved");
    assert!(
        !h.control_store()
            .scoped(scope)
            .users()
            .is_quarantined(
                &ironauth_store::UserId::parse_in_scope(&subject, &scope).expect("subject")
            )
            .await
            .expect("read quarantine"),
        "the account is no longer quarantined"
    );
    let (replay_status, _h, replay) = h
        .post(&format!("{base}/{subject}/approve"), "sq-approve-1", "")
        .await;
    assert_eq!(replay_status.as_u16(), 200, "approve replay: {replay}");
    assert_eq!(replay, body, "an idempotent replay returns the same body");

    // REJECT disables the rejected account and audits the operator.
    let (status, _h, body) = h
        .post(
            &format!("{base}/{reject_subject}/reject"),
            "sq-reject-1",
            "",
        )
        .await;
    assert_eq!(status.as_u16(), 200, "reject: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["state"],
        "rejected"
    );

    // EXTEND bumps the window (state -> extended) and audits the operator.
    let (status, _h, body) = h
        .post(
            &format!("{base}/{extend_subject}/extend"),
            "sq-extend-1",
            "{\"extend_secs\": 604800}",
        )
        .await;
    assert_eq!(status.as_u16(), 200, "extend: {body}");
    let extended: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(extended["state"], "extended");
    assert!(
        extended["quarantined_until_unix_ms"].is_i64(),
        "extend reports the new horizon"
    );

    // Every review action wrote an audit row naming the operator actor.
    let audit = audit_rows(&h, scope).await;
    for action in [
        "signup_quarantine.approved",
        "signup_quarantine.rejected",
        "signup_quarantine.extended",
    ] {
        assert!(
            audit
                .iter()
                .any(|(a, actor)| a == action && actor == OPERATOR_ACTOR_ID),
            "{action} is audited to the operator actor; got {audit:?}"
        );
    }

    // The released and rejected cases are closed; only the extended case stays open.
    let (_s, _h, body) = h.get(&base).await;
    let open = serde_json::from_str::<Value>(&body).expect("json");
    let items = open["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "only the extended case stays open");
    assert_eq!(items[0]["subject"], extend_subject);
}

#[tokio::test]
async fn an_end_user_with_no_management_principal_cannot_reach_the_review_routes() {
    // Self-approval is structurally impossible: the review routes require a management
    // principal. A request with no bearer (an end-user has none) never reaches the mutation.
    let h = Harness::start_with_signup_quarantine(50, true).await;
    let scope = h.seed_scope().await;
    let subject = seed_quarantined(&h, scope, "risky@example.test").await;
    let base = base(scope);

    let (status, _h, _b) = h
        .post_unauthenticated(&format!("{base}/{subject}/approve"), "")
        .await;
    assert_eq!(
        status.as_u16(),
        401,
        "an unauthenticated (end-user) approve is rejected before any mutation"
    );
    // The account is STILL quarantined: no data-plane path cleared it.
    assert!(
        h.control_store()
            .scoped(scope)
            .users()
            .is_quarantined(
                &ironauth_store::UserId::parse_in_scope(&subject, &scope).expect("subject")
            )
            .await
            .expect("read quarantine"),
        "the account stays quarantined: only an admin can release it"
    );
}

#[tokio::test]
async fn every_review_route_is_a_uniform_404_when_the_feature_is_off() {
    // Flag OFF (default): the review-queue endpoints answer a uniform 404, so the surface is
    // inert until an operator enables AND acknowledges the experiment.
    let h = Harness::start_with_signup_quarantine(50, false).await;
    let scope = h.seed_scope().await;
    let subject = seed_quarantined(&h, scope, "risky@example.test").await;
    let base = base(scope);

    let (list_status, _h, _b) = h.get(&base).await;
    assert_eq!(
        list_status.as_u16(),
        404,
        "list is 404 when the feature is off"
    );
    for (verb, key, body) in [
        ("approve", "k1", ""),
        ("reject", "k2", ""),
        ("extend", "k3", "{\"extend_secs\": 1}"),
    ] {
        let (status, _h, _b) = h
            .post_as(
                &format!("{base}/{subject}/{verb}"),
                OPERATOR_TOKEN,
                key,
                body,
            )
            .await;
        assert_eq!(
            status.as_u16(),
            404,
            "{verb} is 404 when the feature is off"
        );
    }
}
