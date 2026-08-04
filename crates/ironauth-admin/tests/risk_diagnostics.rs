// SPDX-License-Identifier: MIT OR Apache-2.0

//! The risk posture diagnostics (issue #79), driven through the management router against a
//! real database.
//!
//! The store half has been complete since #54's migration and none of it was reachable.
//! Measured before this surface existed: `credentials_flagged_for_review`, `latest_decision`
//! and `get_decision` all had ZERO production callers, and no risk operation appeared in the
//! published management contract.
//!
//! The one that matters is the flag. The "this wasn't me" disavowal page tells the user, in
//! those words, that their credentials will be flagged for review. Consuming a disavowal is
//! what sets that flag, and nothing could read it, so the promise was unreviewable: an
//! operator had no way to find the accounts a user had reported as compromised.
//!
//! Migration 0054 already granted the control role SELECT on both risk tables, deliberately,
//! so unlike the SMS surface this needed no new grant. Only the surface was missing.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    CorrelationId, EnvironmentId, NewDisavowalToken, NewRiskDecision, Scope, TenantId, UserId,
};
use serde_json::Value;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn posture_path(tenant: &str, environment: &str, user: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/risk/users/{user}")
}

fn decision_path(tenant: &str, environment: &str, decision: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/risk/decisions/{decision}")
}

/// Create a user through the management API and return its `usr_` id.
async fn user(h: &Harness, tenant: &str, environment: &str, identifier: &str, key: &str) -> String {
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": identifier }).to_string();
    let (status, _, response) = h.post(&path, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "seed user: {response}");
    let created: Value = serde_json::from_str(&response).expect("json");
    created["id"].as_str().expect("id").to_owned()
}

#[tokio::test]
async fn an_unscored_account_reports_no_decision_and_an_unflagged_posture() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let subject = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;

    // Never scored, never disavowed. This is the baseline the other tests move away from,
    // and it must be a legible 200 rather than a not-found: an operator asking "has this
    // account been flagged" needs an answer, and "no" is an answer.
    let (status, _, response) = h.get(&posture_path(&tenant, &environment, &subject)).await;
    assert_eq!(status, StatusCode::OK, "posture read: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["subject"], subject.as_str());
    assert_eq!(view["credentials_flagged_for_review"], false);
    assert!(
        view["latest_decision"].is_null(),
        "an unscored account has no decision: {response}"
    );
}

#[tokio::test]
async fn a_recorded_decision_is_readable_by_id_and_as_the_latest() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let subject = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;

    // Record two decisions through the DATA plane, which is the role that owns the write
    // (0054 grants INSERT to `ironauth_app` alone). The management surface only reads.
    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    let subject_id = UserId::parse_in_scope(&subject, &scope).expect("subject in scope");
    let mut ids = Vec::new();
    for (score, action, signals) in [
        ("low", "allow", r#"{"new_device":false}"#),
        (
            "high",
            "challenge",
            r#"{"new_device":true,"impossible_travel":true}"#,
        ),
    ] {
        let id = h
            .store()
            .scoped(scope)
            .acting(h.test_actor(&env), CorrelationId::generate(&env))
            .risk()
            .record_decision(
                &env,
                &subject_id,
                NewRiskDecision {
                    score,
                    action,
                    signals_json: signals,
                    signals_summary: "new_device:high",
                    correlation_id: None,
                },
            )
            .await
            .expect("record a decision");
        ids.push(id.to_string());
    }

    // The posture reports the LATEST, which is the second one.
    let (status, _, response) = h.get(&posture_path(&tenant, &environment, &subject)).await;
    assert_eq!(status, StatusCode::OK, "posture: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    let latest = &view["latest_decision"];
    assert_eq!(
        latest["id"],
        ids[1].as_str(),
        "the newest decision: {response}"
    );
    assert_eq!(latest["score"], "high");
    assert_eq!(latest["action"], "challenge");
    assert_eq!(
        latest["signals"]["impossible_travel"], true,
        "the signals document is returned PARSED, not as an opaque string: {response}"
    );

    // And the older one is still addressable by id, which is what makes an audit row
    // naming a decision reconstructable.
    let (status, _, response) = h.get(&decision_path(&tenant, &environment, &ids[0])).await;
    assert_eq!(status, StatusCode::OK, "decision by id: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["id"], ids[0].as_str());
    assert_eq!(view["score"], "low");
    assert_eq!(view["action"], "allow");
}

#[tokio::test]
async fn an_absent_user_and_an_absent_decision_are_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;

    let absent_user = format!("usr_{}", "0".repeat(26));
    let (status, _, response) = h
        .get(&posture_path(&tenant, &environment, &absent_user))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "absent user: {response}");

    // A malformed decision id and an absent one collapse to the same answer, so neither
    // tells a caller whether an id belongs to some other environment.
    for id in ["not-an-id", "rsk_0000000000000000000000000"] {
        let (status, _, response) = h.get(&decision_path(&tenant, &environment, id)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{id}: {response}");
    }
}

#[tokio::test]
async fn a_decision_is_invisible_to_a_sibling_environment() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let sibling = h.create_environment(&tenant, "sibling", "k-sibling").await;
    let subject = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;

    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    let subject_id = UserId::parse_in_scope(&subject, &scope).expect("subject in scope");
    let id = h
        .store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .risk()
        .record_decision(
            &env,
            &subject_id,
            NewRiskDecision {
                score: "high",
                action: "challenge",
                signals_json: r#"{"new_device":true}"#,
                signals_summary: "new_device:high",
                correlation_id: None,
            },
        )
        .await
        .expect("record")
        .to_string();

    // The fixtures differ in the ENVIRONMENT alone, under one tenant, so this measures the
    // environment half of the fence rather than the tenant predicate. A risk decision that
    // leaked across environments would expose one environment's login telemetry to another.
    let (status, _, response) = h.get(&decision_path(&tenant, &sibling, &id)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a decision minted in another environment is not readable here: {response}"
    );
}

#[tokio::test]
async fn a_consumed_disavowal_is_what_makes_the_posture_report_a_flagged_account() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let subject = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    let subject_id = UserId::parse_in_scope(&subject, &scope).expect("subject in scope");

    // ISSUING a disavowal is not the flag: the user has been offered the link and has not
    // acted on it. Asserting this first is what stops the test below from passing for the
    // wrong reason, since a posture that reported every account with a token would look
    // identical on the happy path.
    let digest = [7u8; 32];
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .risk()
        .issue_disavowal(
            &env,
            &subject_id,
            NewDisavowalToken {
                token_digest: &digest,
                decision_id: None,
                session_ids: &[],
                expires_at_micros: 4_000_000_000_000_000,
            },
        )
        .await
        .expect("issue a disavowal token");

    let (_, _, response) = h.get(&posture_path(&tenant, &environment, &subject)).await;
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        view["credentials_flagged_for_review"], false,
        "an UNUSED disavowal link is not a flag: the user has not said anything yet: \
         {response}"
    );

    // CONSUMING it is the user saying "this wasn't me", and that is the flag the disavowal
    // page promises. Before this surface existed nothing could read it, so the promise was
    // unreviewable.
    h.store()
        .scoped(scope)
        .acting(h.test_actor(&env), CorrelationId::generate(&env))
        .risk()
        .consume_disavowal(&env, &digest, 1_000_000)
        .await
        .expect("consume the disavowal")
        .expect("the live token resolves");

    let (status, _, response) = h.get(&posture_path(&tenant, &environment, &subject)).await;
    assert_eq!(status, StatusCode::OK, "posture: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert!(
        view["credentials_flagged_for_review"]
            .as_bool()
            .expect("a boolean"),
        "a consumed disavowal flags the credentials for review, and an operator can now \
         SEE it: {response}"
    );
}
