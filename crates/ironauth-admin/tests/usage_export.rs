// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-tenant usage export (issue #107 criterion 4).
//!
//! The store-side fold has its own seeded fixture. What this proves is the EXPORT: that the
//! endpoint folds the same feed, reports the same numbers, and is honest when it stops
//! early. An export that quietly truncated would be the one number a customer never thinks
//! to question, which is why `truncated` is a field rather than a log line.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{EnvironmentId, NewOutboxMessage, Scope, TenantId};
use serde_json::Value;

/// Append one event envelope through the commit-ordered appender.
async fn append(h: &Harness, env: &Env, scope: Scope, key: &str, event_type: &str, subject: &str) {
    h.store()
        .scoped(scope)
        .outbox()
        .append_event(
            env,
            &NewOutboxMessage {
                consumer: "usage-export-test",
                idempotency_key: key,
                ordering_key: "k",
                payload: serde_json::json!({
                    "id": key,
                    "type": event_type,
                    "payload_schema_version": 1,
                    "occurred_at_unix_ms": 0,
                    "tenant_id": scope.tenant().to_string(),
                    "environment_id": scope.environment().to_string(),
                    "payload": { "subject": subject },
                }),
            },
        )
        .await
        .expect("append");
}

#[tokio::test]
async fn the_export_reports_distinct_actives_and_raw_issuance() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage").await;
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    // Not uniform, deliberately: alice three times and bob once. A fixture with one event
    // per user cannot tell distinct users from activity events apart.
    for (i, subject) in ["alice", "bob", "alice", "alice"].iter().enumerate() {
        append(
            &h,
            &env,
            scope,
            &format!("u_act_{i}"),
            "user.signed_in",
            subject,
        )
        .await;
    }
    for i in 0..3 {
        append(&h, &env, scope, &format!("u_tok_{i}"), "token.issued", "-").await;
    }

    let path = format!("/v1/tenants/{tenant}/environments/{environment}/usage");

    // The feed is watermarked cluster-wide, so a bounded poll is what "the events have
    // landed" honestly means here. Same reason as the store-side tests.
    let mut body = Value::Null;
    for _ in 0..100 {
        let (status, _, response) = h.get(&path).await;
        assert_eq!(status, StatusCode::OK, "usage: {response}");
        body = serde_json::from_str(&response).expect("json");
        if body["tokens_issued"] == 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(
        body["monthly_active_users"], 2,
        "alice three times and bob once is TWO active users: {body}"
    );
    assert_eq!(body["tokens_issued"], 3, "issuance counts events: {body}");
    assert_eq!(
        body["truncated"], false,
        "a short feed must not report truncation: {body}"
    );
}

#[tokio::test]
async fn an_unknown_tenant_is_not_a_zero_usage_report() {
    // A 404 rather than a plausible-looking export of zeros. An operator scripting against
    // this would read zeros as "no activity" and never learn they typed the wrong tenant,
    // which is the same silent-wrong-answer class the feed's 410 exists to avoid.
    let h = Harness::start(50).await;
    let (_tenant, environment) = h.create_tenant("acme", "k-usage-404").await;

    // A WELL-FORMED tenant id that does not exist, generated the same way a real one is.
    // A fabricated string fails at PARSING, which is a different branch: the first version
    // of this test used one, and a mutation to the existence check survived because the
    // request never reached it. The test was passing for a reason it did not control.
    let absent = TenantId::generate(&Env::system()).to_string();
    let (status, _, body) = h
        .get(&format!(
            "/v1/tenants/{absent}/environments/{environment}/usage"
        ))
        .await;

    // NOT_FOUND specifically, not merely "not OK". The spec documents 404 for this, and a
    // 500 would satisfy a not-OK assertion while telling an operator their deployment is
    // broken rather than their tenant id is wrong. A mutation swapping one for the other
    // survived until this was tightened.
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown tenant is a 404, not a fault and not a zero report: {body}"
    );
}

#[tokio::test]
async fn a_fold_that_stops_early_says_so() {
    // The `truncated` flag, exercised. A mutation that never set it SURVIVED until this
    // existed, because the fixture was seven events against a ten-thousand limit, and the
    // one field whose whole job is to admit the number is a lower bound was unverified.
    //
    // Driving `fold_usage` directly with a tiny limit reaches the path without seeding ten
    // thousand events, which is why the limit is a parameter rather than a constant.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-trunc").await;
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    for i in 0..3 {
        append(&h, &env, scope, &format!("u_tr_{i}"), "token.issued", "-").await;
    }

    // Wait for the cluster-wide watermark to release them, then fold with a limit BELOW
    // the number of events.
    let mut truncated = false;
    let mut counted = 0;
    for _ in 0..100 {
        let scoped = h.store().scoped(scope);
        let (tally, stopped_early) = ironauth_admin::usage::fold_usage(&scoped.outbox(), 2)
            .await
            .expect("fold");
        counted = tally.tokens_issued();
        truncated = stopped_early;
        if counted > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        counted > 0,
        "the events must have landed for this to mean anything"
    );
    assert!(
        truncated,
        "a fold limited to 2 over 3 events must report that it stopped early"
    );

    // And the same feed folded WITHOUT a binding limit must not claim truncation, or the
    // flag would just be always-on and equally useless.
    let scoped = h.store().scoped(scope);
    let (_, not_truncated) = ironauth_admin::usage::fold_usage(&scoped.outbox(), 10_000)
        .await
        .expect("fold");
    assert!(
        !not_truncated,
        "a fold that reached the end of the feed must not report truncation"
    );
}
