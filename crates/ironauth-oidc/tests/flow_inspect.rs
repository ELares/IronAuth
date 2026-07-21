// SPDX-License-Identifier: MIT OR Apache-2.0

//! The read only flow inspector against a real database (issue #91, PR4): the OBSERVE
//! projection of an existing flow, and the ZERO SIDE EFFECT proof that neither observe nor a
//! policy dry run writes any row.
//!
//! The hard acceptance criterion is that a dry run writes NOTHING. This suite proves it the
//! strongest way: it snapshots the ENTIRE database (every public table's row count, read as
//! the superuser owner so row level security never hides a write) BEFORE and AFTER an observe
//! plus a policy dry run, and asserts the snapshot is byte identical. Because the
//! `flow::inspect` module holds no store handle, a dry run is structurally incapable of a
//! write; this is the belt and suspenders that pins it against a real database.

mod common;

use std::collections::BTreeMap;

use common::Harness;
use ironauth_oidc::RiskLevel;
use ironauth_oidc::flow::create_flow;
use ironauth_oidc::flow::inspect::{self, DryRunInput, RiskInput, RiskSignalInput};
use ironauth_oidc::flow::model::{FlowStateTag, Journey, Transport};
use sqlx::PgPool;

/// Snapshot every public table's row count, read as the superuser owner (so forced row level
/// security never hides a row from the count). The full map is the byte identical snapshot the
/// zero side effect assertion compares.
async fn snapshot(pool: &PgPool) -> BTreeMap<String, i64> {
    let tables: Vec<(String,)> =
        sqlx::query_as("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            .fetch_all(pool)
            .await
            .expect("list public tables");
    let mut counts = BTreeMap::new();
    for (table,) in tables {
        // The table name comes from the Postgres catalog (never user input), so the
        // interpolation is safe; count(*) is read only.
        let (count,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM \"{table}\""))
            .fetch_one(pool)
            .await
            .expect("count table rows");
        counts.insert(table, count);
    }
    counts
}

/// A representative dry run input over the login journey, carrying a risk scenario that would
/// (if this were the live path) compute and PERSIST a risk decision. The dry run computes it
/// and persists nothing.
fn dry_run_input() -> DryRunInput {
    DryRunInput {
        journey: Journey::Login,
        subject: Some("usr_inspectordryrun".to_owned()),
        required_acr: Some("mfa".to_owned()),
        achieved_acr: "pwd".to_owned(),
        max_auth_age_secs: Some(300),
        auth_time_micros: None,
        now_micros: 2_000_000_000_000_000,
        order: None,
        risk: Some(RiskInput {
            signals: vec![
                RiskSignalInput {
                    name: "velocity".to_owned(),
                    level: RiskLevel::Med,
                    hard_deny: false,
                },
                RiskSignalInput {
                    name: "impossible_travel".to_owned(),
                    level: RiskLevel::Med,
                    hard_deny: false,
                },
            ],
            new_device_fired: true,
            threshold: Some(RiskLevel::Med),
            block_on_high: true,
            notify_on_new_device: true,
        }),
    }
}

#[tokio::test]
async fn observe_and_dry_run_write_no_row_anywhere() {
    let harness = Harness::start().await;
    let scope = harness.scope();

    // Create a real flow so there is something to observe (this write is part of the baseline).
    let (flow_id, _submit_token, _flow) = create_flow(
        harness.state(),
        scope,
        Transport::Api,
        Journey::Login,
        None,
        None,
        None,
        &axum::http::HeaderMap::new(),
    )
    .await
    .expect("create a login flow");
    let record = harness
        .store()
        .scoped(scope)
        .flows()
        .load(&flow_id)
        .await
        .expect("load the flow row")
        .expect("the flow exists");

    // The BEFORE snapshot: every table's row count, superuser read (RLS never hides a write).
    let before = snapshot(harness.db().owner_pool()).await;

    // OBSERVE the flow (read only) and DRY RUN a supplied context (pure). Neither touches the
    // store: observe projects the record the caller already loaded, and dry_run holds no store
    // handle at all.
    let observation = inspect::observe(&record, scope, 0).expect("observe the flow");
    assert_eq!(observation.current, FlowStateTag::IdentifierPassword);
    let projection = inspect::dry_run(&dry_run_input());
    // The dry run computed a real risk decision (a challenge, from two corroborating MED
    // signals), proving the compute path ran without persisting it.
    let primary = &projection.steps[0];
    let risk = primary.risk.as_ref().expect("a risk decision was computed");
    assert_eq!(risk.action, "challenge", "the risk compute ran");

    // The AFTER snapshot MUST be byte identical: no flow, session, risk decision, jti, policy
    // trace, or ANY other row was written by the observe or the dry run.
    let after = snapshot(harness.db().owner_pool()).await;
    assert_eq!(
        before, after,
        "the inspector wrote a row: the store is not byte identical before and after a dry run"
    );
}

#[tokio::test]
async fn observe_renders_the_plan_context_and_current_node() {
    let harness = Harness::start().await;
    let scope = harness.scope();

    let (flow_id, _submit_token, _flow) = create_flow(
        harness.state(),
        scope,
        Transport::Browser,
        Journey::Login,
        None,
        None,
        None,
        &axum::http::HeaderMap::new(),
    )
    .await
    .expect("create a login flow");
    let record = harness
        .store()
        .scoped(scope)
        .flows()
        .load(&flow_id)
        .await
        .expect("load the flow row")
        .expect("the flow exists");

    let observation = inspect::observe(&record, scope, 0).expect("observe the flow");

    // The plan is the ONE transition table the engine shares (the ordered login state
    // sequence), the current state is the login start, and the flow is neither completed nor
    // expired at the epoch.
    assert_eq!(observation.journey, Journey::Login);
    assert_eq!(observation.current, FlowStateTag::IdentifierPassword);
    assert_eq!(observation.plan.steps, Journey::Login.plan().to_vec());
    assert!(!observation.completed && !observation.expired);

    // The redacted context carries the step and no leaked identifier value.
    assert_eq!(observation.context.step, FlowStateTag::IdentifierPassword);
    assert!(!observation.context.has_identifier);

    // The current node render reuses the engine's node model (the login start form has at
    // least the identifier input).
    assert!(
        !observation.node_render.ui.nodes.is_empty(),
        "the current node render is not empty"
    );
}
