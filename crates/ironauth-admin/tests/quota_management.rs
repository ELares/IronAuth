// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime quota overrides through the management API (issue #150 criterion 4).
//!
//! The criterion asks that a tenant's limits "change at runtime per tenant via the
//! management API without restart, taking effect within the invalidation SLO". Migration 0229
//! shipped the table, `quota_refresh` ships the reader, and this drives the WRITE half over
//! HTTP: a PUT reaches the same table the refresher reads, so a management-API write plus one
//! refresh pass is a limit change with no restart.
//!
//! The enforcement half is asserted through a real `QuotaEnforcer`, not through the enforcer's
//! internal state: "the override was applied" is a claim about what happens to the next spend.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::Harness;
use ironauth_config::{QuotaConfig, ScopeQuotaConfig};
use ironauth_env::Env;
use ironauth_quota::{EnvironmentId, QuotaDimension, QuotaEnforcer, Scope as QuotaScope, TenantId};
use ironauth_store::Scope;
use serde_json::Value;

/// The bootstrap operator's audit actor: a service actor with the well-known id.
const OPERATOR_ACTOR_ID: &str = "svc_AAAAAAAAAAAAAAAAAAAAAA";

/// An enforcer whose configured tiers are generous, so anything that refuses comes from an
/// override rather than from the default.
fn generous_enforcer(env: &Env) -> Arc<QuotaEnforcer> {
    let tier = ScopeQuotaConfig {
        requests_per_second: 1_000,
        requests_burst: 1_000,
        token_issuance_per_second: 1_000,
        token_issuance_burst: 1_000,
        hook_seconds_per_second: 1_000,
        hook_seconds_burst: 1_000,
        password_hashing_per_second: 1_000,
        password_hashing_burst: 1_000,
    };
    let config = QuotaConfig {
        tenant: tier.clone(),
        environment: tier,
        ..QuotaConfig::default()
    };
    Arc::new(QuotaEnforcer::from_config(&config, env.clock_arc()))
}

/// Spend one request unit against `scope`, answering whether it was admitted.
fn admits(enforcer: &Arc<QuotaEnforcer>, scope: Scope) -> bool {
    let spend = QuotaScope::Environment(
        TenantId::new(scope.tenant().to_string()),
        EnvironmentId::new(scope.environment().to_string()),
    );
    enforcer
        .admit(&spend, QuotaDimension::Requests, 1.0)
        .decision
        .is_admitted()
}

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        ironauth_store::TenantId::parse(tenant).expect("tenant parses"),
        ironauth_store::EnvironmentId::parse(environment).expect("environment parses"),
    )
}

fn limits_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/quota/limits")
}

fn limit_path(tenant: &str, environment: &str, dimension: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/quota/limits/{dimension}")
}

/// The parsed `items` of a quota-limits response.
fn items(response: &str) -> Vec<Value> {
    let view: Value = serde_json::from_str(response).expect("json");
    view["items"].as_array().expect("items is a list").clone()
}

/// Mint a management key for `(tenant, environment)` and return its secret (the bearer).
async fn mint_key(h: &Harness, tenant: &str, environment: &str, idem: &str) -> String {
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/keys"),
            idem,
            &serde_json::json!({ "display_name": "quota-test" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "mint management key: {body}");
    let created: Value = serde_json::from_str(&body).expect("json");
    created["secret"].as_str().expect("secret").to_owned()
}

#[tokio::test]
async fn an_override_written_through_the_management_api_reaches_the_enforcer_within_one_refresh() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-qmgr-apply").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let enforcer = generous_enforcer(&env);

    // CONTROL: the configured tier admits before any override exists, so a later refusal is
    // attributable to the management write rather than to a default that refuses anyway.
    assert!(admits(&enforcer, scope), "the configured tier admits first");

    // A zero-burst override is this codebase's spelling of "refuse everything".
    let (status, _, body) = h
        .put(
            &limit_path(&tenant, &environment, QuotaDimension::Requests.as_str()),
            r#"{"refill_per_sec":0.0,"burst":0.0}"#,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "put override: {body}");

    // The row is in Postgres and nothing has read it yet: this is the state every release
    // before the refresher shipped was permanently in.
    assert!(
        admits(&enforcer, scope),
        "a stored override changes nothing until something applies it"
    );

    // The management surface reads it back, naming the dimension this build recognizes.
    let (status, _, body) = h.get(&limits_path(&tenant, &environment)).await;
    assert_eq!(status, StatusCode::OK, "list overrides: {body}");
    let items = items(&body);
    assert_eq!(items.len(), 1, "exactly one override: {body}");
    assert_eq!(items[0]["dimension"], QuotaDimension::Requests.as_str());
    assert_eq!(items[0]["recognized"], true);
    assert_eq!(items[0]["refill_per_sec"], 0.0);
    assert_eq!(items[0]["burst"], 0.0);

    // ONE REFRESH, the same pass the running node runs on its tick: the write now governs the
    // next spend, which is the criterion's "without restart".
    let summary = ironauth_admin::quota_refresh::refresh(h.store(), &[scope], &enforcer)
        .await
        .expect("refresh");
    assert_eq!(summary.applied, 1, "{summary:?}");
    assert!(
        !admits(&enforcer, scope),
        "after one refresh the management-API write is what the next request is judged against"
    );
}

#[tokio::test]
async fn deleting_an_override_through_the_api_returns_the_scope_to_its_configured_tier() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-qmgr-clear").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    // A FROZEN clock, advanced explicitly: the final admit depends on the restored tier
    // refilling the bucket, and a 1000/s tier needs a full millisecond to mint the one
    // token it costs. On a fast machine the API round-trips between the two spends take
    // less, which made the same assertions flake on wall-clock timing.
    let manual_clock = std::sync::Arc::new(ironauth_env::ManualClock::new(
        std::time::SystemTime::UNIX_EPOCH,
    ));
    let clock: std::sync::Arc<dyn ironauth_env::Clock> = manual_clock.clone();
    let config = QuotaConfig {
        tenant: ScopeQuotaConfig {
            requests_per_second: 1_000,
            requests_burst: 1_000,
            ..ScopeQuotaConfig::default()
        },
        environment: ScopeQuotaConfig {
            requests_per_second: 1_000,
            requests_burst: 1_000,
            ..ScopeQuotaConfig::default()
        },
        ..QuotaConfig::default()
    };
    let enforcer = Arc::new(QuotaEnforcer::from_config(&config, clock));

    h.put(
        &limit_path(&tenant, &environment, QuotaDimension::Requests.as_str()),
        r#"{"refill_per_sec":0.0,"burst":0.0}"#,
    )
    .await;
    ironauth_admin::quota_refresh::refresh(h.store(), &[scope], &enforcer)
        .await
        .expect("refresh");
    assert!(!admits(&enforcer, scope), "the override is in force");

    let (status, _, body) = h
        .delete(&limit_path(
            &tenant,
            &environment,
            QuotaDimension::Requests.as_str(),
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "clear override: {body}");

    // The list is empty again, and one refresh restores the configured tier WITHOUT restart.
    let (status, _, body) = h.get(&limits_path(&tenant, &environment)).await;
    assert_eq!(status, StatusCode::OK, "list overrides: {body}");
    assert!(items(&body).is_empty(), "no overrides remain: {body}");

    let summary = ironauth_admin::quota_refresh::refresh(h.store(), &[scope], &enforcer)
        .await
        .expect("refresh");
    assert_eq!(summary.cleared, 1, "{summary:?}");

    // Two seconds of frozen time later, the restored tier has refilled the bucket: the
    // spend is admitted because the override is GONE, not because a millisecond passed.
    manual_clock.advance(std::time::Duration::from_secs(2));
    assert!(
        admits(&enforcer, scope),
        "deleting the override returns the scope to its configured tier"
    );
}

#[tokio::test]
async fn clearing_an_override_that_is_not_stored_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-qmgr-absent").await;

    let (status, _, body) = h
        .delete(&limit_path(
            &tenant,
            &environment,
            QuotaDimension::Requests.as_str(),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "absent override: {body}");
}

#[tokio::test]
async fn an_unknown_dimension_is_a_400_on_both_write_and_delete() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-qmgr-unknown").await;

    // The management surface REFUSES a label it cannot name: an operator typing `requsts`
    // must be told, not silently given a row nothing will ever read.
    let (status, _, body) = h
        .put(
            &limit_path(&tenant, &environment, "requsts"),
            r#"{"refill_per_sec":1.0,"burst":1.0}"#,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown dimension put: {body}"
    );
    assert!(
        body.contains("requsts"),
        "names the offending label: {body}"
    );

    let (status, _, body) = h
        .delete(&limit_path(&tenant, &environment, "requsts"))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown dimension delete: {body}"
    );
}

#[tokio::test]
async fn a_negative_limit_is_a_400_naming_the_constraint() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-qmgr-negative").await;

    let (status, _, body) = h
        .put(
            &limit_path(&tenant, &environment, QuotaDimension::Requests.as_str()),
            r#"{"refill_per_sec":1.0,"burst":-5}"#,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "negative burst: {body}");
}

#[tokio::test]
async fn a_management_key_scoped_to_another_environment_cannot_touch_this_scope() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-qmgr-scope").await;
    let other = h
        .create_environment(&tenant, "second", "k-qmgr-scope-env")
        .await;

    // A key minted for the OTHER environment, used against this one's quota surface: the
    // LOUD wrong-scope error, never a silent success or an oracle-not-found.
    let other_secret = mint_key(&h, &tenant, &other, "k-qmgr-scope-key").await;

    let (status, _, body) = h
        .get_as(&limits_path(&tenant, &environment), &other_secret)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong-scope read: {body}");

    let (status, _, body) = h
        .put_as(
            &limit_path(&tenant, &environment, QuotaDimension::Requests.as_str()),
            &other_secret,
            r#"{"refill_per_sec":0.0,"burst":0.0}"#,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong-scope write: {body}");

    // And nothing was written: the operator's own read still shows an empty set.
    let (_, _, body) = h.get(&limits_path(&tenant, &environment)).await;
    assert!(items(&body).is_empty(), "no override landed: {body}");
}

#[tokio::test]
async fn quota_limit_changes_are_audited_naming_the_dimension() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-qmgr-audit").await;
    let scope = scope_of(&tenant, &environment);

    let (status, _, _) = h
        .put(
            &limit_path(&tenant, &environment, QuotaDimension::Requests.as_str()),
            r#"{"refill_per_sec":5.0,"burst":3}"#,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = h
        .delete(&limit_path(
            &tenant,
            &environment,
            QuotaDimension::Requests.as_str(),
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The two writes left an audit trail naming WHICH limit moved, through the same control
    // store the management surface writes. The actor is the bootstrap operator (the well-known
    // service actor), because these requests rode the operator token.
    let rows = h
        .control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list");
    let actions: Vec<&str> = rows.iter().map(|row| row.action.as_str()).collect();
    assert!(
        actions.contains(&"quota.limit.set"),
        "a set is audited: {actions:?}"
    );
    assert!(
        actions.contains(&"quota.limit.cleared"),
        "a clear is audited: {actions:?}"
    );
    let set = rows
        .iter()
        .find(|row| row.action == "quota.limit.set")
        .expect("the set row");
    assert_eq!(
        set.actor.id_string(),
        OPERATOR_ACTOR_ID,
        "the audit row names the acting credential"
    );
    assert_eq!(set.target_kind, "quota");
    assert_eq!(
        set.target_id,
        QuotaDimension::Requests.as_str(),
        "the audit row names WHICH limit moved"
    );
}
