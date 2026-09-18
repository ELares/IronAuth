// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stored quota overrides reach the running enforcer (issue #150 criterion 4).
//!
//! The criterion asks that a tenant's limits "change at runtime ... without restart, taking
//! effect within the invalidation SLO". Three pieces existed and none of them was joined to the
//! next: the `tenant_quota_limits` table with its repository, `QuotaEnforcer`'s override
//! methods, and the running engine. A row could be written and would change nothing, on any
//! node, for ever.
//!
//! These drive the join. Each asserts on ENFORCEMENT -- whether a spend is admitted -- rather
//! than on the enforcer's internal state, because "the override was applied" is a claim about
//! what happens to the next request.

mod common;

use std::sync::Arc;

use common::Harness;
use ironauth_config::{QuotaConfig, ScopeQuotaConfig};
use ironauth_env::Env;
use ironauth_quota::{EnvironmentId, QuotaDimension, QuotaEnforcer, TenantId};
use ironauth_store::{ActorRef, CorrelationId, Scope, ServiceId};

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
    let spend = ironauth_quota::Scope::Environment(
        TenantId::new(scope.tenant().to_string()),
        EnvironmentId::new(scope.environment().to_string()),
    );
    enforcer
        .admit(&spend, QuotaDimension::Requests, 1.0)
        .decision
        .is_admitted()
}

/// The store scope for a created tenant and environment.
fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        ironauth_store::TenantId::parse(tenant).expect("tenant parses"),
        ironauth_store::EnvironmentId::parse(environment).expect("environment parses"),
    )
}

/// Write one dimension's override through the acting (audited) repository.
async fn store_override(
    h: &Harness,
    scope: Scope,
    env: &Env,
    dimension: &str,
    refill_per_sec: f64,
    burst: f64,
) {
    // THE CONTROL-PLANE STORE. Migration 0229 grants the data plane SELECT on this table and
    // nothing else, which is the point: a compromised request path must not be able to raise
    // its own tenant's limit. Writes are a management operation, so they go through the role
    // the management API runs as.
    h.db()
        .control_store()
        .scoped(scope)
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .quota_limits()
        .set(env, dimension, refill_per_sec, burst)
        .await
        .expect("store the override");
}

/// Clear one dimension's override through the acting (audited) repository.
async fn clear_override(h: &Harness, scope: Scope, env: &Env, dimension: &str) {
    h.db()
        .control_store()
        .scoped(scope)
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .quota_limits()
        .clear(env, dimension)
        .await
        .expect("clear the override");
}

#[tokio::test]
async fn a_stored_override_is_enforced_after_one_refresh_and_not_before() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-quota-apply").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let enforcer = generous_enforcer(&env);

    // BEFORE: the configured tier admits, which is the control. Without it a test that only
    // checks the refusal cannot tell an applied override from a default that refuses anyway.
    assert!(
        admits(&enforcer, scope),
        "the generous configured tier admits before any override"
    );

    // A zero-burst override is this codebase's spelling of "refuse everything", so the
    // assertion below is about the override arriving rather than about arithmetic.
    store_override(&h, scope, &env, QuotaDimension::Requests.as_str(), 0.0, 0.0).await;

    // STILL ADMITS. The row is in Postgres and nothing has read it: this is the state every
    // release before the refresher shipped was permanently in.
    assert!(
        admits(&enforcer, scope),
        "a stored override changes nothing until something applies it"
    );

    let summary = ironauth_admin::quota_refresh::refresh(h.store(), &[scope], &enforcer)
        .await
        .expect("refresh");
    assert_eq!(summary.applied, 1, "{summary:?}");
    assert_eq!(summary.cleared, 0, "{summary:?}");

    assert!(
        !admits(&enforcer, scope),
        "after one refresh the stored override is what the next request is judged against"
    );
}

#[tokio::test]
async fn deleting_an_override_restores_the_configured_tier_without_a_restart() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-quota-clear").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let enforcer = generous_enforcer(&env);

    store_override(&h, scope, &env, QuotaDimension::Requests.as_str(), 0.0, 0.0).await;
    ironauth_admin::quota_refresh::refresh(h.store(), &[scope], &enforcer)
        .await
        .expect("refresh");
    assert!(!admits(&enforcer, scope), "the override is in force");

    clear_override(&h, scope, &env, QuotaDimension::Requests.as_str()).await;

    // THE ASYMMETRY IS THE POINT. A pass that only applied what it found would leave every node
    // enforcing the deleted limit until it restarted, which is exactly the "without restart"
    // the criterion names. An absent row is an instruction.
    let summary = ironauth_admin::quota_refresh::refresh(h.store(), &[scope], &enforcer)
        .await
        .expect("refresh");
    assert_eq!(summary.cleared, 1, "{summary:?}");
    assert_eq!(summary.applied, 0, "{summary:?}");
    assert!(
        admits(&enforcer, scope),
        "deleting the override returns the scope to its configured tier"
    );
}

#[tokio::test]
async fn a_dimension_this_build_does_not_have_is_counted_and_skipped() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-quota-unknown").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    let enforcer = generous_enforcer(&env);

    // A NEWER NODE'S ROW. The store keeps the dimension as text precisely so a rolling upgrade
    // works, and an older node must apply the rest of the scope's limits rather than refuse the
    // whole set. Both rows are written; only one of them names something this build has.
    store_override(&h, scope, &env, "storage_bytes", 1.0, 1.0).await;
    store_override(&h, scope, &env, QuotaDimension::Requests.as_str(), 0.0, 0.0).await;

    let summary = ironauth_admin::quota_refresh::refresh(h.store(), &[scope], &enforcer)
        .await
        .expect("refresh");
    assert_eq!(summary.unknown_dimensions, 1, "{summary:?}");
    assert_eq!(summary.applied, 1, "{summary:?}");
    assert!(
        !admits(&enforcer, scope),
        "the dimension this build DOES have still applied"
    );
}
