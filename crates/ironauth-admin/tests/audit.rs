// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit on every mutation: each management mutation writes its audit row in the
//! same transaction, naming the acting credential. Verified by reading the audit
//! log through the control store after driving mutations over the HTTP API.

mod common;

use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};

/// The bootstrap operator's audit actor: a service actor with the well-known id.
const OPERATOR_ACTOR_ID: &str = "svc_AAAAAAAAAAAAAAAAAAAAAA";

async fn actions_in(harness: &Harness, scope: Scope) -> Vec<String> {
    harness
        .control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .collect()
}

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

#[tokio::test]
async fn every_management_mutation_writes_a_scoped_audit_row_naming_the_actor() {
    let harness = Harness::start(50).await;

    // create tenant -> audits tenant.create scoped to (tenant, first environment).
    let (tenant, env1) = harness.create_tenant("Acme", "k1").await;
    let scope1 = scope_of(&tenant, &env1);
    let rows = harness
        .control_store()
        .scoped(scope1)
        .audit()
        .list()
        .await
        .expect("audit");
    assert_eq!(rows.len(), 1, "tenant.create writes exactly one audit row");
    assert_eq!(rows[0].action, "tenant.create");
    assert_eq!(
        rows[0].actor.kind_str(),
        "service",
        "operator is a service actor"
    );
    assert_eq!(
        rows[0].actor.id_string(),
        OPERATOR_ACTOR_ID,
        "the audit row names the bootstrap operator credential"
    );
    assert_eq!(rows[0].target_kind, "ten");
    assert_eq!(rows[0].target_id, tenant);

    // create environment -> audits environment.create scoped to (tenant, env2).
    let env2 = harness.create_environment(&tenant, "staging", "k2").await;
    let scope2 = scope_of(&tenant, &env2);
    assert_eq!(
        actions_in(&harness, scope2).await,
        vec!["environment.create"]
    );

    // mint + revoke a key -> management_key.create and management_key.delete in
    // the key's scope (tenant, env1).
    let secret = harness.create_key(&tenant, &env1, "ci", "k3").await;
    let key_id = secret.split('.').next().expect("mak id").to_owned();
    let (delete_status, _, _) = harness
        .delete(&format!(
            "/v1/tenants/{tenant}/environments/{env1}/keys/{key_id}"
        ))
        .await;
    assert_eq!(delete_status, axum::http::StatusCode::NO_CONTENT);

    // deactivate the second environment and then the tenant.
    let (env_del, _, _) = harness
        .delete(&format!("/v1/tenants/{tenant}/environments/{env2}"))
        .await;
    assert_eq!(env_del, axum::http::StatusCode::NO_CONTENT);
    let (tenant_del, _, _) = harness.delete(&format!("/v1/tenants/{tenant}")).await;
    assert_eq!(tenant_del, axum::http::StatusCode::NO_CONTENT);

    // Scope (tenant, env1) accumulated: tenant.create, management_key.create,
    // management_key.delete, and tenant.delete (which scopes to the oldest env).
    let scope1_actions = actions_in(&harness, scope1).await;
    for expected in [
        "tenant.create",
        "management_key.create",
        "management_key.delete",
        "tenant.delete",
    ] {
        assert!(
            scope1_actions.iter().any(|a| a == expected),
            "scope1 must contain {expected}: {scope1_actions:?}"
        );
    }

    // Scope (tenant, env2) accumulated the environment create and delete.
    let scope2_actions = actions_in(&harness, scope2).await;
    for expected in ["environment.create", "environment.delete"] {
        assert!(
            scope2_actions.iter().any(|a| a == expected),
            "scope2 must contain {expected}: {scope2_actions:?}"
        );
    }
}
