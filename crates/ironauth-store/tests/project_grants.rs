// SPDX-License-Identifier: MIT OR Apache-2.0

//! Project-grant domain events (issue #108), over a real database (`DATABASE_URL`).
//!
//! A project grant is what lets a client act FOR a customer organization, so a consumer
//! mirroring delegated authority acts on both halves of its life. The create carries both
//! ends and the organization, because the grant id alone does not say who may act for whom;
//! the withdrawal is the half a receiver DEPROVISIONS on, and is its own type so that a
//! consumer cannot read a revocation as a no-op and keep honouring a client's authority over
//! an organization after an operator took it away.
//!
//! Both events are enqueued in the write's own transaction, after the write's guard: the
//! withdrawal of an already-withdrawn grant is a typed not-found and announces nothing.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, NewOrgRole, NewProjectGrant, OrgRoleId, OrganizationId,
    ProjectGrantId, Scope, ServiceId, StoreError,
};

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// The current clock-seam time in microseconds since the Unix epoch.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Claim and complete the single queued event, returning its payload envelope.
async fn claim_one_event(db: &TestDatabase, env: &Env, scope: Scope) -> serde_json::Value {
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "expected exactly one queued event");
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().next().expect("one message").payload
}

/// Seed the three rows a grant binds together: an organization, one live role in it, and a
/// client. Returns them in that order.
async fn seed_parties(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
) -> (OrganizationId, OrgRoleId, ClientId) {
    let org = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &org, now_micros(env), "grant events org", None)
        .await
        .expect("create organization");

    let role = OrgRoleId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_roles(scope)
        .create(
            env,
            NewOrgRole {
                id: &role,
                organization_id: &org,
                slug: "delegated-admin",
                display_name: "Delegated administrator",
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create role");

    let client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create(env, "grant events client")
        .await
        .expect("create client");

    (org, role, client)
}

/// Creating and withdrawing a project grant emit distinct types, and a withdrawal that
/// changes nothing announces nothing.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn creating_and_withdrawing_a_project_grant_emit_distinct_types() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (org, role, client) = seed_parties(&db, &env, scope).await;
    let grant_id = ProjectGrantId::generate(&env, &scope);

    let created = ironauth_store::event_catalog::envelope(
        "evt_project_grant_created",
        "project_grant.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "project_grant_id": grant_id.to_string(),
            "client_id": client.to_string(),
            "organization_id": org.to_string(),
        }),
    )
    .expect("project_grant.created is registered");

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .project_grants(scope)
        .create_with_event(
            &env,
            NewProjectGrant {
                id: &grant_id,
                client_id: &client,
                organization_id: &org,
                role_ids: &[role],
            },
            now_micros(&env),
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_project_grant_created",
                subject: &grant_id.to_string(),
                envelope: &created,
            }),
        )
        .await
        .expect("create the grant");

    let first = claim_one_event(&db, &env, scope).await;
    assert_eq!(first["type"], "project_grant.created");
    assert_eq!(
        first["payload"]["client_id"],
        client.to_string(),
        "the grant id alone does not say WHO may act, so the client must be on the wire"
    );
    assert_eq!(
        first["payload"]["organization_id"],
        org.to_string(),
        "nor for WHOM, so the organization must be on the wire"
    );
    assert!(
        first["payload"].get("role_ids").is_none(),
        "the assignable roles are not part of the announced contract: {first}"
    );

    let withdrawn = ironauth_store::event_catalog::envelope(
        "evt_project_grant_withdrawn",
        "project_grant.withdrawn",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({ "project_grant_id": grant_id.to_string() }),
    )
    .expect("project_grant.withdrawn is registered");

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .project_grants(scope)
        .withdraw_with_event(
            &env,
            &grant_id,
            now_micros(&env),
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_project_grant_withdrawn",
                subject: &grant_id.to_string(),
                envelope: &withdrawn,
            }),
        )
        .await
        .expect("withdraw the grant");

    let second = claim_one_event(&db, &env, scope).await;
    assert_eq!(
        second["type"], "project_grant.withdrawn",
        "a withdrawal REVOKES delegated authority; announcing it as a create, or not at all, \
         leaves a receiver honouring a client's authority an operator took away"
    );
    assert_eq!(second["payload"]["project_grant_id"], grant_id.to_string());

    // The guard sits BEFORE the enqueue: a second withdrawal changes no row, so it announces
    // nothing. A consumer must not see a revocation that did not happen.
    let repeat = ironauth_store::event_catalog::envelope(
        "evt_project_grant_withdrawn_again",
        "project_grant.withdrawn",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        3,
        &serde_json::json!({ "project_grant_id": grant_id.to_string() }),
    )
    .expect("project_grant.withdrawn is registered");
    let error = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .project_grants(scope)
        .withdraw_with_event(
            &env,
            &grant_id,
            now_micros(&env),
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_project_grant_withdrawn_again",
                subject: &grant_id.to_string(),
                envelope: &repeat,
            }),
        )
        .await
        .expect_err("an already-withdrawn grant is not found");
    assert!(matches!(error, StoreError::NotFound), "got {error:?}");

    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    assert!(
        claimed.is_empty(),
        "a no-op withdrawal must announce nothing: {claimed:?}"
    );
}
