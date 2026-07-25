// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management-plane IDOR probes, registered with the #6 harness and run
//! against a real database. A management key resolved by id under one scope must
//! never reach a key minted in another tenant or environment.

use ironauth_env::Env;
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, ManagementKeyId, NewAdminUser, NewMembership, NewOrgGroup,
    NewOrgGroupMember, NewOrgGroupRole, NewOrgMembershipRole, NewOrgRole, OrgGroupId,
    OrgGroupMemberId, OrgGroupRoleId, OrgMembershipId, OrgMembershipRoleId, OrgRoleId,
    OrganizationId, Scope, ServiceId, StoreError, UserState,
};

/// A stand-in key hash for a planted victim (the probes resolve by id, not hash).
const VICTIM_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn management_probes_deny_cross_tenant_and_cross_environment_uniformly() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let control = db.control_store();

    // Caller is tenant A, environment A1. Victims: tenant B, and a second
    // environment of tenant A (cross-environment is a distinct probe).
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let victim_b = plant_key(control, &env, scope_b).await;
    let victim_a2 = plant_key(control, &env, scope_a2).await;

    // Organizations are the fourth level (issue #41): plant a victim in each
    // foreign scope so the organization probes have a real cross-scope target.
    let victim_org_b = plant_org(control, &env, scope_b).await;
    let victim_org_a2 = plant_org(control, &env, scope_a2).await;

    // Organization memberships (issue #94): plant a victim membership in each
    // foreign scope so the membership probes have a real cross-scope target.
    let victim_member_b = plant_membership(control, &env, scope_b, &victim_org_b).await;
    let victim_member_a2 = plant_membership(control, &env, scope_a2, &victim_org_a2).await;

    // Organization roles (issue #97): plant a victim role in each foreign scope so
    // the role probes have a real cross-scope target.
    let victim_role_b = plant_role(control, &env, scope_b, &victim_org_b).await;
    let victim_role_a2 = plant_role(control, &env, scope_a2, &victim_org_a2).await;

    // Organization groups (issue #97): plant a victim group in each foreign scope so
    // the group probes have a real cross-scope target, including for the update probe
    // (a rename is a cross-scope mutation too) and for the reparent probe, whose
    // refusal must be the uniform not-found and never a typed cycle or depth error
    // (either would be an oracle over a foreign group graph).
    let victim_group_b = plant_group(control, &env, scope_b, &victim_org_b).await;
    let victim_group_a2 = plant_group(control, &env, scope_a2, &victim_org_a2).await;

    // The three JOIN surfaces (issue #97): a group binding, a group role grant, and a
    // direct role grant, planted in each foreign scope. Every one of them is a
    // mutation with a real authorization effect (unassigning a group role withdraws it
    // from every member of that group and of its descendants), so each needs a real
    // cross-scope target rather than only an absent id.
    let victim_binding_b =
        plant_group_member(control, &env, scope_b, &victim_org_b, &victim_group_b).await;
    let victim_binding_a2 =
        plant_group_member(control, &env, scope_a2, &victim_org_a2, &victim_group_a2).await;
    let victim_group_grant_b = plant_group_role(
        control,
        &env,
        scope_b,
        &victim_org_b,
        &victim_group_b,
        &victim_role_b,
    )
    .await;
    let victim_group_grant_a2 = plant_group_role(
        control,
        &env,
        scope_a2,
        &victim_org_a2,
        &victim_group_a2,
        &victim_role_a2,
    )
    .await;
    let victim_direct_grant_b = plant_membership_role(
        control,
        &env,
        scope_b,
        &victim_org_b,
        &victim_member_b,
        &victim_role_b,
    )
    .await;
    let victim_direct_grant_a2 = plant_membership_role(
        control,
        &env,
        scope_a2,
        &victim_org_a2,
        &victim_member_a2,
        &victim_role_a2,
    )
    .await;

    // A well-formed key id in the caller's OWN scope that was never stored.
    let absent_in_a = ManagementKeyId::generate(&env, &scope_a).to_string();

    // Baseline for uniformity: the absent id is NotFound in the caller's scope.
    let credentials_a = control.management().credentials(scope_a);
    let absent_id = credentials_a
        .parse_id(&absent_in_a)
        .expect("absent id is well formed and in scope");
    assert!(matches!(
        credentials_a.get(&absent_id).await,
        Err(StoreError::NotFound)
    ));

    let mut harness = IdorHarness::new();
    harness.register_management_probes();
    assert_eq!(
        harness.probe_names(),
        vec![
            "management_credentials.get",
            "management_credentials.delete",
            "organizations.get",
            "organizations.delete",
            "org_memberships.get",
            "org_memberships.remove",
            "org_roles.get",
            "org_roles.delete",
            "org_groups.get",
            "org_groups.update",
            "org_groups.delete",
            "org_groups.reparent",
            "org_group_members.remove",
            "org_group_roles.unassign",
            "org_membership_roles.unassign",
        ],
        "every management resolve-by-id operation is registered",
    );

    let foreign = [
        victim_b.to_string(),
        victim_a2.to_string(),
        victim_org_b.to_string(),
        victim_org_a2.to_string(),
        victim_member_b.to_string(),
        victim_member_a2.to_string(),
        victim_role_b.to_string(),
        victim_role_a2.to_string(),
        victim_group_b.to_string(),
        victim_group_a2.to_string(),
        victim_binding_b.to_string(),
        victim_binding_a2.to_string(),
        victim_group_grant_b.to_string(),
        victim_group_grant_a2.to_string(),
        victim_direct_grant_b.to_string(),
        victim_direct_grant_a2.to_string(),
        absent_in_a.clone(),
    ];
    let foreign_refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(control, scope_a, &foreign_refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // The delete probe must not have leak-deleted the victims: they survive.
    assert!(
        control
            .management()
            .credentials(scope_b)
            .get(&victim_b)
            .await
            .is_ok(),
        "tenant B's key must survive the delete probe"
    );
    assert!(
        control
            .management()
            .credentials(scope_a2)
            .get(&victim_a2)
            .await
            .is_ok(),
        "environment A2's key must survive the delete probe"
    );

    // The victim organizations must likewise survive: the organizations.delete
    // probe must not have leak-deactivated a foreign-scope row.
    assert!(
        control
            .management()
            .organizations(scope_b)
            .get(&victim_org_b)
            .await
            .is_ok(),
        "tenant B's organization must survive the delete probe"
    );
    assert!(
        control
            .management()
            .organizations(scope_a2)
            .get(&victim_org_a2)
            .await
            .is_ok(),
        "environment A2's organization must survive the delete probe"
    );

    // The victim memberships must likewise survive the remove probe.
    assert!(
        control
            .management()
            .org_memberships(scope_b)
            .get(&victim_member_b)
            .await
            .is_ok(),
        "tenant B's membership must survive the remove probe"
    );
    assert!(
        control
            .management()
            .org_memberships(scope_a2)
            .get(&victim_member_a2)
            .await
            .is_ok(),
        "environment A2's membership must survive the remove probe"
    );

    // The victim roles must likewise survive the delete probe.
    assert!(
        control
            .management()
            .org_roles(scope_b)
            .get(&victim_role_b)
            .await
            .is_ok(),
        "tenant B's role must survive the delete probe"
    );
    assert!(
        control
            .management()
            .org_roles(scope_a2)
            .get(&victim_role_a2)
            .await
            .is_ok(),
        "environment A2's role must survive the delete probe"
    );

    // The victim groups must survive the update, delete, and reparent probes, must
    // still carry their OWN display name, and must still be ROOTS: a cross-scope
    // rename or reparent that landed would leave the read intact while having
    // mutated the foreign organization's group, which is exactly the leak a
    // liveness-only assertion would miss.
    for (scope, group) in [(scope_b, &victim_group_b), (scope_a2, &victim_group_a2)] {
        let record = control
            .management()
            .org_groups(scope)
            .get(group)
            .await
            .expect("the victim group must survive the update, delete, and reparent probes");
        assert_eq!(
            record.display_name, "victim group",
            "the victim group's display name must be untouched by the update probe"
        );
        assert_eq!(
            record.parent_id, None,
            "the victim group's position in its own hierarchy must be untouched"
        );
    }

    // The three victim JOIN rows must survive their remove and unassign probes. A
    // liveness read is the whole assertion here: these tables carry no mutable field
    // besides the soft-delete pair, so "still readable" IS "still granting".
    for (scope, org, binding, group_role, direct_role) in [
        (
            scope_b,
            &victim_org_b,
            &victim_binding_b,
            &victim_group_grant_b,
            &victim_direct_grant_b,
        ),
        (
            scope_a2,
            &victim_org_a2,
            &victim_binding_a2,
            &victim_group_grant_a2,
            &victim_direct_grant_a2,
        ),
    ] {
        assert!(
            control
                .management()
                .org_group_members(scope)
                .get_in_org(org, binding)
                .await
                .is_ok(),
            "the victim group binding must survive the remove probe"
        );
        assert!(
            control
                .management()
                .org_group_roles(scope)
                .get_in_org(org, group_role)
                .await
                .is_ok(),
            "the victim group role grant must survive the unassign probe"
        );
        assert!(
            control
                .management()
                .org_membership_roles(scope)
                .get_in_org(org, direct_role)
                .await
                .is_ok(),
            "the victim direct role grant must survive the unassign probe"
        );
    }
}

/// Plant a live group binding in `scope` via the control store, returning its id.
async fn plant_group_member(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &OrgGroupId,
) -> OrgGroupMemberId {
    let membership =
        plant_membership_named(control, env, scope, org, "victim-bound@example.test").await;
    let id = OrgGroupMemberId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .org_group_members(scope)
        .add(
            env,
            NewOrgGroupMember {
                id: &id,
                organization_id: org,
                group_id: group,
                membership_id: &membership,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim group binding");
    id
}

/// Plant a live group role grant in `scope` via the control store, returning its id.
async fn plant_group_role(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &OrgGroupId,
    role: &OrgRoleId,
) -> OrgGroupRoleId {
    let id = OrgGroupRoleId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .org_group_roles(scope)
        .assign(
            env,
            NewOrgGroupRole {
                id: &id,
                organization_id: org,
                group_id: group,
                role_id: role,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim group role grant");
    id
}

/// Plant a live DIRECT role grant in `scope` via the control store, returning its id.
async fn plant_membership_role(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    membership: &OrgMembershipId,
    role: &OrgRoleId,
) -> OrgMembershipRoleId {
    let id = OrgMembershipRoleId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .org_membership_roles(scope)
        .assign(
            env,
            NewOrgMembershipRole {
                id: &id,
                organization_id: org,
                membership_id: membership,
                role_id: role,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim direct role grant");
    id
}

/// Plant a live group in `org` within `scope` via the control store, returning the
/// group id.
async fn plant_group(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
) -> OrgGroupId {
    let id = OrgGroupId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .org_groups(scope)
        .create(
            env,
            NewOrgGroup {
                id: &id,
                organization_id: org,
                parent_id: None,
                slug: "victim-group",
                display_name: "victim group",
                metadata: None,
            },
            1_000_000,
            8,
            None,
        )
        .await
        .expect("plant victim group");
    id
}

/// Plant a live role in `org` within `scope` via the control store, returning the
/// role id.
async fn plant_role(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
) -> OrgRoleId {
    let id = OrgRoleId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .org_roles(scope)
        .create(
            env,
            NewOrgRole {
                id: &id,
                organization_id: org,
                slug: "victim-role",
                display_name: "victim role",
                metadata: None,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim role");
    id
}

/// Plant a live membership (a fresh active user bound into `org`) in `scope` via the
/// control store, returning the membership id.
async fn plant_membership(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
) -> OrgMembershipId {
    plant_membership_named(control, env, scope, org, "victim-member@example.test").await
}

/// Plant a live membership under an explicit identifier, so one scope can hold more
/// than one victim member (identifiers are unique per scope).
async fn plant_membership_named(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    identifier: &str,
) -> OrgMembershipId {
    let actor = ActorRef::service(ServiceId::generate(env));
    let user = control
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim user");
    let id = OrgMembershipId::generate(env, &scope);
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .org_memberships(scope)
        .create(
            env,
            NewMembership {
                id: &id,
                organization_id: org,
                user_id: &user,
                metadata: None,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim membership");
    id
}

/// Plant a live organization in `scope` via the control store.
async fn plant_org(control: &ironauth_store::Store, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, 1_000_000, "victim organization", None)
        .await
        .expect("plant victim organization");
    id
}

/// Plant a live management key in `scope` via the control store.
async fn plant_key(control: &ironauth_store::Store, env: &Env, scope: Scope) -> ManagementKeyId {
    let id = ManagementKeyId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .credentials(scope)
        .create(env, &id, 1_000_000, VICTIM_HASH, "victim key", None)
        .await
        .expect("plant victim key");
    id
}
