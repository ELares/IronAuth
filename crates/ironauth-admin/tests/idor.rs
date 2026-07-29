// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management-plane IDOR probes, registered with the #6 harness and run
//! against a real database. A management key resolved by id under one scope must
//! never reach a key minted in another tenant or environment.

use ironauth_env::Env;
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, AuthPolicy, CorrelationId, ManagementKeyId, NewAdminUser, NewMembership, NewOrgGroup,
    NewOrgGroupMember, NewOrgGroupRole, NewOrgMembershipRole, NewOrgRole, NewOrgRolePermission,
    NewPermission, NewResourceServer, ORG_POLICY_MAX_SESSION_TTL_SECS, OrgGroupId,
    OrgGroupMemberId, OrgGroupRoleId, OrgMembershipId, OrgMembershipRoleId, OrgRoleId,
    OrgRolePermissionId, OrganizationId, PermissionId, ResourceServerId, Scope, ServiceId,
    StoreError, TokenFormat, UserState,
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

    // Per-organization authentication policies (issue #95): plant a victim policy on
    // each foreign organization so the REMOVE probe has a real target. Without one it
    // would be denied simply because nothing was there, passing for the wrong reason.
    // The document tightens something real (an MFA requirement), so a leak would be a
    // cross-tenant WEAKENING rather than a no-op.
    let victim_policy_document = AuthPolicy {
        mfa_required: Some(true),
        ..AuthPolicy::default()
    };
    for (scope, org) in [(scope_b, &victim_org_b), (scope_a2, &victim_org_a2)] {
        control
            .management()
            .acting(
                ActorRef::service(ServiceId::generate(&env)),
                CorrelationId::generate(&env),
            )
            .org_auth_policies(scope)
            .set(
                &env,
                org,
                &victim_policy_document,
                ORG_POLICY_MAX_SESSION_TTL_SECS,
            )
            .await
            .expect("plant the victim policy");
    }

    // The permission vocabulary (issue #98): plant a victim permission in each
    // foreign scope so the vocabulary probes have a real cross-scope target rather
    // than only an absent id. `permissions.delete` is a MUTATING probe, so the target
    // has to be a live row that a leak could actually destroy.
    let victim_permission_b = plant_permission(control, &env, scope_b).await;
    let victim_permission_a2 = plant_permission(control, &env, scope_a2).await;

    // The role-to-permission MAPPING (issue #98): plant a victim in each foreign
    // scope, attaching that scope's victim permission to that scope's victim role.
    // `org_role_permissions.unassign` is a MUTATING probe over the row that decides
    // which capability names a token carries, so a leak here silently WITHDRAWS a
    // capability in a foreign environment rather than merely reading one.
    let victim_mapping_b = plant_role_permission(
        control,
        &env,
        scope_b,
        &victim_org_b,
        &victim_role_b,
        &victim_permission_b,
    )
    .await;
    let victim_mapping_a2 = plant_role_permission(
        control,
        &env,
        scope_a2,
        &victim_org_a2,
        &victim_role_a2,
        &victim_permission_a2,
    )
    .await;

    // The RESOURCE-SERVER registry (issue #98): plant a victim in each foreign scope,
    // registered OPTED OUT. `resource_servers.set_permission_claims` is a MUTATING
    // probe that flips the opt-in ON, so a leak leaves an observable `true` on a row
    // planted `false`, and the survival assertion below reads the flag rather than
    // only the row's existence. Reading only "is it still there" would miss the
    // entire mutation, because this table has no soft delete and the leaked write
    // changes one boolean in place.
    let victim_server_b = plant_resource_server(control, &env, scope_b).await;
    let victim_server_a2 = plant_resource_server(control, &env, scope_a2).await;

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
            "org_auth_policies.set",
            "org_auth_policies.remove",
            "permissions.get",
            "permissions.delete",
            "org_role_permissions.unassign",
            "resource_servers.get",
            "resource_servers.set_permission_claims",
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
        victim_permission_b.to_string(),
        victim_permission_a2.to_string(),
        victim_mapping_b.to_string(),
        victim_mapping_a2.to_string(),
        victim_server_b.to_string(),
        victim_server_a2.to_string(),
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

    // The victim PERMISSIONS must have SURVIVED `permissions.delete`, and must still
    // be readable in their own scope. Both halves matter and neither implies the
    // other. A `permissions.delete` that leaked would soft-delete the row, and every
    // read filters `deleted_at IS NULL`, so a destroyed victim reads as absent here.
    // And a probe that reported Denied because the victim was never planted would
    // pass for the wrong reason and would keep passing if the fence were removed,
    // which is the failure mode #97's review actually found.
    for (scope, permission) in [
        (scope_b, &victim_permission_b),
        (scope_a2, &victim_permission_a2),
    ] {
        let record = control
            .management()
            .permissions(scope)
            .get(permission)
            .await
            .expect("the victim permission must survive the probes in its OWN scope");
        assert_eq!(record.slug, "victim.permission");
        // The label is untouched too: nothing planted a relabel, and asserting it
        // keeps this check honest if a future probe mutates rather than deletes.
        assert_eq!(record.display_name, "victim permission");
    }

    // The victim MAPPINGS must have SURVIVED `org_role_permissions.unassign`, read
    // back through the PAIR address rather than by id. The pair address is the
    // stronger read: it proves the row is still live AND still joins the same role to
    // the same permission in the same organization, which is exactly the grant a leak
    // would have withdrawn. A by-id read would prove only that the row exists.
    for (scope, org, role, permission) in [
        (scope_b, &victim_org_b, &victim_role_b, &victim_permission_b),
        (
            scope_a2,
            &victim_org_a2,
            &victim_role_a2,
            &victim_permission_a2,
        ),
    ] {
        let record = control
            .management()
            .org_role_permissions(scope)
            .get_assignment(org, role, permission)
            .await
            .expect("the victim mapping must survive the unassign probe in its OWN scope");
        assert_eq!(&record.organization_id, org);
        assert_eq!(&record.role_id, role);
        assert_eq!(&record.permission_id, permission);
    }

    // The victim RESOURCE SERVERS must still read `permission_claims_enabled = false`.
    // This assertion, and not a liveness read, is what makes the mutating probe
    // non-vacuous: `resource_servers` has no soft delete, so a leaked
    // `set_permission_claims` leaves the row perfectly readable while having opted a
    // foreign environment's audience INTO carrying permission claims, which is a
    // widening of what that environment's tokens will assert.
    for (scope, server) in [(scope_b, &victim_server_b), (scope_a2, &victim_server_a2)] {
        let record = control
            .management()
            .resource_servers(scope)
            .get(server)
            .await
            .expect("the victim resource server must survive the probes in its OWN scope");
        assert_eq!(record.audience, "https://victim.example.test/api");
        assert!(
            !record.permission_claims_enabled,
            "the victim resource server must still be opted OUT: a cross-scope \
             set_permission_claims that landed would read `true` here"
        );
    }

    // The victim POLICIES must survive both probes AND still carry their own
    // document. A liveness-only assertion would miss the sharper leak: a cross-scope
    // `set` that landed would leave the policy readable while having REPLACED the
    // foreign organization's MFA requirement with an empty document, which is
    // precisely the weakening the probe exists to catch.
    for (scope, org) in [(scope_b, &victim_org_b), (scope_a2, &victim_org_a2)] {
        let record = control
            .management()
            .org_auth_policies(scope)
            .get_for_org(org)
            .await
            .expect("the victim policy must survive the set and remove probes");
        assert_eq!(
            record.document, victim_policy_document,
            "the victim policy's document must be untouched by the set probe"
        );
    }
}

/// Plant a live role-to-permission mapping in `scope` via the control store,
/// returning its id (issue #98).
///
/// Through the AUDITED WRITE repository, so the victim is a row a real operator
/// could have created: it passes the same live-role-in-organization and
/// live-permission-in-scope resolutions a production attach passes, which also means
/// a mis-seeded fixture fails loudly here rather than producing a victim the probe
/// then cannot destroy for the wrong reason.
async fn plant_role_permission(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    role: &OrgRoleId,
    permission: &PermissionId,
) -> OrgRolePermissionId {
    let id = OrgRolePermissionId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .org_role_permissions(scope)
        .assign(
            env,
            NewOrgRolePermission {
                id: &id,
                organization_id: org,
                role_id: role,
                permission_id: permission,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim role-permission mapping");
    id
}

/// Plant a registered resource server in `scope` via the control store, returning
/// its id (issue #98).
///
/// Registered OPTED OUT, which is the only state a registration can produce
/// ([`NewResourceServer`] has no opt-in field by design), so the mutating probe has
/// a real `false` to flip and the survival assertion has something to observe.
async fn plant_resource_server(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
) -> ResourceServerId {
    let id = ResourceServerId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience: "https://victim.example.test/api",
                // `at_jwt`, so the opt-in this probe tries to flip is one the
                // management API would genuinely accept in its own scope. An opaque
                // victim would be refused by the edge for a reason unrelated to
                // scope, which is not what this probe measures.
                token_format: TokenFormat::AtJwt,
                access_token_ttl_secs: None,
            },
        )
        .await
        .expect("plant victim resource server");
    id
}

/// Plant a live permission in `scope` via the control store, returning its id
/// (issue #98).
///
/// Through the AUDITED WRITE repository rather than direct SQL, now that one exists:
/// the victim is then a row a real operator could have created, under the same
/// grants, the same isolation policy, and with the same audit row, so a probe that
/// destroyed it would be destroying something production-shaped.
async fn plant_permission(
    control: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
) -> PermissionId {
    let id = PermissionId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .permissions(scope)
        .create(
            env,
            NewPermission {
                id: &id,
                slug: "victim.permission",
                display_name: "victim permission",
                metadata: None,
            },
            1_000_000,
            None,
        )
        .await
        .expect("plant victim permission");
    id
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
