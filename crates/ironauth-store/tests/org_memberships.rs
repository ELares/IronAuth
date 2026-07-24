// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization membership (issue #94, PR-A), over a real database (`DATABASE_URL`).
//!
//! Pins the M10 data-model foundation at the persistence layer: a user is bound
//! into an organization through an audited membership; a duplicate add is a typed
//! already-member conflict; multi-org is native (one user in two organizations);
//! removing a membership soft-deletes it (audited) and it reads as absent; an
//! organization's lifecycle state toggles (audited); and accepting an invitation
//! that carried an org-context creates the membership in the SAME transaction as
//! the pending -> accepted flip, while an invitation with no org-context creates
//! none. Cross-tenant and cross-environment isolation is exercised in the IDOR
//! harness (tests/idor.rs).

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, InvitationCredentialType, MintedInvitationToken, NewAdminUser,
    NewInvitation, NewMembership, OrgMembershipId, OrganizationId, OrganizationState, Scope,
    ServiceId, StoreError, UserId, UserState, mint_invitation_token,
};
use sqlx::Row;

/// A valid Argon2id PHC verifier (a fixed one; hashing is exercised in the higher
/// layers, the store only persists the string).
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

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

/// Create an organization in `scope` via the control store, returning its id.
async fn create_org(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    display_name: &str,
) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), display_name, None)
        .await
        .expect("create organization");
    id
}

/// Create an ACTIVE user in `scope` via the control store, returning its id.
async fn create_active_user(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    identifier: &str,
) -> UserId {
    db.control_store()
        .scoped(scope)
        .acting(actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: Some(PASSWORD_HASH),
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create active user")
}

/// Add `user` to `org` via the control store, returning the new membership id.
async fn add_member(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> Result<OrgMembershipId, StoreError> {
    let id = OrgMembershipId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .create(
            env,
            NewMembership {
                id: &id,
                organization_id: org,
                user_id: user,
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
}

/// The audit actions recorded against `target_id` in `scope`, in order.
async fn audit_actions(db: &TestDatabase, scope: Scope, target_id: &str) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit rows");
    rows.iter().map(|r| r.get::<String, _>("action")).collect()
}

#[tokio::test]
async fn membership_add_list_remove_round_trip_and_audits() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;
    let user = create_active_user(&db, &env, scope, "member@example.test").await;

    let membership = add_member(&db, &env, scope, &org, &user)
        .await
        .expect("add member");

    // The membership reads back within scope, bound to the org and user.
    let record = control
        .management()
        .org_memberships(scope)
        .get(&membership)
        .await
        .expect("get membership");
    assert_eq!(record.id, membership);
    assert_eq!(record.organization_id, org);
    assert_eq!(record.user_id, user);
    assert_eq!(record.state, "active");

    // exists and the two list projections all see it.
    assert!(
        control
            .management()
            .org_memberships(scope)
            .exists(&org, &user)
            .await
            .expect("exists")
    );
    let by_org = control
        .management()
        .org_memberships(scope)
        .list_for_org(&org, 50, None)
        .await
        .expect("list_for_org");
    assert_eq!(by_org.len(), 1);
    assert_eq!(by_org[0].id, membership);
    let by_user = control
        .management()
        .org_memberships(scope)
        .list_for_user(&user)
        .await
        .expect("list_for_user");
    assert_eq!(by_user.len(), 1);

    // Remove is a soft delete: afterwards the membership reads as absent everywhere.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_memberships(scope)
        .remove(&env, &membership)
        .await
        .expect("remove member");
    assert!(matches!(
        control
            .management()
            .org_memberships(scope)
            .get(&membership)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        !control
            .management()
            .org_memberships(scope)
            .exists(&org, &user)
            .await
            .expect("exists after remove")
    );
    assert!(
        control
            .management()
            .org_memberships(scope)
            .list_for_org(&org, 50, None)
            .await
            .expect("list after remove")
            .is_empty()
    );

    // A repeat remove of an already removed membership is the uniform not-found.
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_memberships(scope)
            .remove(&env, &membership)
            .await,
        Err(StoreError::NotFound)
    ));

    // Both mutations audited against the membership, in order.
    assert_eq!(
        audit_actions(&db, scope, &membership.to_string()).await,
        vec![
            "organization.membership.add",
            "organization.membership.remove"
        ]
    );
}

#[tokio::test]
async fn duplicate_add_is_a_typed_already_member_conflict() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let user = create_active_user(&db, &env, scope, "dup@example.test").await;

    add_member(&db, &env, scope, &org, &user)
        .await
        .expect("first add");
    // A second add of the SAME (org, user) is refused on the UNIQUE key.
    assert!(matches!(
        add_member(&db, &env, scope, &org, &user).await,
        Err(StoreError::Conflict)
    ));
}

#[tokio::test]
async fn a_user_can_belong_to_two_organizations() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org_a = create_org(&db, &env, scope, "Alpha").await;
    let org_b = create_org(&db, &env, scope, "Beta").await;
    let user = create_active_user(&db, &env, scope, "multi@example.test").await;

    add_member(&db, &env, scope, &org_a, &user)
        .await
        .expect("add to A");
    add_member(&db, &env, scope, &org_b, &user)
        .await
        .expect("add to B");

    // The user is in BOTH organizations (multi-org).
    let by_user = control
        .management()
        .org_memberships(scope)
        .list_for_user(&user)
        .await
        .expect("list_for_user");
    assert_eq!(by_user.len(), 2, "the user belongs to two organizations");
    let orgs: Vec<OrganizationId> = by_user.iter().map(|m| m.organization_id).collect();
    assert!(orgs.contains(&org_a) && orgs.contains(&org_b));
    // Each org's roster contains exactly this one user.
    for org in [&org_a, &org_b] {
        assert_eq!(
            control
                .management()
                .org_memberships(scope)
                .list_for_org(org, 50, None)
                .await
                .expect("list_for_org")
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn organization_disable_toggles_state_and_audits() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Toggle").await;
    // A fresh organization is active.
    assert_eq!(
        control
            .management()
            .organizations(scope)
            .get(&org)
            .await
            .expect("get")
            .state,
        OrganizationState::Active
    );

    // Disable it: still readable (a disabled org is not a soft delete), but disabled.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(&env, &org, OrganizationState::Disabled)
        .await
        .expect("disable");
    assert_eq!(
        control
            .management()
            .organizations(scope)
            .get(&org)
            .await
            .expect("get after disable")
            .state,
        OrganizationState::Disabled
    );

    // Re-enable it.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(&env, &org, OrganizationState::Active)
        .await
        .expect("enable");
    assert_eq!(
        control
            .management()
            .organizations(scope)
            .get(&org)
            .await
            .expect("get after enable")
            .state,
        OrganizationState::Active
    );

    // create + two state changes audited against the org.
    assert_eq!(
        audit_actions(&db, scope, &org.to_string()).await,
        vec![
            "organization.create",
            "organization.state_change",
            "organization.state_change"
        ]
    );
}

#[tokio::test]
async fn accepting_an_invitation_with_org_context_creates_a_membership() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Onboarder").await;

    // Create a pending_verification user and an invitation carrying the org-context.
    let created = now_micros(&env);
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(&env, &scope);
    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: None,
                identifier: "invitee@example.test",
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            created,
            None,
        )
        .await
        .expect("create pending user");
    let org_context = org.to_string();
    db.control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create(
            &env,
            NewInvitation {
                id: &id,
                user_id: &user_id,
                target_identifier: "invitee@example.test",
                token_digest: &digest,
                credential_type: InvitationCredentialType::Password,
                org_context: Some(&org_context),
                expires_at_unix_micros: created.saturating_add(3_600_000_000),
            },
            created,
            None,
        )
        .await
        .expect("create org invitation");

    // Accept on the DATA plane (as the invitee side does in ironauth-oidc).
    let accepted = db
        .store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .accept(&env, &token, Some(PASSWORD_HASH), now_micros(&env))
        .await
        .expect("accept");
    assert_eq!(accepted.organization_id, Some(org));

    // The membership now exists, created in the accept transaction.
    assert!(
        db.control_store()
            .management()
            .org_memberships(scope)
            .exists(&org, &user_id)
            .await
            .expect("exists")
    );
    // The invitation id carries its create and its redeem audit rows (the membership
    // add is audited against the NEW membership, not the invitation).
    assert_eq!(
        audit_actions(&db, scope, &id.to_string()).await,
        vec!["invitation.create", "invitation.redeem"]
    );
    // The accept path recorded a SECOND audit row for the membership add.
    let adds = sqlx::query(
        "SELECT COUNT(*) AS n FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'organization.membership.add'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count add audits")
    .get::<i64, _>("n");
    assert_eq!(
        adds, 1,
        "the accept wrote exactly one membership-add audit row"
    );
}

#[tokio::test]
async fn accepting_an_invitation_without_org_context_creates_no_membership() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let created = now_micros(&env);
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(&env, &scope);
    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: None,
                identifier: "plain@example.test",
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            created,
            None,
        )
        .await
        .expect("create pending user");
    db.control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create(
            &env,
            NewInvitation {
                id: &id,
                user_id: &user_id,
                target_identifier: "plain@example.test",
                token_digest: &digest,
                credential_type: InvitationCredentialType::Password,
                org_context: None,
                expires_at_unix_micros: created.saturating_add(3_600_000_000),
            },
            created,
            None,
        )
        .await
        .expect("create invitation");

    let accepted = db
        .store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .accept(&env, &token, Some(PASSWORD_HASH), now_micros(&env))
        .await
        .expect("accept");
    assert_eq!(accepted.organization_id, None);

    let by_user = db
        .control_store()
        .management()
        .org_memberships(scope)
        .list_for_user(&user_id)
        .await
        .expect("list_for_user");
    assert!(by_user.is_empty(), "no membership without an org-context");
}

#[tokio::test]
async fn invitation_create_rejects_an_out_of_scope_org_context() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;

    // An org id minted in ANOTHER scope is not a valid org-context here.
    let foreign_org = OrganizationId::generate(&env, &other).to_string();
    let created = now_micros(&env);
    let MintedInvitationToken { digest, id, .. } = mint_invitation_token(&env, &scope);
    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: None,
                identifier: "reject@example.test",
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            created,
            None,
        )
        .await
        .expect("create pending user");
    let result = db
        .control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create(
            &env,
            NewInvitation {
                id: &id,
                user_id: &user_id,
                target_identifier: "reject@example.test",
                token_digest: &digest,
                credential_type: InvitationCredentialType::Password,
                org_context: Some(&foreign_org),
                expires_at_unix_micros: created.saturating_add(3_600_000_000),
            },
            created,
            None,
        )
        .await;
    assert!(matches!(result, Err(StoreError::InvalidOrgContext)));
}
