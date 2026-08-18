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

use std::collections::BTreeMap;
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, InvitationCredentialType, MintedInvitationToken, NewAdminUser,
    NewInvitation, NewMembership, OrgMembershipId, OrgMembershipRecord, OrganizationId,
    OrganizationState, ResolvedIdempotencyWrite, Scope, ServiceId, StoreError, UserId, UserState,
    mint_invitation_token,
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
                traits: None,
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
        // The create returns the RESOLVED row (issues #395, #435); these helpers only
        // want its id.
        .map(|record| record.id)
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
        .set_state(&env, &org, OrganizationState::Disabled, None)
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
        .set_state(&env, &org, OrganizationState::Active, None)
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
                traits: None,
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
                traits: None,
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
                traits: None,
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

/// Soft-delete a membership via the control store.
async fn remove_member(db: &TestDatabase, env: &Env, scope: Scope, membership: &OrgMembershipId) {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .remove(env, membership)
        .await
        .expect("remove member");
}

/// Provision a pending user and an org invitation carrying `org` as its org-context,
/// returning the one-time token and the pending user id.
async fn create_org_invitation(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    identifier: &str,
) -> (String, UserId) {
    let created = now_micros(env);
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(env, &scope);
    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            created,
            None,
        )
        .await
        .expect("create pending user");
    let org_context = org.to_string();
    db.control_store()
        .scoped(scope)
        .acting(actor(env), CorrelationId::generate(env))
        .invitations()
        .create(
            env,
            NewInvitation {
                id: &id,
                user_id: &user_id,
                target_identifier: identifier,
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
    (token, user_id)
}

/// The count of `organization.membership.add` audit rows in `scope`.
async fn membership_add_count(db: &TestDatabase, scope: Scope) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 \
         AND action = 'organization.membership.add'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count add audits")
    .get::<i64, _>("n")
}

#[tokio::test]
async fn admin_remove_then_readd_revives_the_membership() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Revive").await;
    let user = create_active_user(&db, &env, scope, "revive@example.test").await;

    // Add, then remove: the (org, user) key is now held only by a soft-deleted row.
    let first = add_member(&db, &env, scope, &org, &user)
        .await
        .expect("first add");
    remove_member(&db, &env, scope, &first).await;
    assert!(
        !control
            .management()
            .org_memberships(scope)
            .exists(&org, &user)
            .await
            .expect("exists after remove")
    );

    // Re-add: this REVIVES the dead row (not a 409), reusing its id, and a live
    // membership exists again.
    let second = add_member(&db, &env, scope, &org, &user)
        .await
        .expect("re-add revives, not conflicts");
    assert_eq!(
        second, first,
        "the revived membership reuses the original id"
    );
    assert!(
        control
            .management()
            .org_memberships(scope)
            .exists(&org, &user)
            .await
            .expect("exists after re-add")
    );
    let live = control
        .management()
        .org_memberships(scope)
        .get(&second)
        .await
        .expect("the revived membership is live");
    assert_eq!(live.state, "active");

    // A SECOND add while it is live is still the typed already-member conflict.
    assert!(matches!(
        add_member(&db, &env, scope, &org, &user).await,
        Err(StoreError::Conflict)
    ));

    // add, remove, add(revive) all audited against the one membership id.
    assert_eq!(
        audit_actions(&db, scope, &first.to_string()).await,
        vec![
            "organization.membership.add",
            "organization.membership.remove",
            "organization.membership.add"
        ]
    );
}

#[tokio::test]
async fn accept_revives_a_previously_removed_membership() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Onboarder").await;
    let (token, user_id) =
        create_org_invitation(&db, &env, scope, &org, "revive@example.test").await;

    // Before the accept, add then remove a membership for this (org, user), so a
    // soft-deleted row already occupies the key the accept will revive.
    let membership = add_member(&db, &env, scope, &org, &user_id)
        .await
        .expect("pre-add");
    remove_member(&db, &env, scope, &membership).await;
    let adds_before = membership_add_count(&db, scope).await;

    // Accept: the org-context membership is REVIVED (not a fresh insert), so a live
    // membership exists again and AcceptedInvitation.organization_id is truthful.
    let accepted = db
        .store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .accept(&env, &token, Some(PASSWORD_HASH), now_micros(&env))
        .await
        .expect("accept");
    assert_eq!(accepted.organization_id, Some(org));
    assert!(
        db.control_store()
            .management()
            .org_memberships(scope)
            .exists(&org, &user_id)
            .await
            .expect("exists")
    );
    // The revive wrote exactly one NEW membership-add audit row, against the revived id.
    assert_eq!(membership_add_count(&db, scope).await, adds_before + 1);
    assert!(
        audit_actions(&db, scope, &membership.to_string())
            .await
            .iter()
            .filter(|a| *a == "organization.membership.add")
            .count()
            == 2,
        "the revived membership carries its original add plus the accept revive add"
    );
}

#[tokio::test]
async fn accept_when_already_a_live_member_writes_no_second_add_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Onboarder").await;
    let (token, user_id) =
        create_org_invitation(&db, &env, scope, &org, "already@example.test").await;

    // The user is ALREADY a live member before the accept.
    add_member(&db, &env, scope, &org, &user_id)
        .await
        .expect("pre-add live");
    let adds_before = membership_add_count(&db, scope).await;

    let accepted = db
        .store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .accept(&env, &token, Some(PASSWORD_HASH), now_micros(&env))
        .await
        .expect("accept");
    // A live membership still exists (organization_id truthful), but the accept was a
    // no-op on the membership: no SECOND membership-add audit row.
    assert_eq!(accepted.organization_id, Some(org));
    assert!(
        db.control_store()
            .management()
            .org_memberships(scope)
            .exists(&org, &user_id)
            .await
            .expect("exists")
    );
    assert_eq!(
        membership_add_count(&db, scope).await,
        adds_before,
        "an accept for an already-live member writes no second membership-add audit"
    );
}

/// A body renderer that cannot succeed: a map with a non-string key is not
/// representable as JSON, so `serde_json` refuses it. (A float NaN would NOT do: it
/// serializes to `null`.) Stands in for any future response type whose serialization
/// can fail.
fn unrenderable_body(_resolved: &OrgMembershipRecord) -> Result<String, serde_json::Error> {
    serde_json::to_string(&BTreeMap::from([((1_u8, 2_u8), 3_u8)]))
}

/// Every membership row in `scope`, INCLUDING soft-deleted ones (which the repository
/// reads deliberately cannot see), so a rollback check cannot be fooled by a row that
/// merely reads as absent.
async fn membership_row_count(db: &TestDatabase, scope: Scope) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM org_memberships \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count membership rows")
    .get::<i64, _>("n")
}

/// The response body stored under an Idempotency-Key, or `None` when no record was
/// committed for it.
async fn stored_idempotent_body(
    db: &TestDatabase,
    credential_ref: &str,
    key: &str,
) -> Option<String> {
    sqlx::query(
        "SELECT response_body FROM idempotency_keys \
         WHERE credential_ref = $1 AND idempotency_key = $2",
    )
    .bind(credential_ref)
    .bind(key)
    .fetch_optional(db.owner_pool())
    .await
    .expect("read stored response")
    .map(|row| row.get::<String, _>("response_body"))
}

/// Add `user` to `org` under the fixed test Idempotency-Key, storing whatever
/// `render` makes of the row the write resolves.
async fn add_member_storing(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    membership: (&OrgMembershipId, &OrganizationId, &UserId),
    render: &(dyn Fn(&OrgMembershipRecord) -> Result<String, serde_json::Error> + Sync),
) -> Result<OrgMembershipRecord, StoreError> {
    let (id, org, user) = membership;
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .create(
            env,
            NewMembership {
                id,
                organization_id: org,
                user_id: user,
                metadata: None,
            },
            now_micros(env),
            Some(ResolvedIdempotencyWrite {
                credential_ref: "cred-rollback",
                key: "k-rollback",
                request_fingerprint: "fp-rollback",
                response_status: 201,
                response_body: render,
            }),
        )
        .await
}

/// The membership add and its Idempotency-Key record commit TOGETHER or not at all
/// (issues #395, #435). The stored response is rendered from the resolved row inside
/// the write's own transaction, so a body that cannot be rendered must abort the
/// whole thing: no membership row, no audit row (both written BEFORE the render), and
/// above all no idempotency record, because a record that outlived its write would let
/// a replay serve a response describing a row that does not exist.
///
/// The complement matters just as much: an aborted attempt must not POISON the key.
/// A retry with the SAME Idempotency-Key has to be free to execute, which it can only
/// be if the failed attempt left nothing behind.
#[tokio::test]
async fn a_body_that_cannot_be_rendered_rolls_the_whole_add_back() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Rollback").await;
    let user = create_active_user(&db, &env, scope, "rollback@example.test").await;
    let adds_before = membership_add_count(&db, scope).await;

    let id = OrgMembershipId::generate(&env, &scope);
    let failed = add_member_storing(&db, &env, scope, (&id, &org, &user), &unrenderable_body).await;
    assert!(
        matches!(failed, Err(StoreError::Database(_))),
        "an unrenderable body is a persistence failure, not a silent success"
    );

    // Nothing landed: no membership row (not even a soft-deleted one), and no audit
    // row, even though both were written BEFORE the render in the same transaction.
    assert!(
        !db.control_store()
            .management()
            .org_memberships(scope)
            .exists(&org, &user)
            .await
            .expect("exists"),
        "the membership row rolled back with the transaction"
    );
    assert_eq!(membership_row_count(&db, scope).await, 0);
    assert_eq!(
        membership_add_count(&db, scope).await,
        adds_before,
        "the audit row written before the render rolled back too"
    );

    // And no idempotency record: a committed one would make every replay of this key
    // serve a response for a membership that was never created.
    assert_eq!(
        stored_idempotent_body(&db, "cred-rollback", "k-rollback").await,
        None,
        "no idempotency record outlived its aborted write"
    );

    // The key is not poisoned: the same one is free to carry a successful retry, which
    // now stores the body it really rendered.
    let retry_id = OrgMembershipId::generate(&env, &scope);
    let created = add_member_storing(&db, &env, scope, (&retry_id, &org, &user), &|resolved| {
        Ok(resolved.id.to_string())
    })
    .await
    .expect("the retry executes: the aborted attempt reserved nothing");
    assert_eq!(created.id, retry_id);
    assert_eq!(
        stored_idempotent_body(&db, "cred-rollback", "k-rollback").await,
        Some(retry_id.to_string()),
        "the stored response describes the row the retry resolved"
    );
}

/// Every webhook-event envelope queued in `scope`.
async fn queued_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events")
        .into_iter()
        .map(|message| message.payload)
        .collect()
}

/// Adding a member emits `organization.member_added`, naming BOTH ends of the join.
///
/// A membership is a join, and a consumer cannot act on it without both ends: this is the
/// event an integrator PROVISIONS on, and it needs to know whose access, to what.
#[tokio::test]
async fn adding_a_member_emits_an_event_naming_both_ends() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Globex").await;
    let user = create_active_user(&db, &env, scope, "member@example.test").await;
    let membership = OrgMembershipId::generate(&env, &scope);
    let subject = membership.to_string();

    let added = ironauth_store::event_catalog::envelope(
        "evt_member_added",
        "organization.member_added",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "membership_id": subject,
            "organization_id": org.to_string(),
            "user_id": user.to_string(),
        }),
    )
    .expect("organization.member_added is registered");

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_memberships(scope)
        .create_with_event(
            &env,
            NewMembership {
                id: &membership,
                organization_id: &org,
                user_id: &user,
                metadata: None,
            },
            now_micros(&env),
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_member_added",
                subject: &subject,
                envelope: &added,
            }),
        )
        .await
        .expect("add member with event");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the add enqueues exactly one event");
    assert_eq!(events[0]["type"], "organization.member_added");
    assert_eq!(events[0]["payload"]["organization_id"], org.to_string());
    assert_eq!(events[0]["payload"]["user_id"], user.to_string());
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// Removing a member is announced as a REMOVAL, not an addition.
///
/// This is the event an integrator DEPROVISIONS on, so collapsing the pair into one type
/// would make the most consequential distinction in it a field to branch on. The seed uses the
/// un-suffixed `add_member`, which emits nothing, so the only event queued is the removal's.
#[tokio::test]
async fn removing_a_member_is_announced_as_a_removal_not_an_addition() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Globex").await;
    let user = create_active_user(&db, &env, scope, "member@example.test").await;
    let membership = add_member(&db, &env, scope, &org, &user)
        .await
        .expect("seed membership");
    let subject = membership.to_string();

    let removed = ironauth_store::event_catalog::envelope(
        "evt_member_removed",
        "organization.member_removed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({
            "membership_id": subject,
            "organization_id": org.to_string(),
            "user_id": user.to_string(),
        }),
    )
    .expect("organization.member_removed is registered");

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_memberships(scope)
        .remove_with_event(
            &env,
            &membership,
            Some(&ironauth_store::DomainEvent {
                id: "evt_member_removed",
                subject: &subject,
                envelope: &removed,
            }),
        )
        .await
        .expect("remove member with event");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the removal enqueues exactly one event");
    assert_eq!(
        events[0]["type"], "organization.member_removed",
        "a removal must NOT be announced as an addition"
    );
    assert_eq!(events[0]["payload"]["user_id"], user.to_string());
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}
