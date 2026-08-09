// SPDX-License-Identifier: MIT OR Apache-2.0

//! The permission suite, run against BOTH principal types (issue #99, criterion 3).
//!
//! The criterion is not "a service account can resolve permissions", which
//! `membership_principal_arc.rs` already shows. It is that authorization makes NO distinction
//! between a user and a service account, and the only honest way to state that is to run one
//! body of scenarios twice and let the difference be the principal alone.
//!
//! Every scenario below is written once, as a function taking a [`Kind`], and the `parity!`
//! macro instantiates it as two tests. A scenario that passes for a user and fails for a
//! service account names the kind in the failing test's name, which is what a suite
//! parameterized by a loop inside one test would not do.
//!
//! The two kinds differ in exactly two places, both inside [`Principal`]: how the principal is
//! minted, and which of the two `effective_permissions` entries reads it. Everything between
//! those points, the organization, the roles, the groups, the depth budget and the
//! soft-deletes, is shared code operating on a membership id. That is not an accident of the
//! test; it is the shape of `EFFECTIVE_CLOSURE_CTE`, whose closure arm keys off a membership
//! and has never known what the membership binds.
//!
//! A service-account membership is inserted through the engine because nothing writes one yet.
//! When that write path lands, [`Principal::bind`] is the single place this file changes.

use std::collections::BTreeSet;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewMembership, NewOrgGroup, NewOrgGroupMember, NewOrgGroupRole,
    NewOrgMembershipRole, NewOrgRole, NewOrgRolePermission, NewPermission, OrgGroupId,
    OrgGroupMemberId, OrgGroupRoleId, OrgMembershipId, OrgMembershipRoleId, OrgRoleId,
    OrgRolePermissionId, OrganizationId, PermissionId, Scope, ServiceAccountId, UserId,
};

const AT: i64 = 1_000;
const DEPTH: u32 = 8;

/// Which kind of principal a scenario is running against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    User,
    ServiceAccount,
}

/// Instantiate one scenario body as one test per principal kind.
///
/// Two named tests rather than a loop inside one, so a failure says which principal broke
/// parity without anyone reading the assertion message.
macro_rules! parity {
    ($body:ident, $user_test:ident, $machine_test:ident) => {
        #[tokio::test]
        async fn $user_test() {
            $body(Kind::User).await;
        }

        #[tokio::test]
        async fn $machine_test() {
            $body(Kind::ServiceAccount).await;
        }
    };
}

/// A seeded principal of either kind, and the only place the two differ.
enum Principal {
    User(UserId),
    ServiceAccount(ServiceAccountId),
}

impl Principal {
    /// Mint a principal of `kind` in `scope`.
    async fn seed(db: &TestDatabase, env: &Env, scope: Scope, kind: Kind) -> Self {
        match kind {
            Kind::User => {
                let id = UserId::generate(env, &scope);
                db.store()
                    .scoped(scope)
                    .acting(db.test_actor(env), CorrelationId::generate(env))
                    .users()
                    .register_passwordless(env, &id, "parity@example.test")
                    .await
                    .expect("register the user");
                Self::User(id)
            }
            Kind::ServiceAccount => {
                let client = db
                    .store()
                    .scoped(scope)
                    .acting(db.test_actor(env), CorrelationId::generate(env))
                    .clients()
                    .create(env, "a parity client")
                    .await
                    .expect("create the client");
                let id = db
                    .store()
                    .scoped(scope)
                    .acting(db.test_actor(env), CorrelationId::generate(env))
                    .service_accounts()
                    .ensure(env, &client)
                    .await
                    .expect("mint the principal");
                Self::ServiceAccount(id)
            }
        }
    }

    /// Bind the principal into `org` and return the membership id every later step keys off.
    ///
    /// The user arm goes through the repository. The service-account arm inserts through the
    /// engine, because no write path exists for one yet; when it lands this arm is the single
    /// place that changes, and nothing below it moves.
    async fn bind(
        &self,
        db: &TestDatabase,
        env: &Env,
        scope: Scope,
        org: &OrganizationId,
    ) -> OrgMembershipId {
        let id = OrgMembershipId::generate(env, &scope);
        match self {
            Self::User(user) => {
                db.control_store()
                    .scoped(scope)
                    .acting(db.test_actor(env), CorrelationId::generate(env))
                    .org_memberships()
                    .create(
                        env,
                        NewMembership {
                            id: &id,
                            organization_id: org,
                            user_id: user,
                            metadata: None,
                        },
                        AT,
                        None,
                    )
                    .await
                    .expect("create the user membership");
            }
            Self::ServiceAccount(principal) => {
                sqlx::query(
                    "INSERT INTO org_memberships \
                     (id, tenant_id, environment_id, organization_id, service_account_id, \
                      owner_kind) \
                     VALUES ($1, $2, $3, $4, $5, 'service_account')",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(org.to_string())
                .bind(principal.to_string())
                .execute(db.owner_pool())
                .await
                .expect("insert the service-account membership");
            }
        }
        id
    }

    /// The effective permission slugs for this principal in `org`.
    async fn permissions(
        &self,
        db: &TestDatabase,
        scope: Scope,
        org: &OrganizationId,
        depth: u32,
    ) -> BTreeSet<String> {
        let groups = db.control_store().management().org_groups(scope);
        match self {
            Self::User(user) => groups.effective_permissions(org, user, depth).await,
            Self::ServiceAccount(principal) => {
                groups
                    .effective_permissions_for_service_account(org, principal, depth)
                    .await
            }
        }
        .expect("resolve effective permissions")
    }
}

/// Everything a scenario needs, seeded identically for either kind.
struct Fixture {
    db: TestDatabase,
    env: Env,
    scope: Scope,
    org: OrganizationId,
    principal: Principal,
    membership: OrgMembershipId,
}

impl Fixture {
    async fn start(kind: Kind) -> Self {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let scope = db.seed_scope(&env).await;
        let org = OrganizationId::generate(&env, &scope);
        db.control_store()
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .organizations(scope)
            .create(&env, &org, AT, "acme", None)
            .await
            .expect("create the organization");
        let principal = Principal::seed(&db, &env, scope, kind).await;
        let membership = principal.bind(&db, &env, scope, &org).await;
        Self {
            db,
            env,
            scope,
            org,
            principal,
            membership,
        }
    }

    async fn permissions(&self) -> BTreeSet<String> {
        self.permissions_to_depth(DEPTH).await
    }

    async fn permissions_to_depth(&self, depth: u32) -> BTreeSet<String> {
        self.principal
            .permissions(&self.db, self.scope, &self.org, depth)
            .await
    }

    /// A role granting exactly `slugs`.
    async fn role(&self, slug: &str, slugs: &[&str]) -> OrgRoleId {
        let role = OrgRoleId::generate(&self.env, &self.scope);
        self.acting()
            .org_roles(self.scope)
            .create(
                &self.env,
                NewOrgRole {
                    id: &role,
                    organization_id: &self.org,
                    slug,
                    display_name: "Role",
                    metadata: None,
                },
                AT,
                None,
            )
            .await
            .expect("create the role");
        for granted in slugs {
            let permission = PermissionId::generate(&self.env, &self.scope);
            self.acting()
                .permissions(self.scope)
                .create(
                    &self.env,
                    NewPermission {
                        id: &permission,
                        slug: granted,
                        display_name: "Capability",
                        metadata: None,
                    },
                    AT,
                    None,
                )
                .await
                .expect("define the permission");
            self.acting()
                .org_role_permissions(self.scope)
                .assign(
                    &self.env,
                    NewOrgRolePermission {
                        id: &OrgRolePermissionId::generate(&self.env, &self.scope),
                        organization_id: &self.org,
                        role_id: &role,
                        permission_id: &permission,
                    },
                    AT,
                    None,
                )
                .await
                .expect("map the permission onto the role");
        }
        role
    }

    /// Grant `role` to the membership directly.
    async fn grant(&self, role: &OrgRoleId) {
        self.acting()
            .org_membership_roles(self.scope)
            .assign(
                &self.env,
                NewOrgMembershipRole {
                    id: &OrgMembershipRoleId::generate(&self.env, &self.scope),
                    organization_id: &self.org,
                    membership_id: &self.membership,
                    role_id: role,
                },
                AT,
                None,
            )
            .await
            .expect("grant the role directly");
    }

    /// A group, optionally under `parent`.
    async fn group(&self, slug: &str, parent: Option<&OrgGroupId>) -> OrgGroupId {
        let id = OrgGroupId::generate(&self.env, &self.scope);
        self.acting()
            .org_groups(self.scope)
            .create(
                &self.env,
                NewOrgGroup {
                    id: &id,
                    organization_id: &self.org,
                    parent_id: parent,
                    slug,
                    display_name: "Group",
                    metadata: None,
                },
                AT,
                ironauth_store::ORG_GROUP_MAX_DEPTH_CEILING,
                None,
            )
            .await
            .expect("create the group");
        id
    }

    /// Put the membership in `group`.
    async fn join(&self, group: &OrgGroupId) {
        self.acting()
            .org_group_members(self.scope)
            .add(
                &self.env,
                NewOrgGroupMember {
                    id: &OrgGroupMemberId::generate(&self.env, &self.scope),
                    organization_id: &self.org,
                    group_id: group,
                    membership_id: &self.membership,
                },
                AT,
                None,
            )
            .await
            .expect("add the membership to the group");
    }

    /// Attach `role` to `group`.
    async fn group_role(&self, group: &OrgGroupId, role: &OrgRoleId) {
        self.acting()
            .org_group_roles(self.scope)
            .assign(
                &self.env,
                NewOrgGroupRole {
                    id: &OrgGroupRoleId::generate(&self.env, &self.scope),
                    organization_id: &self.org,
                    group_id: group,
                    role_id: role,
                },
                AT,
                None,
            )
            .await
            .expect("attach the role to the group");
    }

    fn acting(&self) -> ironauth_store::ActingManagementStore<'_> {
        self.db.control_store().management().acting(
            self.db.test_actor(&self.env),
            CorrelationId::generate(&self.env),
        )
    }
}

fn set(slugs: &[&str]) -> BTreeSet<String> {
    slugs.iter().map(|slug| (*slug).to_string()).collect()
}

// A principal with no roles holds nothing. The floor: every assertion below is a difference
// from this, so a scenario cannot pass because resolution returns everything.
async fn an_unroled_principal_holds_nothing(kind: Kind) {
    let fixture = Fixture::start(kind).await;
    assert_eq!(fixture.permissions().await, BTreeSet::new());
}
parity!(
    an_unroled_principal_holds_nothing,
    an_unroled_user_holds_nothing,
    an_unroled_service_account_holds_nothing
);

// A directly granted role's permissions resolve, and the result is the UNION over every role
// held rather than the first one found.
async fn direct_roles_union(kind: Kind) {
    let fixture = Fixture::start(kind).await;
    let billing = fixture.role("billing", &["billing.invoice.read"]).await;
    let deploys = fixture
        .role("deploys", &["deploy.write", "deploy.read"])
        .await;
    fixture.grant(&billing).await;
    assert_eq!(
        fixture.permissions().await,
        set(&["billing.invoice.read"]),
        "one role resolves to exactly its own permissions"
    );
    fixture.grant(&deploys).await;
    assert_eq!(
        fixture.permissions().await,
        set(&["billing.invoice.read", "deploy.read", "deploy.write"]),
        "a second role adds to the set rather than replacing it"
    );
}
parity!(
    direct_roles_union,
    direct_roles_union_for_a_user,
    direct_roles_union_for_a_service_account
);

// A role attached to a group the principal belongs to resolves, and so does one attached to
// that group's ANCESTOR: the closure walks upward from the group the membership joined.
async fn group_roles_inherit_up_the_closure(kind: Kind) {
    let fixture = Fixture::start(kind).await;
    let platform = fixture.group("platform", None).await;
    let payments = fixture.group("payments", Some(&platform)).await;
    let on_leaf = fixture.role("leaf", &["deploy.write"]).await;
    let on_ancestor = fixture.role("ancestor", &["audit.read"]).await;
    fixture.group_role(&payments, &on_leaf).await;
    fixture.group_role(&platform, &on_ancestor).await;

    assert_eq!(
        fixture.permissions().await,
        BTreeSet::new(),
        "the roles exist but the principal has not joined the group yet"
    );
    fixture.join(&payments).await;
    assert_eq!(
        fixture.permissions().await,
        set(&["audit.read", "deploy.write"]),
        "joining the leaf group inherits its role AND its ancestor's"
    );
}
parity!(
    group_roles_inherit_up_the_closure,
    group_roles_inherit_up_the_closure_for_a_user,
    group_roles_inherit_up_the_closure_for_a_service_account
);

// The depth budget cuts the walk at the same distance for either principal. The ancestor two
// hops up is reachable at depth 2 and invisible at depth 1.
async fn the_depth_budget_bounds_the_walk(kind: Kind) {
    let fixture = Fixture::start(kind).await;
    let root = fixture.group("root", None).await;
    let middle = fixture.group("middle", Some(&root)).await;
    let leaf = fixture.group("leaf", Some(&middle)).await;
    let near = fixture.role("near", &["deploy.write"]).await;
    let far = fixture.role("far", &["audit.read"]).await;
    fixture.group_role(&leaf, &near).await;
    fixture.group_role(&root, &far).await;
    fixture.join(&leaf).await;

    assert_eq!(
        fixture.permissions_to_depth(1).await,
        set(&["deploy.write"]),
        "a budget of one hop cannot reach the root two hops up"
    );
    assert_eq!(
        fixture.permissions_to_depth(2).await,
        set(&["audit.read", "deploy.write"]),
        "two hops reaches it"
    );
}
parity!(
    the_depth_budget_bounds_the_walk,
    the_depth_budget_bounds_the_walk_for_a_user,
    the_depth_budget_bounds_the_walk_for_a_service_account
);

// A removed membership resolves to nothing, whatever it held. The membership is the anchor of
// the whole closure, so this is the revocation that has to hold for either principal.
async fn a_removed_membership_holds_nothing(kind: Kind) {
    let fixture = Fixture::start(kind).await;
    let role = fixture.role("billing", &["billing.invoice.read"]).await;
    fixture.grant(&role).await;
    assert_eq!(
        fixture.permissions().await,
        set(&["billing.invoice.read"]),
        "held before the removal, so the assertion after it is a difference"
    );

    // Through the repository, not the engine. `remove` is principal agnostic: it keys on the
    // membership id, and its user-only cascade (re-pointing org-scoped identifiers) is skipped
    // when the row bound no user. Running it here is what says a machine's membership is
    // removable by the same call that removes a human's, and that the attachment cascade
    // stripping its roles runs either way.
    fixture
        .db
        .control_store()
        .scoped(fixture.scope)
        .acting(
            fixture.db.test_actor(&fixture.env),
            CorrelationId::generate(&fixture.env),
        )
        .org_memberships()
        .remove(&fixture.env, &fixture.membership)
        .await
        .expect("remove the membership");
    assert_eq!(
        fixture.permissions().await,
        BTreeSet::new(),
        "a removed membership resolves to nothing whatever roles it held"
    );
}
parity!(
    a_removed_membership_holds_nothing,
    a_removed_membership_holds_nothing_for_a_user,
    a_removed_membership_holds_nothing_for_a_service_account
);
