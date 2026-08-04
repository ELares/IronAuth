// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reusable cross-tenant IDOR harness (feature `testing`).
//!
//! Given any isolation-relevant operation, this harness exercises it with
//! identifiers minted in ANOTHER tenant and ANOTHER environment and asserts a
//! uniform denial: the same not-found outcome a genuinely absent resource
//! produces, with no error-shape oracle. It is the suite the issue mandates
//! "every future surface must register with."
//!
//! # Registering a future surface
//!
//! A new surface implements [`IsolationProbe`] for each operation that reads or
//! mutates a scoped resource by identifier, then registers it:
//!
//! ```no_run
//! use ironauth_store::idor_harness::{IdorHarness, IsolationProbe, ProbeOutcome, BoxProbeFuture};
//! use ironauth_store::{Scope, Store};
//!
//! struct MySurfaceGet;
//! impl IsolationProbe for MySurfaceGet {
//!     fn name(&self) -> &'static str { "my_surface.get" }
//!     fn probe<'a>(&'a self, store: &'a Store, caller: Scope, foreign_id: &'a str)
//!         -> BoxProbeFuture<'a> {
//!         Box::pin(async move {
//!             // Parse the untrusted id under the caller's own scope, then read.
//!             // Map both "malformed" and "absent" to Denied.
//!             let _ = (store, caller, foreign_id);
//!             ProbeOutcome::Denied
//!         })
//!     }
//! }
//!
//! let mut harness = IdorHarness::new();
//! harness.register(Box::new(MySurfaceGet));
//! ```
//!
//! The harness then covers that operation in CI automatically.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use ironauth_env::Env;

use crate::audit::ActorRef;
use crate::id::{
    ConnectorId, CorrelationId, CredentialId, GrantId, IssuedTokenId, OrganizationId, ServiceId,
    SessionId, SigningKeyId, UserId, UserIdentifierId,
};
use crate::identifier::{IdentifierType, UniquenessMode};
use crate::org_policy::{AuthPolicy, ORG_POLICY_MAX_SESSION_TTL_SECS};
use crate::repository::{
    CredentialRemoveOutcome, NewUserIdentifier, RedeemOutcome, RefreshFamilyFleetFilter,
    SessionEndCause, SessionFleetFilter, TokenStatus, UserListFilter, UserState,
};
use crate::scope::Scope;
use crate::store::Store;

/// The page size the fleet LIST probes read. Comfortably larger than the handful of
/// rows any probe fixture plants, so a leaked foreign row can never hide behind
/// pagination.
const PROBE_PAGE_LIMIT: i64 = 100;

/// The outcome of a single cross-scope probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The operation refused the cross-scope resource with the uniform
    /// not-found behavior. This is the required outcome.
    Denied,
    /// The operation exposed or mutated a resource from another tenant or
    /// environment: an IDOR defect.
    Leaked,
}

/// A boxed future returned by a probe. The boxing keeps [`IsolationProbe`]
/// object safe, so probes from many surfaces live in one registry.
pub type BoxProbeFuture<'a> = Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>>;

/// One isolation-relevant operation, exercised against a foreign identifier.
///
/// Implement this for every operation that resolves a scoped resource by
/// identifier. The contract: parse the untrusted identifier under the caller's
/// OWN scope, perform the operation, and return [`ProbeOutcome::Denied`] for a
/// not-found (whether malformed, absent, or cross-scope) and
/// [`ProbeOutcome::Leaked`] only if a foreign resource was actually exposed or
/// changed.
pub trait IsolationProbe: Send + Sync {
    /// A stable name for reporting (for example `clients.get`).
    fn name(&self) -> &'static str;

    /// Run the operation as `caller`, targeting `foreign_id`.
    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a>;
}

/// A detected cross-scope leak, reported by [`IdorHarness::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    /// The probe that leaked.
    pub probe: &'static str,
    /// The foreign identifier that was exposed.
    pub foreign_id: String,
}

/// A registry of isolation probes.
#[derive(Default)]
pub struct IdorHarness {
    probes: Vec<Box<dyn IsolationProbe>>,
}

impl IdorHarness {
    /// An empty harness.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a probe. Chainable.
    pub fn register(&mut self, probe: Box<dyn IsolationProbe>) -> &mut Self {
        self.probes.push(probe);
        self
    }

    /// Register the built-in probes for every scoped-repository operation that
    /// resolves a resource by identifier today: `clients.get` and
    /// `clients.delete`.
    pub fn register_store_probes(&mut self) -> &mut Self {
        self.register(Box::new(ClientGetProbe));
        self.register(Box::new(ClientDeleteProbe));
        self
    }

    /// Register the management-plane probes (issue #11, #41): the scoped-resource
    /// resolve-by-id operations of the management API. Today that is the
    /// environment-scoped management-credential repository
    /// (`management_credentials.get`, `management_credentials.delete`) and the
    /// environment-scoped organization repository (`organizations.get`,
    /// `organizations.delete`), its membership join (`org_memberships.get`,
    /// `org_memberships.remove`), its role set (`org_roles.get`,
    /// `org_roles.delete`), its group forest (`org_groups.get`,
    /// `org_groups.update`, `org_groups.delete`, `org_groups.reparent`), the
    /// three join surfaces that bind those together (`org_group_members.remove`,
    /// `org_group_roles.unassign`, `org_membership_roles.unassign`), its
    /// per-organization authentication policy (`org_auth_policies.set`,
    /// `org_auth_policies.remove`, both addressed by ORGANIZATION id rather than by
    /// the policy's own id, because the organization IS the policy's identity), and
    /// its permission vocabulary (`permissions.get` and `permissions.delete`), its
    /// role-to-permission mapping (`org_role_permissions.unassign`), its
    /// resource-server registry (`resource_servers.get` and
    /// `resource_servers.set_permission_claims`, the read and the one mutation the
    /// issue #98 management surface exposes over the audience-to-format registry),
    /// its per-client SCOPE allowlist (`client_scope_policies.get` and
    /// `client_scope_policies.set`, the read and the one mutation the issue #98
    /// management surface exposes over `clients.allowed_scopes`; a NARROW door onto
    /// one column of `clients`, not the whole client repository, which is why these
    /// are distinct from the data-plane `clients.get` / `clients.delete` probes),
    /// the two-thirds of the four-level resource model
    /// that is tenant-and-environment scoped (operators, tenants, and environments
    /// are LEVEL tables whose isolation is exercised by the management-plane tests
    /// directly, not through the scope-embedding IDOR harness).
    ///
    /// Run these with a store whose pool authenticates as `ironauth_control`
    /// (the data-plane role has no grant on `management_credentials`); a
    /// control-plane store is what [`crate::test_support::TestDatabase::control_store`]
    /// hands back. As every management resource endpoint lands, its probe is
    /// registered here so the harness covers it in CI.
    pub fn register_management_probes(&mut self) -> &mut Self {
        self.register(Box::new(ManagementCredentialGetProbe));
        self.register(Box::new(ManagementCredentialDeleteProbe));
        self.register(Box::new(OrganizationGetProbe));
        self.register(Box::new(OrganizationDeleteProbe));
        self.register(Box::new(OrgMembershipGetProbe));
        self.register(Box::new(OrgMembershipRemoveProbe));
        self.register(Box::new(OrgRoleGetProbe));
        self.register(Box::new(OrgRoleDeleteProbe));
        self.register(Box::new(OrgGroupGetProbe));
        self.register(Box::new(OrgGroupUpdateProbe));
        self.register(Box::new(OrgGroupDeleteProbe));
        self.register(Box::new(OrgGroupReparentProbe));
        self.register(Box::new(OrgGroupMemberRemoveProbe));
        self.register(Box::new(OrgGroupRoleUnassignProbe));
        self.register(Box::new(OrgMembershipRoleUnassignProbe));
        self.register(Box::new(OrgAuthPolicySetProbe));
        self.register(Box::new(OrgAuthPolicyRemoveProbe));
        self.register(Box::new(PermissionGetProbe));
        self.register(Box::new(PermissionDeleteProbe));
        self.register(Box::new(OrgRolePermissionUnassignProbe));
        self.register(Box::new(ResourceServerGetProbe));
        self.register(Box::new(ResourceServerSetPermissionClaimsProbe));
        self.register(Box::new(ClientScopePolicyGetProbe));
        self.register(Box::new(ClientScopePolicySetProbe));
        self
    }

    /// Register the OIDC data-plane probes (issue #12, #15): the scoped-resource
    /// resolve-by-id operations of the authorization-code grant. Today that is
    /// `authorization_codes.redeem` (a cross-scope code must never be consumable),
    /// `issued_tokens.token_status` (a cross-scope token's active state must never
    /// be observable), and `issued_tokens.resolve_access_token` (a cross-scope
    /// access token must never resolve to a subject/client for `UserInfo`). Run these
    /// with the data-plane store (`ironauth_app`).
    pub fn register_oidc_probes(&mut self) -> &mut Self {
        self.register(Box::new(AuthorizationCodeRedeemProbe));
        self.register(Box::new(IssuedTokenStatusProbe));
        self.register(Box::new(AccessTokenResolveProbe));
        self
    }

    /// Register the signing-key probes (issue #19): a signing key provisioned in
    /// another tenant or environment must never be readable under the caller's
    /// scope. That is what makes "the signing core's key lookup cannot express a
    /// cross-tenant read" a tested property, not just a design claim. Run these
    /// with the data-plane store (`ironauth_app`).
    pub fn register_signing_key_probes(&mut self) -> &mut Self {
        self.register(Box::new(SigningKeyGetProbe));
        self
    }

    /// Register the session fleet-operations probes (issue #32): every surface the
    /// management API exposes over the two-tier session model resolves a scoped
    /// resource by identifier, so every one of them is registered here and runs under
    /// forced row-level security.
    ///
    /// The set is the authentication read path (`sessions.get`), the per-client `sid`
    /// store (`client_sessions.ensure_sid`, which must never attach a per-client
    /// session to a foreign SSO session), the fleet read surfaces
    /// (`session_fleet.get`, `refresh_family_fleet.get`) AND the fleet LIST surfaces
    /// (`session_fleet.list`, `refresh_family_fleet.list`), and the three mutating
    /// fleet surfaces (`sessions.revoke`, `sessions.bulk_revoke`,
    /// `sessions.revoke_all`).
    ///
    /// The bulk probe is the important MUTATING one: a batch is scope-FENCED, so a
    /// foreign id smuggled into an otherwise valid batch must be a uniform no-op rather
    /// than a cross-tenant revocation. The two LIST probes are the important READING
    /// ones: unlike every by-id surface, a list has no identifier to fence on, so it is
    /// where a broken isolation policy would leak an entire foreign tenant at once
    /// instead of a single row.
    pub fn register_session_fleet_probes(&mut self) -> &mut Self {
        self.register(Box::new(SessionGetProbe));
        self.register(Box::new(ClientSessionEnsureSidProbe));
        self.register(Box::new(SessionFleetGetProbe));
        self.register(Box::new(SessionFleetListProbe));
        self.register(Box::new(RefreshFamilyFleetGetProbe));
        self.register(Box::new(RefreshFamilyFleetListProbe));
        self.register(Box::new(SessionRevokeProbe));
        self.register(Box::new(SessionBulkRevokeProbe));
        self.register(Box::new(UserSessionsRevokeAllProbe));
        self
    }

    /// Register the user-surface probes (issue #52, completed by issue #241): every
    /// surface that resolves a user, on the management plane and the DATA plane alike. A
    /// foreign user must be the uniform not-found on every one, and the list surface must
    /// never leak a foreign tenant's users. Run these with a store that carries the
    /// platform master key (the user PII paths fail closed without it).
    ///
    /// Three groups:
    ///
    /// - the management READS (`users.get`, `users.list`, `users.by_external_id`);
    /// - the management MUTATIONS (`users.delete`, `users.set_state`,
    ///   `users.update_claims`, `users.external_id.link`, `users.external_id.unlink`);
    /// - the BY-SUBJECT data-plane reads (`users.state_for_subject`,
    ///   `users.claims_for_subject`, `users.by_identifier`), added by issue #241.
    ///
    /// That third group is why this doc no longer says "admin". It was left out
    /// originally with a written argument that it could not leak, and the argument was
    /// correct: those three hard filter `tenant_id`/`environment_id` in SQL and open
    /// their PII under a scope-bound AAD. What was wrong was claiming COMPLETE coverage
    /// on top of an unmeasured argument. These reads are the ones the login path and the
    /// token-mint lifecycle fences are built on, so if any user surface deserved a
    /// measurement rather than a paragraph it was these. They are measured now, and the
    /// claim is true rather than nearly true.
    ///
    /// `users.by_identifier` keys on a login HANDLE, not an id, so the caller must
    /// include a victim's real identifier among the foreign references or that probe is
    /// vacuous. `users.by_external_id` already carried the same requirement.
    pub fn register_user_admin_probes(&mut self) -> &mut Self {
        self.register(Box::new(UserAdminGetProbe));
        self.register(Box::new(UserAdminListProbe));
        self.register(Box::new(UserAdminByExternalIdProbe));
        self.register(Box::new(UserAdminDeleteProbe));
        self.register(Box::new(UserAdminStateChangeProbe));
        self.register(Box::new(UserAdminUpdateClaimsProbe));
        self.register(Box::new(UserAdminExternalIdLinkProbe));
        self.register(Box::new(UserAdminExternalIdUnlinkProbe));
        self.register(Box::new(UserStateForSubjectProbe));
        self.register(Box::new(UserClaimsForSubjectProbe));
        self.register(Box::new(UserByIdentifierProbe));
        // The flexible login-identifier surface (issue #54, epic #514). Its three
        // operations each address a scoped resource by identifier, so the harness's own
        // mandate covers them: the two user-addressed ones take a foreign `usr_`, and the
        // remove takes a foreign `uid_`, which is why the caller seeds a real victim
        // identifier rather than relying on the user ids alone.
        self.register(Box::new(UserIdentifierListProbe));
        self.register(Box::new(UserIdentifierAddProbe));
        // `ActingUserIdentifierRepo::remove` is deliberately NOT registered, and the
        // reason is measured rather than assumed. It is keyed on the OWNING USER as well
        // as the `uid_`, and a probe receives one identifier at a time, so it cannot
        // supply the owner and must invent one. Every call therefore removes zero rows
        // and answers `Denied` whatever scope the `uid_` came from: driven with a
        // CALLER-SCOPE identifier it still reports no leak, which is the definition of a
        // probe that cannot fail. Registering it would raise the probe count without
        // raising the coverage, which is worse than the gap because the count is what
        // the pinned name list makes people trust.
        //
        // Its isolation is not unmeasured. The scope half is the same `parse_in_scope`
        // plus scope-predicate plus row-level-security stack every probe above exercises,
        // and the OWNER half has its own end-to-end test on the management surface,
        // `an_identifier_cannot_be_removed_through_another_users_path`, which is
        // mutation-proven: replacing the `user_id` predicate with a tautology turns it
        // red.
        self
    }

    /// Register the federation-connector probes (issue #75): a connector definition
    /// registered in another tenant or environment must never be readable under the
    /// caller's scope, or a management read would expose a foreign tenant's upstream
    /// configuration. Run these with the control-plane store (`ironauth_control`), the
    /// plane that owns the connector lifecycle.
    pub fn register_connector_probes(&mut self) -> &mut Self {
        self.register(Box::new(ConnectorGetProbe));
        self.register(Box::new(ConnectorDeleteProbe));
        self
    }

    /// Register the federation outbound-login correlation probe (issue #75, PR B): the
    /// single-use consume of a correlation row planted in another tenant or environment
    /// must never resolve under the caller's scope, or a federated callback could burn a
    /// foreign tenant's pending login (and recover its sealed PKCE verifier). The probe's
    /// foreign identifier is the row's opaque STATE (the natural consume key). Run with
    /// the data-plane store (`ironauth_app`).
    pub fn register_federation_probes(&mut self) -> &mut Self {
        self.register(Box::new(FederationLoginStateConsumeProbe));
        self
    }

    /// Register the self-service account-credential probes (issue #61): the
    /// mutating removal of an enrolled credential must refuse a credential id from
    /// another tenant or environment as the uniform not-found, never a cross-scope
    /// credential deletion. Run with the data-plane store (`ironauth_app`).
    pub fn register_account_probes(&mut self) -> &mut Self {
        self.register(Box::new(AccountCredentialRemoveProbe));
        self
    }

    /// Register the upstream token vault probe (issue #77, PR 3): a session's captured
    /// upstream tokens must never be readable under another tenant or environment's
    /// scope, or a stolen retrieval could exfiltrate a foreign tenant's upstream access
    /// and refresh tokens. The read is keyed on the session id (the IDOR scoping key), so
    /// the probe's `foreign_id` is a session id planted in another scope: it must parse as
    /// a uniform not-found (or resolve to no row) under the caller's scope. Run with the
    /// data-plane store (`ironauth_app`), which carries the platform master key.
    pub fn register_upstream_token_probes(&mut self) -> &mut Self {
        self.register(Box::new(UpstreamTokenReadProbe));
        self
    }

    /// Register the third-party risk-signal read probe (issue #82, PR 1): a subject's
    /// ingested external risk signals must never be readable under another tenant or
    /// environment's scope, or the #79 engine could fold a FOREIGN tenant's signals into a
    /// login decision. The read is keyed on the subject (a `usr_` id, the IDOR scoping key),
    /// so the probe's `foreign_id` is a subject planted in another scope: it must parse as a
    /// uniform not-found (or resolve to no row) under the caller's scope. Run with the
    /// data-plane store (`ironauth_app`), which carries the platform master key.
    pub fn register_risk_signal_probes(&mut self) -> &mut Self {
        self.register(Box::new(RiskSignalReadProbe));
        self
    }

    /// Register the client-authentication diagnostics read probe (issue #91): the M9
    /// admin flow inspector's read path over the `client_auth_diagnostics` sink must
    /// never surface a diagnostic recorded under another tenant or environment, or the
    /// inspector would leak WHICH clients in a foreign tenant were failing to
    /// authenticate and how. The read is keyed on the CLIENT ID (a plain string
    /// filter, the M9 view's natural key), so the probe's `foreign_id` is a client id
    /// whose diagnostics were planted in another scope: the scoped, forced-RLS
    /// `query` must resolve to no rows under the caller's scope. Run with the
    /// data-plane store (`ironauth_app`), which holds the sink's SELECT grant.
    pub fn register_diagnostic_probes(&mut self) -> &mut Self {
        self.register(Box::new(ClientAuthDiagnosticReadProbe));
        self
    }

    /// Register the policy decision trace read probe (issue #91): the M9 admin flow
    /// inspector's read over the `policy_decision_traces` sink must never surface a trace
    /// recorded under another tenant or environment, or the inspector would leak WHICH
    /// subjects in a foreign tenant were being step up challenged, risk denied, or claim
    /// mapping failed. The read is keyed on the SUBJECT (a plain usr_ handle filter), so
    /// the probe's `foreign_id` is a subject whose traces were planted in another scope:
    /// the scoped, forced RLS `query` must resolve to no rows under the caller's scope.
    /// Run with the data plane store (`ironauth_app`), which holds the sink's SELECT grant.
    pub fn register_policy_trace_probes(&mut self) -> &mut Self {
        self.register(Box::new(PolicyDecisionTraceReadProbe));
        self
    }

    /// The names of the registered probes, in registration order.
    #[must_use]
    pub fn probe_names(&self) -> Vec<&'static str> {
        self.probes.iter().map(|p| p.name()).collect()
    }

    /// Run every registered probe as `caller` against every `foreign_id`, and
    /// return every leak found. An empty vector is a pass.
    pub async fn run(&self, store: &Store, caller: Scope, foreign_ids: &[&str]) -> Vec<Leak> {
        let mut leaks = Vec::new();
        for probe in &self.probes {
            for foreign_id in foreign_ids {
                if probe.probe(store, caller, foreign_id).await == ProbeOutcome::Leaked {
                    leaks.push(Leak {
                        probe: probe.name(),
                        foreign_id: (*foreign_id).to_string(),
                    });
                }
            }
        }
        leaks
    }
}

/// Built-in probe for `UserIdentifierRepo::list_for_user` (issue #54).
///
/// A foreign user's login identifiers must never be listable under the caller's scope.
/// `list_for_user` answers an EMPTY vector for an out-of-scope user rather than an error,
/// so this probe reads a non-empty result as the leak: an empty answer is exactly what a
/// genuinely absent user produces, which is the uniformity this harness is about.
struct UserIdentifierListProbe;

impl IsolationProbe for UserIdentifierListProbe {
    fn name(&self) -> &'static str {
        "user_identifiers.list_for_user"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let Ok(id) = UserId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store
                .scoped(caller)
                .user_identifiers()
                .list_for_user(&id)
                .await
            {
                Ok(rows) if rows.is_empty() => ProbeOutcome::Denied,
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingUserIdentifierRepo::add` (issue #54).
///
/// Adding a login identifier to a FOREIGN user would plant a login handle on an account
/// in another scope, which is a write-side takeover rather than a read leak.
struct UserIdentifierAddProbe;

impl IsolationProbe for UserIdentifierAddProbe {
    fn name(&self) -> &'static str {
        "user_identifiers.add"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(user) = UserId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .user_identifiers()
                .add(
                    &env,
                    NewUserIdentifier {
                        id: &UserIdentifierId::generate(&env, &caller),
                        user_id: &user,
                        identifier_type: IdentifierType::Email,
                        raw: "idor-probe@example.test",
                        verified: false,
                        mode: UniquenessMode::EnvironmentWide,
                        org: None,
                    },
                    None,
                )
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ClientRepo::get`.
struct ClientGetProbe;

impl IsolationProbe for ClientGetProbe {
    fn name(&self) -> &'static str {
        "clients.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let clients = store.scoped(caller).clients();
            // A real handler parses the untrusted id under its own scope first;
            // a cross-scope id fails here as a uniform not-found.
            let Ok(id) = clients.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match clients.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                // Not found (cross-scope or absent) is the correct denial; a
                // database fault is likewise not a leak. The tests assert the
                // absence of faults separately, so the harness measures leakage
                // only.
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ClientRepo::delete`.
struct ClientDeleteProbe;

impl IsolationProbe for ClientDeleteProbe {
    fn name(&self) -> &'static str {
        "clients.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            // Parsing the untrusted id happens under the caller's own scope on
            // the read repository; a cross-scope id fails here as a uniform
            // not-found before any mutating repository is reached.
            let Ok(id) = store.scoped(caller).clients().parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            // Mutations require an acting context; the probe fabricates a service
            // actor and a fresh correlation id (this is test-support code).
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let clients = store.scoped(caller).acting(actor, correlation).clients();
            match clients.delete(&env, &id).await {
                // A leaked deletion would affect the foreign row and report Ok.
                Ok(()) => ProbeOutcome::Leaked,
                // Not found affects zero rows (the foreign resource is
                // untouched); a database fault is likewise not a leak.
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ManagementCredentialRepo::get` (issue #11). `store` must
/// authenticate as `ironauth_control`.
struct ManagementCredentialGetProbe;

impl IsolationProbe for ManagementCredentialGetProbe {
    fn name(&self) -> &'static str {
        "management_credentials.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let credentials = store.management().credentials(caller);
            // Parse the untrusted id under the caller's OWN scope; a management
            // key minted in another scope fails here as a uniform not-found.
            let Ok(id) = credentials.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match credentials.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingManagementCredentialRepo::delete` (issue #11).
/// `store` must authenticate as `ironauth_control`.
struct ManagementCredentialDeleteProbe;

impl IsolationProbe for ManagementCredentialDeleteProbe {
    fn name(&self) -> &'static str {
        "management_credentials.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.management().credentials(caller).parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let credentials = store
                .management()
                .acting(actor, correlation)
                .credentials(caller);
            match credentials.delete(&env, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `OrganizationRepo::get` (issue #41). `store` must
/// authenticate as `ironauth_control`. An organization created in another tenant
/// or environment must never be readable under the caller's scope.
struct OrganizationGetProbe;

impl IsolationProbe for OrganizationGetProbe {
    fn name(&self) -> &'static str {
        "organizations.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let organizations = store.management().organizations(caller);
            // Parse the untrusted id under the caller's OWN scope; an organization
            // minted in another scope fails here as a uniform not-found.
            let Ok(id) = organizations.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match organizations.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrganizationRepo::delete` (issue #41). `store` must
/// authenticate as `ironauth_control`. Deactivating another tenant's organization
/// would be a cross-tenant mutation, so it must be the uniform not-found.
struct OrganizationDeleteProbe;

impl IsolationProbe for OrganizationDeleteProbe {
    fn name(&self) -> &'static str {
        "organizations.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .organizations(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let organizations = store
                .management()
                .acting(actor, correlation)
                .organizations(caller);
            match organizations.delete(&env, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `OrgMembershipRepo::get` (issue #94). `store` must
/// authenticate as `ironauth_control`. A membership minted in another scope must
/// resolve as the uniform not-found under the caller's scope.
struct OrgMembershipGetProbe;

impl IsolationProbe for OrgMembershipGetProbe {
    fn name(&self) -> &'static str {
        "org_memberships.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let memberships = store.management().org_memberships(caller);
            let Ok(id) = memberships.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match memberships.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgMembershipRepo::remove` (issue #94). `store` must
/// authenticate as `ironauth_control`. Removing another scope's membership would be
/// a cross-scope mutation, so it must be the uniform not-found.
struct OrgMembershipRemoveProbe;

impl IsolationProbe for OrgMembershipRemoveProbe {
    fn name(&self) -> &'static str {
        "org_memberships.remove"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .org_memberships(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let memberships = store
                .management()
                .acting(actor, correlation)
                .org_memberships(caller);
            match memberships.remove(&env, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `OrgRoleRepo::get` (issue #97). `store` must authenticate as
/// `ironauth_control`. A role defined in another scope must resolve as the uniform
/// not-found under the caller's scope, indistinguishable from an absent one.
struct OrgRoleGetProbe;

impl IsolationProbe for OrgRoleGetProbe {
    fn name(&self) -> &'static str {
        "org_roles.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let roles = store.management().org_roles(caller);
            let Ok(id) = roles.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match roles.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgAuthPolicyRepo::set` (issue #95). `store` must
/// authenticate as `ironauth_control`.
///
/// Unlike every other probe in this module the untrusted identifier here is an
/// ORGANIZATION id, not the resource's own id, because a policy is 1:1 with its
/// organization and both mutations address it that way. That makes this the probe
/// for the whole addressing scheme: if a foreign organization id could be used to
/// STATE a policy, one tenant could impose an authentication requirement on another
/// tenant's members, or lift one.
///
/// The submitted document is EMPTY, which is valid in every respect (it restricts
/// nothing, so no validator can refuse it) and therefore leaves the cross-scope
/// resolution as the only thing that can deny the write. A probe submitting an
/// INVALID document would be refused for the wrong reason and would prove nothing.
struct OrgAuthPolicySetProbe;

impl IsolationProbe for OrgAuthPolicySetProbe {
    fn name(&self) -> &'static str {
        "org_auth_policies.set"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(organization) = store
                .management()
                .organizations(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let policies = store
                .management()
                .acting(actor, correlation)
                .org_auth_policies(caller);
            match policies
                .set(
                    &env,
                    &organization,
                    &AuthPolicy::default(),
                    ORG_POLICY_MAX_SESSION_TTL_SECS,
                )
                .await
            {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgAuthPolicyRepo::remove` (issue #95). `store` must
/// authenticate as `ironauth_control`.
///
/// The mutation with the larger blast radius of the two: removing a foreign
/// organization's policy would silently LIFT whatever that organization had
/// tightened (an MFA requirement, a factor allowlist), so it must be the uniform
/// not-found. Addressed by organization id, like `set`.
struct OrgAuthPolicyRemoveProbe;

impl IsolationProbe for OrgAuthPolicyRemoveProbe {
    fn name(&self) -> &'static str {
        "org_auth_policies.remove"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(organization) = store
                .management()
                .organizations(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let policies = store
                .management()
                .acting(actor, correlation)
                .org_auth_policies(caller);
            match policies.remove(&env, &organization).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgRoleRepo::delete` (issue #97). `store` must
/// authenticate as `ironauth_control`. Deleting another scope's role would be a
/// cross-scope mutation, so it must be the uniform not-found.
struct OrgRoleDeleteProbe;

impl IsolationProbe for OrgRoleDeleteProbe {
    fn name(&self) -> &'static str {
        "org_roles.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.management().org_roles(caller).parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let roles = store
                .management()
                .acting(actor, correlation)
                .org_roles(caller);
            match roles.delete(&env, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `OrgGroupRepo::get` (issue #97). `store` must authenticate as
/// `ironauth_control`. A group defined in another scope must resolve as the uniform
/// not-found under the caller's scope, indistinguishable from an absent one.
struct OrgGroupGetProbe;

impl IsolationProbe for OrgGroupGetProbe {
    fn name(&self) -> &'static str {
        "org_groups.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let groups = store.management().org_groups(caller);
            let Ok(id) = groups.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match groups.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgGroupRepo::update` (issue #97). `store` must
/// authenticate as `ironauth_control`. Renaming another scope's group would be a
/// cross-scope mutation, so it must be the uniform not-found.
///
/// Registered alongside the delete and reparent probes because `update` addresses a
/// group by the SAME key they do (scope, organization, id), and a rename is not a
/// lesser mutation than a delete: it rewrites the label the console and every
/// operator reads. The organization the probe names is a fresh id in the CALLER's
/// own scope, so the refusal must not depend on the caller guessing the group's real
/// organization; the SAME-SCOPE cross-organization case, which this harness's
/// tenant-and-environment axis cannot express, is pinned directly in the group store
/// tests.
struct OrgGroupUpdateProbe;

impl IsolationProbe for OrgGroupUpdateProbe {
    fn name(&self) -> &'static str {
        "org_groups.update"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.management().org_groups(caller).parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let organization = OrganizationId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let groups = store
                .management()
                .acting(actor, correlation)
                .org_groups(caller);
            match groups
                .update(&env, &organization, &id, Some(PROBE_RENAME), None)
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// The display name the group update probe would write if it leaked. Distinctive so
/// the planted victim's surviving name is an assertion the probe really was refused,
/// not a coincidence.
const PROBE_RENAME: &str = "leaked by the idor probe";

/// Built-in probe for `ActingOrgGroupRepo::delete` (issue #97). `store` must
/// authenticate as `ironauth_control`. Deleting another scope's group would be a
/// cross-scope mutation, so it must be the uniform not-found.
///
/// The organization the probe names is a fresh id in the CALLER's own scope, so the
/// probe additionally asserts that the refusal does not depend on the caller
/// guessing the group's real organization. The SAME-SCOPE cross-organization case
/// (which row-level security cannot fence, because both organizations sit inside the
/// caller's bound scope) is not expressible through this harness, whose axis is
/// tenant and environment; it is pinned directly in the group store tests.
struct OrgGroupDeleteProbe;

impl IsolationProbe for OrgGroupDeleteProbe {
    fn name(&self) -> &'static str {
        "org_groups.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.management().org_groups(caller).parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let organization = OrganizationId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let groups = store
                .management()
                .acting(actor, correlation)
                .org_groups(caller);
            match groups.delete(&env, &organization, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgGroupRepo::reparent` (issue #97). `store` must
/// authenticate as `ironauth_control`. Moving another scope's group within a
/// hierarchy would be a cross-scope mutation, so it must be the uniform not-found,
/// and it must NOT be a typed cycle or depth refusal: those are informative errors,
/// and returning either for an id the caller cannot see would turn them into an
/// existence oracle over another tenant's group graph. `Err(_)` here accepts any
/// error, so the anti-oracle discipline is pinned by the group store tests, which
/// assert the exact variant.
struct OrgGroupReparentProbe;

impl IsolationProbe for OrgGroupReparentProbe {
    fn name(&self) -> &'static str {
        "org_groups.reparent"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.management().org_groups(caller).parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let organization = OrganizationId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let groups = store
                .management()
                .acting(actor, correlation)
                .org_groups(caller);
            // Clearing the parent is the least demanding reparent there is (it needs
            // no second group and passes no hierarchy check), so if ANY reparent of a
            // foreign group could succeed, this one would.
            match groups
                .reparent(&env, &organization, &id, None, DEFAULT_PROBE_GROUP_DEPTH)
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// The group nesting bound the reparent probe passes (issue #97). The probe never
/// reaches a hierarchy check (it clears the parent), so the value is immaterial;
/// it mirrors the config default so the probe reads like a real caller.
const DEFAULT_PROBE_GROUP_DEPTH: u32 = 8;

/// Built-in probe for `ActingOrgGroupMemberRepo::remove` (issue #97). `store` must
/// authenticate as `ironauth_control`. Unbinding another scope's group member would
/// be a cross-scope mutation, so it must be the uniform not-found: the same answer an
/// absent, a soft-deleted, and a foreign-organization binding give.
struct OrgGroupMemberRemoveProbe;

impl IsolationProbe for OrgGroupMemberRemoveProbe {
    fn name(&self) -> &'static str {
        "org_group_members.remove"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .org_group_members(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let organization = OrganizationId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let members = store
                .management()
                .acting(actor, correlation)
                .org_group_members(caller);
            match members.remove(&env, &organization, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgGroupRoleRepo::unassign` (issue #97). `store` must
/// authenticate as `ironauth_control`. Withdrawing another scope's group role
/// assignment would be a cross-scope mutation with a real authorization effect (every
/// member of that group and its descendants would lose the role), so it must be the
/// uniform not-found.
struct OrgGroupRoleUnassignProbe;

impl IsolationProbe for OrgGroupRoleUnassignProbe {
    fn name(&self) -> &'static str {
        "org_group_roles.unassign"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .org_group_roles(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let organization = OrganizationId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let assignments = store
                .management()
                .acting(actor, correlation)
                .org_group_roles(caller);
            match assignments.unassign(&env, &organization, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgMembershipRoleRepo::unassign` (issue #97). `store`
/// must authenticate as `ironauth_control`. Withdrawing another scope's direct role
/// grant would be a cross-scope mutation, so it must be the uniform not-found.
struct OrgMembershipRoleUnassignProbe;

impl IsolationProbe for OrgMembershipRoleUnassignProbe {
    fn name(&self) -> &'static str {
        "org_membership_roles.unassign"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .org_membership_roles(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let organization = OrganizationId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let assignments = store
                .management()
                .acting(actor, correlation)
                .org_membership_roles(caller);
            match assignments.unassign(&env, &organization, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `PermissionRepo::get` (issue #98). `store` must authenticate
/// as `ironauth_control`. A permission defined in another scope must resolve as the
/// uniform not-found under the caller's scope, indistinguishable from an absent one.
///
/// This resource is scoped to exactly `(tenant, environment)` and carries no
/// organization, so the row-level-security policy is its complete fence and this
/// probe is the whole cross-scope story for it. There is no organization dimension
/// to probe separately, unlike the #97 family above.
struct PermissionGetProbe;

impl IsolationProbe for PermissionGetProbe {
    fn name(&self) -> &'static str {
        "permissions.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let permissions = store.management().permissions(caller);
            let Ok(id) = permissions.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match permissions.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingPermissionRepo::delete` (issue #98). `store` must
/// authenticate as `ironauth_control`. Soft-deleting another scope's permission
/// would be a cross-scope mutation with a real authorization effect once the
/// role-to-permission mapping lands, so it must be the uniform not-found.
///
/// The DELETE rather than the update is the probe worth running, for the reason the
/// harness applies everywhere: a cross-scope relabel is recoverable, while a
/// cross-scope delete frees the slug and can never be undone, because a re-create
/// mints a FRESH id and is never a revival. `ProbeOutcome::Leaked` here therefore
/// means a permission in another environment was destroyed, which is why the
/// registering suite additionally asserts that the victim rows SURVIVED: a probe
/// that returned Denied because nothing was planted would pass for the wrong reason.
struct PermissionDeleteProbe;

impl IsolationProbe for PermissionDeleteProbe {
    fn name(&self) -> &'static str {
        "permissions.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.management().permissions(caller).parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let permissions = store
                .management()
                .acting(actor, correlation)
                .permissions(caller);
            match permissions.delete(&env, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingOrgRolePermissionRepo::unassign` (issue #98). `store`
/// must authenticate as `ironauth_control`. Detaching another scope's permission
/// from another scope's role would silently withdraw a capability an operator
/// believes is in force, so it must be the uniform not-found.
///
/// The DETACH rather than the attach is the probe worth running, on the harness's
/// usual rule: an attach names a mapping id the caller minted, while a detach names
/// a row that already exists in the victim's scope and destroys it. `Leaked` here
/// therefore means a live grant in another environment was withdrawn, which is why
/// the registering suite additionally asserts the victim mappings SURVIVED: a probe
/// denied because nothing was planted would pass for the wrong reason.
struct OrgRolePermissionUnassignProbe;

impl IsolationProbe for OrgRolePermissionUnassignProbe {
    fn name(&self) -> &'static str {
        "org_role_permissions.unassign"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .org_role_permissions(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let organization = OrganizationId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let mappings = store
                .management()
                .acting(actor, correlation)
                .org_role_permissions(caller);
            match mappings.unassign(&env, &organization, &id).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ResourceServerRepo::get` (issue #98). `store` must
/// authenticate as `ironauth_control`. A resource server registered in another scope
/// must resolve as the uniform not-found under the caller's scope, indistinguishable
/// from an absent one.
///
/// The row it addresses carries an AUDIENCE, which is the URI of a protected API,
/// plus that API's token format and its permission-claim opt-in. A leak here is
/// therefore an inventory of a sibling environment's protected APIs, read one id at
/// a time, which is why the read half is probed at all on a table whose reads are
/// otherwise unremarkable.
///
/// Like `permissions`, this table is scoped to exactly `(tenant, environment)` and
/// carries no organization, so the row-level-security policy is its complete fence
/// and there is no sibling-organization dimension to probe separately. Unlike it,
/// this table has no soft delete, so a probe cannot be answered by a `deleted_at`
/// filter and the scope predicates are the whole of what refuses it.
struct ResourceServerGetProbe;

impl IsolationProbe for ResourceServerGetProbe {
    fn name(&self) -> &'static str {
        "resource_servers.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let servers = store.management().resource_servers(caller);
            let Ok(id) = servers.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match servers.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingResourceServerRepo::set_permission_claims` (issue #98).
/// `store` must authenticate as `ironauth_control`.
///
/// The MUTATING half, and on this table it is the sharper of the two: the opt-in
/// decides whether tokens minted for that audience may carry permission claims, so a
/// cross-scope flip either widens what a foreign environment's tokens assert or
/// silently withdraws a claim an operator believes is in force. It is probed in the
/// ENABLING direction, so a leak leaves an observable `true` on a victim planted
/// `false`, and the registering suite asserts the victim still reads `false`: a probe
/// denied because nothing was planted would pass for the wrong reason.
struct ResourceServerSetPermissionClaimsProbe;

impl IsolationProbe for ResourceServerSetPermissionClaimsProbe {
    fn name(&self) -> &'static str {
        "resource_servers.set_permission_claims"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .resource_servers(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let servers = store
                .management()
                .acting(actor, correlation)
                .resource_servers(caller);
            match servers.set_permission_claims(&env, &id, true).await {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ClientScopePolicyRepo::get` (issue #98). `store` must
/// authenticate as `ironauth_control`. A client registered in another scope must
/// resolve as the uniform not-found under the caller's scope, indistinguishable from
/// an absent one.
///
/// The DATA plane already has `clients.get` and `clients.delete` probes. This one is
/// registered separately because it is a DIFFERENT door on a different plane: the
/// management surface reaches `clients.allowed_scopes` through
/// `ManagementStore::client_scope_policies`, a narrow repository that exists so the
/// control plane gets one column and not the whole of `ClientRepo`. A narrow door is
/// still a door, and it needs its own probe.
///
/// The row it reads is a client's delegation policy: which scope tokens that machine
/// may ask for. A leak is a read of how a sibling environment's clients are
/// constrained, one id at a time.
struct ClientScopePolicyGetProbe;

impl IsolationProbe for ClientScopePolicyGetProbe {
    fn name(&self) -> &'static str {
        "client_scope_policies.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let policies = store.management().client_scope_policies(caller);
            let Ok(id) = policies.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match policies.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingClientScopePolicyRepo::set` (issue #98). `store` must
/// authenticate as `ironauth_control`.
///
/// The MUTATING half, and the sharper of the two. It is probed in the WIDENING
/// direction: it writes a NON-empty allowlist onto a victim planted with NULL. That
/// is deliberate and worth stating, because it is not the obvious choice.
///
/// A leak here does not read as "the allowlist got bigger". A victim with NULL has NO
/// allowlist, which is the WIDEST state there is, so a landed write actually
/// RESTRICTS it: a cross-scope write is a denial of service against a foreign
/// environment's machine clients, silently cutting them down to whatever scopes the
/// attacker named. Both directions are real damage and either would do as a probe;
/// this one is chosen because the observable is unambiguous. The registering suite
/// asserts the victim still reads `None`, and `None` cannot be produced by a landed
/// write, whereas an "attacker set `[]`" probe would be indistinguishable from a
/// malformed-value read.
struct ClientScopePolicySetProbe;

impl IsolationProbe for ClientScopePolicySetProbe {
    fn name(&self) -> &'static str {
        "client_scope_policies.set"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store
                .management()
                .client_scope_policies(caller)
                .parse_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let policies = store
                .management()
                .acting(actor, correlation)
                .client_scope_policies(caller);
            match policies
                .set(&env, &id, Some(&["attacker:owned".to_owned()]))
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingAuthorizationRepo::redeem` (issue #12). A code
/// minted in another scope must never be consumable under the caller's scope.
struct AuthorizationCodeRedeemProbe;

impl IsolationProbe for AuthorizationCodeRedeemProbe {
    fn name(&self) -> &'static str {
        "authorization_codes.redeem"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            // Parse the untrusted code under the caller's OWN scope; a code minted
            // in another scope fails here as a uniform not-found.
            let Ok(code_id) = store
                .scoped(caller)
                .authorization()
                .parse_code_id(foreign_id)
            else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let authorization = store
                .scoped(caller)
                .acting(actor, correlation)
                .authorization();
            // Redeem now folds the issued-token records in; the probe passes a
            // grant minted in the caller's own scope and no tokens, since a
            // foreign code never gets this far (parse_code_id above denies it).
            let grant_id = GrantId::generate(&env, &caller);
            match authorization
                .redeem(&env, &code_id, &grant_id, &[], None, Duration::ZERO)
                .await
            {
                // Any outcome that shows the code existed (consumed now, a benign
                // grace retry, or a genuine reuse) would be a cross-scope leak.
                Ok(
                    RedeemOutcome::Consumed
                    | RedeemOutcome::RetryWithinGrace
                    | RedeemOutcome::Reused,
                ) => ProbeOutcome::Leaked,
                // Invalid (nothing matched in scope) or an error is the denial.
                Ok(RedeemOutcome::Invalid) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `AuthorizationRepo::token_status` (issue #12). A token
/// issued in another scope must never resolve to an observable active state.
struct IssuedTokenStatusProbe;

impl IsolationProbe for IssuedTokenStatusProbe {
    fn name(&self) -> &'static str {
        "issued_tokens.token_status"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // Parse the untrusted token id under the caller's OWN scope; a token
            // minted in another scope fails here as a uniform not-found.
            let Ok(jti) = IssuedTokenId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store
                .scoped(caller)
                .authorization()
                .token_status(&jti)
                .await
            {
                // Observing a foreign token's active state would be a leak.
                Ok(TokenStatus::Active | TokenStatus::Revoked) => ProbeOutcome::Leaked,
                Ok(TokenStatus::Unknown) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `AuthorizationRepo::resolve_access_token` (issue #15). An
/// access token issued in another scope must never resolve to a subject and
/// client under the caller's scope: that is what keeps a `UserInfo` request bearing
/// an environment-A token from resolving in environment B.
struct AccessTokenResolveProbe;

impl IsolationProbe for AccessTokenResolveProbe {
    fn name(&self) -> &'static str {
        "issued_tokens.resolve_access_token"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // Parse the untrusted token id under the caller's OWN scope; a token
            // minted in another scope fails here as a uniform not-found.
            let Ok(jti) = IssuedTokenId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store
                .scoped(caller)
                .authorization()
                .resolve_access_token(&jti)
                .await
            {
                // Resolving a foreign token to its subject/client would be a leak.
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `SigningKeyRepo::get` (issue #19). A signing key
/// provisioned in another scope must never resolve under the caller's scope: a
/// cross-tenant key read must be structurally unexpressable.
struct SigningKeyGetProbe;

impl IsolationProbe for SigningKeyGetProbe {
    fn name(&self) -> &'static str {
        "signing_keys.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // Parse the untrusted key id under the caller's OWN scope; a key minted
            // in another scope fails here as a uniform not-found.
            let Ok(id) = SigningKeyId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store.scoped(caller).signing_keys().get(&id).await {
                // Reading a foreign key's material or metadata would be a leak.
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ConnectorRepo::get` (issue #75): a federation connector
/// definition registered in another tenant or environment must never resolve under
/// the caller's scope, or a management read would expose a foreign tenant's upstream
/// configuration.
struct ConnectorGetProbe;

impl IsolationProbe for ConnectorGetProbe {
    fn name(&self) -> &'static str {
        "connectors.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let Ok(id) = ConnectorId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store.scoped(caller).connectors().get(&id).await {
                // Reading a foreign connector's definition or capabilities is a leak.
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingConnectorRepo::delete` (issue #75): the mutating delete
/// of a foreign connector must be the uniform not-found, never a cross-scope removal.
struct ConnectorDeleteProbe;

impl IsolationProbe for ConnectorDeleteProbe {
    fn name(&self) -> &'static str {
        "connectors.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = ConnectorId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            let acting = store.scoped(caller).acting(actor, correlation);
            match acting.connectors().delete(&env, &id).await {
                // Deleting a foreign connector would be a cross-scope mutation.
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `FederationLoginStateRepo::consume` (issue #75, PR B): the
/// single-use consume of a federation correlation row planted in another tenant or
/// environment must never resolve under the caller's scope, or a callback could burn a
/// foreign tenant's pending federated login. The `foreign_id` is the planted row's opaque
/// STATE value (the consume key), so a match under the caller scope would be a genuine
/// cross-scope leak of both the correlation and its sealed PKCE verifier.
struct FederationLoginStateConsumeProbe;

impl IsolationProbe for FederationLoginStateConsumeProbe {
    fn name(&self) -> &'static str {
        "federation_login_states.consume"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            match store
                .scoped(caller)
                .federation_login_states()
                .consume(foreign_id, 1_000_000)
                .await
            {
                // Consuming a foreign scope's correlation row is a cross-scope leak.
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `SessionRepo::get` (issue #32): the authentication read path.
/// A session established in another tenant or environment must never resolve under
/// the caller's scope, or a stolen cookie would authenticate across a tenant
/// boundary.
struct SessionGetProbe;

impl IsolationProbe for SessionGetProbe {
    fn name(&self) -> &'static str {
        "sessions.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // Parse the untrusted cookie value under the caller's OWN scope; a
            // session minted in another scope fails here as a uniform not-found.
            let Ok(id) = SessionId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store.scoped(caller).sessions().get(&id, 0, 0).await {
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ClientSessionRepo::ensure_sid` (issue #32). The per-client
/// `sid` tier must never be attached to a foreign SSO session: that would mint a
/// `sid` for another tenant's session and hand the caller a back-channel-logout
/// join key into a scope it does not own.
struct ClientSessionEnsureSidProbe;

impl IsolationProbe for ClientSessionEnsureSidProbe {
    fn name(&self) -> &'static str {
        "client_sessions.ensure_sid"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            // A foreign session id must not even parse under the caller's scope.
            let Ok(id) = SessionId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store
                .scoped(caller)
                .client_sessions()
                .ensure_sid(&env, &id, "cli_probe", 0)
                .await
            {
                // Minting a sid against a foreign SSO session would be a leak.
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `SessionFleetRepo::get` (issue #32): the management inspect
/// surface. A foreign session's metadata (its subject, its user agent, its lifecycle)
/// must never be readable under the caller's scope.
struct SessionFleetGetProbe;

impl IsolationProbe for SessionFleetGetProbe {
    fn name(&self) -> &'static str {
        "session_fleet.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let fleet = store.scoped(caller).session_fleet();
            let Ok(id) = fleet.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match fleet.get(&id).await {
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `RefreshFamilyFleetRepo::get` (issue #32): refresh-token
/// families are a searchable fleet resource, so a foreign family must be a uniform
/// not-found like every other cross-scope resource.
struct RefreshFamilyFleetGetProbe;

impl IsolationProbe for RefreshFamilyFleetGetProbe {
    fn name(&self) -> &'static str {
        "refresh_family_fleet.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let fleet = store.scoped(caller).refresh_family_fleet();
            let Ok(id) = fleet.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match fleet.get(&id).await {
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `SessionFleetRepo::list` (issue #32): the management LIST
/// surface.
///
/// A list has no identifier to fence on (it returns whatever row-level security lets
/// through), so it is the surface where a broken RLS policy leaks a whole tenant at
/// once rather than one row. The probe lists under the CALLER's scope and fails if a
/// foreign session appears anywhere in the page.
struct SessionFleetListProbe;

impl IsolationProbe for SessionFleetListProbe {
    fn name(&self) -> &'static str {
        "session_fleet.list"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // An unfiltered list: the widest read this surface offers.
            let Ok(page) = store
                .scoped(caller)
                .session_fleet()
                .list(SessionFleetFilter::default(), PROBE_PAGE_LIMIT, None)
                .await
            else {
                return ProbeOutcome::Denied;
            };
            if page.iter().any(|session| session.id == foreign_id) {
                return ProbeOutcome::Leaked;
            }
            ProbeOutcome::Denied
        })
    }
}

/// Built-in probe for `RefreshFamilyFleetRepo::list` (issue #32): the refresh-family
/// LIST surface, fenced the same way as the session list above.
struct RefreshFamilyFleetListProbe;

impl IsolationProbe for RefreshFamilyFleetListProbe {
    fn name(&self) -> &'static str {
        "refresh_family_fleet.list"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let Ok(page) = store
                .scoped(caller)
                .refresh_family_fleet()
                .list(RefreshFamilyFleetFilter::default(), PROBE_PAGE_LIMIT, None)
                .await
            else {
                return ProbeOutcome::Denied;
            };
            if page.iter().any(|family| family.id == foreign_id) {
                return ProbeOutcome::Leaked;
            }
            ProbeOutcome::Denied
        })
    }
}

/// Built-in probe for `ActingSessionRepo::revoke` (issue #32): the single-session
/// fleet revoke. Revoking another tenant's session would be a cross-tenant denial of
/// service, so it must be the uniform not-found.
struct SessionRevokeProbe;

impl IsolationProbe for SessionRevokeProbe {
    fn name(&self) -> &'static str {
        "sessions.revoke"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.scoped(caller).session_fleet().parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .sessions()
                .revoke(&env, &id, SessionEndCause::Revoked, false, None)
                .await
            {
                // Flipping a foreign session would be a leak (a cross-tenant logout).
                Ok(outcome) if outcome.session_flipped => ProbeOutcome::Leaked,
                Ok(_) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingSessionRepo::bulk_revoke` (issue #32). A bulk revoke is
/// the surface where a scope fence is easiest to forget: this hands it a session id
/// carrying its OWN (foreign) declared scope, exactly as an attacker would smuggle
/// one into an otherwise valid batch, and requires it to be a uniform no-op.
struct SessionBulkRevokeProbe;

impl IsolationProbe for SessionBulkRevokeProbe {
    fn name(&self) -> &'static str {
        "sessions.bulk_revoke"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            // Deliberately DO NOT parse under the caller's scope: parse the id under
            // its OWN declared scope, so the typed value reaching the batch really is
            // a foreign session. The repository's scope fence is what must reject it.
            let Ok(id) = SessionId::parse_declared_scope(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .sessions()
                .bulk_revoke(&env, &[id], false, None)
                .await
            {
                // Any flip means the batch reached a session outside the caller's
                // scope.
                Ok(0) | Err(_) => ProbeOutcome::Denied,
                Ok(_) => ProbeOutcome::Leaked,
            }
        })
    }
}

/// Built-in probe for `ActingSessionRepo::revoke_all_for_user` (issue #32): the
/// revoke-everything-for-a-user cascade. Aimed at a foreign user it must be the
/// uniform not-found, never a cross-tenant mass logout.
struct UserSessionsRevokeAllProbe;

impl IsolationProbe for UserSessionsRevokeAllProbe {
    fn name(&self) -> &'static str {
        "sessions.revoke_all"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            // The subject is a user id; parse it under the caller's OWN scope.
            let Ok(subject) = UserId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .sessions()
                .revoke_all_for_user(&env, &subject, false, None)
                .await
            {
                Ok(outcome) if outcome.sessions_revoked > 0 || outcome.families_revoked > 0 => {
                    ProbeOutcome::Leaked
                }
                Ok(_) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `UserRepo::get` (issue #52): a user in another tenant or
/// environment must never be readable under the caller's scope.
struct UserAdminGetProbe;

impl IsolationProbe for UserAdminGetProbe {
    fn name(&self) -> &'static str {
        "users.get"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let users = store.scoped(caller).users();
            let Ok(id) = users.parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            match users.get(&id).await {
                Ok(_) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `UserRepo::list` (issue #52): the list has no identifier to
/// fence on, so it is where a broken isolation policy would leak an entire foreign
/// tenant's users at once. A page must contain no foreign user.
struct UserAdminListProbe;

impl IsolationProbe for UserAdminListProbe {
    fn name(&self) -> &'static str {
        "users.list"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            match store
                .scoped(caller)
                .users()
                .list(UserListFilter::default(), PROBE_PAGE_LIMIT, None)
                .await
            {
                Ok(rows) => {
                    if rows
                        .iter()
                        .any(|record| record.id.to_string() == foreign_id)
                    {
                        ProbeOutcome::Leaked
                    } else {
                        ProbeOutcome::Denied
                    }
                }
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingUserRepo::delete` (issue #52): deleting another
/// tenant's user would be a cross-tenant offboarding, so it must be the uniform
/// not-found.
struct UserAdminDeleteProbe;

impl IsolationProbe for UserAdminDeleteProbe {
    fn name(&self) -> &'static str {
        "users.delete"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.scoped(caller).users().parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .users()
                .delete(&env, &id, false, None)
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingUserRepo::set_state` (issue #52): flipping another
/// tenant's user to a blocked state would be a cross-tenant lifecycle change, so it
/// must be the uniform not-found.
struct UserAdminStateChangeProbe;

impl IsolationProbe for UserAdminStateChangeProbe {
    fn name(&self) -> &'static str {
        "users.set_state"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.scoped(caller).users().parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .users()
                .set_state(&env, &id, UserState::Blocked, None, false, None)
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingUserRepo::link_external_id` (issue #52): linking an
/// external id onto another tenant's user would be a cross-tenant mutation, so it
/// must be the uniform not-found.
struct UserAdminExternalIdLinkProbe;

impl IsolationProbe for UserAdminExternalIdLinkProbe {
    fn name(&self) -> &'static str {
        "users.external_id.link"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.scoped(caller).users().parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .users()
                .link_external_id(&env, &id, "idor-probe-external-id")
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `UserRepo::by_external_id` (issue #52): a lookup by external
/// id must never resolve ANOTHER tenant's user. The external id is a per-tenant
/// blind index, so the read is twice fenced (the index is keyed with the caller's
/// tenant key AND the query filters `tenant_id`/`environment_id`), and any hit on a
/// foreign external-id value is a cross-tenant READ leak. The harness passes a
/// victim's real external-id string as a `foreign_id`, so this probe hunts a foreign
/// row of its own key type rather than being vacuous.
struct UserAdminByExternalIdProbe;

impl IsolationProbe for UserAdminByExternalIdProbe {
    fn name(&self) -> &'static str {
        "users.by_external_id"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            match store
                .scoped(caller)
                .users()
                .by_external_id(foreign_id)
                .await
            {
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingUserRepo::update_claims` (issue #52): patching another
/// tenant's user claims would be a cross-tenant mutation of a PII surface, so it must
/// be the uniform not-found.
struct UserAdminUpdateClaimsProbe;

impl IsolationProbe for UserAdminUpdateClaimsProbe {
    fn name(&self) -> &'static str {
        "users.update_claims"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.scoped(caller).users().parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .users()
                .update_claims(&env, &id, "{\"nickname\":\"idor-probe\"}")
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingUserRepo::unlink_external_id` (issue #52): clearing the
/// external id off another tenant's user would be a cross-tenant mutation, so it must
/// be the uniform not-found.
struct UserAdminExternalIdUnlinkProbe;

impl IsolationProbe for UserAdminExternalIdUnlinkProbe {
    fn name(&self) -> &'static str {
        "users.external_id.unlink"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = store.scoped(caller).users().parse_id(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .users()
                .unlink_external_id(&env, &id)
                .await
            {
                Ok(()) => ProbeOutcome::Leaked,
                Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `UserRepo::state_for_subject` (issue #241): the LIFECYCLE READ
/// the token-minting fences are built on. A foreign subject must read as absent here, or
/// a fence would be evaluating another tenant's account state, and the answer to "may
/// this subject still obtain tokens" would come from the wrong tenant's `users` row.
///
/// Registered because "complete coverage" had been claimed for a set that stopped at the
/// admin surfaces. There was no gap to close (the SQL hard filters `tenant_id` and
/// `environment_id`), and that is precisely why the claim needed a probe rather than a
/// paragraph: an unmeasured guarantee is indistinguishable from a broken one.
struct UserStateForSubjectProbe;

impl IsolationProbe for UserStateForSubjectProbe {
    fn name(&self) -> &'static str {
        "users.state_for_subject"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            match store
                .scoped(caller)
                .users()
                .state_for_subject(foreign_id)
                .await
            {
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `UserRepo::claims_for_subject` (issue #241): the standard-claim
/// document `UserInfo` releases. A foreign subject resolving here would be a cross-tenant
/// PII read, the highest-value one on the user surface.
///
/// Isolated TWICE over, and the probe proves both hold at once: the SQL filters
/// `tenant_id`/`environment_id`, and the sealed claims are opened under a scope-bound AAD
/// (`user_pii_seal_aad(self.scope, ..)`), so even a row reached past the filter would fail
/// to decrypt rather than yield plaintext.
struct UserClaimsForSubjectProbe;

impl IsolationProbe for UserClaimsForSubjectProbe {
    fn name(&self) -> &'static str {
        "users.claims_for_subject"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            match store
                .scoped(caller)
                .users()
                .claims_for_subject(foreign_id)
                .await
            {
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `UserRepo::by_identifier` (issue #241): the LOGIN lookup. A foreign
/// user resolving by its login handle would let one tenant authenticate against another
/// tenant's account, so this is the read with the most direct authentication consequence
/// of the three.
///
/// Its key is a login handle rather than an id, so the harness must be given a victim's
/// real identifier as a `foreign_id` for the probe to hunt a foreign row of its own key
/// type; `users.by_external_id` has the same requirement and the same fixture answers
/// both. Isolated twice over here too: the blind index is a per-scope keyed HMAC, so the
/// caller's scope computes a DIFFERENT index for the same handle, and the SQL filter
/// stands behind that.
struct UserByIdentifierProbe;

impl IsolationProbe for UserByIdentifierProbe {
    fn name(&self) -> &'static str {
        "users.by_identifier"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            match store.scoped(caller).users().by_identifier(foreign_id).await {
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ActingAccountCredentialRepo::remove` (issue #61): the
/// self-service credential removal. A credential id minted in another tenant or
/// environment must be the uniform not-found, never a cross-scope deletion. The id
/// is parsed under its OWN declared scope (as an attacker would smuggle it), so the
/// repository's `id.scope() != self.scope` fence is what must reject it; the subject
/// is a throwaway one in the caller's scope, so only the scope fence can save it.
struct AccountCredentialRemoveProbe;

impl IsolationProbe for AccountCredentialRemoveProbe {
    fn name(&self) -> &'static str {
        "account_credentials.remove"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            let Ok(id) = CredentialId::parse_declared_scope(foreign_id) else {
                return ProbeOutcome::Denied;
            };
            let subject = UserId::generate(&env, &caller);
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .account_credentials()
                .remove(&env, &subject, &id, true, "probe")
                .await
            {
                // Removing a foreign credential would be a cross-tenant deletion.
                Ok(CredentialRemoveOutcome::Removed) => ProbeOutcome::Leaked,
                Ok(_) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// The connector id the upstream-token IDOR probe reads under, and the one a planting
/// helper MUST capture the victim token beneath, so the probe's read is filtered on the
/// SAME connector the victim was captured under (issue #77, PR 3 coherence hardening). If
/// the probe read a different connector the read would return no row for a benign reason
/// (the connector filter, not the scope boundary), making the isolation assertion vacuous;
/// pinning both sides to this one connector keeps ONLY the scope boundary between the
/// probe and the victim token.
pub const UPSTREAM_TOKEN_PROBE_CONNECTOR: &str = "cnr_probe";

/// Built-in probe for `ActingUpstreamTokenRepo::read_for_session` (issue #77, PR 3): a
/// session's captured upstream tokens must never resolve under another tenant or
/// environment's scope. The `foreign_id` is a session id planted in another scope; it is
/// parsed under the caller's OWN scope (a cross-scope id fails there as a uniform
/// not-found), so a resolved token row would be a genuine cross-tenant leak of the
/// upstream access and refresh tokens. Run with the data-plane store (`ironauth_app`).
struct UpstreamTokenReadProbe;

impl IsolationProbe for UpstreamTokenReadProbe {
    fn name(&self) -> &'static str {
        "upstream_tokens.read_for_session"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            let env = Env::system();
            // Parse the untrusted session id under the caller's OWN scope; a session
            // minted in another scope fails here as a uniform not-found.
            let Ok(session_id) = SessionId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            let actor = ActorRef::service(ServiceId::generate(&env));
            let correlation = CorrelationId::generate(&env);
            match store
                .scoped(caller)
                .acting(actor, correlation)
                .upstream_tokens()
                .read_for_session(&env, &session_id, UPSTREAM_TOKEN_PROBE_CONNECTOR)
                .await
            {
                // Resolving a foreign session's captured tokens would be a leak.
                Ok(Some(_)) => ProbeOutcome::Leaked,
                Ok(None) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `RiskSignalRepo::fresh_signals_for_subject` (issue #82, PR 1): a
/// subject's ingested external risk signals must never be readable under another tenant or
/// environment's scope, or the #79 engine could fold a FOREIGN tenant's signals into a
/// login decision. The read is keyed on the subject (a `usr_` id), so the probe's
/// `foreign_id` is a subject planted in another scope: it must parse as a uniform not-found
/// (or resolve to no row) under the caller's scope.
struct RiskSignalReadProbe;

impl IsolationProbe for RiskSignalReadProbe {
    fn name(&self) -> &'static str {
        "risk_signals.fresh_signals_for_subject"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // Parse the untrusted subject id under the caller's OWN scope; a subject minted
            // in another scope fails here as a uniform not-found.
            let Ok(subject) = UserId::parse_in_scope(foreign_id, &caller) else {
                return ProbeOutcome::Denied;
            };
            match store
                .scoped(caller)
                .risk_signals()
                .fresh_signals_for_subject(&subject, 100)
                .await
            {
                // Reading a foreign subject's ingested signals would be a leak.
                Ok(signals) if !signals.is_empty() => ProbeOutcome::Leaked,
                Ok(_) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built-in probe for `ClientAuthDiagnosticsRepo::query` (issue #91): a client's recorded
/// authentication-failure diagnostics must never be readable under another tenant or
/// environment's scope, or the M9 admin flow inspector would leak which foreign clients were
/// failing to authenticate. The read is keyed on the CLIENT ID (a plain string filter, not a
/// scoped-parsed id), so the probe's `foreign_id` is a client id whose diagnostics were planted
/// in another scope: the scoped, forced-RLS query must resolve to no rows under the caller's
/// scope.
struct ClientAuthDiagnosticReadProbe;

impl IsolationProbe for ClientAuthDiagnosticReadProbe {
    fn name(&self) -> &'static str {
        "client_auth_diagnostics.query"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // The client id is a plain string filter (no scoped id to parse): the forced RLS
            // and the (tenant, environment) predicates confine the read to the caller's scope,
            // so a foreign client's diagnostics resolve to no rows here.
            match store
                .scoped(caller)
                .client_auth_diagnostics()
                .query(crate::repository::ClientAuthDiagnosticQuery {
                    client_id: Some(foreign_id),
                    ..Default::default()
                })
                .await
            {
                // Reading a foreign client's recorded diagnostics would be a leak.
                Ok(rows) if !rows.is_empty() => ProbeOutcome::Leaked,
                Ok(_) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}

/// Built in probe for `PolicyDecisionTracesRepo::query` (issue #91). The M9 admin flow
/// inspector reads recorded policy decision traces scoped to a (tenant, environment); a
/// subject whose traces were planted in another scope must resolve to no rows under the
/// caller's scope: the forced RLS and the scope predicates confine the read.
struct PolicyDecisionTraceReadProbe;

impl IsolationProbe for PolicyDecisionTraceReadProbe {
    fn name(&self) -> &'static str {
        "policy_decision_traces.query"
    }

    fn probe<'a>(
        &'a self,
        store: &'a Store,
        caller: Scope,
        foreign_id: &'a str,
    ) -> BoxProbeFuture<'a> {
        Box::pin(async move {
            // The subject is a plain string filter (no scoped id to parse): the forced RLS
            // and the (tenant, environment) predicates confine the read to the caller's
            // scope, so a foreign subject's traces resolve to no rows here.
            match store
                .scoped(caller)
                .policy_decision_traces()
                .query(crate::repository::PolicyDecisionTraceQuery {
                    subject: Some(foreign_id),
                    ..Default::default()
                })
                .await
            {
                // Reading a foreign subject's recorded traces would be a leak.
                Ok(rows) if !rows.is_empty() => ProbeOutcome::Leaked,
                Ok(_) | Err(_) => ProbeOutcome::Denied,
            }
        })
    }
}
