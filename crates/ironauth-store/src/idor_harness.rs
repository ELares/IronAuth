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
    CorrelationId, GrantId, IssuedTokenId, ServiceId, SessionId, SigningKeyId, UserId,
};
use crate::repository::{
    RedeemOutcome, RefreshFamilyFleetFilter, SessionEndCause, SessionFleetFilter, TokenStatus,
    UserListFilter, UserState,
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
    /// `organizations.delete`), the two-thirds of the four-level resource model
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

    /// Register the admin user-management probes (issue #52): every management-plane
    /// user surface that resolves a user by identifier. The set is the read surfaces
    /// (`users.get`, `users.list`) and the mutating surfaces (`users.delete`,
    /// `users.set_state`, `users.external_id.link`). A foreign user must be the
    /// uniform not-found on every one, and the list surface must never leak a foreign
    /// tenant's users. Run these with a store that carries the platform master key
    /// (the user PII paths fail closed without it).
    pub fn register_user_admin_probes(&mut self) -> &mut Self {
        self.register(Box::new(UserAdminGetProbe));
        self.register(Box::new(UserAdminListProbe));
        self.register(Box::new(UserAdminByExternalIdProbe));
        self.register(Box::new(UserAdminDeleteProbe));
        self.register(Box::new(UserAdminStateChangeProbe));
        self.register(Box::new(UserAdminUpdateClaimsProbe));
        self.register(Box::new(UserAdminExternalIdLinkProbe));
        self.register(Box::new(UserAdminExternalIdUnlinkProbe));
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
