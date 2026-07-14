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
use crate::id::{CorrelationId, GrantId, IssuedTokenId, ServiceId, SigningKeyId};
use crate::repository::{RedeemOutcome, TokenStatus};
use crate::scope::Scope;
use crate::store::Store;

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

    /// Register the management-plane probes (issue #11): the scoped-resource
    /// resolve-by-id operations of the management API. Today that is the
    /// environment-scoped management-credential repository:
    /// `management_credentials.get` and `management_credentials.delete`.
    ///
    /// Run these with a store whose pool authenticates as `ironauth_control`
    /// (the data-plane role has no grant on `management_credentials`); a
    /// control-plane store is what [`crate::test_support::TestDatabase::control_store`]
    /// hands back. As every management resource endpoint lands, its probe is
    /// registered here so the harness covers it in CI.
    pub fn register_management_probes(&mut self) -> &mut Self {
        self.register(Box::new(ManagementCredentialGetProbe));
        self.register(Box::new(ManagementCredentialDeleteProbe));
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
