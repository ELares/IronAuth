// SPDX-License-Identifier: MIT OR Apache-2.0

//! Persistence and tenant isolation layer for IronAuth.
//!
//! Cross-tenant access is the top CVE class for a multi-tenant identity
//! provider: the surveyed field ships isolation by convention (authorization
//! checked per handler) and pays for it in the IDOR family, recycled-identifier
//! leakage, and cross-organization escalation. This crate ships isolation by
//! construction instead, in three layers that all sit BELOW the application:
//!
//! 1. **Typed scoped identifiers.** Every identifier is a non-guessable,
//!    non-recyclable, typed-prefixed token. A scoped resource identifier
//!    ([`ClientId`]) embeds its tenant and environment, so parsing one under the
//!    wrong [`Scope`] fails as a uniform not-found with no existence oracle.
//! 2. **Scope-only repositories.** A repository ([`ClientRepo`]) can only be
//!    built from a [`Scope`] (via [`Store::scoped`]) and applies that scope to
//!    every query itself. The pool and the scoped tables are crate-private, so
//!    no other crate can issue an unscoped query; `scripts/query-audit.sh`
//!    fails the build if scoped-table SQL appears outside the repository
//!    module.
//! 3. **Row-level security** (the migration). Every tenant-scoped table has
//!    Postgres row-level security ENABLED and FORCED, keyed on the
//!    transaction-local session variables the repository binds. Even a bug in
//!    the application layer cannot read another tenant's rows.
//!
//! Postgres relations are the sole source of truth (normalized tables, foreign
//! keys enforced, explicitly not event sourced; see
//! `docs/adr/0002-relational-primary-store.md`). Two facilities build on the
//! isolation substrate:
//!
//! - a **same-transaction audit log**: every repository mutation writes exactly
//!   one [`audit`] row in the same transaction as the data change, through the
//!   one audited-write primitive in the repository layer, so a mutation without
//!   an audit row is structurally impossible and a failed mutation leaves no
//!   trace;
//! - an **expand-contract migration runner** ([`MigrationRunner`]): the tracked,
//!   checksummed, in-order schema evolution that later makes zero-downtime
//!   upgrades achievable.
//!
//! The four-level resource model (operator, tenant, environment, organization)
//! and the reasoning behind the pooled shared-schema design are recorded in
//! `docs/design/TENANCY.md`. Time and entropy flow through
//! [`ironauth_env`]; identifiers draw randomness only from its entropy seam, and
//! audit timestamps from its clock seam.
//!
//! Only the runtime sqlx query API is used (never the compile-time-checked
//! `query!` macros), so every database-free CI lane stays database-free; a live
//! database is needed only to run the integration tests.

pub mod audit;
mod error;
mod id;
mod migrate;
mod redirect;
mod repository;
mod scope;
mod store;

/// The reusable cross-tenant IDOR test harness. Present only under the
/// `testing` feature; every future surface registers its operations here.
#[cfg(feature = "testing")]
pub mod idor_harness;

/// The real-database test harness (driven by `DATABASE_URL`). Present only
/// under the `testing` feature.
#[cfg(feature = "testing")]
pub mod test_support;

pub use audit::{ActingContext, Action, ActorRef};
pub use error::StoreError;
pub use id::{
    AgentId, AgentKind, AuditId, AuditKind, AuditTarget, AuthorizationCodeId,
    AuthorizationCodeKind, COMPONENT_BYTES, ClientId, ClientKind, ConsentId, ConsentKind,
    CorrelationId, CorrelationKind, EnvironmentId, EnvironmentKind, GrantId, GrantKind, HumanId,
    HumanKind, IdParseError, IssuedTokenId, IssuedTokenKind, LevelId, LevelKind, ManagementKeyId,
    ManagementKeyKind, NotInScope, OperatorId, OperatorKind, OrganizationId, OrganizationKind,
    PushedRequestId, PushedRequestKind, RefreshFamilyId, RefreshFamilyKind, RefreshTokenId,
    RefreshTokenKind, ResourceServerId, ResourceServerKind, ScopedId, ScopedKind, ServiceId,
    ServiceKind, SessionId, SessionKind, SigningKeyId, SigningKeyKind, TenantId, TenantKind,
    UserId, UserKind,
};
pub use migrate::{Migration, MigrationError, MigrationReport, MigrationRunner, Phase};
pub use redirect::{redirect_uri_is_registrable, redirect_uri_matches};
pub use repository::{
    AccessTokenResolution, ActingAuthorizationRepo, ActingClientRepo, ActingConsentRepo,
    ActingEnvironmentRepo, ActingManagementCredentialRepo, ActingManagementStore,
    ActingPushedRequestRepo, ActingRefreshRepo, ActingResourceServerRepo, ActingSessionRepo,
    ActingSigningKeyRepo, ActingStore, ActingTenantRepo, ActingUserRepo, ActiveOpaqueToken,
    AuditRecord, AuditRepo, AuthorizationRepo, ClientAssertionJtiRepo, ClientAuthDiagnosticReason,
    ClientAuthDiagnosticRecord, ClientAuthDiagnosticsRepo, ClientAuthRecord, ClientRecord,
    ClientRepo, CodeBindings, ConsentRepo, ConsumePushedRequest, CursorPosition,
    DynamicClientRecord, DynamicClientRegistration, DynamicClientUpdate, EnvironmentRecord,
    EnvironmentRepo, GrantedConsent, IdempotencyRepo, IdempotencyWrite, IssueCode,
    IssuedTokenRecord, JtiOutcome, MANAGEMENT_LIST_HARD_CAP, ManagementCredentialRecord,
    ManagementCredentialRepo, ManagementStore, NewClientAuthDiagnostic, NewDynamicClient,
    NewJwtAuthClient, NewOpaqueAccessToken, NewRefreshFamily, NewResourceServer, NewSigningKey,
    PushRequest, PushedRequestRepo, RedeemOutcome, RefreshRedeem, RefreshRedeemOutcome,
    RefreshRepo, RefreshTokenResolution, ResourceServerRecord, ResourceServerRepo,
    RotatedRefreshToken, ScopedStore, SessionRecord, SessionRepo, SigningKeyMaterial,
    SigningKeyMaterialKind, SigningKeyRecord, SigningKeyRepo, StoredIdempotentResponse,
    TenantRecord, TenantRepo, TokenFormat, TokenKind, TokenStatus, UserRecord, UserRepo,
    opaque_access_token_digest, refresh_token_digest,
};
pub use scope::Scope;
pub use store::Store;
