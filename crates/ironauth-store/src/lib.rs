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
pub mod classification;
pub mod custom_domain;
pub mod environment;
mod error;
pub mod esv;
mod id;
pub mod identifier;
mod migrate;
pub mod promotion;
mod redirect;
mod repository;
mod scope;
pub mod snapshot;
mod store;
pub mod trait_schema;

/// The reusable cross-tenant IDOR test harness. Present only under the
/// `testing` feature; every future surface registers its operations here.
#[cfg(feature = "testing")]
pub mod idor_harness;

/// The real-database test harness (driven by `DATABASE_URL`). Present only
/// under the `testing` feature.
#[cfg(feature = "testing")]
pub mod test_support;

pub use audit::{ActingContext, Action, ActorRef};
pub use classification::{ResourceClassification, ResourceLevel, ResourceType, classify};
pub use custom_domain::{
    AcmeChallengeRecord, ChallengeOutcome, ChallengeStatus, ChallengeType, CustomDomainError,
    CustomDomainRecord, VerificationStatus, domain_is_registrable, normalize_domain,
};
pub use environment::{
    EnvironmentType, Guardrail, GuardrailClass, GuardrailReport, GuardrailSet, GuardrailViolation,
    UnknownEnvironmentType,
};
pub use error::StoreError;
pub use esv::{
    MAX_NAME_LEN, Reference, ReferenceError, ReferenceKind, ResolveError, Resolved, name_is_valid,
    reference_resolves, resolve_value,
};
pub use id::{
    AcmeChallengeId, AcmeChallengeKind, AgentId, AgentKind, AssertionMappingId,
    AssertionMappingKind, AuditId, AuditKind, AuditTarget, AuthorizationCodeId,
    AuthorizationCodeKind, BackChannelDeliveryId, BackChannelDeliveryKind, COMPONENT_BYTES,
    ClientId, ClientKind, ClientSessionId, ClientSessionKind, ConsentId, ConsentKind,
    CorrelationId, CorrelationKind, CredentialId, CredentialKind, CustomDomainId, CustomDomainKind,
    DcrPolicyId, DcrPolicyKind, DekId, DekKind, DeviceCodeId, DeviceCodeKind, EncryptedSecretId,
    EncryptedSecretKind, EnvironmentId, EnvironmentKind, EnvironmentSecretId,
    EnvironmentSecretKind, ExternalIssuerId, ExternalIssuerKind, GrantId, GrantKind, HumanId,
    HumanKind, IdParseError, InitialAccessTokenId, InitialAccessTokenKind, InvitationId,
    InvitationKind, IssuedTokenId, IssuedTokenKind, KekId, KekKind, LevelId, LevelKind,
    ManagementKeyId, ManagementKeyKind, NotInScope, OperatorId, OperatorKind, OrganizationId,
    OrganizationKind, PushedRequestId, PushedRequestKind, RefreshFamilyId, RefreshFamilyKind,
    RefreshTokenId, RefreshTokenKind, ResourceServerId, ResourceServerKind, ScopedId, ScopedKind,
    ServiceAccountId, ServiceAccountKind, ServiceId, ServiceKind, SessionEventId, SessionEventKind,
    SessionId, SessionKind, SigningKeyId, SigningKeyKind, TenantId, TenantKind,
    TraitMigrationJobId, TraitMigrationJobKind, TraitSchemaId, TraitSchemaKind, UserId,
    UserIdentifierId, UserIdentifierKind, UserKind, VariableId, VariableKind,
};
pub use identifier::{
    CanonicalIdentifier, IdentifierType, UniquenessMode, canonicalize_identifier,
};
pub use migrate::{Migration, MigrationError, MigrationReport, MigrationRunner, Phase};
pub use promotion::{
    ChangeKind, ConfigDiff, PROMOTED_RESOURCE_TYPES, Plan, PlanError, PromotionApplyError,
    PromotionOutcome, ResourceChange, collect_references, diff as diff_snapshots, evaluate_plan,
    plan_promotion, revision as promotion_revision,
};
pub use redirect::{redirect_uri_is_registrable, redirect_uri_matches};
pub use repository::{
    AcceptedInvitation, AccessTokenResolution, AccountCredentialRepo, AccountCredentialSummary,
    ActingAccountCredentialRepo, ActingAssertionSubjectMappingRepo, ActingAuthorizationRepo,
    ActingClientRepo, ActingConsentRepo, ActingCustomDomainRepo, ActingDcrPolicyRepo,
    ActingDeviceCodeRepo, ActingEnvelopeRepo, ActingEnvironmentRepo, ActingEnvironmentSecretRepo,
    ActingEnvironmentVariableRepo, ActingExternalAssertionIssuerRepo, ActingInitialAccessTokenRepo,
    ActingInvitationRepo, ActingManagementCredentialRepo, ActingManagementStore,
    ActingOrganizationRepo, ActingPushedRequestRepo, ActingRefreshRepo, ActingResourceServerRepo,
    ActingServiceAccountRepo, ActingSessionRepo, ActingSigningKeyRepo, ActingStore,
    ActingTenantRepo, ActingTraitMigrationJobRepo, ActingTraitSchemaRepo, ActingUserIdentifierRepo,
    ActingUserRepo, ActiveDeviceFlow, ActiveOpaqueToken, ApprovedDeviceGrant,
    AssertionSubjectMappingRecord, AssertionSubjectMappingRepo, AuditRecord, AuditRepo,
    AuthorizationRepo, BackChannelDeliveryRepo, ByokBinding, ClientAssertionJtiRepo,
    ClientAuthDiagnosticReason, ClientAuthDiagnosticRecord, ClientAuthDiagnosticsRepo,
    ClientAuthRecord, ClientCredentialsAccess, ClientRecord, ClientRepo, ClientResourcePolicy,
    ClientSessionRepo, CodeBindings, ConsentRepo, ConsumePushedRequest, ConsumedInitialAccessToken,
    CredentialRemoveOutcome, CredentialType, CursorPosition, CustomDomainRepo, DcrPolicyRecord,
    DcrPolicyRepo, DcrRateLimiterRepo, DeviceApproval, DeviceApproveOutcome, DeviceAttemptOutcome,
    DeviceClientProfile, DeviceCodeRepo, DevicePollOutcome, DeviceRedeemOutcome,
    DeviceUserCodeLookup, DynamicClientRecord, DynamicClientRegistration, DynamicClientUpdate,
    EnvelopeRepo, EnvironmentGuardrailRepo, EnvironmentRecord, EnvironmentRepo,
    EnvironmentSecretMetadata, EnvironmentSecretRepo, EnvironmentServingState,
    EnvironmentVariableRecord, EnvironmentVariableRepo, ExportedCredential,
    ExternalAssertionIssuerRecord, ExternalAssertionIssuerRepo, ExternalAssertionJtiRepo,
    FrontchannelLogoutParticipant, GrantOwner, GrantedConsent, INVITATION_TOKEN_PREFIX,
    IdempotencyRepo, IdempotencyWrite, IdentifierCollision, IdentifierResolution,
    InitialAccessTokenRepo, InvitationAdminRecord, InvitationCredentialType, InvitationListFilter,
    InvitationRepo, InvitationState, IssueClientCredentials, IssueCode, IssuedTokenRecord,
    JtiOutcome, LoginMethod, LogoutDelivery, MANAGEMENT_LIST_HARD_CAP, ManagementCredentialRecord,
    ManagementCredentialRepo, ManagementStore, MigrationProgress, MintedInvitationToken,
    NewAdminUser, NewAssertionSubjectMapping, NewClientAuthDiagnostic, NewDcrPolicy, NewDeviceCode,
    NewDynamicClient, NewEnvironment, NewExternalAssertionIssuer, NewInitialAccessToken,
    NewInvitation, NewJwtAuthClient, NewOpaqueAccessToken, NewRefreshFamily, NewResourceServer,
    NewSession, NewSigningKey, NewTraitMigrationJob, NewUserIdentifier, OperatorRecord,
    OperatorRepo, OrganizationRecord, OrganizationRepo, PendingInvitation, PriorSessionOutcome,
    PushRequest, PushedRequestRepo, RecordFailure, RedeemOutcome, RefreshFamilyFleetFilter,
    RefreshFamilyFleetRepo, RefreshFamilyOpenOutcome, RefreshFamilySummary, RefreshRedeem,
    RefreshRedeemOutcome, RefreshRepo, RefreshTokenResolution, ResourceServerRecord,
    ResourceServerRepo, RotatedRefreshToken, ScopedStore, ServiceAccountRepo, SessionEndCause,
    SessionEndedEvent, SessionEventOutboxRepo, SessionFleetFilter, SessionFleetRepo, SessionRecord,
    SessionRepo, SessionRevocation, SessionSummary, SigningKeyMaterial, SigningKeyMaterialKind,
    SigningKeyRecord, SigningKeyRepo, StoredIdempotentResponse, TenantRecord, TenantRepo,
    TenantStatus, TokenFormat, TokenKind, TokenStatus, TraitJobKind, TraitJobStatus,
    TraitMigrationJob, TraitMigrationJobRepo, TraitSchemaRepo, TraitSchemaVersion, UserAdminRecord,
    UserExportRecord, UserIdentifierRecord, UserIdentifierRepo, UserListFilter, UserRecord,
    UserRepo, UserRevocation, UserState, device_code_digest, invitation_token_digest,
    mint_invitation_token, mint_invitation_token_for, opaque_access_token_digest,
    refresh_token_digest, user_code_hash,
};
pub use scope::Scope;
pub use snapshot::{
    CLIENT_SECRET_REFERENCE, ClientSnapshot, DcrPolicySnapshot, ResourceServerSnapshot,
    SNAPSHOT_RESOURCE_TYPES, SNAPSHOT_SCHEMA_VERSION, SecretRef, Snapshot, SnapshotResources,
    SnapshotViolation, VariableSnapshot, classification_coverage_gaps, export as export_snapshot,
    validate_document,
};
pub use store::Store;
pub use trait_schema::{
    MAX_DEPTH as TRAIT_SCHEMA_MAX_DEPTH, SchemaError, TraitAnnotations, TraitSchema, TransformOp,
    ValidationFailure, Visibility, apply_transform, parse_transform,
};
