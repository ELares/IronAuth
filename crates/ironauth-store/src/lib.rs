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

pub mod abuse;
pub mod audit;
pub mod classification;
pub mod connector;
pub mod custom_domain;
pub mod email_otp;
pub mod environment;
mod error;
pub mod esv;
pub mod federation_state;
mod id;
pub mod identifier;
mod migrate;
pub mod pow_challenge;
pub mod promotion;
pub mod recovery;
mod redirect;
mod repository;
pub mod risk;
mod scope;
pub mod sms_otp;
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

pub use abuse::{AbuseBanView, AbuseSubject, AbuseSubjectKind, AuthPath, NewBan};
pub use audit::{ActingContext, Action, ActorRef};
pub use classification::{ResourceClassification, ResourceLevel, ResourceType, classify};
pub use connector::{ConnectorCapabilities, ConnectorRecord, NewConnector, StoredCapabilities};
pub use custom_domain::{
    AcmeChallengeRecord, ChallengeOutcome, ChallengeStatus, ChallengeType, CustomDomainError,
    CustomDomainRecord, VerificationStatus, domain_is_registrable, normalize_domain,
};
pub use email_otp::{
    ActiveEmailOtpCode, EmailFactorPurpose, MagicLinkChallenge, MagicLinkConsumeOutcome,
    NewEmailOtpCode, NewMagicLink, OtpAttemptOutcome,
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
pub use federation_state::{ConsumedFederationLoginState, NewFederationLoginState};
pub use id::{
    AbuseBanId, AbuseBanKind, AccountLinkId, AccountLinkKind, AcmeChallengeId, AcmeChallengeKind,
    AdminSudoElevationId, AdminSudoElevationKind, AgentId, AgentKind, AssertionMappingId,
    AssertionMappingKind, AttestationConfigId, AttestationConfigKind, AuditId, AuditKind,
    AuditTarget, AuthorizationCodeId, AuthorizationCodeKind, BackChannelDeliveryId,
    BackChannelDeliveryKind, COMPONENT_BYTES, ClientId, ClientKind, ClientSessionId,
    ClientSessionKind, ConnectorId, ConnectorKind, ConsentId, ConsentKind, CorrelationId,
    CorrelationKind, CredentialClassPolicyId, CredentialClassPolicyKind, CredentialId,
    CredentialKind, CustomDomainId, CustomDomainKind, DcrPolicyId, DcrPolicyKind, DekId, DekKind,
    DeviceCodeId, DeviceCodeKind, EmailOtpCodeId, EmailOtpCodeKind, EncryptedSecretId,
    EncryptedSecretKind, EnvironmentId, EnvironmentKind, EnvironmentSecretId,
    EnvironmentSecretKind, ExternalIssuerId, ExternalIssuerKind, FedcmNonceId, FedcmNonceKind,
    FederationLoginStateId, FederationLoginStateKind, GrantId, GrantKind, HumanId, HumanKind,
    IdParseError, InitialAccessTokenId, InitialAccessTokenKind, InvitationId, InvitationKind,
    IssuedTokenId, IssuedTokenKind, KekId, KekKind, LevelId, LevelKind, MagicLinkTokenId,
    MagicLinkTokenKind, ManagementKeyId, ManagementKeyKind, MigrationRunId, MigrationRunKind,
    MigrationRunRecordId, MigrationRunRecordKind, NotInScope, OperatorId, OperatorKind,
    OrgConnectionId, OrgConnectionKind, OrganizationId, OrganizationKind, PowChallengeId,
    PowChallengeKind, PushedRequestId, PushedRequestKind, RecoveryCodeId, RecoveryCodeKind,
    RecoveryFlowId, RecoveryFlowKind, RefreshFamilyId, RefreshFamilyKind, RefreshTokenId,
    RefreshTokenKind, ResourceServerId, ResourceServerKind, RiskDecisionId, RiskDecisionKind,
    RiskDisavowalId, RiskDisavowalKind, RiskLoginGeoId, RiskLoginGeoKind, RiskSignalId,
    RiskSignalKind, RoutingRuleId, RoutingRuleKind, ScopeStepUpPolicyId, ScopeStepUpPolicyKind,
    ScopedId, ScopedKind, ServiceAccountId, ServiceAccountKind, ServiceId, ServiceKind,
    SessionEventId, SessionEventKind, SessionId, SessionKind, SigningKeyId, SigningKeyKind,
    SmsOtpCodeId, SmsOtpCodeKind, SmsRouteStatId, SmsRouteStatKind, TenantId, TenantKind,
    TotpCredentialId, TotpCredentialKind, TraitMigrationJobId, TraitMigrationJobKind,
    TraitSchemaId, TraitSchemaKind, TrustedDeviceId, TrustedDeviceKind, UpstreamTokenGrantId,
    UpstreamTokenGrantKind, UpstreamTokenId, UpstreamTokenKind, UserId, UserIdentifierId,
    UserIdentifierKind, UserKind, VariableId, VariableKind, WebauthnChallengeId,
    WebauthnChallengeKind, WebauthnCredentialId, WebauthnCredentialKind,
};
pub use identifier::{
    CanonicalIdentifier, IdentifierType, UniquenessMode, canonicalize_identifier,
    normalize_routing_domain,
};
pub use migrate::{Migration, MigrationError, MigrationReport, MigrationRunner, Phase};
pub use pow_challenge::{NewPowChallenge, PowChallengeView};
pub use promotion::{
    ChangeKind, ConfigDiff, PROMOTED_RESOURCE_TYPES, Plan, PlanError, PromotionApplyError,
    PromotionOutcome, ResourceChange, collect_references, diff as diff_snapshots, evaluate_plan,
    plan_promotion, revision as promotion_revision,
};
pub use recovery::{
    NewRecoveryFlow, RecoveryCancelReason, RecoveryEntryPoint, RecoveryFlowRecord, RecoveryState,
};
pub use redirect::{redirect_uri_is_registrable, redirect_uri_matches};
pub use repository::{
    AbuseRepo, AcceptedInvitation, AccessTokenResolution, AccountCredentialRepo,
    AccountCredentialSummary, AccountLinkMethod, AccountLinkRecord, AccountLinkRepo,
    ActingAbuseRepo, ActingAccountCredentialRepo, ActingAccountLinkRepo,
    ActingAdminSudoElevationRepo, ActingAssertionSubjectMappingRepo, ActingAttestationConfigRepo,
    ActingAuthorizationRepo, ActingClientRepo, ActingConsentRepo, ActingCredentialClassPolicyRepo,
    ActingCustomDomainRepo, ActingDcrPolicyRepo, ActingDeviceCodeRepo, ActingEnvelopeRepo,
    ActingEnvironmentRepo, ActingEnvironmentSecretRepo, ActingEnvironmentVariableRepo,
    ActingExternalAssertionIssuerRepo, ActingFedcmNonceRepo, ActingInitialAccessTokenRepo,
    ActingInvitationRepo, ActingManagementCredentialRepo, ActingManagementStore,
    ActingMigrationRunRepo, ActingOrgConnectionRepo, ActingOrganizationRepo,
    ActingPushedRequestRepo, ActingRecoveryCodeRepo, ActingRefreshRepo, ActingResourceServerRepo,
    ActingRoutingRuleRepo, ActingScopeStepUpPolicyRepo, ActingServiceAccountRepo,
    ActingSessionRepo, ActingSigningKeyRepo, ActingSmsOtpRepo, ActingStore, ActingTenantRepo,
    ActingTotpCredentialRepo, ActingTraitMigrationJobRepo, ActingTraitSchemaRepo,
    ActingTrustedDeviceRepo, ActingUpstreamTokenGrantRepo, ActingUpstreamTokenRepo,
    ActingUserIdentifierRepo, ActingUserRepo, ActingWebauthnCredentialRepo, ActiveDeviceFlow,
    ActiveOpaqueToken, AdminSudoElevation, AdminSudoElevationRepo, ApprovedDeviceGrant,
    AssertionSubjectMappingRecord, AssertionSubjectMappingRepo, AttestationConfig,
    AttestationConfigRepo, AuditRecord, AuditRepo, AuthorizationRepo, BackChannelDeliveryRepo,
    ByokBinding, ClientAssertionJtiRepo, ClientAuthDiagnosticReason, ClientAuthDiagnosticRecord,
    ClientAuthDiagnosticsRepo, ClientAuthRecord, ClientCredentialsAccess, ClientRecord, ClientRepo,
    ClientResourcePolicy, ClientSessionRepo, CodeBindings, CompletionOutcome, ConsentRepo,
    ConsumePushedRequest, ConsumedChallenge, ConsumedInitialAccessToken, CredentialClassPolicy,
    CredentialClassPolicyRepo, CredentialRemoveOutcome, CredentialType, CursorPosition,
    CustomDomainRepo, DcrPolicyRecord, DcrPolicyRepo, DcrRateLimiterRepo, DeviceApproval,
    DeviceApproveOutcome, DeviceAttemptOutcome, DeviceClientProfile, DeviceCodeRepo,
    DevicePollOutcome, DeviceRedeemOutcome, DeviceUserCodeLookup, DynamicClientRecord,
    DynamicClientRegistration, DynamicClientUpdate, EnvelopeRepo, EnvironmentGuardrailRepo,
    EnvironmentRecord, EnvironmentRepo, EnvironmentSecretMetadata, EnvironmentSecretRepo,
    EnvironmentServingState, EnvironmentVariableRecord, EnvironmentVariableRepo,
    ExportedCredential, ExportedRecoveryCode, ExportedTotp, ExternalAssertionIssuerRecord,
    ExternalAssertionIssuerRepo, ExternalAssertionJtiRepo, FedcmNonceRepo, FirstPasswordOutcome,
    FrontchannelLogoutParticipant, GrantOwner, GrantedConsent, INVITATION_TOKEN_PREFIX,
    IdempotencyRepo, IdempotencyWrite, IdentifierCollision, IdentifierResolution,
    InitialAccessTokenRepo, InvariantEvaluation, InvariantKind, InvitationAdminRecord,
    InvitationCredentialType, InvitationListFilter, InvitationRepo, InvitationState,
    IssueClientCredentials, IssueCode, IssuedChallenge, IssuedTokenRecord, JtiOutcome, LoginMethod,
    LogoutDelivery, MANAGEMENT_LIST_HARD_CAP, ManagementCredentialRecord, ManagementCredentialRepo,
    ManagementStore, MigrationKind, MigrationProgress, MigrationRecordOutcome, MigrationRun,
    MigrationRunRepo, MigrationRunTallies, MigrationState, MintedInvitationToken, NewAccountLink,
    NewAdminUser, NewAssertionSubjectMapping, NewClientAuthDiagnostic, NewDcrPolicy, NewDeviceCode,
    NewDynamicClient, NewEnvironment, NewExternalAssertionIssuer, NewInitialAccessToken,
    NewInvitation, NewJwtAuthClient, NewMigrationRun, NewOpaqueAccessToken, NewOrgConnection,
    NewRecoveryCode, NewRefreshFamily, NewResourceServer, NewRoutingRule, NewSession,
    NewSigningKey, NewTotpEnrollment, NewTraitMigrationJob, NewTrustedDevice,
    NewUpstreamTokenGrant, NewUpstreamTokens, NewUserIdentifier, NewWebauthnCredential,
    OffendingRecord, OperatorRecord, OperatorRepo, OrgConnectionRecord, OrgConnectionRepo,
    OrganizationRecord, OrganizationRepo, PasswordRemovalOutcome, PendingInvitation,
    PriorSessionOutcome, PushRequest, PushedRequestRepo, RecordFailure, RecordOutcomeInput,
    RecoveryCodeCandidate, RecoveryCodeRepo, RecoveryRedeemOutcome, RedeemOutcome,
    RefreshFamilyFleetFilter, RefreshFamilyFleetRepo, RefreshFamilyOpenOutcome,
    RefreshFamilySummary, RefreshRedeem, RefreshRedeemOutcome, RefreshRepo, RefreshTokenResolution,
    ResourceServerRecord, ResourceServerRepo, RestoredRecoveryCode, RestoredTotp,
    RotatedRefreshToken, RoutingRuleRecord, RoutingRuleRepo, RoutingSelector, ScopeStepUpPolicy,
    ScopeStepUpPolicyRepo, ScopedStore, ServiceAccountRepo, SessionEndCause, SessionEndedEvent,
    SessionEventOutboxRepo, SessionFleetFilter, SessionFleetRepo, SessionRecord, SessionRepo,
    SessionRevocation, SessionSummary, SigningKeyMaterial, SigningKeyMaterialKind,
    SigningKeyRecord, SigningKeyRepo, SmsOtpRepo, StoredIdempotentResponse, TenantRecord,
    TenantRepo, TenantStatus, TokenFormat, TokenKind, TokenStatus, TotpActivateOutcome,
    TotpCredentialRepo, TotpCredentialSummary, TotpMaterial, TotpVerifyOutcome, TraitJobKind,
    TraitJobStatus, TraitMigrationJob, TraitMigrationJobRepo, TraitSchemaRepo, TraitSchemaVersion,
    TrustedDeviceRepo, TrustedDeviceRevokeReason, TrustedDeviceSummary, UnlinkOutcome,
    UpstreamToken, UpstreamTokenGrantRecord, UpstreamTokenGrantRepo, UpstreamTokenMaterial,
    UserAdminRecord, UserExportRecord, UserIdentifierRecord, UserIdentifierRepo, UserListFilter,
    UserRecord, UserRepo, UserRevocation, UserState, WEBAUTHN_CHALLENGE_TTL_SECS,
    WebauthnAssertionTarget, WebauthnCeremony, WebauthnChallengeRepo, WebauthnCredentialDescriptor,
    WebauthnCredentialOutcome, WebauthnCredentialRecord, WebauthnCredentialRepo,
    WebauthnFactorStrength, device_code_digest, invitation_token_digest, magic_link_binding_digest,
    magic_link_token_digest, mint_invitation_token, mint_invitation_token_for,
    opaque_access_token_digest, refresh_token_digest, user_code_hash,
};
pub use risk::{
    DisavowalResolution, LoginGeoView, NewDisavowalToken, NewLoginGeo, NewRiskDecision,
    NewRiskSignal, RiskDecisionView, RiskSignalView,
};
pub use scope::Scope;
pub use sms_otp::{ActiveSmsOtpCode, NewSmsOtpCode, SmsRouteStat, SmsTenantConfig};
pub use snapshot::{
    CLIENT_SECRET_REFERENCE, ClientSnapshot, DcrPolicySnapshot, OrgConnectionSnapshot,
    ResourceServerSnapshot, RoutingRuleSnapshot, SNAPSHOT_RESOURCE_TYPES, SNAPSHOT_SCHEMA_VERSION,
    SecretRef, Snapshot, SnapshotResources, SnapshotViolation, UpstreamTokenGrantSnapshot,
    VariableSnapshot, classification_coverage_gaps, export as export_snapshot, validate_document,
};
pub use store::Store;
pub use trait_schema::{
    MAX_DEPTH as TRAIT_SCHEMA_MAX_DEPTH, SchemaError, TraitAnnotations, TraitSchema, TransformOp,
    ValidationFailure, Visibility, apply_transform, parse_transform,
};
