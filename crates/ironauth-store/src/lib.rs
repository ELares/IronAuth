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
pub mod api_key;
pub mod audit;
pub mod brand;
pub mod classification;
pub mod client_admin_grant;
pub mod connector;
pub mod custom_domain;
pub mod email_otp;
pub mod environment;
mod error;
pub mod esv;
pub mod federation_state;
pub mod flow;
pub mod flow_version;
mod id;
pub mod identifier;
pub mod interchange;
pub mod locale_bundle;
mod migrate;
pub mod org_policy;
pub mod org_provisioning;
pub mod outbox;
pub mod pow_challenge;
pub mod promotion;
pub mod recovery;
mod redirect;
mod repository;
pub mod risk;
mod scope;
pub mod signup_form;
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
pub use brand::{
    BrandAssetKind, BrandAssetMeta, BrandAssetRecord, BrandRecord, NewBrand, NewBrandAsset,
    canonicalize_host,
};
pub use classification::{ResourceClassification, ResourceLevel, ResourceType, classify};
pub use client_admin_grant::{
    ClientAdminGrantRecord, NewClientAdminGrant, admin_grant_covers_scope,
};
pub use connector::{ConnectorCapabilities, ConnectorRecord, NewConnector, StoredCapabilities};
pub use custom_domain::{
    AcmeChallengeRecord, ChallengeOutcome, ChallengeStatus, ChallengeType, CustomDomainError,
    CustomDomainRecord, VerificationStatus, domain_is_registrable, normalize_domain,
};
pub use email_otp::{
    ActiveEmailOtpCode, EmailFactorConfig, EmailFactorPurpose, MagicLinkChallenge,
    MagicLinkConsumeOutcome, NewEmailOtpCode, NewMagicLink, OtpAttemptOutcome,
};
pub use environment::{
    EnvironmentType, Guardrail, GuardrailClass, GuardrailReport, GuardrailSet, GuardrailViolation,
    UnknownEnvironmentType,
};
pub use error::{StoreError, StoreErrorWire};
pub use esv::{
    MAX_NAME_LEN, Reference, ReferenceError, ReferenceKind, ResolveError, Resolved, name_is_valid,
    reference_resolves, resolve_value,
};
pub use federation_state::{ConsumedFederationLoginState, NewFederationLoginState};
pub use flow::{FlowRecord, NewFlow};
pub use flow_version::{
    FlowVersionRecord, NewFlowVersion, validate_artifact as validate_journey_artifact,
    validate_artifact_json as validate_journey_artifact_json,
};
pub use id::{
    AbuseBanId, AbuseBanKind, AccountLinkId, AccountLinkKind, AcmeChallengeId, AcmeChallengeKind,
    AdminSudoElevationId, AdminSudoElevationKind, AgentId, AgentKind, ApiKeyId, ApiKeyKind,
    AssertionMappingId, AssertionMappingKind, AttestationConfigId, AttestationConfigKind, AuditId,
    AuditKind, AuditTarget, AuthorizationCodeId, AuthorizationCodeKind, BackChannelDeliveryId,
    BackChannelDeliveryKind, BrandId, BrandKind, COMPONENT_BYTES, ClientAdminGrantId,
    ClientAdminGrantKind, ClientId, ClientKind, ClientSessionId, ClientSessionKind, ConnectorId,
    ConnectorKind, ConsentId, ConsentKind, CorrelationId, CorrelationKind, CredentialClassPolicyId,
    CredentialClassPolicyKind, CredentialId, CredentialKind, CustomDomainId, CustomDomainKind,
    DcrPolicyId, DcrPolicyKind, DekId, DekKind, DeviceCodeId, DeviceCodeKind, EmailOtpCodeId,
    EmailOtpCodeKind, EncryptedSecretId, EncryptedSecretKind, EnvironmentId, EnvironmentKind,
    EnvironmentSecretId, EnvironmentSecretKind, ExternalIssuerId, ExternalIssuerKind, FedcmNonceId,
    FedcmNonceKind, FederationLoginStateId, FederationLoginStateKind, FlowId, FlowKind,
    FlowVersionId, FlowVersionKind, FlowVersionPinId, FlowVersionPinKind, GrantId, GrantKind,
    HumanId, HumanKind, IdParseError, InitialAccessTokenId, InitialAccessTokenKind, InvitationId,
    InvitationKind, IssuedTokenId, IssuedTokenKind, KekId, KekKind, LevelId, LevelKind,
    LocaleBundleId, LocaleBundleKind, MagicLinkTokenId, MagicLinkTokenKind, ManagementKeyId,
    ManagementKeyKind, MigrationRunId, MigrationRunKind, MigrationRunRecordId,
    MigrationRunRecordKind, NotInScope, OperatorId, OperatorKind, OrgAuthPolicyId,
    OrgAuthPolicyKind, OrgConnectionId, OrgConnectionKind, OrgGroupId, OrgGroupKind,
    OrgGroupMemberId, OrgGroupMemberKind, OrgGroupRoleId, OrgGroupRoleKind, OrgMembershipId,
    OrgMembershipKind, OrgMembershipRoleId, OrgMembershipRoleKind, OrgRoleId, OrgRoleKind,
    OrgRolePermissionId, OrgRolePermissionKind, OrganizationId, OrganizationKind, OutboxMessageId,
    OutboxMessageKind, PermissionId, PermissionKind, PowChallengeId, PowChallengeKind,
    ProjectGrantId, ProjectGrantKind, ProjectGrantRoleId, ProjectGrantRoleKind, PushedRequestId,
    PushedRequestKind, RecoveryApprovalId, RecoveryApprovalKind, RecoveryCodeId, RecoveryCodeKind,
    RecoveryContactConfirmationId, RecoveryContactConfirmationKind, RecoveryFlowId,
    RecoveryFlowKind, RecoveryIdvSessionId, RecoveryIdvSessionKind, RecoveryTrustedContactId,
    RecoveryTrustedContactKind, RefreshFamilyId, RefreshFamilyKind, RefreshTokenId,
    RefreshTokenKind, ResourceServerId, ResourceServerKind, RiskDecisionId, RiskDecisionKind,
    RiskDisavowalId, RiskDisavowalKind, RiskLoginGeoId, RiskLoginGeoKind, RiskSignalId,
    RiskSignalKind, RoutingRuleId, RoutingRuleKind, ScopeStepUpPolicyId, ScopeStepUpPolicyKind,
    ScopedId, ScopedKind, ServiceAccountId, ServiceAccountKind, ServiceId, ServiceKind,
    SessionEventId, SessionEventKind, SessionId, SessionKind, SigningKeyId, SigningKeyKind,
    SignupFormId, SignupFormKind, SignupQuarantineId, SignupQuarantineKind, SmsOtpCodeId,
    SmsOtpCodeKind, SmsRouteStatId, SmsRouteStatKind, TenantId, TenantKind, TotpCredentialId,
    TotpCredentialKind, TraitMigrationJobId, TraitMigrationJobKind, TraitSchemaId, TraitSchemaKind,
    TrustedDeviceId, TrustedDeviceKind, UpstreamTokenGrantId, UpstreamTokenGrantKind,
    UpstreamTokenId, UpstreamTokenKind, UserId, UserIdentifierId, UserIdentifierKind, UserKind,
    VariableId, VariableKind, WebauthnChallengeId, WebauthnChallengeKind, WebauthnCredentialId,
    WebauthnCredentialKind, WebhookDeliveryAttemptId, WebhookDeliveryAttemptKind,
    WebhookEndpointId,
};
pub use identifier::{
    CanonicalIdentifier, IdentifierType, UniquenessMode, canonicalize_identifier,
    normalize_routing_domain,
};
pub use interchange::{
    Capability, ExportRequest, FixedCapability, GrantedCapabilities, INTERCHANGE_AUDIENCE,
    ImportEnvironment, ImportedBundle, InterchangeError, LaunchConstraints, MAX_ARCHIVE_BYTES,
    SafetyManifest, SignedArchive, TrustedExporter, derive_capabilities, derive_min_engine_version,
    export_archive, import_archive,
};
pub use locale_bundle::{LocaleBundleRecord, NewLocaleBundle};
pub use migrate::{Migration, MigrationError, MigrationReport, MigrationRunner, Phase};
pub use org_policy::{
    AllowedDomains, AllowedFactors, AuthPolicy, AuthPolicyError, KNOWN_FACTOR_TOKENS,
    ORG_POLICY_MAX_SESSION_TTL_SECS, PolicyLevels, ResolvedAuthPolicy, SECOND_FACTOR_TOKENS,
    Satisfiability, audit_detail as org_policy_audit_detail, is_known_factor_token,
    is_second_factor_token, normalize as normalize_org_policy, resolve as resolve_org_policy,
    resolved_session_pair_is_coherent, validate as validate_org_policy,
};
pub use pow_challenge::{NewPowChallenge, PowChallengeView};
pub use promotion::{
    ChangeKind, ConfigDiff, PROMOTED_RESOURCE_TYPES, Plan, PlanError, PromotedResourceType,
    PromotionApplyError, PromotionOutcome, ResourceChange, collect_references,
    diff as diff_snapshots, evaluate_plan, plan_promotion, revision as promotion_revision,
};
pub use recovery::{
    NewRecoveryFlow, RecoveryCancelReason, RecoveryEntryPoint, RecoveryFlowRecord, RecoveryMethod,
    RecoveryState,
};
pub use redirect::{redirect_uri_is_registrable, redirect_uri_matches};
pub use repository::{
    AbuseRepo, AcceptedInvitation, AccessTokenResolution, AccountCredentialRepo,
    AccountCredentialSummary, AccountLinkMethod, AccountLinkRecord, AccountLinkRepo,
    ActingAbuseRepo, ActingAccountCredentialRepo, ActingAccountLinkRepo,
    ActingAdminSudoElevationRepo, ActingApiKeyRepo, ActingAssertionSubjectMappingRepo,
    ActingAttestationConfigRepo, ActingAuthorizationRepo, ActingClientRepo,
    ActingClientScopePolicyRepo, ActingConsentRepo, ActingCredentialClassPolicyRepo,
    ActingCustomDomainRepo, ActingDcrPolicyRepo, ActingDeviceCodeRepo, ActingEnvelopeRepo,
    ActingEnvironmentRepo, ActingEnvironmentSecretRepo, ActingEnvironmentVariableRepo,
    ActingExternalAssertionIssuerRepo, ActingFedcmNonceRepo, ActingInitialAccessTokenRepo,
    ActingInvitationRepo, ActingManagementCredentialRepo, ActingManagementStore,
    ActingMigrationRunRepo, ActingOrgConnectionRepo, ActingOrgGroupMemberRepo, ActingOrgGroupRepo,
    ActingOrgGroupRoleRepo, ActingOrgMembershipRepo, ActingOrgMembershipRoleRepo,
    ActingOrgRolePermissionRepo, ActingOrgRoleRepo, ActingOrganizationRepo, ActingPermissionRepo,
    ActingProjectGrantRepo, ActingPushedRequestRepo, ActingRecoveryApprovalRepo,
    ActingRecoveryCodeRepo, ActingRecoveryContactConfirmationRepo, ActingRecoveryIdvSessionRepo,
    ActingRecoveryTrustedContactRepo, ActingRefreshRepo, ActingResourceServerRepo,
    ActingRoutingRuleRepo, ActingScopeStepUpPolicyRepo, ActingServiceAccountRepo,
    ActingSessionRepo, ActingSigningKeyRepo, ActingSmsOtpRepo, ActingStore, ActingTenantRepo,
    ActingTotpCredentialRepo, ActingTraitMigrationJobRepo, ActingTraitSchemaRepo,
    ActingTrustedDeviceRepo, ActingUpstreamTokenGrantRepo, ActingUpstreamTokenRepo,
    ActingUserIdentifierRepo, ActingUserRepo, ActingWebauthnCredentialRepo, ActiveConsent,
    ActiveDeviceFlow, ActiveOpaqueToken, AdminSudoElevation, AdminSudoElevationRepo, ApiKeyOwner,
    ApiKeyRecord, ApiKeyRepo, ApprovedDeviceGrant, AssertionSubjectMappingRecord,
    AssertionSubjectMappingRepo, AttestationConfig, AttestationConfigRepo, AuditRecord, AuditRepo,
    AuthorizationRepo, BACKCHANNEL_LOGOUT_CONSUMER, BackchannelLogoutParticipant, ByokBinding,
    ClientAssertionJtiRepo, ClientAuthDiagnosticQuery, ClientAuthDiagnosticReason,
    ClientAuthDiagnosticRecord, ClientAuthDiagnosticsRepo, ClientAuthRecord,
    ClientCredentialsAccess, ClientRecord, ClientRepo, ClientResourcePolicy, ClientScopePolicy,
    ClientScopePolicyRepo, ClientSessionRepo, CodeBindings, CompletionOutcome, ConsentRepo,
    ConsentRevocation, ConsumePushedRequest, ConsumedChallenge, ConsumedInitialAccessToken,
    CredentialClassPolicy, CredentialClassPolicyRepo, CredentialRemoveOutcome, CredentialType,
    CursorPosition, CustomDomainRepo, DcrPolicyRecord, DcrPolicyRepo, DcrRateLimiterRepo,
    DeviceApproval, DeviceApproveOutcome, DeviceAttemptOutcome, DeviceClientProfile,
    DeviceCodeRepo, DevicePollOutcome, DeviceRedeemOutcome, DeviceUserCodeLookup,
    DiagnosticExpectation, DpopProofReplayRepo, DynamicClientRecord, DynamicClientRegistration,
    DynamicClientUpdate, EffectiveRoleGrant, EffectiveRoleSource, EnvelopeRepo,
    EnvironmentGuardrailRepo, EnvironmentRecord, EnvironmentRepo, EnvironmentSecretMetadata,
    EnvironmentSecretRepo, EnvironmentServingState, EnvironmentVariableRecord,
    EnvironmentVariableRepo, ExportedCredential, ExportedRecoveryCode, ExportedTotp,
    ExternalAssertionIssuerRecord, ExternalAssertionIssuerRepo, ExternalAssertionJtiRepo,
    FailureOutcome, FedcmNonceRepo, FirstPasswordOutcome, FrontchannelLogoutParticipant,
    GrantOwner, GrantedConsent, INVITATION_TOKEN_PREFIX, IdempotencyRepo, IdempotencyWrite,
    IdentifierCollision, IdentifierResolution, InitialAccessTokenRepo, InvariantEvaluation,
    InvariantKind, InvitationAdminRecord, InvitationCredentialType, InvitationListFilter,
    InvitationRepo, InvitationState, IssueClientCredentials, IssueCode, IssuedChallenge,
    IssuedTokenRecord, JtiOutcome, LoginMethod, MANAGEMENT_LIST_HARD_CAP,
    ManagementCredentialRecord, ManagementCredentialRepo, ManagementStore, MigrationKind,
    MigrationProgress, MigrationRecordOutcome, MigrationRun, MigrationRunRepo, MigrationRunTallies,
    MigrationState, MintedInvitationToken, NewAccountLink, NewAdminUser, NewApiKey,
    NewAssertionSubjectMapping, NewClientAuthDiagnostic, NewDcrPolicy, NewDeviceCode,
    NewDynamicClient, NewEnvironment, NewExternalAssertionIssuer, NewInitialAccessToken,
    NewInvitation, NewInvitedUser, NewJwtAuthClient, NewMembership, NewMigrationRun,
    NewOpaqueAccessToken, NewOrgConnection, NewOrgGroup, NewOrgGroupMember, NewOrgGroupRole,
    NewOrgMembershipRole, NewOrgRole, NewOrgRolePermission, NewOutboxMessage, NewPermission,
    NewPolicyDecisionTrace, NewProjectGrant, NewRecoveryCode, NewRefreshFamily, NewResourceServer,
    NewRoutingRule, NewSession, NewSigningKey, NewTokenSizeEvent, NewTotpEnrollment,
    NewTraitMigrationJob, NewTrustedDevice, NewUpstreamTokenGrant, NewUpstreamTokens,
    NewUserIdentifier, NewUserTraits, NewWebauthnCredential, ORG_GROUP_MAX_DEPTH_CEILING,
    OffendingRecord, OpenedTrustedContact, OperatorRecord, OperatorRepo, OrgAuthPolicyRecord,
    OrgAuthPolicyRepo, OrgConnectionRecord, OrgConnectionRepo, OrgGroupMemberRecord,
    OrgGroupMemberRepo, OrgGroupRecord, OrgGroupRepo, OrgGroupRoleRecord, OrgGroupRoleRepo,
    OrgMembershipRecord, OrgMembershipRepo, OrgMembershipRoleRecord, OrgMembershipRoleRepo,
    OrgRolePermissionRecord, OrgRolePermissionRepo, OrgRoleRecord, OrgRoleRepo, OrganizationRecord,
    OrganizationRepo, OrganizationState, OutboxDepth, OutboxMessage, OutboxRepo,
    PasswordRemovalOutcome, PendingInvitation, PermissionEntryKind, PermissionRecord,
    PermissionRepo, PolicyDecisionInputs, PolicyDecisionTraceQuery, PolicyDecisionTraceRecord,
    PolicyDecisionTracesRepo, PolicyKind, PolicyOutcome, PolicyTraceSignal, PriorSessionOutcome,
    ProjectGrantRecord, ProjectGrantRepo, PushRequest, PushedRequestRepo, RecordFailure,
    RecordOutcomeInput, RecoveryApprovalRepo, RecoveryApprovalState, RecoveryApprovalView,
    RecoveryCodeCandidate, RecoveryCodeRepo, RecoveryContactConfirmationRepo,
    RecoveryIdvSessionRecord, RecoveryIdvSessionRepo, RecoveryRedeemOutcome,
    RecoveryTrustedContactRepo, RedeemOutcome, RefreshFamilyFleetFilter, RefreshFamilyFleetRepo,
    RefreshFamilyOpenOutcome, RefreshFamilySummary, RefreshRedeem, RefreshRedeemOutcome,
    RefreshRepo, RefreshTokenResolution, RegisteredTraits, ResolvedIdempotencyWrite,
    ResourceServerRecord, ResourceServerRepo, RestoredRecoveryCode, RestoredTotp, RetryPolicy,
    RotatedRefreshToken, RoutingRuleRecord, RoutingRuleRepo, RoutingSelector,
    SESSION_ENDED_CONSUMER, ScopeStepUpPolicy, ScopeStepUpPolicyRepo, ScopedStore,
    ServiceAccountRepo, SessionEndCause, SessionEndedEvent, SessionEventOutboxRepo,
    SessionFleetFilter, SessionFleetRepo, SessionRecord, SessionRepo, SessionRevocation,
    SessionSummary, SigningKeyMaterial, SigningKeyMaterialKind, SigningKeyRecord, SigningKeyRepo,
    SignupQuarantineReason, SignupQuarantineRepo, SignupQuarantineState, SignupQuarantineView,
    SmsOtpRepo, StoredIdempotentResponse, TenantRecord, TenantRepo, TenantStatus, TokenFormat,
    TokenKind, TokenSizeEventRecord, TokenSizeEventsRepo, TokenSizeKind, TokenSizeReason,
    TokenStatus, TotpActivateOutcome, TotpCredentialRepo, TotpCredentialSummary, TotpMaterial,
    TotpVerifyOutcome, TraitJobKind, TraitJobStatus, TraitMigrationJob, TraitMigrationJobRepo,
    TraitSchemaRepo, TraitSchemaVersion, TraitWriteVisibility, TrustedDeviceRepo,
    TrustedDeviceRevokeReason, TrustedDeviceSummary, UnlinkOutcome, UpstreamToken,
    UpstreamTokenGrantRecord, UpstreamTokenGrantRepo, UpstreamTokenMaterial, UserAdminRecord,
    UserExportRecord, UserIdentifierRecord, UserIdentifierRepo, UserListFilter, UserRecord,
    UserRepo, UserRevocation, UserState, WEBAUTHN_CHALLENGE_TTL_SECS, WebauthnAssertionTarget,
    WebauthnCeremony, WebauthnChallengeRepo, WebauthnCredentialDescriptor,
    WebauthnCredentialOutcome, WebauthnCredentialRecord, WebauthnCredentialRepo,
    WebauthnFactorStrength, device_code_digest, invitation_token_digest, magic_link_binding_digest,
    magic_link_token_digest, mint_invitation_token, mint_invitation_token_for,
    opaque_access_token_digest, refresh_token_digest, user_code_hash,
};
pub use repository::{
    ActingWebhookEndpointRepo, DeliveryAttemptRecord, DeliveryTargetLookup, DomainEvent,
    NewDeliveryAttempt, NewWebhookEndpoint, OFFBOARDING_CONSUMER, OUTBOX_MAX_BACKOFF_SECS,
    OffboardingSchedule, TRAIT_MIGRATION_CONSUMER, TraitMigrationStart, WEBHOOK_DELIVERY_CONSUMER,
    WEBHOOK_EVENT_CONSUMER, WEBHOOK_REPLAY_CONSUMER, WebhookDeliveryAttemptRepo,
    WebhookDeliveryTarget, WebhookEndpointRecord, WebhookEndpointRepo,
};
/// The testing-only atomicity probes (issue #247): the seams at which a test can force
/// the joined invitation create and the joined recovery approve to fail INSIDE their one
/// transaction. Present only under the `testing` feature, so a production build carries
/// no failure-injection seam and no name for one.
#[cfg(feature = "testing")]
pub use repository::{InvitationCreateFailurePoint, RecoveryApproveFailurePoint};
pub use risk::{
    DisavowalResolution, LoginGeoView, NewDisavowalToken, NewLoginGeo, NewRiskDecision,
    NewRiskSignal, RiskDecisionView, RiskSignalView,
};
pub use scope::Scope;
pub use signup_form::{
    NewSignupForm, SignupFormConfig, SignupFormError, SignupFormField, SignupFormRecord,
    SignupStep, validate_against_schema as validate_signup_form,
};
pub use sms_otp::{ActiveSmsOtpCode, NewSmsOtpCode, SmsRouteStat, SmsTenantConfig};
pub use snapshot::{
    BrandAssetMetaSnapshot, BrandSnapshot, CLIENT_SECRET_REFERENCE, ClientSnapshot,
    DcrPolicySnapshot, FlowVersionSnapshot, LocaleBundleSnapshot, OrgConnectionSnapshot,
    ResourceServerSnapshot, RoutingRuleSnapshot, SNAPSHOT_RESOURCE_TYPES, SNAPSHOT_SCHEMA_VERSION,
    SecretRef, SignupFormSnapshot, Snapshot, SnapshotResources, SnapshotViolation,
    UpstreamTokenGrantSnapshot, VariableSnapshot, classification_coverage_gaps,
    export as export_snapshot, validate_document,
};
pub use store::Store;
pub use trait_schema::{
    MAX_DEPTH as TRAIT_SCHEMA_MAX_DEPTH, NarrowingViolation, SchemaError, TraitAnnotations,
    TraitSchema, TransformOp, ValidationFailure, Visibility, apply_transform, narrows,
    parse_transform,
};
