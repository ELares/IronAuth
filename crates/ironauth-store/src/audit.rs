// SPDX-License-Identifier: MIT OR Apache-2.0

//! The audit envelope: who did what to which resource, under which scope, when.
//!
//! Every repository mutation writes exactly one audit row in the SAME
//! transaction as the data change (see the repository module). This module holds
//! the value types that make up that row's envelope; the repository owns the
//! single write primitive that commits them together. The envelope is
//! deliberately richer than milestone M1 consumes: it is the substrate for the
//! later OCSF mapping and the auth-stream versus admin-stream separation (M11).
//! Those streams are not built here; only the fields they will need are carried.
//!
//! The envelope has four moving parts:
//!
//! - an [`ActorRef`]: a typed principal ([`ActorRef::Human`], [`ActorRef::Service`],
//!   [`ActorRef::Agent`]), each wrapping a typed actor identifier;
//! - an [`Action`]: the verb, for example `client.create`;
//! - a target: the typed scoped identifier of the resource acted on (carried by
//!   the repository, not stored here);
//! - the ambient context: the `(tenant, environment)` scope, the wall-clock
//!   time (drawn from the [`ironauth_env`] clock seam, never a direct process
//!   clock read), and a [`CorrelationId`] tying the row back to the request.
//!
//! Writes require an [`ActingContext`] (actor plus correlation id); reads do not.
//! That asymmetry is enforced at the type level by the repository: a plain
//! scoped repository can only read, and the mutating repository is reachable
//! only through [`crate::ScopedStore::acting`], which demands the context.

use std::fmt;

use crate::id::{AgentId, CorrelationId, HumanId, IdParseError, ServiceId};

/// A typed reference to the principal responsible for a mutation.
///
/// The three kinds are distinct on the wire (`human`, `service`, `agent`) and
/// each carries its own typed, non-guessable identifier, so an audit row always
/// attributes a change to a concrete principal of a known kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorRef {
    /// An interactive human user.
    Human(HumanId),
    /// A machine client acting on its own behalf (a service account).
    Service(ServiceId),
    /// An autonomous agent acting for a principal.
    Agent(AgentId),
}

impl ActorRef {
    /// Reference a human actor.
    #[must_use]
    pub fn human(id: HumanId) -> Self {
        Self::Human(id)
    }

    /// Reference a service actor.
    #[must_use]
    pub fn service(id: ServiceId) -> Self {
        Self::Service(id)
    }

    /// Reference an agent actor.
    #[must_use]
    pub fn agent(id: AgentId) -> Self {
        Self::Agent(id)
    }

    /// The stable wire tag for this actor's kind (`human`, `service`, `agent`).
    /// Stored in its own column so the audit log can be filtered by actor kind
    /// without parsing the identifier.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            ActorRef::Human(_) => "human",
            ActorRef::Service(_) => "service",
            ActorRef::Agent(_) => "agent",
        }
    }

    /// The typed actor identifier in its wire form (for example `hum_...`).
    #[must_use]
    pub fn id_string(&self) -> String {
        match self {
            ActorRef::Human(id) => id.to_string(),
            ActorRef::Service(id) => id.to_string(),
            ActorRef::Agent(id) => id.to_string(),
        }
    }

    /// Reconstruct an actor from the two columns an audit row stores.
    ///
    /// # Errors
    ///
    /// [`IdParseError`] if the kind tag is unknown or the identifier does not
    /// parse under the kind. Reading a stored audit row should never hit this;
    /// it exists so a corrupt row surfaces as a decode error rather than a panic.
    pub(crate) fn from_parts(kind: &str, id: &str) -> Result<Self, IdParseError> {
        match kind {
            "human" => Ok(Self::Human(HumanId::parse(id)?)),
            "service" => Ok(Self::Service(ServiceId::parse(id)?)),
            "agent" => Ok(Self::Agent(AgentId::parse(id)?)),
            _ => Err(IdParseError::Prefix),
        }
    }
}

impl fmt::Display for ActorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind_str(), self.id_string())
    }
}

/// The action recorded on an audit row: the verb of the mutation.
///
/// Modeled as an enum so that every mutation type shipped to date is a named,
/// exhaustively matched variant rather than a free-form string a caller could
/// mistype. Each variant renders to a stable dotted string (`client.create`)
/// that is what the OCSF mapping (M11) will key on. Adding a mutation is a
/// deliberate act: it must add a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// A client was created.
    ClientCreate,
    /// A client was deleted.
    ClientDelete,
    /// A client's registered redirect URIs were set (issue #13).
    ClientRedirectUrisRegister,
    /// A client's registered POST-LOGOUT redirect URIs were set (issue #33): the
    /// exact-match set the RP-Initiated Logout `end_session` endpoint honors a
    /// `post_logout_redirect_uri` against. Distinct from
    /// [`Action::ClientRedirectUrisRegister`] so the two registered sets are legible
    /// apart in the audit trail.
    ClientPostLogoutRedirectUrisRegister,
    /// A client's OIDC Front-Channel Logout 1.0 registration was set (issue #39):
    /// its `frontchannel_logout_uri` and `frontchannel_logout_session_required`
    /// flag, the per-client opt-in the `end_session` flow reads when the environment
    /// feature is enabled.
    ClientFrontchannelLogoutRegister,
    /// A client's Back-Channel Logout registration was set (issue #34): the
    /// `backchannel_logout_uri` the OP POSTs a signed Logout Token to, and the
    /// `backchannel_logout_session_required` flag. Distinct from the redirect-URI
    /// registrations so the back-channel target is legible on its own in the audit trail.
    ClientBackchannelLogoutRegister,
    /// A client's consent mode and refresh-rotation policy were configured (issue
    /// #21): the consent mode, the skip and no-store consent knobs, and the optional
    /// per-client rotation override.
    ClientConfigure,
    /// A client was registered through Dynamic Client Registration (issue #30,
    /// RFC 7591). Distinct from [`Action::ClientCreate`] so a self-service DCR
    /// registration is legible in the audit trail as such.
    ClientRegistered,
    /// A dynamically registered client's configuration was updated through the
    /// RFC 7592 management endpoint (issue #30). Every successful update also
    /// ROTATES the client's registration access token in the same transaction, so
    /// this one action covers the metadata change and the token rotation together.
    ClientUpdated,
    /// A tenant was created (management plane, issue #11).
    TenantCreate,
    /// A tenant was offboarded into the GRACE stage (management plane, issue
    /// #46): a soft delete that fences the data plane and keeps every key INTACT,
    /// so a restore inside the retention window loses no data. It does NOT
    /// crypto-shred; erasure is the terminal purge's job.
    TenantDelete,
    /// A tenant was RESTORED from the grace stage (management plane, issue #46):
    /// the soft-delete tombstones are cleared and the data plane serves again with
    /// no data loss.
    TenantRestore,
    /// A grace tenant was terminally HARD-DELETED (purged) after its retention
    /// window elapsed (management plane, issue #46): the envelope keys are
    /// crypto-shredded (through #48) so the tenant's PII is permanently
    /// unrecoverable, and the tenant can no longer be restored.
    TenantPurge,
    /// A tenant was SUSPENDED (management plane, issue #46): a reversible fence
    /// that stops it serving the data plane while keeping its data intact.
    TenantSuspend,
    /// A suspended tenant was RESUMED (management plane, issue #46): service is
    /// restored with no data loss.
    TenantResume,
    /// An environment was created (management plane, issue #11).
    EnvironmentCreate,
    /// An environment was deactivated (management plane, issue #11).
    EnvironmentDelete,
    /// A management API key was minted (management plane, issue #11).
    ManagementKeyCreate,
    /// A management API key was revoked (management plane, issue #11).
    ManagementKeyDelete,
    /// An organization was created (management plane, issue #41). The minimal
    /// per-environment organization shell M10 later extends with membership.
    OrganizationCreate,
    /// An organization was deactivated (management plane, issue #41): a soft
    /// delete that retains the row so the audit foreign key to it stays intact.
    OrganizationDelete,
    /// An authorization code and its grant were issued (issue #12).
    AuthorizationCodeIssue,
    /// An authorization code was redeemed at the token endpoint (issue #12).
    AuthorizationCodeRedeem,
    /// A consumed authorization code was replayed, revoking its grant chain
    /// (issue #12). This is the reuse event: it is written only when a code that
    /// was already redeemed is presented again.
    AuthorizationCodeReuse,
    /// Tokens (access and/or ID) were issued from a grant (issue #12).
    TokenIssue,
    /// A bootstrap end user was registered (issue #20).
    UserRegister,
    /// A user was created through the management API (issue #52): the admin
    /// create, optionally with a caller-supplied id. Distinct from
    /// [`Action::UserRegister`] (the data-plane self-registration) so an
    /// operator-created account is legible as such in the audit trail.
    UserCreate,
    /// A user's mutable profile was updated through the management API (issue #52):
    /// a PATCH of the standard-claim document. The claim values are never recorded
    /// on the audit row; only that the user was updated, by whom, and when.
    UserUpdate,
    /// A user was DELETED through the management API (issue #52): a soft-delete
    /// tombstone that cascades the user's sessions and non-offline refresh families
    /// and publishes to the session-ended fan-out (issue #35), then reads as a
    /// uniform not-found. Offboarding, not erasure (crypto-shredding is #48/#49).
    UserDelete,
    /// A user's lifecycle STATE was changed through the management API (issue #52):
    /// a validated transition of the user state machine (active, blocked, disabled,
    /// `pending_verification`, `scheduled_offboarding`). The audit row's operator-safe
    /// `detail` records the target state; a session-ending transition (block,
    /// disable) cascades in the same transaction and fans out to relying parties.
    UserStateChange,
    /// A user's imported FOREIGN password hash was verified on first login and
    /// transparently rehashed to the native Argon2id verifier (issue #55): the
    /// verify-then-rehash upgrade. The foreign hash and its algorithm tag are
    /// cleared in the same transaction; no credential material is recorded on the
    /// audit row, only that the user's credential was upgraded, and when.
    UserPasswordUpgrade,
    /// A user's EXTERNAL ID was linked through the management API (issue #52): a
    /// correlation id from the tenant's own systems was claimed for the user
    /// (unique per scope, so a second claim of the same external id is refused).
    /// The external-id value is never recorded on the audit row.
    UserExternalIdLink,
    /// A user's EXTERNAL ID was unlinked through the management API (issue #52): the
    /// user's correlation id was cleared, freeing it for another user in the scope.
    UserExternalIdUnlink,
    /// A scheduled-offboarding user was EXECUTED by the worker (issue #52): at or
    /// past its scheduled instant the user was disabled and its sessions and
    /// non-offline refresh families cascaded, fanning out identically to a manual
    /// disable. Idempotent: once executed the user is no longer scheduled, so a
    /// re-run of the worker re-processes nothing.
    UserOffboardingExecute,
    /// A typed login IDENTIFIER was added to a user (issue #54): an email, username,
    /// or phone, canonicalized once at the seam and blind-indexed for uniqueness. The
    /// identifier value is never recorded on the audit row (it is sealed and
    /// blind-indexed on its row); only that the user gained an identifier, and when.
    UserIdentifierAdd,
    /// A per-environment identifier UNIQUENESS mode was APPLIED (issue #54): an
    /// operator switched the environment's mode and the store recomputed every
    /// identifier row's uniqueness discriminator under the new mode, in one
    /// scope-fenced transaction, after refusing the change while a
    /// post-canonicalization collision the new mode would enforce still existed. The
    /// target is the environment; no identifier value is recorded (they are sealed and
    /// blind-indexed on their rows).
    UserIdentifierApplyUniquenessMode,
    /// A user invitation was CREATED through the management API (issue #60): an
    /// admin invited a new identity, provisioning a `pending_verification` user and a
    /// single-use, expiring, unguessable token. The token is never recorded on the
    /// audit row (only its digest is stored anywhere); the audit row's operator-safe
    /// `detail` records the enrolled credential type.
    InvitationCreate,
    /// A user invitation was REDEEMED (issue #60): the invitee presented a valid
    /// token, which was consumed atomically (pending -> accepted), and the invited
    /// user was activated (`pending_verification` -> active) with a credential set.
    InvitationRedeem,
    /// A pending user invitation was REVOKED through the management API (issue #60):
    /// an admin invalidated it before it was accepted, so its token can never be
    /// redeemed.
    InvitationRevoke,
    /// A pending user invitation was RESENT through the management API (issue #60):
    /// the prior token was invalidated (its digest overwritten) and a fresh
    /// single-use token with a reset expiry was issued for the same invitation.
    InvitationResend,
    /// A user's identity TRAITS were set or updated through an audited write (issue
    /// #53): the custom profile fields beyond the standard OIDC claims, validated
    /// against the active trait-schema version and sealed at rest. The trait values
    /// are never recorded on the audit row; only that the user's traits changed, by
    /// whom, and when.
    UserTraitsUpdate,
    /// A full identity EXPORT was served through the management API (issue #58): the
    /// exit-friendliness covenant made observable. Every export is a permission-gated
    /// admin action attributed to its actor, so a bulk read of sensitive credential
    /// material (password hashes, foreign hashes, sealed PII) leaves an auditable
    /// trail. The exported values are never recorded on the audit row; the
    /// operator-safe `detail` records only how many identities were exported, targeted
    /// at the environment the export drained.
    UserExport,
    /// A new identity trait-schema VERSION was created in a (tenant, environment)
    /// registry (issue #53): an immutable candidate JSON Schema (draft 2020-12) the
    /// scope's future trait writes may validate against once it is activated.
    TraitSchemaCreate,
    /// A trait-schema version was ACTIVATED as the scope's served default (issue
    /// #53): the cutover, refused while a dry-run or migration reports unresolved
    /// invalid identities. The audit row's operator-safe `detail` records the
    /// activated version.
    TraitSchemaActivate,
    /// A trait migration or dry-run JOB was created (issue #53): a queued job that
    /// validates (dry-run) or transforms and re-validates (migrate) the scope's
    /// existing identities against a candidate schema version.
    TraitMigrationJobCreate,
    /// A trait migration/dry-run job was ADVANCED by a worker step (issue #53): a
    /// deterministic, idempotent, resumable batch that processed a bounded run of the
    /// scope's identities and recorded per-record failures. Re-running a completed or
    /// failed job is a no-op (idempotent), so a crash mid-migration resumes without
    /// double-migrating.
    TraitMigrationJobAdvance,
    /// A wrapped migration RUN was defined (issue #59): a long-running data
    /// migration (a streaming bulk import, a schema migration job) enrolled into the
    /// invariant-checked state machine in its initial `defined` state.
    MigrationRunCreate,
    /// A wrapped migration run TRANSITIONED between lifecycle states (issue #59):
    /// defined -> validating -> running -> reconciling. Every transition is audited
    /// with actor attribution; the target state is the operator-safe `detail`.
    MigrationRunTransition,
    /// A batch of per-record OUTCOMES was ingested into a migration run (issue #59):
    /// the imported / failed / skipped accounting and consistency the invariants
    /// later re-evaluate. One audit row per ingest batch, not per record.
    MigrationRunIngest,
    /// A migration run's records were marked by a BACKFILL pass (issue #59): the
    /// sentinel the backfill invariant requires set. One audit row per backfill batch.
    MigrationRunBackfill,
    /// A migration run's records were RECONCILED (issue #59): a previously-inconsistent
    /// identity that an operator triaged or repaired is flipped back to consistent (and
    /// its recorded reason cleared), so a fixed identity unblocks the consistency
    /// invariant exactly as re-ingest unblocks count and a backfill mark unblocks the
    /// sentinel. One audit row per reconcile batch; the next completion attempt
    /// re-evaluates the invariant live, never a cached verdict.
    MigrationRunReconcile,
    /// A migration run COMPLETED (issue #59): the terminal success transition, taken
    /// only after every invariant re-evaluated satisfied. A blocked completion
    /// attempt writes NO row (it is not a transition), so a `migration_run.complete`
    /// row in the trail always means the invariants were clean.
    MigrationRunComplete,
    /// A migration run was explicitly ABANDONED (issue #59): the terminal giving-up
    /// transition, so a stuck half-applied migration cannot be silently forgotten.
    /// The operator-safe reason is the audit row's `detail`.
    MigrationRunAbandon,
    /// A bootstrap session was established at login or registration (issue #20).
    SessionCreate,
    /// An SSO session identifier was ROTATED at a privilege transition (issue #32):
    /// login (and the future MFA / step-up seam) mints a fresh unpredictable session
    /// id and INVALIDATES the prior one in the SAME transaction (session-fixation
    /// defense). Distinct from [`Action::SessionRevoke`] so a rotation is never
    /// mistaken for a terminal revoke in the audit trail.
    SessionRotate,
    /// A single SSO session was REVOKED by the management API (issue #32), stopping it
    /// from resolving immediately and cascading to its session-bound refresh-token
    /// families (the `offline_access` families survive unless a hard kill was asked
    /// for). Written in the same transaction as the revocation.
    SessionRevoke,
    /// One session of a BULK session revocation was revoked by the management API
    /// (issue #32). Each session in the batch is its own audited transaction, so the
    /// audit trail names every revoked session individually.
    SessionsBulkRevoke,
    /// EVERY session of one user was revoked by the management API (issue #32),
    /// cascading to the user's refresh-token families in the SAME transaction (the
    /// `offline_access` families survive unless a hard kill was asked for). One audit
    /// row targets the user.
    UserSessionsRevokeAll,
    /// A subject granted consent to a client (issue #20).
    ConsentGrant,
    /// A per-environment signing key was provisioned (issue #19). Covers both a
    /// day-one key and a manually rotated-in successor.
    SigningKeyProvision,
    /// A resource server was registered (issue #29). Records the audience and the
    /// access-token format a registered protected API receives.
    ResourceServerRegister,
    /// A refresh-token family was opened at first issuance (issue #21). The
    /// generation-0 refresh token and its family were recorded against the grant.
    RefreshTokenIssue,
    /// A refresh token was rotated (issue #21): a presented token was superseded by
    /// a fresh successor generation and a new access token was issued.
    RefreshTokenRotate,
    /// A refresh token was reused outside the grace window (issue #21), revoking the
    /// whole family. This is the typed reuse event: it is written only when a
    /// superseded refresh token is presented beyond the grace window, and exactly
    /// once per incident (only the revocation that flips the family emits it).
    RefreshTokenReuse,
    /// A session's session-bound refresh-token families were revoked at RP logout
    /// (issue #21). The `offline_access` families are left intact by construction.
    /// Also emitted when a client REVOKES a refresh token at the RFC 7009 revocation
    /// endpoint (issue #22): the whole family and its grant are revoked together, so
    /// the reuse of this action covers both the logout and the explicit-revoke paths.
    RefreshFamilyRevoke,
    /// A token was revoked at the RFC 7009 revocation endpoint (issue #22). Written
    /// against the token's GRANT (the append-only issued/opaque token rows derive
    /// their active state from `grants.revoked_at`), so revoking an access token
    /// revokes its grant chain. The refresh-token revoke path audits through
    /// [`Action::RefreshFamilyRevoke`] instead (it also revokes the family spine).
    TokenRevoke,
    /// A pushed authorization request was stored behind a one-time `request_uri`
    /// (RFC 9126, issue #27). The back-channel push the authorization endpoint later
    /// consumes exactly once.
    PushedAuthorizationRequestPush,
    /// A pushed authorization request's `request_uri` was consumed at the
    /// authorization endpoint (RFC 9126, issue #27). Written only on the winning
    /// single-use consume; a reuse, expiry, or client-mismatch miss writes nothing.
    PushedAuthorizationRequestConsume,
    /// A client's `require_pushed_authorization_requests` flag was set (RFC 9126
    /// section 5, issue #27).
    ClientRequirePushedAuthorizationSet,
    /// A DCR initial access token was minted through the management API (issue
    /// #31, RFC 7591 section 1.2). The token authorizes future self-service client
    /// registrations, optionally under an attached policy chain.
    DcrInitialAccessTokenMint,
    /// A DCR policy object was created through the management API (issue #31): a
    /// named, reusable set of registration-metadata primitives.
    DcrPolicyCreate,
    /// A DCR registration was refused because its submitted metadata violated the
    /// initial access token's policy chain (issue #31). The actionable diagnostic
    /// is recorded out of band; the wire response stays an opaque
    /// `invalid_client_metadata`.
    DcrPolicyRejected,
    /// A DCR registration was refused because the environment's registered-client
    /// quota was already reached (issue #31).
    DcrQuotaHit,
    /// A DCR registration was refused because the endpoint's per-source or per-token
    /// rate limit was exceeded (issue #31).
    DcrRateLimited,
    /// An admin verified a dynamically registered client through the management API
    /// (issue #31), lifting its unverified-client quarantine.
    DcrClientVerified,
    /// A service-account principal was minted for a client (issue #23), lazily on
    /// its first client-credentials issuance. The stable machine `sub` the client's
    /// M2M tokens carry.
    ServiceAccountCreate,
    /// A client's static custom-claims configuration was set (issue #23): the
    /// declarative claims embedded in its client-credentials access tokens.
    ClientCustomClaimsSet,
    /// An external assertion issuer was registered as a trust anchor for the RFC
    /// 7521 / RFC 7523 JWT bearer assertion grant (issue #26). Records the `xai_`
    /// issuer registration (its key source and enable switch).
    ExternalAssertionIssuerRegister,
    /// A subject-mapping rule was created for the JWT bearer assertion grant (issue
    /// #26): the explicit rule mapping an external (issuer + `sub`) to an IronAuth
    /// principal. Unmapped subjects are rejected, never auto-provisioned.
    ExternalAssertionSubjectMappingCreate,
    /// An external assertion issuer's enable switch was toggled (issue #26): a
    /// compromised or decommissioned trust anchor was DISABLED (or re-enabled)
    /// through the column-scoped data-plane grant, so its assertions are rejected
    /// exactly as an unregistered issuer's are. The data-plane revocation capability
    /// (the HTTP management surface for it is M13).
    ExternalAssertionIssuerSetEnabled,
    /// A subject-mapping rule's enable switch was toggled (issue #26): a mis-authored
    /// or decommissioned mapping was DISABLED (or re-enabled) through the
    /// column-scoped data-plane grant, so it resolves to no rule and the grant
    /// rejects the subject exactly as an unmapped one.
    ExternalAssertionSubjectMappingSetEnabled,
    /// A short-lived access token was issued under the JWT bearer assertion grant
    /// (issue #26): a validated external assertion was exchanged for a token under
    /// the mapped identity. No refresh token accompanies it (RFC 7521 4.1).
    JwtBearerAssertionIssue,
    /// A client's RFC 8707 resource-indicator policy was set (issue #28): the
    /// per-client allowed-resource allowlist and the no-resource behavior
    /// (default audience or refusal).
    ClientResourceIndicatorPolicySet,
    /// A device-authorization device code and user code were issued (issue #24, RFC
    /// 8628 section 3.2). The back-channel row a constrained device polls against and
    /// a human approves through the verification page.
    DeviceCodeIssue,
    /// A device-authorization request was APPROVED by an authenticated human at the
    /// verification page (issue #24, RFC 8628 section 3.3): the explicit
    /// confirmation that binds the flow to a subject and opens its grant, so the
    /// next poll at the token endpoint issues tokens.
    DeviceCodeApprove,
    /// A device-authorization request was DENIED (issue #24, RFC 8628 section 3.5):
    /// the human explicitly rejected it at the verification page, or the user code
    /// was invalidated after exhausting its bounded failed-match budget (RFC 8628
    /// section 5.1). A subsequent poll at the token endpoint yields `access_denied`.
    DeviceCodeDeny,
    /// A per-tenant envelope key-encryption key was provisioned (issue #48): a
    /// day-one KEK, generated and stored wrapped under the platform master key.
    EnvelopeKekProvision,
    /// A per-tenant envelope KEK was rotated (issue #48): a fresh KEK version was
    /// generated and every one of the scope's DEKs was re-wrapped under it in the
    /// same transaction, with NO record-payload rewrite. Online and cheap.
    EnvelopeKekRotate,
    /// A per-tenant envelope KEK was DESTROYED (issue #48): the crypto-shred. Every
    /// KEK version of the scope is overwritten and marked destroyed, so the scope's
    /// DEKs can never be unwrapped again and all of its envelope-protected data is
    /// permanently unreadable. The productized offboarding flow is #49.
    EnvelopeKekDestroy,
    /// A scope was enrolled in bring-your-own-key (issue #49): a BYOK binding was
    /// recorded so a customer-managed root key (in an external KMS/HSM, or a
    /// customer-supplied key) governs the scope's key hierarchy. The audit row
    /// carries only the driver and the opaque external key reference, never key
    /// material. The binding is severed at the terminal offboarding stage.
    EnvelopeByokEnroll,
    /// A per-tenant envelope data-encryption key was provisioned (issue #48): a
    /// day-one DEK, generated and stored wrapped under the scope's active KEK.
    EnvelopeDekProvision,
    /// A per-tenant envelope DEK was rotated (issue #48): a fresh DEK version was
    /// generated for new writes and the prior version was retired but stays
    /// readable for background re-encryption of old rows.
    EnvelopeDekRotate,
    /// An encrypted secret value was written (issue #48): a plaintext secret was
    /// sealed under the scope's active DEK with its column context bound as
    /// associated data, and stored as ciphertext.
    EncryptedSecretPut,
    /// An encrypted secret value was re-encrypted from an older DEK version to the
    /// active one (issue #48): the observable background re-encryption step that
    /// follows a DEK rotation. The plaintext never changes; only the sealing key
    /// version does.
    EncryptedSecretReencrypt,
    /// A custom domain was registered for an environment (issue #47): a
    /// customer-owned hostname claimed for later ACME verification and issuance.
    /// The domain starts unverified and is never served until a challenge proves
    /// control of it.
    CustomDomainRegister,
    /// A custom domain's ACME challenge SUCCEEDED (issue #47): a domain-control
    /// verification (http-01 or dns-01) completed and the domain moved to
    /// verified, so it is now eligible to be served. Refused (and NOT written) if
    /// another tenant already verified the same domain.
    CustomDomainChallengeSucceed,
    /// A custom domain's ACME challenge FAILED (issue #47): a domain-control
    /// verification could not be satisfied, so the domain stays unserved. The
    /// failure surfaces to the operator rather than silently degrading.
    CustomDomainChallengeFail,
    /// A custom domain's issued certificate was stored (issue #47): the cert chain
    /// and its PRIVATE KEY were sealed under the scope's envelope DEK (issue #48)
    /// and the domain row was pointed at the sealed bundle. The key never touches
    /// a plaintext column.
    CustomDomainCertificateStore,
    /// An environment VARIABLE (a non-secret named config value) was set through
    /// the management API (issue #45): a first write or an overwrite. The audit row
    /// names the variable id and scope; the value itself is not recorded here.
    EnvironmentVariableSet,
    /// An environment VARIABLE was deleted through the management API (issue #45).
    EnvironmentVariableDelete,
    /// An environment SECRET was set through the management API (issue #45): a
    /// plaintext value was sealed under the scope's envelope DEK (issue #48) and
    /// stored as ciphertext. The audit row names the secret id and scope; the
    /// value is NEVER recorded (the write-only discipline, the #11 secret lesson).
    EnvironmentSecretPut,
    /// An environment SECRET was deleted through the management API (issue #45).
    EnvironmentSecretDelete,
    /// A server-side config PROMOTION was applied (issue #44): a source snapshot's
    /// promotable configuration was transactionally applied onto a target
    /// environment. The row targets the environment and is written in the SAME
    /// transaction as every resource change the apply makes, so a promotion without
    /// its audit row is structurally impossible and a rolled-back apply leaves no
    /// row. The operator-safe `detail` records the change counts (create, update,
    /// delete); no promoted value or secret is recorded.
    ConfigPromotionApply,
    /// An end user CHANGED their OWN password through the self-service account
    /// surface (issue #61): the current password was verified and a fresh Argon2id
    /// verifier was written, and (session-fixation defense) every OTHER session of
    /// the user was revoked in the SAME transaction. The row targets the user and
    /// is attributed to the end user. No password or hash is ever recorded; the
    /// `detail` records the step-up policy the sensitive change declared.
    AccountPasswordChange,
    /// An end user CONVERTED their account to passkey-only by REMOVING their password
    /// (issue #66): the native `password_hash` was flipped to the unusable sentinel and
    /// `passwordless` set true, gated by fresh re-authentication and the cross-source
    /// last-credential guard (the account must retain a usable passkey). The row targets
    /// the user and is attributed to the end user; the `detail` records the step-up
    /// policy. No password or hash is ever recorded.
    AccountPasswordRemove,
    /// An end user CONVERTED a passkey-only account to password-holding by SETTING a
    /// first password (issue #66): the sentinel `password_hash` was replaced with a fresh
    /// Argon2id verifier and `passwordless` cleared, gated by fresh passkey
    /// re-authentication and the full set-path policy (length, strength, breach screen).
    /// The row targets the user and is attributed to the end user; the `detail` records
    /// the step-up policy. No password or hash is ever recorded.
    AccountPasswordSet,
    /// An end user ENROLLED a credential through the self-service account surface
    /// (issue #61): a passkey, TOTP authenticator, or recovery-code set was added
    /// to their own registry. The row targets the credential and is attributed to
    /// the end user; the `detail` records the step-up policy the sensitive change
    /// declared. The concrete factor material lands with the M7 factor issues.
    AccountCredentialEnroll,
    /// An end user REMOVED one of their OWN credentials through the self-service
    /// account surface (issue #61). Blocked by the last-usable-credential guardrail
    /// unless it is not the last, or the request carried the documented recovery
    /// acknowledgment. The row targets the credential and is attributed to the end
    /// user; the `detail` records the step-up policy the sensitive change declared.
    AccountCredentialRemove,
    /// An end user REGISTERED a WebAuthn passkey (issue #65): a verified
    /// registration ceremony persisted a new credential (its COSE public key,
    /// AAGUID, transports, and BE/BS flags). The row targets the `pky_` credential
    /// and is attributed to the end user.
    WebauthnCredentialRegister,
    /// An end user RENAMED one of their OWN WebAuthn passkeys (issue #65): the
    /// user-authored nickname was resealed. The row targets the `pky_` credential
    /// and is attributed to the end user.
    WebauthnCredentialRename,
    /// An end user REMOVED one of their OWN WebAuthn passkeys (issue #65). The row
    /// targets the `pky_` credential and is attributed to the end user.
    WebauthnCredentialRemove,
    /// A WebAuthn assertion presented a backup-eligibility (BE) flag that DIVERGED
    /// from the credential's registration-time, stored BE (issue #65). BE is
    /// immutable across a credential's life (WebAuthn L3 7.2), so a flip is a spec
    /// violation and a signal of a cloned or spoofed authenticator: the sign-in is
    /// refused and this security event is written. The row targets the `pky_`
    /// credential; the `detail` records the stored and presented BE values.
    WebauthnBackupEligibilityMismatch,
    /// A WebAuthn assertion presented a REGRESSING signature counter (issue #65):
    /// the credential's stored counter did not advance, a possible cloned
    /// authenticator. The row targets the `pky_` credential; the `detail` records
    /// the per-tenant policy applied (warn or block). A zero/zero counter (a synced
    /// passkey with no counter) never emits this event.
    WebauthnCloneDetected,
    /// An end user BEGAN a TOTP enrollment (issue #69): a pending `tot_` row was
    /// created with a freshly generated, sealed seed. It cannot satisfy MFA until
    /// activation. The row targets the credential and is attributed to the end user.
    TotpEnrollBegin,
    /// An end user ACTIVATED a TOTP authenticator (issue #69): they proved
    /// possession with a valid current code, so the pending factor became active
    /// and its recovery codes were minted. The row targets the `tot_` credential.
    TotpActivate,
    /// An end user VERIFIED a TOTP code as a second factor (issue #69). Audited
    /// DISTINCTLY from a recovery-code redemption so the two second-factor paths are
    /// never conflated. The row targets the `tot_` credential.
    TotpVerify,
    /// An end user REMOVED one of their OWN TOTP authenticators (issue #69). The row
    /// targets the `tot_` credential and is attributed to the end user.
    TotpRemove,
    /// An end user GENERATED (or REGENERATED) their recovery codes (issue #69):
    /// a fresh batch replaced any prior set, invalidating every outstanding code.
    /// The row targets the user and is attributed to the end user.
    RecoveryCodesGenerate,
    /// An end user REDEEMED a one-time recovery code in place of a second factor
    /// (issue #69). Audited DISTINCTLY from a TOTP verification. The row targets the
    /// redeemed `rvc_` code and is attributed to the end user.
    RecoveryCodeRedeem,
    /// An end user REVOKED one of their OWN sessions through the self-service
    /// account surface (issue #61): a single session the user chose to sign out,
    /// stopping it from resolving immediately and cascading through the unified
    /// session-ended fan-out exactly as an admin revoke does. The row targets the
    /// session and is attributed to the end user.
    AccountSessionRevoke,
    /// An end user REVOKED all of their OTHER sessions through the self-service
    /// account surface (issue #61): every session except the one making the request
    /// (the "sign out everywhere else" action). Each revoked session cascades
    /// through the unified session-ended fan-out. The row targets the user and is
    /// attributed to the end user; the `detail` records the step-up policy the
    /// sensitive change declared.
    AccountSessionsRevokeOthers,
    /// A device was REMEMBERED as trusted after a completed multi-factor login (issue
    /// #71): the remember-device state a subsequent login skips the second factor
    /// against. The row targets the `tdv_` device and is attributed to the end user.
    TrustedDeviceRemember,
    /// A remembered device was REVOKED (issue #71): the user (through the self-service
    /// account surface), an admin, or a password/factor-change invalidation flipped it,
    /// so a replayed device cookie fails server-side IMMEDIATELY. The row targets the
    /// `tdv_` device; the `detail` records the revocation reason.
    TrustedDeviceRevoke,
    /// A credential-abuse BAN was placed on a regulated dimension (issue #64): an
    /// operator, through the CLI or the admin API, banned an attacker IP, an account,
    /// or a canonical identifier on ONE authentication path. The row targets the
    /// `abn_` ban; the `detail` records the banned dimension and path (never the
    /// plaintext subject, which is sealed on the row). The per-path scope is the
    /// account-DoS safeguard: a `password` ban never governs the `passkey` or
    /// `recovery` path (Keycloak CVE-2024-1722).
    AbuseBanCreate,
    /// A credential-abuse ban was LIFTED (issue #64): an operator un-banned a
    /// previously banned dimension and path through the CLI or admin API. The row
    /// targets the `abn_` ban; the `detail` records the dimension and path.
    AbuseBanLift,
    /// A per-scope step-up policy was SET (created or updated) through the
    /// management seam (RFC 9470, issue #72): the (acr floor, max auth age)
    /// requirement governing an OAuth scope token. The row targets the `sup_`
    /// policy.
    ScopeStepUpPolicySet,
    /// A per-scope step-up policy was REMOVED (issue #72): the requirement governing
    /// an OAuth scope token was deleted. The row targets the `sup_` policy.
    ScopeStepUpPolicyRemove,
    /// A per-CLIENT step-up floor was SET (issue #72): the client's `step_up_acr` /
    /// `step_up_max_age_secs` registration floor was configured through the
    /// management seam. The row targets the `cli_` client.
    ClientStepUpPolicySet,
    /// An admin sudo elevation was RECORDED (issue #73): a management credential
    /// completed a re-authentication that opens a freshness window for admin
    /// mutations in a (tenant, environment). The row targets the `elv_` elevation; the
    /// `detail` records the achieved acr and the window expiry.
    AdminPrivilegeElevated,
    /// An admin mutation was REFUSED because the sudo freshness window had lapsed
    /// (issue #73): the recorded elevation was absent or expired, so a structured
    /// re-authentication challenge was returned instead of executing the mutation. The
    /// row targets the `elv_` elevation handle; the freshness expiry is the audited
    /// fact (a stolen credential without a fresh re-auth cannot mutate).
    AdminPrivilegeChallenged,
    /// A credential-class policy was SET (created or updated) through the management
    /// seam (issue #66): the minimum credential class required of a login for a
    /// subject (the tenant, a group, or an org). The row targets the `ccp_` policy;
    /// the `detail` records the subject and the minimum class.
    CredentialClassPolicySet,
    /// A credential-class policy was REMOVED (issue #66): the minimum-class
    /// requirement for a subject was deleted. The row targets the `ccp_` policy.
    CredentialClassPolicyRemove,
    /// The per-scope attestation mode was SET (issue #66): the attestation conveyance
    /// ('none' or 'direct') the passkey registration path requests. The row targets
    /// the `atc_` config; the `detail` records the mode.
    AttestationConfigSet,
    /// The per-scope MDS3 BLOB cache was REFRESHED (issue #66, PR B): a newer, re-verified
    /// FIDO MDS3 metadata BLOB was fetched and cached (or a byte-identical refetch touched
    /// the row). The row targets the `mbc_` cache; the `detail` records the BLOB `no`.
    Mds3BlobCacheRefresh,
    /// An AAGUID allow/deny rule was SET (created or updated) through the management seam
    /// (issue #66, PR B): a specific authenticator model was pinned to a disposition
    /// ('allow' or 'deny'). The row targets the `aag_` rule; the `detail` records the
    /// disposition.
    AaguidRuleSet,
    /// An AAGUID allow/deny rule was REMOVED (issue #66, PR B): the disposition for a
    /// pinned authenticator model was deleted. The row targets the `aag_` rule.
    AaguidRuleRemove,
    /// An email-OTP code was SENT (issue #68): a fresh numeric code was issued to a
    /// user for a purpose, invalidating any prior active code. The row targets the
    /// `eot_` code; the `detail` records the purpose (never the plaintext code, which
    /// is hashed on the row). A send suppressed for anti-enumeration writes no row.
    EmailOtpSend,
    /// An email-OTP code was VERIFIED (issue #68): a user presented the correct code
    /// and it was consumed single-use. The row targets the `eot_` code; the `detail`
    /// records the purpose.
    EmailOtpVerify,
    /// A scanner-safe magic link was SENT (issue #68): a fresh single-use link token
    /// and its cross-device short code were issued to a user for a purpose,
    /// invalidating any prior active link. The row targets the `mlk_` token; the
    /// `detail` records the purpose (never the token or code, both one-way on the row).
    MagicLinkSend,
    /// A scanner-safe magic link was CONSUMED (issue #68): a user completed the POST
    /// confirmation (or the cross-device short code) and the link was consumed
    /// single-use, establishing a session. A prefetching scanner's GET never reaches
    /// this. The row targets the `mlk_` token; the `detail` records the purpose.
    MagicLinkConsume,
    /// An SMS-OTP code was SENT (issue #70): a fresh numeric code was issued to a
    /// user for a purpose, invalidating any prior active code. The row targets the
    /// `sot_` code; the `detail` records the purpose (never the plaintext code, which
    /// is hashed on the row). A send suppressed / refused for anti-enumeration writes
    /// no row.
    SmsOtpSend,
    /// An SMS-OTP code was VERIFIED (issue #70): a user presented the correct code
    /// and it was consumed single-use. The row targets the `sot_` code; the `detail`
    /// records the purpose.
    SmsOtpVerify,
    /// An SMS route was AUTO-THROTTLED by the pumping defense (issue #70): the
    /// send-to-verify conversion on the route dropped below the configured threshold
    /// over a sufficient sample, so the route was throttled WITHOUT operator
    /// intervention. The row targets the route; the `detail` records the route and
    /// the observed conversion.
    SmsRouteThrottled,
    /// An SMS route's low-conversion ALARM fired (issue #70): the send-to-verify
    /// conversion crossed below the configured threshold. The row targets the route;
    /// the `detail` records the route and the observed conversion.
    SmsConversionAlarm,
    /// The per (tenant, environment) SMS configuration was CHANGED (issue #70):
    /// SMS OTP was enabled/disabled, the factor-downgrade path was set, or the
    /// country allowlist was edited. The row records what changed in `detail`.
    SmsConfigUpdate,
    /// An account-recovery flow was INITIATED (issue #81): the first-class recovery
    /// state machine started for a subject. The row targets the `rcv_` flow; the
    /// `detail` records the entry point, the recover-factor strength (acr), whether a
    /// delay was applied, and the number of channels notified (never the plaintext
    /// recipient, which is sealed on the row). A recovery init for a NON-EXISTENT
    /// account writes no row (the anti-enumeration suppressed path).
    RecoveryInitiate,
    /// An account-recovery flow was CANCELLED (issue #81): a held recovery was
    /// revoked from a notification link (or superseded by a newer request), so the
    /// pending recovery can never complete. The row targets the `rcv_` flow; the
    /// `detail` records the cancellation reason.
    RecoveryCancel,
    /// An account-recovery flow COMPLETED (issue #81): the recovery restored access
    /// after the delay elapsed or the challenge was satisfied. The row targets the
    /// `rcv_` flow; the `detail` records the recover-factor strength (acr).
    RecoveryComplete,
    /// A factor change was evaluated against an active recovery (issue #81, the
    /// downgrade invariant): removing or replacing a factor STRONGER than the one used
    /// to recover was either ALLOWED (the delay elapsed or a fresh equal-or-stronger
    /// re-verification was presented) or BLOCKED. The row targets the `rcv_` flow; the
    /// `detail` records the decision and the target factor strength (acr), so an
    /// attacker-initiated downgrade attempt is always reconstructable from the log.
    RecoveryFactorChange,
}

impl Action {
    /// The stable wire string for this action.
    // One flat arm per action verb; splitting the map would not make it clearer.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::ClientCreate => "client.create",
            Action::ClientDelete => "client.delete",
            Action::ClientRedirectUrisRegister => "client.redirect_uris.register",
            Action::ClientBackchannelLogoutRegister => "client.backchannel_logout.register",
            Action::ClientPostLogoutRedirectUrisRegister => {
                "client.post_logout_redirect_uris.register"
            }
            Action::ClientFrontchannelLogoutRegister => "client.frontchannel_logout.register",
            Action::ClientConfigure => "client.configure",
            Action::ClientRegistered => "client.registered",
            Action::ClientUpdated => "client.updated",
            Action::TenantCreate => "tenant.create",
            Action::TenantDelete => "tenant.delete",
            Action::TenantRestore => "tenant.restore",
            Action::TenantPurge => "tenant.purge",
            Action::TenantSuspend => "tenant.suspend",
            Action::TenantResume => "tenant.resume",
            Action::EnvironmentCreate => "environment.create",
            Action::EnvironmentDelete => "environment.delete",
            Action::ManagementKeyCreate => "management_key.create",
            Action::ManagementKeyDelete => "management_key.delete",
            Action::OrganizationCreate => "organization.create",
            Action::OrganizationDelete => "organization.delete",
            Action::AuthorizationCodeIssue => "authorization_code.issue",
            Action::AuthorizationCodeRedeem => "authorization_code.redeem",
            Action::AuthorizationCodeReuse => "authorization_code.reuse",
            Action::TokenIssue => "token.issue",
            Action::UserRegister => "user.register",
            Action::UserCreate => "user.create",
            Action::UserUpdate => "user.update",
            Action::UserDelete => "user.delete",
            Action::UserStateChange => "user.state_change",
            Action::UserPasswordUpgrade => "user.password.upgrade",
            Action::UserExternalIdLink => "user.external_id.link",
            Action::UserExternalIdUnlink => "user.external_id.unlink",
            Action::UserOffboardingExecute => "user.offboarding.execute",
            Action::UserIdentifierAdd => "user.identifier.add",
            Action::UserIdentifierApplyUniquenessMode => "user.identifier.uniqueness.apply",
            Action::InvitationCreate => "invitation.create",
            Action::InvitationRedeem => "invitation.redeem",
            Action::InvitationRevoke => "invitation.revoke",
            Action::InvitationResend => "invitation.resend",
            Action::UserTraitsUpdate => "user.traits.update",
            Action::UserExport => "user.export",
            Action::TraitSchemaCreate => "trait_schema.create",
            Action::TraitSchemaActivate => "trait_schema.activate",
            Action::TraitMigrationJobCreate => "trait_migration_job.create",
            Action::TraitMigrationJobAdvance => "trait_migration_job.advance",
            Action::MigrationRunCreate => "migration_run.create",
            Action::MigrationRunTransition => "migration_run.transition",
            Action::MigrationRunIngest => "migration_run.ingest",
            Action::MigrationRunBackfill => "migration_run.backfill",
            Action::MigrationRunReconcile => "migration_run.reconcile",
            Action::MigrationRunComplete => "migration_run.complete",
            Action::MigrationRunAbandon => "migration_run.abandon",
            Action::SessionCreate => "session.create",
            Action::SessionRotate => "session.rotate",
            Action::SessionRevoke => "session.revoke",
            Action::SessionsBulkRevoke => "sessions.bulk_revoke",
            Action::UserSessionsRevokeAll => "user.sessions.revoke_all",
            Action::ConsentGrant => "consent.grant",
            Action::SigningKeyProvision => "signing_key.provision",
            Action::ResourceServerRegister => "resource_server.register",
            Action::RefreshTokenIssue => "refresh_token.issue",
            Action::RefreshTokenRotate => "refresh_token.rotate",
            Action::RefreshTokenReuse => "refresh_token.reuse",
            Action::RefreshFamilyRevoke => "refresh_family.revoke",
            Action::TokenRevoke => "token.revoke",
            Action::PushedAuthorizationRequestPush => "pushed_authorization_request.push",
            Action::PushedAuthorizationRequestConsume => "pushed_authorization_request.consume",
            Action::ClientRequirePushedAuthorizationSet => {
                "client.require_pushed_authorization_requests.set"
            }
            Action::DcrInitialAccessTokenMint => "dcr.iat_minted",
            Action::DcrPolicyCreate => "dcr.policy_created",
            Action::DcrPolicyRejected => "dcr.policy_rejected",
            Action::DcrQuotaHit => "dcr.quota_hit",
            Action::DcrRateLimited => "dcr.rate_limited",
            Action::DcrClientVerified => "dcr.client_verified",
            Action::ServiceAccountCreate => "service_account.create",
            Action::ClientCustomClaimsSet => "client.custom_claims.set",
            Action::ExternalAssertionIssuerRegister => "external_assertion_issuer.register",
            Action::ExternalAssertionSubjectMappingCreate => {
                "external_assertion_subject_mapping.create"
            }
            Action::ExternalAssertionIssuerSetEnabled => "external_assertion_issuer.set_enabled",
            Action::ExternalAssertionSubjectMappingSetEnabled => {
                "external_assertion_subject_mapping.set_enabled"
            }
            Action::JwtBearerAssertionIssue => "jwt_bearer_assertion.issue",
            Action::ClientResourceIndicatorPolicySet => "client.resource_indicator_policy.set",
            Action::DeviceCodeIssue => "device_code.issue",
            Action::DeviceCodeApprove => "device_code.approve",
            Action::DeviceCodeDeny => "device_code.deny",
            Action::EnvelopeKekProvision => "envelope.kek.provision",
            Action::EnvelopeKekRotate => "envelope.kek.rotate",
            Action::EnvelopeKekDestroy => "envelope.kek.destroy",
            Action::EnvelopeByokEnroll => "envelope.byok.enroll",
            Action::EnvelopeDekProvision => "envelope.dek.provision",
            Action::EnvelopeDekRotate => "envelope.dek.rotate",
            Action::EncryptedSecretPut => "encrypted_secret.put",
            Action::EncryptedSecretReencrypt => "encrypted_secret.reencrypt",
            Action::CustomDomainRegister => "custom_domain.register",
            Action::CustomDomainChallengeSucceed => "custom_domain.challenge.succeed",
            Action::CustomDomainChallengeFail => "custom_domain.challenge.fail",
            Action::CustomDomainCertificateStore => "custom_domain.certificate.store",
            Action::EnvironmentVariableSet => "environment_variable.set",
            Action::EnvironmentVariableDelete => "environment_variable.delete",
            Action::EnvironmentSecretPut => "environment_secret.put",
            Action::EnvironmentSecretDelete => "environment_secret.delete",
            Action::ConfigPromotionApply => "config_promotion.apply",
            Action::AccountPasswordChange => "account.password.change",
            Action::AccountPasswordRemove => "account.password.remove",
            Action::AccountPasswordSet => "account.password.set",
            Action::AccountCredentialEnroll => "account.credential.enroll",
            Action::AccountCredentialRemove => "account.credential.remove",
            Action::WebauthnCredentialRegister => "webauthn.credential.register",
            Action::WebauthnCredentialRename => "webauthn.credential.rename",
            Action::WebauthnCredentialRemove => "webauthn.credential.remove",
            Action::WebauthnCloneDetected => "webauthn.clone.detected",
            Action::WebauthnBackupEligibilityMismatch => "webauthn.backup_eligibility.mismatch",
            Action::TotpEnrollBegin => "account.totp.enroll_begin",
            Action::TotpActivate => "account.totp.activate",
            Action::TotpVerify => "account.totp.verify",
            Action::TotpRemove => "account.totp.remove",
            Action::RecoveryCodesGenerate => "account.recovery_codes.generate",
            Action::RecoveryCodeRedeem => "account.recovery_code.redeem",
            Action::AccountSessionRevoke => "account.session.revoke",
            Action::TrustedDeviceRemember => "trusted_device.remember",
            Action::TrustedDeviceRevoke => "trusted_device.revoke",
            Action::AccountSessionsRevokeOthers => "account.sessions.revoke_others",
            Action::AbuseBanCreate => "abuse.ban.create",
            Action::AbuseBanLift => "abuse.ban.lift",
            Action::ScopeStepUpPolicySet => "step_up.scope_policy.set",
            Action::ScopeStepUpPolicyRemove => "step_up.scope_policy.remove",
            Action::ClientStepUpPolicySet => "client.step_up_policy.set",
            Action::AdminPrivilegeElevated => "admin.privilege.elevated",
            Action::AdminPrivilegeChallenged => "admin.privilege.challenged",
            Action::CredentialClassPolicySet => "credential_class.policy.set",
            Action::CredentialClassPolicyRemove => "credential_class.policy.remove",
            Action::AttestationConfigSet => "attestation.config.set",
            Action::Mds3BlobCacheRefresh => "mds3.blob_cache.refresh",
            Action::AaguidRuleSet => "aaguid.rule.set",
            Action::AaguidRuleRemove => "aaguid.rule.remove",
            Action::EmailOtpSend => "email_otp.send",
            Action::EmailOtpVerify => "email_otp.verify",
            Action::SmsOtpSend => "sms_otp.send",
            Action::SmsOtpVerify => "sms_otp.verify",
            Action::SmsRouteThrottled => "sms_route.throttled",
            Action::SmsConversionAlarm => "sms_route.conversion_alarm",
            Action::SmsConfigUpdate => "sms_config.update",
            Action::MagicLinkSend => "magic_link.send",
            Action::MagicLinkConsume => "magic_link.consume",
            Action::RecoveryInitiate => "recovery.initiate",
            Action::RecoveryCancel => "recovery.cancel",
            Action::RecoveryComplete => "recovery.complete",
            Action::RecoveryFactorChange => "recovery.factor_change",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The acting context a mutation runs under: who is acting and which request the
/// action belongs to.
///
/// Required for every write and for no read. It is threaded into the audit row
/// so the log answers "who did this, as part of which request" for every
/// mutation. Construct it once per request from the authenticated caller context
/// and the inbound correlation id (generate a fresh [`CorrelationId`] with
/// [`CorrelationId::generate`] when the caller supplies none).
#[derive(Debug, Clone, Copy)]
pub struct ActingContext {
    actor: ActorRef,
    correlation: CorrelationId,
}

impl ActingContext {
    /// Bind an actor and a correlation id into an acting context.
    #[must_use]
    pub fn new(actor: ActorRef, correlation: CorrelationId) -> Self {
        Self { actor, correlation }
    }

    /// The acting principal.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        self.actor
    }

    /// The correlation id this action belongs to.
    #[must_use]
    pub fn correlation(&self) -> CorrelationId {
        self.correlation
    }
}
