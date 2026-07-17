// SPDX-License-Identifier: MIT OR Apache-2.0

//! The wire types (request bodies and response views) of the management API.
//!
//! Every type here is both `serde` (the wire format) and `utoipa::ToSchema` (the
//! OpenAPI schema), so the served JSON and the generated spec are derived from
//! one definition and cannot drift. Timestamps are exposed as integer
//! milliseconds since the Unix epoch, which needs no date-library dependency and
//! is unambiguous; identifiers are the typed-prefix wire strings.

use std::fmt;

use ironauth_store::{
    EnvironmentRecord, GuardrailSet, InvitationAdminRecord, InvitationCredentialType,
    InvitationState, ManagementCredentialRecord, OperatorRecord, OrganizationRecord,
    RefreshFamilySummary, ResourceType, SessionSummary, TenantRecord, UserAdminRecord, UserState,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Milliseconds since the Unix epoch from stored microseconds.
fn ms(micros: i64) -> i64 {
    micros / 1000
}

/// A tenant, as returned by the management API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantView {
    /// The tenant identifier (`ten_...`).
    pub id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// The lifecycle status: `active` or `suspended` (issue #46). A suspended
    /// tenant is fenced off the data plane but keeps all its data and stays visible
    /// here.
    pub status: String,
    /// The recorded data-residency region (issue #46), or null when the deployment
    /// pins no region. Immutable after create; nothing routes by it yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_region: Option<String>,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl From<TenantRecord> for TenantView {
    fn from(record: TenantRecord) -> Self {
        Self {
            id: record.id.to_string(),
            display_name: record.display_name,
            status: record.status.as_str().to_owned(),
            home_region: record.home_region,
            created_at_unix_ms: ms(record.created_at_unix_micros),
        }
    }
}

/// An environment, as returned by the management API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnvironmentView {
    /// The environment identifier (`env_...`).
    pub id: String,
    /// The tenant the environment belongs to (`ten_...`).
    pub tenant_id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// The typed environment kind: `dev`, `staging`, or `prod` (issue #42).
    pub kind: String,
    /// The guardrail class the kind maps onto: `non-production` or `production`.
    pub guardrail_class: String,
    /// The configured custom domain, if any. A production environment always has
    /// one (the custom-domain guardrail); a non-production environment may omit it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_domain: Option<String>,
    /// The typed guardrails this environment enforces, derived from its kind.
    pub guardrails: GuardrailView,
    /// The recorded per-environment data-residency region pin (issue #46), or null
    /// when the environment pins no region. Immutable after create; nothing routes
    /// by it yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

/// The typed guardrails an environment enforces (issue #42), derived purely from
/// its kind so the production asymmetry can never drift.
// The guardrail flags are a flat set of independent booleans by design, mirroring
// the store's `GuardrailSet`; an enum would hide the per-guardrail table.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GuardrailView {
    /// Whether an `http` loopback redirect URI is registrable (true for
    /// non-production, false for production).
    pub allow_insecure_redirect_uris: bool,
    /// Whether every redirect URI must be `https` (true for production only).
    pub require_https_redirect_uris: bool,
    /// Whether a configured custom domain is required (true for production only).
    pub require_custom_domain: bool,
    /// Whether secret values are one-time-view (true for production only).
    pub one_time_view_secrets: bool,
    /// Whether hosted pages carry a `noindex` marker (true for non-production only).
    pub hosted_pages_noindex: bool,
    /// Whether a visible environment banner is shown (true for non-production only).
    pub show_environment_banner: bool,
}

impl From<GuardrailSet> for GuardrailView {
    fn from(set: GuardrailSet) -> Self {
        Self {
            allow_insecure_redirect_uris: set.allow_insecure_redirect_uris,
            require_https_redirect_uris: set.require_https_redirect_uris,
            require_custom_domain: set.require_custom_domain,
            one_time_view_secrets: set.one_time_view_secrets,
            hosted_pages_noindex: set.hosted_pages_noindex,
            show_environment_banner: set.show_environment_banner,
        }
    }
}

impl From<EnvironmentRecord> for EnvironmentView {
    fn from(record: EnvironmentRecord) -> Self {
        Self {
            id: record.id.to_string(),
            tenant_id: record.tenant_id.to_string(),
            display_name: record.display_name,
            kind: record.kind.as_str().to_owned(),
            guardrail_class: record.kind.guardrail_class().as_str().to_owned(),
            custom_domain: record.custom_domain,
            guardrails: record.kind.guardrails().into(),
            region: record.region,
            created_at_unix_ms: ms(record.created_at_unix_micros),
        }
    }
}

/// A management API key's metadata (never its secret), as returned on read.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ManagementKeyView {
    /// The key identifier (`mak_...`, embeds its scope; safe to display).
    pub id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl From<ManagementCredentialRecord> for ManagementKeyView {
    fn from(record: ManagementCredentialRecord) -> Self {
        Self {
            id: record.id.to_string(),
            display_name: record.display_name,
            created_at_unix_ms: ms(record.created_at_unix_micros),
        }
    }
}

/// The body to create a tenant. The first environment is created with it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    /// The tenant's display name.
    #[schema(example = "Acme, Inc.")]
    pub display_name: String,
    /// The first environment's display name. Defaults to `development`.
    #[serde(default)]
    pub environment_display_name: Option<String>,
    /// The first environment's kind: `dev`, `staging`, or `prod` (issue #42).
    /// Defaults to `dev`, the relaxed non-production kind that requires no custom
    /// domain, so a tenant is always creatable in one call with sane defaults.
    #[serde(default)]
    #[schema(example = "dev")]
    pub environment_kind: Option<String>,
    /// The first environment's custom domain, if any. Required only when
    /// `environment_kind` is `prod` (the production custom-domain guardrail).
    #[serde(default)]
    pub environment_custom_domain: Option<String>,
    /// The tenant's data-residency region (issue #46). When present it must be one
    /// of the operator's configured regions, is persisted immutably, and appears in
    /// every read; when omitted the tenant records no region. Nothing routes or
    /// replicates by it yet.
    #[serde(default)]
    #[schema(example = "eu-west")]
    pub home_region: Option<String>,
}

/// The result of a tenant lifecycle transition (issue #46): the tenant id and its
/// new status. It states the POST-CONDITION (what is true after the call), so the
/// body is known before the write and stored verbatim for an Idempotency-Key
/// replay, exactly like the session-revocation views.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantStatusView {
    /// The tenant identifier (`ten_...`).
    pub id: String,
    /// The tenant's status after the transition: `active` or `suspended`.
    pub status: String,
}

/// The result of creating a tenant: the tenant and its first environment.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantCreated {
    /// The created tenant.
    pub tenant: TenantView,
    /// The tenant's first environment.
    pub environment: EnvironmentView,
}

/// The body to create an environment under a tenant.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateEnvironmentRequest {
    /// The environment's display name.
    #[schema(example = "staging")]
    pub display_name: String,
    /// The environment kind: `dev`, `staging`, or `prod` (issue #42). Required;
    /// an unknown value is rejected. The kind fixes the environment's guardrail
    /// class (dev and staging inherit the relaxed non-production set; prod gets
    /// the hard production set).
    #[schema(example = "staging")]
    pub kind: String,
    /// The custom domain to configure. Required when `kind` is `prod` (the
    /// production custom-domain guardrail); optional otherwise.
    #[serde(default)]
    pub custom_domain: Option<String>,
    /// The environment's data-residency region pin (issue #46). When present it must
    /// be one of the operator's configured regions (the same set the tenant
    /// `home_region` validates against), is persisted immutably, and appears in every
    /// read; when omitted the environment records no region. Nothing routes or
    /// replicates by it yet.
    #[serde(default)]
    #[schema(example = "eu-west")]
    pub region: Option<String>,
}

/// The body to mint a management API key in a `(tenant, environment)` scope.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateManagementKeyRequest {
    /// The key's display name.
    #[schema(example = "ci-terraform")]
    pub display_name: String,
}

/// The result of minting a management API key.
///
/// On the genuine first creation (HTTP 201) `secret` carries the full bearer
/// token, shown exactly ONCE, and `secret_already_issued` is false. The secret
/// is never stored, so an idempotent replay of the same POST (HTTP 200) returns
/// this same view with `secret` OMITTED and `secret_already_issued` true. Store
/// the secret on first receipt; it is never retrievable again.
///
/// `Debug` is hand-written to redact the secret so a live token can never reach
/// a log line through `{value:?}`.
#[derive(Clone, Serialize, ToSchema)]
pub struct ManagementKeyCreated {
    /// The key identifier (`mak_...`).
    pub id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// The full bearer token, present ONLY on the first creation (HTTP 201) and
    /// never stored. Present it as `Authorization: Bearer <secret>`. Absent on an
    /// idempotent replay (HTTP 200); see `secret_already_issued`. Never
    /// retrievable again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// True on an idempotent replay, when the secret has already been issued and
    /// is not repeated. False on the first creation.
    pub secret_already_issued: bool,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl fmt::Debug for ManagementKeyCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the secret: the struct must never print a live token, even when
        // it is present on the first-creation view.
        f.debug_struct("ManagementKeyCreated")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field(
                "secret",
                &self.secret.as_ref().map(|_| ironauth_config::REDACTED),
            )
            .field("secret_already_issued", &self.secret_already_issued)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .finish()
    }
}

/// A page of tenants.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantList {
    /// The tenants on this page, oldest first.
    pub items: Vec<TenantView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A page of environments.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnvironmentList {
    /// The environments on this page, oldest first.
    pub items: Vec<EnvironmentView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A page of management API keys.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ManagementKeyList {
    /// The keys on this page, oldest first.
    pub items: Vec<ManagementKeyView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// The four-level resource model as public APIs (issue #41): operators (the
// operator plane above tenants) and organizations (the minimal per-environment
// shell), plus the machine-readable promotable/runtime/environment-identity
// classification of every resource type.
// ---------------------------------------------------------------------------

/// An operator, as returned by the management API. The operator plane is the root
/// of the four-level model; its identifier embeds neither a tenant nor an
/// environment.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OperatorView {
    /// The operator identifier (`op_...`).
    pub id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl From<OperatorRecord> for OperatorView {
    fn from(record: OperatorRecord) -> Self {
        Self {
            id: record.id.to_string(),
            display_name: record.display_name,
            created_at_unix_ms: ms(record.created_at_unix_micros),
        }
    }
}

/// A page of operators.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OperatorList {
    /// The operators on this page, oldest first.
    pub items: Vec<OperatorView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// An organization, as returned by the management API. Organizations live inside
/// environments, so the identifier embeds both the tenant and the environment.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrganizationView {
    /// The organization identifier (`org_...`, embeds its scope).
    pub id: String,
    /// The tenant the organization belongs to (`ten_...`).
    pub tenant_id: String,
    /// The environment the organization lives in (`env_...`).
    pub environment_id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// Whether the organization is active. Always true on a read (a deactivated
    /// organization reads as not-found); present so the wire shape carries the
    /// active-state field the resource model declares.
    pub active: bool,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl OrganizationView {
    /// Build a view from a stored record. `active` is always true here: the
    /// repository only returns live organizations.
    #[must_use]
    pub fn from_record(record: OrganizationRecord) -> Self {
        Self {
            id: record.id.to_string(),
            tenant_id: record.id.scope().tenant().to_string(),
            environment_id: record.id.scope().environment().to_string(),
            display_name: record.display_name,
            active: true,
            created_at_unix_ms: ms(record.created_at_unix_micros),
        }
    }
}

/// The body to create an organization in an environment.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    /// The organization's display name.
    #[schema(example = "Globex Corporation")]
    pub display_name: String,
}

/// A page of organizations.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrganizationList {
    /// The organizations on this page, oldest first.
    pub items: Vec<OrganizationView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// One resource type's promotion classification, as served by the resource-model
/// metadata endpoint. This is the machine-readable classification the snapshot
/// export (5.3) and the promotion engine (5.4) consume so they never maintain a
/// parallel promotable/runtime list.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResourceTypeView {
    /// The resource type's stable wire name (for example `organization`).
    pub name: String,
    /// The scope level its identifier is defined at (`operator`, `tenant`, or
    /// `environment`).
    pub level: String,
    /// The promotion classification: `promotable`, `runtime`, or
    /// `environment-identity`.
    pub classification: String,
}

impl From<ResourceType> for ResourceTypeView {
    fn from(resource: ResourceType) -> Self {
        Self {
            name: resource.as_str().to_owned(),
            level: resource.level().as_str().to_owned(),
            classification: resource.classification().as_str().to_owned(),
        }
    }
}

/// The resource-type classification catalog.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResourceTypesList {
    /// Every first-class resource type and its classification.
    pub items: Vec<ResourceTypeView>,
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration abuse controls (issue #31).
// ---------------------------------------------------------------------------

/// The body to create a named, reusable DCR policy (issue #31).
///
/// `primitives` is the ordered list of policy primitives, each a JSON object with a
/// `kind` of `force`, `restrict`, `reject`, or `default` plus its fields (a `force`
/// or `default` carries `property` and `value`; a `restrict` carries `property` and
/// `allowed`; a `reject` carries `property`). The management API validates the shape
/// at create time against the OIDC policy engine.
///
/// FOOTGUN: `restrict` only narrows a property that is PRESENT; an OMITTED property is
/// unconstrained by it, and the endpoint then applies the spec default for the omitted
/// property. So a `restrict` whose `allowed` set excludes the spec default can be
/// dodged by simply omitting the property (the client ends up with the default the
/// restrict meant to forbid). To make a property mandatory and pinned, pair the
/// `restrict` with a `default` (fills the omitted value so the restrict validates a
/// present one) or a `force` (overrides it outright). This holds at registration AND
/// at RFC 7592 update time.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateDcrPolicyRequest {
    /// The policy name, unique per environment (referenced by name at token mint).
    #[schema(example = "force-private-key-jwt")]
    pub name: String,
    /// The ordered primitive list (force / restrict / reject / default objects).
    pub primitives: Vec<serde_json::Value>,
}

/// A DCR policy, as returned by the management API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DcrPolicyView {
    /// The policy identifier (`pol_...`).
    pub id: String,
    /// The policy name.
    pub name: String,
    /// The ordered primitive list (as stored).
    pub primitives: Vec<serde_json::Value>,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

/// A page of DCR policies.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DcrPolicyList {
    /// The policies on this page, oldest first.
    pub items: Vec<DcrPolicyView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The body to mint a DCR initial access token (RFC 7591, issue #31).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateInitialAccessTokenRequest {
    /// The ordered names of the policies to attach as this token's chain. Each must
    /// name a policy that exists in this environment; the chain is resolved to its
    /// primitives and snapshotted onto the token, so a later edit of a named policy
    /// never changes an already-minted token. Empty means an unconstrained token.
    #[serde(default)]
    pub policy_names: Vec<String>,
    /// The token lifetime in seconds from now (from the server clock).
    #[schema(example = 86_400)]
    pub expires_in_secs: u64,
    /// The maximum number of registrations this token may authorize, or null for
    /// unlimited (within its lifetime).
    #[serde(default)]
    pub max_uses: Option<u32>,
}

/// The result of minting a DCR initial access token.
///
/// On the genuine first creation (HTTP 201) `token` carries the plaintext bearer
/// token, shown exactly ONCE and never stored. An idempotent replay (HTTP 200) omits
/// it and sets `token_already_issued`.
///
/// `Debug` is hand-written to redact the token so a live credential never reaches a
/// log line through `{value:?}`.
#[derive(Clone, Serialize, ToSchema)]
pub struct InitialAccessTokenCreated {
    /// The token identifier (`iat_...`; embeds its scope; safe to display).
    pub id: String,
    /// The plaintext bearer token, present ONLY on the first creation (HTTP 201) and
    /// never stored. Present it as `Authorization: Bearer <token>` at registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// True on an idempotent replay, when the token has already been issued and is
    /// not repeated.
    pub token_already_issued: bool,
    /// Expiry time, milliseconds since the Unix epoch.
    pub expires_at_unix_ms: i64,
    /// The usage limit, or null for unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl fmt::Debug for InitialAccessTokenCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialAccessTokenCreated")
            .field("id", &self.id)
            .field(
                "token",
                &self.token.as_ref().map(|_| ironauth_config::REDACTED),
            )
            .field("token_already_issued", &self.token_already_issued)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("max_uses", &self.max_uses)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .finish()
    }
}

/// A dynamically registered client's verification state (issue #31), as returned by
/// the management API. `quarantined` is the live gate the authorization/consent path
/// honors; `verified_at_unix_ms` records when an admin lifted the quarantine.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientVerificationView {
    /// The client identifier (`cli_...`).
    pub id: String,
    /// Whether the client is under the unverified-client quarantine.
    pub quarantined: bool,
    /// Whether an admin has verified the client (the quarantine is lifted).
    pub verified: bool,
    /// When the client was verified, milliseconds since the Unix epoch, or null if
    /// never verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at_unix_ms: Option<i64>,
}

/// A session, as the fleet-operations surface reports it (issue #32).
///
/// Sessions are first-class, searchable, metadata-carrying fleet resources rather
/// than an opaque internal table. The view deliberately reports REVOKED, ROTATED, and
/// ENDED sessions too (not just live ones), so an operator can inspect the whole
/// lifecycle: `ended_at` plus `end_cause` say when and why, and `superseded_by` names
/// the successor when the session was rotated away at a privilege transition.
///
/// `user_agent` and `peer_ip` are present only when the operator enabled the
/// corresponding OFF-BY-DEFAULT binding knob, so the safe default records neither.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionView {
    /// The session identifier (`ses_...`).
    pub id: String,
    /// The authenticated end-user subject (`usr_...`).
    pub subject: String,
    /// The recorded authentication methods (space-separated RFC 8176 values).
    pub auth_methods: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// When the session was last seen, milliseconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at_unix_ms: Option<i64>,
    /// The idle timeout, milliseconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_expires_at_unix_ms: Option<i64>,
    /// The absolute hard-cap expiry, milliseconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute_expires_at_unix_ms: Option<i64>,
    /// When the session was revoked, milliseconds since the Unix epoch, or null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<i64>,
    /// When the session ended (revoked or rotated away), or null if it is live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_unix_ms: Option<i64>,
    /// Why the session ended (`revoked`, `bulk_revoked`, `user_revoked_all`,
    /// `logged_out`, or `rotated`), or null if it is live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_cause: Option<String>,
    /// The successor session id when this one was ROTATED away, or null. Its presence
    /// is what distinguishes a rotation from a terminal end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// The recorded user agent (only when the device binding knob is on).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// The recorded peer IP (only when the peer-IP binding knob is on).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
}

impl From<SessionSummary> for SessionView {
    fn from(record: SessionSummary) -> Self {
        Self {
            id: record.id,
            subject: record.subject,
            auth_methods: record.auth_methods,
            created_at_unix_ms: ms(record.created_at_unix_micros),
            last_seen_at_unix_ms: record.last_seen_at_unix_micros.map(ms),
            idle_expires_at_unix_ms: record.idle_expires_at_unix_micros.map(ms),
            absolute_expires_at_unix_ms: record.absolute_expires_at_unix_micros.map(ms),
            revoked_at_unix_ms: record.revoked_at_unix_micros.map(ms),
            ended_at_unix_ms: record.ended_at_unix_micros.map(ms),
            end_cause: record.end_cause,
            superseded_by: record.superseded_by,
            user_agent: record.user_agent,
            peer_ip: record.peer_ip,
        }
    }
}

/// A page of sessions.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionList {
    /// The sessions in this page.
    pub items: Vec<SessionView>,
    /// The cursor for the next page, or null when this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A refresh-token family, as the fleet-operations surface reports it (issue #32).
/// Families are searchable fleet resources alongside sessions, so an operator can see
/// exactly which long-lived credential chains a user or a client holds.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RefreshFamilyView {
    /// The family identifier (`rff_...`).
    pub id: String,
    /// The authenticated end-user subject the family's tokens are minted for.
    pub subject: String,
    /// The OAuth client the family belongs to.
    pub client_id: String,
    /// The granted OAuth scope the family was issued against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The authenticating SSO session (`ses_...`), when a session backed the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    /// Whether this is an `offline_access` family. An offline family SURVIVES a
    /// logout and a session revocation (issue #21); only an explicit hard kill ends
    /// it.
    pub offline: bool,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// The absolute hard cap on the family's rotated lifetime.
    pub absolute_expires_at_unix_ms: i64,
    /// When the family was revoked, milliseconds since the Unix epoch, or null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<i64>,
}

impl From<RefreshFamilySummary> for RefreshFamilyView {
    fn from(record: RefreshFamilySummary) -> Self {
        Self {
            id: record.id,
            subject: record.subject,
            client_id: record.client_id,
            scope: record.scope,
            session_ref: record.session_ref,
            offline: record.offline,
            created_at_unix_ms: ms(record.created_at_unix_micros),
            absolute_expires_at_unix_ms: ms(record.absolute_expires_at_unix_micros),
            revoked_at_unix_ms: record.revoked_at_unix_micros.map(ms),
        }
    }
}

/// A page of refresh-token families.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RefreshFamilyList {
    /// The families in this page.
    pub items: Vec<RefreshFamilyView>,
    /// The cursor for the next page, or null when this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The body of a single-session or revoke-everything-for-a-user revocation (issue
/// #32). Both fields are optional, so an empty body is a plain, offline-preserving
/// revoke.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct RevokeSessionsRequest {
    /// Also revoke the user's `offline_access` refresh families AND their grants, so
    /// every already-issued access token dies immediately (a HARD KILL).
    ///
    /// The default (`false`) PRESERVES the `offline_access` families, which is the
    /// documented offline-survives-logout semantic (issue #21): a background job
    /// holding an offline token keeps working when the user's browser session is
    /// revoked. Set this only when the intent is to cut a compromised principal off
    /// from everything.
    #[serde(default)]
    pub hard_kill: bool,
}

/// The body of a BULK session revocation (issue #32).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct BulkRevokeSessionsRequest {
    /// The sessions to revoke. Every id is scope-FENCED: one belonging to another
    /// tenant or environment is a uniform no-op (never an error that would confirm
    /// its existence), so a batch can never reach across a scope boundary.
    #[serde(default)]
    pub session_ids: Vec<String>,
    /// Also revoke the `offline_access` families and their grants (a HARD KILL). The
    /// default preserves them; see [`RevokeSessionsRequest::hard_kill`].
    #[serde(default)]
    pub hard_kill: bool,
}

/// The result of revoking one session (issue #32).
///
/// Every revocation view states the POST-CONDITION (what is true now), never a delta
/// (how many rows this particular call happened to flip). That is deliberate, and it
/// is what makes the two cross-cutting contracts hold at once:
///
/// - **Idempotency-Key replay.** The stored response is written in the SAME
///   transaction as the revocation, so its body must be known before the write. A
///   post-condition is; a row count is not.
/// - **The anti-oracle.** An absent session, a session in ANOTHER tenant, and an
///   already-revoked session all produce the identical response, so the surface never
///   confirms which sessions exist.
///
/// The actual cascade is observable where it belongs: the refresh-family fleet list,
/// which shows exactly which families were revoked and which `offline_access`
/// families survived.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionRevocationView {
    /// The session that was targeted.
    pub id: String,
    /// Always true: after this call the session does not resolve, whether it was live,
    /// already revoked, or absent (the anti-oracle).
    pub revoked: bool,
    /// Whether the `offline_access` refresh families were killed too. When false (the
    /// default) they SURVIVE, which is issue #21's offline-survives-logout semantic.
    pub hard_kill: bool,
}

/// The result of a BULK session revocation (issue #32). States the post-condition; see
/// [`SessionRevocationView`] for why.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkRevocationView {
    /// How many of the named sessions were IN SCOPE and therefore targeted. Ids that
    /// were malformed or belonged to another tenant or environment are silently
    /// dropped (scope fence), so this can be lower than the number of ids sent.
    pub sessions_targeted: u64,
    /// Whether the `offline_access` refresh families were killed too.
    pub hard_kill: bool,
}

/// The result of revoking every session of one user (issue #32). States the
/// post-condition; see [`SessionRevocationView`] for why.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserRevocationView {
    /// The user that was targeted.
    pub subject: String,
    /// Always true: after this call none of the user's sessions resolve.
    pub revoked: bool,
    /// Whether the user's `offline_access` refresh families were killed too. When
    /// false (the default) they SURVIVE the mass logout.
    pub hard_kill: bool,
}

/// A user's lifecycle state on the wire (issue #52). The stable, closed enum the
/// management API exposes: state changes are explicit API operations validated
/// against a state machine in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserStateView {
    /// A live account that can authenticate.
    Active,
    /// Administratively blocked: cannot authenticate; sessions ended on entry.
    Blocked,
    /// Disabled: cannot authenticate; sessions ended on entry.
    Disabled,
    /// Created but not yet verified: cannot authenticate until activated.
    PendingVerification,
    /// Scheduled for offboarding at a recorded instant; still able to authenticate
    /// until the worker executes it.
    ScheduledOffboarding,
}

impl From<UserState> for UserStateView {
    fn from(state: UserState) -> Self {
        match state {
            UserState::Active => UserStateView::Active,
            UserState::Blocked => UserStateView::Blocked,
            UserState::Disabled => UserStateView::Disabled,
            UserState::PendingVerification => UserStateView::PendingVerification,
            UserState::ScheduledOffboarding => UserStateView::ScheduledOffboarding,
        }
    }
}

impl From<UserStateView> for UserState {
    fn from(view: UserStateView) -> Self {
        match view {
            UserStateView::Active => UserState::Active,
            UserStateView::Blocked => UserState::Blocked,
            UserStateView::Disabled => UserState::Disabled,
            UserStateView::PendingVerification => UserState::PendingVerification,
            UserStateView::ScheduledOffboarding => UserState::ScheduledOffboarding,
        }
    }
}

/// A user, as returned by the management API (issue #52). The identifier embeds its
/// tenant and environment. NEVER carries the password hash (a management response
/// must not return a stored credential, the #11 secret lesson).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserView {
    /// The user identifier (`usr_...`, embeds its scope).
    pub id: String,
    /// The tenant the user belongs to (`ten_...`).
    pub tenant_id: String,
    /// The environment the user lives in (`env_...`).
    pub environment_id: String,
    /// The login handle (decrypted for display).
    pub identifier: String,
    /// The lifecycle state.
    pub state: UserStateView,
    /// The external correlation id (decrypted for display), or null when none is
    /// linked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The scheduled-offboarding instant (milliseconds since the Unix epoch),
    /// present only in the scheduled-offboarding state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_offboarding_at_unix_ms: Option<i64>,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-mutation time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl UserView {
    /// Build a view from a stored record.
    #[must_use]
    pub fn from_record(record: UserAdminRecord) -> Self {
        Self {
            id: record.id.to_string(),
            tenant_id: record.id.scope().tenant().to_string(),
            environment_id: record.id.scope().environment().to_string(),
            identifier: record.identifier,
            state: record.state.into(),
            external_id: record.external_id,
            scheduled_offboarding_at_unix_ms: record.scheduled_offboarding_at_unix_micros.map(ms),
            created_at_unix_ms: ms(record.created_at_unix_micros),
            updated_at_unix_ms: ms(record.updated_at_unix_micros),
        }
    }
}

/// A page of users.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserList {
    /// The users on this page, oldest first.
    pub items: Vec<UserView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The body to create a user (issue #52). Every field but `identifier` is optional.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    /// An OPTIONAL caller-supplied user id (`usr_...`, in this scope). A supplied id
    /// already taken in the scope returns 409; absent, a fresh id is minted.
    #[serde(default)]
    pub id: Option<String>,
    /// The login handle, unique per scope.
    #[schema(example = "ada@example.test")]
    pub identifier: String,
    /// An OPTIONAL precomputed Argon2id PHC verifier string. Absent, the user is
    /// created without a usable credential and cannot log in until one is set.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// An OPTIONAL standard-claim JSON document (issue #15), stored verbatim.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub claims: Option<serde_json::Value>,
    /// An OPTIONAL external correlation id to link at creation (unique per scope).
    #[serde(default)]
    pub external_id: Option<String>,
    /// The OPTIONAL initial lifecycle state (default `active`). Must be a creatable
    /// state (not `scheduled_offboarding`, which needs a timestamp).
    #[serde(default)]
    pub state: Option<UserStateView>,
}

/// The body to update a user (issue #52), applied as an RFC 7396 JSON Merge Patch
/// over the mutable profile. Only the standard-claim document is updatable here;
/// the lifecycle state and external id have their own explicit operations.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    /// The replacement standard-claim JSON document. Absent leaves the claims
    /// unchanged.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub claims: Option<serde_json::Value>,
}

/// The body to transition a user's lifecycle state (issue #52).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetUserStateRequest {
    /// The target state.
    pub state: UserStateView,
    /// Required for and only for `scheduled_offboarding`: the instant the worker
    /// executes the offboarding, in milliseconds since the Unix epoch.
    #[serde(default)]
    pub scheduled_offboarding_at_unix_ms: Option<i64>,
    /// Whether a session-ending transition also kills the user's `offline_access`
    /// refresh families (default false: they survive).
    #[serde(default)]
    pub hard_kill: bool,
}

/// A user's lifecycle state after a transition (issue #52). The deterministic
/// post-condition returned by the state and delete operations.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserStateChangeView {
    /// The user that was transitioned.
    pub id: String,
    /// The state the user is now in.
    pub state: UserStateView,
    /// Whether the transition killed the user's `offline_access` refresh families.
    pub hard_kill: bool,
}

/// The body to link an external id to a user (issue #52).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct LinkExternalIdRequest {
    /// The external correlation id from the tenant's own systems (unique per scope).
    #[schema(example = "crm-42")]
    pub external_id: String,
}

/// A user's external id after a link or unlink (issue #52).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserExternalIdView {
    /// The user the external id belongs to.
    pub id: String,
    /// The linked external id, or null after an unlink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// The primary-login credential an invitation enrolls on accept (issue #60): a
/// password (the #20 Argon2id path) or a passkey deep link (the Zitadel enrollment
/// pattern). The stable, closed wire enum the management API exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InvitationCredentialTypeView {
    /// The invitee sets a password (an Argon2id verifier) on accept.
    Password,
    /// The invitee enrolls a passkey; no password is ever provisioned.
    Passkey,
}

impl From<InvitationCredentialType> for InvitationCredentialTypeView {
    fn from(kind: InvitationCredentialType) -> Self {
        match kind {
            InvitationCredentialType::Password => InvitationCredentialTypeView::Password,
            InvitationCredentialType::Passkey => InvitationCredentialTypeView::Passkey,
        }
    }
}

impl From<InvitationCredentialTypeView> for InvitationCredentialType {
    fn from(view: InvitationCredentialTypeView) -> Self {
        match view {
            InvitationCredentialTypeView::Password => InvitationCredentialType::Password,
            InvitationCredentialTypeView::Passkey => InvitationCredentialType::Passkey,
        }
    }
}

/// An invitation's lifecycle state on the wire (issue #60): pending until it is
/// redeemed (accepted) or invalidated (revoked). Both terminal states make the
/// token unredeemable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStateView {
    /// Awaiting redemption: the token can still be accepted until it expires.
    Pending,
    /// Redeemed: the invitee accepted it and the user was activated. Terminal.
    Accepted,
    /// Revoked by an admin before acceptance. Terminal.
    Revoked,
}

impl From<InvitationState> for InvitationStateView {
    fn from(state: InvitationState) -> Self {
        match state {
            InvitationState::Pending => InvitationStateView::Pending,
            InvitationState::Accepted => InvitationStateView::Accepted,
            InvitationState::Revoked => InvitationStateView::Revoked,
        }
    }
}

impl From<InvitationStateView> for InvitationState {
    fn from(view: InvitationStateView) -> Self {
        match view {
            InvitationStateView::Pending => InvitationState::Pending,
            InvitationStateView::Accepted => InvitationState::Accepted,
            InvitationStateView::Revoked => InvitationState::Revoked,
        }
    }
}

/// An invitation, as returned by the management API (issue #60). This is the
/// DURABLE representation: it NEVER carries the token or its digest (the raw token
/// is delivered ONCE at create/resend and only its digest is ever stored, so a
/// database dump yields nothing replayable). The invited identifier is decrypted
/// from its sealed column for display.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationView {
    /// The invitation identifier (`inv_...`, embeds its scope).
    pub id: String,
    /// The tenant the invitation belongs to (`ten_...`).
    pub tenant_id: String,
    /// The environment the invitation lives in (`env_...`).
    pub environment_id: String,
    /// The `pending_verification` user (`usr_...`) this invitation provisions and
    /// activates on accept.
    pub user_id: String,
    /// The invited identifier (an email or login handle), decrypted for display.
    pub target_identifier: String,
    /// The primary-login credential the invitee enrolls on accept.
    pub credential_type: InvitationCredentialTypeView,
    /// The lifecycle state.
    pub state: InvitationStateView,
    /// The opaque org handle M10 layers membership on, or null when none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_context: Option<String>,
    /// When the token expires, milliseconds since the Unix epoch.
    pub expires_at_unix_ms: i64,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-mutation time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
    /// When the invitation was redeemed, present only in the accepted state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at_unix_ms: Option<i64>,
    /// When the invitation was revoked, present only in the revoked state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<i64>,
}

impl InvitationView {
    /// Build a view from a stored record.
    #[must_use]
    pub fn from_record(record: InvitationAdminRecord) -> Self {
        Self {
            id: record.id.to_string(),
            tenant_id: record.id.scope().tenant().to_string(),
            environment_id: record.id.scope().environment().to_string(),
            user_id: record.user_id.to_string(),
            target_identifier: record.target_identifier,
            credential_type: record.credential_type.into(),
            state: record.state.into(),
            org_context: record.org_context,
            expires_at_unix_ms: ms(record.expires_at_unix_micros),
            created_at_unix_ms: ms(record.created_at_unix_micros),
            updated_at_unix_ms: ms(record.updated_at_unix_micros),
            accepted_at_unix_ms: record.accepted_at_unix_micros.map(ms),
            revoked_at_unix_ms: record.revoked_at_unix_micros.map(ms),
        }
    }
}

/// A page of invitations.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationList {
    /// The invitations on this page, oldest first.
    pub items: Vec<InvitationView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The body to create an invitation (issue #60). The invited `identifier` is
/// required; every other field has a safe default.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    /// The invited identifier (an email or other login handle), unique per scope: a
    /// `pending_verification` user is provisioned for it. An identifier already in use
    /// by an existing user returns 409.
    #[schema(example = "ada@example.test")]
    pub identifier: String,
    /// The OPTIONAL primary-login credential the invitee enrolls on accept (default
    /// `password`). A `passkey` invitation provisions no password.
    #[serde(default)]
    pub credential_type: Option<InvitationCredentialTypeView>,
    /// An OPTIONAL opaque org handle M10 layers membership semantics on. Carried,
    /// not interpreted here.
    #[serde(default)]
    pub org_context: Option<String>,
    /// The OPTIONAL token lifetime in seconds (default: the configured invitation
    /// TTL). Bounds how long the invite link stays acceptable.
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
}

/// The result of creating (or resending) an invitation (issue #60): the durable
/// invitation, PLUS the raw single-use token returned exactly ONCE for out-of-band
/// delivery. The token is NEVER readable again and is never persisted (only its
/// digest is stored), so an idempotent replay of the POST returns the invitation
/// WITHOUT the token.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationCreatedView {
    /// The created (or resent) invitation.
    pub invitation: InvitationView,
    /// The raw `ira_inv_...` single-use token, returned ONCE at creation/resend for
    /// out-of-band delivery to the invitee. Absent on an idempotent replay (the
    /// token is shown only at the original creation). Compose the accept link by
    /// presenting this token to the public invitation-accept endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// An invitation's lifecycle state after a revoke (issue #60): the deterministic
/// post-condition, so an Idempotency-Key replay is byte-identical.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationStateChangeView {
    /// The invitation that was transitioned.
    pub id: String,
    /// The state the invitation is now in.
    pub state: InvitationStateView,
}

// ---------------------------------------------------------------------------
// Federation connectors (issue #75).
// ---------------------------------------------------------------------------

/// The body to create or replace a federation connector (issue #75): the declarative
/// connector definition itself. The management API parses it with the strict
/// `ironauth-connector` layer (`deny_unknown_fields` plus the semantic validator), so
/// an unknown key or a semantic fault is a 400 carrying a JSON-pointer error. This
/// view documents the top-level shape; the FULL, authoritative JSON Schema is
/// published at `docs/connector-schema.json`.
// Doc-only: the management API parses the request body directly into
// `ironauth_connector::ConnectorDefinition` (the single source of truth for the
// definition shape and its strict validation), so these fields are referenced only
// by the generated OpenAPI schema, never read in code.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateConnectorRequest {
    /// The connector slug (lowercase ASCII alphanumerics, hyphen, underscore), unique
    /// per environment.
    #[schema(example = "acme-oidc")]
    pub connector_id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// The federation protocol (`oidc` only in this slice).
    #[schema(example = "oidc")]
    pub protocol: String,
    /// The upstream endpoints: EITHER `{ "issuer": "..." }` OR
    /// `{ "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"? }`.
    pub endpoints: serde_json::Value,
    /// The scopes requested from the upstream (`openid` is required).
    pub scopes: Vec<String>,
    /// The client identifier IronAuth registers at the upstream.
    pub client_id: String,
    /// The upstream client secret by indirection (`"..."`, `{ "file": "/path" }`, or
    /// `{ "env": "VAR" }`); sealed at rest, never returned by a read.
    pub client_secret: serde_json::Value,
    /// How PKCE is applied to the upstream (`auto_where_supported` / `required` /
    /// `disabled`).
    #[serde(default)]
    pub pkce: Option<String>,
    /// The declarative claim mapping (the stored shape).
    #[serde(default)]
    pub claim_mapping: Option<serde_json::Value>,
    /// The capability matrix (conservative defaults; `email_verified_trust` defaults
    /// to `untrusted`).
    #[serde(default)]
    pub capabilities: Option<serde_json::Value>,
    /// Provider quirks expressed as data.
    #[serde(default)]
    pub quirks: Option<serde_json::Value>,
}

/// The per-connector capability matrix (issue #75), exposed by the management API.
/// SECRET-FREE: the upstream client secret is never part of this view.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorCapabilitiesView {
    /// Whether the upstream supports refresh tokens.
    pub refresh: bool,
    /// Whether the upstream delivers group memberships.
    pub groups: bool,
    /// Whether the upstream supports logout propagation.
    pub logout_propagation: bool,
    /// How much the upstream's `email_verified` claim is trusted (`untrusted` /
    /// `trusted`); defaults to `untrusted` for a new connector.
    #[schema(example = "untrusted")]
    pub email_verified_trust: String,
}

/// A federation connector, as returned by the management API (issue #75). SECRET-FREE:
/// the `definition` carries no `client_secret` and the sealed upstream secret is never
/// projected.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorView {
    /// The connector identifier (`cnr_...`).
    pub id: String,
    /// The connector slug (unique per environment).
    pub connector_slug: String,
    /// The connector's secret-free definition document (no `client_secret`).
    pub definition: serde_json::Value,
    /// Whether the connector is active.
    pub enabled: bool,
    /// The capability matrix derived from the definition.
    pub capabilities: ConnectorCapabilitiesView,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-update time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

/// A cursor-paginated page of federation connectors (issue #75).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectorList {
    /// The connectors on this page.
    pub items: Vec<ConnectorView>,
    /// The opaque cursor for the next page, or absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}
