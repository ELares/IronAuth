// SPDX-License-Identifier: MIT OR Apache-2.0

//! The wire types (request bodies and response views) of the management API.
//!
//! Every type here is both `serde` (the wire format) and `utoipa::ToSchema` (the
//! OpenAPI schema), so the served JSON and the generated spec are derived from
//! one definition and cannot drift. Timestamps are exposed as integer
//! milliseconds since the Unix epoch, which needs no date-library dependency and
//! is unambiguous; identifiers are the typed-prefix wire strings.

use std::fmt;

use ironauth_store::{EnvironmentRecord, ManagementCredentialRecord, TenantRecord};
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
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl From<TenantRecord> for TenantView {
    fn from(record: TenantRecord) -> Self {
        Self {
            id: record.id.to_string(),
            display_name: record.display_name,
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
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

impl From<EnvironmentRecord> for EnvironmentView {
    fn from(record: EnvironmentRecord) -> Self {
        Self {
            id: record.id.to_string(),
            tenant_id: record.tenant_id.to_string(),
            display_name: record.display_name,
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
    /// The first environment's display name. Defaults to `production`.
    #[serde(default)]
    pub environment_display_name: Option<String>,
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
// Dynamic Client Registration abuse controls (issue #31).
// ---------------------------------------------------------------------------

/// The body to create a named, reusable DCR policy (issue #31).
///
/// `primitives` is the ordered list of policy primitives, each a JSON object with a
/// `kind` of `force`, `restrict`, `reject`, or `default` plus its fields (a `force`
/// or `default` carries `property` and `value`; a `restrict` carries `property` and
/// `allowed`; a `reject` carries `property`). The management API validates the shape
/// at create time against the OIDC policy engine.
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
