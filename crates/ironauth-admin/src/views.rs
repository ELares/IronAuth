// SPDX-License-Identifier: MIT OR Apache-2.0

//! The wire types (request bodies and response views) of the management API.
//!
//! Every type here is both `serde` (the wire format) and `utoipa::ToSchema` (the
//! OpenAPI schema), so the served JSON and the generated spec are derived from
//! one definition and cannot drift. Timestamps are exposed as integer
//! milliseconds since the Unix epoch, which needs no date-library dependency and
//! is unambiguous; identifiers are the typed-prefix wire strings.

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

/// The result of minting a management API key. The `secret` is returned exactly
/// once and never stored in plaintext; store it now or mint a new key.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ManagementKeyCreated {
    /// The key identifier (`mak_...`).
    pub id: String,
    /// The human-facing display name.
    pub display_name: String,
    /// The full bearer token, shown ONCE. Present it as `Authorization: Bearer
    /// <secret>`. It is never retrievable again.
    pub secret: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
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
