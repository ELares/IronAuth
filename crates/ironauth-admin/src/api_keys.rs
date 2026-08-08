// SPDX-License-Identifier: MIT OR Apache-2.0

//! The API key and personal-access-token management surface (issue #99, criterion 6).
//!
//! # What a listing may and may not contain
//!
//! No digest and no plaintext, and that is a property of the types rather than a rule the
//! handler follows. `ApiKeyRecord` has no digest field, so there is nothing here to leak even
//! by accident, and the plaintext exists only in a creation response that this module does not
//! yet serve.
//!
//! A management surface that returned verifiers would hand a credential-equivalent to every
//! caller allowed to LOOK, which is a strictly larger set than those allowed to USE.
//!
//! # Revoked keys are listed
//!
//! For the same reason migration 0123 retains the rows. A rotation's whole point is that the
//! old key is visible beside the new one, and an operator investigating a leak has to be able
//! to tell "I revoked that at 14:02" from "no such key ever existed".

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::ApiKeyOwner;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::response::json;
use crate::state::AdminState;

/// One key, as the management surface renders it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyView {
    /// The non-secret `akey_` handle. Every other operation names the key by this.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// Expiry in milliseconds since the epoch, absent for a key that does not expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
    /// Revocation time in milliseconds since the epoch, absent while the key is live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<i64>,
}

/// A page of keys.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyListView {
    /// This owner's keys, newest first, revoked ones included.
    pub items: Vec<ApiKeyView>,
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys",
    operation_id = "listOrganizationApiKeys",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "This organization's keys, newest first, revoked ones included", body = ApiKeyListView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The organization is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn list_organization_api_keys(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): READ. Listing keys reveals which integrations
    // exist and when each was revoked, which is operational intelligence about an
    // organization, so it needs the read authority rather than being open to any
    // authenticated management credential.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    // NOT `require_vendor`, unlike project grants. A grant BOUNDS a confined credential, so
    // letting it read its own grant leaks the shape of its own cage. A key belongs TO the
    // organization, and `resolve_live_org` has already refused any organization outside a
    // confined credential's own, so an org admin listing their own organization's keys is
    // reading what they administer.
    let records = state
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&ApiKeyOwner::Organization(org_id))
        .await
        .map_err(|_| ApiError::Internal)?;

    let view = ApiKeyListView {
        items: records.into_iter().map(view_of).collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Render one record. Shared so a second listing endpoint cannot drift into exposing a
/// different set of fields for the same object.
fn view_of(record: ironauth_store::ApiKeyRecord) -> ApiKeyView {
    ApiKeyView {
        id: record.id.to_string(),
        display_name: record.display_name,
        expires_at_unix_ms: record.expires_at_unix_micros.map(|micros| micros / 1000),
        revoked_at_unix_ms: record.revoked_at_unix_micros.map(|micros| micros / 1000),
    }
}
