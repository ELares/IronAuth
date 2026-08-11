// SPDX-License-Identifier: MIT OR Apache-2.0

//! The API key and personal-access-token management surface (issue #99, criterion 6).
//!
//! # What a listing may and may not contain
//!
//! No digest and no plaintext, and that is a property of the types rather than a rule the
//! handler follows. `ApiKeyRecord` has no digest field, so there is nothing here to leak even
//! by accident, and the plaintext appears in exactly one place, the 201 of a create or a
//! rotate, which is a different response type from the one a listing renders.
//!
//! A management surface that returned verifiers would hand a credential-equivalent to every
//! caller allowed to LOOK, which is a strictly larger set than those allowed to USE.
//!
//! # Revoked keys are listed
//!
//! For the same reason migration 0123 retains the rows. A rotation's whole point is that the
//! old key is visible beside the new one, and an operator investigating a leak has to be able
//! to tell "I revoked that at 14:02" from "no such key ever existed".

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::api_key::{ApiKeyKindTag, mint_api_key};
use ironauth_store::{
    ApiKeyId, ApiKeyOwner, CorrelationId, IdempotencyWrite, NewApiKey, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::response::{json, no_content};
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

/// Render one record. Shared with the service-account key surface so a second listing endpoint
/// cannot drift into exposing a different set of fields for the same object.
pub(crate) fn view_of(record: ironauth_store::ApiKeyRecord) -> ApiKeyView {
    ApiKeyView {
        id: record.id.to_string(),
        display_name: record.display_name,
        expires_at_unix_ms: record.expires_at_unix_micros.map(|micros| micros / 1000),
        revoked_at_unix_ms: record.revoked_at_unix_micros.map(|micros| micros / 1000),
    }
}

/// The create request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApiKeyRequest {
    /// The operator-facing label. Never secret and never part of the key.
    pub display_name: String,
}

/// The creation response: the ONLY place the key itself ever appears.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyCreated {
    /// The non-secret `akey_` handle.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// The key. Present exactly once, on the original 201. Copy it now; nothing can recover
    /// it afterwards, including a replay of this very request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// True on an idempotent REPLAY, where the key is deliberately absent.
    pub key_already_issued: bool,
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys",
    operation_id = "createOrganizationApiKey",
    tag = "org-roles",
    request_body = CreateApiKeyRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response WITHOUT the key material.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created. The `key` field is the only time the key is returned", body = ApiKeyCreated),
        (status = 200, description = "Idempotent replay, carrying no `key`: it was issued once and is not recoverable", body = ApiKeyCreated),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The organization is not a live row of this scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_organization_api_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): WRITE CREDENTIALS rather than write
    // organizations. Minting a key creates a credential that authenticates AS this
    // organization, which is strictly higher authority than editing its configuration, and
    // the permission vocabulary already separates the two.
    //
    // PROVEN, not merely classified.
    // `a_read_only_credential_can_list_api_keys_and_cannot_mint_or_kill_one` in
    // `delegated_admin.rs` drives a credential holding `management.read` and asserts the
    // refusal NAMES `management.write_credentials`. That is what pins the specific
    // permission: `management_permissions.rs` only asserts that some permission is demanded,
    // as its own comment says, and a downgrade to `Read` used to survive every pin.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let request: CreateApiKeyRequest = parse_json(&body)?;

    let minted = mint_api_key(state.env(), &scope, ApiKeyKindTag::ApiKey);
    let created = ApiKeyCreated {
        id: minted.id.to_string(),
        display_name: request.display_name.clone(),
        key: Some(minted.plaintext.clone()),
        key_already_issued: false,
    };
    let created_body = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;

    // The body STORED for replay carries NO key, and replays as 200 rather than 201.
    // Following `keys.rs`, which solved this for management keys.
    //
    // `idempotency_keys.response_body` is plaintext retained 24 hours. Storing the created
    // body verbatim would put a live credential there, which is exactly the recoverable copy
    // migration 0123 exists to prevent: `api_keys` has no column the plaintext can come back
    // from, and this would have created one in a different table.
    let stored = ApiKeyCreated {
        id: minted.id.to_string(),
        display_name: request.display_name.clone(),
        key: None,
        key_already_issued: true,
    };
    let stored_body = serde_json::to_string(&stored).map_err(|_| ApiError::Internal)?;

    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .api_keys()
        .create(
            state.env(),
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::Organization(org_id),
                display_name: &request.display_name,
                expires_at_unix_micros: None,
            },
            state.now_unix_micros(),
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &idem_key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &stored_body,
            }),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, created_body)),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys/{key_id}",
    operation_id = "revokeOrganizationApiKey",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("key_id" = String, Path, description = "The akey_ handle, never the key itself")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Revoked. The key stops verifying on the very next request, and the row is retained so the revocation stays legible"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The organization or the key is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn revoke_organization_api_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, key_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): WRITE CREDENTIALS, matching create. Revoking is
    // the other half of the credential lifecycle, and an administrator who may mint a key
    // must be able to kill it; splitting the two would leave whoever contains a leak needing
    // an authority they were not given for the act that caused it.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id = ApiKeyId::parse_in_scope(&key_id, &scope).map_err(|_| ApiError::NotFound)?;

    // The key must belong to THIS organization. `revoke` is scoped to the environment and
    // would otherwise happily kill a sibling organization's key from this organization's URL,
    // which is a cross-tenant-ish authorization hole inside one environment: a delegated
    // admin confined to org A could revoke org B's credentials by guessing a handle.
    //
    // Checked by listing rather than by a targeted read, because `list_for_owner` is the one
    // place ownership is already expressed and a second ownership query would be a second
    // definition of the same thing.
    let owned = state
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&ApiKeyOwner::Organization(org_id))
        .await
        .map_err(|_| ApiError::Internal)?
        .into_iter()
        .any(|record| record.id == id);
    if !owned {
        return Err(ApiError::NotFound);
    }

    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .api_keys()
        .revoke(state.env(), &id, state.now_unix_micros())
        .await;

    match result {
        Ok(()) => Ok(no_content()),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys/{key_id}/rotate",
    operation_id = "rotateOrganizationApiKey",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("key_id" = String, Path, description = "The akey_ handle of the key being replaced"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying returns the \
         original response WITHOUT the key material.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Rotated. The old key is revoked and the new one is returned, once, in the same transaction", body = ApiKeyCreated),
        (status = 200, description = "Idempotent replay, carrying no `key`", body = ApiKeyCreated),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The organization or the key is not a live row of this scope, or the key is already revoked", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn rotate_organization_api_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, key_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): WRITE CREDENTIALS, as create and revoke.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let idem_key = idempotency::required_key(&headers)?;
    // No request body: the PATH carries everything, so it is the whole discriminator. Two
    // rotations of DIFFERENT keys under one idempotency key therefore differ, and a genuine
    // retry of the same one matches.
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let old = ApiKeyId::parse_in_scope(&key_id, &scope).map_err(|_| ApiError::NotFound)?;

    // The key must belong to THIS organization, for the reason recorded on revoke: the store
    // operation is environment-scoped, so without this the organization in the URL is
    // decorative and a confined admin could rotate a sibling organization's credentials.
    let existing = state
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&ApiKeyOwner::Organization(org_id))
        .await
        .map_err(|_| ApiError::Internal)?;
    let Some(previous) = existing.into_iter().find(|record| record.id == old) else {
        return Err(ApiError::NotFound);
    };

    // The replacement inherits the label. Rotation replaces the SECRET, not the identity of
    // the integration, and making the caller re-supply a name invites a rotation that silently
    // renames the thing an operator is watching.
    let minted = mint_api_key(state.env(), &scope, ApiKeyKindTag::ApiKey);
    let created = ApiKeyCreated {
        id: minted.id.to_string(),
        display_name: previous.display_name.clone(),
        key: Some(minted.plaintext.clone()),
        key_already_issued: false,
    };
    let created_body = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;
    let stored = ApiKeyCreated {
        id: minted.id.to_string(),
        display_name: previous.display_name.clone(),
        key: None,
        key_already_issued: true,
    };
    let stored_body = serde_json::to_string(&stored).map_err(|_| ApiError::Internal)?;

    // ONE request, because `rotate` is ONE transaction. Exposing this as create-then-revoke
    // over two calls would hand the window back: a client that crashed between them would
    // leave the old key live alongside the new one, which is the failure a rotation performed
    // to contain a leak exists to prevent.
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .api_keys()
        .rotate(
            state.env(),
            &old,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::Organization(org_id),
                display_name: &previous.display_name,
                expires_at_unix_micros: previous.expires_at_unix_micros,
            },
            state.now_unix_micros(),
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &idem_key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &stored_body,
            }),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, created_body)),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}
