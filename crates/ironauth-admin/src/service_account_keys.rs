// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keys owned by a SERVICE ACCOUNT (issue #99, criterion 6).
//!
//! The sibling of [`crate::api_keys`], which serves organization-owned keys. It reuses that
//! module's view, request and response types deliberately: the two surfaces render the same
//! object, and giving each its own types is how they drift into disagreeing about which fields
//! a key has.
//!
//! # Why these routes are not nested under an organization
//!
//! `service_accounts` carries `tenant_id`, `environment_id` and `client_id`, and no
//! `organization_id`. A principal is minted for a CLIENT and belongs to the environment; the
//! organization memberships it may hold are a separate relation and a service account can hold
//! several or none. Nesting the route under an organization would assert an ownership the
//! schema does not have, and would make the same key reachable at more than one path or at
//! none.
//!
//! # Why a confined credential is refused
//!
//! A project grant confines a management credential to ONE organization. A service account
//! sits outside every organization's boundary, so there is no organization for such a
//! credential's confinement to be checked against, and a key minted here authenticates as a
//! principal that may be a member of organizations the credential was never granted. The
//! failure is closed rather than interpreted: the confinement cannot be satisfied, so the
//! request is refused rather than allowed on the grounds that nothing contradicted it.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::api_key::{ApiKeyKindTag, mint_api_key};
use ironauth_store::{
    ApiKeyId, ApiKeyOwner, CorrelationId, IdempotencyWrite, NewApiKey, ServiceAccountId, StoreError,
};

use crate::api_keys::{ApiKeyCreated, ApiKeyListView, CreateApiKeyRequest, view_of};
use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;
use ironauth_store::Scope;

/// Refuse a credential confined to one organization.
///
/// See the module note. This is a separate function from `project_grants::require_vendor`
/// because the REASON differs and the message a caller sees should say which one applies.
fn require_unconfined(principal: &Principal) -> Result<(), ApiError> {
    if principal.confined_organization().is_none() {
        return Ok(());
    }
    Err(ApiError::WrongScope {
        expected: "an unconfined management credential".to_owned(),
        actual: "credential confined to one organization".to_owned(),
        message: "a service account belongs to the environment rather than to one \
                  organization, so a credential confined to a single organization has no \
                  boundary this key could be checked against"
            .to_owned(),
    })
}

/// Resolve the principal named in the path, or the uniform not-found.
///
/// Existence IS liveness for the PRINCIPAL: `service_accounts` has no `state` and no
/// `deleted_at`, because a principal's id is the `sub` of every token issued for it and
/// rotating one would break them all. A malformed id and an id belonging to another scope both
/// give the same answer as an id that names nothing, so the path segment reveals nothing about
/// what exists elsewhere.
///
/// The ENVIRONMENT is a different question and this takes the same `access` parameter
/// [`resolve_live_org`] takes, for the same reason and with the same asymmetry. A WRITE
/// requires the environment to be live; a READ does not, so a soft-deleted environment can
/// still be inspected. The parameter is here rather than at each call site because it is the
/// kind of precondition a fourth route forgets, and a route that forgets it writes into a
/// deleted environment: the principal's row survives the environment's soft delete, so
/// nothing else in this path would notice.
///
/// Callers place this AFTER the idempotency replay, so a genuine replay of a write that
/// already succeeded still returns its original response even if the environment went away in
/// between. That ordering is the one the organization surface pins.
async fn resolve_service_account(
    state: &AdminState,
    scope: Scope,
    service_account_id: &str,
    access: EnvironmentAccess,
) -> Result<ServiceAccountId, ApiError> {
    if access == EnvironmentAccess::Write {
        require_live_environment(state, &scope).await?;
    }
    let id = ServiceAccountId::parse_in_scope(service_account_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    let present = state
        .store()
        .scoped(scope)
        .service_accounts()
        .exists(&id)
        .await
        .map_err(|_| ApiError::Internal)?;
    if present {
        Ok(id)
    } else {
        Err(ApiError::NotFound)
    }
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys",
    operation_id = "listServiceAccountApiKeys",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("service_account_id" = String, Path, description = "The sva_ principal identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "This service account's keys, newest first, revoked ones included", body = ApiKeyListView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential", body = ErrorBody),
        (status = 404, description = "The service account is not a row of this scope", body = ErrorBody)
    )
)]
pub async fn list_service_account_api_keys(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, service_account_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): READ, matching the organization surface. A
    // listing reveals which integrations exist and when each was revoked, which is
    // operational intelligence about a principal rather than public.
    principal.require_permission(ManagementPermission::Read)?;
    require_unconfined(&principal)?;
    let owner =
        resolve_service_account(&state, scope, &service_account_id, EnvironmentAccess::Read)
            .await?;

    let records = state
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&ApiKeyOwner::ServiceAccount(owner))
        .await
        .map_err(|_| ApiError::Internal)?;
    let view = ApiKeyListView {
        items: records.into_iter().map(view_of).collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys",
    operation_id = "createServiceAccountApiKey",
    tag = "org-roles",
    request_body = CreateApiKeyRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("service_account_id" = String, Path, description = "The sva_ principal identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response WITHOUT the key material.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created. The `key` field is the only time the key is returned", body = ApiKeyCreated),
        (status = 200, description = "Idempotent replay, carrying no `key`: it was issued once and is not recoverable", body = ApiKeyCreated),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential", body = ErrorBody),
        (status = 404, description = "The service account is not a row of this scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_service_account_api_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, service_account_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): WRITE CREDENTIALS rather than write, for the
    // reason the organization surface gives. Minting a key creates something that
    // authenticates AS this principal, which is strictly higher authority than editing its
    // configuration, and the permission vocabulary already separates the two.
    //
    // PROVEN, not merely classified.
    // `a_read_only_credential_cannot_mint_or_kill_a_service_accounts_key` in
    // `delegated_admin.rs` drives a credential holding `management.read` and asserts the
    // refusal NAMES `management.write_credentials`.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    require_unconfined(&principal)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let owner =
        resolve_service_account(&state, scope, &service_account_id, EnvironmentAccess::Write)
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
    // The STORED body carries no key and replays as 200. `idempotency_keys.response_body` is
    // plaintext retained 24 hours, so storing the created body verbatim would put a live
    // credential in the one place migration 0123 exists to keep it out of.
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
        .api_keys()
        .create(
            state.env(),
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::ServiceAccount(owner),
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

/// Confirm the key is this principal's, or the uniform not-found.
///
/// The store's key operations are environment scoped and address a key by its handle alone, so
/// without this a caller holding one service account's path could revoke another's key by
/// naming it. The organization surface answers the same question the same way and for the same
/// reason.
async fn owned_by(
    state: &AdminState,
    scope: Scope,
    owner: ServiceAccountId,
    id: &ApiKeyId,
) -> Result<ironauth_store::ApiKeyRecord, ApiError> {
    state
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&ApiKeyOwner::ServiceAccount(owner))
        .await
        .map_err(|_| ApiError::Internal)?
        .into_iter()
        .find(|record| &record.id == id)
        .ok_or(ApiError::NotFound)
}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys/{key_id}",
    operation_id = "revokeServiceAccountApiKey",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("service_account_id" = String, Path, description = "The sva_ principal identifier"),
        ("key_id" = String, Path, description = "The akey_ handle, never the key itself")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Revoked. The key stops verifying on the very next request, and the row is retained so the revocation stays legible"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential", body = ErrorBody),
        (status = 404, description = "The service account or the key is not a row of this scope", body = ErrorBody)
    )
)]
pub async fn revoke_service_account_api_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, service_account_id, key_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): WRITE CREDENTIALS, matching create. Revoking a
    // credential is the same authority as minting one; a caller who may do one and not the
    // other is a distinction with no security meaning.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    require_unconfined(&principal)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let owner =
        resolve_service_account(&state, scope, &service_account_id, EnvironmentAccess::Write)
            .await?;
    let id = ApiKeyId::parse_in_scope(&key_id, &scope).map_err(|_| ApiError::NotFound)?;
    owned_by(&state, scope, owner, &id).await?;

    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
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
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys/{key_id}/rotate",
    operation_id = "rotateServiceAccountApiKey",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("service_account_id" = String, Path, description = "The sva_ principal identifier"),
        ("key_id" = String, Path, description = "The akey_ handle of the key being replaced"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying returns the \
         original response WITHOUT the key material.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Rotated. The old key is revoked and the new one is returned, once, in the same transaction", body = ApiKeyCreated),
        (status = 200, description = "Idempotent replay, carrying no `key`", body = ApiKeyCreated),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential", body = ErrorBody),
        (status = 404, description = "The service account or the key is not a row of this scope, or the key is already revoked", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn rotate_service_account_api_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, service_account_id, key_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): WRITE CREDENTIALS, as create and revoke. A
    // rotation mints and revokes in one transaction, so it is both of those authorities and
    // cannot be less than either.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    require_unconfined(&principal)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let owner =
        resolve_service_account(&state, scope, &service_account_id, EnvironmentAccess::Write)
            .await?;
    let old = ApiKeyId::parse_in_scope(&key_id, &scope).map_err(|_| ApiError::NotFound)?;
    let previous = owned_by(&state, scope, owner, &old).await?;

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

    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .api_keys()
        .rotate(
            state.env(),
            &old,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::ServiceAccount(owner),
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
