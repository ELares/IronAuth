// SPDX-License-Identifier: MIT OR Apache-2.0

//! Personal access tokens: keys owned by a USER (issue #99, criterion 6).
//!
//! The third owner in `ApiKeyOwner` and the last one to get a surface. It reuses the view,
//! request and response types the organization and service-account surfaces share, so all three
//! render a key the same way.
//!
//! # This is the only place `ira_pat_` is minted
//!
//! A personal access token differs from an API key in exactly two ways: who owns it, and its
//! prefix. `docs/design/TOKEN-FORMATS.md` publishes `ira_pat_` and asks operators to register
//! it with their secret scanner, and until this route existed nothing in the product issued
//! one, so that registration guarded a token type that could not occur.
//!
//! The kind passed to `mint_api_key` here is therefore load bearing in a way a status code
//! cannot see. Minting `ApiKeyKindTag::ApiKey` for a user would produce a token that
//! authenticates perfectly and carries the WRONG prefix, so every scanner configured from the
//! published document would stop matching the credential most likely to end up in a
//! developer's dotfile. `a_personal_access_token_carries_the_published_pat_prefix` is what
//! refuses that.
//!
//! # Why a confined credential is refused
//!
//! A project grant confines a management credential to ONE organization. A user, like a service
//! account, belongs to the environment and may be a member of several organizations or none, so
//! there is no organization for the confinement to be checked against. A token minted here
//! authenticates as that user everywhere they are a member, which is not a subset of any single
//! organization. The failure is closed rather than interpreted.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::api_key::{ApiKeyKindTag, mint_api_key};
use ironauth_store::{
    ApiKeyId, ApiKeyOwner, CorrelationId, IdempotencyWrite, NewApiKey, StoreError, UserId,
};

use crate::api_keys::{ApiKeyCreated, ApiKeyListView, CreateApiKeyRequest, view_of};
use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, resolve_scope, resolve_user};
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
        message: "a personal access token authenticates as its user everywhere that user is \
                  a member, which is not a subset of any one organization, so a credential \
                  confined to a single organization has no boundary to check it against"
            .to_owned(),
    })
}

/// Resolve the user named in the path, or the uniform not-found.
///
/// `users().get()` already answers the existence question with the typed not-found, so unlike
/// the service-account surface this needs no bespoke probe. Skipping it would not merely
/// mis-shape the status code: minting a token for a user who does not exist reaches the insert
/// and comes back as the foreign key's 500.
///
/// The ENVIRONMENT is the other half, and it takes the same `access` parameter
/// [`resolve_live_org`] takes. A WRITE requires the environment to be live; a READ does not.
/// The parameter lives here rather than at each call site because it is the kind of
/// precondition a fourth route forgets, and a user row survives its environment's soft delete,
/// so nothing else in this path would notice.
///
/// Callers place this AFTER the idempotency replay, so a genuine replay of a write that already
/// succeeded still returns its original response even if the environment went away in between.
async fn resolve_pat_owner(
    state: &AdminState,
    scope: Scope,
    user_id: &str,
    access: EnvironmentAccess,
) -> Result<UserId, ApiError> {
    let id = resolve_user(state, scope, user_id, access).await?;
    state.store().scoped(scope).users().get(&id).await?;
    Ok(id)
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens",
    operation_id = "listUserPersonalAccessTokens",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The usr_ user identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "This service account's keys, newest first, revoked ones included", body = ApiKeyListView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential", body = ErrorBody),
        (status = 404, description = "The service account is not a row of this scope", body = ErrorBody)
    )
)]
pub async fn list_user_personal_access_tokens(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): READ, matching the organization surface. A
    // listing reveals which integrations exist and when each was revoked, which is
    // operational intelligence about a principal rather than public.
    principal.require_permission(ManagementPermission::Read)?;
    require_unconfined(&principal)?;
    let owner = resolve_pat_owner(&state, scope, &user_id, EnvironmentAccess::Read).await?;

    let records = state
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&ApiKeyOwner::User(owner))
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
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens",
    operation_id = "createUserPersonalAccessToken",
    tag = "org-roles",
    request_body = CreateApiKeyRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The usr_ user identifier"),
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
pub async fn create_user_personal_access_token(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
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

    let owner = resolve_pat_owner(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    let request: CreateApiKeyRequest = parse_json(&body)?;

    let minted = mint_api_key(state.env(), &scope, ApiKeyKindTag::PersonalAccessToken);
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

    let pending = api_key_lifecycle_event(&state, scope, &minted.id, None);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .api_keys()
        .create_with_event(
            state.env(),
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::User(owner),
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
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, created_body)),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

/// Confirm the token is this user's, or the uniform not-found.
///
/// The store's key operations are environment scoped and address a key by its handle alone, so
/// without this a caller holding one user's path could revoke another user's token by naming
/// it. Both sibling surfaces answer this the same way and for the same reason.
async fn owned_by(
    state: &AdminState,
    scope: Scope,
    owner: UserId,
    id: &ApiKeyId,
) -> Result<ironauth_store::ApiKeyRecord, ApiError> {
    state
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&ApiKeyOwner::User(owner))
        .await
        .map_err(|_| ApiError::Internal)?
        .into_iter()
        .find(|record| &record.id == id)
        .ok_or(ApiError::NotFound)
}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens/{key_id}",
    operation_id = "revokeUserPersonalAccessToken",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The usr_ user identifier"),
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
pub async fn revoke_user_personal_access_token(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id, key_id)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): WRITE CREDENTIALS, matching create. Revoking a
    // credential is the same authority as minting one; a caller who may do one and not the
    // other is a distinction with no security meaning.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    require_unconfined(&principal)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let owner = resolve_pat_owner(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    let id = ApiKeyId::parse_in_scope(&key_id, &scope).map_err(|_| ApiError::NotFound)?;
    owned_by(&state, scope, owner, &id).await?;

    let pending = api_key_revoked_event(&state, scope, &id);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .api_keys()
        .revoke_with_event(
            state.env(),
            &id,
            state.now_unix_micros(),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;
    match result {
        Ok(()) => Ok(no_content()),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens/{key_id}/rotate",
    operation_id = "rotateUserPersonalAccessToken",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The usr_ user identifier"),
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
pub async fn rotate_user_personal_access_token(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id, key_id)): Path<(String, String, String, String)>,
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

    let owner = resolve_pat_owner(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    let old = ApiKeyId::parse_in_scope(&key_id, &scope).map_err(|_| ApiError::NotFound)?;
    let previous = owned_by(&state, scope, owner, &old).await?;

    let minted = mint_api_key(state.env(), &scope, ApiKeyKindTag::PersonalAccessToken);
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

    let pending = api_key_lifecycle_event(&state, scope, &minted.id, Some(&old));
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .api_keys()
        .rotate_with_event(
            state.env(),
            &old,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::User(owner),
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
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, created_body)),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

/// The event an API-key revocation emits (issue #108).
///
/// The id only, for the reason on `management_key.revoked`: nothing derived from the secret
/// belongs on the wire that announces the credential is dead.
fn api_key_revoked_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    key_id: &ApiKeyId,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = key_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "api_key.revoked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "api_key_id": subject }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event a personal-access-token create or rotation emits (issue #108).
///
/// The SAME `api_key.created` and `api_key.rotated` types the organization path emits: a
/// personal access token and an organization key are the same credential kind under different
/// owners, and a second pair of types for the owner would make every consumer subscribe twice
/// to learn one fact. The OWNER KIND on the create payload is what tells them apart.
///
/// `revoked` present means a ROTATION, absent means a CREATE, and the type is derived from it
/// so payload and type cannot disagree.
///
/// NO KEY MATERIAL and no digest: the digest verifies exactly as well as the key does.
fn api_key_lifecycle_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    created: &ApiKeyId,
    revoked: Option<&ApiKeyId>,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let (event_type, subject, payload) = match revoked {
        Some(old) => (
            "api_key.rotated",
            old.to_string(),
            serde_json::json!({
                "revoked_api_key_id": old.to_string(),
                "created_api_key_id": created.to_string(),
            }),
        ),
        None => (
            "api_key.created",
            created.to_string(),
            serde_json::json!({
                "api_key_id": created.to_string(),
                "owner_kind": "user",
            }),
        ),
    };
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
