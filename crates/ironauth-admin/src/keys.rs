// SPDX-License-Identifier: MIT OR Apache-2.0

//! Management API key CRUD under an environment (operator plane).
//!
//! A key is the environment-scoped credential class. Its identifier (`mak_...`)
//! embeds its `(tenant, environment)` scope and is safe to display; the SECRET is
//! a separate high-entropy token, returned exactly once and stored only as a
//! SHA-256 hash. The presented bearer token is `<mak_id>.<secret>`, so the auth
//! path recovers the declared scope from the id half and then proves possession
//! of the secret within that scope.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Env;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, ManagementKeyId, Scope, StoreError, TenantId,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{
    CreateManagementKeyRequest, ManagementKeyCreated, ManagementKeyList, ManagementKeyView,
};

/// Bytes of secret entropy in a management-key token, beyond the public id.
const SECRET_BYTES: usize = 32;

/// Mint a fresh secret token for a management key, from the entropy seam.
fn generate_secret(env: &Env) -> String {
    let mut bytes = [0_u8; SECRET_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids.
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(TenantId, Scope), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    Ok((tenant, Scope::new(tenant, environment)))
}

/// Mint a management API key in an environment. Returns the secret ONCE.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/keys",
    operation_id = "createManagementKey",
    tag = "keys",
    request_body = CreateManagementKeyRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created; the secret is shown once", body = ManagementKeyCreated),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // The environment must exist; a clean 404 rather than a foreign-key error.
    state
        .store()
        .management()
        .environments(tenant)
        .get(&scope.environment())
        .await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: CreateManagementKeyRequest = parse_json(&body)?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;

    let created_at_micros = state.now_unix_micros();
    let id = ManagementKeyId::generate(state.env(), &scope);
    let secret = generate_secret(state.env());
    let token = format!("{id}.{secret}");
    let key_hash = crate::hash::sha256_hex(token.as_bytes());

    let created = ManagementKeyCreated {
        id: id.to_string(),
        display_name: display_name.clone(),
        secret: token,
        created_at_unix_ms: created_at_micros / 1000,
    };
    let body_string = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .credentials(scope)
        .create(
            state.env(),
            &id,
            created_at_micros,
            &key_hash,
            &display_name,
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List management API keys in an environment (cursor paginated; metadata only).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/keys",
    operation_id = "listManagementKeys",
    tag = "keys",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of keys", body = ManagementKeyList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_keys(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .credentials(scope)
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = ManagementKeyList {
        items: rows.into_iter().map(ManagementKeyView::from).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one management API key's metadata (never its secret).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
    operation_id = "getManagementKey",
    tag = "keys",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("key_id" = String, Path, description = "The management key identifier (mak_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The key metadata", body = ManagementKeyView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, key_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let credentials = state.store().management().credentials(scope);
    // A key minted in another scope parses as the uniform not-found (anti-oracle).
    let id = credentials.parse_id(&key_id)?;
    let record = credentials.get(&id).await?;
    let body =
        serde_json::to_string(&ManagementKeyView::from(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Revoke a management API key (soft delete; idempotent).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
    operation_id = "deleteManagementKey",
    tag = "keys",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("key_id" = String, Path, description = "The management key identifier (mak_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Revoked (idempotent)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, already revoked, or in another scope)", body = ErrorBody)
    )
)]
pub async fn delete_key(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, key_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let id: ManagementKeyId = state
        .store()
        .management()
        .credentials(scope)
        .parse_id(&key_id)?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .credentials(scope)
        .delete(state.env(), &id)
        .await?;
    Ok(no_content())
}
