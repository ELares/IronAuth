// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin user CRUD, lifecycle transitions, and external-id linkage (issue #52).
//!
//! This is the management-plane surface over the `users` entity: create (with an
//! optional caller-supplied id and an external id), read, list (cursor paginated,
//! filterable by state / `external_id` / identifier), update (RFC 7396 partial
//! profile patch), delete (a soft-delete offboarding that cascades sessions), the
//! explicit lifecycle state transitions, and external-id link/unlink.
//!
//! Every surface holds the three management-plane properties: it is scope-fenced
//! (a user id is parsed under the caller's OWN scope, so a foreign user is the
//! uniform not-found, and every surface registers an `IsolationProbe` with the #6
//! IDOR harness), it is audited in the same transaction as the data change, and
//! the session-ending transitions (block, disable, delete) cascade to the user's
//! sessions and non-offline refresh families and publish to the unified
//! session-ended fan-out (issue #35), which delivers back-channel logout to
//! affected relying parties.
//!
//! The user PII (the login handle, the claim document, the external id) is
//! envelope-encrypted at rest (issue #48): the create seals it and the reads open
//! it, so the control-plane store carries the platform master key exactly as the
//! data plane does. A management response NEVER returns the password hash (the #11
//! secret lesson).

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewAdminUser, Scope, StoreError, UserId, UserListFilter,
    UserState,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{
    CreateUserRequest, LinkExternalIdRequest, SetUserStateRequest, UpdateUserRequest,
    UserExternalIdView, UserList, UserStateChangeView, UserStateView, UserView,
};

/// The user list search filters: by lifecycle state, by external id, and by login
/// handle. The environment dimension is the scope itself (it is in the path).
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UserFilterQuery {
    /// Only users in this lifecycle state.
    pub state: Option<UserStateView>,
    /// Only the user whose external id equals this value.
    pub external_id: Option<String>,
    /// Only the user whose login handle equals this value.
    pub identifier: Option<String>,
}

/// Whether a session-ending mutation also kills the user's `offline_access`
/// families. Off by default (they survive), like every other fleet operation.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HardKillQuery {
    /// Kill the `offline_access` refresh families too (default false).
    #[serde(default)]
    pub hard_kill: bool,
}

/// Resolve and authorize the `(tenant, environment)` scope from the path. The
/// operator passes; a management key must be scoped to exactly this environment
/// (otherwise the LOUD wrong-scope error). A malformed tenant or environment id is
/// the uniform not-found.
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
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
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Parse a user id under this scope, mapping a malformed or cross-scope id to the
/// uniform not-found.
fn parse_user_id(scope: Scope, raw: &str) -> Result<UserId, ApiError> {
    UserId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// Create a user under an environment.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users",
    operation_id = "createUser",
    tag = "users",
    request_body = CreateUserRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = UserView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 409, description = "The id, login handle, or external id is already taken", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_user(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Containment: the parent environment must exist and be live. A foreign or
    // soft-deleted environment reads as a uniform not-found.
    state
        .store()
        .management()
        .environments(scope.tenant())
        .get(&scope.environment())
        .await?;

    let request: CreateUserRequest = parse_json(&body)?;
    let identifier = require_non_empty(&request.identifier, "identifier")?;
    let view_state = request.state.unwrap_or(UserStateView::Active);
    let user_state: UserState = view_state.into();
    if !user_state.is_creatable() {
        return Err(ApiError::BadRequest(
            "state is not a valid initial state (scheduled_offboarding needs a timestamp)"
                .to_owned(),
        ));
    }
    // An optional caller-supplied id must be a user id in THIS scope.
    let supplied_id = match request.id.as_deref() {
        Some(raw) => Some(parse_user_id(scope, raw)?),
        None => None,
    };
    let external_id = match request.external_id.as_deref() {
        Some(value) => Some(require_non_empty(value, "external_id")?),
        None => None,
    };
    let claims_string = request.claims.as_ref().map(ToString::to_string);
    let password_hash = match request.password_hash.as_deref() {
        Some(value) => Some(require_non_empty(value, "password_hash")?),
        None => None,
    };

    let created_at_micros = state.now_unix_micros();
    let user_id = supplied_id.unwrap_or_else(|| UserId::generate(state.env(), &scope));
    let view = UserView {
        id: user_id.to_string(),
        tenant_id: scope.tenant().to_string(),
        environment_id: scope.environment().to_string(),
        identifier: identifier.clone(),
        state: view_state,
        external_id: external_id.clone(),
        scheduled_offboarding_at_unix_ms: None,
        created_at_unix_ms: created_at_micros / 1000,
        updated_at_unix_ms: created_at_micros / 1000,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .admin_create(
            state.env(),
            NewAdminUser {
                id: Some(&user_id),
                identifier: &identifier,
                password_hash: password_hash.as_deref(),
                claims_json: claims_string.as_deref(),
                external_id: external_id.as_deref(),
                state: user_state,
            },
            created_at_micros,
            Some(write),
        )
        .await;

    match result {
        Ok(_) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a user with this id, login handle, or external id already exists".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// List users under an environment (cursor paginated), filterable by state,
/// external id, and identifier.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users",
    operation_id = "listUsers",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        UserFilterQuery,
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of users", body = UserList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_users(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(filter): Query<UserFilterQuery>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .users()
        .list(
            UserListFilter {
                state: filter.state.map(UserState::from),
                external_id: filter.external_id.as_deref(),
                identifier: filter.identifier.as_deref(),
            },
            page.fetch_limit(),
            page.after(),
        )
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = UserList {
        items: rows.into_iter().map(UserView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one user.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    operation_id = "getUser",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The user", body = UserView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_user(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let id = parse_user_id(scope, &user_id)?;
    let record = state.store().scoped(scope).users().get(&id).await?;
    let body =
        serde_json::to_string(&UserView::from_record(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Update a user's profile (RFC 7396 partial patch of the standard claims).
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    operation_id = "updateUser",
    tag = "users",
    request_body = UpdateUserRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated user", body = UserView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn update_user(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let id = parse_user_id(scope, &user_id)?;
    let request: UpdateUserRequest = parse_json(&body)?;
    if let Some(claims) = request.claims.as_ref() {
        let claims_json = claims.to_string();
        state
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .users()
            .update_claims(state.env(), &id, &claims_json)
            .await?;
    } else {
        // No mutable field supplied: still confirm the user exists (a not-found is
        // the uniform 404), so an empty patch of an absent user is not a silent 200.
        state.store().scoped(scope).users().get(&id).await?;
    }
    let record = state.store().scoped(scope).users().get(&id).await?;
    let body =
        serde_json::to_string(&UserView::from_record(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Delete a user (a soft-delete offboarding that cascades sessions).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    operation_id = "deleteUser",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        HardKillQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted (sessions cascaded, session-ended events published)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, already deleted, or in another scope)", body = ErrorBody)
    )
)]
pub async fn delete_user(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    Query(hard): Query<HardKillQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let id = parse_user_id(scope, &user_id)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .delete(state.env(), &id, hard.hard_kill, None)
        .await?;
    Ok(no_content())
}

/// Transition a user's lifecycle state.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/state",
    operation_id = "setUserState",
    tag = "users",
    request_body = SetUserStateRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The user's new state", body = UserStateChangeView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody),
        (status = 409, description = "The transition is not valid from the user's current state", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn set_user_state(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: SetUserStateRequest = parse_json(&body)?;
    let target: UserState = request.state.into();
    // A scheduled-offboarding target needs an instant; every other target must not
    // carry one. Reject the mismatch as a clean 400.
    let scheduled_micros = match (target, request.scheduled_offboarding_at_unix_ms) {
        (UserState::ScheduledOffboarding, Some(ms)) => Some(ms.saturating_mul(1000)),
        (UserState::ScheduledOffboarding, None) => {
            return Err(ApiError::BadRequest(
                "scheduled_offboarding requires scheduled_offboarding_at_unix_ms".to_owned(),
            ));
        }
        (_, Some(_)) => {
            return Err(ApiError::BadRequest(
                "scheduled_offboarding_at_unix_ms is only valid for the scheduled_offboarding state"
                    .to_owned(),
            ));
        }
        (_, None) => None,
    };
    let id = parse_user_id(scope, &user_id)?;

    let view = UserStateChangeView {
        id: id.to_string(),
        state: request.state,
        hard_kill: request.hard_kill,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .set_state(
            state.env(),
            &id,
            target,
            scheduled_micros,
            request.hard_kill,
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &body_string,
            }),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "the requested state transition is not valid from the user's current state".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// Link an external id to a user.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
    operation_id = "linkUserExternalId",
    tag = "users",
    request_body = LinkExternalIdRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The linked external id", body = UserExternalIdView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody),
        (status = 409, description = "The external id is already claimed by another user", body = ErrorBody)
    )
)]
pub async fn link_user_external_id(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let id = parse_user_id(scope, &user_id)?;
    let request: LinkExternalIdRequest = parse_json(&body)?;
    let external_id = require_non_empty(&request.external_id, "external_id")?;
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .link_external_id(state.env(), &id, &external_id)
        .await;
    match result {
        Ok(()) => {
            let view = UserExternalIdView {
                id: id.to_string(),
                external_id: Some(external_id),
            };
            let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::OK, body))
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "the external id is already claimed by another user in this environment".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// Unlink a user's external id.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
    operation_id = "unlinkUserExternalId",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The external id was unlinked", body = UserExternalIdView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn unlink_user_external_id(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let id = parse_user_id(scope, &user_id)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .unlink_external_id(state.env(), &id)
        .await?;
    let view = UserExternalIdView {
        id: id.to_string(),
        external_id: None,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
