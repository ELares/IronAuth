// SPDX-License-Identifier: MIT OR Apache-2.0

//! Session and refresh-family FLEET OPERATIONS, management surface (issue #32).
//!
//! Auth0 needed twelve years to expose sessions and refresh tokens as searchable
//! fleet resources. A greenfield data model bakes them in from the first milestone,
//! so this module makes both first-class management resources: list and inspect
//! sessions (searchable by user, by client, and by environment, which is the scope
//! itself), revoke one, revoke a batch, revoke EVERYTHING for a user with a cascade
//! to the refresh-token families, and list and inspect the families themselves.
//!
//! Three properties every surface here holds:
//!
//! - **Scope-fenced.** Every identifier is parsed under the caller's OWN scope, so a
//!   session in another tenant or environment is the uniform not-found (the
//!   anti-oracle), and a BULK revoke silently skips a foreign id rather than reaching
//!   across the boundary. Each surface registers an `IsolationProbe` with the #6 IDOR
//!   harness and runs under forced row-level security.
//! - **Audited, in the same transaction.** Every revocation writes its audit row in
//!   the SAME transaction as the data change (a revocation without its audit row is
//!   not representable), through the store's audited-write primitive.
//! - **Offline-preserving by default.** A revoke cascades to the session-bound refresh
//!   families but PRESERVES the `offline_access` families, the documented
//!   offline-survives-logout semantic of issue #21. Killing those too is an explicit,
//!   documented `hard_kill` flag, never the default.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, RefreshFamilyFleetFilter, Scope, SessionEndCause, SessionId,
    StoreError, TenantId, UserId,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{
    BulkRevocationView, BulkRevokeSessionsRequest, RefreshFamilyList, RefreshFamilyView,
    RevokeSessionsRequest, SessionList, SessionRevocationView, SessionView, UserRevocationView,
};

/// The most sessions one BULK revoke may name. A batch is a single transaction, so it
/// is bounded rather than unbounded: an operator with more to revoke pages through, or
/// uses the revoke-everything-for-a-user surface (which is bounded by the user, not by
/// the request body).
const MAX_BULK_REVOKE: usize = 100;

/// The fleet-search filters shared by the session and refresh-family list endpoints:
/// by user and by client. The ENVIRONMENT dimension is the scope itself (it is in the
/// path), so a search can never span environments.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FleetFilterQuery {
    /// Only sessions or families of this subject (a `usr_...` id).
    pub subject: Option<String>,
    /// Only sessions or families of this client (a `cli_...` id).
    pub client_id: Option<String>,
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids through
/// the management repositories (a malformed id is the uniform not-found).
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

/// The revocation body, which is OPTIONAL: an empty body is the safe default (an
/// offline-preserving revoke). Present but malformed JSON is still a clean 400.
fn revoke_request(body: &Bytes) -> Result<RevokeSessionsRequest, ApiError> {
    if body.is_empty() {
        return Ok(RevokeSessionsRequest::default());
    }
    parse_json(body)
}

/// List the sessions in an environment (cursor paginated), searchable by user and by
/// client.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions",
    operation_id = "listSessions",
    tag = "sessions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        FleetFilterQuery,
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of sessions", body = SessionList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_sessions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(filter): Query<FleetFilterQuery>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .session_fleet()
        .list(
            ironauth_store::SessionFleetFilter {
                subject: filter.subject.as_deref(),
                client_id: filter.client_id.as_deref(),
            },
            page.fetch_limit(),
            page.after(),
        )
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.clone())
    });
    let list = SessionList {
        items: rows.into_iter().map(SessionView::from).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Inspect one session, whatever its lifecycle state (live, revoked, or rotated away).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}",
    operation_id = "getSession",
    tag = "sessions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("session_id" = String, Path, description = "The session identifier (ses_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The session", body = SessionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_session(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, session_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let fleet = state.store().scoped(scope).session_fleet();
    // A malformed id and a cross-scope id both fail here as the uniform not-found.
    let id = fleet.parse_id(&session_id)?;
    let record = fleet.get(&id).await?.ok_or(StoreError::NotFound)?;
    let body = serde_json::to_string(&SessionView::from(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Revoke ONE session. It stops resolving immediately and its session-bound refresh
/// families are revoked with it; the `offline_access` families survive unless
/// `hard_kill` is set.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}/revoke",
    operation_id = "revokeSession",
    tag = "sessions",
    request_body = RevokeSessionsRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("session_id" = String, Path, description = "The session identifier (ses_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Revoked", body = SessionRevocationView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn revoke_session(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, session_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request = revoke_request(&body)?;
    // Parse under the caller's OWN scope: a foreign session is the uniform not-found
    // BEFORE any mutating repository is reached.
    let id: SessionId = state
        .store()
        .scoped(scope)
        .session_fleet()
        .parse_id(&session_id)?;

    // The response is the deterministic POST-CONDITION (the session does not resolve
    // any more), so the body stored for an Idempotency-Key replay in the SAME
    // transaction as the revocation is byte-identical to the live response, and an
    // absent, foreign, or already-revoked session is indistinguishable from a live one
    // (the anti-oracle). The cascade's effect is observable on the refresh-family list.
    let view = SessionRevocationView {
        id: id.to_string(),
        revoked: true,
        hard_kill: request.hard_kill,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sessions()
        .revoke(
            state.env(),
            &id,
            SessionEndCause::Revoked,
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
        Ok(_) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Revoke a BATCH of sessions in one audited transaction. A foreign-scope id in the
/// batch is a uniform no-op (never a cross-tenant revocation).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions/revoke",
    operation_id = "bulkRevokeSessions",
    tag = "sessions",
    request_body = BulkRevokeSessionsRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The batch was revoked", body = BulkRevocationView),
        (status = 400, description = "Malformed request or too many sessions", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn bulk_revoke_sessions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: BulkRevokeSessionsRequest = parse_json(&body)?;
    if request.session_ids.len() > MAX_BULK_REVOKE {
        return Err(ApiError::BadRequest(format!(
            "a bulk revoke names at most {MAX_BULK_REVOKE} sessions"
        )));
    }
    // Parse every id under the caller's OWN scope. An id that is malformed or belongs
    // to another scope is DROPPED as a uniform no-op rather than erroring, so the batch
    // neither reaches across the scope boundary nor confirms which ids exist elsewhere.
    let fleet = state.store().scoped(scope).session_fleet();
    let ids: Vec<SessionId> = request
        .session_ids
        .iter()
        .filter_map(|raw| fleet.parse_id(raw).ok())
        .collect();

    let view = BulkRevocationView {
        sessions_targeted: ids.len() as u64,
        hard_kill: request.hard_kill,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sessions()
        .bulk_revoke(
            state.env(),
            &ids,
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
        Ok(_) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Revoke EVERYTHING for one user: every session, cascading to the user's
/// refresh-token families in the SAME transaction. The `offline_access` families
/// SURVIVE (issue #21's offline-survives-logout semantic) unless the explicit
/// `hard_kill` flag is passed, which also revokes their grants so every already-issued
/// access token dies immediately.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/sessions/revoke",
    operation_id = "revokeUserSessions",
    tag = "sessions",
    request_body = RevokeSessionsRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Every session of the user was revoked", body = UserRevocationView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn revoke_user_sessions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request = revoke_request(&body)?;
    // A user id from another scope (or a malformed one) is the uniform not-found.
    let subject = UserId::parse_in_scope(&user_id, &scope).map_err(|_| StoreError::NotFound)?;

    let view = UserRevocationView {
        subject: subject.to_string(),
        revoked: true,
        hard_kill: request.hard_kill,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sessions()
        .revoke_all_for_user(
            state.env(),
            &subject,
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
        Ok(_) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List the refresh-token families in an environment (cursor paginated), searchable by
/// user and by client.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families",
    operation_id = "listRefreshFamilies",
    tag = "sessions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        FleetFilterQuery,
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of refresh-token families", body = RefreshFamilyList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_refresh_families(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(filter): Query<FleetFilterQuery>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .refresh_family_fleet()
        .list(
            RefreshFamilyFleetFilter {
                subject: filter.subject.as_deref(),
                client_id: filter.client_id.as_deref(),
            },
            page.fetch_limit(),
            page.after(),
        )
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.clone())
    });
    let list = RefreshFamilyList {
        items: rows.into_iter().map(RefreshFamilyView::from).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Inspect one refresh-token family.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families/{family_id}",
    operation_id = "getRefreshFamily",
    tag = "sessions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("family_id" = String, Path, description = "The family identifier (rff_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The refresh-token family", body = RefreshFamilyView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_refresh_family(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, family_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let fleet = state.store().scoped(scope).refresh_family_fleet();
    let id = fleet.parse_id(&family_id)?;
    let record = fleet.get(&id).await?.ok_or(StoreError::NotFound)?;
    let body =
        serde_json::to_string(&RefreshFamilyView::from(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
