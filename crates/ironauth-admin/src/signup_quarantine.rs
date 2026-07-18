// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signup fraud review queue, management surface (issue #82, PR 2).
//!
//! The per-environment management endpoints that back the signup fraud review queue: list
//! the OPEN quarantine cases, RELEASE an account (clear its quarantine), REJECT a signup
//! (disable the account and end its sessions), or EXTEND a review window. These mutate
//! DATA-PLANE scoped resources (the `users.quarantined` flag and the `signup_quarantines`
//! queue), so they route through the control-plane store's scoped repositories (the control
//! role holds the narrow grants the two-sided quarantine lifecycle needs). A quarantined
//! END USER holds no management principal, so it can never reach these routes: only an admin
//! ever lifts a quarantine, which is the self-approval-impossible guarantee.
//!
//! The whole surface is gated by the `signup-quarantine` experimental feature: every handler
//! answers a uniform 404 until the feature is enabled AND acknowledged. Every POST honors
//! Idempotency-Key (stored in the SAME transaction as the mutation and its audit row) and
//! every mutation writes its typed audit event naming the deciding admin actor, in keeping
//! with the crate's contract.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{CorrelationId, IdempotencyWrite, Scope, StoreError, UserId};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{
    ExtendSignupQuarantineRequest, SignupQuarantineCaseView, SignupQuarantineDecisionView,
    SignupQuarantineList, SignupQuarantineStateView,
};

/// Resolve the (tenant, environment) scope and the acting principal, exactly like the other
/// per-environment management surfaces. A management key scoped to a different environment is
/// a wrong-scope error.
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

/// Parse a subject (`usr_...`) under this scope, mapping a malformed or cross-scope id to the
/// uniform not-found.
fn parse_subject(scope: Scope, raw: &str) -> Result<UserId, ApiError> {
    UserId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// The deterministic decision body, built without a re-read so an Idempotency-Key replay is
/// byte-identical.
fn decision_body(
    subject: &UserId,
    state: SignupQuarantineStateView,
    quarantined_until_unix_ms: Option<i64>,
) -> Result<String, ApiError> {
    let view = SignupQuarantineDecisionView {
        subject: subject.to_string(),
        state,
        quarantined_until_unix_ms,
    };
    serde_json::to_string(&view).map_err(|_| ApiError::Internal)
}

/// List the OPEN signup-quarantine cases under an environment (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine",
    operation_id = "listSignupQuarantines",
    tag = "signup-quarantine",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of open quarantine cases", body = SignupQuarantineList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The signup-quarantine feature is not enabled", body = ErrorBody)
    )
)]
pub async fn list_signup_quarantines(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if !state.signup_quarantine_enabled() {
        return Err(ApiError::NotFound);
    }
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .signup_quarantines()
        .list_open(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = SignupQuarantineList {
        items: rows
            .into_iter()
            .map(SignupQuarantineCaseView::from_view)
            .collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// RELEASE a quarantined account: clear its quarantine so it becomes a normal account.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/approve",
    operation_id = "approveSignupQuarantine",
    tag = "signup-quarantine",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The quarantined account (usr_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The account is released", body = SignupQuarantineDecisionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no open case, absent, or feature disabled)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn approve_signup_quarantine(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !state.signup_quarantine_enabled() {
        return Err(ApiError::NotFound);
    }
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let subject = parse_subject(scope, &user_id)?;
    let body_string = decision_body(&subject, SignupQuarantineStateView::Approved, None)?;
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .signup_quarantines()
        .approve(state.env(), &subject, Some(write))
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// REJECT a quarantined signup: disable the account and end its sessions.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/reject",
    operation_id = "rejectSignupQuarantine",
    tag = "signup-quarantine",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The quarantined account (usr_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The signup is rejected", body = SignupQuarantineDecisionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no open case, absent, or feature disabled)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn reject_signup_quarantine(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !state.signup_quarantine_enabled() {
        return Err(ApiError::NotFound);
    }
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let subject = parse_subject(scope, &user_id)?;
    let body_string = decision_body(&subject, SignupQuarantineStateView::Rejected, None)?;
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .signup_quarantines()
        .reject(state.env(), &subject, Some(write))
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// EXTEND a signup-quarantine review window: bump the review deadline (the account stays
/// quarantined).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/extend",
    operation_id = "extendSignupQuarantine",
    tag = "signup-quarantine",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The quarantined account (usr_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    request_body = ExtendSignupQuarantineRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The review window is extended", body = SignupQuarantineDecisionView),
        (status = 400, description = "Malformed request (extend_secs missing or zero)", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no open case, absent, or feature disabled)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn extend_signup_quarantine(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    if !state.signup_quarantine_enabled() {
        return Err(ApiError::NotFound);
    }
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let request: ExtendSignupQuarantineRequest = parse_json(&body)?;
    if request.extend_secs == 0 {
        return Err(ApiError::BadRequest(
            "extend_secs must be at least 1".to_owned(),
        ));
    }
    // The new horizon is now + extend_secs, from the admin clock seam. A window larger than
    // i64 microseconds is clamped rather than overflowing (an absurd request, not a fault).
    let now_micros = state.now_unix_micros();
    let added_micros = i64::try_from(request.extend_secs)
        .ok()
        .and_then(|secs| secs.checked_mul(1_000_000))
        .unwrap_or(i64::MAX);
    let quarantined_until_micros = now_micros.saturating_add(added_micros);

    let key = idempotency::required_key(&headers)?;
    // The fingerprint is over the concrete body, so a replay with the SAME key but a
    // different window is a 422 rather than a silent no-op.
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let subject = parse_subject(scope, &user_id)?;
    let body_string = decision_body(
        &subject,
        SignupQuarantineStateView::Extended,
        Some(quarantined_until_micros / 1000),
    )?;
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .signup_quarantines()
        .extend(state.env(), &subject, quarantined_until_micros, Some(write))
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}
