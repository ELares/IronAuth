// SPDX-License-Identifier: MIT OR Apache-2.0

//! The admin-approved recovery review queue, management surface (issue #82, PR 3).
//!
//! The per-environment management endpoints that back admin-approved recovery: list the OPEN
//! recovery approvals, APPROVE one (satisfying the recovery's method precondition and then
//! completing it THROUGH the #81 delay/downgrade gate), or REJECT one. These mutate
//! DATA-PLANE scoped resources (the `recovery_approvals` queue and, on completion, the
//! `recovery_flows` state), so they route through the control-plane store's scoped
//! repositories. A recovering END USER holds no management principal, so it can never reach
//! these routes: only an admin ever approves a recovery, which is the self-approval-impossible
//! guarantee.
//!
//! The whole surface is gated by the `advanced-recovery` experimental feature: every handler
//! answers a uniform 404 until the feature is enabled AND acknowledged. Every POST honors
//! Idempotency-Key and every review action writes its typed audit event naming the deciding
//! admin actor.
//!
//! COMPLETION runs THROUGH the #81 gate: after recording the approval, the handler reads the
//! recovery flow and calls `complete()`, whose `hold_until <= now` guard enforces the delay.
//! A recovery whose delay window has not yet elapsed is approved but stays held; an admin
//! re-approve after the window finalizes it (approve is idempotent over pending/approved).

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{CorrelationId, IdempotencyWrite, RecoveryFlowId, Scope, StoreError};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{
    RecoveryApprovalCaseView, RecoveryApprovalDecisionView, RecoveryApprovalList,
    RecoveryApprovalStateView,
};

/// Resolve the (tenant, environment) scope and the acting principal, exactly like the other
/// per-environment management surfaces.
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

/// Parse a recovery flow id (`rcv_...`) under this scope, mapping a malformed or cross-scope
/// id to the uniform not-found.
fn parse_flow(scope: Scope, raw: &str) -> Result<RecoveryFlowId, ApiError> {
    RecoveryFlowId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// The deterministic decision body, built without a re-read so an Idempotency-Key replay is
/// byte-identical.
fn decision_body(
    flow_id: &RecoveryFlowId,
    state: RecoveryApprovalStateView,
) -> Result<String, ApiError> {
    let view = RecoveryApprovalDecisionView {
        flow_id: flow_id.to_string(),
        state,
    };
    serde_json::to_string(&view).map_err(|_| ApiError::Internal)
}

/// List the OPEN admin-approved recovery approvals under an environment (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals",
    operation_id = "listRecoveryApprovals",
    tag = "recovery-approvals",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of open recovery approvals", body = RecoveryApprovalList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The advanced-recovery feature is not enabled", body = ErrorBody)
    )
)]
pub async fn list_recovery_approvals(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if !state.advanced_recovery_enabled() {
        return Err(ApiError::NotFound);
    }
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .recovery_approvals()
        .list_open(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = RecoveryApprovalList {
        items: rows
            .into_iter()
            .map(RecoveryApprovalCaseView::from_view)
            .collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// APPROVE an admin-approved recovery: satisfy the method precondition, then complete the
/// recovery THROUGH the #81 delay/downgrade gate.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/approve",
    operation_id = "approveRecoveryApproval",
    tag = "recovery-approvals",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("flow_id" = String, Path, description = "The recovery flow (rcv_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The recovery is approved", body = RecoveryApprovalDecisionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no open approval, absent, or feature disabled)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn approve_recovery_approval(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, flow_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    decide(
        &state,
        &principal,
        &tenant_id,
        &environment_id,
        &flow_id,
        &uri,
        &headers,
        RecoveryApprovalStateView::Approved,
    )
    .await
}

/// REJECT an admin-approved recovery: the recovery can never complete via this method.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/reject",
    operation_id = "rejectRecoveryApproval",
    tag = "recovery-approvals",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("flow_id" = String, Path, description = "The recovery flow (rcv_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The recovery is rejected", body = RecoveryApprovalDecisionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no open approval, absent, or feature disabled)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn reject_recovery_approval(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, flow_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    decide(
        &state,
        &principal,
        &tenant_id,
        &environment_id,
        &flow_id,
        &uri,
        &headers,
        RecoveryApprovalStateView::Rejected,
    )
    .await
}

/// The shared approve/reject flow (issue #82, PR 3): resolve scope + actor, require fresh
/// privilege, honor Idempotency-Key, record the audited decision, and on an APPROVE complete
/// the recovery THROUGH the #81 delay gate.
#[allow(clippy::too_many_arguments)]
async fn decide(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
    flow_id: &str,
    uri: &Uri,
    headers: &HeaderMap,
    decision: RecoveryApprovalStateView,
) -> Result<Response, ApiError> {
    if !state.advanced_recovery_enabled() {
        return Err(ApiError::NotFound);
    }
    let (scope, actor) = resolve_scope(state, principal, tenant_id, environment_id)?;
    crate::sudo::require_fresh_privilege(state, scope, actor).await?;

    let key = idempotency::required_key(headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let flow = parse_flow(scope, flow_id)?;
    let body_string = decision_body(&flow, decision)?;
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let acting = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()));
    let result = match decision {
        RecoveryApprovalStateView::Approved => {
            acting
                .recovery_approvals()
                .approve(state.env(), &flow, Some(write))
                .await
        }
        _ => {
            acting
                .recovery_approvals()
                .reject(state.env(), &flow, Some(write))
                .await
        }
    };
    match result {
        Ok(()) => {
            // On an approve, complete THROUGH the #81 gate: read the flow for its
            // recover_acr and call complete(), whose hold_until guard enforces the delay. A
            // held recovery whose window has not elapsed stays held (best effort; a re-approve
            // after the window finalizes it). Completion is a side effect, not in the body.
            if matches!(decision, RecoveryApprovalStateView::Approved) {
                if let Ok(Some(record)) = state
                    .store()
                    .scoped(scope)
                    .recovery_flows()
                    .get(&flow)
                    .await
                {
                    let _completed = state
                        .store()
                        .scoped(scope)
                        .acting(actor, CorrelationId::generate(state.env()))
                        .recovery_flows()
                        .complete(state.env(), &flow, &record.recover_acr)
                        .await;
                }
            }
            Ok(json(StatusCode::OK, body_string))
        }
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}
