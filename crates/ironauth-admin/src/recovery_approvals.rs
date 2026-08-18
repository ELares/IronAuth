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

use crate::auth::{ManagementPermission, Principal};
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
async fn resolve_scope(
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
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    // Issue #185: the caller's OPERATOR fences the pair. `tenants` and `environments`
    // sit ABOVE row-level security (RLS fences the pair these tables define), so without
    // this a caller naming another operator's tenant reached that tenant's environments
    // and everything under them: measured returning another operator's organization
    // document in full.
    //
    // ADDRESSABILITY, not liveness. A soft-deleted environment must stay readable (see
    // `EnvironmentAccess`), so this asks only whether the pair exists under this
    // operator; whether it is live is each endpoint's own question.
    if !state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .exists_in_any_state(&environment)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::NotFound);
    }
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
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
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
        (status = 404, description = "Not found (no open approval, absent, or feature disabled). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
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
        (status = 404, description = "Not found (no open approval, absent, or feature disabled). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
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
    let (scope, actor) = resolve_scope(state, principal, tenant_id, environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // Approving a recovery hands someone back an ACCOUNT, so it is user authority.
    // Enforced in the SHARED body: `approve_recovery_approval` and
    // `reject_recovery_approval` both route here, so one check covers both and a third
    // decision added later inherits it rather than needing a third edit.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(state, scope, actor).await?;

    let key = idempotency::required_key(headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The parent-existence precondition, through the ONE expression of it (issues #443,
    // #451). A `recovery_flows` row and its approval survive their environment's soft
    // delete, so an approve COMPLETED a recovery inside a decommissioned environment and
    // a reject fenced one there (MEASURED: 200 and 200). It is placed in the shared
    // helper rather than in the two routes, so approve and reject cannot be given
    // different answers. It sits AFTER the idempotency replay for the reason `resolve_live_org`
    // records: a genuine replay must still return the original response even if the
    // environment went away in between.
    crate::org_context::require_live_environment(state, &scope).await?;

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
    // An APPROVE decides the case AND completes the recovery it unblocks in ONE store
    // transaction (issue #247), through the #81 delay gate, which is unchanged: a held
    // recovery whose window has not elapsed stays held and the admin re-approves after
    // the window to finalize. Completion is a side effect, not in the body.
    //
    // The completion used to run as a SECOND, un-joined transaction after this one, with
    // its result discarded. Because the Idempotency-Key record committed with the
    // decision, a failed completion left an approved-but-unfinished flow the replay store
    // could not see: a retry under the same key replayed the stored 200 and never
    // re-attempted the completion, so only a FRESH key could ever finish that flow.
    let pending = recovery_decision_event(state, scope, &flow, decision);
    let result = match decision {
        RecoveryApprovalStateView::Approved => acting
            .recovery_approvals()
            .approve_with_event(
                state.env(),
                &flow,
                Some(write),
                pending
                    .as_ref()
                    .map(crate::events::PendingEvent::domain_event)
                    .as_ref(),
            )
            .await
            .map(|_completed| ()),
        _ => {
            acting
                .recovery_approvals()
                .reject_with_event(
                    state.env(),
                    &flow,
                    Some(write),
                    pending
                        .as_ref()
                        .map(crate::events::PendingEvent::domain_event)
                        .as_ref(),
                )
                .await
        }
    };
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// The event a recovery-approval decision emits (issue #108).
///
/// ONE type carrying the decision: approve and reject are the same review reaching opposite
/// conclusions, and a consumer must act on BOTH -- an approval is an account takeover if the
/// request was fraudulent, so "someone regained access" and "someone was refused" are equally
/// worth alerting on.
///
/// NO `completed` FIELD. Whether the approval also finished the recovery flow is the store's
/// RETURN VALUE, discovered inside the write; this builds its envelope before the call and
/// cannot know it. A field nothing can populate is worse than no field, because a consumer
/// would read its absence as "not completed" rather than "not stated".
fn recovery_decision_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    flow_id: &ironauth_store::RecoveryFlowId,
    decision: RecoveryApprovalStateView,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = flow_id.to_string();
    let rendered = match decision {
        RecoveryApprovalStateView::Approved => "approved",
        _ => "rejected",
    };
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "recovery_approval.decided",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "recovery_flow_id": subject, "decision": rendered }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
