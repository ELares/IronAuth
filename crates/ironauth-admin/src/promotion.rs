// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server-side config promotion, management surface (issue #44).
//!
//! The write half of the config-promotion flagship (the read half, the canonical
//! snapshot export, is in [`crate::config`]). Two operator-plane POSTs move an
//! environment's PROMOTABLE configuration from a source snapshot into a TARGET
//! environment:
//!
//! - `POST .../config/promotion/plan` takes a source snapshot document (another
//!   environment's export, or a submitted validated document) and DRY-RUNS a
//!   promotion into the target: it validates the document, resolves every reference
//!   against the target environment, and returns a reviewable plan (a stable plan
//!   id, the target's base and result revisions, and the structured diff). It
//!   changes NOTHING. An unresolved reference fails here (422) so an apply can never
//!   half-complete on a missing reference.
//! - `POST .../config/promotion/apply` transactionally applies a plan's source
//!   snapshot onto the target, all-or-nothing, gated on the plan's captured
//!   `base_revision` (optimistic concurrency): a target that drifted since the plan
//!   was computed fails with a structured drift error (409) and changes nothing;
//!   applying an already-applied plan is an idempotent no-op.
//!
//! Both endpoints run on the CONTROL plane against the target `(tenant,
//! environment)` scope under forced row-level security, so a promotion applies only
//! to its target scope. The apply writes its audit trail in the same transaction as
//! the changes (the store's [`ironauth_store::ActingStore::apply_promotion`]).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{
    CorrelationId, PromotionApplyError, PromotionOutcome, Scope, Snapshot, SnapshotViolation,
    TenantId, plan_promotion, validate_document,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::json;
use crate::state::AdminState;

/// The apply request body: the source snapshot to promote, plus the plan's captured
/// `base_revision` precondition (issue #44).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ApplyConfigPromotionRequest {
    /// The source config snapshot document (the same canonical, secret-free shape
    /// the snapshot export returns). Validated before anything is applied.
    #[schema(value_type = Object)]
    pub source: serde_json::Value,
    /// The target's promotable-config revision the plan captured
    /// (`base_revision`). Apply proceeds only if the target still carries it;
    /// otherwise it fails with a drift error and changes nothing.
    pub base_revision: String,
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids
/// through the management repositories (a malformed id is the uniform not-found).
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

/// Render a set of snapshot-validation violations as a bad-request message.
fn violation_message(violations: &[SnapshotViolation]) -> String {
    let joined = violations
        .iter()
        .map(|violation| format!("{}: {}", violation.path, violation.message))
        .collect::<Vec<_>>()
        .join("; ");
    format!("the source snapshot is invalid: {joined}")
}

/// Dry-run a promotion into the target environment, returning a reviewable plan.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/plan",
    operation_id = "planConfigPromotion",
    tag = "config-promotion",
    params(
        ("tenant_id" = String, Path, description = "The target tenant identifier"),
        ("environment_id" = String, Path, description = "The target environment identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional. A plan is a \
         pure dry run and changes nothing, so a replay is inherently safe.")
    ),
    request_body(content = String, description = "The source config snapshot document \
        (canonical, secret-free JSON), the same shape the snapshot export returns.",
        content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The reviewable promotion plan: a stable plan id, the \
         target's base and result revisions, the resolved references, and the structured diff \
         (per resource: create, update, or delete with before and after).",
         content_type = "application/json"),
        (status = 400, description = "The source snapshot document is invalid", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Target environment not found", body = ErrorBody),
        (status = 422, description = "One or more references do not resolve in the target \
         environment (the plan fails closed)", content_type = "application/json")
    )
)]
pub async fn plan_config_promotion(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // The target environment must exist (a clean 404 rather than an empty plan).
    state
        .store()
        .management()
        .environments(tenant)
        .get(&scope.environment())
        .await?;

    let source = validate_document(&body)
        .map_err(|violations| ApiError::BadRequest(violation_message(&violations)))?;

    match plan_promotion(&state.store().scoped(scope), &source).await? {
        Ok(plan) => {
            let body = serde_json::to_string(&plan.to_json()).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::OK, body))
        }
        Err(errors) => {
            let messages: Vec<serde_json::Value> = errors
                .iter()
                .map(|error| serde_json::Value::String(error.to_string()))
                .collect();
            let payload = serde_json::json!({
                "error": "plan_failed",
                "message": "the promotion plan could not be built; see errors",
                "errors": messages,
            });
            let body = serde_json::to_string(&payload).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::UNPROCESSABLE_ENTITY, body))
        }
    }
}

/// Transactionally apply a promotion plan onto the target environment.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/apply",
    operation_id = "applyConfigPromotion",
    tag = "config-promotion",
    params(
        ("tenant_id" = String, Path, description = "The target tenant identifier"),
        ("environment_id" = String, Path, description = "The target environment identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional. Apply is \
         idempotent by construction: re-applying an already-applied plan is a no-op.")
    ),
    request_body = ApplyConfigPromotionRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The plan was applied (the applied diff) or was already \
         applied (a no-op).", content_type = "application/json"),
        (status = 400, description = "The source snapshot document is invalid", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Target environment not found", body = ErrorBody),
        (status = 409, description = "The target drifted since the plan was computed (a \
         structured drift error); nothing was changed.", content_type = "application/json"),
        (status = 422, description = "A reference does not resolve in the target environment at \
         apply time; nothing was changed.", content_type = "application/json")
    )
)]
pub async fn apply_config_promotion(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Sudo mutation gate: applying a config snapshot is the most powerful
    // environment-scoped write, so it requires a fresh elevation (issue #73). Placed
    // before the existence read and the apply, so a challenge leaves nothing written.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    state
        .store()
        .management()
        .environments(tenant)
        .get(&scope.environment())
        .await?;

    let request: ApplyConfigPromotionRequest = parse_json(&body)?;
    let source_bytes = serde_json::to_vec(&request.source).map_err(|_| ApiError::Internal)?;
    let source: Snapshot = validate_document(&source_bytes)
        .map_err(|violations| ApiError::BadRequest(violation_message(&violations)))?;

    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .apply_promotion(state.env(), &source, &request.base_revision, false)
        .await;

    match outcome {
        Ok(PromotionOutcome::Applied(diff)) => {
            let payload = serde_json::json!({ "status": "applied", "diff": diff.to_json() });
            let body = serde_json::to_string(&payload).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::OK, body))
        }
        Ok(PromotionOutcome::NoOp) => {
            let payload = serde_json::json!({ "status": "no_op" });
            let body = serde_json::to_string(&payload).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::OK, body))
        }
        Err(PromotionApplyError::Drift { expected, found }) => {
            let payload = serde_json::json!({
                "error": "drift",
                "message": "the target drifted since the plan was computed; nothing was changed",
                "expected_revision": expected,
                "actual_revision": found,
            });
            let body = serde_json::to_string(&payload).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::CONFLICT, body))
        }
        Err(PromotionApplyError::UnresolvedReference(reference)) => {
            let payload = serde_json::json!({
                "error": "unresolved_reference",
                "message": "a reference does not resolve in the target; nothing was changed",
                "reference": reference.render(),
            });
            let body = serde_json::to_string(&payload).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::UNPROCESSABLE_ENTITY, body))
        }
        Err(PromotionApplyError::Store(error)) => Err(error.into()),
    }
}
