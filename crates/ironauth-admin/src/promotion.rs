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

/// Parse and FULLY validate a submitted promotion source document: the snapshot grammar, then
/// the per-resource INGEST WALLS the promotion apply would otherwise bypass.
///
/// [`validate_document`] is the document grammar. It is deliberately shape-only for a brand: it
/// checks that `tokens` and `slots` are JSON objects and stops. But the apply is a full WRITER of
/// the `brands` table and binds those objects verbatim, so on this path alone a submitted
/// document could store an unknown slot key, unsanitized markup, and a CSS breakout in a color
/// token, none of which the brand management endpoint accepts. [`crate::brands::promoted_brand_faults`]
/// is that endpoint's own wall, applied here, so the two doors into `brands` enforce ONE grammar.
///
/// Both the PLAN and the APPLY call this. Refusing at plan time is the point: an operator learns
/// the document is unstorable before reviewing a plan built from it, rather than after approving
/// one, and every faulty brand is reported at once.
fn validated_source(bytes: &[u8]) -> Result<Snapshot, ApiError> {
    let source = validate_document(bytes)
        .map_err(|violations| ApiError::BadRequest(violation_message(&violations)))?;
    let faults = crate::brands::promoted_brand_faults(&source);
    if !faults.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "the source snapshot is invalid: {}",
            faults.join("; ")
        )));
    }
    Ok(source)
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
        (status = 400, description = "The source snapshot document is invalid: either it \
         violates the snapshot grammar, or a brand it carries is not storable as authored (an \
         invalid design token, an unknown or oversize slot, a slot that is not sanitizer \
         output, or two brands claiming one host or one default)", body = ErrorBody),
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
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // The target environment must exist (a clean 404 rather than an empty plan).
    // This used to be an inline copy of the two-line read. It is the shared
    // [`crate::org_context::require_live_environment`] now (issue #443): one expression
    // of one precondition, so a change to what LIVENESS means has one place to change.
    crate::org_context::require_live_environment(&state, &scope).await?;

    let source = validated_source(&body)?;

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
        (status = 400, description = "The source snapshot document is invalid: either it \
         violates the snapshot grammar, or a brand it carries is not storable as authored (an \
         invalid design token, an unknown or oversize slot, a slot that is not sanitizer \
         output, or two brands claiming one host or one default). Nothing was changed",
         body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Target environment not found", body = ErrorBody),
        (status = 409, description = "The target drifted since the plan was computed, or a \
         promoted custom-journey version conflicts with an existing one (a structured error); \
         nothing was changed.", content_type = "application/json"),
        (status = 422, description = "A reference does not resolve in the target environment at \
         apply time, or a promoted brand names an asset whose bytes this environment does not \
         hold (a snapshot carries an asset by content reference, never inline); nothing was \
         changed.", content_type = "application/json")
    )
)]
pub async fn apply_config_promotion(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Sudo mutation gate: applying a config snapshot is the most powerful
    // environment-scoped write, so it requires a fresh elevation (issue #73). Placed
    // before the existence read and the apply, so a challenge leaves nothing written.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // This used to be an inline copy of the two-line read. It is the shared
    // [`crate::org_context::require_live_environment`] now (issue #443): one expression
    // of one precondition, so a change to what LIVENESS means has one place to change.
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: ApplyConfigPromotionRequest = parse_json(&body)?;
    let source_bytes = serde_json::to_vec(&request.source).map_err(|_| ApiError::Internal)?;
    let source: Snapshot = validated_source(&source_bytes)?;

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
        Err(PromotionApplyError::FlowVersionArtifactConflict {
            journey_id,
            version,
        }) => {
            // A custom-journey version is append-only and immutable: the target already has this
            // (journey_id, version) with a different artifact. Apply changed nothing; the operator
            // re-authors the divergent version under a new version number.
            let payload = serde_json::json!({
                "error": "flow_version_conflict",
                "message": "a custom-journey version already exists in the target with a \
                            different artifact; a version is append-only and nothing was changed",
                "journey_id": journey_id,
                "version": version,
            });
            let body = serde_json::to_string(&payload).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::CONFLICT, body))
        }
        Err(PromotionApplyError::BrandAssetBytesUnavailable { slug, kind, sha256 }) => {
            // A snapshot carries a brand asset by CONTENT REFERENCE, never as inline bytes,
            // so the apply materializes one only from bytes the target already holds under
            // that exact digest. It could not, so it changed NOTHING rather than leaving the
            // target with metadata pointing at bytes it does not have. The operator uploads
            // the asset to this environment (creating the brand here first if needed) and
            // re-plans.
            let payload = serde_json::json!({
                "error": "brand_asset_bytes_unavailable",
                "message": "a promoted brand names an asset whose bytes this environment does \
                            not hold; a snapshot carries an asset by content reference, so \
                            upload it here and re-plan. Nothing was changed",
                "slug": slug,
                "kind": kind,
                "sha256": sha256,
            });
            let body = serde_json::to_string(&payload).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::UNPROCESSABLE_ENTITY, body))
        }
        Err(PromotionApplyError::Store(error)) => Err(error.into()),
    }
}
