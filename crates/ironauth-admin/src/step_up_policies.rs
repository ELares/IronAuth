// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-scope step-up policy management under an environment (RFC 9470, issue #262).
//!
//! The management-plane parity for the `ironauth step-up-policy set | list | remove`
//! CLI, which has been the only way to manage these since #72. The store repositories
//! and the CLI already existed; this is the HTTP surface over them, so an operator can
//! manage step-up policy without shell access on the server.
//!
//! Every endpoint is scoped to a `(tenant, environment)` pair and writes through the
//! SAME audited store repository the CLI uses, so the two surfaces are true parity
//! rather than two implementations of one rule. A policy is a floor on the `acr` an
//! authentication must reach for one OAuth scope token, and optionally a maximum
//! authentication age, so setting one is a security mutation and is sudo-gated exactly
//! like the ban surface.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{CorrelationId, IdempotencyWrite};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One per-scope step-up policy.
#[derive(Debug, Serialize, ToSchema)]
pub struct StepUpPolicyView {
    /// The `sup_` policy identifier.
    pub id: String,
    /// The OAuth scope token this policy governs.
    pub scope_token: String,
    /// The `acr` floor an authentication must reach for this scope, if any.
    pub min_acr: Option<String>,
    /// The maximum authentication age in seconds for this scope, if any.
    pub max_auth_age_secs: Option<i64>,
}

/// Every per-scope step-up policy in the environment.
#[derive(Debug, Serialize, ToSchema)]
pub struct StepUpPolicyList {
    /// The policies, oldest first.
    pub items: Vec<StepUpPolicyView>,
}

/// Set (create or replace) the policy for one OAuth scope token.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetStepUpPolicyRequest {
    /// The OAuth scope token to govern (a single scope value).
    pub scope_token: String,
    /// The `acr` floor for this scope. Omit to impose no floor.
    #[serde(default)]
    pub min_acr: Option<String>,
    /// The maximum authentication age in seconds. Omit to impose no bound.
    #[serde(default)]
    pub max_auth_age_secs: Option<i64>,
}

/// List every per-scope step-up policy in the environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies",
    operation_id = "listStepUpPolicies",
    tag = "step-up",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's step-up policies", body = StepUpPolicyList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent", body = ErrorBody)
    )
)]
pub async fn list_step_up_policies(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // `resolve_scope` rather than a bare path parse: it binds the PRINCIPAL to this
    // (tenant, environment), so a management key scoped elsewhere cannot read this
    // environment's policies. A step-up policy names the acr floor guarding a scope, so
    // reading the set tells an attacker exactly which scopes are weakly guarded.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    // Deliberately NO liveness fence on the READ. A soft-deleted environment stays
    // READABLE across this surface (only writes refuse it), which
    // `every_environment_scoped_write_refuses_a_soft_deleted_environment` enforces as a
    // whole-surface rule. My first draft fenced the read too and that sweep caught it.
    let policies = state
        .store()
        .scoped(scope)
        .scope_step_up_policies()
        .list()
        .await?;
    let view = StepUpPolicyList {
        items: policies
            .into_iter()
            .map(|policy| StepUpPolicyView {
                id: policy.id.to_string(),
                scope_token: policy.scope_token,
                min_acr: policy.min_acr,
                max_auth_age_secs: policy.max_auth_age_secs,
            })
            .collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Set the step-up policy for one OAuth scope token.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies",
    operation_id = "setStepUpPolicy",
    tag = "step-up",
    request_body = SetStepUpPolicyRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The policy is set. Read it back through the list endpoint"),
        (status = 400, description = "Malformed request or a blank scope token", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn set_step_up_policy(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: SetStepUpPolicyRequest = parse_json(&body)?;
    let scope_token = require_non_empty(&request.scope_token, "scope_token")?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // 204 rather than the resulting policy, so the stored body is EMPTY and therefore
    // knowable before the write. The upsert's `RETURNING id` means the live id is only
    // known afterwards (issue #436's lesson: on the replace branch the existing row keeps
    // its own id), so returning it would force either a resolved write or a second
    // transaction. The operator reads the policy back through the list endpoint, which is
    // the same shape `applyIdentifierUniqueness` uses.
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .scope_step_up_policies()
        .set(
            state.env(),
            &scope_token,
            request.min_acr.as_deref(),
            request.max_auth_age_secs,
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 204,
                response_body: "",
            }),
        )
        .await?;
    Ok(no_content())
}

/// Remove the step-up policy for one OAuth scope token.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies/{scope_token}",
    operation_id = "removeStepUpPolicy",
    tag = "step-up",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("scope_token" = String, Path, description = "The OAuth scope token whose policy is removed")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The policy is gone. Removing an absent policy is a no-op success"),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody)
    )
)]
pub async fn remove_step_up_policy(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, scope_token)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    // No Idempotency-Key: DELETE is the idempotent removal, as it is on every other
    // delete route here. The store writes its audit row either way, because the
    // management action was attempted whether or not a policy matched.
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .scope_step_up_policies()
        .remove(state.env(), &scope_token)
        .await?;
    Ok(no_content())
}
