// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical secret-free config snapshot export, management surface (issue #43).
//!
//! `GET .../config/snapshot` returns the environment's promotable configuration as
//! a canonical, deterministic, SECRET-FREE JSON document (the format the store's
//! `snapshot` module defines and guarantees). It is the read half of the
//! config-promotion flagship: the document is diffable in ordinary code review,
//! safe to commit to a git repository, and the input the promotion engine (issue
//! #44) and the Terraform provider / CLI (5.11) consume.
//!
//! The endpoint reads the three promotable resource types (clients, resource
//! servers, DCR policies) through the control-plane scoped repositories, so
//! row-level security confines the export to exactly the requested `(tenant,
//! environment)`: a snapshot exports only its own scope's config. The projection
//! is secret-free by construction (no client secret, no key material, no
//! management credential ever enters it); a confidential client's secret is a
//! NAMED REFERENCE the target environment resolves at import.
//!
//! Authorization is environment-scoped: the operator plane, or the environment's
//! OWN management key, may export it (the same `require_environment` gate the
//! other per-environment reads use). Applying a snapshot into an environment is
//! NOT here: the transactional diff/plan/apply promotion engine is issue #44, and
//! resolving a secret reference against a target environment's secret store is
//! issue #45.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{TenantId, export_snapshot};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids
/// through the management repositories (a malformed id is the uniform not-found).
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(TenantId, ironauth_store::Scope), ApiError> {
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
    Ok((tenant, ironauth_store::Scope::new(tenant, environment)))
}

/// Export the environment's canonical secret-free config snapshot.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/config/snapshot",
    operation_id = "exportConfigSnapshot",
    tag = "config-promotion",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The canonical, deterministic, secret-free config \
         snapshot of the environment's promotable resources (clients, resource servers, DCR \
         policies). The document validates against the published JSON Schema at \
         docs/snapshot/snapshot.schema.json; two exports of the same configuration are \
         byte-identical, and no secret or key material appears in it.", content_type = "application/json"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn export_config_snapshot(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Environment-scoped read: the operator plane, or the environment's own
    // management key, may export its config.
    principal.require_environment(tenant, scope.environment())?;

    let snapshot = export_snapshot(&state.store().scoped(scope)).await?;
    let body = snapshot.to_canonical_string()?;
    Ok(json(StatusCode::OK, body))
}
