// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbound lazy-migration progress endpoint (issue #56).
//!
//! `GET .../migration/progress` reports how far an environment's lazy migration has
//! come, so an operator can watch the tail of unmigrated stragglers flatten and then
//! disable the hook for the environment (a pure config change). It returns the scope's
//! DB progress counts (total users, how many are on the native Argon2id verifier, and
//! how many still carry an imported foreign hash awaiting a first-login rehash) and,
//! when this node runs the data plane with a hook installed, that node's circuit-breaker
//! state.
//!
//! Authorization is environment-scoped: the operator plane, or the environment's OWN
//! management key, may read it (the same `require_environment` gate the other
//! per-environment reads use). It reads only counts, so it decrypts no PII.
//!
//! The migrated COUNT, hook latency, error/timeout rates, and the breaker state are ALSO
//! exported as Prometheus metrics on the management plane (see
//! `ironauth_oidc::describe_lazy_migration_metrics`); this endpoint is the queryable JSON
//! view of the same progress.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{Scope, TenantId};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;

/// An environment's lazy-migration progress (issue #56).
#[derive(Serialize, ToSchema)]
pub struct MigrationProgressView {
    /// The total number of live users in the environment.
    pub total_users: i64,
    /// How many users are on the native Argon2id verifier (migrated): the total minus the
    /// foreign-hash stragglers.
    pub migrated_users: i64,
    /// How many users still carry an imported foreign password hash (the #55 import tail
    /// awaiting a first-login rehash). A standard #55 bulk import closes this out, after
    /// which the hook can be disabled for the environment.
    pub foreign_hash_remaining: i64,
    /// This node's lazy-migration circuit-breaker state (`closed`, `open`, or
    /// `half_open`), or null when no hook is installed on the node serving this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaker_state: Option<String>,
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids through the
/// management repositories (a malformed id is the uniform not-found).
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

/// Report the environment's lazy-migration progress.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/progress",
    operation_id = "getMigrationProgress",
    tag = "migration",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's lazy-migration progress: the total \
         user count, how many are on the native Argon2id verifier (migrated), how many still \
         carry an imported foreign hash (the straggler tail a #55 bulk import closes out), and \
         this node's circuit-breaker state. The migrated count, hook latency, error/timeout \
         rates, and breaker state are also exported as Prometheus metrics.", body = MigrationProgressView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn get_migration_progress(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Environment-scoped read: the operator plane, or the environment's own management
    // key, may read its migration progress.
    principal.require_environment(tenant, scope.environment())?;

    let progress = state
        .store()
        .scoped(scope)
        .users()
        .migration_progress()
        .await?;
    let view = MigrationProgressView {
        total_users: progress.total_users,
        migrated_users: progress.total_users - progress.foreign_hash_remaining,
        foreign_hash_remaining: progress.foreign_hash_remaining,
        breaker_state: state
            .migration_breaker_state()
            .map(|state| state.label().to_owned()),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
