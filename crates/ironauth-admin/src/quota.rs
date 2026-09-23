// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management surface for runtime per-tenant quota overrides (issue #150 criterion 4).
//!
//! # The piece that was still missing
//!
//! Migration 0229 shipped `tenant_quota_limits` with a repository, and the quota-override
//! refresher now applies those rows to the running enforcer on a tick. What neither of those
//! had was a caller that wrote the rows: an operator could not reach the table, so the whole
//! "limits change at runtime via the management API" the criterion names had no HTTP surface.
//! This module is that surface.
//!
//! Three routes on the environment prefix:
//!
//! - `GET /quota/limits` lists the stored overrides.
//! - `PUT /quota/limits/{dimension}` sets one dimension's override, replacing any existing
//!   one.
//! - `DELETE /quota/limits/{dimension}` clears one dimension's override, returning the scope
//!   to its configured tier.
//!
//! # The write is a control-plane act, and the grant says so
//!
//! Migration 0229 grants the data plane `SELECT` on this table and nothing else, so the
//! request path can read a limit and never write one. These handlers run as the management
//! plane and write through the acting (audited) repository, exactly as the management routes
//! for every other table do. An operator who wants to change a tenant's limit does it here;
//! a compromised request path cannot raise its own tenant's limit, which is the one write
//! that defeats the feature entirely.
//!
//! # The dimension label is validated, not echoed
//!
//! The overrides table stores the dimension as text because a rolling upgrade lets a newer
//! node write a dimension an older one cannot name (the refresher skips what it cannot
//! parse). The MANAGEMENT surface is the mirror image, and its rule is
//! [`QuotaDimension::parse`]'s: a surface that ACCEPTS a dimension refuses one it cannot
//! name, because an operator typing `requsts` should be told rather than silently given a row
//! nothing will ever read. The LIST endpoint returns every stored label as stored, including
//! one this build cannot name, so an operator on an older node still sees what a newer node
//! wrote.
//!
//! # Writes are naturally idempotent, so no Idempotency-Key
//!
//! A PUT sets an absolute value and a DELETE clears one, so replaying either converges to the
//! same state as the first attempt. The codebase reserves the Idempotency-Key machinery for
//! writes whose replay would duplicate a side effect (a create, a counter); there is none
//! here, and adding the machinery to the store repository just to reject it would be the
//! shape of a future drift.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_quota::QuotaDimension;
use ironauth_store::{CorrelationId, StoreError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One stored override, as the management surface renders it.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuotaLimitView {
    /// The dimension label, as stored (`QuotaDimension::as_str`).
    pub dimension: String,
    /// The sustained rate, tokens per second.
    pub refill_per_sec: f64,
    /// The burst capacity.
    pub burst: f64,
    /// Whether THIS build can name the dimension. A row written by a newer node during a
    /// rolling upgrade is listed but not enforceable here; the refresher on a node that can
    /// name it applies it.
    pub recognized: bool,
}

/// The full set of stored overrides for a scope.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuotaLimitsView {
    /// Every override, in dimension order.
    pub items: Vec<QuotaLimitView>,
}

/// Set (create or replace) one dimension's override.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetQuotaLimitRequest {
    /// The sustained rate, tokens per second. Non-negative and finite.
    pub refill_per_sec: f64,
    /// The burst capacity. Non-negative and finite.
    pub burst: f64,
}

/// The dimension labels this build can name, joined for an operator-facing message.
fn known_dimensions() -> String {
    QuotaDimension::all()
        .iter()
        .map(|dimension| dimension.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// List every stored quota override for this scope.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/quota/limits",
    operation_id = "listQuotaLimits",
    tag = "quota",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Every stored quota override for this scope", body = QuotaLimitsView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or not in this scope", body = ErrorBody)
    )
)]
pub async fn list_quota_limits(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;

    let rows = state.store().scoped(scope).quota_limits().all().await?;
    let items = rows
        .into_iter()
        .map(|(dimension, limit)| QuotaLimitView {
            recognized: QuotaDimension::parse(&dimension).is_some(),
            dimension,
            refill_per_sec: limit.refill_per_sec,
            burst: limit.burst,
        })
        .collect();
    let body = serde_json::to_string(&QuotaLimitsView { items }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Set one dimension's override for this scope, replacing any existing one.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/quota/limits/{dimension}",
    operation_id = "setQuotaLimit",
    tag = "quota",
    request_body = SetQuotaLimitRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("dimension" = String, Path, description = "The quota dimension to override (requests, token_issuance, hook_seconds, password_hashing)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Stored. The override takes effect on every node within one override-refresh interval; the full set is available from the GET"),
        (status = 400, description = "Malformed body, an unknown dimension, or a non-finite or negative limit", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, soft-deleted, or not in this scope", body = ErrorBody)
    )
)]
pub async fn set_quota_limit(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, dimension)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`. A quota
    // override changes what the data plane enforces, which is environment configuration.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // A WRITE requires a LIVE environment (issue #185): reads admit a soft-deleted
    // environment so an operator can inspect it; a write must not land in a decommissioned
    // one.
    require_live_environment(&state, &scope).await?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    // The dimension label is a CLOSED set on the management surface, and an unknown one is
    // refused rather than stored: a row nothing will ever read is a limit the operator thinks
    // is in force and the enforcer never hears about. The refresher SKIPS an unknown label
    // during a rolling upgrade; the surface that ACCEPTS labels refuses one.
    if QuotaDimension::parse(&dimension).is_none() {
        return Err(ApiError::BadRequest(format!(
            "unknown quota dimension {dimension:?}; expected one of: {}",
            known_dimensions()
        )));
    }

    let request: SetQuotaLimitRequest = parse_json(&body)?;
    let (actor, corr) = (actor, CorrelationId::generate(state.env()));
    let pending = quota_limit_event(&state, scope, &dimension, &request);
    state
        .store()
        .scoped(scope)
        .acting(actor, corr)
        .quota_limits()
        .set_with_event(
            state.env(),
            &dimension,
            request.refill_per_sec,
            request.burst,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            // The store's own guard, surfaced as the caller's error: a negative or non-finite
            // limit is a bad request, not a server fault.
            StoreError::Invalid => ApiError::BadRequest(
                "refill_per_sec and burst must be non-negative and finite".to_owned(),
            ),
            other => ApiError::from(other),
        })?;
    Ok(no_content())
}

/// Clear one dimension's override, returning the scope to its configured tier.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/quota/limits/{dimension}",
    operation_id = "clearQuotaLimit",
    tag = "quota",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("dimension" = String, Path, description = "The quota dimension to clear (requests, token_issuance, hook_seconds, password_hashing)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Cleared. Every node returns the scope to its configured tier within one override-refresh interval"),
        (status = 400, description = "An unknown dimension", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, soft-deleted, not in this scope, or the dimension has no stored override", body = ErrorBody)
    )
)]
pub async fn clear_quota_limit(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, dimension)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    require_live_environment(&state, &scope).await?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    if QuotaDimension::parse(&dimension).is_none() {
        return Err(ApiError::BadRequest(format!(
            "unknown quota dimension {dimension:?}; expected one of: {}",
            known_dimensions()
        )));
    }

    // Existence first, so clearing an override that is not stored is the uniform not-found
    // rather than a silent success that tells the caller nothing.
    let scope_store = state.store().scoped(scope);
    if scope_store.quota_limits().get(&dimension).await?.is_none() {
        return Err(ApiError::NotFound);
    }

    let pending = quota_cleared_event(&state, scope, &dimension);
    scope_store
        .acting(actor, CorrelationId::generate(state.env()))
        .quota_limits()
        .clear_with_event(
            state.env(),
            &dimension,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The `quota.limit_changed` event for a set.
fn quota_limit_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    dimension: &str,
    request: &SetQuotaLimitRequest,
) -> Option<crate::events::PendingEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "quota.limit_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "dimension": dimension,
            "refill_per_sec": request.refill_per_sec,
            "burst": request.burst,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: dimension.to_owned(),
        envelope,
    })
}

/// The `quota.limit_changed` event for a clear.
fn quota_cleared_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    dimension: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "quota.limit_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "dimension": dimension, "cleared": true }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: dimension.to_owned(),
        envelope,
    })
}
