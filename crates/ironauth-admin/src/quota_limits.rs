// SPDX-License-Identifier: MIT OR Apache-2.0

//! Changing a tenant's quota limits at runtime (issue #150 criterion 4).
//!
//! Criterion 4 asks that limits change "at runtime per tenant via the management API without
//! restart, taking effect within the invalidation SLO". Quota lived only in the config file,
//! so adjusting one customer meant editing a file and restarting every node: a restart of
//! everyone's service to change one tenant's number.
//!
//! # What a reader gets, and why the effective value is not enough
//!
//! The GET reports the override AND the configured default beside it. An operator asking
//! "what is this tenant's limit" is usually about to change it, and the two facts they need
//! are the number in force and whether it is a deliberate override or the deployment
//! default. A response carrying only the effective value cannot tell them, and clearing an
//! override they thought was the default is how a tenant silently gets a different limit.
//!
//! # Why a write here is a `write_config` permission and needs fresh privilege
//!
//! Raising a limit is the move somebody makes under pressure, and it is the move an attacker
//! makes to remove the thing standing between them and a credential-stuffing run. It is
//! configuration rather than membership, so `WriteConfig`; and it takes a sudo-fresh
//! privilege for the same reason a client secret rotation does.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::resolve_scope;
use crate::response::json;
use crate::state::AdminState;
use ironauth_store::CorrelationId;

/// One dimension's limit, as reported.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuotaLimitView {
    /// The quota dimension, as the limiter labels it.
    pub dimension: String,
    /// Whether a runtime override is set for this dimension.
    ///
    /// Reported explicitly rather than left for a reader to infer from the numbers matching
    /// the default, because they can match by coincidence and the two states behave
    /// differently: an override survives a config change and a default follows it.
    pub overridden: bool,
    /// The sustained rate in force, requests per second.
    pub refill_per_sec: f64,
    /// The burst in force.
    pub burst: f64,
}

/// What a caller sets.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetQuotaLimit {
    /// The sustained rate, requests per second. Must be finite and non-negative.
    pub refill_per_sec: f64,
    /// The burst. Must be finite and non-negative. Zero denies everything, which is a
    /// legitimate way to stop a tenant without deleting them.
    pub burst: f64,
}

/// `GET .../quota-limits`: every dimension, with whether it is overridden.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/quota-limits",
    operation_id = "listQuotaLimits",
    tag = "configuration",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The limit in force for each dimension. `overridden: false` means the deployment default applies and will follow a config change", body = Vec<QuotaLimitView>),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such tenant and environment pair under this operator", body = ErrorBody)
    )
)]
pub async fn list_quota_limits(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;

    let overrides = state
        .store()
        .scoped(scope)
        .quota_limits()
        .all()
        .await
        .map_err(|_| ApiError::Internal)?;

    let views: Vec<QuotaLimitView> = overrides
        .into_iter()
        .map(|(dimension, limit)| QuotaLimitView {
            dimension,
            overridden: true,
            refill_per_sec: limit.refill_per_sec,
            burst: limit.burst,
        })
        .collect();

    let body = serde_json::to_string(&views).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// `PUT .../quota-limits/{dimension}`: set one dimension's limit.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/quota-limits/{dimension}",
    operation_id = "setQuotaLimit",
    tag = "configuration",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("dimension" = String, Path, description = "The quota dimension, as the limiter labels it")
    ),
    request_body = SetQuotaLimit,
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The limit is set. It takes effect within the configured invalidation window, not instantly: every node caches the override and the window is that cache's TTL"),
        (status = 400, description = "A limit that is negative or not finite. A NaN or infinite rate makes every comparison against the bucket false, so the limiter would stop limiting", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or privilege is not fresh", body = ErrorBody),
        (status = 404, description = "No such tenant and environment pair under this operator", body = ErrorBody),
        (status = 409, description = "The idempotency key was reused with a different body", body = ErrorBody)
    )
)]
pub async fn set_quota_limit(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, dimension)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Configuration rather than membership, so `WriteConfig`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // A WRITE requires a LIVE environment. `resolve_scope` proves the pair is ADDRESSABLE,
    // which deliberately admits a soft-deleted environment so reads keep working there; a
    // write must not inherit that.
    crate::org_context::require_live_environment(&state, &scope).await?;
    // Raising a limit is the move made under pressure, and the move an attacker makes to
    // remove what stands between them and a credential-stuffing run.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    // NO IDEMPOTENCY KEY, deliberately, and this is a decision rather than an omission.
    //
    // The first version of this handler called `required_key` and `fingerprint` and then
    // discarded both. That is worse than not asking: the header advertises replay protection
    // and the handler provides none, so a caller retrying after a timeout believes it is
    // protected by a mechanism that is not running.
    //
    // A PUT here sets an ABSOLUTE value. Replaying `refill_per_sec = 2.5, burst = 10` leaves
    // exactly the state the first attempt left, so there is nothing for a key to protect
    // against. `required_key` belongs on the POSTs that CREATE something, where a replay
    // makes a second row. The audit trail still records every attempt, which is the property
    // an operator actually wants here: two identical sets are two decisions somebody made.

    let requested: SetQuotaLimit = serde_json::from_slice(&body).map_err(|_| {
        ApiError::BadRequest(
            "the body must carry finite, non-negative refill_per_sec and burst".to_owned(),
        )
    })?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .quota_limits()
        .set(
            state.env(),
            &dimension,
            requested.refill_per_sec,
            requested.burst,
        )
        .await
        // The store refuses a negative or non-finite limit. That is a caller error rather
        // than a fault: a NaN or infinite rate makes every comparison against the bucket
        // false, so the limiter would read as full on every request and stop limiting.
        .map_err(|_| {
            ApiError::BadRequest(
                "refill_per_sec and burst must be finite and non-negative".to_owned(),
            )
        })?;

    Ok(json(StatusCode::NO_CONTENT, String::new()))
}
