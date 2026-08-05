// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two security postures the data plane ENFORCES and nothing could set (issues #27, #78).
//!
//! Both were found by the same sweep and share one defect shape: a column the OIDC data
//! plane reads on every relevant request, a store setter that writes it, and no caller
//! anywhere in production. The enforcement shipped; the way to turn it on did not.
//!
//! * `clients.require_pushed_authorization_requests` is read at
//!   `authorize.rs:509`, where the gate is `state.require_pushed_authorization_requests()
//!   || client.require_pushed_authorization_requests`. So PAR could be required for the
//!   WHOLE deployment through `oidc.require_pushed_authorization_requests`, and never for
//!   one client. `ironauth_config` describes the per-client flag as one that arrives at
//!   REGISTRATION, which was not true of any code: the dynamic client registration path
//!   neither accepts nor writes it, so the column sat at its `false` default forever.
//!
//! * `environments.auto_link_posture` is the per-environment override of the deployment
//!   account-linking default (issue #78, FORK B). The store write exists, carries its own
//!   audit action and a column-scoped control grant, and had no caller.
//!
//! Neither is a new capability. Both are switches for machinery that already runs.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::CorrelationId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::json;
use crate::state::AdminState;

/// Require (or stop requiring) Pushed Authorization Requests for one client.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetClientParRequirementRequest {
    /// Whether this client must use PAR. `true` requires it for this client even when the
    /// deployment does not; `false` leaves the client to the deployment-wide setting,
    /// which can still require it.
    pub required: bool,
}

/// A client's PAR requirement as stored.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientParRequirementView {
    /// The client this describes.
    pub client_id: String,
    /// Whether PAR is required for this client specifically.
    pub require_pushed_authorization_requests: bool,
}

/// Set a client's Pushed Authorization Request requirement (RFC 9126).
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/par-requirement",
    operation_id = "setClientParRequirement",
    tag = "clients",
    request_body = SetClientParRequirementRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The client identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The stored requirement", body = ClientParRequirementView),
        (status = 400, description = "Malformed request or a body omitting `required`", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or a lapsed sudo elevation", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, malformed, or another scope's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn set_client_par_requirement(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Tightening or relaxing an authorization-request control is exactly the class of
    // change sudo mode exists for.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    require_live_environment(&state, &scope).await?;

    // Address the target FIRST, for the reason `client_scopes.rs` records: a caller who
    // cannot address the client must not learn "that client is not yours" from the STATUS
    // of a body-level refusal.
    let id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(&client_id)
        .map_err(|_| ApiError::NotFound)?;
    // The read is the ADDRESSING check: a client of another scope, or an absent one, is
    // the uniform not-found before the body is even parsed.
    state.store().scoped(scope).clients().get(&id).await?;

    let request: SetClientParRequirementRequest = parse_json(&body)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .set_require_pushed_authorization_requests(state.env(), &id, request.required)
        .await?;

    // Re-read through the SAME address, so the response reports what was stored rather
    // than what was asked for.
    let updated = state.store().scoped(scope).clients().get(&id).await?;
    let view = ClientParRequirementView {
        client_id: id.to_string(),
        require_pushed_authorization_requests: updated.require_pushed_authorization_requests,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Set or clear an environment's account-linking posture override.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetAutoLinkPostureRequest {
    /// `off` or `verified_to_verified`, or an explicit `null` to CLEAR the override so the
    /// environment inherits the deployment default. The field is required so that "clear
    /// it" is stated rather than inferred from an omission.
    pub posture: Option<String>,
}

/// An environment's stored account-linking posture.
#[derive(Debug, Serialize, ToSchema)]
pub struct AutoLinkPostureView {
    /// The stored override, or `null` when the environment inherits the deployment
    /// default.
    pub posture: Option<String>,
}

/// The closed posture vocabulary the column CHECK pins.
///
/// Validated HERE as well as by the CHECK so an unknown token is a precise 400 rather than
/// a database error surfacing as a 500, which is the shape this codebase keeps removing.
const AUTO_LINK_POSTURES: [&str; 2] = ["off", "verified_to_verified"];

/// Set an environment's account-linking posture (issue #78).
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/auto-link-posture",
    operation_id = "setAutoLinkPosture",
    tag = "environments",
    request_body = SetAutoLinkPostureRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The stored posture, or null when the deployment default is inherited", body = AutoLinkPostureView),
        (status = 400, description = "Malformed request, a body omitting `posture`, or a token outside the closed set", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or a lapsed sudo elevation", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or soft-deleted", body = ErrorBody)
    )
)]
pub async fn set_auto_link_posture(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Account linking decides when two identities from different sources become ONE
    // account, so loosening it is a privileged change.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    require_live_environment(&state, &scope).await?;

    let request: SetAutoLinkPostureRequest = parse_json(&body)?;
    if let Some(posture) = request.posture.as_deref() {
        if !AUTO_LINK_POSTURES.contains(&posture) {
            return Err(ApiError::BadRequest(format!(
                "posture must be one of {} (or null to inherit the deployment default)",
                AUTO_LINK_POSTURES.join(" | ")
            )));
        }
    }

    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .environments(scope.tenant())
        .set_auto_link_posture(
            state.env(),
            &scope.environment(),
            request.posture.as_deref(),
        )
        .await?;

    let view = AutoLinkPostureView {
        posture: request.posture,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}
