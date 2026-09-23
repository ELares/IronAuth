// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management surface for the signing-key rotation state machine (issue #160).
//!
//! Three operations on the environment prefix:
//!
//! - `GET /signing/rotation` lists every key's derived state (pending, current, retiring,
//!   retired), the lifecycle instants, and the next scheduled rotation for the current
//!   head. Read-only; an operator inspects the machine without touching it.
//! - `POST /signing/rotation/advance` runs the machine's tick NOW (the manual trigger):
//!   seeds a successor when the pre-publication point is due, promotes due pending keys,
//!   and records withdrawals. The trigger is naturally idempotent — re-running at the
//!   same instant does nothing new, which is exactly the crashed-timer property — so no
//!   Idempotency-Key machinery is warranted. Every transition is audited in its own
//!   transaction; the summary domain event (`signing_key.rotation_advanced`) is emitted
//!   after the machine returns its report.
//! - `POST /signing/rotation/break-glass` is the rotate-now-and-revoke path a real
//!   compromise requires: a fresh successor is minted and promoted immediately and the
//!   compromised key is withdrawn NOW, accepting the verification breakage that entails.
//!   The request MUST carry `confirmed: true` — a refused invocation leaves no trace —
//!   and the invocation is audited with the acting actor.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::key_rotation::{KeyState, RotationPolicy, RotationStateMachine};
use ironauth_store::{CorrelationId, StoreError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One key's lifecycle view, as the management surface renders it.
#[derive(Debug, Serialize, ToSchema)]
pub struct RotationKeyView {
    /// The JOSE kid.
    pub kid: String,
    /// The JOSE algorithm.
    pub algorithm: String,
    /// The derived state.
    pub state: String,
    /// The pre-publication instant, epoch milliseconds.
    pub publish_at: i64,
    /// The activation instant, epoch milliseconds.
    pub activate_at: i64,
    /// The handoff instant, epoch milliseconds (absent while head).
    pub retire_at: Option<i64>,
    /// The expiry instant, epoch milliseconds (absent while published).
    pub expire_at: Option<i64>,
    /// The next scheduled rotation for the current head, epoch milliseconds.
    pub next_rotation_at: Option<i64>,
}

/// The full state of the machine for a scope.
#[derive(Debug, Serialize, ToSchema)]
pub struct SigningKeyRotationView {
    /// Every key, in store order.
    pub keys: Vec<RotationKeyView>,
}

/// The break-glass request: the confirmation flag is mandatory, not advisory.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BreakGlassRequest {
    /// Must be `true`. A refused invocation leaves no trace.
    pub confirmed: bool,
}

fn as_view(key: &ironauth_store::key_rotation::RotationKeyView) -> RotationKeyView {
    RotationKeyView {
        kid: key.kid.clone(),
        algorithm: key.algorithm.clone(),
        state: match key.state {
            KeyState::Pending => "pending",
            KeyState::Current => "current",
            KeyState::Retiring => "retiring",
            KeyState::Retired => "retired",
        }
        .to_owned(),
        publish_at: key.publish_at_unix_micros / 1000,
        activate_at: key.activate_at_unix_micros / 1000,
        retire_at: key.retire_at_unix_micros.map(|us| us / 1000),
        expire_at: key.expire_at_unix_micros.map(|us| us / 1000),
        next_rotation_at: key.next_rotation_at_unix_micros.map(|us| us / 1000),
    }
}

/// The per-environment policy for the machine's surfaces. The config seam owns the
/// values; the default is the safe one (a 90-day cadence, a day of pre-publication).
fn policy() -> RotationPolicy {
    RotationPolicy::default()
}

/// The assumed access-token lifetime the machine uses to size the retiring key's
/// expiry: the OIDC default. The durable timer's boot wiring (the next slice of #160)
/// will read the environment's real configured value; the machine's retirement buffer
/// covers the difference.
const ASSUMED_ACCESS_TOKEN_LIFETIME_SECS: u64 = 3600;

/// List every key's rotation state and the next scheduled rotation.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/signing/rotation",
    operation_id = "listSigningKeyRotation",
    tag = "signing",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Every signing key's rotation state", body = SigningKeyRotationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or not in this scope", body = ErrorBody)
    )
)]
pub async fn list_signing_key_rotation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;
    let records = state
        .store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .map_err(ApiError::from)?;
    let views = ironauth_store::key_rotation::rotation_key_views(
        &records,
        policy(),
        state.now_unix_micros() * 1000,
    );
    let body = serde_json::to_string(&SigningKeyRotationView {
        keys: views.iter().map(as_view).collect(),
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Run the machine's tick now: the manual trigger.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/signing/rotation/advance",
    operation_id = "advanceSigningKeyRotation",
    tag = "signing",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The tick ran; every transition was audited and the summary event emitted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, soft-deleted, or not in this scope", body = ErrorBody)
    )
)]
pub async fn advance_signing_key_rotation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    require_live_environment(&state, &scope).await?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let (actor, corr) = (actor, CorrelationId::generate(state.env()));
    let machine = RotationStateMachine::new(state.store(), scope, actor, corr);
    let now = state.now_unix_micros() * 1000;
    let report = machine
        .advance(
            state.env(),
            policy(),
            now,
            ASSUMED_ACCESS_TOKEN_LIFETIME_SECS,
        )
        .await
        .map_err(ApiError::from)?;
    let event = rotation_advanced_event(&state, scope, &report);
    if let Some(event) = event {
        state
            .store()
            .scoped(scope)
            .events()
            .emit(state.env(), &event.domain_event())
            .await
            .map_err(ApiError::from)?;
    }
    Ok(no_content())
}

/// The rotate-now-and-revoke path: a fresh successor immediately, the compromised key
/// withdrawn NOW. The confirmation flag is mandatory.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/signing/rotation/break-glass",
    operation_id = "breakGlassSigningKeyRotation",
    tag = "signing",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    request_body = BreakGlassRequest,
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The compromised key was withdrawn immediately; the fresh successor signs"),
        (status = 400, description = "The confirmation flag was not `true`", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, soft-deleted, or not in this scope", body = ErrorBody)
    )
)]
pub async fn break_glass_signing_key_rotation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    require_live_environment(&state, &scope).await?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let request: BreakGlassRequest = parse_json(&body)?;
    if !request.confirmed {
        return Err(ApiError::BadRequest(
            "break-glass requires an explicit confirmation flag".to_owned(),
        ));
    }
    let (actor, corr) = (actor, CorrelationId::generate(state.env()));
    let machine = RotationStateMachine::new(state.store(), scope, actor, corr);
    let report = machine
        .break_glass(state.env(), state.now_unix_micros() * 1000, true)
        .await
        .map_err(|error| match error {
            StoreError::Invalid => ApiError::BadRequest(
                "break-glass requires an explicit confirmation flag".to_owned(),
            ),
            other => ApiError::from(other),
        })?;
    let event = break_glass_event(&state, scope, &report);
    if let Some(event) = event {
        state
            .store()
            .scoped(scope)
            .events()
            .emit(state.env(), &event.domain_event())
            .await
            .map_err(ApiError::from)?;
    }
    Ok(no_content())
}

/// The summary event for a manual advance: the report's kids travel.
fn rotation_advanced_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    report: &ironauth_store::key_rotation::RotationReport,
) -> Option<crate::events::PendingEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "signing_key.rotation_advanced",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "provisioned": report.provisioned.iter().map(|(_, kid)| kid).collect::<Vec<_>>(),
            "promoted": report.promoted.iter().map(|(_, kid)| kid).collect::<Vec<_>>(),
            "retiring": report.retiring.iter().map(|(_, kid)| kid).collect::<Vec<_>>(),
            "retired": report.retired.iter().map(|(_, kid)| kid).collect::<Vec<_>>(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: scope.environment().to_string(),
        envelope,
    })
}

/// The break-glass event: the withdrawn kids travel.
fn break_glass_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    report: &ironauth_store::key_rotation::RotationReport,
) -> Option<crate::events::PendingEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let withdrawn = report
        .retired
        .iter()
        .map(|(_, kid)| kid)
        .collect::<Vec<_>>();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "signing_key.break_glass",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "withdrawn": withdrawn }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: scope.environment().to_string(),
        envelope,
    })
}
