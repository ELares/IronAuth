// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin session privilege separation (sudo mode), issue #73.
//!
//! Sudo mode bounds what a stolen admin credential can do. A READ is always allowed;
//! a MUTATION additionally requires a RECENT re-authentication. The freshness is
//! evaluated the SAME way the step-up path (issue #72) evaluates a max-auth-age
//! window, via the reusable [`ironauth_oidc::privilege_is_fresh`] seam, against a
//! recorded elevation instant that DERIVES FROM A SERVER-WRITTEN RE-AUTH EVENT and
//! never from a client-supplied header or flag (the #14/#72 acr honesty discipline).
//!
//! Two pieces:
//!
//! - [`require_fresh_privilege`] is the mutation guard. When the flag is off it is a
//!   no-op (the admin surface is unchanged); when on, it reads the LATEST elevation
//!   for the acting principal in the request scope and returns the RFC 9470
//!   [`ApiError::ReauthRequired`] challenge when the window has lapsed or no elevation
//!   exists, executing nothing.
//! - [`elevate_sudo`] is the re-authentication endpoint. It records a fresh elevation
//!   for the acting principal, entirely server-side (the instant comes from the clock
//!   seam, never the request), and audits it. The prototype scopes elevation to the
//!   ENVIRONMENT plane, keyed by `(tenant, environment, acting principal)`, which
//!   covers the highest-risk environment-scoped mutation surfaces; extending the same
//!   seam to the operator plane and to end-user application sessions is future work
//!   the reusable freshness check is deliberately not admin-hardcoded for.
//!
//! The acceptance-critical guarantee: because the elevation is read from server-side
//! state and can never be set by any request field, a stolen credential whose recorded
//! elevation is absent or stale cannot perform a mutation once the window lapses, while
//! its reads still work.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ActorRef, CorrelationId, Scope};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::sessions::scope_from_path;
use crate::state::AdminState;

/// The recorded authentication context of an admin sudo re-authentication (issue #73).
/// A server-derived, honest acr value (never a client-asserted one); it records that
/// the elevation came from an admin re-authentication event.
const ADMIN_REAUTH_ACR: &str = "urn:ironauth:acr:admin_reauth";

/// The mutation freshness guard (issue #73).
///
/// When sudo mode is OFF this is a no-op, so the admin surface behaves exactly as
/// before. When ON, it reads the latest recorded elevation for `actor` in `scope` and
/// authorizes the mutation only while the freshness window has not lapsed; otherwise it
/// audits the refusal (the expiry event) and returns the RFC 9470 challenge. The
/// freshness derives entirely from server-side state, so no request field can forge it.
///
/// # Errors
///
/// [`ApiError::ReauthRequired`] when sudo mode is on and the acting credential has no
/// fresh elevation; [`ApiError::Internal`] on a store fault reading the elevation.
pub(crate) async fn require_fresh_privilege(
    state: &AdminState,
    scope: Scope,
    actor: ActorRef,
) -> Result<(), ApiError> {
    // Inert when off: the admin surface is unchanged.
    if !state.sudo_mode_enabled() {
        return Ok(());
    }
    let elevation = state
        .store()
        .scoped(scope)
        .admin_sudo_elevations()
        .latest_for_actor(&actor.id_string())
        .await?;
    // The freshness source is the recorded elevation instant. A missing elevation is
    // `None`, which the reused step-up seam treats as lapsed (fail closed).
    let auth_time = elevation.as_ref().map(|row| row.elevated_at_unix_micros);
    let fresh = ironauth_oidc::privilege_is_fresh(
        auth_time,
        state.sudo_mode_window_secs(),
        state.now_unix_micros(),
    );
    if fresh {
        return Ok(());
    }
    // Audit the refusal (the expiry / challenge event). A store fault auditing the
    // refusal must NEVER turn the refusal into a success, so it is logged and the
    // challenge is still returned.
    if let Err(err) = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .admin_sudo_elevations()
        .record_challenge(state.env())
        .await
    {
        tracing::error!(error = %err, "failed to audit admin sudo challenge");
    }
    Err(ApiError::ReauthRequired {
        max_age: state.sudo_mode_window_secs(),
    })
}

/// The result of a successful admin sudo elevation (issue #73).
#[derive(Debug, Serialize, ToSchema)]
pub struct SudoElevationView {
    /// Always `true`: the acting credential is now elevated for the scope.
    pub elevated: bool,
    /// The achieved authentication context recorded for the elevation.
    pub acr: String,
    /// The recorded re-authentication instant, epoch microseconds.
    pub elevated_at_unix_micros: i64,
    /// When the elevation lapses, epoch microseconds (`elevated_at + the window`).
    pub expires_at_unix_micros: i64,
    /// The freshness window, in seconds, this elevation authorizes mutations for.
    pub window_secs: u64,
}

/// `POST .../admin/sudo/elevate`: record a fresh re-authentication elevation for the
/// acting credential (issue #73), opening the sudo freshness window so subsequent
/// admin mutations in this environment are authorized until the window lapses.
///
/// The elevation instant is taken from the server clock seam, never the request, and
/// the event is audited (`admin.privilege.elevated`). When sudo mode is off the
/// endpoint is a uniform not-found, so the feature is fully inert.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/admin/sudo/elevate",
    operation_id = "elevateAdminSudo",
    tag = "sudo",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional. Recording an \
         elevation is naturally safe to repeat (it refreshes the window), so the key is \
         not required.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The acting credential is elevated", body = SudoElevationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Sudo mode is disabled, or the scope is not found", body = ErrorBody)
    )
)]
pub async fn elevate_sudo(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // Inert when off: the endpoint is a uniform not-found, so a disabled deployment
    // exposes no sudo surface.
    if !state.sudo_mode_enabled() {
        return Err(ApiError::NotFound);
    }
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Authorize the scope (the operator plane, or the environment's own key). The
    // returned actor is exactly the identity the mutation guard later keys freshness on.
    let actor = principal.require_environment(tenant, scope.environment())?;

    let now = state.now_unix_micros();
    let window = state.sudo_mode_window_secs();
    let window_micros = i64::try_from(window)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    let expires = now.saturating_add(window_micros);

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .admin_sudo_elevations()
        .record(state.env(), ADMIN_REAUTH_ACR, now, expires)
        .await?;

    let view = SudoElevationView {
        elevated: true,
        acr: ADMIN_REAUTH_ACR.to_owned(),
        elevated_at_unix_micros: now,
        expires_at_unix_micros: expires,
        window_secs: window,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
