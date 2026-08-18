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
use crate::org_context::require_live_environment;
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
/// # This runs BEFORE the environment liveness fence, deliberately (issue #452)
///
/// Every environment-scoped write calls this FIRST and resolves its parent environment
/// SECOND. That ordering is the one that leaks nothing: a caller whose elevation has
/// lapsed is answered 401 `insufficient_user_authentication` without the server having
/// read a single row of the environment it named, so the challenge cannot be used to
/// distinguish a live environment from a decommissioned one from one that never existed.
/// Fencing first would answer the unprivileged caller a 404 for a live environment and a
/// 404 for an absent one, which is uniform, but it would also spend an environment read
/// on an unauthorized request and would make the two checks' order the thing a future
/// reader has to reason about.
///
/// The consequence is a WRITE that lands in a soft-deleted environment, and it is
/// intended rather than accidental: `record_challenge` below writes an
/// `admin.privilege.challenged` row into the `audit_log` of an environment an operator
/// believes is decommissioned. MEASURED, at a router with sudo mode armed, a lapsed
/// elevation, and the environment soft-deleted first: the write answered 401
/// `insufficient_user_authentication`, and the scope's audit trail went from three rows
/// to four, the new row being exactly `admin.privilege.challenged`.
///
/// The owner decided that row STAYS. An audit row recording a REJECTED access attempt
/// has value against a decommissioned environment, arguably more than usual, because
/// someone is poking at something an operator believes is gone, and the record of that is
/// precisely what an investigation would want. It is the one documented exception to
/// "no write lands in a soft-deleted environment" (issues #411, #443, #451), and the
/// whole-surface sweep in `crates/ironauth-admin/tests/live_surface.rs` measures the
/// unarmed configuration, in which this guard is inert and the claim holds without
/// exception.
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
    // Note: freshness recomputes `elevated_at + the CURRENT window_secs` and ignores the
    // stored `expires_at`, so lowering `admin.sudo_window_secs` shrinks already-live
    // elevations immediately (the tunability principle: a config change takes effect now).
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
        (status = 404, description = "The environment is absent or deleted, or sudo mode is disabled", body = ErrorBody)
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
    // The PARENT-EXISTENCE precondition (issue #409). `scope_from_path` proves only that
    // the two path segments PARSE, and an elevation is a WRITE: `admin_sudo_elevations`
    // carries a composite foreign key to `environments`, and a well-formed identifier
    // naming an environment that does not exist was MEASURED reaching that constraint
    // (`admin_sudo_elevations_environment_id_tenant_id_fkey`, a value recorded from that
    // run rather than an invariant any test enforces, since `StoreError` is mapped to
    // `ApiError::Internal` before it reaches the wire) and coming back as an opaque 500.
    // The route already answers the uniform not-found when sudo mode is off, so an
    // unreachable environment gives the same answer and adds no new shape. There is no
    // Idempotency-Key here (an elevation is naturally safe to repeat), so nothing orders
    // ahead of it.
    require_live_environment(&state, &scope).await?;

    let now = state.now_unix_micros();
    let window = state.sudo_mode_window_secs();
    let window_micros = i64::try_from(window)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    let expires = now.saturating_add(window_micros);

    let pending = sudo_elevated_event(&state, scope, &actor.id_string(), expires);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .admin_sudo_elevations()
        .record_with_event(
            state.env(),
            ADMIN_REAUTH_ACR,
            now,
            expires,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
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

/// The event a sudo elevation emits (issue #108).
///
/// A management credential just gained sudo: for the length of the window it may make the
/// mutations the freshness gate otherwise refuses. That is a privilege escalation by design,
/// and it is what an oversight consumer watches for.
///
/// The EXPIRY travels because an elevation is a window, not a state, and a receiver that
/// could not see the window would have to treat every elevation as permanent. The achieved
/// `acr` travels because it says what the re-authentication actually proved.
///
/// No elevation id: the store mints it inside the write, so naming one here would mean
/// announcing a handle this producer does not hold.
fn sudo_elevated_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    actor_id: &str,
    expires_at_unix_micros: i64,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "sudo.elevated",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "actor_id": actor_id,
            "acr": ADMIN_REAUTH_ACR,
            "expires_at_unix_ms": expires_at_unix_micros / 1000,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The ACTOR is the subject: successive elevations by one credential stay ordered, and
        // an oversight consumer reads them as one timeline.
        subject: actor_id.to_owned(),
        envelope,
    })
}
