// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authorizing an impersonation (issue #101, criteria 3 and 6).
//!
//! # Why this issues an authorization rather than creating a session
//!
//! Starting an impersonation ultimately means a session for the target user, and the control
//! plane cannot create one: `INSERT` on `sessions` belongs to the app plane alone. Granting the
//! control plane that INSERT would work in one line and would also let it mint an ORDINARY
//! session for any user, unflagged and unaudited, because `impersonator` is nullable and a
//! grant cannot be conditioned on a column value. That is the capability the two-plane split
//! exists to deny.
//!
//! So this route issues a single-use, bounded, audited AUTHORIZATION, and the app plane
//! redeems it into the flagged session. What an operator gets back is the handle to redeem.
//!
//! # Why the justification is not validated here
//!
//! It is validated by [`ironauth_store::impersonation::Impersonation::start`], and this only
//! maps the refusal onto the wire. A check written a third time in a handler would be a third
//! opinion about what a justification is, and the one an operator meets would be the one
//! nothing else agreed with. The rejection carries a stable code per rule, so a caller is told
//! WHICH rule they broke rather than "rejected".

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::impersonation::{IMPERSONATION_MAX_DURATION_MICROS, Impersonation};
use ironauth_store::{
    CorrelationId, ImpersonationAuthorizationId, NewImpersonationAuthorization, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, resolve_scope, resolve_user};
use crate::response::json;
use crate::state::AdminState;

/// The authorize request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizeImpersonationRequest {
    /// The structured reason, from the operator's vocabulary. Required.
    pub reason_code: String,
    /// The written justification. Required, and required to be more than blank: a category
    /// alone answers "what kind" and not "why this user, right now", which is what an auditor
    /// reads.
    pub reason_text: String,
    /// How long the impersonation may last, in seconds. Absent means the full cap.
    ///
    /// A value ABOVE the cap is refused rather than clamped. Silently shortening it would tell
    /// an operator their sixty-first minute was granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i64>,
}

/// What authorizing an impersonation answers.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImpersonationAuthorized {
    /// The `imp_` handle, redeemed ONCE on the app plane for the flagged session.
    pub authorization_id: String,
    /// The user this authorizes acting as.
    pub user_id: String,
    /// When the impersonation must stop, in milliseconds since the epoch. The redeemed
    /// session inherits this, and nothing extends it.
    pub expires_at_unix_ms: i64,
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/impersonation",
    operation_id = "authorizeUserImpersonation",
    tag = "users",
    request_body = AuthorizeImpersonationRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user to be impersonated")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Authorized. The handle is redeemed once for a flagged, capped session", body = ImpersonationAuthorized),
        (status = 400, description = "Malformed request, or a justification that is missing, blank, or a duration past the 60 minute cap. The error code names the rule", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or the credential does not hold management.impersonate", body = ErrorBody),
        (status = 404, description = "The user is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn authorize_user_impersonation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): IMPERSONATE, its own permission and held by no
    // persona by default. A credential that can authorize an impersonation can reach anything
    // any user of the environment can reach, so `WriteUsers` must not carry it: editing a user
    // and becoming one are different authorities.
    //
    // PROVEN, not merely classified.
    // `only_a_credential_holding_impersonate_can_authorize_one` in `delegated_admin.rs` drives
    // a credential holding every OTHER permission and asserts the refusal names
    // `management.impersonate`.
    principal.require_permission(ManagementPermission::Impersonate)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let target = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    // The user must EXIST. Without this an authorization could name nobody, and the failure
    // would surface at redemption as a foreign-key error on a plane that did not make the
    // mistake.
    state.store().scoped(scope).users().get(&target).await?;
    let request: AuthorizeImpersonationRequest = parse_json(&body)?;

    let now = state.now_unix_micros();
    let requested = request
        .duration_seconds
        .map_or(IMPERSONATION_MAX_DURATION_MICROS, |seconds| {
            seconds.saturating_mul(1_000_000)
        });
    let impersonator = principal.credential_ref();
    // The ONE validation, borrowed rather than restated.
    let act = Impersonation::start(
        impersonator.as_str(),
        &request.reason_code,
        &request.reason_text,
        now,
        requested,
    )
    .map_err(ApiError::ImpersonationRejected)?;

    let id = ImpersonationAuthorizationId::generate(state.env(), &scope);
    let authorized = ImpersonationAuthorized {
        authorization_id: id.to_string(),
        user_id: target.to_string(),
        expires_at_unix_ms: act.expires_at_unix_micros() / 1000,
    };
    let body_string = serde_json::to_string(&authorized).map_err(|_| ApiError::Internal)?;

    let pending = impersonation_authorized_event(
        &state,
        scope,
        &id,
        &target,
        &request.reason_code,
        act.expires_at_unix_micros(),
    );
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .impersonation_authorizations()
        .issue_with_event(
            state.env(),
            NewImpersonationAuthorization {
                id: &id,
                user_id: &target,
                impersonation: act,
            },
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

/// The event an impersonation authorization emits (issue #108).
///
/// An operator was authorized to BECOME a user: the widest authority this surface hands out,
/// reaching everything that user can reach. A consumer running detection or oversight acts on
/// this above almost anything else the management plane emits.
///
/// The expiry travels because the authorization is time-boxed, and a receiver that cannot see
/// the box has to treat every authorization as permanent. The reason CODE travels because it
/// is a registered classification. The reason TEXT does not: it is prose an operator wrote
/// about a person's account, and it belongs in the audit trail, which is a narrower audience
/// than a webhook.
fn impersonation_authorized_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    authorization_id: &ImpersonationAuthorizationId,
    user_id: &ironauth_store::UserId,
    reason_code: &str,
    expires_at_unix_micros: i64,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "impersonation.authorized",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "authorization_id": authorization_id.to_string(),
            "user_id": user_id.to_string(),
            "reason_code": reason_code,
            "expires_at_unix_ms": expires_at_unix_micros / 1000,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The USER is the subject: every authorization against one person stays ordered, and
        // an oversight consumer reads them as one timeline.
        subject: user_id.to_string(),
        envelope,
    })
}
