// SPDX-License-Identifier: MIT OR Apache-2.0

//! Guarded SMS OTP configuration (issue #70): the per-environment enable switch, the
//! factor-downgrade opt-in, and the country calling-code allowlist.
//!
//! Migration 0050 states the operating requirement in its own comment on `sms_config`:
//! "Off by default in EVERY tenant/environment: SMS OTP is unusable until a tenant
//! explicitly turns it on AND populates the country allowlist." Nothing could do either.
//! Measured before this module existed: `set_config`, `allowlist`, `add_allowlist_country`
//! and `remove_allowlist_country` had ZERO production callers, and the published
//! management contract carried no SMS operation at all.
//!
//! So every deployment ran with no `sms_config` row, which reads as disabled, and an EMPTY
//! allowlist. `allowlist_contains` is an allowlist rather than a blocklist, so an empty one
//! refuses EVERY country: the factor was unreachable twice over, and an operator who
//! wanted it had no way to ask for it.
//!
//! The data plane already reads both relations on the send path and keeps its grants;
//! migration 0105 adds the control-plane grants this surface needs, mirroring 0050's
//! app-role grants exactly and no wider.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use ironauth_store::CorrelationId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    auth::{ManagementPermission, Principal},
    error::{ApiError, ErrorBody},
    input::parse_json,
    org_context::{require_live_environment, resolve_scope},
    response::{json, no_content},
    state::AdminState,
    sudo,
};

/// The environment's SMS OTP configuration.
#[derive(Debug, Serialize, ToSchema)]
pub struct SmsConfigView {
    /// Whether the SMS OTP factor is enabled for this environment. Off by default, and
    /// enabling it alone is not enough: the country allowlist must also be populated.
    pub enabled: bool,
    /// Whether SMS may satisfy a step-up that a stronger factor would otherwise require.
    /// Off by default; this is the no-silent-downgrade invariant, and turning it on is an
    /// explicit weakening a tenant opts into.
    pub allow_factor_downgrade: bool,
}

/// Set the environment's SMS OTP configuration.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetSmsConfigRequest {
    /// Whether the SMS OTP factor is enabled.
    pub enabled: bool,
    /// Whether SMS may satisfy a step-up a stronger factor would otherwise require.
    #[serde(default)]
    pub allow_factor_downgrade: bool,
}

/// The country calling codes SMS may be sent to.
#[derive(Debug, Serialize, ToSchema)]
pub struct SmsAllowlistView {
    /// E.164 country calling codes, digits only (for example `1`, `44`), ordered.
    /// EMPTY means every destination is refused, which is what an unconfigured
    /// environment looks like.
    pub items: Vec<String>,
}

/// Validate an E.164 country calling code at the edge.
///
/// The store does not check the shape and migration 0050's CHECK only enforces non-empty,
/// so without this a caller could put arbitrary text on the allowlist. It would never match
/// a parsed number's country code, so the row would be silently inert: an operator would
/// see their code listed and sends would still refuse, which is the worst of both answers.
/// The comment on the column defines the grammar (digits only), so it is enforced here.
fn require_country_code(raw: &str) -> Result<String, ApiError> {
    if !raw.is_empty() && raw.len() <= 4 && raw.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(raw.to_owned());
    }
    Err(ApiError::BadRequest(
        "country_code must be an E.164 calling code of one to four digits, for example 1 or 44"
            .to_owned(),
    ))
}

/// Read the environment's SMS OTP configuration.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/config",
    operation_id = "getSmsOtpConfig",
    tag = "sms_otp",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The SMS OTP configuration", body = SmsConfigView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Tenant or environment not found", body = ErrorBody)
    )
)]
pub async fn get_sms_otp_config(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    // An environment with no row is DISABLED, which is the shipped default rather than a
    // not-found: reporting 404 here would make "never configured" indistinguishable from
    // "absent environment" on a read an operator uses to decide what to configure.
    let config = state.store().scoped(scope).sms_otp().config().await?;
    let view = SmsConfigView {
        enabled: config.enabled,
        allow_factor_downgrade: config.allow_factor_downgrade,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Set the environment's SMS OTP configuration.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/config",
    operation_id = "setSmsOtpConfig",
    tag = "sms_otp",
    request_body = SetSmsConfigRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The stored configuration", body = SmsConfigView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody)
    )
)]
pub async fn set_sms_otp_config(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;
    require_live_environment(&state, &scope).await?;
    let request: SetSmsConfigRequest = parse_json(&body)?;
    let pending = sms_config_event(
        &state,
        scope,
        request.enabled,
        request.allow_factor_downgrade,
    );
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sms_otp()
        .set_config_with_event(
            state.env(),
            request.enabled,
            request.allow_factor_downgrade,
            state.now_unix_micros(),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    let view = SmsConfigView {
        enabled: request.enabled,
        allow_factor_downgrade: request.allow_factor_downgrade,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// List the environment's SMS country allowlist.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist",
    operation_id = "listSmsAllowlist",
    tag = "sms_otp",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The allowed country calling codes", body = SmsAllowlistView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Tenant or environment not found", body = ErrorBody)
    )
)]
pub async fn list_sms_allowlist(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let items = state.store().scoped(scope).sms_otp().allowlist().await?;
    let body =
        serde_json::to_string(&SmsAllowlistView { items }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Allow SMS to a country calling code.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist/{country_code}",
    operation_id = "allowSmsCountry",
    tag = "sms_otp",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("country_code" = String, Path, description = "The E.164 country calling code, digits only")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The country is allowed"),
        (status = 400, description = "The country code is not an E.164 calling code", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody)
    )
)]
pub async fn allow_sms_country(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, country_code)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;
    require_live_environment(&state, &scope).await?;
    let country_code = require_country_code(&country_code)?;
    let pending = sms_allowlist_event(&state, scope, &country_code, true);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sms_otp()
        .add_allowlist_country_with_event(
            state.env(),
            &country_code,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// Stop allowing SMS to a country calling code.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist/{country_code}",
    operation_id = "denySmsCountry",
    tag = "sms_otp",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("country_code" = String, Path, description = "The E.164 country calling code, digits only")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The country is no longer allowed"),
        (status = 400, description = "The country code is not an E.164 calling code", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody)
    )
)]
pub async fn deny_sms_country(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, country_code)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;
    require_live_environment(&state, &scope).await?;
    let country_code = require_country_code(&country_code)?;
    // Removing a code that was never allowed is a NO-OP that answers 204, not a not-found.
    // The post-state is what the caller asked for either way, and a 404 here would turn
    // this route into a probe for which countries an environment allows, which the list
    // read above already answers to an authorized caller and should not be inferable from
    // a delete.
    let pending = sms_allowlist_event(&state, scope, &country_code, false);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sms_otp()
        .remove_allowlist_country_with_event(
            state.env(),
            &country_code,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The event an SMS-OTP configuration change emits (issue #108).
///
/// BOTH flags, because the pair IS the policy: "enabled" alone does not tell a receiver
/// whether a user may fall back from a stronger factor, and that is the part with security
/// consequences.
fn sms_config_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    enabled: bool,
    allow_factor_downgrade: bool,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "sms_otp.config_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "enabled": enabled,
            "allow_factor_downgrade": allow_factor_downgrade,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The ENVIRONMENT is the subject: successive config changes stay ordered.
        subject: scope.environment().to_string(),
        envelope,
    })
}

/// The event an SMS-OTP allowlist change emits (issue #108).
///
/// ONE type with the country and the direction. An allowlist is a set, and adding to it or
/// removing from it are the same edit in two directions -- a consumer mirroring "where may we
/// send" reads one field rather than correlating two subscriptions.
///
/// The COUNTRY is the payload's reason for existing: this allowlist is what stands between the
/// SMS surface and toll fraud, so a receiver auditing it needs to know WHICH destination
/// changed, not merely that something did.
fn sms_allowlist_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    country_code: &str,
    allowed: bool,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "sms_otp.allowlist_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "country_code": country_code, "allowed": allowed }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The COUNTRY is the subject: two edits to one destination stay ordered.
        subject: country_code.to_owned(),
        envelope,
    })
}
