// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client admin consent pre-authorization management (issue #88, PR 4).
//!
//! The management surface for the third-party admin-consent ESCAPE: set (create or overwrite),
//! get, and delete (revoke) the scope set an admin pre-authorized for a third-party client, keyed
//! on the authorize `client_id`. A pre-authorization is a DATA-plane scoped resource
//! (`client_admin_grants`), reachable by the operator OR by a management key scoped to exactly
//! this environment (the same authorization as the environment reads), exactly like signup forms
//! and locales.
//!
//! A covering pre-authorization SKIPS the user consent screen at the authorization endpoint (the
//! admin grant is the consent of record, the Microsoft model); an uncovered third-party request
//! is refused with a "requires administrator approval" terminal. The pre-authorization is RUNTIME
//! per-environment state (never carried in a config snapshot), so a promoted third-party client
//! stays locked in the target environment until pre-authorized there.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ClientAdminGrantId, ClientId, CorrelationId, NewClientAdminGrant, Scope};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{ClientAdminConsentView, SetClientAdminConsentRequest};

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #88, PR 4). The
/// operator passes; a management key must be scoped to exactly this environment (otherwise the
/// LOUD wrong-scope error). A malformed tenant or environment id is the uniform not-found.
async fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    // Issue #185: the caller's OPERATOR fences the pair. `tenants` and `environments`
    // sit ABOVE row-level security (RLS fences the pair these tables define), so without
    // this a caller naming another operator's tenant reached that tenant's environments
    // and everything under them: measured returning another operator's organization
    // document in full.
    //
    // ADDRESSABILITY, not liveness. A soft-deleted environment must stay readable (see
    // `EnvironmentAccess`), so this asks only whether the pair exists under this
    // operator; whether it is live is each endpoint's own question.
    if !state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .exists_in_any_state(&environment)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::NotFound);
    }
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Normalize the `{client_id}` path parameter to a validated, in-scope client id, or the uniform
/// not-found for a malformed or cross-scope id (a pre-authorization can be keyed only on a client
/// id that belongs to this scope, so anything else names no installable pre-authorization and is a
/// uniform not-found).
fn parse_client_id(raw: &str, scope: Scope) -> Result<String, ApiError> {
    ClientId::parse_in_scope(raw, &scope)
        .map(|id| id.to_string())
        .map_err(|_| ApiError::NotFound)
}

/// The trimmed, non-empty scope from the request, or a loud 400 (an empty pre-authorization
/// pre-authorizes nothing and is meaningless).
fn parse_scope(request: &SetClientAdminConsentRequest) -> Result<String, ApiError> {
    let scope = request.scope.trim();
    if scope.is_empty() {
        return Err(ApiError::BadRequest(
            "an admin consent pre-authorization must name a non-empty scope".to_string(),
        ));
    }
    Ok(scope.to_string())
}

/// Set (create or overwrite) a per-environment, per-client admin consent pre-authorization.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
    operation_id = "setClientAdminConsent",
    tag = "client-admin-consent",
    request_body = SetClientAdminConsentRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier the pre-authorization governs")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Set", body = ClientAdminConsentView),
        (status = 400, description = "An empty scope", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found or malformed client id", body = ErrorBody)
    )
)]
pub async fn set_client_admin_consent(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // An admin consent pre-authorization changes WHICH third-party client can obtain user consent,
    // a security-relevant config surface, so it demands fresh privilege exactly like the other
    // environment-scoped management writes (signup forms, locales, connectors).
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let client_id = parse_client_id(&client_id, scope)?;

    // The environment must exist (a clean 404 rather than a foreign-key error).
    // This used to be an inline copy of the two-line read. It is the shared
    // [`crate::org_context::require_live_environment`] now (issue #443): one expression
    // of one precondition, so a change to what LIVENESS means has one place to change.
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: SetClientAdminConsentRequest = parse_json(&body)?;
    let scope_value = parse_scope(&request)?;
    let granted_by = actor.id_string();

    let created_at_micros = state.now_unix_micros();
    let id = ClientAdminGrantId::generate(state.env(), &scope);
    let pending = admin_consent_granted_event(&state, scope, &client_id, &scope_value);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .client_admin_grants()
        .set_with_event(
            state.env(),
            &id,
            created_at_micros,
            NewClientAdminGrant {
                client_id: &client_id,
                granted_scope: Some(&scope_value),
                granted_by: &granted_by,
            },
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;

    let view = ClientAdminConsentView {
        client_id,
        scope: scope_value,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get a per-environment, per-client admin consent pre-authorization.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
    operation_id = "getClientAdminConsent",
    tag = "client-admin-consent",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier the pre-authorization governs")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The admin consent pre-authorization", body = ClientAdminConsentView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_client_admin_consent(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let client_id = parse_client_id(&client_id, scope)?;
    let record = state
        .store()
        .scoped(scope)
        .client_admin_grants()
        .get(&client_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let view = ClientAdminConsentView {
        client_id: record.client_id,
        scope: record.granted_scope.unwrap_or_default(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Delete (revoke) a per-environment, per-client admin consent pre-authorization.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
    operation_id = "deleteClientAdminConsent",
    tag = "client-admin-consent",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The authorize client identifier the pre-authorization governs")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn delete_client_admin_consent(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // The parent-existence precondition, through the ONE expression of it (issues #443,
    // #451). A `client_admin_grants` row survives its
    // environment's soft delete, so the read below still resolved and the revoke landed
    // inside a decommissioned environment. The SET next door already refused, which made
    // this the two-answers-to-one-question shape issue #451 is about.
    crate::org_context::require_live_environment(&state, &scope).await?;
    let client_id = parse_client_id(&client_id, scope)?;
    // Resolve the stored id by client (a uniform not-found when absent), then delete by id so the
    // audit row names the immutable pre-authorization id.
    let record = state
        .store()
        .scoped(scope)
        .client_admin_grants()
        .get(&client_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let id =
        ClientAdminGrantId::parse_in_scope(&record.id, &scope).map_err(|_| ApiError::NotFound)?;
    let pending = admin_consent_revoked_event(&state, scope, &id, &client_id);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .client_admin_grants()
        .delete_with_event(
            state.env(),
            &id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The event an admin-consent revocation emits (issue #108).
///
/// The client id rides along because the pre-authorization is per-client and that is what an
/// operator revoked; the grant's own id is an internal handle they never type.
fn admin_consent_revoked_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    grant_id: &ClientAdminGrantId,
    client_id: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = grant_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "admin_consent.revoked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "client_admin_grant_id": subject,
            "client_id": client_id,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The CLIENT is the ordering key, not the grant. A set REUSES the existing row's id
        // inside the write, so keying on the grant would put a grant and the revoke that
        // follows it on different keys, and a consumer could be told of the revocation of a
        // pre-authorization it had never been told about.
        subject: client_id.to_owned(),
        envelope,
    })
}

/// The event an admin-consent GRANT emits (issue #108), the counterpart of
/// [`admin_consent_revoked_event`].
///
/// No grant id, and the asymmetry with the revoke is deliberate. A set is an upsert that
/// reuses the EXISTING row's id, resolved inside the write, so this producer holds only the
/// id it minted -- the row id on a first write and a stale invention on an overwrite. The
/// client is what an operator addressed, and what identifies the pre-authorization.
fn admin_consent_granted_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    client_id: &str,
    granted_scope: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "admin_consent.granted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "client_id": client_id,
            "granted_scope": granted_scope,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: client_id.to_owned(),
        envelope,
    })
}
