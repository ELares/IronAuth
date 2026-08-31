// SPDX-License-Identifier: MIT OR Apache-2.0

//! Agent principals: register, list, and set lifecycle state (issue #130).
//!
//! An agent is a first-class principal, not a user with a label or a service account with a
//! note. It acts FOR a person, INSIDE an organization, with a DECLARED and bounded set of
//! tools -- and every endpoint here exists because one of those three is something an operator
//! has to be able to see or change.
//!
//! Nested under an organization throughout. That is the boundary criterion 4 asks for: an org
//! admin listing "the agents acting for my organization" is asking a question the scope and
//! the nesting answer together, not filtering a global list and hoping.
//!
//! # Why the list shows suspended and revoked agents
//!
//! Criterion 5 asks that a suspended agent obtain no tokens and REMAIN listable and auditable.
//! A surface that hid them would answer the operator's question ("what can act here?") and
//! destroy the investigator's ("what WAS acting here, and who turned it off?"). So the state
//! is a column in the view rather than a filter on the query.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    AgentPrincipalId, CorrelationId, NewAgent, ResolvedIdempotencyWrite, StoreError, UserId,
};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{AgentList, AgentView, RegisterAgentRequest, SetAgentStateRequest};

/// The states an operator may set. `revoked` is terminal; the store refuses to move out of it.
const SETTABLE_STATES: [&str; 3] = ["active", "suspended", "revoked"];

/// Register an agent inside an organization.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/agents",
    operation_id = "registerAgent",
    tag = "organizations",
    request_body = RegisterAgentRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Registered", body = AgentView),
        (status = 400, description = "Malformed request, or a tool set that is empty or oversized", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization or linked user not found. The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn register_agent(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    // Registering an agent creates a principal that acts with a person's authority, which is
    // squarely the class of change sudo mode exists for.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    let request: RegisterAgentRequest = parse_json(&body)?;
    // The linked user must exist in THIS scope. Checked up front so an absent user is a clean
    // 404 rather than a foreign-key 500, and because an agent linked to nobody is the
    // unattributable principal this whole issue exists to prevent.
    let linked_user_id =
        UserId::parse_in_scope(&request.linked_user_id, &scope).map_err(|_| ApiError::NotFound)?;
    state
        .store()
        .scoped(scope)
        .users()
        .get(&linked_user_id)
        .await?;

    // The schema bounds `display_name` at 1..=200 characters. Validated HERE too, because a
    // CHECK violation inside the write transaction is SQLSTATE 23514, which is not a unique
    // violation and so renders as a 500: a caller-controlled 500 is a defect, not a refusal.
    // Every other handler with a display_name uses this same edge validator.
    let display_name = require_non_empty(&request.display_name, "display_name")?;
    if display_name.chars().count() > 200 {
        return Err(ApiError::BadRequest(
            "display_name must be at most 200 characters".to_owned(),
        ));
    }

    // AN EMPTY TOOL SET IS REFUSED, rather than registered as an agent that can do nothing.
    // The schema permits it (an empty array is a valid bound), so the refusal lives here: an
    // agent with no declared tools is almost always a caller that forgot the field, and
    // registering it silently produces a principal whose every request will be denied with no
    // hint as to why.
    if request.tool_scopes.is_empty() {
        return Err(ApiError::BadRequest(
            "tool_scopes must declare at least one tool".to_owned(),
        ));
    }
    if request.tool_scopes.len() > 64 {
        return Err(ApiError::BadRequest(
            "tool_scopes may declare at most 64 tools".to_owned(),
        ));
    }
    if request
        .tool_scopes
        .iter()
        .any(|tool| tool.trim().is_empty())
    {
        return Err(ApiError::BadRequest(
            "a declared tool must not be blank".to_owned(),
        ));
    }

    let created_at_micros = state.now_unix_micros();
    let agent_id = AgentPrincipalId::generate(state.env(), &scope);
    let pending = agent_registered_event(&state, scope, &agent_id, &org_id, &linked_user_id);

    // ONE renderer for the 201 and for the stored idempotency record, so a replay serves the
    // same bytes as the original.
    let render = |record: &ironauth_store::AgentRecord| {
        serde_json::to_string(&AgentView::from_record(record.clone()))
    };
    let write = ResolvedIdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &render,
    };

    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .agents(scope)
        .register(
            state.env(),
            NewAgent {
                id: &agent_id,
                organization_id: &org_id,
                linked_user_id: &linked_user_id,
                display_name: &display_name,
                tool_scopes: &request.tool_scopes,
            },
            created_at_micros,
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(record) => {
            let body_string = render(&record).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::CREATED, body_string))
        }
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List the agents acting inside an organization.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/agents",
    operation_id = "listAgents",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        // The whole ListQuery, not a hand-written `limit`: the handler honours `cursor` and
        // the response returns `next_cursor`, so documenting only `limit` leaves a typed
        // client holding a cursor with no field to send it back in, and page 2 unreachable
        // through the published contract.
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The agents acting inside this organization, oldest first. INCLUDES suspended and revoked ones: an investigator's question is what WAS acting here", body = AgentList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization not found, or the environment is absent or soft-deleted", body = ErrorBody)
    )
)]
pub async fn list_agents(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    // The shared pagination parser owns the bounds; a private clamp here would be a second
    // definition of the page size this deployment allows.
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .agents()
        .list_for_organization(&org_id, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = AgentList {
        items: rows.into_iter().map(AgentView::from_record).collect(),
        next_cursor,
    };
    let body_string = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Set an agent's lifecycle state.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/agents/{agent_id}/state",
    operation_id = "setAgentState",
    tag = "organizations",
    request_body = SetAgentStateRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("agent_id" = String, Path, description = "The agent identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The stored state", body = AgentView),
        (status = 400, description = "A state outside the closed set", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or a lapsed sudo elevation", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found, another organization's agent, or already revoked (revocation is terminal)", body = ErrorBody)
    )
)]
pub async fn set_agent_state(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, agent_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    // Suspending or revoking an agent is what an incident responder reaches for, and
    // RE-ACTIVATING one restores authority: both directions are privileged.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    // Address the target FIRST, and enforce the NESTING: an agent of a different organization
    // presented under this one's path is the uniform not-found, so a wrong-org path can never
    // revoke another organization's agent.
    let agents = state.store().scoped(scope).agents();
    let id = agents.parse_id(&agent_id)?;
    let existing = agents.get(&id).await?;
    if existing.organization_id != org_id {
        return Err(ApiError::NotFound);
    }

    let request: SetAgentStateRequest = parse_json(&body)?;
    if !SETTABLE_STATES.contains(&request.state.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "state must be one of {}",
            SETTABLE_STATES.join(" | ")
        )));
    }

    let pending = agent_state_event(&state, scope, &id, &org_id, &request.state);
    let record = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .agents(scope)
        .set_state(
            state.env(),
            &id,
            &request.state,
            state.now_unix_micros(),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            // Already revoked: the store refuses to move out of the terminal state, and the
            // caller is told the same thing it would be told about an agent that is not
            // there. Both mean "this agent will not be changing".
            StoreError::NotFound => ApiError::NotFound,
            other => other.into(),
        })?;

    let body_string =
        serde_json::to_string(&AgentView::from_record(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// The event an agent registration emits (issue #130).
fn agent_registered_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    agent_id: &AgentPrincipalId,
    organization_id: &ironauth_store::OrganizationId,
    linked_user_id: &UserId,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = agent_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "agent.registered",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "agent_id": subject,
            "organization_id": organization_id.to_string(),
            "linked_user_id": linked_user_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event an agent lifecycle change emits (issue #130).
fn agent_state_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    agent_id: &AgentPrincipalId,
    organization_id: &ironauth_store::OrganizationId,
    new_state: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = agent_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "agent.state_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "agent_id": subject,
            "organization_id": organization_id.to_string(),
            "state": new_state,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
