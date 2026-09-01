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
    AgentPrincipalId, AgentVaultConnectionId, ClientId, CorrelationId, NewAgent,
    NewVaultConnection, ResolvedIdempotencyWrite, StoreError, UserId,
};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{
    AgentList, AgentView, RegisterAgentRequest, SetAgentStateRequest, StoreVaultConnectionRequest,
    VaultConnectionView,
};

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
#[allow(
    clippy::too_many_lines,
    reason = "one line over the pedantic bound. The body is the registration in order: \
    resolve the live organization, check the linked user is in it, parse and bound the \
    declared tool set, insert, audit. Splitting it would separate the membership check \
    from the insert it gates, which is the seam that must not be easy to skip"
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

    // A named client must EXIST in this scope. The schema's composite key would refuse a
    // cross-scope or absent one anyway, but that arrives as a 23503 inside the write, which
    // renders as a 500; the caller deserves the uniform not-found instead.
    let client_id = match &request.client_id {
        Some(raw) => {
            let parsed = ClientId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)?;
            state.store().scoped(scope).clients().get(&parsed).await?;
            Some(parsed.to_string())
        }
        None => None,
    };

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
        // Attribute the audit row to this organization (issue #110) AND to the person the
        // agent will act for (issue #130, criterion 2). Both, at all four agent write sites:
        // an earlier version set only the organization here and on `set_state`, so two of the
        // four actions carried no subject and `docs/agents.md`'s "every one of the four" was
        // false for exactly the two an operator performs by hand.
        .in_organization(org_id)
        .about_subject(linked_user_id)
        .agents(scope)
        .register(
            state.env(),
            NewAgent {
                id: &agent_id,
                organization_id: &org_id,
                linked_user_id: &linked_user_id,
                display_name: &display_name,
                client_id: client_id.as_deref(),
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
        // The person the agent acts for, read off the record this handler already fetched to
        // enforce the organization nesting.
        .about_subject(existing.linked_user_id)
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

/// Store the downstream credential an agent exchanges its IronAuth token for (issue #132).
///
/// THE GRANTING PATH. Without it the vault is unreachable: `store_connection` had no
/// production caller at all, so every exchange answered "this agent has no connection for
/// that provider" forever and criterion 1 could not hold in any real deployment. This is the
/// repo's dominant defect class -- the enforcement ships, the way to turn it on does not --
/// and it is worth naming here so the next surface does not repeat it.
///
/// The credential arrives in PLAINTEXT and is sealed before it is written. Three checks run
/// before it is accepted, in this order, and each refuses with the uniform not-found rather
/// than a distinguishing error:
///
///   1. the organization must be live and the caller must reach it (`resolve_live_org`), and
///      an unreachable one is the uniform not-found;
///   2. the agent must belong to THAT organization, also the uniform not-found, so an agent
///      of a sibling organization presented under this path cannot be given a credential;
///   3. the provider must be shaped as the column requires and must be inside the agent's
///      DECLARED tool set. This one is a 400 NAMING the provider, not a not-found: the caller
///      is an authenticated operator who has already been shown the agent, so there is
///      nothing left to withhold and telling them which tool is undeclared is the difference
///      between a fixable error and a guess. An agent that never
///      declared `google` cannot be handed a Google credential, because the exchange would
///      refuse to hand it back and the row would be a third-party secret nobody can reach --
///      stored, sealed, and permanently orphaned.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/agents/{agent_id}/vault-connections",
    operation_id = "storeAgentVaultConnection",
    tag = "organizations",
    request_body = StoreVaultConnectionRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("agent_id" = String, Path, description = "The agent identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The stored connection, carrying no secret", body = VaultConnectionView),
        (status = 400, description = "A malformed body, a blank token, or a provider outside the agent's declared set", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or a lapsed sudo elevation", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found, or another organization's agent", body = ErrorBody)
    )
)]
pub async fn store_agent_vault_connection(
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
    // Handing an agent a live third-party credential is at least as privileged as changing
    // its lifecycle state, which already requires this.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    let agents = state.store().scoped(scope).agents();
    let id = agents.parse_id(&agent_id)?;
    let agent = agents.get(&id).await?;
    if agent.organization_id != org_id {
        return Err(ApiError::NotFound);
    }

    let request: StoreVaultConnectionRequest = parse_json(&body)?;
    let provider = require_non_empty(&request.provider, "provider")?;
    let access_token = require_non_empty(&request.access_token, "access_token")?;
    // The SHAPE the column accepts, checked HERE rather than left to the schema.
    //
    // `0178`'s `agent_vault_connections_provider_shaped` requires a lowercase identifier, and
    // an agent's declared tool set does not: registration checks only that each entry is
    // non-blank, so an agent may legitimately declare `Google` or `mail.read`. Passing one of
    // those through would violate the CHECK, surface as a 23514, and render as a 500 -- an
    // operator error reported as a server fault. The store's own `mark_failed` truncates at
    // the edge for exactly this reason two functions away.
    if !provider_is_shaped(&provider) {
        return Err(ApiError::BadRequest(
            "provider must be a lowercase identifier: only a-z, 0-9, `_` and `-`, starting with a letter or digit, at most 64 characters"
                .to_owned(),
        ));
    }
    if !agent.declares_tool(&provider) {
        return Err(ApiError::BadRequest(format!(
            "the agent has not declared the tool {provider}, so it could never exchange for \
             this credential"
        )));
    }
    let refresh_token = match request.refresh_token.as_deref() {
        Some(value) => Some(require_non_empty(value, "refresh_token")?),
        None => None,
    };
    let refresh_token = refresh_token.as_deref();

    // The instant, guarded against BOTH ways it can be unrepresentable: the i64 multiply, and
    // the range Postgres can actually store. `checked_mul` alone left roughly a billion
    // accepted second values (and a far wider negative band) that multiply cleanly and then
    // raise 22008 at `TIMESTAMPTZ 'epoch' + interval`, which renders as a 500 -- an operator's
    // bad request reported as a server fault, which is what the check was added to stop.
    let expires_at_micros = match request.expires_at {
        None => None,
        Some(seconds) => Some(
            seconds
                .checked_mul(1_000_000)
                .filter(|micros| (MIN_STORABLE_MICROS..=MAX_STORABLE_MICROS).contains(micros))
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "expires_at is outside the range of instants that can be stored".to_owned(),
                    )
                })?,
        ),
    };

    // A fresh id, which the upsert uses only when there is no existing row: it upserts on
    // (agent, provider) and does NOT update `id`, so a re-store keeps the row's original id.
    // The AUTHORITATIVE id comes back from the write, not from here.
    let connection_id = AgentVaultConnectionId::generate(state.env(), &scope);
    // The event names the AGENT, the ORGANIZATION and the PROVIDER, and no connection id.
    // (agent, provider) is the connection's identity -- it is the upsert key -- so the id is
    // redundant here and carrying it would mean building the event before the write knows
    // which id the row has.
    let pending = vault_connection_event(&state, scope, &id, &org_id, &provider);
    // The CONTROL store: writes to the vault are control-plane, and the data-plane role holds
    // no INSERT on this table.
    let stored_id = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .agent_vault(scope)
        .store_connection_with_event(
            state.env(),
            NewVaultConnection {
                id: &connection_id,
                agent_id: &id,
                provider: &provider,
                access_token: &access_token,
                refresh_token,
                granted_scopes: &request.granted_scopes,
                expires_at_unix_micros: expires_at_micros,
            },
            state.now_unix_micros(),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;

    // Built from what was WRITTEN rather than read back, deliberately. A read-back would
    // have to open the sealed columns to return a view that carries no secret, which is a
    // decryption performed only to throw the plaintext away. `store_connection` replaces any
    // existing row for this (agent, provider) and returns it to `active`, so these are the
    // values the row now holds.
    //
    // The view carries NO SECRET, which is the property that matters here: there is no field
    // on `VaultConnectionView` for a token, so one cannot be added without somebody writing
    // it into a struct whose name says it is what the operator sees.
    //
    // Deliberately NOT claiming `no-store`. An earlier version of this comment did, and the
    // response does not carry that header: `crate::response::json` sets `Content-Type` only,
    // and the server's backstop deliberately imposes no cache directive. The body has nothing
    // worth caching, so this is a corrected sentence rather than a missing header -- but a
    // comment asserting a header that is not sent is how the next reader stops checking.
    let body_string = serde_json::to_string(&VaultConnectionView {
        // The id the ROW has, returned by the write. Minting one and reporting it was the
        // defect: on a re-store the row keeps its first id, so the operator was handed one
        // nothing could address and a later `mark_failed` on it would answer not-found.
        id: stored_id.to_string(),
        agent_id: id.to_string(),
        provider,
        granted_scopes: request.granted_scopes,
        state: "active".to_owned(),
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// The earliest instant a `timestamptz` can hold, in microseconds since the Unix epoch.
///
/// Postgres stores a timestamp as microseconds from 2000-01-01, so the representable range is
/// that i64 window shifted by the 946 684 800 seconds between the two epochs. BOTH ends are
/// named here rather than checking only the multiply, because a multiply succeeding says
/// nothing about the database being able to store what it produced.
const MIN_STORABLE_MICROS: i64 = i64::MIN + 946_684_800_000_000;

/// The latest instant a `timestamptz` can hold, in microseconds since the Unix epoch.
const MAX_STORABLE_MICROS: i64 = i64::MAX - 946_684_800_000_000;

/// Whether `provider` matches the shape migration 0178's CHECK constraint requires.
///
/// The SAME rule, written once in each language because the schema cannot validate a request
/// before it reaches the database and the handler cannot enforce a column constraint. They
/// are pinned together by `the_route_and_the_schema_agree_on_what_a_provider_looks_like`.
fn provider_is_shaped(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 64
        && provider
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && provider
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// The event storing a downstream vault connection emits (issue #132).
///
/// Names the connection, the agent, the organization and the PROVIDER, and no part of the
/// credential: an event carrying the secret would put it in every integrator's stream, which
/// is the opposite of what sealing it at rest is for.
fn vault_connection_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    agent_id: &AgentPrincipalId,
    organization_id: &ironauth_store::OrganizationId,
    provider: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = agent_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "agent.vault_connection_stored",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "agent_id": subject,
            "organization_id": organization_id.to_string(),
            "provider": provider,
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

#[cfg(test)]
mod tests {
    use super::provider_is_shaped;

    /// The route's provider check and the SCHEMA's agree on what a provider looks like.
    ///
    /// Two implementations of one rule, in two languages, which is exactly the situation a
    /// review found broken: the route accepted anything non-blank and the column requires a
    /// lowercase identifier, so `Google` reached the database, violated the CHECK, and
    /// surfaced as a 500. Pinning them together is the only thing that keeps the two honest,
    /// and the migration is frozen so the Rust is the half that can move.
    ///
    /// The regex is read FROM the migration rather than restated here, so a future edit to
    /// either side fails this rather than passing against a copy of itself.
    #[test]
    fn the_route_and_the_schema_agree_on_what_a_provider_looks_like() {
        const MIGRATION: &str =
            include_str!("../../ironauth-store/migrations/0178_agent_token_vault.sql");
        assert!(
            MIGRATION.contains("provider ~ '^[a-z0-9][a-z0-9_-]*$'"),
            "the schema's shape rule moved; the route's copy of it below has to move too"
        );
        assert!(
            MIGRATION.contains("char_length(provider) <= 64"),
            "the schema's length bound moved"
        );

        for accepted in [
            "google",
            "github",
            "slack",
            "g",
            "0",
            "a_b-c",
            &"a".repeat(64),
        ] {
            assert!(
                provider_is_shaped(accepted),
                "the schema accepts {accepted:?}, so the route must too"
            );
        }
        for refused in [
            "",              // empty
            "Google",        // uppercase
            "mail.read",     // a dot, which a tool scope may legitimately contain
            "slack api",     // a space
            "_leading",      // the schema requires a leading alnum
            "-leading",      //
            &"a".repeat(65), // over the length bound
        ] {
            assert!(
                !provider_is_shaped(refused),
                "the schema refuses {refused:?}, so the route must refuse it FIRST: reaching \
                 the column turns an operator's bad request into a 500"
            );
        }
    }
}
