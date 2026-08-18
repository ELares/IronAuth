// SPDX-License-Identifier: MIT OR Apache-2.0

//! Declarative federation connector management (issue #75, PR A).
//!
//! The management surface for the declarative inbound-federation connectors: create
//! (parse and STRICTLY validate the definition, seal the upstream client secret, and
//! write the capability matrix), list, get, update, delete, and a capability-matrix
//! READ endpoint. A connector is a DATA-plane scoped resource (`connectors`), so these
//! route through the control-plane store's scoped repositories (the control role owns
//! the connector lifecycle and, per issue #37, holds the KEK/DEK grants to seal the
//! secret inline).
//!
//! The definition is parsed with the pure, I/O-free `ironauth-connector` crate: phase
//! one is serde with `deny_unknown_fields` (an unknown key is a 400), phase two is the
//! semantic validator (a fault is a 400 carrying its RFC 6901 JSON POINTER). The
//! upstream client SECRET is resolved and sealed at rest; it is NEVER returned by a
//! read and NEVER appears in the stored definition or a config snapshot.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_connector::ConnectorDefinition;
use ironauth_store::{
    ConnectorId, ConnectorRecord, CorrelationId, IdempotencyWrite, NewConnector, Scope, StoreError,
    TenantId, TraitSchema,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{
    ConnectorCapabilitiesView, ConnectorHealthView, ConnectorList, ConnectorView,
    CreateConnectorRequest,
};

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids through
/// the management repositories (a malformed id is the uniform not-found).
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(TenantId, Scope), ApiError> {
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
    Ok((tenant, Scope::new(tenant, environment)))
}

/// Parse the request body into a connector definition and STRICTLY validate it. Phase
/// one (serde `deny_unknown_fields`) and phase two (the semantic validator's JSON
/// pointer errors) both surface as a 400 the caller can act on.
fn parse_and_validate(body: &Bytes) -> Result<ConnectorDefinition, ApiError> {
    let definition: ConnectorDefinition = serde_json::from_slice(body).map_err(|error| {
        ApiError::BadRequest(format!("malformed connector definition: {error}"))
    })?;
    if let Err(violations) = definition.validate() {
        // Enumerate every violation with its JSON pointer, so the caller learns all
        // faults at once (the strict-config, pointer-error contract).
        let detail = violations
            .iter()
            .map(|violation| format!("{}: {}", violation.pointer, violation.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ApiError::BadRequest(format!(
            "invalid connector definition: {detail}"
        )));
    }
    Ok(definition)
}

/// Refuse a claim mapping that TARGETS an admin-only trait, at CONFIG time (issue #53).
///
/// A connector's claim mapping is the other configuration surface that can name a trait, and
/// it had NO admin-only gate at all: `grep -rn "is_admin_only|admin_only|visibility"` over
/// `ironauth-connector` and this file returned nothing. MEASURED consequence: a mapping
/// naming an admin-only trait let an upstream identity provider WRITE admin-only metadata
/// onto a local identity on first login. The store's self-service write class refuses that
/// now, but a login-time refusal breaks the END USER for a fault only the operator can fix,
/// so the refusal belongs here, exactly where `validate_signup_form` puts the same refusal
/// for the other trait-naming surface.
///
/// Deterministic and per field: every offending trait is named at once, each as the JSON
/// pointer into the DEFINITION (`/claim_mapping/traits/<field>`) that the operator edits, so
/// the message is actionable and value-free.
///
/// A scope with no active trait schema declares no annotations, so nothing can be admin-only
/// and there is nothing to refuse; a mapping that produces traits against no active schema
/// already fails closed in the evaluator.
async fn refuse_admin_only_claim_mapping(
    state: &AdminState,
    scope: Scope,
    definition: &ConnectorDefinition,
) -> Result<(), ApiError> {
    if definition.claim_mapping.traits.is_empty() {
        return Ok(());
    }
    let Some(active) = state.store().scoped(scope).trait_schemas().active().await? else {
        return Ok(());
    };
    // A STORED schema is proved well formed on write, so a compile fault is a persistence
    // corruption and never a caller fault.
    let schema = TraitSchema::compile(&active.schema_json).map_err(|_| ApiError::Internal)?;
    let annotations = schema.annotations();
    let offending: Vec<String> = definition
        .claim_mapping
        .traits
        .keys()
        .filter(|field| annotations.is_admin_only(field))
        .map(|field| format!("/claim_mapping/traits/{field}"))
        .collect();
    if offending.is_empty() {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "the claim mapping targets an admin-only trait, which an upstream identity provider \
         must never be a channel into: {}",
        offending.join(", ")
    )))
}

/// Resolve the definition's upstream client secret to its plaintext bytes for sealing.
/// A file/env indirection that cannot be read is an operator configuration error (a
/// 400 naming only the source, never the value).
fn resolve_client_secret(definition: &ConnectorDefinition) -> Result<Vec<u8>, ApiError> {
    let resolved = definition
        .client_secret()
        .resolve()
        .map_err(|error| ApiError::BadRequest(format!("cannot read the client secret: {error}")))?;
    Ok(resolved.expose().as_bytes().to_vec())
}

/// Build the API view of a stored connector record. SECRET-FREE: the sealed secret is
/// never part of the record.
fn view_of(record: &ConnectorRecord) -> Result<ConnectorView, ApiError> {
    let definition: serde_json::Value =
        serde_json::from_str(&record.definition_json).map_err(|_| ApiError::Internal)?;
    Ok(ConnectorView {
        id: record.id.to_string(),
        connector_slug: record.slug.clone(),
        definition,
        enabled: record.enabled,
        capabilities: ConnectorCapabilitiesView {
            refresh: record.capabilities.refresh,
            groups: record.capabilities.groups,
            logout_propagation: record.capabilities.logout_propagation,
            email_verified_trust: record.capabilities.email_verified_trust.clone(),
        },
        created_at_unix_ms: record.created_at_unix_micros / 1000,
        updated_at_unix_ms: record.updated_at_unix_micros / 1000,
    })
}

/// Create a declarative federation connector.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
    operation_id = "createConnector",
    tag = "connectors",
    request_body = CreateConnectorRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = ConnectorView),
        (status = 400, description = "Malformed or invalid definition (JSON-pointer error), \
         including a claim mapping that targets an admin-only trait", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 409, description = "A connector with this slug already exists", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_connector(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Sudo mutation gate (issue #73): writing a connector is an environment-scoped
    // mutation. Gate before the idempotency replay so a challenge writes nothing.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let definition = parse_and_validate(&body)?;
    // The trait-visibility gate (issue #53), at CONFIG time, before anything is written.
    refuse_admin_only_claim_mapping(&state, scope, &definition).await?;
    let secret = resolve_client_secret(&definition)?;
    let projection = definition
        .secret_free_json()
        .map_err(|_| ApiError::Internal)?;
    let definition_json = serde_json::to_string(&projection).map_err(|_| ApiError::Internal)?;
    let capabilities = definition.capabilities();

    // The environment must exist (a clean 404 rather than a foreign-key error).
    // This used to be an inline copy of the two-line read. It is the shared
    // [`crate::org_context::require_live_environment`] now (issue #443): one expression
    // of one precondition, so a change to what LIVENESS means has one place to change.
    crate::org_context::require_live_environment(&state, &scope).await?;

    let created_at_micros = state.now_unix_micros();
    let id = ConnectorId::generate(state.env(), &scope);
    let record = ConnectorRecord {
        id,
        slug: definition.connector_id.clone(),
        definition_json: definition_json.clone(),
        capabilities: ironauth_store::StoredCapabilities {
            refresh: capabilities.refresh,
            groups: capabilities.groups,
            logout_propagation: capabilities.logout_propagation,
            email_verified_trust: capabilities.email_verified_trust.as_str().to_owned(),
        },
        enabled: definition.enabled,
        created_at_unix_micros: created_at_micros,
        updated_at_unix_micros: created_at_micros,
    };
    let view = view_of(&record)?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let pending = connector_event(
        &state,
        scope,
        &id,
        &definition.connector_id,
        "connector.created",
    );
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .connectors()
        .create_with_event(
            state.env(),
            &id,
            created_at_micros,
            NewConnector {
                slug: &definition.connector_id,
                definition_json: &definition_json,
                client_secret: &secret,
                capabilities: ironauth_store::ConnectorCapabilities {
                    refresh: capabilities.refresh,
                    groups: capabilities.groups,
                    logout_propagation: capabilities.logout_propagation,
                    email_verified_trust: capabilities.email_verified_trust.as_str(),
                },
                enabled: definition.enabled,
            },
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a connector with this slug already exists in this environment".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List federation connectors in an environment (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
    operation_id = "listConnectors",
    tag = "connectors",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of connectors", body = ConnectorList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_connectors(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .connectors()
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let items = rows.iter().map(view_of).collect::<Result<Vec<_>, _>>()?;
    let list = ConnectorList { items, next_cursor };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get a federation connector's secret-free definition and capability matrix.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
    operation_id = "getConnector",
    tag = "connectors",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("connector_id" = String, Path, description = "The connector identifier (cnr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The connector (secret-free)", body = ConnectorView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_connector(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, connector_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let connectors = state.store().scoped(scope).connectors();
    let id = connectors.parse_id(&connector_id)?;
    let record = connectors.get(&id).await?;
    let view = view_of(&record)?;
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get a federation connector's capability matrix (issue #75). SECRET-FREE: the
/// upstream client secret is never returned.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/capabilities",
    operation_id = "getConnectorCapabilities",
    tag = "connectors",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("connector_id" = String, Path, description = "The connector identifier (cnr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The capability matrix", body = ConnectorCapabilitiesView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_connector_capabilities(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, connector_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let connectors = state.store().scoped(scope).connectors();
    let id = connectors.parse_id(&connector_id)?;
    let record = connectors.get(&id).await?;
    let view = ConnectorCapabilitiesView {
        refresh: record.capabilities.refresh,
        groups: record.capabilities.groups,
        logout_propagation: record.capabilities.logout_propagation,
        email_verified_trust: record.capabilities.email_verified_trust,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get a federation connector's live health for admin diagnostics (issue #76). Reports
/// THIS node's in-memory federation health for the connector: its health state, recent
/// upstream error rate, last success / failure, and backoff retry instant. A connector that
/// exists but has never been exercised on this node (or when federation is not installed here)
/// reports `state = "unknown"`. SECRET-FREE.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/health",
    operation_id = "getConnectorHealth",
    tag = "connectors",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("connector_id" = String, Path, description = "The connector identifier (cnr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The connector's live health", body = ConnectorHealthView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_connector_health(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, connector_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let connectors = state.store().scoped(scope).connectors();
    let id = connectors.parse_id(&connector_id)?;
    // Confirm the connector EXISTS in this scope (a uniform not-found otherwise), so the
    // health read is not an oracle for arbitrary ids. Its `updated_at` is the definition
    // fingerprint the health read discounts a stale (pre-reconfiguration) record against.
    let record = connectors.get(&id).await?;
    let key = id.to_string();
    let view = match state.connector_health(&key, record.updated_at_unix_micros) {
        Some(snapshot) => ConnectorHealthView {
            id: key,
            state: snapshot.state.as_str().to_owned(),
            last_error_kind: snapshot.last_error_kind.map(str::to_owned),
            consecutive_failures: snapshot.consecutive_failures,
            last_success_at_unix_ms: snapshot.last_success_at.map(unix_ms),
            last_failure_at_unix_ms: snapshot.last_failure_at.map(unix_ms),
            next_retry_at_unix_ms: snapshot.next_retry_at.map(unix_ms),
            recent_error_rate: snapshot.recent_error_rate,
            success_total: snapshot.success_total,
            error_total: snapshot.error_total,
        },
        None => ConnectorHealthView {
            id: key,
            state: "unknown".to_owned(),
            last_error_kind: None,
            consecutive_failures: 0,
            last_success_at_unix_ms: None,
            last_failure_at_unix_ms: None,
            next_retry_at_unix_ms: None,
            recent_error_rate: 0.0,
            success_total: 0,
            error_total: 0,
        },
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Milliseconds since the Unix epoch for a wall-clock instant (issue #76), saturating.
fn unix_ms(at: std::time::SystemTime) -> i64 {
    match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Update (replace) a federation connector definition.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
    operation_id = "updateConnector",
    tag = "connectors",
    request_body = CreateConnectorRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("connector_id" = String, Path, description = "The connector identifier (cnr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Updated", body = ConnectorView),
        (status = 400, description = "Malformed or invalid definition (JSON-pointer error), \
         including a claim mapping that targets an admin-only trait", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn update_connector(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, connector_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // The parent-existence precondition, through the ONE expression of it (issues #443,
    // #451). A `connectors` row survives its
    // environment's soft delete, so the update landed inside a decommissioned environment
    // (MEASURED: 200) while the CREATE next door refused.
    crate::org_context::require_live_environment(&state, &scope).await?;
    let id = state
        .store()
        .scoped(scope)
        .connectors()
        .parse_id(&connector_id)?;

    let definition = parse_and_validate(&body)?;
    // The SAME config-time trait-visibility gate the create makes (issue #53). An update is
    // the other way a mapping enters the store, so a gate on only one of them would read as
    // enforced while the update walked around it.
    refuse_admin_only_claim_mapping(&state, scope, &definition).await?;

    // The slug is the IMMUTABLE natural key (and the anchor the sealed-secret AAD is
    // bound to on the store's immutable id): it cannot be changed via an update. A body
    // whose `connector_id` differs from the stored slug is rejected outright, before any
    // mutation, so the stored slug and the definition's `connector_id` can never diverge.
    let stored = state.store().scoped(scope).connectors().get(&id).await?;
    if definition.connector_id != stored.slug {
        return Err(ApiError::Conflict(
            "the connector slug is immutable and cannot be changed on update".to_owned(),
        ));
    }

    let secret = resolve_client_secret(&definition)?;
    let projection = definition
        .secret_free_json()
        .map_err(|_| ApiError::Internal)?;
    let definition_json = serde_json::to_string(&projection).map_err(|_| ApiError::Internal)?;
    let capabilities = definition.capabilities();

    let pending = connector_event(
        &state,
        scope,
        &id,
        &definition.connector_id,
        "connector.updated",
    );
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .connectors()
        .update_with_event(
            state.env(),
            &id,
            NewConnector {
                slug: &definition.connector_id,
                definition_json: &definition_json,
                client_secret: &secret,
                capabilities: ironauth_store::ConnectorCapabilities {
                    refresh: capabilities.refresh,
                    groups: capabilities.groups,
                    logout_propagation: capabilities.logout_propagation,
                    email_verified_trust: capabilities.email_verified_trust.as_str(),
                },
                enabled: definition.enabled,
            },
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;

    // Read the persisted record back for the response (secret-free).
    let record = state.store().scoped(scope).connectors().get(&id).await?;
    let view = view_of(&record)?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Delete a federation connector.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
    operation_id = "deleteConnector",
    tag = "connectors",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("connector_id" = String, Path, description = "The connector identifier (cnr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn delete_connector(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, connector_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // The parent-existence precondition, through the ONE expression of it (issues #443,
    // #451). For the reason the update records
    // (MEASURED: 204, and the connector row gone).
    crate::org_context::require_live_environment(&state, &scope).await?;
    let id = state
        .store()
        .scoped(scope)
        .connectors()
        .parse_id(&connector_id)?;
    // Read the SLUG before the row goes. It is what a connector is referenced by everywhere
    // else -- routing rules, the federation URL, an operator's own config -- so an event
    // carrying only the id would send a receiver looking it up in a row that no longer
    // exists. A not-found here is the same not-found the delete would return.
    let slug = state
        .store()
        .scoped(scope)
        .connectors()
        .get(&id)
        .await?
        .slug;
    let pending = connector_deleted_event(&state, scope, &id, &slug);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .connectors()
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

/// The event a connector delete emits (issue #108).
///
/// Carries the slug as well as the id: removing a connector changes who can log in, and a
/// receiver reconciling its own copy references connectors by slug.
fn connector_deleted_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    connector_id: &ironauth_store::ConnectorId,
    slug: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = connector_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "connector.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "connector_id": subject, "slug": slug }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event a connector create or update emits (issue #108).
///
/// ONE builder for both types, because the payload is identical and the only difference is
/// which fact is being announced. The types are still SEPARATE: an update replaces the
/// upstream definition of a LIVE federation, and a consumer counting new federations would
/// otherwise count every edit as a new one.
///
/// The id AND the slug, mirroring the delete: the slug is how a connector is named in
/// configuration and in the federation URLs, so an event carrying only the id would make a
/// receiver look the name up before it could act.
///
/// NEVER the definition and NEVER the client secret. A connector row holds an upstream
/// CREDENTIAL, and the whole point of the secret-free read surface is that it does not leave
/// through the API -- a webhook is a wider audience than the API, not a narrower one.
fn connector_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    connector_id: &ironauth_store::ConnectorId,
    slug: &str,
    event_type: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = connector_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "connector_id": subject, "slug": slug }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
