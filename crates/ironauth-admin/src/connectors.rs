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
    TenantId,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{
    ConnectorCapabilitiesView, ConnectorList, ConnectorView, CreateConnectorRequest,
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
        .environments(tenant)
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
        (status = 400, description = "Malformed or invalid definition (JSON-pointer error)", body = ErrorBody),
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
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
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
    let secret = resolve_client_secret(&definition)?;
    let projection = definition
        .secret_free_json()
        .map_err(|_| ApiError::Internal)?;
    let definition_json = serde_json::to_string(&projection).map_err(|_| ApiError::Internal)?;
    let capabilities = definition.capabilities();

    // The environment must exist (a clean 404 rather than a foreign-key error).
    state
        .store()
        .management()
        .environments(tenant)
        .get(&scope.environment())
        .await?;

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
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .connectors()
        .create(
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
        (status = 400, description = "Malformed or invalid definition (JSON-pointer error)", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
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
    let id = state
        .store()
        .scoped(scope)
        .connectors()
        .parse_id(&connector_id)?;

    let definition = parse_and_validate(&body)?;

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

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .connectors()
        .update(
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
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
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
    let id = state
        .store()
        .scoped(scope)
        .connectors()
        .parse_id(&connector_id)?;
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .connectors()
        .delete(state.env(), &id)
        .await?;
    Ok(no_content())
}
