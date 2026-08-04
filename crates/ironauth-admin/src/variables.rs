// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment variable management (issue #235, follow-up to #45).
//!
//! #45 shipped the environment-scoped variable store and the reference-resolution library
//! that #44 promotion consumes, and deliberately deferred the HTTP surface. The substrate has
//! been live since: `apply_promotion` writes variables on the promotion path, and
//! `ironauth-store`'s `esv` module resolves references against them. What was missing was the
//! per-key management layer, so an operator could set a variable only by promoting a whole
//! config snapshot.
//!
//! # Why this half lives on the CONTROL plane
//!
//! Secrets and variables are deliberately split. A secret is sealed through the #48 envelope
//! substrate and needs the master key, which the control plane does not hold and is not given
//! here; the secret surface is a separate design decision recorded on issue #235. A VARIABLE is
//! non-secret by construction, so the control plane can manage it with no envelope access at
//! all, and migration 0100 already granted `ironauth_control` exactly what that needs:
//! `SELECT`, `INSERT`, `DELETE`, and a COLUMN-SCOPED `UPDATE (value, version, updated_at)`.
//! Nothing here widens a grant.
//!
//! # Delete consults the references
//!
//! A variable that a promotion plan still references is not free to remove: dropping it turns
//! the next plan into an unresolvable reference, and the failure surfaces far from the delete
//! that caused it. `referents` exists for exactly this, so the delete path asks it first and
//! refuses with a conflict that NAMES what still points at the variable. That is the difference
//! between an API an operator can trust and one that lets them break a later deploy.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, EnvironmentVariableRecord, IdempotencyWrite, Reference, ReferenceKind,
    StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::sudo;

/// One environment variable.
#[derive(Debug, Serialize, ToSchema)]
pub struct VariableView {
    /// The variable identifier (`var_...`).
    pub id: String,
    /// The variable name, unique within the environment.
    pub name: String,
    /// The variable value. Variables are NON-SECRET by construction, so unlike a secret the
    /// value is returned on read; anything that must not be readable belongs in a secret.
    pub value: String,
    /// The revision counter, incremented on every write. Exposed for observability, and
    /// deliberately NOT accepted as a precondition on write: see the note on `set_variable`.
    pub version: i32,
    /// Creation time in Unix milliseconds.
    pub created_at_unix_ms: i64,
    /// Last update time in Unix milliseconds.
    pub updated_at_unix_ms: i64,
}

impl VariableView {
    fn from_record(record: EnvironmentVariableRecord) -> Self {
        Self {
            id: record.id.to_string(),
            name: record.name,
            value: record.value,
            version: record.version,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// One page of environment variables.
#[derive(Debug, Serialize, ToSchema)]
pub struct VariableList {
    /// The variables in this page.
    pub items: Vec<VariableView>,
    /// The cursor for the next page, absent on the last page.
    pub next_cursor: Option<String>,
}

/// Set (create or replace) a variable.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetVariableRequest {
    /// The value to store.
    pub value: String,
}

/// List the variables of an environment (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/variables",
    operation_id = "listVariables",
    tag = "variables",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("limit" = Option<i64>, Query, description = "Page size"),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from a previous page")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of variables", body = VariableList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_variables(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .environment_variables()
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = VariableList {
        items: rows.into_iter().map(VariableView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one variable by name.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/variables/{name}",
    operation_id = "getVariable",
    tag = "variables",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Path, description = "The variable name")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The variable", body = VariableView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_variable(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, name)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let record = state
        .store()
        .scoped(scope)
        .environment_variables()
        .get(&name)
        .await?;
    let body = serde_json::to_string(&VariableView::from_record(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Set (create or replace) a variable by name.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/variables/{name}",
    operation_id = "setVariable",
    tag = "variables",
    request_body = SetVariableRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Path, description = "The variable name"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a PUT \
          with the same key returns the original response.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Stored. The full record, with its version and timestamps, is available from the GET"),
        (status = 400, description = "Malformed request or invalid name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or not live", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn set_variable(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, name)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("PUT", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    // Replay BEFORE any validation, so a genuine replay returns the original response rather
    // than re-deciding anything about the request.
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    require_live_environment(&state, &scope).await?;

    let request: SetVariableRequest = parse_json(&body)?;

    // The NAME grammar is enforced by the store (`esv::name_is_valid`, surfaced as
    // `StoreError::InvalidName`), so it is deliberately NOT re-implemented here. A second copy
    // of a grammar is a second thing to drift.
    //
    // 204 with NO body, and that is a consequence of how idempotency works here rather than a
    // style choice. The Idempotency-Key record rides INTO the store call, so the stored
    // response has to be known BEFORE the write. `set` assigns the id, the version and the
    // timestamps itself, so any body naming them would be a guess that is wrong on every
    // replace. An empty body is the one thing that is true either way, and the full record is
    // one GET away.
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 204,
        response_body: "",
    };
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .environment_variables()
        .set(state.env(), &name, &request.value, Some(write))
        .await
        .map_err(|error| match error {
            StoreError::InvalidName => {
                ApiError::BadRequest(format!("variable name {name} is not a valid name"))
            }
            other => ApiError::from(other),
        })?;
    Ok(no_content())
}

/// Delete a variable by name.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/variables/{name}",
    operation_id = "deleteVariable",
    tag = "variables",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Path, description = "The variable name")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody),
        (status = 409, description = "Still referenced by another variable", body = ErrorBody)
    )
)]
pub async fn delete_variable(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, name)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;

    // A soft-deleted environment refuses every WRITE, and a delete is a write. Reads stay
    // readable so an operator can still inspect what a retired environment held, which is why
    // this sits here and not in the two read handlers.
    require_live_environment(&state, &scope).await?;

    // Existence first, so deleting an absent variable is the uniform not-found rather than a
    // silent success that tells the caller nothing.
    state
        .store()
        .scoped(scope)
        .environment_variables()
        .get(&name)
        .await?;

    // REFUSE a delete that would break a live reference. `referents` reports every variable
    // whose value still points at this one, and removing it would turn the next promotion plan
    // into an unresolvable reference, failing far from the delete that caused it.
    let reference = Reference {
        kind: ReferenceKind::Variable,
        name: name.clone(),
    };
    let referents = state
        .store()
        .scoped(scope)
        .environment_variables()
        .referents(&reference)
        .await?;
    if !referents.is_empty() {
        return Err(ApiError::Conflict(format!(
            "variable {name} is still referenced by {}; update or remove those first",
            referents.join(", ")
        )));
    }

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .environment_variables()
        .delete(state.env(), &name)
        .await?;
    Ok(json(StatusCode::NO_CONTENT, String::new()))
}
