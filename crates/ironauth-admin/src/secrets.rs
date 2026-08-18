// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment secret management (issue #235, follow-up to #45).
//!
//! The other half of the surface `variables.rs` opened. #45 shipped the sealed
//! environment-secret store and the reference-resolution library, and deferred the HTTP
//! layer; #235 deferred it a second time, because a secret is sealed through the #48 envelope
//! substrate and the plane that manages it must be able to reach the key hierarchy.
//!
//! # Why the writes go through the DATA-plane store
//!
//! The management API runs as `ironauth_control`, and that role is deliberately fenced out
//! of this table. Migration 0035 grants it SELECT for the promotion plan's reference-presence
//! check, and 0100 grants it INSERT, DELETE and a column-scoped UPDATE but then binds all
//! three with RESTRICTIVE row-level-security policies to ONE reserved name
//! (`ironauth.outbound_verification_token`).
//!
//! 0100's header explains why that fence is load-bearing, and the argument survives this
//! module: column grants alone do not fence a writer, because INSERT plus DELETE together are
//! a rename and a replace of any other secret in the scope. Widening the policies so this
//! surface could write any name would dismantle exactly the control the previous migration
//! installed on purpose, and it would do it for convenience rather than for a new requirement.
//!
//! So nothing here changes a grant or a policy. The writes run against the DATA-plane store,
//! which already holds every right this needs, reached through the shared issuer registry the
//! admin state carries. That is the seam issue #93's compatibility wizard already uses for the
//! same reason (its per-client column is data-plane writable only), and issue #414's argument
//! for ONE shared data-plane handle rather than a second pool per feature applies unchanged.
//!
//! The HTTP surface stays on the MANAGEMENT bind rather than moving to the public one. The two
//! planes are a network split and a database-role split, and only the role half is at issue
//! here: a privileged secret surface belongs on the bind that is not publicly reachable, and
//! it reaches the privileged role through a connection rather than by moving the endpoint.
//!
//! With no registry installed the surface fails CLOSED and reports it, exactly as the wizard
//! does, rather than half-working through a role that would refuse the write anyway.
//!
//! # The value is never returned
//!
//! There is no read-the-value endpoint, and `get_secret` returns METADATA. The `mak_` lesson
//! from issue #11 is the same one: a management API that can write a credential must not
//! double as a way to enumerate credentials, because the API's own bearer tokens are a much
//! softer target than the sealed column.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_oidc::IssuerRegistry;
use ironauth_store::{CorrelationId, EnvironmentSecretMetadata, StoreError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::sudo;

/// The DATA-plane store every handler in this module runs against, or a fail-closed error.
///
/// `ironauth_control` is fenced out of `environment_secrets` by 0100's restrictive policies
/// (see the module header), so a handler that used `state.store()` would be refused by the
/// database on every name but the reserved one. Reaching the data-plane role through the
/// shared registry is what makes the surface work WITHOUT widening that fence.
///
/// Reads go through it too, even though 0035 would let the control role serve them. One store
/// for all four handlers means one failure mode and one answer to "which role saw this",
/// instead of a surface that half-works when the registry is missing.
fn data_plane_store(state: &AdminState) -> Result<&ironauth_store::Store, ApiError> {
    state
        .signing_registry()
        .and_then(IssuerRegistry::store)
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "environment secret management is not available: this deployment has no \
                 data-plane connection, and the management role is not permitted to write \
                 secrets"
                    .to_owned(),
            )
        })
}

/// One environment secret's METADATA. The sealed value is never part of this shape.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretView {
    /// The secret identifier (`esec_...`).
    pub id: String,
    /// The secret name, unique within the environment, and the key a `${secret:NAME}`
    /// reference resolves against. The NAME is metadata and is not itself sensitive.
    pub name: String,
    /// The revision counter, incremented on every write. It is how an operator confirms a
    /// rotation actually landed without ever reading the value back.
    pub version: i32,
    /// Creation time in Unix milliseconds.
    pub created_at_unix_ms: i64,
    /// Last update time in Unix milliseconds.
    pub updated_at_unix_ms: i64,
}

impl SecretView {
    fn from_metadata(record: EnvironmentSecretMetadata) -> Self {
        Self {
            id: record.id.to_string(),
            name: record.name,
            version: record.version,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// One page of environment secret metadata.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretList {
    /// The secrets in this page, as metadata only.
    pub items: Vec<SecretView>,
    /// The cursor for the next page, absent on the last page.
    pub next_cursor: Option<String>,
}

/// Set (create or replace) a secret.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetSecretRequest {
    /// The value to seal. It is sealed under the environment's DEK before it reaches the
    /// table and is never readable through this API afterwards.
    pub value: String,
}

/// List the secrets of an environment (metadata only, cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/secrets",
    operation_id = "listSecrets",
    tag = "secrets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("limit" = Option<i64>, Query, description = "Page size"),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from a previous page")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of secret metadata. Values are never included", body = SecretList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_secrets(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = data_plane_store(&state)?
        .scoped(scope)
        .environment_secrets()
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = SecretList {
        items: rows.into_iter().map(SecretView::from_metadata).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one secret's metadata by name. The value is NEVER returned.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/secrets/{name}",
    operation_id = "getSecret",
    tag = "secrets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Path, description = "The secret name")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The secret's metadata. The value is never returned by any endpoint", body = SecretView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, name)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let record = data_plane_store(&state)?
        .scoped(scope)
        .environment_secrets()
        .metadata(&name)
        .await?;
    let body = serde_json::to_string(&SecretView::from_metadata(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Set (create or replace) a secret by name.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/secrets/{name}",
    operation_id = "setSecret",
    tag = "secrets",
    request_body = SetSecretRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Path, description = "The secret name"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a PUT \
          with the same key returns the original response.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Sealed and stored. The metadata, with its version and timestamps, is available from the GET"),
        (status = 400, description = "Malformed request or invalid name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or not live", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn set_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, name)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // A secret WRITE is configuration authority: a credential that can seal a
    // value into an environment can change what every connector authenticates
    // with, so it is gated with the rest of the config surface rather than
    // treated as a lesser operation because the value is unreadable afterwards.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("PUT", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    // Replay BEFORE any validation, so a genuine replay returns the original response rather
    // than re-deciding anything about the request. It also means a retried write never seals a
    // second time, which matters more here than for a variable: a second seal would bump the
    // version and make a retry look like a rotation.
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    require_live_environment(&state, &scope).await?;

    let request: SetSecretRequest = parse_json(&body)?;

    // CROSS-ROLE idempotency (NOT same-transaction), exactly as `signing_algorithm` records
    // for the same structural reason: the write lands on the DATA-plane role and the
    // Idempotency-Key replay table is control-plane only, so the two cannot share one
    // transaction. The seal is performed first, then the response is recorded on the control
    // plane, and a concurrent duplicate that stored the key first replays the original.
    //
    // The consequence, stated rather than hidden: a crash BETWEEN the two phases leaves the
    // secret written and the key unrecorded, so a retry seals the same value again and bumps
    // `version` a second time. The stored value is identical either way, so this costs an
    // operator an over-counted revision on a crashed request and never a wrong secret.
    //
    // 204 with NO body, for the reason `set_variable` records, plus one specific to this
    // surface: the only field a body could carry that this handler already knows is the value,
    // and echoing it back is exactly what this surface must never do.
    let pending = environment_secret_event(&state, scope, &name, "environment_secret.set");
    data_plane_store(&state)?
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .environment_secrets()
        // `put_under_platform_key` rather than `put`, and that is not a convenience. A request
        // handler holds a `Store`, not a key handle, and `Store::master` is crate-private
        // precisely so it keeps holding no key: the seal happens inside the store.
        .put_under_platform_key_with_event(
            state.env(),
            &name,
            request.value.as_bytes(),
            None,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            // The NAME grammar is the store's (`esv::name_is_valid`), deliberately not
            // re-implemented here: a second copy of a grammar is a second thing to drift.
            StoreError::InvalidName => {
                ApiError::BadRequest(format!("secret name {name} is not a valid name"))
            }
            // A deployment with no envelope master key cannot seal, and there is no unsealed
            // fallback. That is a CONFIGURATION state, not a fault, so it is reported as one:
            // rendering it as a 500 would be the issue #442 defect shape, where an operation
            // that happens to seal answers a server error while its non-sealing neighbour on
            // the same resource answers cleanly.
            StoreError::Encryption => ApiError::Unprocessable(
                "environment secrets cannot be sealed: this deployment has no envelope master \
                 key configured"
                    .to_owned(),
            ),
            other => ApiError::from(other),
        })?;

    match state
        .store()
        .management()
        .idempotency()
        .record(&credential_ref, &key, &fingerprint, 204, "")
        .await
    {
        Ok(()) => Ok(no_content()),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Delete a secret by name.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/secrets/{name}",
    operation_id = "deleteSecret",
    tag = "secrets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("name" = String, Path, description = "The secret name")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody),
        (status = 409, description = "Still referenced by a variable or another secret", body = ErrorBody)
    )
)]
pub async fn delete_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, name)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // A secret WRITE is configuration authority: a credential that can seal a
    // value into an environment can change what every connector authenticates
    // with, so it is gated with the rest of the config surface rather than
    // treated as a lesser operation because the value is unreadable afterwards.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;

    // A soft-deleted environment refuses every WRITE, and a delete is a write. Reads stay
    // readable so an operator can still inspect what a retired environment held, which is why
    // this sits here and not in the two read handlers.
    require_live_environment(&state, &scope).await?;

    // The reference check is NOT repeated here, unlike `delete_variable`. The store's own
    // `delete` resolves the referents of a `${secret:NAME}` reference and refuses, so a copy in
    // this handler would be a second expression of one rule: the exact shape issue #443 was
    // filed about. The refusal surfaces as a conflict either way.
    let pending = environment_secret_event(&state, scope, &name, "environment_secret.deleted");
    data_plane_store(&state)?
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .environment_secrets()
        .delete_with_event(
            state.env(),
            &name,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The event an environment-secret write or delete emits (issue #108).
///
/// THE NAME ONLY, and here that is not a judgement call: the value is a SECRET, sealed at
/// rest, and the management read surface will not return it either. An event is a WIDER
/// audience than that surface, so the same refusal has to hold.
///
/// Nothing DERIVED from the value goes on the wire either -- no digest, no length, no prefix.
/// A digest of a low-entropy secret is guessable and a length narrows a search. The name is
/// what tells a consumer which reference to re-resolve, and it is enough.
pub(crate) fn environment_secret_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    name: &str,
    event_type: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "name": name }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The secret NAME is the subject: two events about one secret stay ordered.
        subject: name.to_owned(),
        envelope,
    })
}
