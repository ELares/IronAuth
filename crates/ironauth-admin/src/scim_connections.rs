// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM connection management surface (issue #135).
//!
//! # Why this exists, and what shipped without it
//!
//! The SCIM 2.0 inbound surface authenticates every route against a per-connection bearer
//! token, and until this module there was NO WAY TO CREATE ONE. The store could
//! (`ActingScimConnectionRepo::create`) but nothing reachable called it: `ironauth-admin` had
//! no SCIM route and the published management API had no SCIM path. A deployment that turned
//! `scim.enabled` on got a surface that authenticated correctly and that nobody could obtain a
//! credential for through any shipped interface.
//!
//! That is the "enforcement without a granting path" shape: the control is real, the door to
//! it is missing, and nothing fails because a control that refuses everyone refuses correctly.
//!
//! # The token is returned ONCE
//!
//! `scim_connections` stores only a SHA-256 digest, so the plaintext exists in exactly one
//! response: the 201 of a create. It is not in a listing, not in a read, and not in the
//! idempotency replay body -- the stored replay carries the id and a flag saying the token was
//! already issued, because `idempotency_keys.response_body` is plaintext retained for a day
//! and putting a live credential there would recreate the recoverable copy migration 0183
//! exists to prevent. `api_keys.rs` solved this first and this follows it, with two knowing
//! differences: the provider is validated in the handler rather than by catching the column's
//! CHECK, and the writes emit domain events through the `*_with_event` methods.
//!
//! # Revoked connections are listed
//!
//! For the reason 0183 retains the rows: an operator investigating a provisioning incident has
//! to be able to tell "I revoked that at 14:02" from "no such connection ever existed".

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewScimConnection, ScimConnectionId, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::ApiError;
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{
    EnvironmentAccess, require_present_environment, resolve_live_org, resolve_scope,
};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One connection, as the management surface renders it.
///
/// NO DIGEST FIELD, and that is the type doing the work rather than the handler remembering:
/// `ScimConnection` carries no plaintext and this view carries no digest, so a listing has
/// nothing to leak even by accident.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimConnectionView {
    /// The non-secret `scim_` handle. Every other operation names the connection by this.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// Which vendor this connection is for: `okta`, `entra` or `generic`.
    pub provider: String,
    /// Expiry in milliseconds since the epoch, absent for a connection that does not expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
    /// Revocation time in milliseconds since the epoch, absent while the connection is live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<i64>,
}

/// A page of connections.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimConnectionListView {
    /// This organization's connections, revoked ones included.
    pub items: Vec<ScimConnectionView>,
    /// The cursor for the next page, absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// What a create names.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScimConnectionRequest {
    /// The operator-facing label, for telling two identity providers apart in a listing.
    pub display_name: String,
    /// `okta`, `entra` or `generic`. Anything else is refused by this route with
    /// `400 invalid_provider`, before the write.
    pub provider: String,
    /// Optional expiry, in milliseconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
}

/// The 201 of a create: the ONLY response that carries the token.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScimConnectionCreated {
    /// The non-secret handle.
    pub id: String,
    /// The operator-facing label.
    pub display_name: String,
    /// The bearer token, present exactly once. Absent on an idempotent replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Whether the token was already issued on an earlier identical request.
    ///
    /// A replay cannot return the token -- nothing stores it -- so it says so rather than
    /// returning a body that looks like a create with a missing field.
    pub token_already_issued: bool,
}

fn micros_to_millis(micros: i64) -> i64 {
    micros / 1_000
}

fn view(connection: &ironauth_store::ScimConnection) -> ScimConnectionView {
    ScimConnectionView {
        id: connection.id.to_string(),
        display_name: connection.display_name.clone(),
        provider: connection.provider.clone(),
        expires_at_unix_ms: connection.expires_at_unix_micros.map(micros_to_millis),
        revoked_at_unix_ms: connection.revoked_at_unix_micros.map(micros_to_millis),
    }
}

/// `GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections`
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections",
    operation_id = "listScimConnections",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ListQuery
    ),
    responses(
        (status = 200, description = "A page of the organization's SCIM connections", body = ScimConnectionListView),
        (status = 400, description = "Malformed cursor or limit", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not read this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scim_connections(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // READ, not write credentials: a listing carries no digest and no plaintext, so it is a
    // strictly smaller capability than minting one.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    // CURSOR PAGINATED, like every sibling listing on this surface. It was not, and an
    // organization's whole inventory came back in one response however large it had grown;
    // `MANAGEMENT_LIST_HARD_CAP` is the bound nothing was applying.
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let connections = state
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&org_id, page.fetch_limit(), page.after())
        .await
        .map_err(|_| ApiError::Internal)?;
    let (connections, next_cursor) = page.finish(connections, |connection| {
        (connection.created_at_unix_micros, connection.id.to_string())
    });
    let body = serde_json::to_string(&ScimConnectionListView {
        items: connections.iter().map(view).collect(),
        next_cursor,
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Check what a create names, and return the expiry in micros.
///
/// VALIDATED HERE, not by catching the database's refusal. The provider column carries a closed
/// vocabulary, and an earlier version mapped every `StoreError::Database` onto a 400 naming that
/// field -- so a revoked INSERT grant, a full disk, or a failed idempotency write all told the
/// caller their provider was wrong. A reviewer drove it: revoking `INSERT ON scim_connections`
/// produced `400 invalid_provider`, where `api_keys.rs` under the same revocation produces a 500.
///
/// That mattered beyond the message. `no_management_operation_answers_a_server_error_...` sweeps
/// for exactly the missing-grant case, and a handler that answers 400 to it passes the sweep
/// while being broken.
///
/// THE EXPIRY MUST BE IN THE FUTURE. A past one was accepted and minted a credential that never
/// authenticated: `authenticate` filters on `expires_at > now`, so the operator got a 201, a
/// token, and a connection that answered 401 to their identity provider from the first request.
/// Refusing here is the only place that can tell them why, because by the time SCIM fails there
/// is nothing left to distinguish "expired" from "wrong token".
fn validated_create(
    request: &CreateScimConnectionRequest,
    now_micros: i64,
) -> Result<(String, Option<i64>), ApiError> {
    // THE DISPLAY NAME, through the helper 15 admin modules already call. Migration 0183
    // carries `CHECK (display_name <> '')`, and a review drove what happens without this:
    // `{"display_name":""}` reached the INSERT, Postgres refused with SQLSTATE 23514, and
    // `is_unique_violation` is false for a CHECK violation, so it fell through to
    // `ApiError::Internal` -- a 500 on a brand-new route from a one-character body.
    // `input.rs`'s own doc says the helper exists for exactly that reason.
    let display_name = require_non_empty(&request.display_name, "display_name")?;
    // AND BOUNDED ABOVE, which 0183 does not do. A 200 000 character name was accepted and
    // stored; the migration is shipped and checksummed, so the bound lives here. The figure is
    // the schema's own slug ceiling times four, which is far more than an operator label needs
    // and far less than a row worth storing.
    if display_name.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(ApiError::BadRequest(format!(
            "display_name must be at most {MAX_DISPLAY_NAME_BYTES} bytes"
        )));
    }
    if !matches!(request.provider.as_str(), "okta" | "entra" | "generic") {
        return Err(ApiError::BadRequest(
            "invalid_provider: provider must be one of okta, entra, generic".to_owned(),
        ));
    }
    let expires_micros = request
        .expires_at_unix_ms
        .map(|millis| millis.saturating_mul(1_000));
    if let Some(expires) = expires_micros
        && expires <= now_micros
    {
        return Err(ApiError::BadRequest(
            "invalid_expiry: expires_at_unix_ms must be in the future".to_owned(),
        ));
    }
    // AND BOUNDED ABOVE TOO. `saturating_mul` clamps to `i64::MAX` micros, which is in the
    // future and so passed the check above, and then reached
    // `TIMESTAMPTZ 'epoch' + ($8::bigint * INTERVAL '1 microsecond')` -- outside Postgres'
    // timestamp range, which is a 500. A review drove it: `i64::MAX` answered 500 while
    // 900000000000000 answered 201. A bound with only one side is half a bound.
    if let Some(expires) = expires_micros
        && expires > MAX_EXPIRY_UNIX_MICROS
    {
        return Err(ApiError::BadRequest(
            "invalid_expiry: expires_at_unix_ms is further ahead than this server stores"
                .to_owned(),
        ));
    }
    Ok((display_name, expires_micros))
}

/// The longest operator-facing label this route accepts.
///
/// Migration 0183 bounds the column below (non-empty) and not above, and it is shipped and
/// checksummed, so this is where the ceiling lives.
const MAX_DISPLAY_NAME_BYTES: usize = 252;

/// The furthest future expiry this route accepts, in microseconds since the epoch.
///
/// The year 9999, which is inside Postgres' `timestamptz` range with room to spare. Anything
/// past it is a client that computed a date wrong, and answering 400 says so where a 500 does
/// not.
const MAX_EXPIRY_UNIX_MICROS: i64 = 253_402_300_799_000_000;

/// `POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections`
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections",
    operation_id = "createScimConnection",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required idempotency key"),
    ),
    request_body = CreateScimConnectionRequest,
    responses(
        (status = 201, description = "The connection, with its token, returned once", body = ScimConnectionCreated),
        (status = 200, description = "An idempotent replay; the token is not returned again", body = ScimConnectionCreated),
        (status = 400, description = "Malformed request, unknown provider, or an expiry that is not in the future", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not mint credentials for this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization", body = crate::error::ErrorBody),
        (status = 409, description = "The same Idempotency-Key was used for a different request", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_scim_connection(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // WRITE CREDENTIALS, not write organizations, for the reason `api_keys.rs` gives: this
    // mints a credential that provisions INTO the organization, which is strictly higher
    // authority than editing its configuration, and the permission vocabulary separates them.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let idem_key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &idem_key, &fingerprint).await?
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
    let request: CreateScimConnectionRequest = parse_json(&body)?;
    let (display_name, expires_micros) = validated_create(&request, state.now_unix_micros())?;

    // MINTED THROUGH THE SCIM CRATE, not reimplemented here. `mint_token` and `digest_of` are
    // the format the verifier uses, so a second copy of `{scim_id}.{secret}` in this crate
    // would be two definitions of a credential that must agree byte for byte -- and they would
    // agree until somebody changed one.
    let id = ScimConnectionId::generate(state.env(), &scope);
    let mut secret = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut secret);
    let token = ironauth_scim::server::mint_token(
        &id,
        &base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, secret),
    );
    let digest = ironauth_scim::server::digest_of(&token);

    let created = ScimConnectionCreated {
        id: id.to_string(),
        display_name: display_name.clone(),
        token: Some(token.clone()),
        token_already_issued: false,
    };
    let created_body = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;

    // The body STORED for replay carries NO token, and replays as 200 rather than 201.
    // `idempotency_keys.response_body` is plaintext retained 24 hours; storing the created
    // body verbatim would put a live provisioning credential there, which is the recoverable
    // copy migration 0183 exists to prevent -- `scim_connections` has no column the plaintext
    // can come back from, and this would have created one in a different table.
    let stored = ScimConnectionCreated {
        id: id.to_string(),
        display_name: display_name.clone(),
        token: None,
        token_already_issued: true,
    };
    let stored_body = serde_json::to_string(&stored).map_err(|_| ApiError::Internal)?;

    let pending = created_event(&state, scope, &id, &org_id, &request.provider);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization, as every organization-scoped write
        // on this surface does.
        .in_organization(org_id)
        .scim_connections()
        .create_with_event(
            state.env(),
            NewScimConnection {
                id: &id,
                organization_id: &org_id,
                display_name: &display_name,
                provider: &request.provider,
                token_digest: &digest,
                expires_at_unix_micros: expires_micros,
            },
            // IN THE SAME TRANSACTION as the row, which is why it is a parameter rather than a
            // second call: a record written afterwards leaves a window in which the connection
            // exists and the retry that created it can still mint a second one.
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &idem_key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &stored_body,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;
    match result {
        Ok(()) => {}
        // A unique violation on either the id or the digest. Neither is reachable from this
        // handler, which mints both, but the arm names the case rather than letting it fall
        // into an opaque 500.
        Err(StoreError::Conflict) => {
            return Err(ApiError::Conflict(
                "connection_exists: a connection with this id or token digest already exists"
                    .to_owned(),
            ));
        }
        // The idempotency race the record exists to close: two requests with one key arriving
        // together. A 409 telling the caller to retry, not a 500.
        Err(StoreError::IdempotencyConflict) => return Err(ApiError::IdempotencyKeyConflict),
        // EVERYTHING ELSE IS THE SERVER'S. A database failure is a 500 so the sweep that
        // looks for one can see it, and so a client that retries 5xx does.
        Err(_) => return Err(ApiError::Internal),
    }

    Ok(json(StatusCode::CREATED, created_body))
}

/// `DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}`
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}",
    operation_id = "revokeScimConnection",
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
        ("connection_id" = String, Path, description = "The scim_ handle"),
    ),
    responses(
        (status = 204, description = "Revoked, or already revoked"),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not revoke credentials for this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such connection in this organization", body = crate::error::ErrorBody),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_scim_connection(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, connection_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // PRESENT, NOT LIVE, and this is the one route on this surface where the difference
    // matters. A revoke DESTROYS a capability, and `authenticate` joins only `organizations`:
    // soft-deleting an ENVIRONMENT cascades to neither the organization's `deleted_at` nor its
    // state, so a minted token goes on provisioning after the environment is decommissioned.
    // Under `EnvironmentAccess::Write` the revoke then answered the uniform not-found while
    // the listing beside it still showed the connection live -- the management API telling an
    // operator, in the same breath, that a credential exists and that it does not.
    //
    // `org_context.rs` names this shape and the rule for it: requiring liveness to DISARM
    // turns a soft delete into a one-way door. Issue #250 measured the same state on the
    // outbound-verification credential; this is that lesson applied to the strongest
    // credential this surface issues.
    require_present_environment(&state, &scope).await?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    // PARSED IN SCOPE, so a handle minted in another tenant is the uniform not-found rather
    // than a distinguishable parse failure.
    let id =
        ScimConnectionId::parse_in_scope(&connection_id, &scope).map_err(|_| ApiError::NotFound)?;
    // AND CHECKED AGAINST THIS ORGANIZATION. The store's revoke is scope-fenced but not
    // organization-fenced, so without this an operator holding write-credentials on one
    // organization could revoke another organization's provisioning connection in the same
    // environment -- a denial of service against a sibling tenant's identity provider.
    //
    // A POINT LOOKUP rather than a scan of the listing. Scanning was correct only while the
    // listing was unbounded; once it took a page limit, a connection past the first page would
    // have become unrevokable, which is the failure that matters most on this route.
    let belongs = state
        .store()
        .scoped(scope)
        .scim_connections()
        .exists_in_organization(&org_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?;
    if !belongs {
        return Err(ApiError::NotFound);
    }

    let now = state.now_unix_micros();
    let pending = revoked_event(&state, scope, &id, &org_id);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .scim_connections()
        .revoke_with_event(
            state.env(),
            &id,
            now,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
    {
        // TRUE and FALSE are both 204: revoking a connection that is already revoked is the
        // state the caller asked for, and distinguishing them would make a retry look like a
        // failure. The store writes an audit row only for the first, which is where the
        // distinction belongs.
        Ok(_) => Ok(no_content()),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

/// The `scim_connection.created` envelope.
fn created_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimConnectionId,
    organization_id: &ironauth_store::OrganizationId,
    provider: &str,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_connection.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "scim_connection_id": subject,
            "organization_id": organization_id.to_string(),
            "provider": provider,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}

/// The `scim_connection.revoked` envelope.
fn revoked_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &ScimConnectionId,
    organization_id: &ironauth_store::OrganizationId,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "scim_connection.revoked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "scim_connection_id": subject,
            "organization_id": organization_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject,
        envelope,
    })
}
