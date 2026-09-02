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
//! exists to prevent. `api_keys.rs` solved this first and this follows it exactly.
//!
//! # Revoked connections are listed
//!
//! For the reason 0183 retains the rows: an operator investigating a provisioning incident has
//! to be able to tell "I revoked that at 14:02" from "no such connection ever existed".

use axum::body::Bytes;
use axum::extract::{Path, State};
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
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
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
}

/// What a create names.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScimConnectionRequest {
    /// The operator-facing label, for telling two identity providers apart in a listing.
    pub display_name: String,
    /// `okta`, `entra` or `generic`. The column carries a closed vocabulary, so anything else
    /// is refused by the database rather than stored and puzzled over later.
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
    tag = "scim",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        ("environment_id" = String, Path, description = "Environment identifier"),
        ("organization_id" = String, Path, description = "Organization identifier"),
    ),
    responses(
        (status = 200, description = "The organization's SCIM connections", body = ScimConnectionListView),
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
    let connections = state
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&org_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    let body = serde_json::to_string(&ScimConnectionListView {
        items: connections.iter().map(view).collect(),
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// `POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections`
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections",
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
        (status = 400, description = "Malformed request or unknown provider", body = crate::error::ErrorBody),
        (status = 401, description = "Missing or invalid management credential", body = crate::error::ErrorBody),
        (status = 403, description = "The credential may not mint credentials for this organization", body = crate::error::ErrorBody),
        (status = 404, description = "No such live organization", body = crate::error::ErrorBody),
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
        display_name: request.display_name.clone(),
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
        display_name: request.display_name.clone(),
        token: None,
        token_already_issued: true,
    };
    let stored_body = serde_json::to_string(&stored).map_err(|_| ApiError::Internal)?;

    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization, as every organization-scoped write
        // on this surface does.
        .in_organization(org_id)
        .scim_connections()
        .create(
            state.env(),
            NewScimConnection {
                id: &id,
                organization_id: &org_id,
                display_name: &request.display_name,
                provider: &request.provider,
                token_digest: &digest,
                expires_at_unix_micros: request
                    .expires_at_unix_ms
                    .map(|millis| millis.saturating_mul(1_000)),
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
        )
        .await;
    match result {
        Ok(()) => {}
        // A provider outside the column's closed vocabulary arrives here as a database error.
        // It is the caller's mistake, not the server's, so it is a 400 naming the field rather
        // than an opaque 500.
        Err(StoreError::Database(_)) => {
            return Err(ApiError::BadRequest(
                "invalid_provider: provider must be one of okta, entra, generic".to_owned(),
            ));
        }
        // A digest already present means a caller reused a token rather than letting the
        // server mint one, which the store refuses. Not reachable from this handler, which
        // always mints, but the arm says so rather than falling into Internal.
        Err(StoreError::Conflict) => {
            return Err(ApiError::Conflict(
                "connection_exists: a connection with this token digest already exists".to_owned(),
            ));
        }
        Err(_) => return Err(ApiError::Internal),
    }

    Ok(json(StatusCode::CREATED, created_body))
}

/// `DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}`
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/scim-connections/{connection_id}",
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
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
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
    let belongs = state
        .store()
        .scoped(scope)
        .scim_connections()
        .list_for_organization(&org_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .into_iter()
        .any(|connection| connection.id == id);
    if !belongs {
        return Err(ApiError::NotFound);
    }

    let now = state.now_unix_micros();
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .in_organization(org_id)
        .scim_connections()
        .revoke(state.env(), &id, now)
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
