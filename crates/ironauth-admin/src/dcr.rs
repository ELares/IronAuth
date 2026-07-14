// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dynamic Client Registration abuse controls, management surface (issue #31).
//!
//! The operator-plane endpoints that back the DCR abuse controls: author a named,
//! reusable policy; mint an initial access token carrying a policy chain; read a
//! dynamically registered client's verification state; and verify a client (lift
//! its unverified-client quarantine). These operate on DATA-PLANE scoped resources
//! (`dcr_policies`, `dcr_initial_access_tokens`, and the `clients` quarantine
//! columns), so they route through the control-plane store's scoped repositories
//! (the control role holds the narrow grants the two-sided DCR lifecycle needs).
//!
//! Every POST honors Idempotency-Key (stored in the SAME transaction as the
//! mutation and its audit row) and every mutation writes its typed audit event, in
//! keeping with the crate's contract.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Env;
use ironauth_oidc::{PolicyPrimitive, parse_chain, serialize_chain};
use ironauth_store::{
    ClientId, CorrelationId, DcrPolicyId, IdempotencyWrite, InitialAccessTokenId, NewDcrPolicy,
    NewInitialAccessToken, Scope, StoreError, TenantId,
};
use serde_json::Value;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::hash::sha256_hex;
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{
    ClientVerificationView, CreateDcrPolicyRequest, CreateInitialAccessTokenRequest, DcrPolicyList,
    DcrPolicyView, InitialAccessTokenCreated,
};

/// Bytes of secret entropy in an initial access token: 32 bytes is 256 bits.
const IAT_SECRET_BYTES: usize = 32;

/// The upper bound on an initial access token's lifetime (issue #31): one year. A
/// longer-lived registration authorization is almost always a misconfiguration.
const IAT_MAX_LIFETIME_SECS: u64 = 31_536_000;

/// Mint a fresh initial-access-token plaintext from the entropy seam. The `ira_iat_`
/// prefix makes it recognizable in a log or a scanner; only its hash is stored.
fn generate_iat_token(env: &Env) -> String {
    let mut bytes = [0_u8; IAT_SECRET_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    format!("ira_iat_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Resolve a named policy chain (in order) to its serialized primitive snapshot, so
/// that a later edit or deletion of a named policy never changes an already-minted
/// token. An unknown name is a clean 400.
async fn resolve_policy_chain_snapshot(
    state: &AdminState,
    scope: Scope,
    policy_names: &[String],
) -> Result<String, ApiError> {
    let mut chain: Vec<PolicyPrimitive> = Vec::new();
    for policy_name in policy_names {
        let record = match state
            .store()
            .scoped(scope)
            .dcr_policies()
            .by_name(policy_name)
            .await
        {
            Ok(record) => record,
            Err(StoreError::NotFound) => {
                return Err(ApiError::BadRequest(format!(
                    "policy `{policy_name}` does not exist in this environment"
                )));
            }
            Err(error) => return Err(error.into()),
        };
        let mut primitives = parse_chain(&record.primitives).map_err(|_| ApiError::Internal)?;
        chain.append(&mut primitives);
    }
    serialize_chain(&chain).map_err(|_| ApiError::Internal)
}

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

/// Create a named, reusable DCR policy.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
    operation_id = "createDcrPolicy",
    tag = "dcr",
    request_body = CreateDcrPolicyRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = DcrPolicyView),
        (status = 400, description = "Malformed request or invalid primitives", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 409, description = "A policy with this name already exists", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_dcr_policy(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: CreateDcrPolicyRequest = parse_json(&body)?;
    let name = require_non_empty(&request.name, "name")?;
    // Validate and canonicalize the primitives against the OIDC policy engine, so
    // what is stored is exactly what the engine will later parse and apply (one
    // source of truth for the primitive shape).
    let primitives: Vec<PolicyPrimitive> = request
        .primitives
        .iter()
        .map(|value| serde_json::from_value(value.clone()))
        .collect::<Result<_, _>>()
        .map_err(|_| {
            ApiError::BadRequest(
                "each primitive must be a policy object (force / restrict / reject / default)"
                    .to_owned(),
            )
        })?;
    let primitives_text = serialize_chain(&primitives).map_err(|_| ApiError::Internal)?;

    // The environment must exist (a clean 404 rather than a foreign-key error).
    state
        .store()
        .management()
        .environments(tenant)
        .get(&scope.environment())
        .await?;

    let created_at_micros = state.now_unix_micros();
    let id = DcrPolicyId::generate(state.env(), &scope);
    let view = DcrPolicyView {
        id: id.to_string(),
        name: name.clone(),
        primitives: request.primitives.clone(),
        created_at_unix_ms: created_at_micros / 1000,
    };
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
        .dcr_policies()
        .create(
            state.env(),
            &id,
            created_at_micros,
            NewDcrPolicy {
                name: &name,
                primitives: &primitives_text,
            },
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a policy with this name already exists in this environment".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List DCR policies in an environment (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
    operation_id = "listDcrPolicies",
    tag = "dcr",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of policies", body = DcrPolicyList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_dcr_policies(
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
        .dcr_policies()
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let items = rows
        .into_iter()
        .map(|record| DcrPolicyView {
            id: record.id.to_string(),
            name: record.name,
            primitives: serde_json::from_str::<Vec<Value>>(&record.primitives).unwrap_or_default(),
            created_at_unix_ms: record.created_at_unix_micros / 1000,
        })
        .collect();
    let list = DcrPolicyList { items, next_cursor };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Mint a DCR initial access token. Returns the plaintext token ONCE.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/initial-access-tokens",
    operation_id = "createDcrInitialAccessToken",
    tag = "dcr",
    request_body = CreateInitialAccessTokenRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created; the token is present on this response ONCE", body = InitialAccessTokenCreated),
        (status = 200, description = "Idempotent replay; the token is omitted", body = InitialAccessTokenCreated),
        (status = 400, description = "Malformed request or unknown policy name", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_initial_access_token(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: CreateInitialAccessTokenRequest = parse_json(&body)?;
    if request.expires_in_secs < 1 || request.expires_in_secs > IAT_MAX_LIFETIME_SECS {
        return Err(ApiError::BadRequest(format!(
            "expires_in_secs must be between 1 and {IAT_MAX_LIFETIME_SECS}"
        )));
    }

    // The environment must exist (a clean 404).
    state
        .store()
        .management()
        .environments(tenant)
        .get(&scope.environment())
        .await?;

    // Resolve the attached policy chain (by name, in order) to its primitive
    // snapshot, so a later edit or deletion of a named policy never changes an
    // already-minted token.
    let policy_chain_text =
        resolve_policy_chain_snapshot(&state, scope, &request.policy_names).await?;

    let created_at_micros = state.now_unix_micros();
    let expires_at_micros = created_at_micros.saturating_add(
        i64::try_from(request.expires_in_secs)
            .unwrap_or(i64::MAX)
            .saturating_mul(1_000_000),
    );
    let max_uses = request
        .max_uses
        .map(|value| i32::try_from(value).unwrap_or(i32::MAX));

    let token = generate_iat_token(state.env());
    let token_hash = sha256_hex(token.as_bytes());
    let id = InitialAccessTokenId::generate(state.env(), &scope);

    // The response returned ONCE, WITH the plaintext token (HTTP 201).
    let created = InitialAccessTokenCreated {
        id: id.to_string(),
        token: Some(token),
        token_already_issued: false,
        expires_at_unix_ms: expires_at_micros / 1000,
        max_uses: request.max_uses,
        created_at_unix_ms: created_at_micros / 1000,
    };
    let created_body = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;

    // The body STORED for idempotent replay carries NO plaintext token (the token
    // must never touch the database) and replays as HTTP 200.
    let stored = InitialAccessTokenCreated {
        id: id.to_string(),
        token: None,
        token_already_issued: true,
        expires_at_unix_ms: expires_at_micros / 1000,
        max_uses: request.max_uses,
        created_at_unix_ms: created_at_micros / 1000,
    };
    let stored_body = serde_json::to_string(&stored).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &stored_body,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .initial_access_tokens()
        .mint(
            state.env(),
            &id,
            created_at_micros,
            NewInitialAccessToken {
                token_hash: &token_hash,
                policy_chain: &policy_chain_text,
                expires_at_unix_micros: expires_at_micros,
                max_uses,
            },
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, created_body)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Get a dynamically registered client's verification state.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}",
    operation_id = "getDcrClient",
    tag = "dcr",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The client identifier (cli_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The client verification state", body = ClientVerificationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, not a DCR client, or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_dcr_client(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let clients = state.store().scoped(scope).clients();
    let id = clients.parse_id(&client_id)?;
    let record = clients.dynamic_registration(&id).await?;
    let view = ClientVerificationView {
        id: record.id.to_string(),
        quarantined: record.quarantined,
        verified: record.verified_at_unix_micros.is_some(),
        verified_at_unix_ms: record.verified_at_unix_micros.map(|micros| micros / 1000),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Verify a dynamically registered client, lifting its unverified-client quarantine.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/verify",
    operation_id = "verifyDcrClient",
    tag = "dcr",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("client_id" = String, Path, description = "The client identifier (cli_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Verified (quarantine lifted)", body = ClientVerificationView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, not a DCR client, or in another scope)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn verify_dcr_client(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, client_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;

    // Verify carries no request body; the idempotency fingerprint is over the
    // method and concrete path (which names the client), so a replay for the same
    // client returns the original response.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id: ClientId = state.store().scoped(scope).clients().parse_id(&client_id)?;
    let verified_at_micros = state.now_unix_micros();
    let view = ClientVerificationView {
        id: id.to_string(),
        quarantined: false,
        verified: true,
        verified_at_unix_ms: Some(verified_at_micros / 1000),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .clients()
        .verify_dynamic_client(state.env(), &id, Some(write))
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}
