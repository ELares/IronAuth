// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tenant CRUD (operator plane).
//!
//! Creating a tenant also creates its first environment, in one transaction, and
//! audits the creation scoped to that fresh `(tenant, environment)` pair (the
//! operator-plane audit resolution). Delete is a soft deactivation, idempotent
//! per RFC 9110: the tenant row is retained (so the append-only audit log's
//! foreign key to it stays satisfiable), reads stop returning it, and repeating
//! the delete has the same effect.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, EnvironmentId, EnvironmentType, GuardrailReport, GuardrailSet, IdempotencyWrite,
    NewEnvironment, Scope, StoreError, TenantId,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::pagination::{ListQuery, Pagination};
use crate::provision::DayOneSigningKeys;
use crate::response::{json, no_content};
use crate::state::{AdminState, BOOTSTRAP_OPERATOR_DISPLAY_NAME};
use crate::views::{
    CreateTenantRequest, EnvironmentView, TenantCreated, TenantList, TenantStatusView, TenantView,
};

/// The validated attributes of a tenant's first environment (issue #42), parsed
/// from a tenant-create request before any write.
struct FirstEnvironment {
    display_name: String,
    kind: EnvironmentType,
    custom_domain: Option<String>,
    guardrails: GuardrailSet,
}

/// Parse and validate the first environment's attributes from a tenant-create
/// request (issue #42): its display name (defaulting to `development`), its kind
/// (defaulting to `dev`, the relaxed non-production kind that needs no custom
/// domain, so a tenant is always creatable in one call; an explicit unknown kind is
/// rejected, never coerced), and its custom domain, with the production
/// custom-domain guardrail enforced before any write.
fn validated_first_environment(
    request: &CreateTenantRequest,
) -> Result<FirstEnvironment, ApiError> {
    let display_name = request
        .environment_display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("development")
        .to_owned();
    let kind = match request.environment_kind.as_deref() {
        None => EnvironmentType::Dev,
        Some(raw) => {
            EnvironmentType::parse(raw).map_err(|error| ApiError::BadRequest(error.to_string()))?
        }
    };
    let custom_domain = request
        .environment_custom_domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let guardrails = kind.guardrails();
    let mut report = GuardrailReport::new();
    report.check(guardrails.check_custom_domain(custom_domain.as_deref()));
    if !report.is_clean() {
        return Err(ApiError::GuardrailViolation(report.into_violations()));
    }
    Ok(FirstEnvironment {
        display_name,
        kind,
        custom_domain,
        guardrails,
    })
}

/// Validate an optional `home_region` against the operator's configured region set
/// (issue #46), returning the normalized value. A blank value is treated as omitted
/// (no region recorded). Validation is against the configured set, so a deployment
/// with no region set rejects any present `home_region` fail closed. Runs BEFORE any
/// write.
fn validated_home_region(
    state: &AdminState,
    raw: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let home_region = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if let Some(region) = home_region.as_deref() {
        if !state.home_region_is_allowed(region) {
            return Err(ApiError::BadRequest(format!(
                "home_region {region:?} is not one of the operator's configured data-residency \
                 regions"
            )));
        }
    }
    Ok(home_region)
}

/// Create a tenant and its first environment.
#[utoipa::path(
    post,
    path = "/v1/tenants",
    operation_id = "createTenant",
    tag = "tenants",
    request_body = CreateTenantRequest,
    params(
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = TenantCreated),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_tenant(
    State(state): State<AdminState>,
    principal: Principal,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: CreateTenantRequest = parse_json(&body)?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;
    let FirstEnvironment {
        display_name: environment_display_name,
        kind: environment_kind,
        custom_domain: environment_custom_domain,
        guardrails,
    } = validated_first_environment(&request)?;

    let home_region = validated_home_region(&state, request.home_region.as_deref())?;

    let created_at_micros = state.now_unix_micros();
    let tenant_id = TenantId::generate(state.env());
    let environment_id = EnvironmentId::generate(state.env());
    let scope = Scope::new(tenant_id, environment_id);
    // The first environment's day-one signing keys (EdDSA + ES256 + RS256, issue #93).
    let signing_keys = DayOneSigningKeys::generate(state.env(), &scope)?;

    let created = TenantCreated {
        tenant: TenantView {
            id: tenant_id.to_string(),
            display_name: display_name.clone(),
            // A freshly created tenant is always active.
            status: "active".to_owned(),
            home_region: home_region.clone(),
            created_at_unix_ms: created_at_micros / 1000,
        },
        environment: EnvironmentView {
            id: environment_id.to_string(),
            tenant_id: tenant_id.to_string(),
            display_name: environment_display_name.clone(),
            kind: environment_kind.as_str().to_owned(),
            guardrail_class: environment_kind.guardrail_class().as_str().to_owned(),
            custom_domain: environment_custom_domain.clone(),
            guardrails: guardrails.into(),
            // The tenant's first environment pins no region here; a per-environment
            // region is set through the dedicated environment-create endpoint.
            region: None,
            created_at_unix_ms: created_at_micros / 1000,
        },
    };
    let body_string = serde_json::to_string(&created).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .tenants(state.bootstrap_operator_id())
        .create(
            state.env(),
            &tenant_id,
            &environment_id,
            created_at_micros,
            BOOTSTRAP_OPERATOR_DISPLAY_NAME,
            &display_name,
            NewEnvironment {
                display_name: &environment_display_name,
                kind: environment_kind,
                custom_domain: environment_custom_domain.as_deref(),
                region: None,
            },
            home_region.as_deref(),
            &signing_keys.as_new(created_at_micros),
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List tenants (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants",
    operation_id = "listTenants",
    tag = "tenants",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of tenants", body = TenantList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_tenants(
    State(state): State<AdminState>,
    principal: Principal,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = TenantList {
        items: rows.into_iter().map(TenantView::from).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one tenant.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}",
    operation_id = "getTenant",
    tag = "tenants",
    params(("tenant_id" = String, Path, description = "The tenant identifier")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant", body = TenantView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
pub async fn get_tenant(
    State(state): State<AdminState>,
    principal: Principal,
    Path(tenant_id): Path<String>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let tenants = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id());
    let id = tenants.parse_id(&tenant_id)?;
    let record = tenants.get(&id).await?;
    let body = serde_json::to_string(&TenantView::from(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Deactivate a tenant (soft delete; idempotent).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}",
    operation_id = "deleteTenant",
    tag = "tenants",
    params(("tenant_id" = String, Path, description = "The tenant identifier")),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deactivated (idempotent)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or already deactivated)", body = ErrorBody)
    )
)]
pub async fn delete_tenant(
    State(state): State<AdminState>,
    principal: Principal,
    Path(tenant_id): Path<String>,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let id = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(&tenant_id)?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .tenants(state.bootstrap_operator_id())
        .delete(state.env(), &id)
        .await?;
    Ok(no_content())
}

/// Suspend a tenant (fence its data plane; reversible).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/suspend",
    operation_id = "suspendTenant",
    tag = "tenants",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Suspended (post-condition)", body = TenantStatusView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Invalid lifecycle transition (not currently active)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn suspend_tenant(
    State(state): State<AdminState>,
    principal: Principal,
    Path(tenant_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    transition_tenant(state, principal, tenant_id, &uri, &headers, true).await
}

/// Resume a suspended tenant (restore data-plane service; no data loss).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/resume",
    operation_id = "resumeTenant",
    tag = "tenants",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Resumed (post-condition)", body = TenantStatusView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Invalid lifecycle transition (not currently suspended)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn resume_tenant(
    State(state): State<AdminState>,
    principal: Principal,
    Path(tenant_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    transition_tenant(state, principal, tenant_id, &uri, &headers, false).await
}

/// Restore a soft-deleted (offboarded) tenant inside its retention window.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/restore",
    operation_id = "restoreTenant",
    tag = "tenants",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Restored (post-condition)", body = TenantStatusView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (never offboarded, already restored, or purged)", body = ErrorBody),
        (status = 409, description = "Retention window elapsed; restore no longer offered", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn restore_tenant(
    State(state): State<AdminState>,
    principal: Principal,
    Path(tenant_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(&tenant_id)?;

    // The deterministic POST-condition: a restored tenant is active.
    let view = TenantStatusView {
        id: id.to_string(),
        status: "active".to_owned(),
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
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .tenants(state.bootstrap_operator_id())
        .restore(state.env(), &id, state.offboarding_retention(), Some(write))
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // The tenant is soft-deleted but its retention window has already elapsed:
        // restore is no longer offered (the terminal hard deletion is due), a loud
        // 409 rather than the anti-oracle 404.
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "tenant retention window has elapsed; restore is no longer available".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// The shared body of the suspend and resume handlers: enforce the operator plane,
/// honor the Idempotency-Key replay, run the state-machine transition, and map an
/// invalid transition to a loud 409 (distinct from the anti-oracle 404). `suspend`
/// selects the target state.
async fn transition_tenant(
    state: AdminState,
    principal: Principal,
    tenant_id: String,
    uri: &Uri,
    headers: &HeaderMap,
    suspend: bool,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let key = idempotency::required_key(headers)?;
    // These transitions carry no request body, so the idempotency fingerprint is
    // over the method and path only (an empty body).
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(&tenant_id)?;

    // The response is the deterministic POST-CONDITION, so the body stored for an
    // Idempotency-Key replay in the SAME transaction as the transition is
    // byte-identical to the live response.
    let view = TenantStatusView {
        id: id.to_string(),
        status: if suspend { "suspended" } else { "active" }.to_owned(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };

    let acting = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()));
    let tenants = acting.tenants(state.bootstrap_operator_id());
    let result = if suspend {
        tenants.suspend(state.env(), &id, Some(write)).await
    } else {
        tenants.resume(state.env(), &id, Some(write)).await
    };

    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // The tenant exists but is not in the state this transition requires (for
        // example a suspend on an already-suspended tenant): an invalid transition,
        // refused fail closed with a loud 409 rather than the anti-oracle 404.
        Err(StoreError::Conflict) => Err(ApiError::Conflict(format!(
            "tenant is not in the required state to {}",
            if suspend { "suspend" } else { "resume" }
        ))),
        Err(error) => Err(error.into()),
    }
}
