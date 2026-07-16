// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment CRUD under a tenant.
//!
//! Create, list, and delete are operator-plane. Get is reachable by the operator
//! OR by a management key scoped to exactly that `(tenant, environment)`, so it
//! is where both wrong-scope behaviors meet: a key presented against a sibling
//! environment or a foreign tenant fails LOUD (naming expected and actual
//! scope), while a well-formed request for an environment that belongs to
//! another tenant is the UNIFORM not-found (the tenant filter is the anti-oracle).

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, EnvironmentId, EnvironmentType, GuardrailReport, IdempotencyWrite,
    NewEnvironment, Scope, StoreError,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::pagination::{ListQuery, Pagination};
use crate::provision::DayOneSigningKey;
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{CreateEnvironmentRequest, EnvironmentList, EnvironmentView};

/// Normalize an optional custom-domain input: trim surrounding whitespace and
/// treat an empty (or whitespace-only) value as unconfigured (`None`). This is
/// the one place the input is canonicalized, so the stored value, the guardrail
/// check, and the response view all agree.
fn normalize_custom_domain(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Create an environment under a tenant.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments",
    operation_id = "createEnvironment",
    tag = "environments",
    request_body = CreateEnvironmentRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = EnvironmentView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Tenant not found", body = ErrorBody),
        (status = 409, description = "Parent tenant is not active (suspended or offboarded)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_environment(
    State(state): State<AdminState>,
    principal: Principal,
    Path(tenant_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(&tenant_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    // Replay BEFORE the parent-existence precondition, so a genuine replay
    // returns the original response even if the tenant was soft-deleted meanwhile.
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The tenant must exist and be live; a clean 404 rather than a foreign-key
    // error (a soft-deleted tenant reads as absent).
    state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .get(&tenant)
        .await?;

    let request: CreateEnvironmentRequest = parse_json(&body)?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;
    // Parse the typed kind: an unknown value is rejected (a plain 400), never
    // coerced to a default, so a typo can never create a mis-typed environment.
    let kind = EnvironmentType::parse(&request.kind)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let custom_domain = normalize_custom_domain(request.custom_domain.as_deref());

    // Validate the environment's guardrails BEFORE any write: a production
    // environment with no configured custom domain fails structurally, listing
    // each failed guardrail (issue #42). A well-formed request that satisfies the
    // guardrails proceeds.
    let guardrails = kind.guardrails();
    let mut report = GuardrailReport::new();
    report.check(guardrails.check_custom_domain(custom_domain.as_deref()));
    if !report.is_clean() {
        return Err(ApiError::GuardrailViolation(report.into_violations()));
    }

    // Residency (issue #46): a present region must be one of the operator's
    // configured regions (the same set the tenant home_region validates against),
    // checked BEFORE any write. A blank value is treated as omitted. A deployment
    // with no region set rejects any region fail closed.
    let region = request
        .region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if let Some(region) = region.as_deref() {
        if !state.region_is_allowed(region) {
            return Err(ApiError::BadRequest(format!(
                "region {region:?} is not one of the operator's configured data-residency regions"
            )));
        }
    }

    let created_at_micros = state.now_unix_micros();
    let environment_id = EnvironmentId::generate(state.env());
    let scope = Scope::new(tenant, environment_id);
    // The environment's day-one signing key, generated here (the entropy seam) and
    // provisioned in the same transaction as the environment.
    let signing_key = DayOneSigningKey::generate(state.env(), &scope);

    let view = EnvironmentView {
        id: environment_id.to_string(),
        tenant_id: tenant.to_string(),
        display_name: display_name.clone(),
        region: region.clone(),
        kind: kind.as_str().to_owned(),
        guardrail_class: kind.guardrail_class().as_str().to_owned(),
        custom_domain: custom_domain.clone(),
        guardrails: guardrails.into(),
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
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .environments(tenant)
        .create(
            state.env(),
            &environment_id,
            created_at_micros,
            NewEnvironment {
                display_name: &display_name,
                kind,
                custom_domain: custom_domain.as_deref(),
                region: region.as_deref(),
            },
            signing_key.as_new(created_at_micros),
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // The parent tenant exists and is visible to the control plane but is NOT
        // active (suspended, or in the offboarding grace/terminal state), so it must
        // not gain a fresh, unfenced environment (issue #46): a loud 409, distinct
        // from the anti-oracle 404 an absent tenant returns.
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "parent tenant is not active; a suspended or offboarded tenant cannot gain \
             a new environment"
                .to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// List environments under a tenant (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments",
    operation_id = "listEnvironments",
    tag = "environments",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of environments", body = EnvironmentList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_environments(
    State(state): State<AdminState>,
    principal: Principal,
    Path(tenant_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    principal.require_operator()?;
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(&tenant_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .environments(tenant)
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = EnvironmentList {
        items: rows.into_iter().map(EnvironmentView::from).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one environment. Reachable by the operator or a management key scoped to
/// exactly this `(tenant, environment)`.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}",
    operation_id = "getEnvironment",
    tag = "environments",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment", body = EnvironmentView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Credential presented against the wrong environment or plane", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
pub async fn get_environment(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(&tenant_id)?;
    let environments = state.store().management().environments(tenant);
    let environment = environments.parse_id(&environment_id)?;
    // The LOUD wrong-scope behavior: a management key against another environment
    // or tenant fails naming expected vs actual. The operator passes.
    principal.require_environment(tenant, environment)?;
    // The UNIFORM not-found behavior: an environment of another tenant (the
    // tenant filter) is indistinguishable from an absent one.
    let record = environments.get(&environment).await?;
    let body =
        serde_json::to_string(&EnvironmentView::from(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Deactivate an environment (soft delete; idempotent).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}",
    operation_id = "deleteEnvironment",
    tag = "environments",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deactivated (idempotent)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or already deactivated)", body = ErrorBody)
    )
)]
pub async fn delete_environment(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let actor = principal.require_operator()?;
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(&tenant_id)?;
    let environment: EnvironmentId = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(&environment_id)?;
    // Sudo mutation gate (issue #73): deleting an environment is an environment-scoped
    // mutation. Gate before the delete write so a challenge leaves nothing removed.
    crate::sudo::require_fresh_privilege(&state, Scope::new(tenant, environment), actor).await?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .environments(tenant)
        .delete(state.env(), &environment)
        .await?;
    Ok(no_content())
}
