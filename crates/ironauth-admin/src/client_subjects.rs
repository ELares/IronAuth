// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scoped identity-policy administration. Sector validation precedes an audited
//! revision-checked write; the control role cannot rewrite redirects or bindings.
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ClientSubjectPolicy, ClientSubjectPolicySnapshot, CorrelationId, Scope};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::json;
use crate::state::AdminState;

/// Policy used only for a user who has not yet received a client identity.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    /// Use the local account identifier for new bindings.
    Public,
    /// Derive an environment-salted identity in the validated sector.
    Pairwise,
}

/// Current policy and its exact validation revision. Existing issued identities
/// remain stable across policy changes; a retained public binding is a legacy
/// exception to pairwise privacy.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSubjectPolicyView {
    /// Scoped registered client identifier.
    pub client_id: String,
    /// Policy for previously unbound users; existing identities remain unchanged.
    pub subject_type: SubjectType,
    /// Canonical sector hostname, or null for public policy.
    pub sector_identifier: Option<String>,
    /// Explicit validated sector document, or null for an inferred/public policy.
    pub sector_identifier_uri: Option<String>,
    /// Revision to send as `expected_revision` on a replacement request.
    pub revision: i64,
    /// False for a legacy client whose issued identities still need reconciliation.
    /// Such a client cannot activate pairwise policy.
    pub history_ready: bool,
    /// Current redirects against which this policy is validated.
    pub redirect_uris: Vec<String>,
}

impl From<ClientSubjectPolicySnapshot> for ClientSubjectPolicyView {
    fn from(snapshot: ClientSubjectPolicySnapshot) -> Self {
        let (subject_type, sector_identifier, sector_identifier_uri) = match snapshot.policy {
            ClientSubjectPolicy::Public => (SubjectType::Public, None, None),
            ClientSubjectPolicy::Pairwise {
                sector_identifier,
                sector_identifier_uri,
            } => (
                SubjectType::Pairwise,
                Some(sector_identifier),
                sector_identifier_uri,
            ),
        };
        Self {
            client_id: snapshot.client_id.to_string(),
            subject_type,
            sector_identifier,
            sector_identifier_uri,
            revision: snapshot.revision,
            history_ready: snapshot.history_ready,
            redirect_uris: snapshot.redirect_uris,
        }
    }
}

/// Replace the policy against a previously read revision. This endpoint does not
/// edit redirects, salts or issued user bindings. Public policy must not carry a
/// sector URI; pairwise policy may omit it only for a single redirect hostname.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetClientSubjectPolicyRequest {
    /// Required revision from the latest GET. A mismatch returns 409.
    pub expected_revision: i64,
    /// Required replacement policy for new identity bindings.
    pub subject_type: SubjectType,
    /// HTTPS document listing every current redirect. Required for mixed/hostless
    /// redirects under pairwise policy; absent or null for public policy.
    pub sector_identifier_uri: Option<String>,
}

async fn current(
    state: &AdminState,
    scope: Scope,
    raw: &str,
) -> Result<ClientSubjectPolicySnapshot, ApiError> {
    require_live_environment(state, &scope).await?;
    let repo = state.store().management().client_subject_policies(scope);
    let id = repo.parse_id(raw)?;
    Ok(repo.get(&id).await?)
}

fn response(snapshot: ClientSubjectPolicySnapshot) -> Result<Response, ApiError> {
    let body = serde_json::to_string(&ClientSubjectPolicyView::from(snapshot))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Read a registered client's identity policy.
#[utoipa::path(get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/subject-policy",
    operation_id = "getClientSubjectPolicy", tag = "client-subjects",
    params(("tenant_id" = String, Path), ("environment_id" = String, Path), ("client_id" = String, Path)),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Identity policy and redirect revision", body = ClientSubjectPolicyView),
        (status = 401, description = "Invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong scope or permission", body = ErrorBody),
        (status = 404, description = "Absent, malformed, foreign or deleted resource", body = ErrorBody)
    )
)]
pub async fn get_client_subject_policy(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant, environment, client)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _) = resolve_scope(&state, &principal, &tenant, &environment).await?;
    principal.require_permission(ManagementPermission::Read)?;
    response(current(&state, scope, &client).await?)
}

/// Set a registered client's policy without changing any already-issued identity.
#[utoipa::path(put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/subject-policy",
    operation_id = "setClientSubjectPolicy", tag = "client-subjects",
    request_body = SetClientSubjectPolicyRequest,
    params(("tenant_id" = String, Path), ("environment_id" = String, Path), ("client_id" = String, Path)),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Committed policy; existing bindings remain unchanged", body = ClientSubjectPolicyView),
        (status = 400, description = "Malformed metadata or refused sector document", body = ErrorBody),
        (status = 401, description = "Invalid credential or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong scope or permission", body = ErrorBody),
        (status = 404, description = "Absent, malformed, foreign or deleted resource", body = ErrorBody),
        (status = 409, description = "Policy changed or legacy identity history needs reconciliation", body = ErrorBody),
        (status = 503, description = "Sector validation unavailable", body = ErrorBody)
    )
)]
pub async fn set_client_subject_policy(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant, environment, client)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant, &environment).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // Resolve authority before inspecting attacker-controlled metadata or URLs.
    let expected = current(&state, scope, &client).await?;
    let request: SetClientSubjectPolicyRequest = parse_json(&body)?;
    if request.expected_revision != expected.revision {
        return Err(ApiError::Conflict(
            "client policy changed; read it again before retrying".to_owned(),
        ));
    }
    if matches!(request.subject_type, SubjectType::Pairwise) && !expected.history_ready {
        return Err(ApiError::Conflict(
            "reconcile legacy public identity history before enabling pairwise".to_owned(),
        ));
    }
    let policy = validate_policy(&state, request, &expected.redirect_uris).await?;
    let committed = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .client_subject_policies(scope)
        .set(state.env(), &expected, &policy)
        .await?;
    response(committed)
}

async fn validate_policy(
    state: &AdminState,
    request: SetClientSubjectPolicyRequest,
    redirects: &[String],
) -> Result<ClientSubjectPolicy, ApiError> {
    if matches!(request.subject_type, SubjectType::Public) {
        if request.sector_identifier_uri.is_some() {
            return Err(ApiError::BadRequest(
                "public policy cannot carry a sector URI".to_owned(),
            ));
        }
        return Ok(ClientSubjectPolicy::Public);
    }
    let sector = if let Some(uri) = request.sector_identifier_uri.as_deref() {
        if !ironauth_fetch::parse_target(uri)
            .is_ok_and(|target| target.scheme == ironauth_fetch::Scheme::Https)
        {
            return Err(ApiError::BadRequest(
                "sector URI must be an HTTPS URL".to_owned(),
            ));
        }
        let fetcher = state.sector_fetcher().ok_or_else(|| {
            ApiError::NotConfigured("sector validation is unavailable".to_owned())
        })?;
        ironauth_oidc::resolve_pairwise_sector(fetcher, Some(uri), redirects)
            .await
            .map_err(|_| {
                ApiError::BadRequest(
                    "sector document could not be validated against the registered redirects"
                        .to_owned(),
                )
            })?
    } else {
        ironauth_oidc::inferred_sector(redirects).ok_or_else(|| {
            ApiError::BadRequest(
                "these redirects require an explicit HTTPS sector document".to_owned(),
            )
        })?
    };
    Ok(ClientSubjectPolicy::Pairwise {
        sector_identifier: sector,
        sector_identifier_uri: request.sector_identifier_uri,
    })
}
