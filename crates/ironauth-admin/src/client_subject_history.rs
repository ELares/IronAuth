// SPDX-License-Identifier: MIT OR Apache-2.0
//! Legacy identity reconciliation. PUT operations are retryable and audited;
//! completion verifies retained coverage independently of supplied page cursors.
use crate::{
    auth::{ManagementPermission, Principal},
    error::{ApiError, ErrorBody},
    input::parse_json,
    org_context::resolve_scope,
    response::json,
    state::AdminState,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ironauth_store::{
    ActorRef, ClientSubjectHistoryAttestation, ClientSubjectHistoryReport,
    ClientSubjectPolicySnapshot, CorrelationId, Scope, UserId,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Retained coverage and any durable reconciliation receipt. Zero missing rows
/// does not prove complete external history or full pairwise privacy.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSubjectHistoryView {
    pub revision: i64,
    pub history_ready: bool,
    pub retained_users: i64,
    pub missing_bindings: i64,
    pub conflicting_bindings: i64,
    /// Operator-supplied SHA-256 of retained external evidence, not server verification.
    pub evidence_sha256: Option<String>,
    pub reconciled_at_unix_micros: Option<i64>,
}
impl From<ClientSubjectHistoryReport> for ClientSubjectHistoryView {
    fn from(r: ClientSubjectHistoryReport) -> Self {
        Self {
            revision: r.revision,
            history_ready: r.ready,
            retained_users: r.retained_users,
            missing_bindings: r.missing_bindings,
            conflicting_bindings: r.conflicting_bindings,
            evidence_sha256: r.evidence_sha256,
            reconciled_at_unix_micros: r.reconciled_at_unix_micros,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackfillClientSubjectHistoryRequest {
    pub expected_revision: i64,
    /// Opaque `next_cursor` from the previous page; absent for the first page.
    pub cursor: Option<String>,
    /// Positive page size, capped by management configuration and 500.
    pub limit: Option<u32>,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSubjectHistoryPageView {
    pub scanned: usize,
    pub inserted: u64,
    pub next_cursor: Option<String>,
}
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportClientSubjectHistoryRequest {
    pub expected_revision: i64,
    /// 1..=500 scoped account IDs from relying-party evidence, including deleted
    /// accounts if they still exist. Duplicates collapse; external values cannot be supplied.
    pub user_ids: Vec<String>,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSubjectHistoryImportView {
    pub inserted: u64,
}
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconcileClientSubjectHistoryRequest {
    pub expected_revision: i64,
    /// Lowercase hex SHA-256 of an operator-held evidence artifact. No URL is fetched.
    pub evidence_sha256: String,
    /// Must explicitly be true: every legacy issuer is stopped.
    pub legacy_issuers_stopped: bool,
    /// Must explicitly be true: audit-only and external actor identities are reconciled.
    pub external_history_reconciled: bool,
    /// Must explicitly be true: recovered public IDs remain a privacy exception.
    pub public_identifiers_retained: bool,
}

fn response<T: Serialize>(value: &T) -> Result<Response, ApiError> {
    Ok(json(
        StatusCode::OK,
        serde_json::to_string(value).map_err(|_| ApiError::Internal)?,
    ))
}
async fn mutation(
    state: &AdminState,
    principal: &Principal,
    tenant: &str,
    environment: &str,
    client: &str,
) -> Result<(Scope, ActorRef, ClientSubjectPolicySnapshot), ApiError> {
    let (scope, actor) = resolve_scope(state, principal, tenant, environment).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(state, scope, actor).await?;
    let expected = crate::client_subjects::current(state, scope, client).await?;
    Ok((scope, actor, expected))
}
fn revision(expected: &ClientSubjectPolicySnapshot, revision: i64) -> Result<(), ApiError> {
    if expected.revision != revision {
        return Err(ApiError::Conflict(
            "client policy changed; read it again before retrying".to_owned(),
        ));
    }
    Ok(())
}
fn decode_cursor(
    raw: &str,
    expected: &ClientSubjectPolicySnapshot,
    scope: Scope,
) -> Result<UserId, ApiError> {
    let bad = || ApiError::BadRequest("invalid or stale history cursor".to_owned());
    if raw.len() > 1024 {
        return Err(bad());
    }
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| bad())?;
    let (version, client, revision, user): (u8, String, i64, String) =
        serde_json::from_slice(&bytes).map_err(|_| bad())?;
    if version != 1 || client != expected.client_id.to_string() || revision != expected.revision {
        return Err(bad());
    }
    UserId::parse_in_scope(&user, &scope).map_err(|_| bad())
}

/// Inspect retained identity coverage and the reconciliation receipt.
#[utoipa::path(get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/subject-history",
    operation_id = "getClientSubjectHistory", tag = "client-subjects",
    params(("tenant_id" = String, Path), ("environment_id" = String, Path), ("client_id" = String, Path)),
    security(("bearer" = [])), responses(
        (status=200, description="Retained coverage; not proof of complete external history", body=ClientSubjectHistoryView),
        (status=401, description="Invalid credential", body=ErrorBody),
        (status=403, description="Wrong scope or permission", body=ErrorBody),
        (status=404, description="Absent, foreign or deleted resource", body=ErrorBody))
)]
pub async fn get_client_subject_history(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant, environment, client)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _) = resolve_scope(&state, &principal, &tenant, &environment).await?;
    principal.require_permission(ManagementPermission::Read)?;
    let expected = crate::client_subjects::current(&state, scope, &client).await?;
    let report = state
        .store()
        .management()
        .client_subject_history(scope)
        .get(&expected.client_id)
        .await?;
    response(&ClientSubjectHistoryView::from(report))
}

/// Recover one bounded page. Repeating a page preserves bindings and records an attempt.
#[utoipa::path(put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/subject-history/backfill",
    operation_id = "backfillClientSubjectHistory", tag = "client-subjects", request_body=BackfillClientSubjectHistoryRequest,
    params(("tenant_id" = String, Path), ("environment_id" = String, Path), ("client_id" = String, Path)),
    security(("bearer" = [])), responses(
        (status=200, description="Bounded recovery page; readiness is unchanged", body=ClientSubjectHistoryPageView),
        (status=400, description="Invalid cursor or page size", body=ErrorBody),
        (status=401, description="Invalid credential or fresh privilege required", body=ErrorBody),
        (status=403, description="Wrong scope or permission", body=ErrorBody),
        (status=404, description="Absent, foreign or deleted resource", body=ErrorBody),
        (status=409, description="Stale revision or non-public policy", body=ErrorBody))
)]
pub async fn backfill_client_subject_history(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant, environment, client)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor, expected) =
        mutation(&state, &principal, &tenant, &environment, &client).await?;
    let request: BackfillClientSubjectHistoryRequest = parse_json(&body)?;
    revision(&expected, request.expected_revision)?;
    let limit = request
        .limit
        .unwrap_or(state.default_page_size())
        .min(state.max_page_size())
        .min(500);
    if limit == 0 {
        return Err(ApiError::BadRequest("limit must be positive".to_owned()));
    }
    let after = request
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c, &expected, scope))
        .transpose()?;
    let page = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .client_subject_history(scope)
        .backfill(state.env(), &expected, after.as_ref(), limit)
        .await?;
    let next_cursor = page
        .next_user
        .map(|user| {
            serde_json::to_vec(&(
                1_u8,
                expected.client_id.to_string(),
                expected.revision,
                user.to_string(),
            ))
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        })
        .transpose()
        .map_err(|_| ApiError::Internal)?;
    response(&ClientSubjectHistoryPageView {
        scanned: page.scanned,
        inserted: page.inserted,
        next_cursor,
    })
}

/// Add public bindings from an explicit relying-party roster. Repeated rows are safe.
#[utoipa::path(put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/subject-history/bindings",
    operation_id = "importClientSubjectHistory", tag = "client-subjects", request_body=ImportClientSubjectHistoryRequest,
    params(("tenant_id" = String, Path), ("environment_id" = String, Path), ("client_id" = String, Path)),
    security(("bearer" = [])), responses(
        (status=200, description="Recovered public bindings; retries do not overwrite identities", body=ClientSubjectHistoryImportView),
        (status=400, description="Invalid body or batch size", body=ErrorBody),
        (status=401, description="Invalid credential or fresh privilege required", body=ErrorBody),
        (status=403, description="Wrong scope or permission", body=ErrorBody),
        (status=404, description="Absent, foreign or deleted scope, client or unknown user", body=ErrorBody),
        (status=409, description="Stale/non-public/ready client or conflicting identity", body=ErrorBody))
)]
pub async fn import_client_subject_history(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant, environment, client)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor, expected) =
        mutation(&state, &principal, &tenant, &environment, &client).await?;
    let request: ImportClientSubjectHistoryRequest = parse_json(&body)?;
    revision(&expected, request.expected_revision)?;
    if request.user_ids.is_empty() || request.user_ids.len() > 500 {
        return Err(ApiError::BadRequest(
            "user_ids must contain 1 to 500 accounts".to_owned(),
        ));
    }
    let users: Vec<UserId> = request
        .user_ids
        .iter()
        .map(|u| UserId::parse_in_scope(u, &scope).map_err(|_| ApiError::NotFound))
        .collect::<Result<_, _>>()?;
    let inserted = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .client_subject_history(scope)
        .import_public(state.env(), &expected, &users)
        .await?;
    response(&ClientSubjectHistoryImportView { inserted })
}

/// Commit an explicit reconciliation receipt. This enables a later policy change,
/// not an automatic switch. All retained history is rechecked, independent of cursors.
#[utoipa::path(put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/subject-history/reconciliation",
    operation_id = "reconcileClientSubjectHistory", tag = "client-subjects", request_body=ReconcileClientSubjectHistoryRequest,
    params(("tenant_id" = String, Path), ("environment_id" = String, Path), ("client_id" = String, Path)),
    security(("bearer" = [])), responses(
        (status=200, description="Durable receipt and new policy revision", body=ClientSubjectHistoryView),
        (status=400, description="Missing attestations or invalid evidence digest", body=ErrorBody),
        (status=401, description="Invalid credential or fresh privilege required", body=ErrorBody),
        (status=403, description="Wrong scope or permission", body=ErrorBody),
        (status=404, description="Absent, foreign or deleted resource", body=ErrorBody),
        (status=409, description="Incomplete/conflicting history, stale policy or already reconciled", body=ErrorBody))
)]
pub async fn reconcile_client_subject_history(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant, environment, client)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor, expected) =
        mutation(&state, &principal, &tenant, &environment, &client).await?;
    let request: ReconcileClientSubjectHistoryRequest = parse_json(&body)?;
    revision(&expected, request.expected_revision)?;
    let attestation = ClientSubjectHistoryAttestation {
        evidence_sha256: request.evidence_sha256,
        legacy_issuers_stopped: request.legacy_issuers_stopped,
        external_history_reconciled: request.external_history_reconciled,
        public_identifiers_retained: request.public_identifiers_retained,
    };
    let report = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .client_subject_history(scope)
        .reconcile(state.env(), &expected, &attestation)
        .await?;
    response(&ClientSubjectHistoryView::from(report))
}
