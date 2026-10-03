// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded preparation of retained primary identifiers for recipient verification.
//! This changes index metadata only, never mailbox ownership or verification.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{CorrelationId, RecipientIndexReport, ResolvedIdempotencyWrite, StoreError};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::state::AdminState;

const fn default_limit() -> u32 {
    100
}

#[derive(Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct RecipientIndexQuery {
    /// Maximum retained users to inspect, from 1 through 100 (default 100).
    #[serde(default = "default_limit")]
    #[param(minimum = 1, maximum = 100, default = 100)]
    pub limit: u32,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareRecipientIndexRequest {
    /// Maximum retained users to index, from 1 through 100 (default 100).
    #[serde(default = "default_limit")]
    #[schema(minimum = 1, maximum = 100, default = 100)]
    pub limit: u32,
    /// Required acknowledgement that all identity writers support recipient indexing.
    /// The server does not attest binary versions. Older writers can make the
    /// environment incomplete again, which blocks recipient proof until repaired.
    pub all_writers_upgraded: bool,
}

#[derive(Serialize, ToSchema)]
pub struct RecipientIndexView {
    /// Whether this response describes a committed write rather than a preview.
    pub applied: bool,
    /// Retained users examined in this batch.
    pub batch_users: u32,
    /// Examined primary identifiers reserving a canonical email ownership index.
    /// This does not mean those addresses are deliverable or verified.
    pub batch_mailbox_users: u32,
    /// All retained users, including soft-deleted accounts, in this environment.
    pub total_users: i64,
    /// Retained users still lacking index metadata at the time of the transaction.
    pub unindexed_users: i64,
    /// Ambiguous mailbox groups among already indexed primary and typed emails.
    /// Further batches can reveal more ambiguity. No accounts are merged.
    pub ambiguous_indexed_mailboxes: i64,
    /// Every retained user has index metadata. This does not establish mailbox
    /// verification, delivery readiness, or the absence of ambiguous ownership.
    pub index_complete: bool,
}

impl From<&RecipientIndexReport> for RecipientIndexView {
    fn from(report: &RecipientIndexReport) -> Self {
        Self {
            applied: report.applied,
            batch_users: report.batch_users,
            batch_mailbox_users: report.batch_mailbox_users,
            total_users: report.total_users,
            unindexed_users: report.unindexed_users,
            ambiguous_indexed_mailboxes: report.ambiguous_indexed_mailboxes,
            index_complete: report.index_complete,
        }
    }
}

fn require_unconfined(principal: &Principal) -> Result<(), ApiError> {
    if principal.confined_organization().is_some() {
        return Err(ApiError::WrongScope {
            expected: "an unconfined management credential".to_owned(),
            actual: "credential confined to one organization".to_owned(),
            message: "recipient index preparation covers all retained users in the environment"
                .to_owned(),
        });
    }
    Ok(())
}

fn valid_limit(limit: u32) -> Result<(), ApiError> {
    if !(1..=100).contains(&limit) {
        return Err(ApiError::BadRequest(
            "limit must be between 1 and 100".to_owned(),
        ));
    }
    Ok(())
}

/// Preview a bounded batch by decrypting its retained primary identifiers.
/// Like other management reads, this remains available for a soft-deleted environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/recipient-verification/index",
    operation_id = "previewRecipientIndex", tag = "users",
    params(("tenant_id" = String, Path), ("environment_id" = String, Path), RecipientIndexQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Aggregate preview; no indices or verification state changed", body = RecipientIndexView),
        (status = 400, description = "Invalid batch bound or query", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Insufficient permission or wrong scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 500, description = "Unreadable stored identifier or persistence failure", body = ErrorBody)
    )
)]
pub async fn preview_recipient_index(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant, environment)): Path<(String, String)>,
    Query(query): Query<RecipientIndexQuery>,
) -> Result<Response, ApiError> {
    let (scope, _) = crate::users::resolve_scope(&state, &principal, &tenant, &environment).await?;
    // Delegated administration (issue #102): aggregate preview requires management.read.
    principal.require_permission(ManagementPermission::Read)?;
    require_unconfined(&principal)?;
    valid_limit(query.limit)?;
    let report = state
        .store()
        .scoped(scope)
        .recipient_verification()
        .index_preview(query.limit)
        .await?;
    let body = serde_json::to_string(&RecipientIndexView::from(&report))
        .map_err(|_| ApiError::Internal)?;
    Ok(crate::response::json(StatusCode::OK, body))
}

/// Prepare the next bounded batch. Retry a lost response with the same key;
/// use a new key to advance. No account is merged or marked email-verified.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/recipient-verification/index",
    operation_id = "prepareRecipientIndex", tag = "users",
    request_body = PrepareRecipientIndexRequest,
    params(("tenant_id" = String, Path), ("environment_id" = String, Path),
        ("Idempotency-Key" = String, Header, description = "Required. Replay returns the original batch response without advancing.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Index metadata, audit and response committed atomically", body = RecipientIndexView),
        (status = 400, description = "Invalid batch, missing acknowledgement or Idempotency-Key", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential; writes can require fresh privilege", body = ErrorBody),
        (status = 403, description = "Insufficient permission or wrong scope", body = ErrorBody),
        (status = 404, description = "Environment not found or not live", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody),
        (status = 500, description = "Unreadable identifier or persistence failure; batch rolled back", body = ErrorBody)
    )
)]
pub async fn prepare_recipient_index(
    State(state): State<AdminState>,
    principal: Principal,
    entry_path: crate::entry_path::DeclaredEntryPath,
    Path((tenant, environment)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) =
        crate::users::resolve_scope(&state, &principal, &tenant, &environment).await?;
    // Delegated administration (issue #102): index mutation requires management.write_users.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    require_unconfined(&principal)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    if uri.query().is_some() {
        return Err(ApiError::BadRequest(
            "this operation accepts no query parameters".to_owned(),
        ));
    }
    let request: PrepareRecipientIndexRequest = crate::input::parse_json(&body)?;
    valid_limit(request.limit)?;
    if !request.all_writers_upgraded {
        return Err(ApiError::BadRequest(
            "all_writers_upgraded must be acknowledged".to_owned(),
        ));
    }
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }
    let render =
        |report: &RecipientIndexReport| serde_json::to_string(&RecipientIndexView::from(report));
    let receipt = ResolvedIdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &render,
    };
    let event =
        |report: &RecipientIndexReport| recipient_index_prepared_event(&state, scope, report);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .via(entry_path.0)
        .recipient_verification()
        .index_backfill_with_event(state.env(), request.limit, Some(receipt), Some(&event))
        .await;
    match result {
        Ok(report) => Ok(crate::response::json(
            StatusCode::OK,
            render(&report).map_err(|_| ApiError::Internal)?,
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

fn recipient_index_prepared_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    report: &RecipientIndexReport,
) -> Option<ironauth_store::OwnedDomainEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = scope.environment().to_string();
    // Only aggregate committed counts leave this boundary, never identifiers,
    // mailbox addresses, blind indexes, challenge codes or verification proofs.
    let payload = serde_json::to_value(RecipientIndexView::from(report)).ok()?;
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "recipient_index.prepared",
        &scope.tenant().to_string(),
        &subject,
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(ironauth_store::OwnedDomainEvent {
        id,
        subject,
        envelope,
    })
}
