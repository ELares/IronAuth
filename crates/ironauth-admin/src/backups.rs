// SPDX-License-Identifier: MIT OR Apache-2.0

//! The on-demand backup endpoint (issue #153): an operator asks, the request is audited,
//! and the scheduled backup runner is woken.
//!
//! The platform's backups are SCHEDULED; this endpoint is the "now" half. Its contract is
//! deliberately narrow:
//!
//! - The request is an AUDITED record: who asked, when, and with which idempotency key,
//!   written in one transaction. That record is the durable command - a request issued
//!   while the scheduler is down is honoured by the next boot's first pass.
//! - The response is `202` BEFORE any backup exists, because the endpoint enqueues rather
//!   than performs: a count or a status here would describe a pass that has not run.
//!   Watching for the result is the backup metrics' job (`ironauth_backup_success_total`,
//!   `ironauth_backup_last_success_timestamp_seconds`), not this endpoint's.
//! - The in-process runner, when one is running, is woken immediately so the "now" is
//!   actually now rather than "within the next interval".

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{CorrelationId, Scope, TenantId};

/// Parse and fence the `(tenant, environment)` path pair, the same resolution every
/// environment-scoped endpoint uses.
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
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    Ok((tenant, Scope::new(tenant, environment)))
}
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::org_context::require_live_environment;
use crate::response::json;
use crate::state::AdminState;

/// The accepted response: the request is queued, not performed.
#[derive(Debug, Serialize, ToSchema)]
pub struct BackupRequestAccepted {
    /// Whether the request was recorded as an audited admin-action row.
    pub recorded: bool,
    /// The unix-micros instant the request was accepted.
    pub requested_at_unix_micros: i64,
}

/// Trigger an on-demand encrypted backup.
///
/// The request is audited and the runner is woken; the backup itself is performed by the
/// next available pass and watched through the backup metrics.
///
/// # Errors
///
/// [`ApiError`] on an unauthorized or malformed request; the documented statuses map
/// from the handler's fence and store calls.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/backups",
    operation_id = "triggerBackup",
    tag = "backups",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 202, description = "The request was recorded and the runner was woken; the backup itself is watched through the backup metrics", body = BackupRequestAccepted),
        (status = 400, description = "The Idempotency-Key header is absent", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn trigger_backup(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (_tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Delegated administration (issue #102): classified `management.write_config`, and
    // sudo-fenced. Requesting a backup causes outbound traffic carrying the primary store
    // to a third-party bucket, which is a larger act than reading configuration.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    let actor = principal.actor();
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    require_live_environment(&state, &scope).await?;

    let key = idempotency::required_key(&headers)?;
    // Fingerprinted over the path alone, because this command HAS no body: the request is
    // "back up now", and the environment is in the path, so two requests for different
    // environments already fingerprint differently.
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let requested_at_unix_micros = state.now_unix_micros();
    let body_string = serde_json::to_string(&BackupRequestAccepted {
        recorded: true,
        requested_at_unix_micros,
    })
    .map_err(|_| ApiError::Internal)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .backup_requests()
        .request_backup(
            state.env(),
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 202,
                response_body: &body_string,
            }),
        )
        .await?;

    // The latency half: wake the runner the moment the request lands. A runner that is
    // down (or a state without one) records and answers all the same; the audited row IS
    // the durable command.
    if let Some(trigger) = state.backup_trigger() {
        trigger.signal();
    }

    Ok(json(StatusCode::ACCEPTED, body_string))
}
