// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-message delivery status (issue #111 criterion 1).
//!
//! The criterion asks that "per-message status and resend are available via API". This is the
//! STATUS half. It answers the question the `messages` ledger was built for, quoted from
//! migration 0154: "what an operator needs to answer 'did this send, and if not why'".
//!
//! # Why this half needs no plane decision and the other does
//!
//! Reading is a `SELECT`, and the control plane holds exactly that on `messages` (0154). The
//! RESEND half writes, and the control plane deliberately holds no UPDATE there --
//! `the_control_plane_cannot_enqueue_and_the_data_plane_cannot_rewrite_a_send` says why in as
//! many words: "UPDATE here makes the management surface a mailer". So resend needs the admin
//! service to reach the data plane, which is a separate change, and it is why these ship apart
//! rather than together.
//!
//! # What it does not return
//!
//! The RECIPIENT. The ledger holds a blind index and a sealed address, and the seal opens on
//! exactly one path, at the moment of delivery (`MessageRepo::open_recipient`). An operator
//! endpoint that opened it would make a support tool into a way to read every address a tenant
//! has ever mailed, which is the plaintext column 0154 refused to add.
//!
//! The blind index goes out instead. It is the key the `message.rate_limited` event carries, so
//! an operator can join a message against that feed today. It is ALSO the key
//! `message_suppressions` is stored under -- but no management API exposes that table yet, so
//! that half is what the index WILL join on when a suppression surface ships, not something a
//! caller can do now. Worth being exact, because an earlier draft claimed the correlation as a
//! present capability.
//!
//! # Scope
//!
//! ENVIRONMENT-wide, for any credential holding `management.read`. A `messages` row carries no
//! organization column, so an organization-confined delegated administrator sees the whole
//! environment's sends, exactly as it does on the event feed. That follows from the ledger's
//! shape rather than from a decision taken here: fencing it would need an organization on the
//! row first.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{MessageId, Resent};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::json;
use crate::state::AdminState;

/// One message's delivery status.
#[derive(Debug, Serialize, ToSchema)]
pub struct MessageStatusView {
    /// The `msg_` identifier.
    pub id: String,
    /// Which message this was: `email_otp`, `magic_link`, and so on.
    pub kind: String,
    /// The recipient's BLIND INDEX, hex-encoded. Never the address; see the module header.
    pub recipient_bidx: String,
    /// `pending`, `sending`, `sent` or `failed`.
    pub state: String,
    /// Why a failed delivery failed, as a classification rather than a provider response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// How many times an operator has re-queued this message. Zero for one that was only ever
    /// sent once, and the answer to "why did this person get four copies".
    pub resend_count: i32,
    /// When the send was accepted, as epoch milliseconds.
    pub created_at_unix_ms: i64,
    /// When the row last changed, as epoch milliseconds. A `failed` message with no date is
    /// half an answer: a failure ten seconds old and one from last week are different problems.
    pub updated_at_unix_ms: i64,
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/messages/{message_id}",
    operation_id = "getMessageStatus",
    tag = "messages",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("message_id" = String, Path, description = "The message identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The message's delivery status", body = MessageStatusView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such message in this scope", body = ErrorBody)
    )
)]
/// Read one message's delivery status.
///
/// # Errors
///
/// [`ApiError::NotFound`] when the identifier names no message of this scope -- including one
/// that parses but belongs to another, which is the same answer on purpose: distinguishing
/// them would confirm the existence of another tenant's message.
pub async fn get_message_status(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, message_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): a read of one message's delivery state.
    principal.require_permission(ManagementPermission::Read)?;

    // Parsed IN SCOPE, so an identifier minted for another environment is refused here rather
    // than reaching a query that would return nothing and look like an absent row.
    let id = MessageId::parse_in_scope(&message_id, &scope).map_err(|_| ApiError::NotFound)?;

    let record = state
        .store()
        .scoped(scope)
        .messages()
        .by_id(&id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    let view = MessageStatusView {
        id: record.id.to_string(),
        kind: record.kind,
        recipient_bidx: {
            use std::fmt::Write as _;
            record
                .recipient_bidx
                .iter()
                .fold(String::new(), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                })
        },
        state: record.state,
        failure_reason: record.failure_reason,
        resend_count: record.resend_count,
        created_at_unix_ms: record.created_at_unix_ms,
        updated_at_unix_ms: record.updated_at_unix_ms,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// What a resend request did.
#[derive(Debug, Serialize, ToSchema)]
pub struct ResendView {
    /// `requeued`, `suppressed`, `not_resendable` or `payload_expired`.
    pub outcome: String,
    /// Which re-queue this was, present only when the outcome is `requeued`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt: Option<i32>,
    /// Why the request was refused, present only when there is a reason to give: the
    /// suppression classification, or the state a `not_resendable` message is actually in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/messages/{message_id}/resend",
    operation_id = "resendMessage",
    tag = "messages",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("message_id" = String, Path, description = "The message identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The re-queue was attempted; the body says what happened", body = ResendView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such message in this scope", body = ErrorBody),
        (status = 503, description = "No data-plane store is wired, so no resend can be performed", body = ErrorBody)
    )
)]
/// Re-queue a terminal message for delivery.
///
/// # Why this writes through the DATA plane
///
/// `messages` grants the control role SELECT only, deliberately, and its own test says why:
/// "UPDATE here makes the management surface a mailer". The separation is kept and the work
/// moves instead: this endpoint DECIDES, and the data plane, which is the thing that mails,
/// performs it, exactly as it did for the original send. When no data-plane store is wired the
/// endpoint refuses with 503 rather than reaching for the control store, because falling back
/// would be precisely the widening the split exists to prevent.
///
/// # Why every refusal is a 200
///
/// `Suppressed`, `NotResendable` and `PayloadExpired` are ANSWERS, not errors. Each says
/// something different and actionable -- the recipient must not be mailed, the message is not
/// in a state a resend can act on, the variables have been reaped -- and collapsing them into a
/// 4xx would lose which one it was. The request was understood and acted on; the body reports
/// what happened.
///
/// # Errors
///
/// [`ApiError::NotFound`] when the identifier names no message of this scope;
/// [`ApiError::NotConfigured`] (503) when no data-plane store is wired.
pub async fn resend_message(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, message_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): re-queueing a message is a credential-adjacent
    // write, so it takes the credentials permission rather than the config one.
    principal.require_permission(ManagementPermission::WriteCredentials)?;
    // A WRITE into a decommissioned environment is refused, like every other write on this
    // surface. `resolve_scope` alone does not do it: reads of a soft-deleted environment stay
    // available on purpose (an operator still needs to see what was there), so the liveness
    // fence is the write's own. Without it this endpoint answered 200 and RE-QUEUED MAIL for
    // an environment somebody had decommissioned, which `live_surface`'s soft-delete sweep
    // caught the moment its fixture named a real message.
    require_live_environment(&state, &scope).await?;

    let id = MessageId::parse_in_scope(&message_id, &scope).map_err(|_| ApiError::NotFound)?;
    let Some(data_store) = state.data_store() else {
        // NotConfigured, which renders 503 and means exactly this: "a dependency this
        // request needs is not installed in this deployment". Not a 500, which would claim
        // the request was at fault, and not a plain refusal, which an operator would read as
        // "this message cannot be resent" and go looking at the message.
        return Err(ApiError::NotConfigured(
            "no data-plane store is wired, so no message can be re-queued".to_owned(),
        ));
    };

    let outcome = data_store
        .scoped(scope)
        .messages()
        .resend(state.env(), &id)
        .await
        .map_err(|error| match error {
            ironauth_store::StoreError::NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        })?;

    let view = match outcome {
        Resent::Requeued { attempt } => ResendView {
            outcome: "requeued".to_owned(),
            attempt: Some(attempt),
            reason: None,
        },
        Resent::Suppressed { reason } => ResendView {
            outcome: "suppressed".to_owned(),
            attempt: None,
            reason: Some(reason),
        },
        Resent::NotResendable { state } => ResendView {
            outcome: "not_resendable".to_owned(),
            attempt: None,
            reason: Some(state),
        },
        Resent::PayloadExpired => ResendView {
            outcome: "payload_expired".to_owned(),
            attempt: None,
            reason: None,
        },
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
