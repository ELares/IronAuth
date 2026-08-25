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
//! has ever mailed, which is the plaintext column 0154 refused to add. The blind index is
//! returned instead: it correlates a message with the suppression list and with the
//! `message.rate_limited` feed, which is what an operator actually needs to answer "why did
//! this person stop receiving mail", and it identifies nobody who is not already known.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::MessageId;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::resolve_scope;
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
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
