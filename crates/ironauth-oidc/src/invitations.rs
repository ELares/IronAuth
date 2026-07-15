// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public invitation-accept endpoint (issue #60).
//!
//! The invitee side of the admin-initiated invitation flow: a person who does not
//! yet have a session presents the single-use token they received out of band and
//! is enrolled onto a credential, which activates the pending_verification user the
//! admin provisioned (pending_verification -> active). It mounts on the PUBLIC data
//! plane (never the management port), is scope-routed under the per-environment path
//! so the redeem runs under the right row-level-security scope, and is authenticated
//! by the TOKEN itself (never a session cookie, never an admin credential).
//!
//! # Safe by construction
//!
//! - **The token is the only authenticator, matched by its digest.** A presented
//!   token is hashed and looked up by digest within scope, so a token minted in
//!   another tenant never resolves here and a database dump yields nothing
//!   replayable.
//! - **Atomic single use.** Accepting CONSUMES the invitation in one transaction (a
//!   guarded pending -> accepted flip) and activates the user in the same
//!   transaction, so a second accept and a concurrent double-accept storm redeem AT
//!   MOST ONCE: never two provisioned users, never two activations.
//! - **Uniform, non-enumerating errors.** A forged, expired, already-redeemed,
//!   revoked, or cross-scope token all collapse to the SAME uniform not-found, so the
//!   endpoint is never a token-guessing or existence oracle.
//! - **No password on a passkey invitation.** A `passkey` invitation provisions no
//!   password (the Zitadel deep-link pattern): the flow contract activates the user
//!   without a password and the concrete passkey ceremony wires in with the M7 factor
//!   issues. A `password` invitation sets an Argon2id verifier through the #20 path;
//!   the plaintext never reaches the store and is never logged.
//!
//! # No CSRF check
//!
//! Unlike the self-service account POSTs (issue #61), this endpoint carries NO
//! ambient authority: it is authenticated only by the unguessable token in the
//! request body, which a cross-site auto-submit cannot know. There is therefore no
//! cookie for a CSRF attack to ride, and the same-origin gate is intentionally
//! absent.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{CorrelationId, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::interaction;
use crate::password::hash_password;
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::{not_found, parse_scope};

/// The accept-invitation request body.
#[derive(Deserialize)]
pub struct AcceptInvitationBody {
    /// The single-use invitation token delivered to the invitee out of band. The ONLY
    /// authenticator: a token matching no pending, unexpired invitation in this scope
    /// is the uniform not-found.
    token: String,
    /// The password to set (required for a `password` invitation, ignored for a
    /// `passkey` one). Hashed to an Argon2id verifier through the entropy seam; the
    /// plaintext never reaches the store and is never logged.
    #[serde(default)]
    password: Option<String>,
}

/// `POST /t/{tenant}/e/{environment}/invitations/accept`: redeem an invitation token
/// and enroll the credential, activating the invited user (pending_verification ->
/// active). Token-authenticated (no session), atomic and single-use, with uniform
/// non-enumerating errors.
pub async fn accept_invitation(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Json(body): Json<AcceptInvitationBody>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    // A per-tenant/per-environment request-quota charge (issue #50), like the other
    // public data-plane surfaces; None when no enforcer is installed.
    if let Some(response) = state.enforce_request_quota(&scope) {
        return response;
    }
    let token = body.token.trim();
    if token.is_empty() {
        return uniform_not_found();
    }
    let now_micros = epoch_micros(state.now());

    // Resolve the presented token to its pending, unexpired invitation to learn the
    // credential type (so we know whether a password is required) BEFORE the atomic
    // redeem re-checks and consumes it. Any non-resolving token is the uniform
    // not-found (never an oracle).
    let pending = match state
        .store()
        .scoped(scope)
        .invitations()
        .resolve_pending(token, now_micros)
        .await
    {
        Ok(Some(pending)) => pending,
        Ok(None) => return uniform_not_found(),
        Err(_) => return server_error(),
    };

    // Compute the credential to set. A password invitation REQUIRES a non-empty
    // password (hashed here); a passkey invitation provisions none.
    let password_hash = if pending.credential_type.requires_password() {
        let password = body.password.as_deref().unwrap_or("");
        if password.is_empty() {
            return password_required();
        }
        match hash_password(state.env(), password) {
            Ok(hash) => Some(hash),
            Err(_) => return server_error(),
        }
    } else {
        None
    };

    let actor = interaction::user_actor(&pending.user_id);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .invitations()
        .accept(state.env(), token, password_hash.as_deref(), now_micros)
        .await;
    match result {
        Ok(accepted) => json_response(
            StatusCode::OK,
            json!({
                "accepted": true,
                "user_id": accepted.user_id.to_string(),
                "credential_type": accepted.credential_type.as_str(),
            }),
        ),
        // Lost a concurrent double-accept, the token was consumed/expired between the
        // resolve and the redeem, or the user was not pending: all uniform not-found.
        Err(StoreError::NotFound | StoreError::Conflict) => uniform_not_found(),
        Err(_) => server_error(),
    }
}

/// A JSON response at `status` with `no-store` caching (an accept response is
/// per-invitee and must never be cached by a shared proxy).
#[allow(clippy::needless_pass_by_value)]
fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// The uniform `404` for a token that matches no pending, unexpired invitation in
/// this scope (forged, expired, already-redeemed, revoked, or cross-scope): the
/// non-enumerating error the issue's uniform-error contract requires, byte-identical
/// across all those causes so the endpoint is never a token-guessing oracle.
fn uniform_not_found() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        json!({
            "error": "invalid_invitation",
            "error_description": "This invitation link is invalid or has expired.",
        }),
    )
}

/// A `400` telling a holder of a VALID password invitation that a password is
/// required. Reachable only after a valid token resolves, so it is not an
/// enumeration oracle.
fn password_required() -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({
            "error": "password_required",
            "error_description": "This invitation enrolls a password; provide one to continue.",
        }),
    )
}

/// A generic `500` that never reveals what failed.
fn server_error() -> Response {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({
            "error": "server_error",
            "error_description": "The request could not be processed.",
        }),
    )
}
