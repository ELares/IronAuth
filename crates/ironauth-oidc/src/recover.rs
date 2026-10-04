// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hosted recovery form fields and scanner-safe cancellation.
//! Request issuance and credential completion live in the `password_reset` modules.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;

use crate::interaction;
use crate::pages;
use crate::state::OidcState;

/// The posted recovery form.
#[derive(Deserialize)]
pub struct RecoverForm {
    /// The identifier to recover.
    pub identifier: Option<String>,
    /// The authorization URL to resume at after recovery (carries the scope).
    pub return_to: Option<String>,
    /// The proof-of-work challenge id the client solved (issue #80), when a challenge is
    /// required on the reset surface.
    pub pow_challenge_id: Option<String>,
    /// The proof-of-work nonce (base64url no-pad) the client found (issue #80).
    pub pow_nonce: Option<String>,
    /// The request context the challenge was issued for (issue #80), echoed back.
    pub pow_context: Option<String>,
    /// An external adapter (Turnstile/reCAPTCHA) response token (issue #80).
    pub pow_token: Option<String>,
}

/// The query carrying a recovery cancellation token on the notification link.
#[derive(Deserialize)]
pub struct CancelTokenQuery {
    /// The high-entropy cancellation token from the notification link.
    pub token: Option<String>,
}

/// `GET /recover/cancel`: render the cancellation CONFIRM page for a recovery
/// notification link (issue #81). Scanner-safe: a prefetching GET renders this page but
/// NEVER cancels; the user must POST the token back to actually revoke the pending
/// recovery.
pub async fn recover_cancel_get(
    State(state): State<OidcState>,
    Query(query): Query<CancelTokenQuery>,
) -> Response {
    let Some(token) = query.token.as_deref().filter(|token| !token.is_empty()) else {
        return interaction::invalid_link_page();
    };
    // Resolve the token BEFORE offering the button. The POST is deliberately UNIFORM,
    // because it is the destructive step and that uniformity is its anti-enumeration
    // property, so without this check a user following a STALE cancellation link pressed
    // the button and got the identical "we have cancelled it" acknowledgment as a real
    // cancellation. They would then believe they had stopped an account-recovery attempt
    // that was in fact still running, which is the worst thing this page can tell someone
    // who suspects an attacker is resetting their password.
    //
    // A pure read that shares the cancel's own predicate, so the page cannot offer a button
    // the POST would refuse. It does not cancel, so a mail scanner prefetching the link
    // still cannot stop a legitimate recovery.
    //
    // The POST is untouched and stays uniform: this decides whether to OFFER the action,
    // not whether to perform it.
    if !crate::recovery::cancel_token_is_live(&state, token).await {
        return interaction::invalid_link_page();
    }
    pages::secure_html(
        StatusCode::OK,
        pages::recover_cancel_page("/recover/cancel", token),
    )
}

/// The posted cancellation form.
#[derive(Deserialize)]
pub struct CancelForm {
    /// The high-entropy cancellation token to revoke the pending recovery with.
    pub token: Option<String>,
}

/// `POST /recover/cancel`: revoke a pending recovery from its notification-link token
/// (issue #81). Valid, invalid and repeated tokens share the acknowledgment after
/// successful store access. A persistence failure returns retryable unavailability
/// instead of claiming cancellation. Hosted cases queue a terminal owner notice.
pub async fn recover_cancel_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Response {
    // CSRF defense-in-depth (issue #196): a conclusively cross-site POST is a generic 403.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let token = form.token.as_deref().unwrap_or_default();
    // Uniform: a valid or invalid token both return the same acknowledgment.
    if crate::recovery::cancel_from_token_result(&state, token)
        .await
        .is_err()
    {
        return pages::secure_html(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::notice_page(
                "Unable to confirm cancellation",
                "Please retry this cancellation link. We could not confirm that the recovery request was cancelled.",
            ),
        );
    }
    pages::secure_html(
        StatusCode::OK,
        pages::notice_page(
            "Recovery cancelled",
            "If a recovery request was pending, it has been cancelled. A security notice \
             will be attempted through the configured delivery service.",
        ),
    )
}
