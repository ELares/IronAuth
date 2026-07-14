// SPDX-License-Identifier: MIT OR Apache-2.0

//! The minimal hosted consent screen (`GET`/`POST /consent`, issue #20).
//!
//! It shows the client's display name and the requested scopes, and records the
//! subject's decision. An Allow records consent (per subject and client) and
//! resumes the authorization request, so the next pass through `/authorize` finds
//! the consent and issues the code; a Deny renders a plain notice and issues no
//! code. Consent requires an authenticated session: if the cookie does not resolve
//! (expired or absent), the consent step redirects to login first.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_store::CorrelationId;
use serde::Deserialize;

use crate::interaction::{self, parse_resume};
use crate::login::ResumeQuery;
use crate::pages;
use crate::state::OidcState;

/// The posted consent decision.
#[derive(Deserialize)]
pub struct ConsentForm {
    /// The decision button pressed: `allow` or `deny`.
    pub decision: Option<String>,
    /// The authorization URL to resume at.
    pub return_to: Option<String>,
}

/// `GET /consent`: show the client and requested scopes for an authenticated
/// subject. Redirects to login if the session does not resolve.
pub async fn consent_get(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Query(query): Query<ResumeQuery>,
) -> Response {
    let Some(resume) = parse_resume(query.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };
    let cookie = interaction::cookie_header(&headers);
    if interaction::resolve_session(&state, resume.scope, cookie)
        .await
        .is_none()
    {
        return interaction::login_redirect(&resume.return_to);
    }

    let client_name = match state
        .store()
        .scoped(resume.scope)
        .clients()
        .auth_record(&resume.client_id)
        .await
    {
        Ok(record) => record.display_name,
        // The client vanished between the authorize redirect and here: treat the
        // resume link as no longer valid.
        Err(_) => return interaction::invalid_link_page(),
    };

    let scopes: Vec<&str> = resume
        .oauth_scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    pages::secure_html(
        StatusCode::OK,
        pages::consent_page(&client_name, &scopes, &resume.return_to, &resume.hints),
    )
}

/// `POST /consent`: record the decision. Allow records consent and resumes; Deny
/// renders a notice and issues no code.
pub async fn consent_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    let Some(resume) = parse_resume(form.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };
    let cookie = interaction::cookie_header(&headers);
    let Some(auth) = interaction::resolve_session(&state, resume.scope, cookie).await else {
        return interaction::login_redirect(&resume.return_to);
    };

    // CSRF: this state-changing POST currently relies on the SameSite=Lax session
    // cookie alone, which blocks the standard cross-site auto-submit but leaves a
    // narrow residual (Chromium Lax+POST window, non-enforcing legacy clients).
    // Defense-in-depth (a session-bound CSRF token or an Origin check) is a hard
    // prerequisite for enabling OIDC (#13), tracked in #196.
    if form.decision.as_deref() == Some("allow") {
        let actor = interaction::subject_actor(&state, resume.scope, &auth.subject);
        let client_id = resume.client_id.to_string();
        match state
            .store()
            .scoped(resume.scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .consents()
            .grant(
                state.env(),
                &auth.subject,
                &client_id,
                resume.oauth_scope.as_deref(),
            )
            .await
        {
            Ok(_) => interaction::redirect(&resume.return_to),
            Err(_) => interaction::server_error_page(),
        }
    } else {
        // Deny (or a missing/other decision): record nothing and issue no code.
        pages::secure_html(
            StatusCode::OK,
            pages::notice_page(
                "Access not granted",
                "You did not grant the application access.",
            ),
        )
    }
}
