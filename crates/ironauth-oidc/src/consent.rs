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
use crate::util::epoch_micros;

/// A client's consent mode (issue #21): how the authorization endpoint decides
/// whether to prompt for consent, skip it, or honor a remembered decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentMode {
    /// Always prompt unless a covering consent is recorded (the default, and the
    /// value an unrecognized stored `consent_mode` degrades to).
    Explicit,
    /// Trusted first-party: never prompt, auto-grant. This is the `offline_access`
    /// consent carve-out.
    Implicit,
    /// Prompt, then honor the recorded consent for the remembered-consent TTL
    /// before re-prompting.
    Remembered,
}

impl ConsentMode {
    /// Parse a stored `consent_mode` string. An unrecognized value degrades to
    /// [`ConsentMode::Explicit`] (the safe default: always prompt).
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw {
            "implicit" => ConsentMode::Implicit,
            "remembered" => ConsentMode::Remembered,
            _ => ConsentMode::Explicit,
        }
    }
}

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

    // CSRF defense-in-depth (issue #196), BEFORE recording consent: the SameSite=Lax
    // session cookie blocks the standard cross-site auto-submit, and this Origin +
    // Sec-Fetch-Site allowlist closes the two residuals it leaves (the Chromium
    // Lax+POST window and non-enforcing legacy clients). A conclusively cross-site
    // POST is refused with a generic 403 and records nothing.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }

    if form.decision.as_deref() == Some("allow") {
        let actor = interaction::subject_actor(&state, resume.scope, &auth.subject);
        let client_id = resume.client_id.to_string();
        // A remembered-mode client's consent lapses after the configured TTL, so it
        // re-prompts on a later authorization (issue #21). Explicit and implicit
        // clients record a never-expiring consent. An unreadable client degrades to
        // a never-expiring consent (the safe default).
        let expires_at = remembered_expiry(&state, resume.scope, &resume.client_id).await;
        let result = state
            .store()
            .scoped(resume.scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .consents()
            .grant_with_expiry(
                state.env(),
                &auth.subject,
                &client_id,
                resume.oauth_scope.as_deref(),
                expires_at,
            )
            .await;
        match result {
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

/// The expiry (epoch microseconds) to record for a consent, by the client's mode
/// (issue #21): a `remembered` client's consent expires after the configured TTL;
/// an `explicit` or `implicit` client's consent never expires. An unreadable
/// client (a race, or a deletion) degrades to a never-expiring consent.
async fn remembered_expiry(
    state: &OidcState,
    scope: ironauth_store::Scope,
    client_id: &ironauth_store::ClientId,
) -> Option<i64> {
    let record = state
        .store()
        .scoped(scope)
        .clients()
        .get(client_id)
        .await
        .ok()?;
    if ConsentMode::parse(&record.consent_mode) == ConsentMode::Remembered {
        let now = state.now();
        let expiry = now
            .checked_add(state.remembered_consent_ttl())
            .unwrap_or(now);
        Some(epoch_micros(expiry))
    } else {
        None
    }
}
