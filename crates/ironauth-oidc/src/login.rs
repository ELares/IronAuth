// SPDX-License-Identifier: MIT OR Apache-2.0

//! The minimal hosted login page (`GET`/`POST /login`, issue #20).
//!
//! It renders an identifier and password form and, on submit, verifies the
//! password against the stored Argon2id hash. On success it establishes a
//! bootstrap session (the `__Host-` cookie) and sends the user back to the
//! authorization request they came from (`return_to`). A failed attempt re-renders
//! the form with a GENERIC error (never distinguishing a wrong password from an
//! unknown account), and an unknown account still spends a full Argon2id
//! verification so the endpoint is not a user-enumeration oracle.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;

use crate::authn::AuthenticationEvent;
use crate::interaction::{self, parse_resume};
use crate::pages;
use crate::password;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The `return_to` carried on the `GET /login` query.
#[derive(Deserialize)]
pub struct ResumeQuery {
    /// The authorization URL to resume at after a successful sign-in.
    pub return_to: Option<String>,
}

/// The posted login form.
#[derive(Deserialize)]
pub struct LoginForm {
    /// The login handle.
    pub identifier: Option<String>,
    /// The password (never logged or echoed).
    pub password: Option<String>,
    /// The authorization URL to resume at.
    pub return_to: Option<String>,
}

/// `GET /login`: render the sign-in form for a valid resume target. The
/// `login_hint` carried on the resuming authorization request prefills the
/// identifier field (escaped into the attribute by the page), and the `display` /
/// `ui_locales` hints shape the page shell (issue #16).
pub async fn login_get(
    State(state): State<OidcState>,
    Query(query): Query<ResumeQuery>,
) -> Response {
    match parse_resume(query.return_to.as_deref()) {
        Some(resume) => {
            // The environment-kind chrome (issue #42): a non-production environment
            // marks the page noindex and shows a visible banner; prod shows neither.
            let banner = state.environment_banner(&resume.scope).await;
            pages::secure_html(
                StatusCode::OK,
                pages::login_page(
                    resume.hints.login_hint().unwrap_or_default(),
                    &resume.return_to,
                    None,
                    &resume.hints,
                    banner,
                ),
            )
        }
        None => interaction::invalid_link_page(),
    }
}

/// `POST /login`: verify the password and, on success, establish a session and
/// resume the authorization request.
pub async fn login_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(resume) = parse_resume(form.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };

    // CSRF defense-in-depth (issue #196), BEFORE verifying the password or creating
    // a session: the SameSite=Lax session cookie the login establishes blocks the
    // standard cross-site auto-submit on later POSTs, and this Origin +
    // Sec-Fetch-Site allowlist closes the two residuals it leaves (the Chromium
    // Lax+POST window and non-enforcing legacy clients) on the login POST itself. A
    // conclusively cross-site POST is refused with a generic 403; no session is
    // created and no password work is spent.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }

    let identifier = form
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let password = form.password.as_deref().unwrap_or_default();

    // The environment-kind chrome (issue #42) for a re-rendered failure page.
    let banner = state.environment_banner(&resume.scope).await;

    let lookup = state
        .store()
        .scoped(resume.scope)
        .users()
        .by_identifier(identifier)
        .await;

    match lookup {
        Ok(Some(user)) if password::verify_password(password, &user.password_hash) => {
            let actor = interaction::user_actor(&user.id);
            let subject = user.id.to_string();
            // The recorded authentication event: a password login (RFC 8176
            // `pwd`) at the current clock instant. The ID token's auth_time, amr,
            // and acr all derive from it (issue #14).
            let event = AuthenticationEvent::password(epoch_micros(state.now()));
            // Session-fixation defense (issue #32): establish_session rotates away
            // any session the browser already presented (read from `headers`),
            // invalidating it in the same transaction as the fresh one.
            match interaction::establish_session(
                &state,
                resume.scope,
                &subject,
                &event,
                actor,
                &headers,
            )
            .await
            {
                Ok(cookie) => interaction::redirect_setting_cookie(&resume.return_to, &cookie),
                Err(_) => interaction::server_error_page(),
            }
        }
        // Present but wrong password: generic failure (no wrong-password oracle).
        Ok(Some(_)) => failed_login_page(identifier, &resume.return_to, &resume.hints, banner),
        // Absent account: spend comparable Argon2id time, then the SAME generic
        // failure (no user-enumeration oracle).
        Ok(None) => {
            let _ = password::verify_absent(password);
            failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
        }
        Err(_) => interaction::server_error_page(),
    }
}

/// Re-render the login form with a generic failure message, prefilling the
/// SUBMITTED identifier. The message never distinguishes a wrong password from an
/// unknown account.
fn failed_login_page(
    identifier: &str,
    return_to: &str,
    hints: &crate::hints::InteractionHints,
    environment_banner: Option<&str>,
) -> Response {
    pages::secure_html(
        StatusCode::OK,
        pages::login_page(
            identifier,
            return_to,
            Some("Incorrect identifier or password."),
            hints,
            environment_banner,
        ),
    )
}
