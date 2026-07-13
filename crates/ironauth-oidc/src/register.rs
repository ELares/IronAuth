// SPDX-License-Identifier: MIT OR Apache-2.0

//! The minimal hosted registration page (`GET`/`POST /register`, issue #20).
//!
//! It renders an identifier and password form (the target of `prompt=create`) and,
//! on submit, hashes the password with Argon2id at the OWASP defaults and creates
//! the account. There is NO email verification yet (that is a later milestone). On
//! success it auto-establishes a session and resumes the authorization request, so
//! a newly registered user flows straight on to consent. A duplicate identifier
//! re-renders the form with a generic "already registered" message.

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{ActorRef, CorrelationId, HumanId, StoreError};
use serde::Deserialize;

use crate::authn::AuthenticationEvent;
use crate::interaction::{self, parse_resume};
use crate::login::ResumeQuery;
use crate::pages;
use crate::password;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The minimum bootstrap password length. The full password policy (breach
/// screening, composition, and the rest) is M7; the bootstrap enforces only a
/// floor so a trivially short password cannot be registered.
const MIN_PASSWORD_LEN: usize = 8;

/// The posted registration form.
#[derive(Deserialize)]
pub struct RegisterForm {
    /// The desired login handle.
    pub identifier: Option<String>,
    /// The chosen password (never logged or echoed).
    pub password: Option<String>,
    /// The authorization URL to resume at.
    pub return_to: Option<String>,
}

/// `GET /register`: render the registration form for a valid resume target.
pub async fn register_get(Query(query): Query<ResumeQuery>) -> Response {
    match parse_resume(query.return_to.as_deref()) {
        Some(resume) => pages::secure_html(
            StatusCode::OK,
            pages::register_page("", &resume.return_to, None),
        ),
        None => interaction::invalid_link_page(),
    }
}

/// `POST /register`: create the account, then auto-establish a session and resume.
pub async fn register_post(
    State(state): State<OidcState>,
    Form(form): Form<RegisterForm>,
) -> Response {
    let Some(resume) = parse_resume(form.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };
    let identifier = form
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let password = form.password.as_deref().unwrap_or_default();

    if identifier.is_empty() {
        return register_error(identifier, &resume.return_to, "An identifier is required.");
    }
    if password.len() < MIN_PASSWORD_LEN {
        return register_error(
            identifier,
            &resume.return_to,
            "The password must be at least 8 characters.",
        );
    }

    let Ok(password_hash) = password::hash_password(state.env(), password) else {
        return interaction::server_error_page();
    };

    // A fresh human actor for the self-registration audit; the audit target is the
    // new user id, so the created account is still identified.
    let actor = ActorRef::human(HumanId::generate(state.env()));
    let result = state
        .store()
        .scoped(resume.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .register(state.env(), identifier, &password_hash)
        .await;

    match result {
        Ok(user_id) => {
            let subject = user_id.to_string();
            let session_actor = interaction::user_actor(&user_id);
            // Registration authenticates the new user with the password they just
            // set: a `pwd` authentication event at the current clock instant.
            let event = AuthenticationEvent::password(epoch_micros(state.now()));
            match interaction::establish_session(
                &state,
                resume.scope,
                &subject,
                &event,
                session_actor,
            )
            .await
            {
                Ok(cookie) => interaction::redirect_setting_cookie(&resume.return_to, &cookie),
                Err(_) => interaction::server_error_page(),
            }
        }
        Err(StoreError::Conflict) => register_error(
            identifier,
            &resume.return_to,
            "That identifier is already registered.",
        ),
        Err(_) => interaction::server_error_page(),
    }
}

/// Re-render the registration form with an error, prefilling the identifier.
fn register_error(identifier: &str, return_to: &str, message: &str) -> Response {
    pages::secure_html(
        StatusCode::OK,
        pages::register_page(identifier, return_to, Some(message)),
    )
}
