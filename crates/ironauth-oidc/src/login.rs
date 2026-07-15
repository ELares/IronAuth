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
use ironauth_import::ForeignHash;
use ironauth_store::{CorrelationId, Scope, UserId, UserRecord};
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
        // A user whose lifecycle state cannot authenticate (blocked, disabled, or
        // pending verification) is FENCED (issue #52): the password is still spent
        // (so a fenced account is timing-indistinguishable from a wrong password),
        // then the SAME generic failure is returned, never a distinct signal.
        Ok(Some(user)) if !user.state.can_authenticate() => {
            let _ = password::verify_password(password, &user.password_hash);
            failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
        }
        Ok(Some(user)) => {
            // Verify the native Argon2id hash first; if the account was imported with
            // a FOREIGN hash (issue #55) and has not yet logged in, the native hash is
            // the unusable sentinel, so fall through to the foreign verify.
            let native_ok = password::verify_password(password, &user.password_hash);
            let foreign_ok = !native_ok && verify_foreign(&user, password);
            if native_ok || foreign_ok {
                // First successful FOREIGN login: transparently rehash the password
                // to the native Argon2id verifier and retire the foreign hash
                // (verify-then-rehash), so the second login verifies natively. This
                // is best-effort: the login has already succeeded, so a rehash
                // failure leaves the foreign hash in place for the next login rather
                // than failing the sign-in.
                if foreign_ok {
                    rehash_foreign_credential(&state, resume.scope, &user.id, password).await;
                }
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
            } else {
                // Present but wrong password: generic failure (no wrong-password
                // oracle), whether the stored verifier is native or foreign.
                failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
            }
        }
        // Absent account: spend comparable Argon2id time, then the SAME generic
        // failure (no user-enumeration oracle).
        Ok(None) => {
            let _ = password::verify_absent(password);
            failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
        }
        Err(_) => interaction::server_error_page(),
    }
}

/// Verify `password` against a user's imported FOREIGN hash (issue #55), if it has
/// one. Returns `false` when the user carries no foreign hash or the stored value
/// cannot be parsed (fail closed). Dispatches on the hash scheme (bcrypt, scrypt,
/// PBKDF2, Argon2, Firebase modified scrypt).
fn verify_foreign(user: &UserRecord, password: &str) -> bool {
    let Some(stored) = user.foreign_password_hash.as_deref() else {
        return false;
    };
    match ForeignHash::parse(stored) {
        Ok(foreign) => foreign.verify(password.as_bytes()),
        Err(_) => false,
    }
}

/// Land the verify-then-rehash upgrade after a successful foreign login (issue #55):
/// hash `password` with the native Argon2id at current parameters and hand it to the
/// audited store upgrade, which writes it onto the user and clears the foreign hash
/// atomically. Best-effort: any failure (a hashing error, a lost race, a transient
/// persistence fault) is swallowed so the sign-in still succeeds; the foreign hash
/// simply remains to be upgraded on the next login. The plaintext never leaves this
/// function and the hash is never logged.
async fn rehash_foreign_credential(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    password: &str,
) {
    let Ok(new_hash) = password::hash_password(state.env(), password) else {
        return;
    };
    let actor = interaction::user_actor(subject);
    let _ = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .upgrade_foreign_password(state.env(), subject, &new_hash)
        .await;
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
