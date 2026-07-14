// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared plumbing for the login, registration, and consent interaction steps
//! (issue #20): resolving the resume target, resolving and establishing the
//! bootstrap session, and building the interaction redirects.
//!
//! # The resume target
//!
//! The authorization endpoint, when it needs an interaction (login, registration,
//! or consent), redirects to the interaction page carrying a `return_to`: the
//! canonical `/authorize?...` URL rebuilt from the validated request. The
//! interaction page posts it back, and on success sends the user there so the
//! authorization request resumes exactly where it paused.
//!
//! `return_to` is UNTRUSTED input, so it is validated as an open-redirect defense:
//! it must be a LOCAL path beginning with the single-slash `/authorize?` (never a
//! scheme-relative `//host` or an absolute URL), must be printable ASCII (so it
//! cannot smuggle a header-splitting `\r\n` into a `Location`), and must carry a
//! syntactically valid `client_id` from which the `(tenant, environment)` scope is
//! recovered. Anything else is refused, so the interaction pages can never be
//! turned into an open redirector.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, HumanId, Scope, SessionId, StoreError, UserId,
};

use crate::authn::AuthenticationEvent;
use crate::hints::InteractionHints;
use crate::pages;
use crate::session;
use crate::state::OidcState;
use crate::util::{append_query, epoch_micros, query_get};

/// The only valid `return_to` prefix: a local authorization path. The single
/// leading slash is load-bearing (a `//host` value would be scheme-relative and
/// an open redirect), so this is matched exactly.
const RESUME_PREFIX: &str = "/authorize?";

/// The interaction paths the authorization endpoint redirects to.
const LOGIN_PATH: &str = "/login";
const REGISTER_PATH: &str = "/register";
const CONSENT_PATH: &str = "/consent";

/// A validated resume target: the local authorization URL to send the user back
/// to, and the client, scope, and interaction hints recovered from it.
pub struct ResumeTarget {
    /// The validated `/authorize?...` path to resume at.
    pub return_to: String,
    /// The client the authorization request is for.
    pub client_id: ClientId,
    /// The `(tenant, environment)` scope recovered from the client id.
    pub scope: Scope,
    /// The requested OAuth `scope` value, if the request carried one.
    pub oauth_scope: Option<String>,
    /// The typed interaction hints (`login_hint`, `ui_locales`, `display`, and the
    /// rest) reconstructed from the resuming query (issue #16), so the interaction
    /// page renders with the identifier prefill, language, and layout the
    /// authorization request asked for.
    pub hints: InteractionHints,
}

/// Validate and parse a `return_to`. Returns [`None`] for any value that is not a
/// safe local authorization path carrying a syntactically valid `client_id`.
#[must_use]
pub fn parse_resume(raw: Option<&str>) -> Option<ResumeTarget> {
    let return_to = raw?.trim();
    // Printable ASCII only: no control characters (CR/LF header splitting), no raw
    // space, no non-ASCII. A conformant URL is already percent-encoded.
    if !return_to.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
        return None;
    }
    let query = return_to.strip_prefix(RESUME_PREFIX)?;
    let client_id_raw = query_get(query, "client_id")?;
    let client_id = ClientId::parse_declared_scope(&client_id_raw).ok()?;
    let scope = client_id.scope();
    let oauth_scope = query_get(query, "scope").filter(|value| !value.is_empty());
    let hints = InteractionHints::from_query(query);
    Some(ResumeTarget {
        return_to: return_to.to_owned(),
        client_id,
        scope,
        oauth_scope,
        hints,
    })
}

/// The `Cookie` header value, if present and valid UTF-8.
#[must_use]
pub fn cookie_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::COOKIE)?.to_str().ok()
}

/// An authenticated bootstrap session: the session id, the subject it names, and
/// the recorded authentication event (its time and methods), which the ID token's
/// `auth_time`, `amr`, and `acr` derive from (issue #14).
pub struct AuthenticatedSession {
    /// The resolved session identifier (also the cookie value).
    pub session_id: SessionId,
    /// The authenticated end-user subject.
    pub subject: String,
    /// When the subject authenticated, in microseconds since the Unix epoch.
    pub auth_time_unix_micros: i64,
    /// The recorded authentication method tokens (space-separated RFC 8176
    /// values), the single source `amr` and the achieved `acr` derive from.
    pub auth_methods: String,
}

/// Resolve the session cookie to an authenticated session within `scope`, or
/// [`None`] when there is no cookie, the cookie names a session in another scope,
/// or the session is absent or expired. A store failure is also [`None`] (fail
/// closed to unauthenticated).
pub async fn resolve_session(
    state: &OidcState,
    scope: Scope,
    cookie: Option<&str>,
) -> Option<AuthenticatedSession> {
    let value = session::session_value_from_cookie_header(cookie)?;
    let session_id = SessionId::parse_in_scope(value, &scope).ok()?;
    let now = epoch_micros(state.now());
    let record = state
        .store()
        .scoped(scope)
        .sessions()
        .get(&session_id, now)
        .await
        .ok()
        .flatten()?;
    Some(AuthenticatedSession {
        session_id,
        subject: record.subject,
        auth_time_unix_micros: record.auth_time_unix_micros,
        auth_methods: record.auth_methods,
    })
}

/// Create a session for `subject` in `scope` recording the authentication `event`
/// (its methods and time), and return the `Set-Cookie` value to establish it,
/// attributed to `actor`. The session's `expires_at` comes from the clock seam
/// and the configured session lifetime; the recorded `auth_time` and methods come
/// from the `event`, so the ID token's claims trace back to the actual login.
///
/// # Errors
///
/// [`StoreError`] on a persistence failure.
pub async fn establish_session(
    state: &OidcState,
    scope: Scope,
    subject: &str,
    event: &AuthenticationEvent,
    actor: ActorRef,
) -> Result<String, StoreError> {
    let now = state.now();
    let session_id = SessionId::generate(state.env(), &scope);
    let expires_micros = epoch_micros(now.checked_add(state.session_ttl()).unwrap_or(now));
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sessions()
        .create(
            state.env(),
            &session_id,
            subject,
            &event.methods_token(),
            event.auth_time_unix_micros(),
            expires_micros,
        )
        .await?;
    Ok(session::build_set_cookie(
        &session_id.to_string(),
        state.session_ttl(),
    ))
}

/// The stable human audit actor for a user (derived from the user id's PUBLIC
/// unique component, so the audit trail names the same human across requests).
#[must_use]
pub fn user_actor(user_id: &UserId) -> ActorRef {
    ActorRef::human(HumanId::from_seed_bytes(user_id.unique_bytes()))
}

/// The human audit actor for a subject string that should be a `usr_` id. Falls
/// back to a fresh human actor if the subject is not a parseable user id in scope
/// (unreachable for a subject this bootstrap issued; defense in depth).
#[must_use]
pub fn subject_actor(state: &OidcState, scope: Scope, subject: &str) -> ActorRef {
    match UserId::parse_in_scope(subject, &scope) {
        Ok(id) => user_actor(&id),
        Err(_) => ActorRef::human(HumanId::generate(state.env())),
    }
}

/// A `302` redirect to the login page carrying `return_to`.
#[must_use]
pub fn login_redirect(return_to: &str) -> Response {
    redirect(&interaction_url(LOGIN_PATH, return_to))
}

/// A `302` redirect to the registration page carrying `return_to`.
#[must_use]
pub fn register_redirect(return_to: &str) -> Response {
    redirect(&interaction_url(REGISTER_PATH, return_to))
}

/// A `302` redirect to the consent page carrying `return_to`.
#[must_use]
pub fn consent_redirect(return_to: &str) -> Response {
    redirect(&interaction_url(CONSENT_PATH, return_to))
}

/// Build an interaction URL (`/login?return_to=...`), percent-encoding the target.
fn interaction_url(path: &str, return_to: &str) -> String {
    append_query(path, &[("return_to", Some(return_to))])
}

/// A `302 Found` to `location` with `Cache-Control: no-store`.
#[must_use]
pub fn redirect(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// A `302 Found` to `location` that also sets a session cookie.
#[must_use]
pub fn redirect_setting_cookie(location: &str, set_cookie: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, set_cookie)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The page shown when an interaction is reached without a usable resume target
/// (a missing, malformed, or non-local `return_to`). A hardened HTML page, never a
/// redirect (the value is untrusted).
#[must_use]
pub fn invalid_link_page() -> Response {
    pages::secure_html(
        StatusCode::BAD_REQUEST,
        pages::notice_page(
            "Link no longer valid",
            "This sign-in link is missing or invalid. Start the sign-in from the application again.",
        ),
    )
}

/// The page shown when an interaction hits an unexpected server-side failure.
/// Generic on purpose: it never reveals what failed.
#[must_use]
pub fn server_error_page() -> Response {
    pages::secure_html(
        StatusCode::INTERNAL_SERVER_ERROR,
        pages::notice_page(
            "Something went wrong",
            "The request could not be processed. Please try again.",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resume_accepts_a_local_authorize_path_and_recovers_scope() {
        // A syntactically valid client_id embeds a scope; parse_declared_scope
        // recovers it. Build one the same way the id type renders it.
        use ironauth_store::{EnvironmentId, TenantId};
        let (env, _) = ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 1);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let client = ClientId::generate(&env, &scope);
        let return_to = format!(
            "/authorize?response_type=code&client_id={client}&scope=openid%20profile&\
             login_hint=ada%40example.test&ui_locales=fr&display=popup"
        );
        let resume = parse_resume(Some(&return_to)).expect("valid resume");
        assert_eq!(resume.scope, scope);
        assert_eq!(resume.client_id, client);
        assert_eq!(resume.oauth_scope.as_deref(), Some("openid profile"));
        // The interaction hints ride the resuming query (issue #16).
        assert_eq!(resume.hints.login_hint(), Some("ada@example.test"));
        assert_eq!(resume.hints.ui_locales(), Some("fr"));
        assert_eq!(resume.hints.display(), crate::hints::Display::Popup);
    }

    #[test]
    fn parse_resume_rejects_open_redirect_and_non_authorize_targets() {
        // Scheme-relative, absolute, non-authorize, and header-splitting values
        // are all refused (open-redirect and header-injection defense).
        for hostile in [
            "//evil.example/authorize?client_id=x",
            "https://evil.example/authorize?client_id=x",
            "/somewhere-else?client_id=x",
            "/authorize?client_id=x\r\nSet-Cookie: a=b",
            "/authorize?no_client=1",
        ] {
            assert!(
                parse_resume(Some(hostile)).is_none(),
                "{hostile} must be refused"
            );
        }
        assert!(parse_resume(None).is_none());
    }
}
