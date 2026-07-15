// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID Connect RP-Initiated Logout 1.0: the `end_session` endpoint (issue #33).
//!
//! A relying party ends the end user's session with the OP by top-level navigation to
//! `end_session`. This is the one logout mechanism unaffected by third-party cookie
//! blocking, and its subtleties are where real providers ship bugs; every rule here is
//! a defense:
//!
//! - **Only spec parameters.** `id_token_hint`, `client_id`, `logout_hint`, `state`,
//!   `ui_locales`, `post_logout_redirect_uri`. Nothing proprietary is accepted,
//!   required, or documented (Cognito's `logout_uri` breaks every standard client, the
//!   trap this endpoint refuses to fall into).
//!
//! - **A hint is verified through the JOSE core, expired accepted, foreign refused.**
//!   The `id_token_hint` is verified by [`OidcState::verify_logout_hint`] against the
//!   environment's own published keys (rotated-out verification keys retained) with a
//!   PAST `exp` accepted; every other check (signature, algorithm allowlist, exact
//!   issuer, exact audience, `nbf`, `iat`) stays. A hint we cannot verify, or one from a
//!   foreign issuer, does NOT attribute the request, so the logout falls to the
//!   confirmation path and can never redirect.
//!
//! - **Synchronous termination through the session domain.** The SSO session (and its
//!   per-client sessions and session-bound refresh families) is dead in Postgres via
//!   [`ActingSessionRepo::revoke`](ironauth_store::ActingSessionRepo) with cause
//!   `LoggedOut` and `hard_kill = false` BEFORE the response is written, closing the
//!   hydra#4070 "logged straight back in" race (the immediate-revocation read guard of
//!   issue #32 refuses the session on the very next request). `hard_kill = false`
//!   PRESERVES the `offline_access` families (OIDC Back-Channel Logout 2.7), so an
//!   offline token survives an RP logout by design. The terminal
//!   [`SessionLifecycleEvent`] fires on the revocation sink so the durable fan-out
//!   (#35) and back-channel logout (#34) attach without touching this endpoint.
//!
//! - **The hint's own `sid` selects the session, never the cookie.** On the attributed
//!   path the session to end is resolved STRICTLY from the `sid` the verified hint
//!   carries (via [`ClientSessionRepo::session_for_sid`](ironauth_store::ClientSessionRepo)),
//!   never from whatever session cookie the browser happened to present. An attacker can
//!   only ever mint their OWN token, whose `sid` maps to their OWN session, so an
//!   attributed logout can end only the hint owner's session, never a co-scoped victim's
//!   (a crafted `GET /end_session?id_token_hint=<attacker token>` sends the victim's
//!   `SameSite=Lax` cookie, but that cookie no longer selects the target). A hint that
//!   carries NO `sid` has no tie to a specific session, so it degrades to the same
//!   confirmation path an unattributable logout gets rather than ending the cookie. The
//!   cookie is cleared and the redirect honored ONLY when the presenting browser IS the
//!   session the `sid` names (compared, never preferred); a different browser is left
//!   exactly as it was. `sub` is deliberately NOT used to select a session (it is a
//!   pairwise/public subject, not a session identifier).
//!
//! - **The cookie is cleared.** Every logout response clears the session cookie
//!   (`Max-Age=0`), so the browser drops it even before the row's lifetime elapses.
//!
//! - **Exact-match redirect, or no redirect.** `post_logout_redirect_uri` is honored
//!   ONLY when it EXACTLY string-matches a value the client pre-registered AND the
//!   request carried a verifiable hint that binds it to that client AND the presenting
//!   browser is the very session the hint's `sid` names. No wildcards, no
//!   normalization, no case folding (RFC 9700 section 2.1). A near miss, an
//!   unregistered value, or an unattributable request gets NO redirect: a neutral
//!   logged-out page is rendered instead, never a redirect to an attacker-supplied URI.
//!   `state` round-trips to the redirect target only on a validated redirect.
//!
//! - **CSRF: confirm before ending an unattributable logout.** A logout that ends a
//!   session on a bare GET with no verifiable hint is a logout-CSRF vector (a crafted
//!   link logs a victim out). Without attribution the GET renders a confirmation prompt
//!   and performs NO state change; the confirm POST then ends the session behind the
//!   same-origin CSRF check (issue #196). A malformed hint degrades to this same
//!   confirmation path rather than erroring the user out.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, Scope, ServiceId, SessionEndCause, SessionId,
};
use serde::Deserialize;
use serde_json::Value;

use crate::interaction::{cookie_header, forbidden_page, same_origin_ok};
use crate::pages;
use crate::revocation::{SessionLifecycleEvent, SessionSignalCause};
use crate::session;
use crate::state::OidcState;
use crate::token_credential::peek_claim;
use crate::util::append_query;

/// The RP-Initiated Logout request parameters (OIDC RP-Initiated Logout 1.0 section 2).
///
/// Every field is a SPEC parameter; nothing proprietary is accepted. The same shape
/// deserializes from the `GET` query and the confirmation `POST` form. `logout_hint`
/// and `ui_locales` are accepted for spec completeness (this English-only bootstrap
/// acts on neither beyond carrying them across the confirmation prompt).
#[derive(Debug, Default, Deserialize)]
pub struct LogoutParams {
    /// The (possibly expired) ID token this OP minted, identifying the session to end.
    pub id_token_hint: Option<String>,
    /// The client the logout is for. When present it MUST agree with the hint's `aud`.
    pub client_id: Option<String>,
    /// An opaque hint at the end user to log out. Not acted on here (accepted only).
    pub logout_hint: Option<String>,
    /// Opaque value round-tripped to the redirect target on a validated redirect.
    pub state: Option<String>,
    /// The end user's preferred languages for any logout page. Accepted only.
    pub ui_locales: Option<String>,
    /// Where to send the browser after logout, honored ONLY on an exact registered
    /// match with a verifiable hint.
    pub post_logout_redirect_uri: Option<String>,
}

/// `GET /end_session` (OIDC RP-Initiated Logout 1.0). A top-level browser navigation.
pub async fn end_session_get(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Query(params): Query<LogoutParams>,
) -> Response {
    handle(&state, &headers, &params, false).await
}

/// `POST /end_session` (the confirmation submit, or a form-posted logout).
pub async fn end_session_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(params): Form<LogoutParams>,
) -> Response {
    handle(&state, &headers, &params, true).await
}

/// A logout request the `id_token_hint` cryptographically attributes to a client of
/// THIS OP: the environment scope, the bound client, and the session-identifying
/// claims the verified hint carried.
struct Attributed {
    /// The environment the hint (and the session it targets) belongs to.
    scope: Scope,
    /// The client the hint's `aud` names, the redirect set is checked against.
    client_id: String,
    /// The per-(client, session) `sid` the hint carried, mapping to the SSO session.
    sid: Option<String>,
}

/// The shared logout flow. `is_post` distinguishes the confirmation SUBMIT (a state
/// change is allowed behind the CSRF check) from the initial GET (a state change on an
/// unattributable request is refused, and a confirmation prompt is shown instead).
async fn handle(
    state: &OidcState,
    headers: &HeaderMap,
    params: &LogoutParams,
    is_post: bool,
) -> Response {
    // Attribute the request through the id_token_hint, if it verifies. An absent,
    // malformed, unverifiable, or foreign-issuer hint yields None (no attribution).
    let attributed = match params.id_token_hint.as_deref() {
        Some(hint) => attribute(state, hint, params.client_id.as_deref()).await,
        None => None,
    };

    let Some(attributed) = attributed else {
        return unattributed(state, headers, params, is_post).await;
    };

    // A verifiable hint attributes the request to a client, but only a hint that carries
    // a `sid` cryptographically identifies WHICH session to end. Without a `sid` there is
    // no tie to a specific session, so ending the browser's cookie session here would be
    // the same logout-CSRF a bare GET is. Degrade to the same-origin-gated confirmation
    // path (changes nothing on a GET, can never redirect).
    let Some(sid) = attributed.sid.as_deref() else {
        return unattributed(state, headers, params, is_post).await;
    };

    // Resolve the target STRICTLY from the hint's own `sid`, never from the presenting
    // cookie. An attacker can only ever mint their OWN token, whose `sid` maps to their
    // OWN session, so this can end only the hint owner's session, never a co-scoped
    // victim's (the #33 forced-logout defect). A `sid` that maps to no live session is a
    // clean no-op.
    let target = state
        .store()
        .scoped(attributed.scope)
        .client_sessions()
        .session_for_sid(sid)
        .await
        .ok()
        .flatten();

    // Whether the request came from the hint owner's OWN browser: only when the presented
    // cookie resolves to the SAME SSO session the `sid` names (compared, never
    // preferred). Only then was THIS browser logged out, so only then may the response
    // clear its cookie and honor a post-logout redirect. A different (victim's) cookie,
    // or none, leaves the presenting browser untouched.
    let browser_is_hint_owner = match (&target, cookie_session_in_scope(headers, &attributed.scope))
    {
        (Some(target), Some(cookie)) => *target == cookie,
        _ => false,
    };

    // End the hint owner's OWN session synchronously (a no-op when the `sid` mapped to no
    // live session). This is always safe: the target is the hint owner's session, whoever
    // the browser is.
    if let Some(session_id) = &target {
        revoke_and_signal(state, attributed.scope, session_id).await;
    }

    if !browser_is_hint_owner {
        // The hint owner's session was ended, but the presenting browser is a DIFFERENT
        // session (a cross-user logout attempt) or has no live cookie. Change NOTHING for
        // it: no cookie clear, no redirect, so an attacker-supplied (even registered)
        // `post_logout_redirect_uri` can never carry the victim's browser away.
        return neutral_logged_out();
    }

    // The presenting browser IS the hint owner: a redirect happens ONLY on an exact
    // registered-URI match, else the neutral logged-out page. Both clear this browser's
    // cookie.
    match validated_redirect(state, &attributed, params).await {
        Some(location) => logout_redirect(state, &location),
        None => logged_out(state),
    }
}

/// The path for a request the hint did NOT attribute (absent, malformed, unverifiable,
/// or foreign). A state change here would be logout-CSRF, so it is gated:
///
/// - a GET renders a confirmation prompt and changes NOTHING;
/// - a POST is the confirmation submit: behind the same-origin CSRF check it ends the
///   browser's cookie session; a POST that fails the check gets a neutral refusal.
///
/// Neither path can redirect: without a verifiable hint no client is bound, so an
/// attacker-supplied `post_logout_redirect_uri` is never honored.
async fn unattributed(
    state: &OidcState,
    headers: &HeaderMap,
    params: &LogoutParams,
    is_post: bool,
) -> Response {
    if !is_post {
        return confirmation_prompt(params);
    }
    if !same_origin_ok(headers, state.self_origin().as_deref()) {
        return forbidden_page();
    }
    // The confirmed logout targets the session the browser presents (its scope is
    // embedded in the cookie value itself).
    if let Some(session_id) = cookie_session_declared(headers) {
        revoke_and_signal(state, session_id.scope(), &session_id).await;
    }
    logged_out(state)
}

/// Attribute a logout request to a client of this OP through its `id_token_hint`.
///
/// Returns [`None`] whenever the hint is not a token THIS OP issued to the named client:
/// a non-JWS shape, an `aud` that is not a parseable client id, a `client_id` parameter
/// that disagrees with the hint's audience, or a signature/issuer/audience/algorithm
/// failure inside [`OidcState::verify_logout_hint`]. The environment scope is derived
/// from the client id the audience names (it embeds its scope), and the hint must then
/// verify under THAT environment's own keys, so a foreign token cannot attribute a
/// request. A past `exp` is accepted; nothing else is relaxed.
async fn attribute(
    state: &OidcState,
    hint: &str,
    client_id_param: Option<&str>,
) -> Option<Attributed> {
    // The client the hint is for: the `client_id` parameter when given (the verify
    // enforces it is a member of the token's `aud`), else the token's own `aud`.
    let expected_client = match client_id_param {
        Some(param) => param.trim().to_owned(),
        None => audience_client(hint)?,
    };
    // The scope is recovered from the client id the audience names, then the hint must
    // verify under exactly that environment's keys.
    let client = ClientId::parse_declared_scope(&expected_client).ok()?;
    let scope = client.scope();
    let verified = state
        .verify_logout_hint(&scope, &expected_client, hint)
        .await
        .ok()?;
    let sid = verified
        .claims()
        .get("sid")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(Attributed {
        scope,
        client_id: expected_client,
        sid,
    })
}

/// The client id an id token's `aud` names, read WITHOUT verifying (the value is
/// re-checked under the signature as the verification audience, so a tampered `aud`
/// fails the signature). A string `aud` is that value; an array `aud` is its first
/// string member. [`None`] for any other shape.
fn audience_client(hint: &str) -> Option<String> {
    match peek_claim(hint, "aud")? {
        Value::String(aud) => Some(aud),
        Value::Array(items) => items
            .iter()
            .find_map(|item| item.as_str().map(str::to_owned)),
        _ => None,
    }
}

/// Revoke ONE SSO session as an RP logout (issue #33) and, when it actually flipped from
/// live, publish the terminal [`SessionLifecycleEvent`] on the revocation sink so the
/// durable session-ended fan-out (#35) and back-channel logout (#34) can react.
///
/// Routes through [`ActingSessionRepo::revoke`](ironauth_store::ActingSessionRepo) with
/// cause `LoggedOut` and `hard_kill = false`: the session, its per-client sessions, and
/// its SESSION-BOUND refresh families are revoked in ONE audited transaction, while the
/// `offline_access` families are PRESERVED (OIDC Back-Channel Logout 2.7).
async fn revoke_and_signal(state: &OidcState, scope: Scope, session_id: &SessionId) {
    let (actor, correlation) = logout_actor(state, scope);
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .sessions()
        .revoke(
            state.env(),
            session_id,
            SessionEndCause::LoggedOut,
            false,
            None,
        )
        .await;
    match outcome {
        Ok(revocation) if revocation.session_flipped => {
            state
                .revocation_sink()
                .publish_session(&SessionLifecycleEvent {
                    tenant: scope.tenant().to_string(),
                    environment: scope.environment().to_string(),
                    session_id: session_id.to_string(),
                    cause: SessionSignalCause::LoggedOut,
                    successor_session_id: None,
                });
        }
        Ok(_) => {
            // Already revoked or absent: idempotent, no terminal signal to publish.
        }
        Err(error) => {
            // The durable record is the audit row the revoke writes in-transaction; a
            // failure here leaves the session as it was. A logout that could not commit
            // must not masquerade as success, but it also must not leak detail: it is
            // logged and the caller still clears the cookie and renders a neutral page.
            tracing::error!(%error, "end_session revoke failed");
        }
    }
}

/// The audit actor for an RP logout: a fresh service principal (the OP's `end_session`
/// endpoint acting on the end user's behalf; there is no authenticated client and the
/// hint's `sub` is a possibly-pairwise PUBLIC subject, not the session's local one) and
/// a fresh correlation id.
fn logout_actor(state: &OidcState, _scope: Scope) -> (ActorRef, CorrelationId) {
    (
        ActorRef::service(ServiceId::generate(state.env())),
        CorrelationId::generate(state.env()),
    )
}

/// The validated post-logout redirect target for an ATTRIBUTED logout, or [`None`] when
/// no redirect is permitted (no `post_logout_redirect_uri`, the bound client is gone, or
/// the presented value does not EXACTLY match a registered value). On a match, `state`
/// is appended so it round-trips to the RP unchanged.
async fn validated_redirect(
    state: &OidcState,
    attributed: &Attributed,
    params: &LogoutParams,
) -> Option<String> {
    let presented = params.post_logout_redirect_uri.as_deref()?;
    let client_id = ClientId::parse_in_scope(&attributed.client_id, &attributed.scope).ok()?;
    let record = state
        .store()
        .scoped(attributed.scope)
        .clients()
        .get(&client_id)
        .await
        .ok()?;
    // EXACT string match, RFC 9700 section 2.1: no wildcards, no normalization, no case
    // folding. A near miss (case change, trailing slash, extra path segment) does not
    // match and gets no redirect.
    if !record
        .post_logout_redirect_uris
        .iter()
        .any(|registered| registered == presented)
    {
        return None;
    }
    Some(match params.state.as_deref() {
        Some(value) => append_query(presented, &[("state", Some(value))]),
        None => presented.to_owned(),
    })
}

/// The `ses_` session the presenting request carries, parsed WITHOUT enforcing a caller
/// scope so the scope embedded in the cookie value drives the revocation (the
/// confirmation-POST path, which has no hint to fix a scope). [`None`] when no cookie is
/// present or it is not a parseable session id.
fn cookie_session_declared(headers: &HeaderMap) -> Option<SessionId> {
    let value = session::session_value_from_cookie_header(cookie_header(headers))?;
    SessionId::parse_declared_scope(value).ok()
}

/// The `ses_` session the presenting request carries, parsed IN `scope` (the attributed
/// path, where the hint fixes the scope). [`None`] when there is no cookie or it names a
/// session in another scope.
fn cookie_session_in_scope(headers: &HeaderMap, scope: &Scope) -> Option<SessionId> {
    let value = session::session_value_from_cookie_header(cookie_header(headers))?;
    SessionId::parse_in_scope(value, scope).ok()
}

/// The confirmation prompt (issue #33 CSRF defense): shown when a logout is not
/// attributable, it changes NOTHING and posts back to `end_session` behind the
/// same-origin check. The spec request parameters ride hidden fields so the confirming
/// POST reconstructs the request; nothing proprietary is carried.
fn confirmation_prompt(params: &LogoutParams) -> Response {
    let carried: [(&str, &str); 6] = [
        (
            "id_token_hint",
            params.id_token_hint.as_deref().unwrap_or_default(),
        ),
        ("client_id", params.client_id.as_deref().unwrap_or_default()),
        (
            "logout_hint",
            params.logout_hint.as_deref().unwrap_or_default(),
        ),
        ("state", params.state.as_deref().unwrap_or_default()),
        (
            "ui_locales",
            params.ui_locales.as_deref().unwrap_or_default(),
        ),
        (
            "post_logout_redirect_uri",
            params
                .post_logout_redirect_uri
                .as_deref()
                .unwrap_or_default(),
        ),
    ];
    pages::secure_html(
        StatusCode::OK,
        pages::logout_confirm_page("/end_session", &carried),
    )
}

/// The neutral logged-out page that changes NOTHING for the presenting browser: no
/// cookie clear and no redirect. Rendered on the attributed path when the request did
/// NOT come from the hint owner's own browser (its cookie is a different session, or it
/// has none). The hint owner's own session was already ended; the presenting browser is
/// left exactly as it was, so a crafted cross-user logout can neither drop the victim's
/// cookie nor navigate the victim away.
fn neutral_logged_out() -> Response {
    pages::secure_html(StatusCode::OK, pages::logged_out_page())
}

/// The neutral logged-out page, clearing the session cookie.
fn logged_out(state: &OidcState) -> Response {
    let mut response = pages::secure_html(StatusCode::OK, pages::logged_out_page());
    set_clear_cookie(state, &mut response);
    response
}

/// A `303` redirect to a validated post-logout `location`, clearing the session cookie.
/// `303` (never a body-preserving `307`/`308`) with `Cache-Control: no-store` and
/// `Referrer-Policy: no-referrer`, matching the interaction redirects.
fn logout_redirect(state: &OidcState, location: &str) -> Response {
    let clear = session::clear_set_cookie(state.session_partitioned_cookie());
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, clear)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Attach the `Max-Age=0` clear-cookie header to a logout page response, matching the
/// CHIPS `Partitioned` shape the session was set with so it targets the same jar.
fn set_clear_cookie(state: &OidcState, response: &mut Response) {
    if let Ok(value) = header::HeaderValue::from_str(&session::clear_set_cookie(
        state.session_partitioned_cookie(),
    )) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}
