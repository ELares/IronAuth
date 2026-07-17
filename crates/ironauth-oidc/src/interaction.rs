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
    ActorRef, ClientId, CorrelationId, HumanId, NewSession, PriorSessionOutcome, Scope, SessionId,
    StoreError, UserId,
};

use crate::authn::AuthenticationEvent;
use crate::hints::InteractionHints;
use crate::pages;
use crate::revocation::{SessionLifecycleEvent, SessionSignalCause};
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
/// The step-up second-factor challenge page (RFC 9470, issue #72).
const MFA_CHALLENGE_PATH: &str = "/login/mfa";

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

/// The `Sec-Fetch-Site` fetch-metadata request header (no `http` constant exists
/// for it, so the lowercase name is used directly; `HeaderMap` lookups are
/// case-insensitive).
const SEC_FETCH_SITE: &str = "sec-fetch-site";

/// The serialization of an OPAQUE origin. A browser sends this exact value (not an
/// absent header) whenever it has an origin to report but must not disclose it: a
/// sandboxed frame, a `data:` or `file:` document, and (per the Fetch standard's
/// "append a request `Origin` header") any non-`GET`/`HEAD`, non-CORS request made
/// from a document whose referrer policy is `no-referrer`. It is NEVER evidence of
/// same-origin.
const OPAQUE_ORIGIN: &str = "null";

/// A CSRF defense-in-depth allowlist for the state-changing interactive POSTs
/// (login, consent, and registration), evaluated BEFORE any state change (issue
/// #196).
///
/// These POSTs rely on the `SameSite=Lax` session cookie to block the standard
/// cross-site auto-submit (registration is the exception: it mints the session, so
/// it has no cookie to lean on and this check is its primary CSRF defense). This
/// closes the two named residuals a header allowlist can, with no schema, cookie,
/// or token plumbing:
///
/// - the Chromium "Lax+POST" transitional window (a `Lax` cookie younger than two
///   minutes is sent on a cross-site top-level POST), caught by `Sec-Fetch-Site`;
/// - legacy clients that do not enforce `SameSite`, caught by `Origin` (browsers
///   have sent it on every cross-origin POST since ~2016).
///
/// The rule is STRICTLY-STRONGER defense-in-depth, not a hard gate, so it fails
/// CLOSED only on positive evidence of a cross-site request and otherwise defers to
/// the cookie:
///
/// - reject when `Sec-Fetch-Site` is present AND `cross-site`;
/// - reject when `Origin` is present AND does not match `expected_origin` (the
///   deployment's own origin, derived from `issuer_base`);
/// - allow when NEITHER is conclusive (header-stripped proxies and non-browser
///   clients keep working; the `SameSite=Lax` cookie remains the backstop).
///
/// `expected_origin` is [`None`] only when the deployment's origin could not be
/// derived; the `Origin` comparison is then skipped and the `Sec-Fetch-Site` rule
/// alone applies.
///
/// # The opaque `Origin: null` case
///
/// A browser serializes the origin of a form POST as the literal `null` in several
/// situations that are NOT cross-site (most importantly a page served with
/// `Referrer-Policy: no-referrer`, per the Fetch standard). Treating `null` as a
/// plain mismatch would reject a legitimate same-origin submission, so `null` is
/// resolved by FETCH METADATA instead of by the origin comparison:
///
/// - `null` with `Sec-Fetch-Site: same-origin` is INCONCLUSIVE (the check defers to
///   the cookie, exactly as an absent `Origin` does);
/// - `null` with any other value (including `same-site`, which is a sibling subdomain
///   on the same registrable domain, a DIFFERENT origin), or with NO,
///   `Sec-Fetch-Site` is a HARD REJECT.
///
/// This cannot produce a false ALLOW for a genuine cross-origin submission.
/// `Sec-Fetch-*` are FORBIDDEN header names: page script (`fetch`, `XMLHttpRequest`,
/// a form) cannot set or forge them, so the value is authored solely by the user
/// agent. A cross-site form POST carries `Sec-Fetch-Site: cross-site`, and a request
/// whose initiator has an opaque origin (a sandboxed frame, a `data:` document) is
/// likewise reported as `cross-site`, so both are rejected here before the `Origin`
/// is ever read. A caller that strips or never sends fetch metadata gets the strict
/// old behavior (`null` rejected).
#[must_use]
pub fn same_origin_ok(headers: &HeaderMap, expected_origin: Option<&str>) -> bool {
    let fetch_site = headers
        .get(SEC_FETCH_SITE)
        .and_then(|value| value.to_str().ok());
    // Positive cross-site signal from fetch metadata: reject.
    if let Some(site) = fetch_site {
        if site.eq_ignore_ascii_case("cross-site") {
            return false;
        }
    }
    // Positive SAME-ORIGIN evidence from fetch metadata (unforgeable by page script).
    // This is the only thing that can rescue an opaque `Origin`, and it must be
    // exactly `same-origin`: `same-site` covers a sibling subdomain sharing the
    // registrable domain, which is a DIFFERENT origin, so accepting it would be a
    // cross-origin CSRF false-allow (a no-referrer sibling page nulls the Origin yet
    // reports `same-site`). A genuine same-origin no-referrer POST always carries a
    // REAL matching Origin, never null, so requiring `same-origin` rescues zero
    // legitimate traffic.
    let same_origin_signal =
        fetch_site.is_some_and(|site| site.eq_ignore_ascii_case("same-origin"));
    // A present Origin that does not match our own is a cross-origin submission.
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        if origin.trim().eq_ignore_ascii_case(OPAQUE_ORIGIN) {
            // The opaque origin carries no information of its own: allow ONLY when
            // the user agent has positively said the request came from our own
            // origin, and reject otherwise (fail closed on an absent, `same-site`,
            // `cross-site`, or `none` signal).
            return same_origin_signal;
        }
        if let Some(expected) = expected_origin {
            // Compare CANONICAL origins (issue #196): a browser lowercases the host
            // and drops the default port in the `Origin` it sends, so both sides are
            // normalized the same way (crate::state::origin_of) before the byte
            // comparison. Without this a `public_url` with an uppercase host or an
            // explicit `:443`/`:80` would falsely reject every legitimate same-origin
            // POST. A value that does not parse falls back to its raw form, so a
            // malformed `Origin` still fails the match and is rejected. Fetch metadata
            // never rescues a genuine FOREIGN origin: this comparison is reached with
            // a real origin value and rejects on mismatch regardless of
            // `Sec-Fetch-Site`. This never produces a false ALLOW.
            let origin_canon = crate::state::origin_of(origin);
            let expected_canon = crate::state::origin_of(expected);
            let origin_cmp = origin_canon.as_deref().unwrap_or(origin);
            let expected_cmp = expected_canon.as_deref().unwrap_or(expected);
            if origin_cmp != expected_cmp {
                return false;
            }
        }
    }
    // Neither header is conclusively cross-site: defer to the SameSite cookie.
    true
}

/// The origin/CSRF guard for a WebAuthn ceremony that may legitimately be invoked
/// from a configured RELATED origin (issue #67, WebAuthn Level 3 Related Origin
/// Requests).
///
/// A WebAuthn assertion from a related origin is a genuinely CROSS-SITE POST (the
/// related origin is a different registrable domain), which [`same_origin_ok`]
/// rejects outright on its `Sec-Fetch-Site: cross-site` signal. This guard instead
/// accepts a request whose browser-set `Origin` canonically matches one of the
/// operator-configured `allowed_origins` (the serving origin plus the related
/// origins the well-known document lists). The `Origin` header is set by the user
/// agent and is UNFORGEABLE by page script, so membership in that explicit,
/// operator-controlled allowlist IS the CSRF authorization: an origin absent from
/// the list is rejected exactly as a cross-site submission is, and no wider set of
/// origins is ever admitted than the deployment declared.
///
/// A missing or opaque (`null`) `Origin` carries no allowlist evidence, so the guard
/// FAILS CLOSED: a fully header-less ceremony request (no `Origin` and no
/// `Sec-Fetch-Site: same-origin`) is refused (issue #67 review INFO-4, acceptance
/// criterion 2's literal "a missing Origin is refused"). The only request admitted
/// without a usable `Origin` is one the user agent positively marks same-origin via
/// the unforgeable `Sec-Fetch-Site: same-origin` (a no-referrer same-origin POST nulls
/// its `Origin` yet still carries that signal). A real related-origin request ALWAYS
/// carries a real `Origin`, so this loses no legitimate cross-origin traffic, and a
/// legitimate same-origin browser ceremony always carries either a real `Origin` or
/// `Sec-Fetch-Site: same-origin`. This is strictly tighter than deferring to the
/// `SameSite` cookie and does not touch [`same_origin_ok`] (the management-endpoint and
/// #196 bootstrap CSRF path is unchanged).
#[must_use]
pub fn related_origin_ok(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let trimmed = origin.trim();
        if !trimmed.eq_ignore_ascii_case(OPAQUE_ORIGIN) {
            // Canonicalize both sides (lowercased host, default port dropped) before
            // the byte comparison, exactly as same_origin_ok does, so a case or
            // default-port difference never falsely rejects a listed origin.
            let origin_canon = crate::state::origin_of(trimmed);
            let origin_cmp = origin_canon.as_deref().unwrap_or(trimmed);
            return allowed_origins.iter().any(|allowed| {
                let allowed_canon = crate::state::origin_of(allowed);
                allowed_canon.as_deref().unwrap_or(allowed) == origin_cmp
            });
        }
    }
    // No usable Origin header (absent, or the opaque `null`): admit ONLY a request the
    // user agent positively marks same-origin (unforgeable by page script), and reject
    // an absent / `same-site` / `cross-site` / `none` signal. A fully header-less
    // request thus fails closed.
    headers
        .get(SEC_FETCH_SITE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|site| site.eq_ignore_ascii_case("same-origin"))
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

/// Resolve the session cookie on `headers` to an authenticated session within
/// `scope`, or [`None`] when there is no cookie, the cookie names a session in
/// another scope, the session is absent, expired, REVOKED, or ROTATED away, or the
/// session's OFF-BY-DEFAULT binding does not match the presenting request. A store
/// failure is also [`None`] (fail closed to unauthenticated).
///
/// The revocation and rotation guard is enforced authoritatively in the store's read
/// query (issue #32), so a revoked or rotated session stops resolving IMMEDIATELY
/// rather than lingering until its lifetime elapses.
///
/// This takes the whole [`HeaderMap`] rather than just the cookie so the binding
/// check can never be forgotten at a call site: every session resolution sees the
/// presenting request.
pub async fn resolve_session(
    state: &OidcState,
    scope: Scope,
    headers: &HeaderMap,
) -> Option<AuthenticatedSession> {
    let value = session::session_value_from_cookie_header(cookie_header(headers))?;
    let session_id = SessionId::parse_in_scope(value, &scope).ok()?;
    let now = epoch_micros(state.now());
    // A successful resolve SLIDES the idle window (issue #32), so the idle timeout is a
    // real idle timeout rather than a second absolute cap that would kill a
    // continuously active session at idle_ttl. The store does the slide in the same
    // transaction as the read, and only past roughly half the window (no hot-path write
    // amplification).
    let idle_ttl = idle_ttl_micros(state);
    let record = state
        .store()
        .scoped(scope)
        .sessions()
        .get(&session_id, now, idle_ttl)
        .await
        .ok()
        .flatten()?;
    // The OFF-BY-DEFAULT binding knobs (issue #32). Each is inert unless an operator
    // turned it on; when it IS on it fails CLOSED: the presenting request must carry
    // the same value the session was established from, so a session replayed from a
    // different peer IP (or a different device/user agent) does not resolve.
    let presented = session_binding(state, headers);
    if state.session_peer_ip_binding()
        && !bound_value_matches(record.peer_ip.as_deref(), presented.peer_ip)
    {
        return None;
    }
    if state.session_device_binding()
        && !bound_value_matches(record.user_agent.as_deref(), presented.user_agent)
    {
        return None;
    }
    Some(AuthenticatedSession {
        session_id,
        subject: record.subject,
        auth_time_unix_micros: record.auth_time_unix_micros,
        auth_methods: record.auth_methods,
    })
}

/// The configured idle window in microseconds, saturating (never negative), for the
/// idle slide on the session read path (issue #32).
fn idle_ttl_micros(state: &OidcState) -> i64 {
    i64::try_from(state.session_idle_ttl().as_micros()).unwrap_or(i64::MAX)
}

/// Whether a bound value on the session matches the presenting request. Fails CLOSED:
/// an absent stored value or an absent presented value is a MISMATCH, so a binding
/// that is enabled can never be bypassed by simply omitting the header.
fn bound_value_matches(stored: Option<&str>, presented: Option<&str>) -> bool {
    match (stored, presented) {
        (Some(stored), Some(presented)) => stored == presented,
        _ => false,
    }
}

/// The OFF-BY-DEFAULT session binding inputs captured from the presenting request
/// (issue #32). Each field is [`None`] unless its knob is enabled, so the safe
/// default records nothing and binds nothing (the tunability principle: a NAT or a
/// mobile IP change must never log a user out unless an operator opted in).
#[derive(Debug, Clone, Copy, Default)]
struct SessionBinding<'a> {
    /// The device / user-agent binding input (the `User-Agent` header).
    user_agent: Option<&'a str>,
    /// The peer-IP binding input (the resolved client IP, see [`session::PEER_IP_HEADER`]).
    peer_ip: Option<&'a str>,
}

/// The binding inputs to capture (at a privilege transition) or to compare against
/// (at a session resolution), read from `headers` and gated on the two knobs.
fn session_binding<'a>(state: &OidcState, headers: &'a HeaderMap) -> SessionBinding<'a> {
    SessionBinding {
        user_agent: if state.session_device_binding() {
            header_str(headers, header::USER_AGENT.as_str())
        } else {
            None
        },
        peer_ip: if state.session_peer_ip_binding() {
            header_str(headers, session::PEER_IP_HEADER)
        } else {
            None
        },
    }
}

/// A header's value as UTF-8, or [`None`] when absent or not valid UTF-8.
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// Why [`establish_session`] refused to mint a session.
///
/// The two variants map to DIFFERENT uniform responses at every call site: a
/// [`NotAuthenticatable`](EstablishSessionError::NotAuthenticatable) refusal is the
/// account-lifecycle fence (issue #80 / #52) and callers render it as their normal
/// auth-failure shape (a wrong code / failed ceremony), so it is never an
/// existence/state oracle; a [`Store`](EstablishSessionError::Store) fault is the
/// neutral server error. Keeping them distinct is load-bearing: mapping a fenced but
/// otherwise-correct login to a 500 would itself be a state oracle.
#[derive(Debug)]
pub enum EstablishSessionError {
    /// The subject's account-lifecycle state forbids authentication (waitlisted,
    /// blocked, disabled, pending-verification) or the subject is absent/deleted. Fail
    /// CLOSED; the caller returns its uniform auth-failure response.
    NotAuthenticatable,
    /// A persistence fault while resolving state or rotating the session. The caller
    /// returns its neutral server-error response (the underlying [`StoreError`] is
    /// deliberately not surfaced, exactly as the callers already discarded it).
    Store,
}

impl From<StoreError> for EstablishSessionError {
    fn from(_: StoreError) -> Self {
        EstablishSessionError::Store
    }
}

/// Establish a session for `subject` in `scope` at a privilege transition (login,
/// registration, and the future MFA / step-up seam), recording the authentication
/// `event` (its methods and time), and return the `Set-Cookie` value that sets it,
/// attributed to `actor`.
///
/// This ROTATES the session identifier (issue #32, session-fixation defense): it
/// mints a fresh unpredictable id from the entropy seam and, when the request already
/// presented a session cookie, INVALIDATES that prior id in the SAME transaction, so
/// the prior id stops resolving from the next request on. The prior id is read from
/// `headers`, so no call site can forget to rotate.
///
/// The session carries both lifetimes from the clock seam (the idle timeout and the
/// absolute cap) and the OFF-BY-DEFAULT binding inputs (captured only when their knob
/// is on). The cookie carries the configured CHIPS `Partitioned` toggle. The recorded
/// `auth_time` and methods come from the `event`, so the ID token's claims trace back
/// to the actual login.
///
/// # Errors
///
/// [`EstablishSessionError::NotAuthenticatable`] when the subject's account-lifecycle
/// state forbids authentication (the central fence, issue #80 / #52), or
/// [`EstablishSessionError::Store`] on a persistence failure (fail closed).
pub async fn establish_session(
    state: &OidcState,
    scope: Scope,
    subject: &str,
    event: &AuthenticationEvent,
    actor: ActorRef,
    headers: &HeaderMap,
) -> Result<SessionCookies, EstablishSessionError> {
    // The CENTRAL lifecycle fence (issue #80 / #52): EVERY session-minting path funnels
    // through this one choke point, so the account-state gate lives HERE and cannot be
    // forgotten by any caller. A user whose state cannot authenticate (waitlisted,
    // blocked, disabled, pending-verification) or is absent/deleted mints NO session on
    // ANY factor -- password, email-OTP, magic-link, SMS-OTP, WebAuthn, device, or
    // registration alike. The state is resolved from the store here (never trusted from a
    // caller) so a stale or omitted caller-side state cannot bypass it, and the refusal is
    // a uniform [`EstablishSessionError::NotAuthenticatable`] the callers render as their
    // OWN normal auth-failure shape (never an existence/state oracle). A store fault fails
    // CLOSED. Active and scheduled-offboarding accounts are authenticatable, so a normal
    // login on any path is unaffected.
    match state
        .store()
        .scoped(scope)
        .users()
        .state_for_subject(subject)
        .await
    {
        Ok(Some(user_state)) if user_state.can_authenticate() => {}
        Ok(_) => return Err(EstablishSessionError::NotAuthenticatable),
        Err(_) => return Err(EstablishSessionError::Store),
    }
    let now = state.now();
    let session_id = SessionId::generate(state.env(), &scope);
    let idle_micros = epoch_micros(now.checked_add(state.session_idle_ttl()).unwrap_or(now));
    let absolute_micros = epoch_micros(now.checked_add(state.session_ttl()).unwrap_or(now));
    // The session the browser already holds, if any: the one this privilege
    // transition rotates AWAY (session-fixation defense).
    let prior = prior_session_id(headers, scope);
    let binding = session_binding(state, headers);
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .sessions()
        .rotate(
            state.env(),
            &session_id,
            prior.as_ref(),
            NewSession {
                subject,
                auth_methods: &event.methods_token(),
                auth_time_micros: event.auth_time_unix_micros(),
                idle_expires_micros: idle_micros,
                absolute_expires_micros: absolute_micros,
                user_agent: binding.user_agent,
                peer_ip: binding.peer_ip,
            },
        )
        .await?;
    // Publish the session-lifecycle signal (issue #32) that TRUTHFULLY describes what
    // the store did with the prior session, so the durable fan-out (#35) can build on
    // this seam. The store's two branches are semantically opposite and the signal must
    // not blur them:
    //
    //   - Carried: the SAME subject re-authenticated, so this is a genuine ROTATION.
    //     It carries a successor and is explicitly NON-terminal (the session lives on
    //     under a new id, with its sids and refresh families), so a naive consumer must
    //     never mistake it for a logout.
    //   - RevokedForeignSubject: a DIFFERENT subject's session was terminally revoked
    //     with its full cascade. There is NO successor for it (the new session belongs
    //     to somebody else), so the signal is TERMINAL and carries no successor. Calling
    //     this a rotation would tell a consumer the outgoing user's session lived on as
    //     the incoming user's, which is exactly backwards.
    if let Some(prior) = prior.as_ref() {
        let signal = match outcome {
            PriorSessionOutcome::None => None,
            PriorSessionOutcome::Carried => Some(SessionLifecycleEvent {
                tenant: scope.tenant().to_string(),
                environment: scope.environment().to_string(),
                session_id: prior.to_string(),
                cause: SessionSignalCause::Rotated,
                successor_session_id: Some(session_id.to_string()),
            }),
            PriorSessionOutcome::RevokedForeignSubject => Some(SessionLifecycleEvent {
                tenant: scope.tenant().to_string(),
                environment: scope.environment().to_string(),
                session_id: prior.to_string(),
                cause: SessionSignalCause::ReplacedByOtherSubject,
                successor_session_id: None,
            }),
        };
        if let Some(signal) = signal {
            state.revocation_sink().publish_session(&signal);
        }
    }
    let session_cookie = session::build_set_cookie(
        &session_id.to_string(),
        state.session_ttl(),
        state.session_partitioned_cookie(),
    );
    // OIDC Session Management 1.0 (issue #39): ONLY when session management is enabled,
    // publish the OP browser state to a script-readable cookie the `check_session_iframe`
    // can read. It is `op_browser_state(issuer, session_id)`, the EXACT value the
    // authorization response folds into `session_state` (authorize.rs), so while this
    // session is stable the iframe recomputes a matching `session_state` and answers
    // `unchanged`; the moment the session rotates (a fresh id here) or is cleared
    // (logout) the value changes and the iframe answers `changed`. Without this cookie
    // the mechanism is inert: the iframe reads nothing and can only ever say `changed`.
    // With the flag off the cookie is absent and the response is byte-identical to before.
    let op_browser_state_cookie = state.session_management_enabled().then(|| {
        let issuer = state.issuer_for(&scope);
        let opbs = crate::session_mgmt::op_browser_state(&issuer, &session_id.to_string());
        session::build_op_browser_state_cookie(&opbs, state.session_ttl())
    });
    Ok(SessionCookies {
        session_id,
        session: session_cookie,
        op_browser_state: op_browser_state_cookie,
    })
}

/// The `Set-Cookie` header value(s) that establish a session (issue #20), plus, ONLY
/// when session management is enabled (issue #39), the script-readable OP browser-state
/// cookie the `check_session_iframe` reads. With session management off the second is
/// [`None`] and nothing beyond the session cookie is emitted.
pub struct SessionCookies {
    /// The just-established session's id (issue #77, PR 3), so a caller that must key
    /// server-side state on the SAME session it just minted (the upstream token vault
    /// keys capture on it) reads it here rather than re-parsing the cookie string.
    session_id: SessionId,
    /// The hardened `__Host-ironauth_session` cookie (see [`session::build_set_cookie`]).
    session: String,
    /// The `__ironauth_opbs` cookie (see [`session::build_op_browser_state_cookie`]),
    /// present ONLY when session management is enabled.
    op_browser_state: Option<String>,
}

impl SessionCookies {
    /// Every `Set-Cookie` header value to emit, in order: the session cookie first, then
    /// the OP browser-state cookie when session management is enabled.
    pub(crate) fn header_values(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.session.as_str()).chain(self.op_browser_state.as_deref())
    }

    /// The just-established session's id (issue #77, PR 3): the key the upstream token
    /// vault captures on, so the tokens share the exact session's lifetime.
    pub(crate) fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

/// The prior session id presented on the request, if any, parsed under `scope`
/// (issue #32). A missing, malformed, or cross-scope cookie is [`None`] (there is
/// simply no prior session of this scope to rotate away).
fn prior_session_id(headers: &HeaderMap, scope: Scope) -> Option<SessionId> {
    let value = session::session_value_from_cookie_header(cookie_header(headers))?;
    SessionId::parse_in_scope(value, &scope).ok()
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

/// A `303` redirect to the login page carrying `return_to`.
#[must_use]
pub fn login_redirect(return_to: &str) -> Response {
    redirect(&interaction_url(LOGIN_PATH, return_to))
}

/// A `303` redirect to the registration page carrying `return_to`.
#[must_use]
pub fn register_redirect(return_to: &str) -> Response {
    redirect(&interaction_url(REGISTER_PATH, return_to))
}

/// A `303` redirect to the PASSKEY-ONLY sign-in (RFC 9470 step-up, issue #72),
/// carrying `return_to` and the `passkey=1` marker. The login page renders the
/// passkey ceremony with NO password form for this marker, so a `phr`/`phrh` step-up
/// cannot be answered by a password re-login (which would loop forever): the only way
/// forward is the passkey ceremony, which yields `phr` and terminates the flow.
#[must_use]
pub fn passkey_reauth_redirect(return_to: &str) -> Response {
    redirect(&append_query(
        LOGIN_PATH,
        &[("return_to", Some(return_to)), ("passkey", Some("1"))],
    ))
}

/// A `303` redirect to the consent page carrying `return_to`.
#[must_use]
pub fn consent_redirect(return_to: &str) -> Response {
    redirect(&interaction_url(CONSENT_PATH, return_to))
}

/// A `303` redirect to the step-up second-factor challenge page carrying
/// `return_to` (RFC 9470, issue #72). When `enroll` is true the subject has no
/// qualifying factor and the page surfaces the enrollment prompt instead of the
/// code form.
#[must_use]
pub fn mfa_challenge_redirect(return_to: &str, enroll: bool) -> Response {
    let location = if enroll {
        append_query(
            MFA_CHALLENGE_PATH,
            &[("return_to", Some(return_to)), ("enroll", Some("1"))],
        )
    } else {
        interaction_url(MFA_CHALLENGE_PATH, return_to)
    };
    redirect(&location)
}

/// Build an interaction URL (`/login?return_to=...`), percent-encoding the target.
fn interaction_url(path: &str, return_to: &str) -> String {
    append_query(path, &[("return_to", Some(return_to))])
}

/// A `303 See Other` to `location` with `Cache-Control: no-store` and
/// `Referrer-Policy: no-referrer`.
///
/// `303` (never `302`, never `307`/`308`) is the RFC 9700 status for these
/// interaction redirects: several are the result of a credential-bearing POST
/// (the login, registration, and consent form submits), and `303` forces the user
/// agent to follow up with a `GET` carrying NO request body, so a password in the
/// request body is never replayed to the `return_to` target. A body-preserving
/// `307`/`308`
/// would replay it; `302` leaves the conversion browser-dependent. `no-referrer`
/// keeps the `return_to` authorization URL (which carries request parameters) out
/// of the `Referer` header.
#[must_use]
pub fn redirect(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// A `303 See Other` to `location` that also sets the session cookie(s). `303` (never
/// `307`/`308`) so the post-login POST is not replayed to `return_to`; see
/// [`redirect`] for the full rationale. When session management is enabled the
/// `cookies` carry the OP browser-state cookie as a second `Set-Cookie` (issue #39).
#[must_use]
pub fn redirect_setting_cookie(location: &str, cookies: &SessionCookies) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer");
    for value in cookies.header_values() {
        builder = builder.header(header::SET_COOKIE, value);
    }
    builder
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Attach every session `Set-Cookie` header to an already-built response (issue #68),
/// so a non-redirect login result (a JSON verify result or a hosted success page) can
/// establish the session on the browser exactly as [`redirect_setting_cookie`] does.
#[must_use]
pub fn attach_session_cookies(mut response: Response, cookies: &SessionCookies) -> Response {
    let headers = response.headers_mut();
    for value in cookies.header_values() {
        if let Ok(value) = header::HeaderValue::from_str(value) {
            headers.append(header::SET_COOKIE, value);
        }
    }
    response
}

/// Append one additional `Set-Cookie` header value to an already-built response (issue
/// #71): the remember-device cookie a completed multi-factor login plants alongside the
/// rotated session cookie, so a subsequent login from this device skips the second
/// factor. A malformed header value is silently dropped (the remember is best-effort and
/// never fails the successful login).
#[must_use]
pub fn append_set_cookie(mut response: Response, value: &str) -> Response {
    if let Ok(value) = header::HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
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

/// The page shown when a federated login is attempted through a connector whose
/// endpoints are an EXPLICIT set rather than issuer discovery (issue #75, LOW-3).
///
/// PR B binds the upstream ID token's `iss` only for an ISSUER-form (discovery)
/// connector; an explicit-endpoint set carries no mix-up-checked issuer to bind, so
/// federation is not yet supported for it. This fails the flow CLEANLY and EARLY (at
/// the authorize leg, before any `state` is persisted or secret unsealed) so an
/// operator gets a documented misconfiguration error instead of a mid-flow 500 after
/// the user has authenticated at the upstream. Full explicit-endpoint support is a
/// later slice.
#[must_use]
pub fn federation_unsupported_page() -> Response {
    pages::secure_html(
        StatusCode::BAD_REQUEST,
        pages::notice_page(
            "Sign-in method not available",
            "This federated sign-in is not available. \
             Explicit-endpoint federation is not yet supported; use issuer discovery.",
        ),
    )
}

/// The page shown when a federated login is attempted through a connector whose
/// upstream is currently UNAVAILABLE or whose definition is CONFIG-broken (issue #76,
/// the failure-isolation crux).
///
/// This is the TYPED, diagnosable connector-unavailable error: a broken upstream
/// degrades EXACTLY its own connector's login option while every OTHER connector and the
/// core OP surface keep serving. `kind` is the stable taxonomy label
/// (`config` / `upstream_unavailable`) an operator reads to tell a permanent
/// misconfiguration from a transient outage; it is a fixed, non-sensitive token (never an
/// upstream address or message), so it is safe to render. The status is `503` so a probe
/// sees the connector is temporarily unavailable, not a client error.
#[must_use]
pub fn connector_unavailable_page(kind: &str) -> Response {
    let detail = match kind {
        "config" => {
            "This sign-in method is misconfigured and unavailable. \
             An administrator must correct the connector configuration."
        }
        _ => {
            "This sign-in method is temporarily unavailable because its identity \
             provider could not be reached. Please try again shortly or choose another \
             sign-in method."
        }
    };
    pages::secure_html(
        StatusCode::SERVICE_UNAVAILABLE,
        pages::notice_page("Sign-in method unavailable", detail),
    )
}

/// The Keycloak-safe "an account already exists" interstitial (issue #78): shown when a
/// federated login collides with an existing local account under the opt-in
/// verified-to-verified posture but the FULL auto-link trust conditions are not all met
/// (an unverified local account, a missing upstream `email_verified`, or an untrusted
/// connector). It creates NO session and links NOTHING; it instructs the account owner to
/// sign in locally and use the deliberate, fresh-re-auth-gated manual link. This is the
/// safe shape: a would-be silent merge is refused, never performed.
#[must_use]
pub fn link_interstitial_page() -> Response {
    pages::secure_html(
        StatusCode::OK,
        pages::notice_page(
            "An account already exists",
            "An account with this email already exists. For your security we did not merge \
             them automatically. Sign in to that account, then link this provider from your \
             account settings.",
        ),
    )
}

/// The notice shown when a self-service manual link cannot complete because the federated
/// identity is ALREADY linked to an account (issue #78): the anti-takeover UNIQUE
/// constraint refused a second binding. Generic on purpose: it never reveals which account
/// holds the existing link, so it is not an existence oracle.
#[must_use]
pub fn link_conflict_page() -> Response {
    pages::secure_html(
        StatusCode::CONFLICT,
        pages::notice_page(
            "Already linked",
            "This sign-in provider is already linked to an account. It cannot be linked to a \
             second account. Remove the existing link first if you want to move it.",
        ),
    )
}

/// The `403` page shown when a state-changing POST is refused by the CSRF
/// header allowlist ([`same_origin_ok`], issue #196). Generic on purpose: it never
/// reveals WHICH signal (Origin or Sec-Fetch-Site) failed, and NO action is
/// performed (no session created, no consent recorded).
#[must_use]
pub fn forbidden_page() -> Response {
    pages::secure_html(
        StatusCode::FORBIDDEN,
        pages::notice_page(
            "Request blocked",
            "This request could not be verified. Start the sign-in from the application again.",
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
    fn same_origin_ok_rejects_cross_site_and_allows_same_origin_or_no_headers() {
        use axum::http::HeaderValue;

        let expected = Some("https://issuer.test");

        // No headers at all: allowed (the SameSite cookie remains the backstop).
        assert!(same_origin_ok(&HeaderMap::new(), expected));

        // Sec-Fetch-Site: cross-site is rejected.
        let mut cross_site = HeaderMap::new();
        cross_site.insert(SEC_FETCH_SITE, HeaderValue::from_static("cross-site"));
        assert!(!same_origin_ok(&cross_site, expected));

        // A cross-origin Origin is rejected.
        let mut cross_origin = HeaderMap::new();
        cross_origin.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.test"),
        );
        assert!(!same_origin_ok(&cross_origin, expected));

        // A matching Origin with same-origin fetch metadata is allowed.
        let mut same = HeaderMap::new();
        same.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://issuer.test"),
        );
        same.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        assert!(same_origin_ok(&same, expected));

        // same-site (a sibling subdomain) is not cross-site, so it is allowed.
        let mut same_site = HeaderMap::new();
        same_site.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-site"));
        assert!(same_origin_ok(&same_site, expected));

        // With no derivable expected origin the Origin comparison is skipped, so a
        // cross-origin Origin alone is allowed but a cross-site fetch is still
        // rejected.
        assert!(same_origin_ok(&cross_origin, None));
        assert!(!same_origin_ok(&cross_site, None));
    }

    #[test]
    fn related_origin_ok_admits_a_listed_related_origin_and_rejects_the_rest() {
        use axum::http::HeaderValue;

        let serving = "https://issuer.test".to_owned();
        let related = "https://example.de".to_owned();
        let allowed = vec![serving.clone(), related.clone()];

        // The serving origin (same-origin) is accepted.
        let mut same = HeaderMap::new();
        same.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://issuer.test"),
        );
        same.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        assert!(related_origin_ok(&same, &allowed));

        // A LISTED related origin, even reported cross-site by fetch metadata (it is a
        // different registrable domain), is accepted: membership in the operator
        // allowlist is the authorization. same_origin_ok would reject this.
        let mut related_hdrs = HeaderMap::new();
        related_hdrs.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.de"),
        );
        related_hdrs.insert(SEC_FETCH_SITE, HeaderValue::from_static("cross-site"));
        assert!(related_origin_ok(&related_hdrs, &allowed));
        // And same_origin_ok against the serving origin rejects it, proving the guard
        // genuinely widens the accepted set rather than the base check already allowing it.
        assert!(!same_origin_ok(&related_hdrs, Some(&serving)));

        // An UNLISTED origin is rejected even though it is not flagged cross-site.
        let mut evil = HeaderMap::new();
        evil.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.test"),
        );
        assert!(!related_origin_ok(&evil, &allowed));

        // Canonicalization: a default https port and uppercase host still match a listed
        // origin (a browser lowercases the host and drops :443).
        let mut ported = HeaderMap::new();
        ported.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://EXAMPLE.de:443"),
        );
        assert!(related_origin_ok(&ported, &allowed));
    }

    #[test]
    fn related_origin_ok_fails_closed_on_a_missing_or_opaque_origin() {
        use axum::http::HeaderValue;

        let allowed = vec![
            "https://issuer.test".to_owned(),
            "https://example.de".to_owned(),
        ];

        // A FULLY header-less ceremony request (no Origin, no Sec-Fetch-Site) is refused
        // (issue #67 review INFO-4, acceptance criterion 2): there is no allowlist
        // evidence, so the guard fails closed rather than deferring to the cookie.
        assert!(!related_origin_ok(&HeaderMap::new(), &allowed));

        // No Origin at all, but a positive same-origin fetch-metadata signal (a
        // no-referrer same-origin POST): admitted, so the legitimate same-origin
        // ceremony is never lost.
        let mut fetch_only = HeaderMap::new();
        fetch_only.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        assert!(related_origin_ok(&fetch_only, &allowed));

        // No Origin with a same-SITE signal (a sibling subdomain is a different origin)
        // is refused.
        let mut fetch_same_site = HeaderMap::new();
        fetch_same_site.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-site"));
        assert!(!related_origin_ok(&fetch_same_site, &allowed));

        // An opaque `null` Origin with a positive same-origin fetch-metadata signal is
        // rescued; without it, it fails closed (no allowlist evidence).
        let mut opaque_ok = HeaderMap::new();
        opaque_ok.insert(header::ORIGIN, HeaderValue::from_static("null"));
        opaque_ok.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        assert!(related_origin_ok(&opaque_ok, &allowed));

        let mut opaque_cross = HeaderMap::new();
        opaque_cross.insert(header::ORIGIN, HeaderValue::from_static("null"));
        opaque_cross.insert(SEC_FETCH_SITE, HeaderValue::from_static("cross-site"));
        assert!(!related_origin_ok(&opaque_cross, &allowed));

        // An opaque `null` Origin with NO fetch metadata also fails closed.
        let mut opaque_bare = HeaderMap::new();
        opaque_bare.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert!(!related_origin_ok(&opaque_bare, &allowed));
    }

    /// A header map built from `(name, value)` pairs, for the CSRF matrix below.
    fn headers_of(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        use axum::http::HeaderValue;

        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn same_origin_ok_resolves_an_opaque_origin_by_fetch_metadata() {
        // A REAL browser posting the login, consent, or registration form sends
        // `Origin: null` whenever the page's referrer policy is `no-referrer` (Fetch:
        // "append a request Origin header" serializes the origin as `null` for a
        // non-GET/HEAD, non-CORS request under that policy). The opaque origin is
        // therefore resolved by fetch metadata, which page script cannot forge.
        let expected = Some("https://issuer.test");

        // ACCEPTED: the user agent positively says the request came from our own
        // origin. This is the ONLY signal that rescues an opaque `Origin: null`.
        assert!(same_origin_ok(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "same-origin")]),
            expected
        ));

        // REJECTED: `same-site` is NOT `same-origin`. A sibling subdomain sharing the
        // registrable domain, serving a page with `Referrer-Policy: no-referrer`, makes
        // the browser send `Origin: null` alongside a UA-authored
        // `Sec-Fetch-Site: same-site`; accepting it would be a cross-origin CSRF
        // false-allow. A genuine same-origin no-referrer POST always carries a REAL
        // matching Origin, never null, so this rescues zero legitimate traffic.
        assert!(!same_origin_ok(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "same-site")]),
            expected
        ));

        // REJECTED: an opaque origin with a cross-site signal (a hostile page's form,
        // or a sandboxed/`data:` initiator, both of which a browser reports as
        // cross-site).
        assert!(!same_origin_ok(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "cross-site")]),
            expected
        ));

        // REJECTED: an opaque origin with NO fetch metadata proves nothing, so it fails
        // closed exactly as it did before.
        assert!(!same_origin_ok(
            &headers_of(&[("origin", "null")]),
            expected
        ));

        // REJECTED: `Sec-Fetch-Site: none` (a user-initiated navigation) is not
        // own-site evidence either.
        assert!(!same_origin_ok(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "none")]),
            expected
        ));

        // REJECTED: the opaque rule is scoped to the literal `null` and never rescues a
        // genuine FOREIGN origin, whatever the fetch metadata claims.
        for site in ["same-origin", "same-site", "cross-site", "none"] {
            let mut headers = headers_of(&[("origin", "https://evil.test")]);
            headers.insert(
                SEC_FETCH_SITE,
                axum::http::HeaderValue::from_str(site).expect("valid"),
            );
            assert!(
                !same_origin_ok(&headers, expected),
                "a foreign Origin is rejected with Sec-Fetch-Site: {site}"
            );
        }

        // REJECTED even with no derivable expected origin: an opaque origin without
        // own-site metadata is refused on the fetch-metadata rule alone.
        assert!(!same_origin_ok(&headers_of(&[("origin", "null")]), None));
        assert!(same_origin_ok(
            &headers_of(&[("origin", "null"), ("sec-fetch-site", "same-origin")]),
            None
        ));
    }

    #[test]
    fn same_origin_ok_normalizes_case_and_default_port_before_comparing() {
        use axum::http::HeaderValue;

        // A deployment whose expected origin carries an uppercase host and an
        // explicit default port (as a `public_url` might) still matches the bare,
        // lowercased `Origin` a browser sends: both sides normalize the same way, so
        // a legitimate same-origin POST is not falsely 403-ed (issue #196).
        let expected = Some("https://Issuer.test:443");
        let mut browser = HeaderMap::new();
        browser.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://issuer.test"),
        );
        assert!(
            same_origin_ok(&browser, expected),
            "a normalized browser Origin matches an un-normalized expected origin"
        );

        // A genuinely different origin still mismatches after normalization (no false
        // allow).
        let mut evil = HeaderMap::new();
        evil.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.test"),
        );
        assert!(!same_origin_ok(&evil, expected));

        // A different NON-default port is a different origin and is rejected.
        let mut other_port = HeaderMap::new();
        other_port.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://issuer.test:8443"),
        );
        assert!(!same_origin_ok(&other_port, expected));
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
