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
use ironauth_store::{
    CorrelationId, NewAdminUser, Scope, TraitSchema, UserId, UserRecord, UserState,
};
use serde::Deserialize;

use crate::authn::{AuthMethod, AuthenticationEvent};
use crate::interaction::{self, parse_resume};
use crate::migration::{HookOutcome, HookProfile, LazyMigrationHook};
use crate::pages;
use crate::state::OidcState;
use crate::totp::{self, SecondFactorOutcome};
use crate::util::epoch_micros;

/// The `return_to` carried on the `GET /login` query.
#[derive(Deserialize)]
pub struct ResumeQuery {
    /// The authorization URL to resume at after a successful sign-in.
    pub return_to: Option<String>,
    /// When present (`1`), a step-up routed the subject here to run the PASSKEY ceremony
    /// specifically for a phishing-resistant (`phr`/`phrh`) floor (RFC 9470, issue #72):
    /// the page renders the passkey ceremony with NO password form (a password re-login
    /// yields `pwd` and could never satisfy the floor, so offering it would loop).
    pub passkey: Option<String>,
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
            // Conditional-UI passkey sign-in (issue #65): when WebAuthn is enabled,
            // the page carries the autofill token, a passkey button, and the one
            // nonce-guarded ceremony script served under the login CSP. The ceremony
            // endpoints are scope-routed, so the script targets this request's scope.
            if state.webauthn_enabled() {
                let nonce = passkey_nonce(&state);
                let scope_path = format!(
                    "/t/{}/e/{}",
                    resume.scope.tenant(),
                    resume.scope.environment()
                );
                let ui = pages::PasskeyUi {
                    nonce: &nonce,
                    scope_path: &scope_path,
                    signal_api: state.webauthn_signal_api_enabled(),
                };
                // A phishing-resistant step-up (RFC 9470, issue #72) routes here with
                // `passkey=1` to run the passkey ceremony SPECIFICALLY: render the
                // passkey-only page (no password form), so a `phr`/`phrh` floor cannot be
                // answered by a `pwd` re-login that would loop.
                let body = if query.passkey.as_deref() == Some("1") {
                    pages::passkey_signin_page(&resume.return_to, None, &resume.hints, banner, &ui)
                } else {
                    pages::login_page(
                        resume.hints.login_hint().unwrap_or_default(),
                        &resume.return_to,
                        None,
                        &resume.hints,
                        banner,
                        Some(&ui),
                    )
                };
                pages::login_html(StatusCode::OK, body, &nonce)
            } else {
                pages::secure_html(
                    StatusCode::OK,
                    pages::login_page(
                        resume.hints.login_hint().unwrap_or_default(),
                        &resume.return_to,
                        None,
                        &resume.hints,
                        banner,
                        None,
                    ),
                )
            }
        }
        None => interaction::invalid_link_page(),
    }
}

/// The `return_to` and optional enroll flag carried on the `GET /login/mfa` query
/// (RFC 9470 step-up challenge, issue #72).
#[derive(Deserialize)]
pub struct MfaChallengeQuery {
    /// The authorization URL to resume at after the second factor is proven.
    pub return_to: Option<String>,
    /// When present (`1`), the subject has no qualifying factor: show the
    /// enrollment prompt instead of the code form.
    pub enroll: Option<String>,
}

/// The posted step-up challenge form (issue #72).
#[derive(Deserialize)]
pub struct MfaChallengeForm {
    /// The TOTP or recovery code (never logged or echoed).
    pub code: Option<String>,
    /// The authorization URL to resume at.
    pub return_to: Option<String>,
    /// The "remember this device" opt-in (issue #71): present (`1`/`on`) when the user
    /// checked the box on the challenge page. Consulted only when the tenant enables
    /// trusted devices AND leaves the choice to the user; when the tenant decides, the
    /// device is remembered regardless of this field.
    pub remember_device: Option<String>,
}

/// `GET /login/mfa`: render the step-up second-factor challenge for a valid resume
/// target (RFC 9470, issue #72). Requires an existing session (the primary
/// authentication already happened); with none it bounces to login. When `enroll`
/// is set the page surfaces the factor-enrollment prompt.
pub async fn mfa_challenge_get(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Query(query): Query<MfaChallengeQuery>,
) -> Response {
    let Some(resume) = parse_resume(query.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };
    // The step-up runs against the CURRENT (primary) session; with none the user
    // must sign in first, which re-establishes it and resumes the same request.
    if interaction::resolve_session(&state, resume.scope, &headers)
        .await
        .is_none()
    {
        return interaction::login_redirect(&resume.return_to);
    }
    let banner = state.environment_banner(&resume.scope).await;
    let enroll_url = query
        .enroll
        .as_deref()
        .filter(|value| *value == "1")
        .map(|_| {
            format!(
                "/t/{}/e/{}/account/mfa/totp/enroll",
                resume.scope.tenant(),
                resume.scope.environment()
            )
        });
    pages::secure_html(
        StatusCode::OK,
        pages::mfa_challenge_page(
            &resume.return_to,
            None,
            enroll_url.as_deref(),
            remember_device_offered(&state),
            &resume.hints,
            banner,
        ),
    )
}

/// Whether the "remember this device" opt-in checkbox is offered on the challenge page
/// (issue #71): only when the tenant enables trusted devices AND leaves the choice to the
/// user. When the tenant decides, no checkbox is shown (the device is remembered
/// regardless); when the feature is off, none is shown either.
fn remember_device_offered(state: &OidcState) -> bool {
    state.trusted_devices_enabled() && state.trusted_device_user_opt_in()
}

/// `POST /login/mfa`: verify the presented second factor and, on success, UPGRADE
/// the session to record the combined authentication (RFC 9470, issue #72). The
/// upgraded session carries a FRESH `auth_time` (the instant the step-up completed)
/// and the honest `acr`/`amr` of the combined factors, so the resumed authorization
/// issues tokens reflecting what ACTUALLY happened, never a stale or asserted value.
#[allow(clippy::too_many_lines)]
pub async fn mfa_challenge_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<MfaChallengeForm>,
) -> Response {
    let Some(resume) = parse_resume(form.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };
    // CSRF defense-in-depth (issue #196) BEFORE any credential work, exactly as the
    // login POST does.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let banner = state.environment_banner(&resume.scope).await;
    // The step-up runs against the CURRENT (primary) session; with none the user
    // must sign in first.
    let Some(session) = interaction::resolve_session(&state, resume.scope, &headers).await else {
        return interaction::login_redirect(&resume.return_to);
    };
    let Ok(subject) = UserId::parse_in_scope(&session.subject, &resume.scope) else {
        return interaction::server_error_page();
    };
    let code = form.code.as_deref().map(str::trim).unwrap_or_default();
    let show_remember = remember_device_offered(&state);
    let rerender = |message: &str| {
        pages::secure_html(
            StatusCode::OK,
            pages::mfa_challenge_page(
                &resume.return_to,
                Some(message),
                None,
                show_remember,
                &resume.hints,
                banner,
            ),
        )
    };
    if code.is_empty() {
        return rerender("Enter a code to continue.");
    }
    // Credential-abuse regulation (issue #64) on the INDEPENDENT second-factor path
    // (issue #72), keyed on the authenticated subject and the non-forgeable resolved
    // peer IP, BEFORE any code is verified: an online TOTP/recovery-code guess storm is
    // escalated to a uniform 429 (and can auto-place a SecondFactor ban) exactly as the
    // password path is, so the step-up challenge is no longer an unbounded guess oracle.
    // A throttled attempt spends NO verification. Path-independent: a second-factor storm
    // never throttles the password or passkey path.
    let ctx = crate::abuse::second_factor_attempt_context(resume.scope, &subject, &headers);
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        return throttled_mfa_challenge_page(&snapshot, &resume.return_to, &resume.hints, banner);
    }
    let new_method = match totp::verify_second_factor(&state, resume.scope, &subject, code).await {
        SecondFactorOutcome::Totp => AuthMethod::Totp,
        SecondFactorOutcome::Recovery => AuthMethod::RecoveryCode,
        SecondFactorOutcome::Invalid => return rerender("Incorrect or expired code."),
        // A retryable server condition (the hashing pool was unavailable) or a store
        // fault: a neutral error, never a wrong-code signal.
        SecondFactorOutcome::Unavailable | SecondFactorOutcome::Error => {
            return interaction::server_error_page();
        }
    };
    // Combine the factors already proven in this session (the primary login) with
    // the one just verified, and record the event at the CURRENT clock instant so
    // auth_time is fresh (issue #14 honesty). establish_session rotates the session
    // (session-fixation defense) and writes the elevated auth_methods + auth_time.
    let mut methods = crate::authn::parse_methods(&session.auth_methods);
    if !methods.contains(&new_method) {
        methods.push(new_method);
    }
    let event = AuthenticationEvent::from_methods(&methods, epoch_micros(state.now()));
    let actor = interaction::user_actor(&subject);
    match interaction::establish_session(
        &state,
        resume.scope,
        &session.subject,
        &event,
        actor,
        &headers,
    )
    .await
    {
        Ok(cookie) => {
            // A proven second factor relaxes THIS path's failure counters (issue #64
            // LOW-6), so a user who fat-fingered a code before entering the right one is
            // not throttled for the rest of the window. Best-effort and per-PATH, so it
            // never touches the password or passkey path.
            state.reset_after_success(&ctx).await;
            let response = interaction::redirect_setting_cookie(&resume.return_to, &cookie);
            // Remember-device (issue #71): a COMPLETED multi-factor login may remember
            // this device so a subsequent login SKIPS the second factor. The trust
            // descends from the session that just proved the second factor (the lineage).
            // Best-effort: a failed remember never fails the successful login.
            maybe_remember_device(
                &state,
                resume.scope,
                &subject,
                &session.session_id,
                &headers,
                form.remember_device.as_deref(),
                response,
            )
            .await
        }
        Err(_) => interaction::server_error_page(),
    }
}

/// Decide whether to REMEMBER this device after a completed multi-factor login (issue
/// #71) and, when so, plant the remember-device cookie on `response`. The device is
/// remembered when the tenant enables trusted devices AND either the tenant decides
/// (no user opt-in) or the user checked the "remember this device" box. Best-effort: a
/// disabled feature, an unchecked box, or a persistence fault simply leaves `response`
/// unchanged, so the successful login is never affected.
async fn maybe_remember_device(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    session_id: &ironauth_store::SessionId,
    headers: &HeaderMap,
    remember_opt_in: Option<&str>,
    response: Response,
) -> Response {
    if !state.trusted_devices_enabled() {
        return response;
    }
    // When the tenant leaves the choice to the user, honor the checkbox; when the tenant
    // decides, always remember.
    let opted_in = matches!(remember_opt_in, Some("1" | "on" | "true"));
    if state.trusted_device_user_opt_in() && !opted_in {
        return response;
    }
    match crate::trusted_device::remember_device(state, scope, subject, session_id, headers).await {
        Some(cookie) => interaction::append_set_cookie(response, &cookie),
        None => response,
    }
}

/// The uniform throttle response when credential-abuse regulation refuses a step-up
/// second-factor attempt (RFC 9470, issue #72): the SAME generic challenge page body a
/// wrong code renders, but with a `429 Too Many Requests` status and the standard
/// rate-limit response headers, so an online guess storm against the second factor is
/// slowed exactly as the password path is. Keyed on the `SecondFactor` path, so it never
/// throttles the password or passkey path.
fn throttled_mfa_challenge_page(
    snapshot: &ironauth_quota::RateLimitSnapshot,
    return_to: &str,
    hints: &crate::hints::InteractionHints,
    environment_banner: Option<&str>,
) -> Response {
    let mut response = pages::secure_html(
        StatusCode::OK,
        pages::mfa_challenge_page(
            return_to,
            Some("Too many attempts. Wait a moment and try again."),
            None,
            // A throttle response is a dead-end retry page; the remember-device opt-in is
            // offered on the real challenge page, not here.
            false,
            hints,
            environment_banner,
        ),
    );
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    crate::abuse::stamp_rate_limit_headers(&mut response, snapshot);
    response
}

/// A per-response CSP script nonce for the login page's conditional-UI script
/// (issue #65), drawn from the entropy seam and hex-encoded so it is a valid CSP
/// nonce token. Reused by the WebAuthn Signal API management page (issue #73), which
/// carries the same nonce-guarded, feature-detected script discipline.
pub(crate) fn passkey_nonce(state: &OidcState) -> String {
    let mut bytes = [0_u8; 16];
    state.env().entropy().fill_bytes(&mut bytes);
    let mut nonce = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(nonce, "{byte:02x}");
    }
    nonce
}

/// `POST /login`: verify the password and, on success, establish a session and
/// resume the authorization request.
// The linear flow (parse, CSRF, lookup, regulate, verify, session, per-arm failure
// recording) reads best as one function; splitting it would scatter the anti-enumeration
// invariant across helpers, so the length lint is allowed here (issue #64).
#[allow(clippy::too_many_lines)]
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

    // Credential-abuse regulation (issue #64), keyed on the CANONICAL identifier (the
    // #54 seam) and the non-forgeable resolved peer IP (the #31 lesson), on the PASSWORD
    // path only. The account id is threaded in when the identifier resolved, so a manual
    // per-account ban applies; the escalation decision itself uses only the
    // existence-INDEPENDENT identifier + IP dimensions, so a throttle never distinguishes
    // a present from an absent identifier. Evaluated AFTER the (uniform-cost) lookup so
    // both present and absent identifiers pay the same work before any throttle. A
    // throttled attempt spends NO password verification, uniformly for both.
    let account_id = match &lookup {
        Ok(Some(user)) => Some(user.id.to_string()),
        _ => None,
    };
    let ctx = crate::abuse::AttemptContext {
        path: ironauth_store::AuthPath::Password,
        scope: resume.scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id,
        client_id: Some(resume.client_id.to_string()),
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        return throttled_login_page(
            &snapshot,
            identifier,
            &resume.return_to,
            &resume.hints,
            banner,
        );
    }

    // Risk velocity (issue #79): count this attempt against the per-account, per-IP, and
    // per-ASN velocity counters (reusing the #64 counter layer), so a flood accumulates.
    // Inert unless the risk engine and the velocity signal are enabled.
    let risk_subject = match &lookup {
        Ok(Some(user)) => Some(user.id),
        _ => None,
    };
    crate::risk::record_attempt(&state, risk_subject.as_ref(), ctx.ip.as_deref());

    match lookup {
        // A user whose lifecycle state cannot authenticate (blocked, disabled, or
        // pending verification) is FENCED (issue #52): the password is still spent
        // (so a fenced account is timing-indistinguishable from a wrong password),
        // then the SAME generic failure is returned, never a distinct signal.
        Ok(Some(user)) if !user.state.can_authenticate() => {
            // Spend the verification through the admission-controlled pool (issue
            // #62), off the async threads; an over-share tenant or a saturated pool
            // is the retryable 429/503, never an inline hash on this thread. A
            // sentinel-hash (passkey-only) account routes through the same dummy
            // Argon2 spend (issue #66 LOW-2) so it stays timing-uniform here too.
            match spend_native_verify(&state, &resume.scope, password, &user).await {
                Ok(_) => {}
                Err(rejection) => return rejection.to_response(),
            }
            failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
        }
        Ok(Some(user)) => {
            // Verify the native Argon2id hash first; if the account was imported with
            // a FOREIGN hash (issue #55) and has not yet logged in, the native hash is
            // the unusable sentinel, so fall through to the foreign verify. The native
            // verification runs on the admission-controlled hashing pool (issue #62). A
            // sentinel-hash account (passkey-only, credential-less, or not-yet-migrated
            // foreign) is routed to keep its timing uniform with an absent account (issue
            // #66 LOW-2), never the fast-fail PHC-parse that would leak its existence.
            let native_ok = match spend_native_verify(&state, &resume.scope, password, &user).await
            {
                Ok(ok) => ok,
                Err(rejection) => return rejection.to_response(),
            };
            let foreign_ok = !native_ok && verify_foreign(&user, password);
            if native_ok || foreign_ok {
                // Transparently upgrade the stored credential when due (best-effort;
                // the login has already succeeded): a first FOREIGN login rehashes to
                // the native Argon2id verifier (#55), and a NATIVE login whose hash was
                // written at OLDER parameters rehashes to the current ones (#62), so a
                // per-environment parameter change reaches existing users on next login.
                upgrade_credential_after_login(&state, resume.scope, &user, password, native_ok)
                    .await;
                // On-login breached detection (issue #63): when screen_on_login is enabled,
                // screen the just-verified password and, if it is NOW breached, emit an
                // audit event so a change can be required. Spawned DETACHED (the outbound
                // HIBP call must not block the login hot path); it never blocks or changes
                // this already-successful sign-in.
                screen_after_login(&state, resume.scope, &user, password);
                // Risk evaluation (issue #79): evaluate BEFORE establishing the session so
                // a BLOCK action yields the SAME uniform failure an ordinary wrong password
                // does (anti-enumeration), with no session created. The decision is still
                // recorded and audited, so a blocked attempt is reconstructable.
                let risk_user_agent = headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .map_or_else(|| "unknown".to_owned(), str::to_owned);
                let risk_ctx = crate::risk::RiskContext {
                    ip: ctx.ip.as_deref(),
                    user_agent: &risk_user_agent,
                    headers: &headers,
                };
                let risk_decision =
                    crate::risk::evaluate(&state, resume.scope, &user.id, &risk_ctx).await;
                if matches!(risk_decision.action, crate::risk::RiskAction::Block) {
                    let _ = crate::risk::record_decision(
                        &state,
                        resume.scope,
                        &user.id,
                        &risk_decision,
                    )
                    .await;
                    return failed_login_page(identifier, &resume.return_to, &resume.hints, banner);
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
                    Ok(cookie) => {
                        // Successful login: relax this path's identifier/account/IP failure
                        // counters so a user who typoed past the soft threshold is not
                        // throttled for the rest of the window (issue #64 LOW-6).
                        state.reset_after_success(&ctx).await;
                        // Risk follow-through (issue #79): persist the audited decision and,
                        // on a new-device login, notify the user with the device/UA/geo
                        // context and the single-use "this wasn't me" link, then refresh the
                        // login geo for the next impossible-travel check. All best-effort.
                        crate::risk::after_successful_login(
                            &state,
                            resume.scope,
                            &user.id,
                            &risk_decision,
                            &risk_ctx,
                            identifier,
                        )
                        .await;
                        interaction::redirect_setting_cookie(&resume.return_to, &cookie)
                    }
                    Err(_) => interaction::server_error_page(),
                }
            } else {
                // Present but wrong password: generic failure (no wrong-password
                // oracle), whether the stored verifier is native or foreign. The failed
                // attempt was already recorded by `regulate_before` on the layered abuse
                // counters (issue #64), so no further recording here.
                failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
            }
        }
        // Absent account: the lazy-migration hook (issue #56) gets FIRST refusal when
        // one is configured, verifying this unknown identifier against a legacy store and
        // (on success) creating the user locally with a native Argon2id hash so the NEXT
        // login is a normal local login that never calls the hook. Every non-success
        // outcome (rejected, timeout, error, breaker open, an invalid profile, a create
        // conflict) falls through to the SAME uniform failure a local wrong password
        // produces, including the comparable Argon2id time spend, so the hook's existence
        // is not observable to an attacker.
        Ok(None) => {
            if let Some(hook) = state.migration_hook() {
                if let HookOutcome::Verified(profile) = hook.attempt(identifier, password).await {
                    if let Some(response) = complete_lazy_migration(
                        &state,
                        resume.scope,
                        identifier,
                        password,
                        &resume.return_to,
                        &headers,
                        profile,
                    )
                    .await
                    {
                        // A verified lazy migration is a successful first login: relax this
                        // path's identifier/IP failure counters (issue #64 LOW-6).
                        state.reset_after_success(&ctx).await;
                        return response;
                    }
                }
            }
            // No hook, a non-success verdict, or a refused/failed create: spend comparable
            // Argon2id time (through the admission-controlled pool, issue #62), then the
            // SAME generic failure (no user-enumeration oracle). Admission is charged here
            // too, so stuffing unknown identifiers cannot bypass fair-share admission.
            match state.verify_absent(&resume.scope, password).await {
                Ok(_) => {}
                Err(rejection) => return rejection.to_response(),
            }
            // The failed attempt was already recorded by `regulate_before` on the SAME
            // existence-independent dimensions (identifier + IP) an existing account would,
            // so an absent identifier is counted and throttled identically (issue #64).
            failed_login_page(identifier, &resume.return_to, &resume.hints, banner)
        }
        Err(_) => interaction::server_error_page(),
    }
}

/// Screen the just-verified password at login (issue #63), best-effort and gated by
/// `screen_on_login`. If the password is NOW in the breach corpus (it grew since the
/// password was set), emit an audit event, a metric plus a structured log naming the
/// subject, so an operator can require a change; it NEVER blocks the already-successful
/// sign-in and never changes the login outcome. A not-breached verdict or a provider
/// outage is a no-op (the forced-change surface lands with the hosted change-password page
/// and M11 messaging). Only the 5-char SHA-1 prefix ever leaves the process.
///
/// The screen runs FULLY DETACHED (issue #63 INFO/LOW-2): the potentially outbound HIBP
/// call must never sit on the login hot path, so a slow or hung provider cannot add latency
/// to (or stall) sign-in. The detached task owns its clones (the cheaply cloneable
/// `OidcState`, the `Copy` scope, the subject id, and the NFKC-normalized password) and
/// carries its own audit/metric emission. It is fire-and-forget: the login has already
/// succeeded, so a dropped task simply means this one login was not screened. The plaintext
/// is normalized into an owned `String` and moved into the task; it is never logged.
fn screen_after_login(state: &OidcState, scope: Scope, user: &UserRecord, password: &str) {
    if !state.screen_on_login() {
        return;
    }
    let state = state.clone();
    let normalized = ironauth_screening::normalize_nfkc(password);
    let subject = user.id.to_string();
    tokio::spawn(async move {
        if let crate::state::ScreenDecision::Breached =
            state.screen_password(&scope, &normalized).await
        {
            metrics::counter!(crate::state::PASSWORD_BREACHED_AT_LOGIN_TOTAL).increment(1);
            tracing::warn!(
                subject,
                "a successful login used a password now found in the breach corpus; a password \
                 change should be required"
            );
        }
    });
}

/// Transparently upgrade a user's stored credential after a successful login,
/// best-effort. When the login succeeded on the NATIVE hash (`native_ok`), rehash
/// it to the current parameters if it drifted (issue #62); otherwise the login
/// succeeded on an imported FOREIGN hash, so rehash it to the native verifier and
/// retire the foreign hash (issue #55). Any failure is swallowed: the sign-in has
/// already succeeded and the credential simply upgrades on the next login.
async fn upgrade_credential_after_login(
    state: &OidcState,
    scope: Scope,
    user: &UserRecord,
    password: &str,
    native_ok: bool,
) {
    if native_ok {
        if crate::password::needs_rehash(&user.password_hash, state.hashing_params()) {
            rehash_native_credential(state, scope, &user.id, &user.password_hash, password).await;
        }
    } else {
        rehash_foreign_credential(state, scope, &user.id, password).await;
    }
}

/// Spend the native-hash password verification for a resolved account in a way that is
/// timing-uniform across every account shape, returning whether the native Argon2id hash
/// verified.
///
/// When the account's native `password_hash` is the unusable sentinel (a passkey-only or
/// credential-less account, issue #66), `verify_password` on the sentinel fails-fast with
/// NO Argon2 work, which would let a login probe distinguish an existing passwordless
/// account by its fast response (a login-timing enumeration oracle, issue #66 LOW-2). This
/// routes the sentinel case through the SAME dummy Argon2 spend as the absent-account path
/// (`verify_absent`), so a passkey-only account's password-login attempt costs comparable
/// time to an absent account and a real wrong-password verify. The login OUTCOME is
/// unchanged: the sentinel never verifies, so this always returns `false` for it.
///
/// A sentinel account that DOES carry a foreign hash (a not-yet-migrated import, issue #55)
/// is left to the foreign verify the caller runs next, which already spends the work, so no
/// extra dummy hash is charged in that case.
async fn spend_native_verify(
    state: &OidcState,
    scope: &Scope,
    password: &str,
    user: &UserRecord,
) -> Result<bool, crate::hashing_pool::HashRejection> {
    if user.has_usable_password_hash() {
        state
            .verify_password(scope, password, &user.password_hash)
            .await
    } else if user.foreign_password_hash.is_none() {
        // Passkey-only / credential-less account: spend the dummy Argon2 (the absent-account
        // path) so the attempt is timing-uniform; the sentinel never verifies (always false).
        state.verify_absent(scope, password).await.map(|_| false)
    } else {
        // Foreign-only account not yet migrated: the caller's foreign verify below spends the
        // work, so no dummy is needed here. The sentinel native hash never verifies.
        Ok(false)
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
    // Rehash through the admission-controlled pool (issue #62). Best-effort: the
    // login already succeeded, so an over-share/pool-exhausted/fault rejection just
    // leaves the foreign hash to upgrade on the next login rather than failing here.
    let Ok(new_hash) = state.hash_password(&scope, password).await else {
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

/// Land the transparent native-parameter rehash after a successful native login
/// (issue #62): hash `password` at the CURRENT parameters through the
/// admission-controlled pool and hand it, with the verified `current_hash`, to the
/// audited store upgrade, which writes it onto the user only while the stored hash
/// still equals `current_hash` (so a concurrent change is never clobbered).
/// Best-effort: any rejection or fault (an over-share pool, a lost race, a
/// transient persistence fault) is swallowed so the sign-in still succeeds; the
/// older-parameter hash simply upgrades on the next login. The plaintext never
/// leaves this function and the hash is never logged.
async fn rehash_native_credential(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    current_hash: &str,
    password: &str,
) {
    let Ok(new_hash) = state.hash_password(&scope, password).await else {
        return;
    };
    let actor = interaction::user_actor(subject);
    let _ = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .rehash_native_password(state.env(), subject, current_hash, &new_hash)
        .await;
}

/// Land a verified lazy-migration first login (issue #56): validate the returned
/// profile, create the user locally with a NATIVE Argon2id hash (and no foreign hash,
/// so they are migrated by construction), audit the create, and establish the session,
/// returning the same redirect a local success does. Returns `None` when nothing could
/// be persisted (an invalid profile, a lost create race, or a persistence fault), in
/// which case the caller falls through to the uniform failure and NOTHING is persisted.
///
/// The plaintext password is hashed here through the shared native hash path (the
/// entropy seam) and never leaves this function; it is never logged.
async fn complete_lazy_migration(
    state: &OidcState,
    scope: Scope,
    identifier: &str,
    password: &str,
    return_to: &str,
    headers: &HeaderMap,
    profile: Option<HookProfile>,
) -> Option<Response> {
    // Hash the in-flight password to the native Argon2id verifier (the migration
    // target) through the admission-controlled pool (issue #62); an over-share or
    // saturated pool falls through to the uniform failure and persists nothing.
    let Ok(new_hash) = state.hash_password(&scope, password).await else {
        return None;
    };

    // Resolve and VALIDATE the optional profile BEFORE persisting anything. The migration
    // profile's ONLY identity channel is the traits document, validated against the
    // environment's active identity schema (issue #53); an INVALID traits document refuses
    // the whole migration (nothing is persisted). There is deliberately NO verbatim-claims
    // channel: a hostile or compromised legacy store must not be able to inject an
    // attacker-controlled email/email_verified/groups claim that an RP would trust. The
    // created user's released claims come from the normal claim path, exactly like any
    // other user; the hook never writes `claims_json`.
    let mut traits_json: Option<String> = None;
    let mut traits_schema_version: Option<i32> = None;
    if let Some(profile) = &profile {
        if let Some(traits) = &profile.traits {
            match state.store().scoped(scope).trait_schemas().active().await {
                // An active schema is the validation contract: an invalid profile is
                // refused and nothing is persisted.
                Ok(Some(active)) => {
                    let schema = TraitSchema::compile(&active.schema_json).ok()?;
                    if !schema.validate(traits).is_empty() {
                        return None;
                    }
                    traits_json = serde_json::to_string(traits).ok();
                    traits_schema_version = Some(active.version);
                }
                // No active schema to validate against: drop the traits rather than
                // persist an unvalidated document. The user still migrates.
                Ok(None) => {}
                // Fail closed on a store fault rather than persist unvalidated traits.
                Err(_) => return None,
            }
        }
    }

    // Mint the id up front so the create's audit actor is the user acting on themselves,
    // matching the interactive login's session actor.
    let id = UserId::generate(state.env(), &scope);
    let actor = interaction::user_actor(&id);
    let created_at_micros = epoch_micros(state.now());
    let spec = NewAdminUser {
        id: Some(&id),
        identifier,
        password_hash: Some(&new_hash),
        // No verbatim claims from the hook: a migrated user's claims come from the normal
        // path, so a legacy store cannot inject an RP-trusted claim (see the traits note).
        claims_json: None,
        external_id: None,
        // A migrated user is live and can authenticate immediately.
        state: UserState::Active,
        // No foreign hash: the user is migrated by construction (native hash only), so
        // the next login is a normal local login and never calls the hook.
        foreign_password_hash: None,
        foreign_password_algo: None,
        traits_json: traits_json.as_deref(),
        traits_schema_version,
    };
    let create = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .admin_create(state.env(), spec, created_at_micros, None)
        .await;
    // A conflict means a concurrent login already migrated this identifier; a fault is a
    // transient failure. Either way, fall through to the uniform failure: the user's retry
    // finds them locally and logs in natively.
    let Ok(user_id) = create else {
        return None;
    };
    LazyMigrationHook::record_migrated();

    // Establish the session exactly as a known-user success does (session-fixation
    // defense included, via establish_session).
    let event = AuthenticationEvent::password(epoch_micros(state.now()));
    let subject = user_id.to_string();
    match interaction::establish_session(
        state,
        scope,
        &subject,
        &event,
        interaction::user_actor(&user_id),
        headers,
    )
    .await
    {
        Ok(cookie) => Some(interaction::redirect_setting_cookie(return_to, &cookie)),
        Err(_) => Some(interaction::server_error_page()),
    }
}

/// The uniform throttle response when credential-abuse regulation refuses the attempt
/// (issue #64): the SAME generic login page body a wrong password renders (so it stays
/// non-oracular), but with a `429 Too Many Requests` status and the standard rate-limit
/// response headers. Identical for a present and an absent identifier, since the throttle
/// decision keys only on the existence-independent identifier + IP dimensions.
fn throttled_login_page(
    snapshot: &ironauth_quota::RateLimitSnapshot,
    identifier: &str,
    return_to: &str,
    hints: &crate::hints::InteractionHints,
    environment_banner: Option<&str>,
) -> Response {
    let mut response = failed_login_page(identifier, return_to, hints, environment_banner);
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    crate::abuse::stamp_rate_limit_headers(&mut response, snapshot);
    response
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
    // The error re-render is the strict, script-free page: the passkey path is
    // offered on the primary GET login page (this is a failed-password re-render).
    pages::secure_html(
        StatusCode::OK,
        pages::login_page(
            identifier,
            return_to,
            Some("Incorrect identifier or password."),
            hints,
            environment_banner,
            None,
        ),
    )
}
