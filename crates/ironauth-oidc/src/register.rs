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
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_store::{ActorRef, CorrelationId, HumanId, SignupQuarantineReason, StoreError};
use serde::Deserialize;

use crate::authn::AuthenticationEvent;
use crate::interaction::{self, parse_resume};
use crate::login::ResumeQuery;
use crate::pages;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The posted registration form.
#[derive(Deserialize)]
pub struct RegisterForm {
    /// The desired login handle.
    pub identifier: Option<String>,
    /// The chosen password (never logged or echoed).
    pub password: Option<String>,
    /// The authorization URL to resume at.
    pub return_to: Option<String>,
    /// The proof-of-work challenge id the client solved (issue #80), when a challenge is
    /// required. Paired with `pow_nonce` and `pow_context` for the built-in `PoW`.
    pub pow_challenge_id: Option<String>,
    /// The proof-of-work nonce (base64url no-pad) the client found (issue #80).
    pub pow_nonce: Option<String>,
    /// The request context the challenge was issued for (issue #80), echoed back so the
    /// server can recompute the context binding.
    pub pow_context: Option<String>,
    /// An external adapter (Turnstile/reCAPTCHA) response token (issue #80), when an adapter
    /// provider is configured instead of the built-in `PoW`.
    pub pow_token: Option<String>,
}

/// The anti-enumeration-uniform message for a disposable-domain block (issue #80): an
/// ORDINARY validation failure (a form re-render at 200), leaking nothing about whether the
/// identifier already exists.
const DISPOSABLE_BLOCK_MESSAGE: &str =
    "That email address cannot be used to register. Please use a different address.";

/// The message shown when a required proof-of-work challenge was not satisfied (issue #80).
const POW_REQUIRED_MESSAGE: &str = "Additional verification is required. Please try again.";

/// `GET /register`: render the registration form for a valid resume target. The
/// `display` / `ui_locales` hints carried on the resuming request shape the page
/// shell, and the `login_hint` prefills the identifier (issue #16).
pub async fn register_get(
    State(state): State<OidcState>,
    Query(query): Query<ResumeQuery>,
) -> Response {
    match parse_resume(query.return_to.as_deref()) {
        Some(resume) => {
            // The environment-kind chrome (issue #42): non-production marks the page
            // noindex and shows a banner; prod shows neither.
            let banner = state.environment_banner(&resume.scope).await;
            pages::secure_html(
                StatusCode::OK,
                pages::register_page(
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

/// `POST /register`: create the account, then auto-establish a session and resume.
// The linear flow (parse, CSRF, regulate, closed-registration uniform path, open-mode
// create) reads best as one function; splitting it would scatter the anti-enumeration
// invariant, so the length lint is allowed here (issue #64).
#[allow(clippy::too_many_lines)]
pub async fn register_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let Some(resume) = parse_resume(form.return_to.as_deref()) else {
        return interaction::invalid_link_page();
    };

    // CSRF defense-in-depth (issue #196), BEFORE creating the account, spending an
    // Argon2 hash, or establishing a session: unlike a later interaction, this POST
    // needs NO pre-existing cookie and MINTS the session on success, so the
    // SameSite=Lax backstop does not protect it and a cross-site auto-submit would
    // otherwise sign the victim into an attacker-known account (login-CSRF / session
    // fixation). The same Origin + Sec-Fetch-Site allowlist the login and consent
    // POSTs use refuses a conclusively cross-site POST with a generic 403; no
    // account is created and no password work is spent.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }

    let identifier = form
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let password = form.password.as_deref().unwrap_or_default();

    // The environment-kind chrome (issue #42) for any re-rendered error page.
    let banner = state.environment_banner(&resume.scope).await;

    // Credential-abuse regulation for the REGISTER path (issue #64), keyed on the
    // canonical identifier and the resolved peer IP, INDEPENDENTLY of the password path.
    // Every processed attempt is counted, so registration spam is throttled per
    // identifier and per IP without a hard lockout.
    let ctx = crate::abuse::AttemptContext {
        path: ironauth_store::AuthPath::Register,
        scope: resume.scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id: None,
        client_id: Some(resume.client_id.to_string()),
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = register_error(
            identifier,
            &resume.return_to,
            "Too many attempts. Wait a moment and try again.",
            &resume.hints,
            banner,
        );
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return response;
    }
    // `regulate_before` already RECORDED this attempt on the register-path counters (every
    // processed attempt is counted, throttled or allowed), so registration spam climbs the
    // per-identifier and per-IP throttle without a hard lockout (issue #64).

    // CLOSED registration (issue #64, the Logto v1.41 pattern): do NOT create an account
    // inline and do NOT reveal whether the identifier exists. Look the identifier up ONLY
    // to decide whether the verification send is permitted, SUPPRESS the send to an
    // unknown recipient, and return the SAME acknowledgment either way, so the surface is
    // not an enumeration oracle. The lookup runs for both present and absent identifiers,
    // so the work is uniform.
    if state.registration_closed() {
        if identifier.is_empty() {
            return register_error(
                identifier,
                &resume.return_to,
                "An identifier is required.",
                &resume.hints,
                banner,
            );
        }
        let recipient_known = matches!(
            state
                .store()
                .scoped(resume.scope)
                .users()
                .by_identifier(identifier)
                .await,
            Ok(Some(_))
        );
        state.dispatch_verification(
            resume.scope,
            crate::verification::VerificationPurpose::Registration,
            identifier,
            recipient_known,
        );
        return registration_ack_page(banner);
    }

    if identifier.is_empty() {
        return register_error(
            identifier,
            &resume.return_to,
            "An identifier is required.",
            &resume.hints,
            banner,
        );
    }

    // Disposable / low-reputation email defense (issue #80), evaluated on the
    // NFKC-normalized email domain per the per-environment config (off / flag / block). A
    // BLOCK is an anti-enumeration UNIFORM failure: the same 200 form re-render an ordinary
    // validation failure produces, leaking nothing about whether the identifier exists. A
    // FLAG admits but feeds the risk engine a signal (raising the PoW challenge level below).
    let disposable = crate::disposable::evaluate(
        &state.registration_abuse_config().disposable_email,
        &ironauth_screening::normalize_nfkc(identifier),
    );
    // The fraud review queue (issue #82, PR 2): when the signup-quarantine feature is armed,
    // a registration the risk path would BLOCK is instead QUARANTINED (created with limited
    // privileges and parked in the admin review queue) so a false positive is RECOVERABLE.
    // The reason is captured here and the create below chooses the quarantine path; with the
    // flag OFF the block returns immediately exactly as before (byte-identical behavior).
    let mut quarantine_reason: Option<SignupQuarantineReason> = None;
    if disposable.is_block() {
        if state.signup_quarantine_enabled() {
            quarantine_reason = Some(SignupQuarantineReason::RiskOutput);
        } else {
            return register_error(
                identifier,
                &resume.return_to,
                DISPOSABLE_BLOCK_MESSAGE,
                &resume.hints,
                banner,
            );
        }
    }

    // Proof-of-work gate (issue #80), CONDITIONED on the #79 risk level (a flagged
    // disposable domain or a suspect IP raises it). Runs BEFORE the Argon2 hash so an
    // unsolved bot attempt spends no password work. The built-in PoW is fully server-side
    // (ZERO third-party calls); an unsolved or missing solution re-renders the form.
    let peer_ip = crate::abuse::resolved_client_ip(&headers);
    if crate::pow_gate::challenge_required(&state, peer_ip.as_deref(), disposable.is_flagged()) {
        let solution = crate::pow_gate::PresentedSolution {
            challenge_id: form.pow_challenge_id.as_deref(),
            nonce: form.pow_nonce.as_deref(),
            context: form.pow_context.as_deref().unwrap_or_default(),
            token: form.pow_token.as_deref(),
            remote_ip: peer_ip.as_deref(),
        };
        if !crate::pow_gate::verify_solution(
            &state,
            resume.scope,
            crate::pow_gate::ENDPOINT_REGISTER,
            &solution,
        )
        .await
        {
            // A failed registration challenge (issue #82, PR 2): with the signup-quarantine
            // feature armed, quarantine the signup instead of blocking it; otherwise block
            // exactly as before.
            if state.signup_quarantine_enabled() {
                quarantine_reason = Some(SignupQuarantineReason::ChallengeFailure);
            } else {
                return register_error(
                    identifier,
                    &resume.return_to,
                    POW_REQUIRED_MESSAGE,
                    &resume.hints,
                    banner,
                );
            }
        }
    }

    // NFKC-normalize ONCE (issue #63): the 800-63B-4 length check (counted in code
    // points) and breach screening both operate on the normalized form, and the hash is
    // derived from the same normalized form, so a Unicode password round-trips.
    let normalized = ironauth_screening::normalize_nfkc(password);
    // 800-63B-4 policy: a registration password is the SOLE authentication factor (15
    // code points by default, no composition unless a legacy tenant enabled it). A policy
    // failure re-renders the form with a clear, non-enumerating message; NO hash is spent.
    if let Err(rejection) = state
        .password_policy()
        .evaluate(&normalized, ironauth_screening::FactorContext::SoleFactor)
    {
        return register_error(
            identifier,
            &resume.return_to,
            &rejection.message(),
            &resume.hints,
            banner,
        );
    }
    // zxcvbn password-quality scoring (issue #66) AFTER the length/composition policy and
    // BEFORE any breach screen or hash: a password that is long enough but easily guessable
    // is refused here, so no outbound screening call or Argon2id hash is spent on it. OFF by
    // default (min_password_strength_score = 0), a pure/deterministic check that needs no
    // env seam. NOTE: this in-tree score is a COARSE floor blind to dictionary words / l33t
    // substitution; the breach screen below is the primary defense (issue #66).
    if let Err(rejection) = state.password_policy().evaluate_strength(&normalized) {
        return register_error(
            identifier,
            &resume.return_to,
            &rejection.message(),
            &resume.hints,
            banner,
        );
    }
    // MANDATORY breached-password screening (issue #63) BEFORE any hash is computed: only
    // the 5-char SHA-1 prefix leaves the process. A breached password is refused; a
    // provider outage follows the configured fail-open (allow + audit) or fail-closed
    // (refuse) policy.
    match state.screen_password(&resume.scope, &normalized).await {
        crate::state::ScreenDecision::Allowed => {}
        crate::state::ScreenDecision::Breached => {
            return register_error(
                identifier,
                &resume.return_to,
                crate::state::BREACHED_PASSWORD_MESSAGE,
                &resume.hints,
                banner,
            );
        }
        crate::state::ScreenDecision::RefusedUnavailable => {
            return register_error(
                identifier,
                &resume.return_to,
                crate::state::SCREENING_UNAVAILABLE_MESSAGE,
                &resume.hints,
                banner,
            );
        }
    }

    // Hash through the dedicated, admission-controlled pool (issue #62), off the
    // async threads. An over-share tenant or a saturated pool is the retryable
    // 429/503; a pool fault is the generic server error page.
    let password_hash = match state.hash_password(&resume.scope, password).await {
        Ok(hash) => hash,
        Err(crate::hashing_pool::HashRejection::Unavailable) => {
            return interaction::server_error_page();
        }
        Err(rejection) => return rejection.to_response(),
    };

    // Waitlist gate (issue #80): with waitlist mode on, a self-service signup lands in the
    // PENDING `waitlisted` lifecycle state, which CANNOT authenticate (it holds no session
    // or token capability) until an admin APPROVES it (transition to active) or REJECTS it
    // (transition to disabled) through the user-lifecycle management API. Approval then
    // resumes the normal verification/login flow.
    let waitlisted = state.registration_abuse_config().waitlist.enabled;

    // A fresh human actor for the self-registration audit; the audit target is the
    // new user id, so the created account is still identified.
    let actor = ActorRef::human(HumanId::generate(state.env()));
    let scoped = state
        .store()
        .scoped(resume.scope)
        .acting(actor, CorrelationId::generate(state.env()));
    let result = if let Some(reason) = quarantine_reason {
        // The fraud queue takes precedence over the waitlist: a risky signup is created
        // ACTIVE-but-quarantined (it can authenticate with limited privileges) plus a
        // pending review-queue row, rather than parked unauthenticatable in the waitlist.
        scoped
            .users()
            .register_quarantined(state.env(), identifier, &password_hash, reason)
            .await
    } else if waitlisted {
        scoped
            .users()
            .register_in_state(
                state.env(),
                identifier,
                &password_hash,
                ironauth_store::UserState::Waitlisted,
            )
            .await
    } else {
        scoped
            .users()
            .register(state.env(), identifier, &password_hash)
            .await
    };

    match result {
        // A waitlisted account cannot authenticate: do NOT establish a session; return the
        // uniform pending acknowledgment. Approval later resumes the normal flow. A
        // quarantined signup (issue #82) is NOT waitlisted: it falls through to the session
        // path below (it is Active, so it authenticates with limited privileges).
        Ok(_) if waitlisted && quarantine_reason.is_none() => registration_pending_page(banner),
        Ok(user_id) => {
            let subject = user_id.to_string();
            let session_actor = interaction::user_actor(&user_id);
            // Registration authenticates the new user with the password they just
            // set: a `pwd` authentication event at the current clock instant.
            let event = AuthenticationEvent::password(epoch_micros(state.now()));
            // Session-fixation defense (issue #32): establish_session rotates away
            // any prior session the request presented, in the same transaction.
            match interaction::establish_session(
                &state,
                resume.scope,
                &subject,
                &event,
                session_actor,
                &headers,
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
            &resume.hints,
            banner,
        ),
        Err(_) => interaction::server_error_page(),
    }
}

/// The UNIFORM closed-registration acknowledgment (issue #64): the SAME body and status
/// for a known and an unknown identifier, so a probe cannot tell whether an account
/// already exists. The environment banner is preserved for the non-production chrome.
fn registration_ack_page(environment_banner: Option<&str>) -> Response {
    let _ = environment_banner;
    pages::secure_html(
        StatusCode::OK,
        pages::notice_page(
            "Check your email",
            "If registration is available for that address, we have sent instructions to \
             complete it.",
        ),
    )
}

/// The waitlist PENDING acknowledgment (issue #80): a self-service signup made while
/// waitlist mode is on lands in the pending state and CANNOT authenticate until an admin
/// approves it, so no session is established and the page tells the user their registration
/// is awaiting approval.
fn registration_pending_page(environment_banner: Option<&str>) -> Response {
    let _ = environment_banner;
    pages::secure_html(
        StatusCode::OK,
        pages::notice_page(
            "Registration received",
            "Your registration is pending approval. We will be in touch once your account has \
             been reviewed.",
        ),
    )
}

/// Re-render the registration form with an error, prefilling the identifier.
fn register_error(
    identifier: &str,
    return_to: &str,
    message: &str,
    hints: &crate::hints::InteractionHints,
    environment_banner: Option<&str>,
) -> Response {
    pages::secure_html(
        StatusCode::OK,
        pages::register_page(
            identifier,
            return_to,
            Some(message),
            hints,
            environment_banner,
        ),
    )
}
