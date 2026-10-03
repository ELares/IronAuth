// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hosted lost-password request and browser-bound challenge issuance. These routes
//! are mounted by the provider; disabled delivery returns explicit unavailability.

use axum::extract::{DefaultBodyLimit, Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use ironauth_store::{
    ActorRef, CorrelationId, HumanId, NewPasswordReset, PasswordResetAccount,
    PasswordResetChallengeId, StoreError, UserId,
};

use crate::interaction::{self, ResumeTarget};
use crate::password_reset_browser::ResetBrowserBinding;
use crate::password_reset_delivery::{ResetRequestDelivery, send_reset_request};
use crate::password_reset_pages::{self as pages, ResetNotice};
use crate::recover::RecoverForm;
use crate::recovery::PreparedPasswordResetCase;
use crate::state::OidcState;

/// Bounded request and completion routes mounted by the provider.
/// GET never issues proof, sets a cookie or sends email.
pub fn routes() -> axum::Router<OidcState> {
    axum::Router::new()
        .route(
            "/recover",
            axum::routing::get(request_get).post(request_post),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .merge(crate::password_reset_hosted::routes())
}

async fn request_page(
    state: &OidcState,
    resume: &ResumeTarget,
    status: StatusCode,
    error: Option<&str>,
) -> Response {
    let banner = state.environment_banner(&resume.scope).await;
    let pow = &state.registration_abuse_config().pow;
    let nonce = (pow.enabled && !state.challenge_provider().kind().is_external())
        .then(|| crate::login::passkey_nonce(state));
    let challenge_url = format!(
        "/t/{}/e/{}/pow/challenge",
        resume.scope.tenant(),
        resume.scope.environment()
    );
    let verification = nonce
        .as_ref()
        .map(|nonce| crate::pages::RecoveryVerificationUi {
            nonce,
            challenge_url: &challenge_url,
        });
    let body = crate::pages::recover_page(
        resume.hints.login_hint().unwrap_or_default(),
        &resume.return_to,
        error,
        &resume.hints,
        banner,
        verification.as_ref(),
    );
    match nonce {
        Some(nonce) => crate::pages::login_html(status, body, &nonce),
        None => pages::response(status, body),
    }
}

async fn disabled(state: &OidcState, resume: &ResumeTarget) -> Response {
    pages::response(
        StatusCode::SERVICE_UNAVAILABLE,
        pages::notice_page(
            ResetNotice::UnavailableService,
            &resume.return_to,
            &resume.hints,
            state.environment_banner(&resume.scope).await,
        ),
    )
}

fn unavailable() -> Response {
    pages::response(
        StatusCode::SERVICE_UNAVAILABLE,
        crate::pages::notice_page(
            "Recovery temporarily unavailable",
            "Please try again shortly. No password has been changed.",
        ),
    )
}

/// Render only after revalidating the registered authorization continuation.
pub async fn request_get(
    State(state): State<OidcState>,
    Query(query): Query<crate::login::ResumeQuery>,
) -> Response {
    let Some(resume) = crate::authorize::recovery_resume(&state, query.return_to.as_deref()).await
    else {
        return interaction::invalid_link_page();
    };
    if !state.password_recovery_delivery_available() {
        return disabled(&state, &resume).await;
    }
    request_page(&state, &resume, StatusCode::OK, None).await
}

/// Validate browser origin, application context, proof-of-work and independent
/// recovery regulation before looking up an identifier. Eligible and ineligible
/// accounts receive the same browser-bound code-entry redirect and cookie shape.
pub async fn request_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(form): Form<RecoverForm>,
) -> Response {
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let Some(resume) = crate::authorize::recovery_resume(&state, form.return_to.as_deref()).await
    else {
        return interaction::invalid_link_page();
    };
    if !state.password_recovery_delivery_available() {
        return disabled(&state, &resume).await;
    }
    let identifier = form.identifier.as_deref().unwrap_or_default().trim();
    if identifier.is_empty() || identifier.len() > 512 {
        return request_page(
            &state,
            &resume,
            StatusCode::BAD_REQUEST,
            Some("Enter your account identifier."),
        )
        .await;
    }
    if let Some(response) = admission(&state, &resume, &headers, &form, identifier).await {
        return response;
    }
    if let Some(response) = recent_browser_attempt(&state, &headers).await {
        return response;
    }
    issue(&state, &resume, &headers, identifier).await
}

// Keep a repeated click from replacing a usable browser binding with a decoy
// during the account cooldown. Applies equally to real and decoy attempts and
// runs before identifier lookup; it cannot disclose whether an account exists.
async fn recent_browser_attempt(state: &OidcState, headers: &HeaderMap) -> Option<Response> {
    let binding = ResetBrowserBinding::from_headers(headers)?;
    let context = match state
        .store()
        .scoped(binding.challenge().scope())
        .password_reset()
        .context(state.env(), binding.challenge(), &binding.binding_hash())
        .await
    {
        Ok(context) => context?,
        Err(_) => return Some(unavailable()),
    };
    let now = crate::util::epoch_micros(state.now());
    let remaining = context
        .created_at_unix_micros
        .saturating_add(60_000_000)
        .saturating_sub(now);
    if remaining <= 0 {
        return None;
    }
    let mut response = pages::response(StatusCode::TOO_MANY_REQUESTS, pages::recent_request_page());
    response.headers_mut().insert(
        header::RETRY_AFTER,
        ((remaining + 999_999) / 1_000_000)
            .to_string()
            .parse()
            .expect("bounded integer"),
    );
    // Static local navigation, no account-specific result or capability in a URL.
    response.headers_mut().insert(
        header::LOCATION,
        "/recover/reset".parse().expect("static local path"),
    );
    Some(response)
}

async fn admission(
    state: &OidcState,
    resume: &ResumeTarget,
    headers: &HeaderMap,
    form: &RecoverForm,
    identifier: &str,
) -> Option<Response> {
    let ip = crate::abuse::resolved_client_ip(headers);
    if crate::pow_gate::challenge_required(state, ip.as_deref(), false) {
        let proof = crate::pow_gate::PresentedSolution {
            challenge_id: form.pow_challenge_id.as_deref(),
            nonce: form.pow_nonce.as_deref(),
            context: form.pow_context.as_deref().unwrap_or_default(),
            token: form.pow_token.as_deref(),
            remote_ip: ip.as_deref(),
        };
        if !crate::pow_gate::verify_solution(
            state,
            resume.scope,
            crate::pow_gate::ENDPOINT_RECOVER,
            &proof,
        )
        .await
        {
            return Some(request_page(state, resume, StatusCode::BAD_REQUEST, Some("Reload the recovery page and complete its verification before trying again.")).await);
        }
    }
    let ctx = crate::abuse::AttemptContext {
        path: ironauth_store::AuthPath::Recovery,
        scope: resume.scope,
        ip,
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id: None,
        client_id: Some(resume.client_id.to_string()),
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = request_page(
            state,
            resume,
            StatusCode::TOO_MANY_REQUESTS,
            Some("Too many recovery requests. Please wait before trying again."),
        )
        .await;
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return Some(response);
    }
    None
}

// Transient delivery content exists only in memory. No Debug, serialization or
// plaintext outbox. The durable claim prevents automatic retry after interruption.
struct PendingMail {
    subject: UserId,
    case: PreparedPasswordResetCase,
    recipient: String,
}

async fn issue(
    state: &OidcState,
    resume: &ResumeTarget,
    headers: &HeaderMap,
    identifier: &str,
) -> Response {
    let code = crate::email_otp::generate_numeric_code(state, 8);
    let hash = match state.hash_password(&resume.scope, &code).await {
        Ok(hash) => hash,
        Err(error) => {
            let original = error.to_response();
            let mut response = unavailable();
            *response.status_mut() = original.status();
            for (name, value) in original.headers() {
                if name == header::RETRY_AFTER || name.as_str().starts_with("ratelimit") {
                    response.headers_mut().insert(name.clone(), value.clone());
                }
            }
            return response;
        }
    };
    let id = PasswordResetChallengeId::generate(state.env(), &resume.scope);
    let binding = ResetBrowserBinding::generate(state.env(), id);
    let expiry = crate::util::epoch_micros(state.now()).saturating_add(300_000_000);
    let Ok(mail) = persist(state, resume, headers, identifier, &binding, &hash, expiry).await
    else {
        return unavailable();
    };
    if let Some(mail) = mail {
        let state = state.clone();
        // No SMTP latency in the public response. No handle is retained for an
        // automatic retry; a crash requires an explicit fresh request. Mail is
        // admitted and bounded by the concrete coordinator/transport.
        tokio::spawn(async move {
            let _ = send_reset_request(
                &state,
                &ResetRequestDelivery {
                    subject: &mail.subject,
                    challenge: &id,
                    primary_recipient: &mail.recipient,
                    code: &code,
                    expires_at_unix_micros: expiry,
                    cancel_url: &mail.case.cancellation_url,
                },
            )
            .await;
        });
    }
    let mut response = pages::response(StatusCode::SEE_OTHER, String::new());
    response.headers_mut().insert(
        header::LOCATION,
        "/recover/reset".parse().expect("static local path"),
    );
    response
        .headers_mut()
        .insert(header::SET_COOKIE, binding.cookie());
    response
}

async fn persist(
    state: &OidcState,
    resume: &ResumeTarget,
    headers: &HeaderMap,
    identifier: &str,
    binding: &ResetBrowserBinding,
    hash: &str,
    expiry: i64,
) -> Result<Option<PendingMail>, StoreError> {
    let scope = resume.scope;
    let ip = crate::abuse::resolved_client_ip(headers);
    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await?;
    let prepared = if let Some(user) = user {
        crate::recovery::prepare_password_reset_case(state, scope, &user.id, ip.as_deref())
            .await
            .map(|case| (user.id, case))
    } else {
        crate::recovery::decoy_recovery_work(
            state,
            scope,
            ironauth_store::RecoveryEntryPoint::LostPassword,
            identifier,
            ip.as_deref(),
        )
        .await;
        None
    };
    let acting = state.store().scoped(scope).acting(
        ActorRef::human(HumanId::generate(state.env())),
        CorrelationId::generate(state.env()),
    );
    let binding_hash = binding.binding_hash();
    let spec = || NewPasswordReset {
        id: binding.challenge(),
        client: &resume.client_id,
        browser_binding_hash: &binding_hash,
        authorization_return_to: &resume.return_to,
        account: None,
        cancellation_token_digest: None,
        code_hash: hash,
        expires_at_unix_micros: expiry,
    };
    if let Some((subject, case)) = prepared {
        let mut real = spec();
        real.account = Some(PasswordResetAccount {
            subject: &subject,
            recovery: &case.id,
        });
        real.cancellation_token_digest = Some(&case.cancellation_digest);
        match acting.password_reset().start(state.env(), real).await {
            Ok(Some(recipient)) => {
                return Ok(Some(PendingMail {
                    subject,
                    case,
                    recipient,
                }));
            }
            Err(StoreError::NotFound | StoreError::Conflict) => {}
            Err(error) => return Err(error),
            Ok(None) => return Err(StoreError::Invalid),
        }
    }
    acting.password_reset().start(state.env(), spec()).await?;
    Ok(None)
}
