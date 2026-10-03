// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hosted reset completion handlers, not yet mounted. Request issuance and
//! completion-notice integration must be finished before the router enables them.

use axum::extract::{DefaultBodyLimit, Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use ironauth_store::{
    CompletePasswordReset, CorrelationId, PasswordResetContext, PasswordResetOutcome,
};
use serde::Deserialize;

use crate::interaction::{self, ResumeTarget};
use crate::password_reset_browser::ResetBrowserBinding;
use crate::password_reset_pages::{self as pages, ResetNotice};
use crate::state::OidcState;

/// Bounded hosted reset routes, deliberately not merged into the provider router
/// until issuance and completion notifications are integrated and qualified.
pub fn routes() -> axum::Router<OidcState> {
    axum::Router::new()
        .route(
            "/recover/reset",
            axum::routing::get(reset_get).post(reset_post),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
}

/// Completion body. No account, client or return destination is accepted here.
/// The mounted route must impose a 16 KiB form body limit before extraction.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetForm {
    /// Purpose-specific form proof tied to the browser cookie.
    pub csrf: String,
    /// Eight-digit email code, never normalized as a number.
    pub code: String,
    /// New password, never echoed into a response.
    pub new_password: String,
    /// Confirmation, compared after the same NFKC normalization.
    pub confirm_password: String,
}

struct Attempt {
    binding: ResetBrowserBinding,
    context: PasswordResetContext,
    resume: ResumeTarget,
    banner: Option<String>,
}

async fn resolve(state: &OidcState, headers: &HeaderMap) -> Result<Attempt, Response> {
    let binding = ResetBrowserBinding::from_headers(headers).ok_or_else(invalid)?;
    let context = state
        .store()
        .scoped(binding.challenge().scope())
        .password_reset()
        .context(state.env(), binding.challenge(), &binding.binding_hash())
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(invalid)?;
    let resume =
        interaction::parse_resume(Some(&context.authorization_return_to)).ok_or_else(invalid)?;
    if resume.client_id != context.client || resume.scope != binding.challenge().scope() {
        return Err(invalid());
    }
    let banner = state
        .environment_banner(&resume.scope)
        .await
        .map(str::to_owned);
    Ok(Attempt {
        binding,
        context,
        resume,
        banner,
    })
}

/// Navigation only: never resolves a reset challenge or grants completion authority.
async fn expired_navigation(state: &OidcState, target: Option<&str>) -> Response {
    let Some(resume) = crate::authorize::recovery_resume(state, target).await else {
        return invalid();
    };
    let banner = state.environment_banner(&resume.scope).await;
    pages::response(
        StatusCode::BAD_REQUEST,
        pages::notice_page(
            ResetNotice::UnavailableAttempt,
            &resume.return_to,
            &resume.hints,
            banner,
        ),
    )
}

fn invalid() -> Response {
    pages::response(
        StatusCode::BAD_REQUEST,
        crate::pages::notice_page(
            "Recovery link unavailable",
            "Return to the application to sign in or request a fresh recovery code.",
        ),
    )
}

fn unavailable() -> Response {
    pages::response(
        StatusCode::SERVICE_UNAVAILABLE,
        crate::pages::notice_page(
            "Recovery temporarily unavailable",
            "We could not check this recovery attempt. Please try again shortly.",
        ),
    )
}

fn timestamp_label(micros: i64) -> String {
    // httpdate accepts dates only through year 9999. Invalid stored horizons must
    // never panic the public handler or masquerade as an elapsed waiting period.
    let seconds = u64::try_from(micros).ok().map(|value| value / 1_000_000);
    seconds
        .filter(|value| *value <= 253_402_300_799)
        .and_then(|value| std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(value)))
        .map_or_else(
            || "the required recovery deadline".to_owned(),
            httpdate::fmt_http_date,
        )
}

fn form_page(
    state: &OidcState,
    attempt: &Attempt,
    status: StatusCode,
    error: Option<&str>,
) -> Response {
    let minimum = state
        .password_policy()
        .min_length_for(ironauth_screening::FactorContext::SoleFactor);
    pages::response(
        status,
        pages::code_page(
            &attempt.binding.csrf_token(),
            &attempt.resume.return_to,
            error,
            &format!(
                "Use at least {minimum} characters and a password you do not use elsewhere. Your account's password policy will be checked before saving."
            ),
            &timestamp_label(attempt.context.expires_at_unix_micros),
            &attempt.resume.hints,
            attempt.banner.as_deref(),
        ),
    )
}

fn notice(attempt: &Attempt, view: ResetNotice<'_>) -> Response {
    pages::response(
        StatusCode::OK,
        pages::notice_page(
            view,
            &attempt.resume.return_to,
            &attempt.resume.hints,
            attempt.banner.as_deref(),
        ),
    )
}

/// Read the original browser's form or bounded recovery guidance, without sends,
/// attempt consumption, password mutation, or session creation.
pub async fn reset_get(
    State(state): State<OidcState>,
    Query(navigation): Query<crate::login::ResumeQuery>,
    headers: HeaderMap,
) -> Response {
    let attempt = match resolve(&state, &headers).await {
        Ok(value) => value,
        Err(response) if response.status() == StatusCode::BAD_REQUEST => {
            return expired_navigation(&state, navigation.return_to.as_deref()).await;
        }
        Err(response) => return response,
    };
    if !state.password_recovery_delivery_available() {
        return notice(&attempt, ResetNotice::UnavailableService);
    }
    match state
        .store()
        .scoped(attempt.resume.scope)
        .password_reset()
        .challenge(
            state.env(),
            attempt.binding.challenge(),
            &attempt.binding.binding_hash(),
        )
        .await
    {
        Ok(Some(_)) => form_page(&state, &attempt, StatusCode::OK, None),
        Ok(None) => notice(&attempt, ResetNotice::UnavailableAttempt),
        Err(_) => unavailable(),
    }
}

/// Process a browser-bound reset completion mounted by the provider router.
/// It never signs the user in.
pub async fn reset_post(
    State(state): State<OidcState>,
    Query(navigation): Query<crate::login::ResumeQuery>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Response {
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return pages::response(
            StatusCode::FORBIDDEN,
            crate::pages::notice_page(
                "Request refused",
                "Return to the recovery page and try again.",
            ),
        );
    }
    let Some(binding) = ResetBrowserBinding::from_headers(&headers) else {
        return expired_navigation(&state, navigation.return_to.as_deref()).await;
    };
    if !binding.accepts_csrf(&form.csrf) {
        return invalid();
    }
    let attempt = match resolve(&state, &headers).await {
        Ok(value) => value,
        Err(response) if response.status() == StatusCode::BAD_REQUEST => {
            return expired_navigation(&state, navigation.return_to.as_deref()).await;
        }
        Err(response) => return response,
    };
    if !state.password_recovery_delivery_available() {
        return notice(&attempt, ResetNotice::UnavailableService);
    }
    let regulation = crate::abuse::AttemptContext {
        path: ironauth_store::AuthPath::Recovery,
        scope: attempt.resume.scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: None,
        account_id: None,
        client_id: Some(attempt.context.client.to_string()),
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) =
        state.regulate_before(&regulation).await
    {
        let mut response = form_page(
            &state,
            &attempt,
            StatusCode::TOO_MANY_REQUESTS,
            Some("Too many attempts. Please wait before trying again."),
        );
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return response;
    }
    complete(&state, &attempt, &form).await
}

fn validate_input(form: &ResetForm) -> Result<String, String> {
    if form.code.len() != 8 || !form.code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Enter the eight-digit recovery code.".to_owned());
    }
    let normalized = ironauth_screening::normalize_nfkc(&form.new_password);
    if normalized != ironauth_screening::normalize_nfkc(&form.confirm_password) {
        return Err("The passwords do not match. Enter them again.".to_owned());
    }
    Ok(normalized)
}

async fn screen_new_password(
    state: &OidcState,
    attempt: &Attempt,
    normalized: &str,
) -> Result<(), Response> {
    let policy = state.password_policy();
    if let Err(error) = policy
        .evaluate(normalized, ironauth_screening::FactorContext::SoleFactor)
        .and_then(|()| policy.evaluate_strength(normalized))
    {
        return Err(form_page(
            state,
            attempt,
            StatusCode::BAD_REQUEST,
            Some(&error.message()),
        ));
    }
    match state
        .screen_password(&attempt.resume.scope, normalized)
        .await
    {
        crate::state::ScreenDecision::Allowed => Ok(()),
        crate::state::ScreenDecision::Breached => Err(form_page(
            state,
            attempt,
            StatusCode::UNPROCESSABLE_ENTITY,
            Some(crate::state::BREACHED_PASSWORD_MESSAGE),
        )),
        crate::state::ScreenDecision::RefusedUnavailable => Err(form_page(
            state,
            attempt,
            StatusCode::SERVICE_UNAVAILABLE,
            Some(crate::state::SCREENING_UNAVAILABLE_MESSAGE),
        )),
    }
}

async fn complete(state: &OidcState, attempt: &Attempt, form: &ResetForm) -> Response {
    let normalized = match validate_input(form) {
        Ok(value) => value,
        Err(message) => return form_page(state, attempt, StatusCode::BAD_REQUEST, Some(&message)),
    };
    let scope = attempt.resume.scope;
    let challenge = match state
        .store()
        .scoped(scope)
        .password_reset()
        .challenge(
            state.env(),
            attempt.binding.challenge(),
            &attempt.binding.binding_hash(),
        )
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return notice(attempt, ResetNotice::UnavailableAttempt),
        Err(_) => return unavailable(),
    };
    let matched = match state
        .verify_password(&scope, &form.code, &challenge.code_hash)
        .await
    {
        Ok(value) => value,
        Err(error) => return hash_rejection(state, attempt, &error),
    };
    let request_hash = attempt
        .binding
        .completion_request_hash(&form.code, &normalized);
    match state
        .store()
        .scoped(scope)
        .password_reset()
        .receipt(
            state.env(),
            ironauth_store::PasswordResetReceipt {
                challenge: &challenge,
                browser_binding_hash: &attempt.binding.binding_hash(),
                code_matched: matched,
                request_hash: &request_hash,
            },
        )
        .await
    {
        Ok(Some(_)) => return notice(attempt, ResetNotice::Completed),
        Ok(None) => {}
        Err(_) => return unavailable(),
    }
    if let Err(response) = screen_new_password(state, attempt, &normalized).await {
        return response;
    }
    let hash = match state.hash_password(&scope, &normalized).await {
        Ok(value) => value,
        Err(error) => return hash_rejection(state, attempt, &error),
    };
    // Unproved requests must not be attributed to the account owner.
    let actor = attempt
        .context
        .subject
        .as_ref()
        .filter(|_| matched)
        .map_or_else(
            || ironauth_store::ActorRef::human(ironauth_store::HumanId::generate(state.env())),
            interaction::user_actor,
        );
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .password_reset()
        .complete(
            state.env(),
            CompletePasswordReset {
                challenge: &challenge,
                browser_binding_hash: &attempt.binding.binding_hash(),
                code_matched: matched,
                new_password_hash: &hash,
                request_hash: &attempt
                    .binding
                    .completion_request_hash(&form.code, &normalized),
            },
        )
        .await;
    completion_response(state, attempt, &outcome)
}

fn completion_response(
    state: &OidcState,
    attempt: &Attempt,
    outcome: &Result<PasswordResetOutcome, ironauth_store::StoreError>,
) -> Response {
    match outcome {
        Ok(PasswordResetOutcome::Completed { .. } | PasswordResetOutcome::Replayed { .. }) => {
            notice(attempt, ResetNotice::Completed)
        }
        Ok(PasswordResetOutcome::Held { until_unix_micros }) => notice(
            attempt,
            ResetNotice::Waiting {
                until_label: &timestamp_label(*until_unix_micros),
            },
        ),
        Ok(PasswordResetOutcome::Refused) => form_page(
            state,
            attempt,
            StatusCode::BAD_REQUEST,
            Some("This code could not complete recovery. Check the code or request a fresh one."),
        ),
        Err(_) => form_page(
            state,
            attempt,
            StatusCode::SERVICE_UNAVAILABLE,
            Some(
                "We could not confirm the result. Retry the same code and password, or try signing in with your chosen password.",
            ),
        ),
    }
}

fn hash_rejection(
    state: &OidcState,
    attempt: &Attempt,
    rejection: &crate::hashing_pool::HashRejection,
) -> Response {
    let original = rejection.to_response();
    let mut response = form_page(
        state,
        attempt,
        original.status(),
        Some("We could not check this request right now. Please try again shortly."),
    );
    for (name, value) in original.headers() {
        if name == header::RETRY_AFTER || name.as_str().starts_with("ratelimit") {
            response.headers_mut().insert(name.clone(), value.clone());
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reset_form_rejects_posted_authority_and_duplicate_fields() {
        for body in [
            "csrf=x&code=12345678&new_password=x&confirm_password=x&subject=other",
            "csrf=x&csrf=y&code=12345678&new_password=x&confirm_password=x",
        ] {
            assert!(serde_urlencoded::from_str::<ResetForm>(body).is_err());
        }
    }
    #[test]
    fn timestamp_labels_bound_untrusted_or_corrupt_horizons() {
        assert_eq!(timestamp_label(-1), "the required recovery deadline");
        assert_eq!(timestamp_label(i64::MAX), "the required recovery deadline");
        assert!(timestamp_label(1_800_000_000_000_000).ends_with("GMT"));
    }

    #[tokio::test]
    async fn reset_route_rejects_cross_origin_missing_csrf_and_oversized_forms_before_store_access()
    {
        use axum::body::Body;
        use axum::http::Request;
        use std::sync::Arc;
        use tower::ServiceExt;
        let env = ironauth_env::Env::system();
        // No database is started: these refusals must happen before any store read.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let registry = crate::issuer::IssuerRegistry::new(
            "https://auth.example.test",
            crate::issuer::JwksCacheWindow::clamped(60),
        );
        let state = OidcState::new(
            ironauth_store::Store::from_pool(pool),
            env,
            Arc::new(registry),
            &ironauth_config::OidcConfig::default(),
            "https://auth.example.test",
        );
        let router = routes().with_state(state);
        let body = "csrf=invalid&code=12345678&new_password=chosen&confirm_password=chosen";
        for (origin, payload, expected) in [
            (
                "https://foreign.test",
                body.to_owned(),
                StatusCode::FORBIDDEN,
            ),
            (
                "https://auth.example.test",
                body.to_owned(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "https://auth.example.test",
                format!("csrf={}", "a".repeat(17 * 1024)),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/recover/reset")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, origin)
                .body(Body::from(payload))
                .unwrap();
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                router.clone().oneshot(request),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), expected);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
        }
    }
    #[cfg(feature = "testing")]
    mod store_receipt;
}
