// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8628 device verification page (issue #24), built on the M2 minimal
//! login/consent bootstrap and the cross-device security BCP.
//!
//! A human opens the `verification_uri` shown on the constrained device (or scans the
//! QR-encoded `verification_uri_complete`, which prefills the user code), enters the
//! user code, signs in, and EXPLICITLY approves before any consent is recorded and
//! before the device is ever handed a token. The page is scope-routed by its own URL
//! (`/t/{tenant}/e/{environment}/device`), so the user-code lookup runs under the
//! right `(tenant, environment)` row-level-security scope.
//!
//! Cross-device BCP mitigations shipped as defaults, not options:
//!
//! - the confirmation screen shows the client name, its registered logo, and a
//!   coarse initiation-location hint, so a human can recognize a flow they did NOT
//!   start (the anti-phishing cue);
//! - approval is a distinct, explicit step (never implicit): tokens are issued only
//!   after the human clicks Approve;
//! - an unknown or expired user code shows a NON-oracular error (identical to a code
//!   that never existed), so the page is not an existence oracle;
//! - user-code entry is rate limited per source, and a flow dies after a bounded
//!   number of failed matches, so the code space cannot be brute forced (RFC 8628
//!   section 5.1);
//! - the device code and user code are NEVER logged in plaintext.

use std::net::IpAddr;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_store::{
    ActiveDeviceFlow, ConsentId, CorrelationId, DeviceApproval, DeviceApproveOutcome,
    DeviceUserCodeLookup, GrantId, Scope, user_code_hash,
};
use serde::Deserialize;

use crate::authn::AuthenticationEvent;
use crate::device::{PeerIp, normalize_user_code};
use crate::interaction::{self, AuthenticatedSession};
use crate::pages::{self, DeviceConfirmPage};
use crate::password;
use crate::state::OidcState;
use crate::util::{epoch_micros, percent_encode_query};
use crate::wellknown::parse_scope;

/// A generic, non-oracular message for any unrecognized, expired, or exhausted user
/// code (issue #24). Deliberately identical for every failure so the page reveals
/// nothing about whether a code exists.
const CODE_NOT_RECOGNIZED: &str = "That code was not recognized, or it has expired. Check the code shown on your device and try \
     again.";

/// The device-verification query (issue #24): the optional prefilled user code from
/// `verification_uri_complete`.
#[derive(Deserialize)]
pub struct DeviceQuery {
    /// The user code, when the page was opened via `verification_uri_complete`.
    user_code: Option<String>,
}

/// The device-verification POST body (issue #24). The step is inferred from which
/// fields are present: a decision (approve/deny), a sign-in (identifier/password), or
/// a code entry (`user_code` alone).
#[derive(Deserialize)]
pub struct DeviceForm {
    /// The submitted user code (the entry step, and carried through later steps).
    user_code: Option<String>,
    /// The flow handle bound on the confirmation screen (the decision step).
    device_code_id: Option<String>,
    /// The explicit decision: `allow` or `deny` (the decision step).
    decision: Option<String>,
    /// The login identifier (the sign-in step).
    identifier: Option<String>,
    /// The login password (the sign-in step).
    password: Option<String>,
}

/// `GET /t/{tenant}/e/{environment}/device`: the verification page (issue #24).
pub async fn device_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<DeviceQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return safe_notice(
            StatusCode::NOT_FOUND,
            "Not found",
            "This page is not available.",
        );
    };
    let action = device_path(&scope);
    let raw_code = query
        .user_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(raw_code) = raw_code else {
        // No code yet: show the entry form.
        return pages::secure_html(StatusCode::OK, pages::device_enter_page(&action, "", None));
    };

    match resolve_flow(&state, scope, raw_code).await {
        FlowLookup::Active(flow) => {
            // Require an authenticated session; escalate into the M2 login otherwise.
            match interaction::resolve_session(&state, scope, interaction::cookie_header(&headers))
                .await
            {
                Some(_) => render_confirm(&state, scope, &action, raw_code, &flow).await,
                None => pages::secure_html(
                    StatusCode::OK,
                    pages::device_login_page(&action, raw_code, None),
                ),
            }
        }
        FlowLookup::NotRecognized => not_recognized(&action),
        FlowLookup::ServerError => server_error(),
    }
}

/// `POST /t/{tenant}/e/{environment}/device`: advance the verification flow (issue
/// #24). The step is inferred from the submitted fields.
pub async fn device_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    PeerIp(peer): PeerIp,
    headers: HeaderMap,
    Form(form): Form<DeviceForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return safe_notice(
            StatusCode::NOT_FOUND,
            "Not found",
            "This page is not available.",
        );
    };
    // CSRF defense-in-depth (issue #196), BEFORE any state change: the SameSite=Lax
    // session cookie blocks the standard cross-site auto-submit, and this allowlist
    // closes the residuals. A conclusively cross-site POST is a generic 403.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let action = device_path(&scope);
    if form.decision.is_some() {
        device_decision(&state, scope, &action, &headers, &form).await
    } else if form.identifier.is_some() || form.password.is_some() {
        device_login(&state, scope, &action, &form).await
    } else {
        device_enter(&state, scope, &action, peer, &form).await
    }
}

/// The code-entry step: rate limit per source, look up the code, and (on a match)
/// redirect to the sign-in-or-confirm view. A non-matching code is the same
/// non-oracular error as a code that never existed.
async fn device_enter(
    state: &OidcState,
    scope: Scope,
    action: &str,
    peer: Option<IpAddr>,
    form: &DeviceForm,
) -> Response {
    let now = epoch_micros(state.now());
    // Per-source rate limit (RFC 8628 5.1): the primary defense against brute forcing
    // the user-code space. Reuses the generic fixed-window counter with a device key.
    let limit = i64::from(state.device_verification_rate_limit());
    if limit > 0 {
        let window =
            i64::try_from(state.device_verification_rate_window().as_secs()).unwrap_or(i64::MAX);
        let key = format!("device_verify:src:{}", request_source(peer));
        match state
            .store()
            .scoped(scope)
            .dcr_rate_limiter()
            .check_and_increment(&key, limit, window, now)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return safe_notice(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many attempts",
                    "Too many attempts. Wait a moment and try again.",
                );
            }
            Err(_) => return server_error(),
        }
    }

    let raw_code = form
        .user_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(raw_code) = raw_code else {
        return pages::secure_html(
            StatusCode::OK,
            pages::device_enter_page(action, "", Some("Enter the code shown on your device.")),
        );
    };
    match resolve_flow(state, scope, raw_code).await {
        FlowLookup::Active(_) => {
            let location = format!("{action}?user_code={}", percent_encode_query(raw_code));
            interaction::redirect(&location)
        }
        FlowLookup::NotRecognized => not_recognized(action),
        FlowLookup::ServerError => server_error(),
    }
}

/// The sign-in step: authenticate through the SAME credential mechanism as `/login`
/// (Argon2id verify, `__Host-` session cookie), then resume at the confirmation view.
async fn device_login(
    state: &OidcState,
    scope: Scope,
    action: &str,
    form: &DeviceForm,
) -> Response {
    let raw_code = form
        .user_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    let identifier = form
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let password = form.password.as_deref().unwrap_or_default();

    let lookup = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await;
    match lookup {
        Ok(Some(user)) if password::verify_password(password, &user.password_hash) => {
            let actor = interaction::user_actor(&user.id);
            let subject = user.id.to_string();
            let event = AuthenticationEvent::password(epoch_micros(state.now()));
            match interaction::establish_session(state, scope, &subject, &event, actor).await {
                Ok(cookie) => {
                    let location = format!("{action}?user_code={}", percent_encode_query(raw_code));
                    interaction::redirect_setting_cookie(&location, &cookie)
                }
                Err(_) => server_error(),
            }
        }
        Ok(Some(_)) => failed_login(action, raw_code),
        Ok(None) => {
            // Spend comparable Argon2id time, then the SAME generic failure.
            let _ = password::verify_absent(password);
            failed_login(action, raw_code)
        }
        Err(_) => server_error(),
    }
}

/// The decision step: require a session, re-validate the (flow, code) binding, and on
/// an explicit Approve record consent and approve the flow (opening its grant). A
/// mismatched code is a failed match against the flow (RFC 8628 5.1), which
/// eventually invalidates it.
async fn device_decision(
    state: &OidcState,
    scope: Scope,
    action: &str,
    headers: &HeaderMap,
    form: &DeviceForm,
) -> Response {
    let Some(session) =
        interaction::resolve_session(state, scope, interaction::cookie_header(headers)).await
    else {
        // No session: fall back to the sign-in step for this code.
        let raw_code = form.user_code.as_deref().unwrap_or_default();
        return pages::secure_html(
            StatusCode::OK,
            pages::device_login_page(action, raw_code, None),
        );
    };

    let raw_code = form
        .user_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    let repo = state.store().scoped(scope);
    let device_codes = repo.device_codes();
    let Some(device_code_id) = form
        .device_code_id
        .as_deref()
        .and_then(|raw| device_codes.parse_device_code_id(raw).ok())
    else {
        return not_recognized(action);
    };

    let now = epoch_micros(state.now());
    let max = i64::from(state.device_user_code_max_attempts());
    // Re-validate that the submitted code names THIS flow. A mismatch is a failed
    // match attributed to the bound flow, so a bounded number of wrong codes kills it.
    let flow = match resolve_flow(state, scope, raw_code).await {
        FlowLookup::Active(flow) if flow.device_code_id == device_code_id => flow,
        FlowLookup::ServerError => return server_error(),
        _ => {
            let _ = device_codes
                .record_failed_user_code(&device_code_id, max, now)
                .await;
            return not_recognized(action);
        }
    };

    // An explicit Approve records consent and opens the grant; any other value (Deny)
    // explicitly rejects the flow.
    if let Some("allow") = form.decision.as_deref() {
        approve_flow(state, scope, &session, &flow).await
    } else {
        let actor = interaction::subject_actor(state, scope, &session.subject);
        let result = state
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .device_codes()
            .deny(state.env(), &flow.device_code_id)
            .await;
        match result {
            Ok(()) => safe_notice(
                StatusCode::OK,
                "Request denied",
                "The device request was denied. You can close this page.",
            ),
            Err(_) => server_error(),
        }
    }
}

/// Record consent and approve the flow (issue #24), opening its grant so the next poll
/// at the token endpoint issues tokens. Tokens are issued ONLY after this explicit
/// human confirmation.
async fn approve_flow(
    state: &OidcState,
    scope: Scope,
    session: &AuthenticatedSession,
    flow: &ActiveDeviceFlow,
) -> Response {
    let actor = interaction::subject_actor(state, scope, &session.subject);
    // Record the subject's consent to the client for this scope (idempotent per
    // (subject, client)); a device flow's consent does not expire on its own.
    let consent: Result<ConsentId, _> = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .consents()
        .grant_with_expiry(
            state.env(),
            &session.subject,
            &flow.client_id,
            flow.requested_scope.as_deref(),
            None,
        )
        .await;
    let consent_id = match consent {
        Ok(id) => id.to_string(),
        Err(_) => return server_error(),
    };

    let grant_id = GrantId::generate(state.env(), &scope);
    let now = epoch_micros(state.now());
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .device_codes()
        .approve(
            state.env(),
            DeviceApproval {
                device_code_id: &flow.device_code_id,
                grant_id: &grant_id,
                subject: &session.subject,
                consent_ref: Some(&consent_id),
                auth_methods: &session.auth_methods,
                auth_time_unix_micros: Some(session.auth_time_unix_micros),
                created_at_unix_micros: now,
                now_unix_micros: now,
            },
        )
        .await;
    match result {
        Ok(DeviceApproveOutcome::Approved) => safe_notice(
            StatusCode::OK,
            "Device approved",
            "Your device is approved. Return to it to continue; you can close this page.",
        ),
        // The flow changed under us (expired or already decided): a safe error.
        Ok(DeviceApproveOutcome::NotApprovable) => not_recognized(&device_path(&scope)),
        Err(_) => server_error(),
    }
}

/// Render the confirmation screen for an active flow (issue #24): client name, logo,
/// initiation-location hint, requested scopes, and the explicit Approve/Deny form.
async fn render_confirm(
    state: &OidcState,
    scope: Scope,
    action: &str,
    raw_code: &str,
    flow: &ActiveDeviceFlow,
) -> Response {
    let Ok(client_id) = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(&flow.client_id)
    else {
        return not_recognized(action);
    };
    let profile = match state
        .store()
        .scoped(scope)
        .device_codes()
        .client_device_profile(&client_id)
        .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => return not_recognized(action),
        Err(_) => return server_error(),
    };
    let scopes: Vec<&str> = flow
        .requested_scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let device_code_id = flow.device_code_id.to_string();
    pages::device_verify_html(
        StatusCode::OK,
        pages::device_confirm_page(&DeviceConfirmPage {
            action,
            client_name: &profile.display_name,
            logo_uri: profile.logo_uri.as_deref(),
            initiation_hint: flow.initiation_hint.as_deref(),
            scopes: &scopes,
            user_code: raw_code,
            device_code_id: &device_code_id,
        }),
    )
}

/// The outcome of resolving a submitted user code to a flow (issue #24). `NotRecognized`
/// collapses both the absent and the not-approvable cases so the caller stays
/// non-oracular.
enum FlowLookup {
    Active(ActiveDeviceFlow),
    NotRecognized,
    ServerError,
}

/// Resolve a submitted (display-form) user code to an active flow within scope.
async fn resolve_flow(state: &OidcState, scope: Scope, raw_code: &str) -> FlowLookup {
    let normalized = normalize_user_code(raw_code);
    if normalized.is_empty() {
        return FlowLookup::NotRecognized;
    }
    let now = epoch_micros(state.now());
    let max = i64::from(state.device_user_code_max_attempts());
    match state
        .store()
        .scoped(scope)
        .device_codes()
        .lookup_user_code(&user_code_hash(&normalized), now, max)
        .await
    {
        Ok(DeviceUserCodeLookup::Active(flow)) => FlowLookup::Active(flow),
        Ok(DeviceUserCodeLookup::Dead | DeviceUserCodeLookup::NotFound) => {
            FlowLookup::NotRecognized
        }
        Err(_) => FlowLookup::ServerError,
    }
}

/// The verification page's own scope-routed path (the form action and redirect base).
fn device_path(scope: &Scope) -> String {
    format!("/t/{}/e/{}/device", scope.tenant(), scope.environment())
}

/// A best-effort source identifier for the per-source rate limit (issue #24): the
/// transport peer's IP, or `none` when the server installed no connection info (an
/// in-process test router), which collapses to a single shared bucket.
fn request_source(peer: Option<IpAddr>) -> String {
    peer.map_or_else(|| "none".to_owned(), |addr| addr.to_string())
}

/// Re-render the sign-in step with a generic failure (no wrong-password or
/// user-enumeration oracle), preserving the entered code.
fn failed_login(action: &str, user_code: &str) -> Response {
    pages::secure_html(
        StatusCode::OK,
        pages::device_login_page(action, user_code, Some("Incorrect identifier or password.")),
    )
}

/// The shared non-oracular error for any unrecognized/expired/exhausted code: the
/// entry form re-rendered with the one generic message.
fn not_recognized(action: &str) -> Response {
    pages::secure_html(
        StatusCode::OK,
        pages::device_enter_page(action, "", Some(CODE_NOT_RECOGNIZED)),
    )
}

/// A minimal server-authored notice page at `status`.
fn safe_notice(status: StatusCode, title: &str, message: &str) -> Response {
    pages::secure_html(status, pages::notice_page(title, message))
}

/// A generic 500 for an internal fault; never leaks tenant data.
fn server_error() -> Response {
    safe_notice(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "Something went wrong. Please try again.",
    )
}
