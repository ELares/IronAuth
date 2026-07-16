// SPDX-License-Identifier: MIT OR Apache-2.0

//! The email-OTP factor: send a numeric one-time code and verify it to establish a
//! session (issue #68).
//!
//! # Safe by construction
//!
//! - **Codes are stored HASHED.** A 6-8 digit code is a low-entropy secret, so it is
//!   hashed to an Argon2id verifier through the admission-controlled hashing pool
//!   (issue #62), exactly like a password. A database dump reveals no usable code.
//! - **One active code per (user, purpose).** Reissue DELETEs the predecessor, so a
//!   fresh send invalidates the prior code (the single-active partial unique index).
//! - **Constant-time, attempt-bounded verify.** The presented code is compared through
//!   the pool's constant-time Argon2 verify; each wrong guess is counted and the code
//!   dies after `email_otp_max_attempts`, bounding an online brute force.
//! - **Abuse-throttled, anti-enumeration send.** The send is throttled per recipient and
//!   per tenant through the #64 abuse layer; a send to an unknown recipient is SUPPRESSED
//!   with an IDENTICAL acknowledgment, so the endpoint is never an existence oracle.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_store::{
    AuthPath, CorrelationId, EmailFactorPurpose, EmailOtpCodeId, NewEmailOtpCode, UserId,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::authn::AuthenticationEvent;
use crate::interaction;
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::verification::EmailOtpMessage;
use crate::wellknown::parse_scope;

/// The send-OTP request body.
#[derive(Deserialize)]
pub struct SendBody {
    /// The recipient identifier (an email address). The ONLY input that decides the
    /// recipient; an identifier matching no account is SUPPRESSED with a uniform ack.
    pub identifier: Option<String>,
    /// The flow the code authorizes (`login`, `register`, `mfa`, `recovery`,
    /// `verify_address`). Defaults to `login`.
    pub purpose: Option<String>,
}

/// The verify-OTP request body.
#[derive(Deserialize)]
pub struct VerifyBody {
    /// The recipient identifier the code was sent to.
    pub identifier: Option<String>,
    /// The flow the code authorizes (must match the send).
    pub purpose: Option<String>,
    /// The numeric code the user received.
    pub code: Option<String>,
}

/// Map a wire purpose string to the typed purpose, defaulting to `login`.
pub(crate) fn purpose_or_login(raw: Option<&str>) -> Option<EmailFactorPurpose> {
    match raw {
        None | Some("") => Some(EmailFactorPurpose::Login),
        Some(value) => EmailFactorPurpose::from_wire(value),
    }
}

/// The authentication PATH an email-factor flow is regulated on (issue #68): mapped onto
/// the existing #64 per-path counters so a code storm on one flow never throttles
/// another path (the account-DoS safeguard). Login rides the password path (both are a
/// primary sign-in attempt from the same source), MFA rides the second-factor path, and
/// recovery / register / address-verification ride their own paths.
pub(crate) fn auth_path_for(purpose: EmailFactorPurpose) -> AuthPath {
    match purpose {
        EmailFactorPurpose::Login => AuthPath::Password,
        EmailFactorPurpose::Register | EmailFactorPurpose::VerifyAddress => AuthPath::Register,
        EmailFactorPurpose::Mfa => AuthPath::SecondFactor,
        EmailFactorPurpose::Recovery => AuthPath::Recovery,
    }
}

/// A uniformly-distributed numeric one-time code of `digits` digits (issue #68), drawn
/// from the CSPRNG entropy seam by rejection sampling per digit (so there is no modulo
/// bias). Leading zeros are preserved, so the code is exactly `digits` characters.
pub(crate) fn generate_numeric_code(state: &OidcState, digits: u32) -> String {
    let entropy = state.env().entropy();
    let mut out = String::with_capacity(digits as usize);
    for _ in 0..digits {
        // Reject a byte in the biased tail (>= 250 == 25*10) so `% 10` is uniform.
        let value = loop {
            let mut byte = [0_u8; 1];
            entropy.fill_bytes(&mut byte);
            if byte[0] < 250 {
                break byte[0] % 10;
            }
        };
        out.push(char::from(b'0' + value));
    }
    out
}

/// Build the abuse [`AttemptContext`](crate::abuse::AttemptContext) for an email-factor
/// send or verify (issue #68): keyed on the canonical recipient identifier and the
/// resolved peer IP, on the flow's path, so the #64 per-recipient and per-tenant counters
/// govern send flooding and verify brute force. Existence-independent (the recipient
/// identifier is the same whether or not the account exists), so it never leaks existence.
pub(crate) fn attempt_context(
    scope: ironauth_store::Scope,
    purpose: EmailFactorPurpose,
    identifier: &str,
    headers: &HeaderMap,
) -> crate::abuse::AttemptContext {
    crate::abuse::AttemptContext {
        path: auth_path_for(purpose),
        scope,
        ip: crate::abuse::resolved_client_ip(headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id: None,
        client_id: None,
    }
}

/// `POST /t/{tenant}/e/{environment}/otp/send`: issue and send a numeric email-OTP code.
/// Abuse-throttled per recipient and per tenant; a send to an unknown recipient is
/// SUPPRESSED with an IDENTICAL acknowledgment (the #64 anti-enumeration contract).
pub async fn send(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SendBody>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found_json();
    };
    if !state.email_otp_enabled() {
        return not_found_json();
    }
    if let Some(response) = state.enforce_request_quota(&scope) {
        return response;
    }
    let Some(purpose) = purpose_or_login(body.purpose.as_deref()) else {
        return bad_request("unknown purpose");
    };
    let identifier = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if identifier.is_empty() {
        // No recipient: the uniform ack, no send, no oracle.
        return ack();
    }

    // Throttle the SEND per recipient and per tenant BEFORE resolving whether the
    // recipient exists, so the throttle is existence-independent (issue #64).
    let ctx = attempt_context(scope, purpose, identifier, &headers);
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = ack();
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return response;
    }

    // Resolve the recipient ONLY to decide whether the send is permitted; the lookup runs
    // for both present and absent identifiers, so the ack is uniform.
    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .ok()
        .flatten();

    if let Some(user) = user {
        let digits = state.email_otp_code_digits();
        let code = generate_numeric_code(&state, digits);
        let code_hash = match state.hash_password(&scope, &code).await {
            Ok(hash) => hash,
            Err(rejection) => return rejection.to_response(),
        };
        let ttl = state.email_otp_code_ttl();
        let now = epoch_micros(state.now());
        let expires = now.saturating_add(i64::try_from(ttl.as_micros()).unwrap_or(i64::MAX));
        let id = EmailOtpCodeId::generate(state.env(), &scope);
        let max_attempts = i32::try_from(state.email_otp_max_attempts()).unwrap_or(5);
        let spec = NewEmailOtpCode {
            id: &id,
            subject: &user.id,
            purpose,
            code_hash: &code_hash,
            recipient_email: identifier,
            max_attempts,
            expires_at_unix_micros: expires,
        };
        let issued = state
            .store()
            .scoped(scope)
            .acting(
                interaction::user_actor(&user.id),
                CorrelationId::generate(state.env()),
            )
            .email_otp_codes()
            .issue(state.env(), spec, now)
            .await;
        if issued.is_err() {
            // A failed issue means no code was stored: for anti-enumeration return the
            // SAME uniform ack a suppressed send returns, never a status difference that
            // would distinguish a present from an absent recipient. Recorded on the
            // observability plane only.
            tracing::error!(target: "ironauth.verification", "email OTP issue failed");
            return ack();
        }
        let message = EmailOtpMessage {
            scope,
            purpose,
            recipient: identifier,
            code: &code,
            ttl_secs: ttl.as_secs(),
        };
        state.deliver_email_otp(&message, true);
    } else {
        // Unknown recipient: SUPPRESS the send (no code stored, no delivery), identical ack.
        //
        // Anti-enumeration TIMING equalization (issue #68): the present branch above spends
        // exactly ONE pool Argon2 hash (hashing the code, ~78 ms), which dominates the
        // send-response time. A suppressed send must burn the SAME single Argon2 spend
        // through the SAME #62 pool, or the response time would distinguish a real from an
        // unknown recipient (the verify path already equalizes this with `verify_absent`).
        // No DB write happens (that is the present path's far cheaper component).
        let _ = state.verify_absent(&scope, identifier).await;
        let message = EmailOtpMessage {
            scope,
            purpose,
            recipient: identifier,
            code: "",
            ttl_secs: state.email_otp_code_ttl().as_secs(),
        };
        state.deliver_email_otp(&message, false);
    }
    ack()
}

/// `POST /t/{tenant}/e/{environment}/otp/verify`: verify a numeric email-OTP code and, on
/// success, establish a session. Constant-time compare through the hashing pool,
/// attempt-bounded, single-use, abuse-throttled.
pub async fn verify(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found_json();
    };
    if !state.email_otp_enabled() {
        return not_found_json();
    }
    if let Some(response) = state.enforce_request_quota(&scope) {
        return response;
    }
    let Some(purpose) = purpose_or_login(body.purpose.as_deref()) else {
        return bad_request("unknown purpose");
    };
    let identifier = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let code = body.code.as_deref().map(str::trim).unwrap_or_default();
    if identifier.is_empty() || code.is_empty() {
        return invalid_code();
    }

    // Throttle the VERIFY on the flow's path, keyed on the recipient and the peer IP, so a
    // brute force escalates to a uniform 429 (issue #64).
    let ctx = attempt_context(scope, purpose, identifier, &headers);
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = json_response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "too_many_requests" }),
        );
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return response;
    }

    // Resolve the recipient. A missing account or missing active code both spend a full
    // dummy verify (so the timing is uniform) and return the SAME invalid-code result.
    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .ok()
        .flatten();
    let Some(user) = user else {
        let _ = state.verify_absent(&scope, code).await;
        return invalid_code();
    };
    let active = match state
        .store()
        .scoped(scope)
        .email_otp_codes()
        .resolve_active(&user.id, purpose, epoch_micros(state.now()))
        .await
    {
        Ok(Some(active)) => active,
        Ok(None) => {
            let _ = state.verify_absent(&scope, code).await;
            return invalid_code();
        }
        Err(_) => return server_error(),
    };

    let matched = match state.verify_password(&scope, code, &active.code_hash).await {
        Ok(matched) => matched,
        Err(rejection) => return rejection.to_response(),
    };
    if !matched {
        // Record the wrong guess; the code dies once the attempt budget is spent.
        let _ = state
            .store()
            .scoped(scope)
            .acting(
                interaction::user_actor(&user.id),
                CorrelationId::generate(state.env()),
            )
            .email_otp_codes()
            .record_wrong_guess(&active.id, epoch_micros(state.now()))
            .await;
        return invalid_code();
    }

    // Correct code: consume it single-use, then establish the session.
    let consumed = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&user.id),
            CorrelationId::generate(state.env()),
        )
        .email_otp_codes()
        .consume(state.env(), &active.id, epoch_micros(state.now()))
        .await;
    match consumed {
        Ok(true) => {}
        // A race already consumed it: the uniform invalid-code result.
        Ok(false) => return invalid_code(),
        Err(_) => return server_error(),
    }

    establish_and_respond(&state, scope, &user.id, &ctx, &headers).await
}

/// Establish a session for a verified email-factor login and return a JSON result that
/// SETS the session cookie, with the honest `amr` (issue #68). Shared by the OTP verify
/// and (via a thin wrapper) the magic-link consume.
pub(crate) async fn establish_and_respond(
    state: &OidcState,
    scope: ironauth_store::Scope,
    subject: &UserId,
    ctx: &crate::abuse::AttemptContext,
    headers: &HeaderMap,
) -> Response {
    let event = AuthenticationEvent::email_otp(epoch_micros(state.now()));
    let actor = interaction::user_actor(subject);
    match interaction::establish_session(state, scope, &subject.to_string(), &event, actor, headers)
        .await
    {
        Ok(cookies) => {
            // A successful login relaxes the abuse throttle for this source (issue #64).
            state.reset_after_success(ctx).await;
            let body = json_response(
                StatusCode::OK,
                json!({ "authenticated": true, "amr": ["otp"] }),
            );
            interaction::attach_session_cookies(body, &cookies)
        }
        Err(_) => server_error(),
    }
}

/// The UNIFORM send acknowledgment (issue #68): the SAME body and status whether the
/// recipient exists, is unknown (suppressed), or the send succeeded.
fn ack() -> Response {
    json_response(
        StatusCode::OK,
        json!({ "status": "sent", "message": "If an account exists, a code has been sent." }),
    )
}

/// A JSON response at `status` with the hardened no-store headers.
fn json_response(status: StatusCode, body: Value) -> Response {
    use axum::response::IntoResponse;
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// The uniform wrong / expired / over-attempted code result (never an oracle).
fn invalid_code() -> Response {
    json_response(StatusCode::UNAUTHORIZED, json!({ "error": "invalid_code" }))
}

/// A uniform not-found for a bad scope or a disabled factor.
fn not_found_json() -> Response {
    json_response(StatusCode::NOT_FOUND, json!({ "error": "not_found" }))
}

/// A generic bad-request for a malformed non-identity input (a bad purpose).
fn bad_request(message: &str) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_request", "error_description": message }),
    )
}

/// A generic server error that never reveals what failed.
fn server_error() -> Response {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({ "error": "server_error" }),
    )
}
