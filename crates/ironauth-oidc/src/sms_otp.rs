// SPDX-License-Identifier: MIT OR Apache-2.0

//! The guarded SMS-OTP factor (issue #70): send a numeric code by text and verify it to
//! establish a session, wrapping the #68 email-OTP core in the SMS-specific guard layer.
//!
//! # The OTP core is REUSED from issue #68
//!
//! Code generation ([`generate_numeric_code`](crate::email_otp::generate_numeric_code)),
//! hashing through the #62 pool, single-active-per-(subject, purpose) issuance, the
//! per-code attempt death, single-use consume, reissue invalidation, and the #64 abuse
//! throttle are all IDENTICAL to the email OTP; only the recipient (a phone number) and
//! the guard layer differ. The `amr` is honestly `sms` (RFC 8176).
//!
//! # The SMS-specific guard layer (this issue)
//!
//! 1. **Off by default.** The deployment kill switch (`sms_otp_enabled`) fails closed
//!    with a 404, and even when on, a tenant is unusable until it EXPLICITLY enables SMS
//!    AND populates a country allowlist (an empty allowlist means unusable, not open).
//! 2. **Country ALLOWLIST, not blocklist.** A destination outside the allowlist is
//!    refused with a UNIFORM, non-enumerating acknowledgment, with the SAME single dummy
//!    Argon2 spend a real send costs, so refusal is timing-indistinguishable from a send.
//! 3. **Velocity caps.** Per-number, per-tenant, and per-route send caps with a
//!    per-number cooldown, layered on the #64 in-process counters.
//! 4. **Pre-send phone scoring.** Number-type and structural checks refuse a known
//!    virtual / premium / malformed destination BEFORE any send.
//! 5. **Send-to-verify conversion telemetry.** Every delivered send and successful
//!    verify is counted per route; a route whose conversion drops below the configured
//!    threshold over a sufficient sample auto-throttles WITHOUT operator intervention
//!    (audit + ops emitted), while healthy routes keep sending.
//! 6. **No silent downgrade.** SMS can never complete a login/recovery for an account
//!    protected by a passkey or an active TOTP unless the tenant explicitly opted into
//!    the documented downgrade path.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, EmailFactorPurpose, IdentifierType, NewSmsOtpCode, Scope, SmsOtpCodeId, UserId,
    canonicalize_identifier,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::authn::AuthenticationEvent;
use crate::email_otp::{attempt_context, generate_numeric_code, purpose_or_login};
use crate::interaction;
use crate::phone::{E164, score};
use crate::sms_conversion::{conversion_percent, route_health};
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::verification::SmsOtpMessage;
use crate::wellknown::parse_scope;

/// The send-OTP request body.
#[derive(Deserialize)]
pub struct SendBody {
    /// The recipient identifier (a phone number). The ONLY input that decides the
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

/// `POST /t/{tenant}/e/{environment}/otp/sms/send`: issue and text a numeric SMS-OTP
/// code, guarded by the off-by-default enablement, the country allowlist, the velocity
/// caps, pre-send phone scoring, and the per-route pumping auto-throttle. Every refusal
/// is a UNIFORM acknowledgment with an equal dummy Argon2 spend, so no branch is an
/// existence / allowlist / scoring oracle.
// One linear guard pipeline; splitting it across helpers would obscure the ordering the
// anti-enumeration and pumping guarantees depend on.
#[allow(clippy::too_many_lines)]
pub async fn send(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    _headers: HeaderMap,
    Json(body): Json<SendBody>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found_json();
    };
    // The deployment-level kill switch: SMS OTP is off by default everywhere.
    if !state.sms_otp_enabled() {
        return not_found_json();
    }
    if let Some(response) = state.enforce_request_quota(&scope) {
        return response;
    }
    let Some(purpose) = purpose_or_login(body.purpose.as_deref()) else {
        return bad_request("unknown purpose");
    };
    let raw = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if raw.is_empty() {
        // No recipient: the uniform ack, no send, no oracle.
        return ack();
    }
    let canonical = canonicalize_identifier(IdentifierType::Phone, raw);
    let phone = canonical.as_str().to_owned();
    let parsed = E164::parse(&phone);
    let route_key = parsed.as_ref().map_or_else(
        || "invalid".to_owned(),
        |number| number.route_key().to_owned(),
    );

    let now = epoch_micros(state.now());

    // Velocity caps FIRST (issue #70): keyed on the destination number and route, both
    // existence-independent, so a rate refusal never distinguishes a real from an unknown
    // account. A per-number / per-tenant / per-route cap or the cooldown returns a 429.
    if state.sms_velocity_exceeded(scope, &route_key, &phone, now) {
        return too_many_requests();
    }

    // The per-tenant SMS configuration. A scope with no row (or SMS not enabled) keeps
    // SMS unusable: the send is refused UNIFORMLY, indistinguishable from a real send.
    let Ok(config) = state.store().scoped(scope).sms_otp().config().await else {
        return server_error();
    };

    // The uniform refusal branches (issue #70): SMS disabled for the tenant, an
    // unparseable number, a country outside the ALLOWLIST, or a number that fails
    // pre-send scoring. Each burns the SAME single Argon2 spend a real send costs and
    // returns the SAME acknowledgment, so none is an oracle.
    if !config.enabled {
        return refuse_uniform(&state, &scope, &phone, &route_key, "disabled").await;
    }
    let Some(number) = parsed else {
        return refuse_uniform(&state, &scope, &phone, &route_key, "unparseable").await;
    };
    let Ok(allowlisted) = state
        .store()
        .scoped(scope)
        .sms_otp()
        .allowlist_contains(number.country_code())
        .await
    else {
        return server_error();
    };
    if !allowlisted {
        return refuse_uniform(&state, &scope, &phone, &route_key, "not_allowlisted").await;
    }
    if let crate::phone::ScoreOutcome::Refused(number_type) =
        score(&number, state.sms_phone_scoring_enabled())
    {
        return refuse_uniform(&state, &scope, &phone, &route_key, number_type.as_str()).await;
    }

    // The per-route pumping auto-throttle (issue #70): a route the conversion defense has
    // throttled refuses UNIFORMLY, while every healthy route continues.
    let throttled = match state
        .store()
        .scoped(scope)
        .sms_otp()
        .route_stat(&route_key)
        .await
    {
        Ok(stat) => stat.is_some_and(|stat| stat.is_throttled(now)),
        Err(_) => return server_error(),
    };
    if throttled {
        return refuse_uniform(&state, &scope, &phone, &route_key, "route_throttled").await;
    }

    // Resolve the recipient ONLY to decide whether the send is permitted; the lookup runs
    // for both present and absent identifiers, so the ack is uniform.
    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(raw)
        .await
        .ok()
        .flatten();

    let Some(user) = user else {
        // Unknown recipient: SUPPRESS (no code stored, no delivery), identical ack. Burn
        // the SAME single Argon2 spend a real send costs (the timing-equalization the
        // email OTP applies), and do NOT count a send (no delivery == no pumping vector).
        let _ = state.verify_absent(&scope, &phone).await;
        let message = SmsOtpMessage {
            scope,
            purpose,
            recipient: &phone,
            route_key: &route_key,
            code: "",
            ttl_secs: state.sms_otp_code_ttl().as_secs(),
        };
        state.deliver_sms_otp(&message, false);
        return ack();
    };

    // A permitted send to a known recipient: issue the hashed code and deliver it.
    let digits = state.sms_otp_code_digits();
    let code = generate_numeric_code(&state, digits);
    let code_hash = match state.hash_password(&scope, &code).await {
        Ok(hash) => hash,
        Err(rejection) => return rejection.to_response(),
    };
    let ttl = state.sms_otp_code_ttl();
    let expires = now.saturating_add(i64::try_from(ttl.as_micros()).unwrap_or(i64::MAX));
    let id = SmsOtpCodeId::generate(state.env(), &scope);
    let max_attempts = i32::try_from(state.sms_otp_max_attempts()).unwrap_or(5);
    let spec = NewSmsOtpCode {
        id: &id,
        subject: &user.id,
        purpose,
        code_hash: &code_hash,
        recipient_phone: &phone,
        max_attempts,
        expires_at_unix_micros: expires,
    };
    let acting = state.store().scoped(scope).acting(
        interaction::user_actor(&user.id),
        CorrelationId::generate(state.env()),
    );
    if acting
        .sms_otp()
        .issue(state.env(), spec, now)
        .await
        .is_err()
    {
        // A failed issue means no code was stored: return the SAME uniform ack a
        // suppressed send returns (anti-enumeration), recorded on the observability
        // plane only.
        tracing::error!(target: "ironauth.verification", "SMS OTP issue failed");
        return ack();
    }
    let message = SmsOtpMessage {
        scope,
        purpose,
        recipient: &phone,
        route_key: &route_key,
        code: &code,
        ttl_secs: ttl.as_secs(),
    };
    state.deliver_sms_otp(&message, true);

    // Account the DELIVERED send to the route and evaluate the conversion signal, then
    // auto-throttle a pumping route WITHOUT operator intervention (issue #70).
    record_and_evaluate_route(&state, scope, &user.id, &route_key, now).await;
    ack()
}

/// `POST /t/{tenant}/e/{environment}/otp/sms/verify`: verify a numeric SMS-OTP code and,
/// on success, establish a session with the honest `sms` amr. Constant-time compare
/// through the hashing pool, attempt-bounded, single-use, abuse-throttled, and gated by
/// the no-silent-downgrade invariant.
// One linear verify pipeline; splitting it would scatter the uniform-response ordering.
#[allow(clippy::too_many_lines)]
pub async fn verify(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found_json();
    };
    if !state.sms_otp_enabled() {
        return not_found_json();
    }
    if let Some(response) = state.enforce_request_quota(&scope) {
        return response;
    }
    let Some(purpose) = purpose_or_login(body.purpose.as_deref()) else {
        return bad_request("unknown purpose");
    };
    let raw = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let code = body.code.as_deref().map(str::trim).unwrap_or_default();
    if raw.is_empty() || code.is_empty() {
        return invalid_code();
    }
    let canonical = canonicalize_identifier(IdentifierType::Phone, raw);
    let phone = canonical.as_str().to_owned();
    let route_key = E164::parse(&phone).map_or_else(
        || "invalid".to_owned(),
        |number| number.route_key().to_owned(),
    );

    // Throttle the VERIFY on the flow's path (issue #64), keyed on the recipient and the
    // peer IP, so a brute force escalates to a uniform 429.
    let ctx = attempt_context(scope, purpose, raw, &headers);
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = json_response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "too_many_requests" }),
        );
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return response;
    }

    // SMS must be enabled for the tenant; a disabled tenant verifies nothing. Spend a
    // dummy verify so a disabled tenant is timing-uniform with a wrong code.
    let Ok(config) = state.store().scoped(scope).sms_otp().config().await else {
        return server_error();
    };
    if !config.enabled {
        let _ = state.verify_absent(&scope, code).await;
        return invalid_code();
    }

    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(raw)
        .await
        .ok()
        .flatten();
    let Some(user) = user else {
        let _ = state.verify_absent(&scope, code).await;
        return invalid_code();
    };

    // The no-silent-downgrade invariant (issue #70): an account protected by a passkey or
    // an active TOTP cannot complete a PRIMARY (login) or RECOVERY authentication by SMS
    // unless the tenant explicitly opted into the downgrade path. Enforced BEFORE the
    // code is compared, with a dummy spend, so a blocked downgrade is timing-uniform with
    // a wrong code (never an oracle for which accounts hold a strong factor). SMS as an
    // additive second factor (`mfa`) or an address proof is not a downgrade, so those
    // purposes are unaffected.
    if matches!(
        purpose,
        EmailFactorPurpose::Login | EmailFactorPurpose::Recovery
    ) && !config.allow_factor_downgrade
    {
        match has_stronger_factor(&state, scope, &user.id).await {
            Ok(true) => {
                let _ = state.verify_absent(&scope, code).await;
                tracing::info!(
                    target: "ironauth.abuse",
                    tenant = %scope.tenant(),
                    environment = %scope.environment(),
                    purpose = purpose.as_str(),
                    "SMS factor-downgrade refused: account holds a stronger factor and no \
                     downgrade path is configured"
                );
                return invalid_code();
            }
            Ok(false) => {}
            Err(()) => return server_error(),
        }
    }

    let active = match state
        .store()
        .scoped(scope)
        .sms_otp()
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
        let _ = state
            .store()
            .scoped(scope)
            .acting(
                interaction::user_actor(&user.id),
                CorrelationId::generate(state.env()),
            )
            .sms_otp()
            .record_wrong_guess(&active.id, epoch_micros(state.now()))
            .await;
        return invalid_code();
    }

    // Correct code: consume it single-use, then account the successful verify to the
    // route (the conversion numerator) and establish the session.
    let consumed = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&user.id),
            CorrelationId::generate(state.env()),
        )
        .sms_otp()
        .consume(state.env(), &active.id, epoch_micros(state.now()))
        .await;
    match consumed {
        Ok(true) => {}
        Ok(false) => return invalid_code(),
        Err(_) => return server_error(),
    }
    let _ = state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&user.id),
            CorrelationId::generate(state.env()),
        )
        .sms_otp()
        .record_verify(&route_key)
        .await;

    establish_and_respond(&state, scope, &user.id, &ctx, &headers).await
}

/// Whether `subject` holds a stronger factor than SMS (a passkey or an active TOTP),
/// for the no-silent-downgrade invariant (issue #70). An error collapses to a
/// fail-closed [`Err`] so the caller refuses rather than silently permits a downgrade.
async fn has_stronger_factor(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
) -> Result<bool, ()> {
    let scoped = state.store().scoped(scope);
    let has_passkey = scoped
        .webauthn_credentials()
        .has_any(subject)
        .await
        .map_err(|_| ())?;
    if has_passkey {
        return Ok(true);
    }
    let has_totp = scoped
        .totp_credentials()
        .has_active(subject)
        .await
        .map_err(|_| ())?;
    Ok(has_totp)
}

/// Account a DELIVERED send to `route_key`, evaluate the send-to-verify conversion, and
/// AUTO-THROTTLE the route when it is pumping (issue #70): the acceptance-critical
/// pumping defense. Best-effort on the counter path (a persistence error never fails the
/// send that already went out), but the throttle + alarm, when they fire, are audited and
/// emit an ops metric exactly once.
async fn record_and_evaluate_route(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    route_key: &str,
    now: i64,
) {
    let window_micros =
        i64::try_from(state.sms_conversion_window().as_micros()).unwrap_or(i64::MAX);
    let window_floor = now.saturating_sub(window_micros);
    let acting = state.store().scoped(scope).acting(
        interaction::user_actor(subject),
        CorrelationId::generate(state.env()),
    );
    let Ok(stat) = acting
        .sms_otp()
        .record_send(state.env(), route_key, window_floor, now)
        .await
    else {
        return;
    };
    let health = route_health(
        stat.send_count,
        stat.verify_count,
        state.sms_conversion_min_samples(),
        state.sms_conversion_alarm_threshold_percent(),
    );
    if !health.is_pumping() {
        return;
    }
    let throttle_micros = i64::try_from(state.sms_route_throttle().as_micros()).unwrap_or(i64::MAX);
    let throttled_until = now.saturating_add(throttle_micros);
    let pct = conversion_percent(stat.send_count, stat.verify_count).unwrap_or(0);
    let detail = format!(
        "route={route_key} conversion_pct={pct} sends={} verifies={}",
        stat.send_count, stat.verify_count
    );
    // Only a state TRANSITION into throttled/alarmed fires the ops metric + warn, exactly
    // once per throttle episode (a repeat call, or a persistence error, is silent).
    if let Ok(true) = acting
        .sms_otp()
        .auto_throttle_route(state.env(), route_key, throttled_until, &detail)
        .await
    {
        // The alarm + throttle are ops (metric) events too (issue #70), fired once.
        metrics::counter!(
            "ironauth_sms_route_throttled_total",
            "route" => route_key.to_owned(),
        )
        .increment(1);
        tracing::warn!(
            target: "ironauth.abuse",
            tenant = %scope.tenant(),
            environment = %scope.environment(),
            route = route_key,
            conversion_pct = pct,
            "SMS route auto-throttled by the pumping defense (low send-to-verify conversion)"
        );
    }
}

/// Establish a session for a verified SMS login and return a JSON result that SETS the
/// session cookie, with the honest `sms` amr (issue #70).
async fn establish_and_respond(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    ctx: &crate::abuse::AttemptContext,
    headers: &HeaderMap,
) -> Response {
    let event = AuthenticationEvent::sms(epoch_micros(state.now()));
    let actor = interaction::user_actor(subject);
    match interaction::establish_session(state, scope, &subject.to_string(), &event, actor, headers)
        .await
    {
        Ok(cookies) => {
            state.reset_after_success(ctx).await;
            let body = json_response(
                StatusCode::OK,
                json!({ "authenticated": true, "amr": ["sms"] }),
            );
            interaction::attach_session_cookies(body, &cookies)
        }
        Err(_) => server_error(),
    }
}

/// Refuse a send UNIFORMLY (issue #70): burn the SAME single dummy Argon2 spend a real
/// send costs (so refusal is timing-indistinguishable from a delivery), record the
/// operator-safe reason on the observability plane only (never a body difference), and
/// return the SAME acknowledgment a real send returns.
async fn refuse_uniform(
    state: &OidcState,
    scope: &Scope,
    phone: &str,
    route_key: &str,
    reason: &'static str,
) -> Response {
    let _ = state.verify_absent(scope, phone).await;
    tracing::info!(
        target: "ironauth.abuse",
        tenant = %scope.tenant(),
        environment = %scope.environment(),
        route = route_key,
        reason,
        "SMS send refused by the guard layer (uniform response)"
    );
    metrics::counter!(
        "ironauth_sms_send_refused_total",
        "reason" => reason,
    )
    .increment(1);
    ack()
}

/// The UNIFORM send acknowledgment (issue #70): the SAME body and status whether the
/// recipient exists, is unknown, is refused by a guard, or the send succeeded.
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

/// The uniform wrong / expired / over-attempted / blocked-downgrade code result.
fn invalid_code() -> Response {
    json_response(StatusCode::UNAUTHORIZED, json!({ "error": "invalid_code" }))
}

/// A uniform 429 for a velocity-cap refusal (issue #70).
fn too_many_requests() -> Response {
    json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({ "error": "too_many_requests" }),
    )
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
