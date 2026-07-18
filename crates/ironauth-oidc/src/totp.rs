// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TOTP second-factor and recovery-code endpoints (issue #69).
//!
//! Scope-routed JSON endpoints, mounted under
//! `/t/{tenant}/e/{environment}/account/mfa/...`, that a signed-in end user drives
//! to enroll and use a TOTP authenticator and its recovery codes. They mirror the
//! self-service account surface (issue #61) and the WebAuthn ceremony surface
//! (issue #65): every operation binds to the AUTHENTICATED subject recovered from
//! the session cookie (never a user-supplied id), every state change is guarded by
//! the same-origin CSRF allowlist BEFORE any mutation, and every endpoint fails
//! closed with a uniform 404 when `oidc.totp_enabled` is off.
//!
//! # The lifecycle
//!
//! - `enroll/begin` mints a fresh seed (from the entropy seam), seals it under the
//!   scope DEK (issue #48) in a PENDING row, and returns the `otpauth://`
//!   provisioning URI (rendered as a QR code by the hosted page) plus the grouped
//!   Base32 secret for manual entry. The seed is never returned raw and the pending
//!   row cannot satisfy MFA.
//! - `enroll/verify` activates the factor ONLY after the user proves possession
//!   with a valid current code, and at that moment mints the one-time recovery
//!   codes, shown EXACTLY ONCE. An abandoned enrollment leaves no active factor.
//! - `verify` checks a code as a second factor, enforcing single-use at the store
//!   (a replay within the drift window is refused) with drift resync.
//! - `recovery-codes/redeem` spends one recovery code IN PLACE OF the second
//!   factor, audited DISTINCTLY from a TOTP verification.
//! - `recovery-codes` (POST) regenerates the whole set behind fresh authentication,
//!   invalidating every prior code.
//! - `plan` reports the per-tenant factor-orchestration plan (which factor is
//!   offered or required first), the flow step the hosted login consumes.
//!
//! # The abuse-defense seam (issue #64/#72)
//!
//! TOTP verification and recovery-code redemption are the brute-forceable
//! surfaces. [`throttle_seam`] routes every attempt through the #64 abuse regulation
//! on the INDEPENDENT [`ironauth_store::AuthPath::SecondFactor`] path (issue #72): it
//! records the attempt and returns a uniform 429 once the per-subject failure budget is
//! exhausted, BEFORE any seed is opened or any code compared, and it never touches the
//! password or passkey path. The RFC 9470 step-up challenge (`/login/mfa`) runs the same
//! regulation on the same path before calling [`verify_second_factor`], so the whole
//! second-factor surface is throttled through the one #64 counter set.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_jose::{TotpParams, base32_encode, grouped_secret, provisioning_uri, verify_totp};
use ironauth_store::{
    CorrelationId, CredentialRemoveOutcome, RecoveryRedeemOutcome, Scope, TotpActivateOutcome,
    TotpVerifyOutcome, UserId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::SystemTime;

use crate::hashing_pool::HashRejection;
use crate::interaction;
use crate::state::OidcState;
use crate::wellknown::{not_found, parse_scope};

/// The number of random bytes in a freshly generated TOTP seed (160 bits, the RFC
/// 6238 / RFC 4226 recommended minimum for HMAC-SHA1 and what authenticator apps
/// expect).
const TOTP_SEED_BYTES: usize = 20;
/// The number of random bytes behind one recovery code (80 bits of entropy, well
/// beyond brute force for a single-use secret that is additionally hashed and
/// throttled).
const RECOVERY_CODE_BYTES: usize = 10;
/// The default friendly name applied to a TOTP factor when the client sends none.
const DEFAULT_TOTP_NAME: &str = "Authenticator app";

/// The resolved account context of a self-service TOTP request.
struct Account {
    scope: Scope,
    subject: UserId,
    subject_str: String,
}

/// Resolve the scope and the session cookie to an authenticated account, or the
/// response to send instead (a uniform 404 for a malformed scope, a 401 for no or
/// an invalid session).
async fn authenticate(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    headers: &HeaderMap,
) -> Result<Account, Response> {
    let Some(scope) = parse_scope(tenant_id, environment_id) else {
        return Err(not_found());
    };
    let Some(session) = interaction::resolve_session(state, scope, headers).await else {
        return Err(unauthenticated());
    };
    let Ok(subject) = UserId::parse_in_scope(&session.subject, &scope) else {
        return Err(unauthenticated());
    };
    Ok(Account {
        scope,
        subject,
        subject_str: session.subject,
    })
}

/// Throttle a second-factor verification through the #64 abuse regulation (issue
/// #72, closing the seam issue #69 left).
///
/// TOTP verification and recovery-code redemption are the brute-forceable
/// second-factor surfaces. This routes an attempt through the SAME per-subject,
/// fail-CLOSED regulation the password path uses, on the INDEPENDENT
/// [`ironauth_store::AuthPath::SecondFactor`]: it RECORDS the attempt and, once the
/// per-subject failure budget is exhausted, returns `Some(response)` (a uniform 429
/// carrying the standard rate-limit headers) BEFORE any seed is opened or any code is
/// compared, so an online guess storm is escalated (and can auto-place a
/// `second_factor` ban). It NEVER touches the password or passkey path, so a
/// second-factor storm cannot lock the owner out of primary login. Returns `None` to
/// admit (the verification runs, additionally bounded by the constant-time compare and
/// the hard store-level single-use invariant).
async fn throttle_seam(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    headers: &HeaderMap,
) -> Option<Response> {
    let ctx = crate::abuse::second_factor_attempt_context(scope, subject, headers);
    match state.regulate_before(&ctx).await {
        crate::abuse::RegulationOutcome::Throttled(snapshot) => {
            let mut response = json_response(
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "too_many_requests" }),
            );
            crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
            Some(response)
        }
        crate::abuse::RegulationOutcome::Allow => None,
    }
}

/// The current wall-clock time in whole seconds since the Unix epoch, from the
/// determinism seam (never a raw clock).
fn now_unix_secs(state: &OidcState) -> u64 {
    state
        .env()
        .clock()
        .now_utc()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The enroll-begin request body: an optional friendly name for the factor.
#[derive(Debug, Default, Deserialize)]
pub struct EnrollBeginBody {
    /// The user-authored friendly name (sealed at rest). Defaults to a generic label.
    #[serde(default)]
    friendly_name: Option<String>,
}

/// `POST /t/{tenant}/e/{environment}/account/mfa/totp/enroll`: begin a TOTP
/// enrollment. Mints a fresh seed, seals it in a PENDING row, and returns the
/// `otpauth://` provisioning URI (for the QR code) plus the grouped Base32 secret
/// (for manual entry). The factor is NOT active until `enroll/verify`.
pub async fn enroll_begin(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Option<Json<EnrollBeginBody>>,
) -> Response {
    if !state.totp_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let Json(body) = body.unwrap_or_default();
    let friendly_name = body
        .friendly_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_TOTP_NAME);
    if friendly_name.len() > 200 {
        return bad_request("friendly_name must be at most 200 characters");
    }
    // Mint a fresh seed from the entropy seam (never a raw RNG).
    let mut seed = [0u8; TOTP_SEED_BYTES];
    state.env().entropy().fill_bytes(&mut seed);
    let params = state.totp_params();
    let actor = interaction::user_actor(&account.subject);
    let enrollment = ironauth_store::NewTotpEnrollment {
        seed: &seed,
        friendly_name,
        algorithm: params.algorithm().as_str(),
        digits: i32::try_from(params.digits()).unwrap_or(6),
        period_secs: i32::try_from(params.period_secs()).unwrap_or(30),
    };
    let result = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .totp_credentials()
        .begin_enroll(state.env(), &account.subject, &enrollment)
        .await;
    let Ok(id) = result else {
        return server_error();
    };
    let issuer = state.totp_issuer();
    let uri = provisioning_uri(&issuer, &account.subject_str, &seed, params);
    let manual = grouped_secret(&seed);
    json_response(
        StatusCode::CREATED,
        json!({
            "credential_id": id.to_string(),
            "otpauth_uri": uri,
            "secret": manual,
            "algorithm": params.algorithm().as_str(),
            "digits": params.digits(),
            "period": params.period_secs(),
        }),
    )
}

/// The enroll-verify request body: the pending credential and the current code.
#[derive(Debug, Deserialize)]
pub struct EnrollVerifyBody {
    /// The `tot_` credential id returned by `enroll/begin`.
    credential_id: String,
    /// The current code from the authenticator, proving possession of the seed.
    code: String,
}

/// `POST /t/{tenant}/e/{environment}/account/mfa/totp/verify-enrollment`: activate a
/// pending TOTP factor after the user proves possession with a valid current code.
/// On success it mints and returns the one-time recovery codes, shown EXACTLY ONCE.
/// A wrong code does NOT activate the factor (an abandoned/failed enrollment leaves
/// no active factor).
pub async fn enroll_verify(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<EnrollVerifyBody>,
) -> Response {
    if !state.totp_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let credentials = state.store().scoped(account.scope).totp_credentials();
    let Ok(id) = credentials.parse_id(&body.credential_id) else {
        return not_found_json();
    };
    let material = match credentials.open_material(&account.subject, &id).await {
        Ok(Some(material)) if material.status == "pending" => material,
        Ok(_) => return not_found_json(),
        Err(_) => return server_error(),
    };
    let Some(params) = params_from_material(&material) else {
        return server_error();
    };
    let now = now_unix_secs(&state);
    let matched = verify_totp(
        &material.seed,
        params,
        now,
        u64::from(state.totp_drift_steps()),
        body.code.trim(),
    );
    let Some(step) = matched else {
        return invalid_code();
    };
    let matched_step = i64::try_from(step).unwrap_or(i64::MAX);
    let actor = interaction::user_actor(&account.subject);
    let activate = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .totp_credentials()
        .activate(state.env(), &account.subject, &id, matched_step)
        .await;
    match activate {
        Ok(TotpActivateOutcome::Activated) => {}
        Ok(TotpActivateOutcome::NotFound) => return not_found_json(),
        Ok(TotpActivateOutcome::AlreadyActive) => {
            return json_response(
                StatusCode::CONFLICT,
                json!({
                    "error": "already_enrolled",
                    "error_description": "You already have an active authenticator. Remove it \
                         before enrolling another.",
                }),
            );
        }
        Err(_) => return server_error(),
    }
    // The factor is active. Mint and return the one-time recovery codes (shown once).
    match generate_and_store_recovery_codes(&state, &account).await {
        Ok(codes) => json_response(
            StatusCode::OK,
            json!({
                "activated": true,
                "recovery_codes": codes,
                "recovery_codes_remaining": codes.len(),
            }),
        ),
        Err(response) => response,
    }
}

/// The verify request body: the current code, as a second factor.
#[derive(Debug, Deserialize)]
pub struct VerifyBody {
    /// The current code from the authenticator.
    code: String,
}

/// `POST /t/{tenant}/e/{environment}/account/mfa/totp/verify`: verify a TOTP code as
/// a second factor for the authenticated subject. Enforces single-use at the store
/// (a replay within the drift window is refused) and records the drift offset for
/// resync. Returns the honest `amr` on success.
pub async fn verify(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Response {
    if !state.totp_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    // The abuse-defense throttle seam (issue #64/#72) gates the attempt here.
    if let Some(response) = throttle_seam(&state, account.scope, &account.subject, &headers).await {
        return response;
    }
    let credentials = state.store().scoped(account.scope).totp_credentials();
    let material = match credentials.open_active_material(&account.subject).await {
        Ok(Some(material)) => material,
        Ok(None) => return not_found_json(),
        Err(_) => return server_error(),
    };
    let Some(params) = params_from_material(&material) else {
        return server_error();
    };
    let now = now_unix_secs(&state);
    let matched = verify_totp(
        &material.seed,
        params,
        now,
        u64::from(state.totp_drift_steps()),
        body.code.trim(),
    );
    let Some(step) = matched else {
        return invalid_code();
    };
    let matched_step = i64::try_from(step).unwrap_or(i64::MAX);
    let now_step = i64::try_from(params.timestep(now)).unwrap_or(0);
    let offset = i32::try_from(matched_step - now_step).unwrap_or(0);
    let actor = interaction::user_actor(&account.subject);
    let recorded = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .totp_credentials()
        .record_verification(
            state.env(),
            &account.subject,
            &material.id,
            matched_step,
            offset,
        )
        .await;
    match recorded {
        Ok(TotpVerifyOutcome::Verified) => json_response(
            StatusCode::OK,
            json!({
                "verified": true,
                "amr": ["otp", "mfa"],
            }),
        ),
        // A replay (or an earlier in-window code) is refused with the SAME uniform
        // invalid-code response, so it is never an oracle for which codes were used.
        Ok(TotpVerifyOutcome::Replay | TotpVerifyOutcome::NotFound) => invalid_code(),
        Err(_) => server_error(),
    }
}

/// The recorded second factor a step-up challenge proved (issue #72), or why it
/// could not. Distinguishes a TOTP verification from a recovery-code redemption so
/// the recorded [`AuthenticationEvent`](crate::authn::AuthenticationEvent) stays
/// honest (they map to different `amr`), and reports an unavailable hashing pool
/// distinctly so the caller can surface a retryable failure rather than a wrong
/// code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecondFactorOutcome {
    /// A valid, single-use TOTP code was verified (amr `otp`+`mfa`).
    Totp,
    /// A valid one-time recovery code was redeemed in place of the second factor
    /// (amr `kba`+`mfa`).
    Recovery,
    /// No TOTP or recovery code matched (a uniform failure; never an oracle for
    /// which codes exist).
    Invalid,
    /// The hashing pool needed to verify a recovery code was unavailable: a
    /// retryable server condition, never a wrong-code signal.
    Unavailable,
    /// A store fault while verifying.
    Error,
}

/// Verify a presented second-factor `code` for `subject` in `scope` as a step-up
/// challenge (RFC 9470, issue #72): try the subject's active TOTP first (with
/// single-use enforcement and drift resync), then fall back to a one-time recovery
/// code. This is the shared primitive the hosted step-up challenge (login/mfa)
/// drives; it records the same audited, single-use verification the self-service
/// account surface does, so a stepped-up second factor is proven exactly once.
///
/// This primitive does NOT itself throttle: its CALLER (the hosted `/login/mfa` step-up
/// challenge, issue #72) runs the #64 abuse regulation on the INDEPENDENT
/// [`ironauth_store::AuthPath::SecondFactor`] path BEFORE calling this, so an online
/// guess storm is escalated (and can auto-place a ban) before any seed is opened. A
/// genuine verification here is additionally bounded by the constant-time compare and the
/// hard store-level single-use invariant.
pub(crate) async fn verify_second_factor(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    code: &str,
) -> SecondFactorOutcome {
    // TOTP first: open the active seed material, verify the code, and enforce
    // single-use at the store (a replay within the drift window is refused).
    let credentials = state.store().scoped(scope).totp_credentials();
    match credentials.open_active_material(subject).await {
        Ok(Some(material)) => {
            let Some(params) = params_from_material(&material) else {
                return SecondFactorOutcome::Error;
            };
            let now = now_unix_secs(state);
            if let Some(step) = verify_totp(
                &material.seed,
                params,
                now,
                u64::from(state.totp_drift_steps()),
                code.trim(),
            ) {
                let matched_step = i64::try_from(step).unwrap_or(i64::MAX);
                let now_step = i64::try_from(params.timestep(now)).unwrap_or(0);
                let offset = i32::try_from(matched_step - now_step).unwrap_or(0);
                let actor = interaction::user_actor(subject);
                let recorded = state
                    .store()
                    .scoped(scope)
                    .acting(actor, CorrelationId::generate(state.env()))
                    .totp_credentials()
                    .record_verification(state.env(), subject, &material.id, matched_step, offset)
                    .await;
                return match recorded {
                    Ok(TotpVerifyOutcome::Verified) => SecondFactorOutcome::Totp,
                    // A replayed (or earlier in-window) TOTP code is a uniform failure,
                    // not an oracle: a replay is never retried as a recovery code.
                    Ok(TotpVerifyOutcome::Replay | TotpVerifyOutcome::NotFound) => {
                        SecondFactorOutcome::Invalid
                    }
                    Err(_) => SecondFactorOutcome::Error,
                };
            }
            // The TOTP did not match: fall through to a recovery-code attempt.
        }
        Ok(None) => {}
        Err(_) => return SecondFactorOutcome::Error,
    }

    // Recovery code: narrow candidates by the presented code's blind index, then
    // verify through the admission-controlled hashing pool and redeem single-use.
    let presented = normalize_recovery_code(code);
    let Ok(candidates) = state
        .store()
        .scoped(scope)
        .recovery_codes()
        .candidates_for_code(subject, &presented)
        .await
    else {
        return SecondFactorOutcome::Error;
    };
    let mut matched = None;
    for candidate in &candidates {
        match state
            .verify_password(&scope, &presented, &candidate.code_hash)
            .await
        {
            Ok(true) => {
                matched = Some(candidate.id);
                break;
            }
            Ok(false) => {}
            Err(HashRejection::Unavailable) => return SecondFactorOutcome::Unavailable,
            Err(_) => return SecondFactorOutcome::Error,
        }
    }
    let Some(id) = matched else {
        return SecondFactorOutcome::Invalid;
    };
    let actor = interaction::user_actor(subject);
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .recovery_codes()
        .redeem(state.env(), subject, &id)
        .await
    {
        Ok(RecoveryRedeemOutcome::Redeemed) => SecondFactorOutcome::Recovery,
        // A concurrent redemption won: treat as a uniform invalid (single-use held).
        Ok(RecoveryRedeemOutcome::NotFound) => SecondFactorOutcome::Invalid,
        Err(_) => SecondFactorOutcome::Error,
    }
}

/// Whether `subject` has an ACTIVE TOTP authenticator enrolled in `scope` (issue
/// #72), the signal the step-up gate uses to decide between challenging a second
/// factor and prompting enrollment.
pub(crate) async fn has_active_totp(state: &OidcState, scope: Scope, subject: &UserId) -> bool {
    state
        .store()
        .scoped(scope)
        .totp_credentials()
        .open_active_material(subject)
        .await
        .is_ok_and(|material| material.is_some())
}

/// Whether `subject` has a registered passkey in `scope` (issue #72): a
/// phishing-resistant factor that reaches the `phr`/`phrh` ACRs.
pub(crate) async fn has_passkey(state: &OidcState, scope: Scope, subject: &UserId) -> bool {
    if !state.webauthn_enabled() {
        return false;
    }
    state
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .descriptors(subject)
        .await
        .is_ok_and(|descriptors| !descriptors.is_empty())
}

/// The provisioning material for a pending TOTP enrollment driven by the headless flow
/// engine (issue #84): the `tot_` credential id to carry on the flow row, plus the
/// `otpauth://` URI and grouped Base32 secret to render so the user can add the factor.
pub(crate) struct FlowEnrollBegin {
    /// The pending `tot_` credential id.
    pub credential_id: String,
    /// The `otpauth://` provisioning URI (for a QR render).
    pub otpauth_uri: String,
    /// The grouped Base32 secret (for manual entry).
    pub secret: String,
}

/// The outcome of confirming a headless flow TOTP enrollment (issue #84).
pub(crate) enum FlowEnrollOutcome {
    /// The factor was activated by a valid current code (the just proven code is a
    /// GENUINE second factor). The one time recovery codes are returned to show once.
    Activated {
        /// The plaintext recovery codes, shown exactly once.
        recovery_codes: Vec<String>,
    },
    /// The presented code did not match (a uniform failure, never an oracle).
    Invalid,
    /// The pending enrollment could not be found (an unknown or already consumed id).
    NotFound,
    /// A store fault or a retryable server condition (the hashing pool was unavailable when
    /// minting the recovery codes): the neutral store error, never a wrong code signal.
    Error,
}

/// Begin a TOTP enrollment for the headless flow engine (issue #84): mint a fresh seed
/// from the entropy seam, seal it in a PENDING credential through the SAME store
/// primitive the account enroll handler uses ([`enroll_begin`]), and return the
/// provisioning material to render. The factor is NOT active until [`flow_enroll_verify`]
/// proves possession, exactly as the account surface requires.
pub(crate) async fn flow_enroll_begin(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
) -> Result<FlowEnrollBegin, ()> {
    let mut seed = [0u8; TOTP_SEED_BYTES];
    state.env().entropy().fill_bytes(&mut seed);
    let params = state.totp_params();
    let actor = interaction::user_actor(subject);
    let enrollment = ironauth_store::NewTotpEnrollment {
        seed: &seed,
        friendly_name: DEFAULT_TOTP_NAME,
        algorithm: params.algorithm().as_str(),
        digits: i32::try_from(params.digits()).unwrap_or(6),
        period_secs: i32::try_from(params.period_secs()).unwrap_or(30),
    };
    let id = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .totp_credentials()
        .begin_enroll(state.env(), subject, &enrollment)
        .await
        .map_err(|_| ())?;
    let subject_str = subject.to_string();
    let uri = provisioning_uri(&state.totp_issuer(), &subject_str, &seed, params);
    Ok(FlowEnrollBegin {
        credential_id: id.to_string(),
        otpauth_uri: uri,
        secret: grouped_secret(&seed),
    })
}

/// Rebuild the provisioning material for an already begun pending TOTP enrollment (issue
/// #84), so a re-render after a wrong confirmation code shows the SAME secret without
/// minting a new one. Returns [`None`] when the pending credential is gone (expired or
/// consumed). The secret lives only in the sealed pending row, never on the flow row.
pub(crate) async fn flow_enroll_material(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    credential_id: &str,
) -> Option<FlowEnrollBegin> {
    let credentials = state.store().scoped(scope).totp_credentials();
    let id = credentials.parse_id(credential_id).ok()?;
    let material = match credentials.open_material(subject, &id).await {
        Ok(Some(material)) if material.status == "pending" => material,
        _ => return None,
    };
    let params = params_from_material(&material)?;
    let subject_str = subject.to_string();
    let uri = provisioning_uri(&state.totp_issuer(), &subject_str, &material.seed, params);
    Some(FlowEnrollBegin {
        credential_id: credential_id.to_owned(),
        otpauth_uri: uri,
        secret: grouped_secret(&material.seed),
    })
}

/// Confirm a headless flow TOTP enrollment (issue #84): verify the presented current code
/// against the PENDING seed, activate the factor through the SAME store primitives the
/// account [`enroll_verify`] handler uses, and mint the one time recovery codes. This is
/// the shared enroll ceremony, so a factor enrolled through the flow is proven and audited
/// exactly like one enrolled through the account surface.
pub(crate) async fn flow_enroll_verify(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    credential_id: &str,
    code: &str,
) -> FlowEnrollOutcome {
    let credentials = state.store().scoped(scope).totp_credentials();
    let Ok(id) = credentials.parse_id(credential_id) else {
        return FlowEnrollOutcome::NotFound;
    };
    let material = match credentials.open_material(subject, &id).await {
        Ok(Some(material)) if material.status == "pending" => material,
        Ok(_) => return FlowEnrollOutcome::NotFound,
        Err(_) => return FlowEnrollOutcome::Error,
    };
    let Some(params) = params_from_material(&material) else {
        return FlowEnrollOutcome::Error;
    };
    let now = now_unix_secs(state);
    let Some(step) = verify_totp(
        &material.seed,
        params,
        now,
        u64::from(state.totp_drift_steps()),
        code.trim(),
    ) else {
        return FlowEnrollOutcome::Invalid;
    };
    let matched_step = i64::try_from(step).unwrap_or(i64::MAX);
    let actor = interaction::user_actor(subject);
    let activate = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .totp_credentials()
        .activate(state.env(), subject, &id, matched_step)
        .await;
    match activate {
        Ok(TotpActivateOutcome::Activated | TotpActivateOutcome::AlreadyActive) => {}
        Ok(TotpActivateOutcome::NotFound) => return FlowEnrollOutcome::NotFound,
        Err(_) => return FlowEnrollOutcome::Error,
    }
    let account = Account {
        scope,
        subject: *subject,
        subject_str: subject.to_string(),
    };
    match generate_and_store_recovery_codes(state, &account).await {
        Ok(recovery_codes) => FlowEnrollOutcome::Activated { recovery_codes },
        Err(_) => FlowEnrollOutcome::Error,
    }
}

/// The remove request body: the TOTP factor to remove.
#[derive(Debug, Deserialize)]
pub struct RemoveBody {
    /// The `tot_` credential id to remove.
    credential_id: String,
}

/// `POST /t/{tenant}/e/{environment}/account/mfa/totp/remove`: remove one of the
/// caller's OWN TOTP factors (pending or active). Subject-bound: another user's id
/// is the uniform not-found. TOTP is a second factor, so removal never strands the
/// account.
pub async fn remove(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RemoveBody>,
) -> Response {
    if !state.totp_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    // Resolve the session directly (not the shared `authenticate`) so the downgrade gate
    // can read the session's freshness/strength for a fresh-reverify unblock (issue #81).
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(session) = interaction::resolve_session(&state, scope, &headers).await else {
        return unauthenticated();
    };
    let Ok(subject) = UserId::parse_in_scope(&session.subject, &scope) else {
        return unauthenticated();
    };
    let credentials = state.store().scoped(scope).totp_credentials();
    let Ok(id) = credentials.parse_id(&body.credential_id) else {
        return not_found_json();
    };
    // THE downgrade-invariant gate (issue #81 HIGH-1): TOTP is an `mfa`-strength second
    // factor, so removing it while a WEAKER recovery (an email-OTP `pwd` session) is pending
    // is BLOCKED until the delay window elapses or a fresh equal-or-stronger factor is
    // re-verified; the decision is audited either way.
    let reverify = crate::recovery::fresh_session_reverify_acr(
        &state,
        session.auth_time_unix_micros,
        &session.auth_methods,
    );
    if !crate::recovery::gate_factor_removal(
        &state,
        scope,
        &subject,
        crate::recovery::RecoveryFactor::Totp,
        reverify,
    )
    .await
    .is_allowed()
    {
        return recovery_downgrade_blocked();
    }
    let actor = interaction::user_actor(&subject);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .totp_credentials()
        .remove(state.env(), &subject, &id)
        .await;
    match result {
        Ok(CredentialRemoveOutcome::Removed) => {
            // Removing a TOTP second factor changes the credential landscape (issue #71),
            // so invalidate the subject's remembered devices (reason FactorChange): a
            // replayed device cookie then re-prompts for a second factor. Best-effort; a
            // no-op when the trusted-device feature is off.
            crate::trusted_device::invalidate_on_factor_change(&state, scope, &subject).await;
            json_response(
                StatusCode::OK,
                json!({ "id": id.to_string(), "removed": true }),
            )
        }
        Ok(_) => not_found_json(),
        Err(_) => server_error(),
    }
}

/// The recovery-redeem request body: the recovery code, in place of the second factor.
#[derive(Debug, Deserialize)]
pub struct RecoveryRedeemBody {
    /// The one-time recovery code.
    code: String,
}

/// `POST /t/{tenant}/e/{environment}/account/mfa/recovery-codes/redeem`: spend one
/// recovery code IN PLACE OF the second factor. Each code is verified against the
/// stored Argon2id hashes through the admission-controlled pool and redeemed
/// single-use. Audited DISTINCTLY from a TOTP verification.
pub async fn recovery_redeem(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RecoveryRedeemBody>,
) -> Response {
    if !state.totp_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    if let Some(response) = throttle_seam(&state, account.scope, &account.subject, &headers).await {
        return response;
    }
    let presented = normalize_recovery_code(&body.code);
    // Resolve the candidate rows by the presented code's keyed blind index (issue
    // #69): a natively generated code narrows to its ONE row (a single Argon2 verify),
    // a wrong code narrows to none (plus any imported NULL-index codes), so a wrong
    // guess no longer costs a full-set scan of Argon2 verifications.
    let Ok(candidates) = state
        .store()
        .scoped(account.scope)
        .recovery_codes()
        .candidates_for_code(&account.subject, &presented)
        .await
    else {
        return server_error();
    };
    // Find the matching unconsumed code by verifying through the hashing pool.
    let mut matched = None;
    for candidate in &candidates {
        match state
            .verify_password(&account.scope, &presented, &candidate.code_hash)
            .await
        {
            Ok(true) => {
                matched = Some(candidate.id);
                break;
            }
            Ok(false) => {}
            Err(HashRejection::Unavailable) => return server_error(),
            Err(rejection) => return rejection.to_response(),
        }
    }
    let Some(id) = matched else {
        return invalid_code();
    };
    let actor = interaction::user_actor(&account.subject);
    let redeemed = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .recovery_codes()
        .redeem(state.env(), &account.subject, &id)
        .await;
    match redeemed {
        Ok(RecoveryRedeemOutcome::Redeemed) => {
            let remaining = state
                .store()
                .scoped(account.scope)
                .recovery_codes()
                .remaining_count(&account.subject)
                .await
                .unwrap_or(0);
            json_response(
                StatusCode::OK,
                json!({
                    "redeemed": true,
                    "recovery_codes_remaining": remaining,
                    "amr": ["kba", "mfa"],
                }),
            )
        }
        // A code that vanished between read and redeem (a concurrent redemption) is
        // the same uniform invalid-code response.
        Ok(RecoveryRedeemOutcome::NotFound) => invalid_code(),
        Err(_) => server_error(),
    }
}

/// The regenerate request body: a fresh-authentication proof (issue #69). Exactly
/// one of a current password, a current TOTP code, or an unconsumed recovery code
/// must be supplied and must verify; regeneration is refused without a valid proof.
#[derive(Debug, Default, Deserialize)]
pub struct RecoveryRegenerateBody {
    /// The caller's CURRENT password, verified through the #62 hashing-pool boundary.
    #[serde(default)]
    password: Option<String>,
    /// A CURRENT code from the caller's active authenticator.
    #[serde(default)]
    totp_code: Option<String>,
    /// One of the caller's still-unconsumed recovery codes.
    #[serde(default)]
    recovery_code: Option<String>,
}

/// The method a fresh-auth proof verified through, for the honest response body.
enum FreshAuthMethod {
    Password,
    Totp,
    RecoveryCode,
}

/// `POST /t/{tenant}/e/{environment}/account/mfa/recovery-codes`: regenerate the
/// caller's recovery-code set behind fresh authentication. Regenerating is a
/// sensitive operation (it invalidates every outstanding code and mints a fresh set),
/// so a valid session and same-origin CSRF are NOT enough: the request must carry a
/// CURRENT credential proof (the password, a current TOTP code, or an unconsumed
/// recovery code) that is verified BEFORE anything is regenerated. This is a "sudo"
/// re-auth on the single sensitive operation, so a stolen or shared already-signed-in
/// cookie cannot silently rotate a victim's recovery codes (a recovery denial of
/// service). It is
/// independent of the full #72 login-flow step-up. Regeneration invalidates ALL prior
/// codes and returns the fresh set, shown EXACTLY ONCE.
pub async fn recovery_regenerate(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Option<Json<RecoveryRegenerateBody>>,
) -> Response {
    if !state.totp_enabled() {
        return not_found();
    }
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return forbidden();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let Json(body) = body.unwrap_or_default();
    // The fresh-auth gate: refuse to regenerate without a verified current credential.
    let method = match verify_fresh_auth(&state, &account, &body).await {
        Ok(method) => method,
        Err(response) => return response,
    };
    match generate_and_store_recovery_codes(&state, &account).await {
        Ok(codes) => json_response(
            StatusCode::OK,
            json!({
                "regenerated": true,
                "recovery_codes": codes,
                "recovery_codes_remaining": codes.len(),
                "fresh_auth": json!({ "verified": true, "method": method.as_str() }),
            }),
        ),
        Err(response) => response,
    }
}

impl FreshAuthMethod {
    /// The honest wire label for the method a fresh-auth proof verified through.
    fn as_str(&self) -> &'static str {
        match self {
            FreshAuthMethod::Password => "password",
            FreshAuthMethod::Totp => "totp",
            FreshAuthMethod::RecoveryCode => "recovery_code",
        }
    }
}

/// Verify a fresh-authentication proof for a sensitive operation (issue #69): accept
/// the FIRST of a current password, a current TOTP code, or an unconsumed recovery
/// code that verifies, and return the method. A request that supplies a proof which
/// does not verify is the uniform 403 `invalid_proof`; a request that supplies NO
/// proof at all is the 403 `reauth_required`. The proofs are checked through the same
/// admission-controlled boundaries the login path uses (the #62 pool for the password
/// and the recovery hash; the constant-time drift verify for the TOTP code). A TOTP
/// code used as a proof is NOT consumed (this is a re-auth check, not a login), and a
/// recovery code is not redeemed (regeneration invalidates it moments later anyway).
async fn verify_fresh_auth(
    state: &OidcState,
    account: &Account,
    body: &RecoveryRegenerateBody,
) -> Result<FreshAuthMethod, Response> {
    let mut provided = false;

    // A current password, verified against the stored verifier through the #62 pool.
    if let Some(password) = body.password.as_deref().filter(|p| !p.is_empty()) {
        provided = true;
        let stored = state
            .store()
            .scoped(account.scope)
            .users()
            .password_hash_for_subject(&account.subject)
            .await;
        match stored {
            Ok(Some(hash)) => match state.verify_password(&account.scope, password, &hash).await {
                Ok(true) => return Ok(FreshAuthMethod::Password),
                Ok(false) => {}
                Err(HashRejection::Unavailable) => return Err(server_error()),
                Err(rejection) => return Err(rejection.to_response()),
            },
            // No password credential on the account: this proof cannot verify, but a
            // TOTP or recovery-code proof still can.
            Ok(None) => {}
            Err(_) => return Err(server_error()),
        }
    }

    // A current TOTP code from the active authenticator (constant-time drift verify).
    if let Some(code) = body
        .totp_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        provided = true;
        match state
            .store()
            .scoped(account.scope)
            .totp_credentials()
            .open_active_material(&account.subject)
            .await
        {
            Ok(Some(material)) => {
                let Some(params) = params_from_material(&material) else {
                    return Err(server_error());
                };
                let now = now_unix_secs(state);
                if verify_totp(
                    &material.seed,
                    params,
                    now,
                    u64::from(state.totp_drift_steps()),
                    code,
                )
                .is_some()
                {
                    return Ok(FreshAuthMethod::Totp);
                }
            }
            Ok(None) => {}
            Err(_) => return Err(server_error()),
        }
    }

    // An unconsumed recovery code (resolved by its blind index, verified once).
    if let Some(raw) = body.recovery_code.as_deref() {
        let normalized = normalize_recovery_code(raw);
        if !normalized.is_empty() {
            provided = true;
            match state
                .store()
                .scoped(account.scope)
                .recovery_codes()
                .candidates_for_code(&account.subject, &normalized)
                .await
            {
                Ok(candidates) => {
                    for candidate in &candidates {
                        match state
                            .verify_password(&account.scope, &normalized, &candidate.code_hash)
                            .await
                        {
                            Ok(true) => return Ok(FreshAuthMethod::RecoveryCode),
                            Ok(false) => {}
                            Err(HashRejection::Unavailable) => return Err(server_error()),
                            Err(rejection) => return Err(rejection.to_response()),
                        }
                    }
                }
                Err(_) => return Err(server_error()),
            }
        }
    }

    if provided {
        Err(invalid_proof())
    } else {
        Err(reauth_required())
    }
}

/// `GET /t/{tenant}/e/{environment}/account/mfa/plan`: the per-tenant
/// factor-orchestration plan the hosted flow consumes (issue #69): the ordered
/// factor steps (which factor is offered first) and whether the subject must enroll
/// a second factor. Two tenant configs with different `mfa_factor_order` /
/// `mfa_required` demonstrably produce different plans.
pub async fn plan(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !state.totp_enabled() {
        return not_found();
    }
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    // What second factors does the subject actually have enrolled?
    let has_totp = state
        .store()
        .scoped(account.scope)
        .totp_credentials()
        .open_active_material(&account.subject)
        .await
        .is_ok_and(|m| m.is_some());
    let has_passkey = if state.webauthn_enabled() {
        state
            .store()
            .scoped(account.scope)
            .webauthn_credentials()
            .descriptors(&account.subject)
            .await
            .is_ok_and(|d| !d.is_empty())
    } else {
        false
    };
    let built = build_mfa_plan(
        state.mfa_factor_order(),
        has_passkey,
        has_totp,
        state.mfa_required(),
    );
    let steps: Vec<Value> = built
        .steps
        .iter()
        .map(|step| json!({ "factor": step.factor, "enrolled": step.enrolled }))
        .collect();
    json_response(
        StatusCode::OK,
        json!({
            "factors": steps,
            "enrollment_required": built.enrollment_required,
        }),
    )
}

/// One ordered step in the factor-orchestration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorStep {
    /// The factor kind (`passkey`, `totp`, or `password`).
    pub factor: String,
    /// Whether the subject already has this factor enrolled.
    pub enrolled: bool,
}

/// The computed factor-orchestration plan for a subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaPlan {
    /// The factor steps, in the tenant's configured order.
    pub steps: Vec<FactorStep>,
    /// Whether the subject must enroll a second factor before proceeding (policy
    /// requires MFA and the subject has none).
    pub enrollment_required: bool,
}

/// Build the factor-orchestration plan from the per-tenant order and the subject's
/// enrolled factors (issue #69). Pure, so the ordering behavior is unit-tested
/// directly: the same enrolled state under two different `order` slices yields two
/// different step orders, which is the per-tenant orchestration the acceptance
/// criteria require.
#[must_use]
pub fn build_mfa_plan(
    order: &[String],
    has_passkey: bool,
    has_totp: bool,
    mfa_required: bool,
) -> MfaPlan {
    let steps: Vec<FactorStep> = order
        .iter()
        .map(|factor| {
            let enrolled = match factor.as_str() {
                "passkey" => has_passkey,
                "totp" => has_totp,
                // A password is a primary factor and is assumed present for a
                // bootstrap account; the orchestration lists it where configured.
                _ => true,
            };
            FactorStep {
                factor: factor.clone(),
                enrolled,
            }
        })
        .collect();
    // A second factor is a passkey or a TOTP authenticator; a password alone is not.
    let has_second_factor = has_passkey || has_totp;
    MfaPlan {
        steps,
        enrollment_required: mfa_required && !has_second_factor,
    }
}

/// Generate `count` fresh recovery codes, hash each through the admission-controlled
/// pool (issue #62), and REPLACE the subject's set (invalidating any prior codes).
/// Returns the plaintext codes to show the user exactly once, or the error response.
async fn generate_and_store_recovery_codes(
    state: &OidcState,
    account: &Account,
) -> Result<Vec<String>, Response> {
    let count = state.totp_recovery_code_count() as usize;
    let mut plaintext = Vec::with_capacity(count);
    // Each entry is (normalized code, Argon2id hash). The normalized code is what the
    // store hashes AND derives the keyed blind index from (for a single-hash redeem);
    // the plaintext (with grouping hyphens) is shown to the user exactly once.
    let mut materials: Vec<(String, String)> = Vec::with_capacity(count);
    for _ in 0..count {
        let code = generate_recovery_code(state);
        // Hash the normalized (hyphen-free) code so redemption can normalize too.
        let normalized = normalize_recovery_code(&code);
        match state.hash_password(&account.scope, &normalized).await {
            Ok(hash) => materials.push((normalized, hash)),
            Err(HashRejection::Unavailable) => return Err(server_error()),
            Err(rejection) => return Err(rejection.to_response()),
        }
        plaintext.push(code);
    }
    let codes: Vec<ironauth_store::NewRecoveryCode<'_>> = materials
        .iter()
        .map(|(normalized, hash)| ironauth_store::NewRecoveryCode {
            normalized_code: normalized,
            code_hash: hash,
        })
        .collect();
    let actor = interaction::user_actor(&account.subject);
    let stored = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .recovery_codes()
        .replace_all(state.env(), &account.subject, &codes)
        .await;
    match stored {
        Ok(_) => Ok(plaintext),
        Err(_) => Err(server_error()),
    }
}

/// Normalize a recovery code to its comparison form (issue #69): strip the grouping
/// hyphens and any spaces the user typed, so the same code hashes and blind-indexes
/// identically at generation and at redemption.
fn normalize_recovery_code(code: &str) -> String {
    code.trim().replace(['-', ' '], "")
}

/// A single recovery code: `RECOVERY_CODE_BYTES` of entropy, Base32-encoded and
/// grouped into hyphen-separated blocks of four for legibility. The plaintext is
/// shown once; only its Argon2id hash is stored.
fn generate_recovery_code(state: &OidcState) -> String {
    let mut bytes = [0u8; RECOVERY_CODE_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    let encoded = base32_encode(&bytes);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 4);
    for (index, ch) in encoded.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Rebuild the [`TotpParams`] from a stored credential's parameters. Returns `None`
/// only if a stored parameter is out of range (a corrupt row), which the caller
/// maps to a server error.
fn params_from_material(material: &ironauth_store::TotpMaterial) -> Option<TotpParams> {
    let algorithm = ironauth_jose::TotpAlgorithm::parse(&material.algorithm)?;
    let digits = u32::try_from(material.digits).ok()?;
    let period = u64::try_from(material.period_secs).ok()?;
    TotpParams::new(algorithm, digits, period).ok()
}

/// A JSON response at `status` with `no-store` caching.
#[allow(clippy::needless_pass_by_value)]
fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// The uniform invalid-code response (a wrong TOTP code, a replay, or a wrong
/// recovery code): byte-identical across those cases so it is never an oracle.
fn invalid_code() -> Response {
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": "invalid_code",
            "error_description": "That code is not valid. Try the current code from your \
                 authenticator, or a recovery code.",
        }),
    )
}

/// A 401 for a request with no or an invalid session.
fn unauthenticated() -> Response {
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": "unauthenticated",
            "error_description": "Sign in to manage your account.",
        }),
    )
}

/// A 403 for a sensitive regeneration attempted with NO fresh-authentication proof.
fn reauth_required() -> Response {
    json_response(
        StatusCode::FORBIDDEN,
        json!({
            "error": "reauth_required",
            "error_description": "Confirm your identity to regenerate recovery codes: supply your \
                 current password, a current authenticator code, or an unused recovery code.",
        }),
    )
}

/// A 403 for a regeneration whose supplied fresh-authentication proof did not verify.
fn invalid_proof() -> Response {
    json_response(
        StatusCode::FORBIDDEN,
        json!({
            "error": "invalid_proof",
            "error_description": "That credential is not valid. Try your current password, a \
                 current authenticator code, or an unused recovery code.",
        }),
    )
}

/// A 403 for a state-changing POST refused by the same-origin CSRF allowlist.
fn forbidden() -> Response {
    json_response(
        StatusCode::FORBIDDEN,
        json!({
            "error": "forbidden",
            "error_description": "This request could not be verified.",
        }),
    )
}

/// The uniform 404 for a resource the caller does not own or that is absent.
fn not_found_json() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        json!({
            "error": "not_found",
            "error_description": "No such resource.",
        }),
    )
}

/// The `409` a removal returns when THE downgrade invariant blocks it (issue #81 HIGH-1):
/// a recovery is pending and removing this second factor would silently drop a factor
/// STRONGER than the one used to recover, before the delay window has elapsed and without a
/// fresh equal-or-stronger re-verification. Non-enumerating and actionable.
fn recovery_downgrade_blocked() -> Response {
    json_response(
        StatusCode::CONFLICT,
        json!({
            "error": "recovery_downgrade_blocked",
            "error_description": "A recovery is pending on this account. Removing a stronger \
                 sign-in factor is held until the recovery delay elapses, or until you \
                 re-verify with an equal-or-stronger factor.",
        }),
    )
}

/// A 400 for a malformed request body.
fn bad_request(message: &str) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_request", "error_description": message }),
    )
}

/// A generic 500 that never reveals what failed.
fn server_error() -> Response {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({
            "error": "server_error",
            "error_description": "The request could not be processed.",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn factor_order_is_honored_per_tenant() {
        // Two tenants with opposite factor orders produce opposite plans for the same
        // enrolled state: this is the per-tenant orchestration the acceptance
        // criteria require.
        let passkey_first = build_mfa_plan(&order(&["passkey", "totp"]), true, true, false);
        let totp_first = build_mfa_plan(&order(&["totp", "passkey"]), true, true, false);
        assert_eq!(
            passkey_first
                .steps
                .iter()
                .map(|s| s.factor.as_str())
                .collect::<Vec<_>>(),
            vec!["passkey", "totp"]
        );
        assert_eq!(
            totp_first
                .steps
                .iter()
                .map(|s| s.factor.as_str())
                .collect::<Vec<_>>(),
            vec!["totp", "passkey"]
        );
    }

    #[test]
    fn enrollment_is_required_only_when_policy_demands_and_no_second_factor() {
        // Policy off: never required.
        assert!(!build_mfa_plan(&order(&["totp"]), false, false, false).enrollment_required);
        // Policy on, no second factor: required.
        assert!(build_mfa_plan(&order(&["totp"]), false, false, true).enrollment_required);
        // Policy on, a passkey enrolled: satisfied, not required.
        assert!(
            !build_mfa_plan(&order(&["totp", "passkey"]), true, false, true).enrollment_required
        );
        // Policy on, a TOTP enrolled: satisfied.
        assert!(!build_mfa_plan(&order(&["totp"]), false, true, true).enrollment_required);
    }

    #[test]
    fn plan_marks_enrolled_factors() {
        let plan = build_mfa_plan(&order(&["passkey", "totp", "password"]), true, false, false);
        assert_eq!(
            plan.steps,
            vec![
                FactorStep {
                    factor: "passkey".to_owned(),
                    enrolled: true
                },
                FactorStep {
                    factor: "totp".to_owned(),
                    enrolled: false
                },
                FactorStep {
                    factor: "password".to_owned(),
                    enrolled: true
                },
            ]
        );
    }
}
