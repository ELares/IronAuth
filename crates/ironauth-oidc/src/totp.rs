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
//! # The abuse-defense seam (issue #64)
//!
//! TOTP verification and recovery-code redemption are the brute-forceable
//! surfaces. The M7 abuse-defense counters (issue #64) are being built in parallel
//! and are not merged yet, so [`throttle_seam`] is the CLEARLY MARKED integration
//! point where those counters will gate a verification. It does the correct thing
//! today (the verification runs and is bounded by the constant-time compare and the
//! store single-use invariant) and is where the #64 merge wires the per-tenant,
//! per-subject rate gate. This issue does NOT block on #64.

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
/// The step-up recent-re-authentication max age (seconds) the sensitive recovery
/// regeneration DECLARES (issue #61 seam): the declaration and enforcement seam
/// ship now; enforcement activates end to end once M7's step-up issue lands.
const STEP_UP_MAX_AGE_SECS: u64 = 300;

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

/// The abuse-defense throttle seam (issue #64, built in parallel).
///
/// This is the CLEARLY MARKED integration point where the M7 per-tenant,
/// per-subject abuse-defense counters (issue #64) will gate a TOTP verification or
/// a recovery-code redemption. Until #64 merges this is a no-op that always admits
/// (returns [`None`]): the verification still runs correctly and is bounded by the
/// constant-time compare and the hard store-level single-use invariant. When #64
/// lands, this returns `Some(response)` (a uniform 429) once the per-subject failure
/// budget is exhausted, BEFORE any seed is opened or any code compared.
fn throttle_seam(_state: &OidcState, _scope: Scope, _subject: &UserId) -> Option<Response> {
    // #64 integration point: consume a per-(tenant, subject) verification-attempt
    // token here and return a 429 when the budget is exhausted.
    None
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
    // The abuse-defense throttle seam (issue #64) gates the attempt here.
    if let Some(response) = throttle_seam(&state, account.scope, &account.subject) {
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
    let account = match authenticate(&state, &tenant_id, &environment_id, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let credentials = state.store().scoped(account.scope).totp_credentials();
    let Ok(id) = credentials.parse_id(&body.credential_id) else {
        return not_found_json();
    };
    let actor = interaction::user_actor(&account.subject);
    let result = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .totp_credentials()
        .remove(state.env(), &account.subject, &id)
        .await;
    match result {
        Ok(CredentialRemoveOutcome::Removed) => json_response(
            StatusCode::OK,
            json!({ "id": id.to_string(), "removed": true }),
        ),
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
    if let Some(response) = throttle_seam(&state, account.scope, &account.subject) {
        return response;
    }
    let Ok(candidates) = state
        .store()
        .scoped(account.scope)
        .recovery_codes()
        .unconsumed(&account.subject)
        .await
    else {
        return server_error();
    };
    let presented = body.code.trim().replace(['-', ' '], "");
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

/// `POST /t/{tenant}/e/{environment}/account/mfa/recovery-codes`: regenerate the
/// caller's recovery-code set behind fresh authentication (a sensitive operation:
/// it declares the step-up requirement). Regeneration invalidates ALL prior codes
/// and returns the fresh set, shown EXACTLY ONCE.
pub async fn recovery_regenerate(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
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
    match generate_and_store_recovery_codes(&state, &account).await {
        Ok(codes) => json_response(
            StatusCode::OK,
            json!({
                "regenerated": true,
                "recovery_codes": codes,
                "recovery_codes_remaining": codes.len(),
                "step_up": json!({ "max_age_secs": STEP_UP_MAX_AGE_SECS, "enforced": false }),
            }),
        ),
        Err(response) => response,
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
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let code = generate_recovery_code(state);
        // Hash the normalized (hyphen-free) code so redemption can normalize too.
        let normalized = code.replace('-', "");
        match state.hash_password(&account.scope, &normalized).await {
            Ok(hash) => hashes.push(hash),
            Err(HashRejection::Unavailable) => return Err(server_error()),
            Err(rejection) => return Err(rejection.to_response()),
        }
        plaintext.push(code);
    }
    let actor = interaction::user_actor(&account.subject);
    let stored = state
        .store()
        .scoped(account.scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .recovery_codes()
        .replace_all(state.env(), &account.subject, &hashes)
        .await;
    match stored {
        Ok(_) => Ok(plaintext),
        Err(_) => Err(server_error()),
    }
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
