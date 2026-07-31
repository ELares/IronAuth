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
//! - **No silent downgrade, on ANY purpose (issue #267).** A verify may not mint a
//!   PRIMARY login session for an account already protected by a stronger factor (a
//!   passkey, an active TOTP, or unconsumed recovery codes) unless the scope explicitly
//!   opted in through `email_factor_config.allow_factor_downgrade`. Only `login`,
//!   `recovery`, and self-service `register` are session-establishing, and each passes
//!   through [`crate::factor_downgrade::blocked`]; `mfa` and `verify_address` are
//!   possession PROOFS that never set the session cookie.
//!
//!   Both halves shipped for SMS in issue #70 and were MISSING here until issue #267:
//!   every purpose fell through to `establish_and_respond`, so an actor who controlled a
//!   mailbox minted a primary session over a passkey, and an `mfa` code alone signed the
//!   presenter in. The gate now lives in [`crate::factor_downgrade`], shared with SMS,
//!   so the two cannot diverge again.
//!
//!   The refusal is uniform in STATUS and BODY with a wrong code, and also in the
//!   statements it runs: [`verify_email_code`] DECIDES the gate on the resolved subject
//!   before the presented code is judged and APPLIES it after the single-use consume, so
//!   a correct-but-refused guess does not cost more than a wrong one. See that function
//!   for the measurement that motivated the ordering.

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
use crate::factor_downgrade;
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
    /// The proof-of-work challenge id the client solved (issue #80), when a challenge is
    /// required on the OTP-send surface.
    pub pow_challenge_id: Option<String>,
    /// The proof-of-work nonce (base64url no-pad) the client found (issue #80).
    pub pow_nonce: Option<String>,
    /// The request context the challenge was issued for (issue #80), echoed back.
    pub pow_context: Option<String>,
    /// An external adapter (Turnstile/reCAPTCHA) response token (issue #80).
    pub pow_token: Option<String>,
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
// The linear send flow (enable/quota gate, PoW gate, throttle, existence-independent
// resolve, issue-or-suppress) reads best as one function; splitting it would scatter the
// anti-enumeration invariant, so the length lint is allowed here (issues #64, #80).
#[allow(clippy::too_many_lines)]
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

    // Proof-of-work gate (issue #80), conditioned on the #79 risk level. Runs BEFORE the
    // recipient lookup and is existence-INDEPENDENT (it keys on the challenge and the IP,
    // never on whether the identifier resolves), so it introduces no enumeration oracle.
    // The built-in PoW is fully server-side (ZERO third-party calls).
    let peer_ip = crate::abuse::resolved_client_ip(&headers);
    if crate::pow_gate::challenge_required(&state, peer_ip.as_deref(), false) {
        let solution = crate::pow_gate::PresentedSolution {
            challenge_id: body.pow_challenge_id.as_deref(),
            nonce: body.pow_nonce.as_deref(),
            context: body.pow_context.as_deref().unwrap_or_default(),
            token: body.pow_token.as_deref(),
            remote_ip: peer_ip.as_deref(),
        };
        if !crate::pow_gate::verify_solution(
            &state,
            scope,
            crate::pow_gate::ENDPOINT_OTP_SEND,
            &solution,
        )
        .await
        {
            return bad_request("challenge required");
        }
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

    // Issue (or anti-enumeration-suppress) the code through the shared core, then the uniform
    // acknowledgment. The core is the ONE place the issue/suppress sequence lives, so the
    // headless recovery flow (issue #84) reuses it rather than re-deriving the send.
    issue_email_code(&state, scope, purpose, identifier).await;
    ack()
}

/// Issue and deliver (or anti-enumeration-SUPPRESS) an email-OTP code for `identifier` on
/// `purpose` (issue #68 core, extracted for issue #84 reuse). A known recipient gets a fresh
/// single-active code delivered; an unknown recipient burns the SAME single Argon2 spend
/// (`verify_absent`, so the response time cannot distinguish a real from an unknown recipient)
/// and the send is suppressed. Side-effect only; the caller owns the throttle and the uniform
/// acknowledgment, so the send stays anti-enumeration-uniform on every surface that drives it.
pub(crate) async fn issue_email_code(
    state: &OidcState,
    scope: ironauth_store::Scope,
    purpose: EmailFactorPurpose,
    identifier: &str,
) {
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
        let code = generate_numeric_code(state, digits);
        let code_hash = match state.hash_password(&scope, &code).await {
            Ok(hash) => hash,
            // A pool rejection means no code was stored: for anti-enumeration this stays the
            // SAME uniform (no delivery) outcome a suppressed send produces, never a
            // distinguishable difference.
            Err(_rejection) => return,
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
            // A failed issue means no code was stored: for anti-enumeration this is the SAME
            // uniform (no delivery) outcome a suppressed send returns, never a status
            // difference that would distinguish a present from an absent recipient. Recorded
            // on the observability plane only.
            tracing::error!(target: "ironauth.verification", "email OTP issue failed");
            return;
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

    // The resolve / gate-decision / constant-time-compare / attempt-count / consume sequence
    // runs through the shared core, then the session mint. The core is the ONE place the
    // email-factor verify security lives, so the headless recovery flow (issue #84) reuses it
    // identically; only the mint differs (this handler responds directly, the flow trips its
    // completion latch). The no-silent-downgrade gate (issue #267) is DECIDED and APPLIED
    // inside the core, so this handler only renders what the core decided.
    match verify_email_code(
        &state,
        scope,
        purpose,
        identifier,
        code,
        &headers,
        factor_downgrade::GatedSessionPath::EmailOtpVerify,
    )
    .await
    {
        EmailCodeOutcome::Verified { subject, ctx } => {
            // The purpose split (issue #267, mirroring issue #70). Before this, EVERY
            // purpose fell through to a full primary session: an `mfa` code alone signed
            // the presenter in (claiming a first factor that was never proven) and a
            // `verify_address` code did the same. Only the purposes for which the code IS
            // the primary authenticator may mint; the core has already cleared those
            // through the no-silent-downgrade gate.
            if !purpose.establishes_session() {
                // A possession proof: no cookie, no `authenticated`, no `amr`. The abuse
                // throttle relaxes on a proven possession just as a sign-in does.
                state.reset_after_success(&ctx).await;
                return proof_response(purpose);
            }
            establish_and_respond(&state, scope, &subject, &ctx, &headers).await
        }
        // A refused downgrade renders the SAME uniform invalid-code result a wrong code
        // does, so the refusal is never a factor-possession oracle.
        EmailCodeOutcome::Invalid | EmailCodeOutcome::Blocked => invalid_code(),
        EmailCodeOutcome::Throttled(snapshot) => {
            let mut response = json_response(
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "too_many_requests" }),
            );
            crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
            response
        }
        EmailCodeOutcome::Rejected(rejection) => rejection.to_response(),
        EmailCodeOutcome::ServerError => server_error(),
    }
}

/// The typed outcome of verifying an email-OTP code WITHOUT establishing a session (issue
/// #84): the shared core the HTTP `verify` handler and the headless recovery flow both drive,
/// so the two can never diverge. The caller owns the session mint (`establish_and_respond` for
/// the handler; the flow engine's single-use completion latch plus `establish_session` for the
/// flow), so a correct code is a genuine completing outcome exactly once.
pub(crate) enum EmailCodeOutcome {
    /// The code matched and was consumed single-use. `subject` is the verified account and
    /// `ctx` the abuse context to relax on the successful mint.
    Verified {
        /// The verified account.
        subject: UserId,
        /// The abuse attempt context to relax after a successful mint.
        ctx: crate::abuse::AttemptContext,
    },
    /// A wrong, expired, absent, or already-consumed code: the UNIFORM invalid result, never
    /// an existence or state oracle.
    Invalid,
    /// The code was CORRECT and was consumed single-use, but the no-silent-downgrade gate
    /// refused the session mint (issue #267): the account holds a stronger factor and this
    /// scope has no downgrade opt-in.
    ///
    /// A separate variant from [`Self::Invalid`] so the caller cannot accidentally treat a
    /// refusal as a mint, but every caller renders it IDENTICALLY to [`Self::Invalid`]:
    /// the response must not distinguish a refused downgrade from a wrong guess. The
    /// proven code is already BURNED when this is returned, so it is never replayable.
    Blocked,
    /// The verify path is throttled (the #64 per-recipient / per-IP brute-force bound).
    Throttled(ironauth_quota::RateLimitSnapshot),
    /// The admission-controlled hashing pool refused the verify (saturated or disabled).
    Rejected(crate::hashing_pool::HashRejection),
    /// A genuine store fault.
    ServerError,
}

/// Verify an email-OTP `code` for `identifier` on `purpose` against the single active code,
/// consuming it single-use on a match (issue #68 core, extracted for issue #84 reuse). This is
/// the ONE place the throttle / resolve / constant-time-compare / attempt-count / consume
/// sequence lives; both the HTTP `verify` handler and the headless recovery flow call it, so
/// neither re-derives the email-factor security. It performs the SAME anti-timing dummy spend
/// on an absent recipient or an absent code, and does NOT establish a session (the caller owns
/// the mint).
///
/// # The no-silent-downgrade gate lives here, and WHERE in here matters
///
/// `gate` names the caller's [`GatedSessionPath`](crate::factor_downgrade::GatedSessionPath).
/// It is REQUIRED, not optional: there is no value a caller can pass to opt out, so a new
/// surface that drives this core is gated by construction and the only decision left to it
/// is which surface to attribute a refusal to. On a session-establishing purpose the gate
/// is DECIDED on the resolved subject BEFORE the presented code is judged, and APPLIED
/// only after the single-use consume, exactly as `sms_otp::verify` has done since issue
/// #70.
///
/// That ordering is the whole point, and the issue #267 review measured what the other one
/// costs. When the gate ran only on a code that had already verified, a WRONG code spent 125
/// transactions and a CORRECT-but-refused code spent 129 on the same passkey-protected
/// account: one gate configuration read and one passkey probe that a wrong guess did not
/// perform. Both answered a byte-identical 401, so the body was uniform, but the latency was
/// not, and a code-guessing attacker who does NOT control the mailbox could in principle read
/// a correct guess off it. Deciding first and applying last removes the difference: the same
/// statements run whatever the code turns out to be.
///
/// Applying LAST is equally load-bearing in the other direction. The gate must not short
/// circuit past the resolve, the Argon2 compare, and the durable write a wrong guess performs,
/// and the proven-but-refused code must be BURNED rather than left replayable.
pub(crate) async fn verify_email_code(
    state: &OidcState,
    scope: ironauth_store::Scope,
    purpose: EmailFactorPurpose,
    identifier: &str,
    code: &str,
    headers: &HeaderMap,
    gate: crate::factor_downgrade::GatedSessionPath,
) -> EmailCodeOutcome {
    // Throttle the VERIFY on the flow's path, keyed on the recipient and the peer IP, so a
    // brute force escalates to a uniform failure (issue #64).
    let ctx = attempt_context(scope, purpose, identifier, headers);
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        return EmailCodeOutcome::Throttled(snapshot);
    }

    // Resolve the recipient. A missing account or missing active code both spend a full
    // dummy verify (so the timing is uniform) and return the SAME invalid result.
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
        return EmailCodeOutcome::Invalid;
    };

    // DECIDE the no-silent-downgrade gate here (issue #267), before the presented code is
    // judged, so the gate's reads are spent on a wrong guess exactly as they are on a
    // correct one. The decision is APPLIED after the consume below. Carrying the path
    // rather than a bare bool means the refusal can be attributed to the surface that
    // refused without a second lookup, and makes it impossible to record a refusal for a
    // path that was never gated.
    let refused = if purpose.establishes_session() {
        match gate_blocks(state, scope, &user.id, gate).await {
            Ok(true) => Some(gate),
            Ok(false) => None,
            // A store fault reading the opt-in or probing the account's factors. Fails
            // CLOSED: no mint. This returns before the compare, which is the same shape
            // `sms_otp::verify` has: a store fault is not attacker-selectable per
            // request, so it is not a code-correctness oracle.
            Err(crate::factor_downgrade::FactorProbeError) => {
                return EmailCodeOutcome::ServerError;
            }
        }
    } else {
        // A possession PROOF (`mfa` / `verify_address`) mints no primary session, so there
        // is nothing to downgrade and no probe to spend.
        None
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
            return EmailCodeOutcome::Invalid;
        }
        Err(_) => return EmailCodeOutcome::ServerError,
    };

    let matched = match state.verify_password(&scope, code, &active.code_hash).await {
        Ok(matched) => matched,
        Err(rejection) => return EmailCodeOutcome::Rejected(rejection),
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
        return EmailCodeOutcome::Invalid;
    }

    // Correct code: consume it single-use. The caller mints the session. A refused
    // downgrade consumes it too, so the refusal spends the SAME durable write a wrong
    // guess does and the proven-but-refused code is burned rather than left replayable.
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
        // APPLY the gate decision taken before the compare. The refusal is recorded on the
        // observability plane HERE rather than at the decision, so a wrong guess on a
        // protected account never logs a refusal it did not earn.
        Ok(true) => match refused {
            Some(path) => {
                crate::factor_downgrade::record_refusal(scope, path, purpose.as_str());
                EmailCodeOutcome::Blocked
            }
            None => EmailCodeOutcome::Verified {
                subject: user.id,
                ctx,
            },
        },
        // A race already consumed it: the uniform invalid result.
        Ok(false) => EmailCodeOutcome::Invalid,
        Err(_) => EmailCodeOutcome::ServerError,
    }
}

/// THE email-family no-silent-downgrade DECISION (issue #267): whether this scope refuses
/// `path`'s weak possession factor a primary session for `subject`.
///
/// This is the ONE place the email OTP, the magic link, and the headless recovery journey
/// funnel through, so none of the three can be gated while another is not. It only
/// DECIDES; recording the refusal and rendering it belong to the caller, at the point the
/// refusal is actually applied, so a decision taken speculatively (before the presented
/// proof has been judged) never emits a refusal the presenter did not earn.
///
/// The scope's opt-in is read here rather than passed in. A scope with no row, and a scope
/// whose read FAILS, both resolve to "not opted in": the permissive value is only ever
/// returned by a row that exists and says so, so neither a store fault nor the day-one
/// state of an existing tenant (issue #267's migration back-fills nothing) can open the
/// downgrade path.
///
/// # Errors
///
/// [`FactorProbeError`](crate::factor_downgrade::FactorProbeError) on a store fault
/// reading the opt-in or probing the account's factors. Every caller fails CLOSED on it:
/// no session is minted.
pub(crate) async fn gate_blocks(
    state: &OidcState,
    scope: ironauth_store::Scope,
    subject: &UserId,
    path: crate::factor_downgrade::GatedSessionPath,
) -> Result<bool, crate::factor_downgrade::FactorProbeError> {
    let allow_downgrade = state
        .store()
        .scoped(scope)
        .email_factor_config()
        .config()
        .await
        .map(|config| config.allow_factor_downgrade)
        .map_err(|_| crate::factor_downgrade::FactorProbeError)?;
    crate::factor_downgrade::blocked(state, scope, subject, path.factor(), allow_downgrade).await
}

/// The NON-session-establishing success result for an `mfa` or `verify_address` verify
/// (issue #267, mirroring the issue #70 SMS shape): a possession proof that the
/// presenter controls the address, with NO session cookie and NO authenticated-login
/// claim. It never carries `authenticated: true` or an `amr`, so it cannot be mistaken
/// for (or promoted into) a primary session.
fn proof_response(purpose: EmailFactorPurpose) -> Response {
    json_response(
        StatusCode::OK,
        json!({ "verified": true, "purpose": purpose.as_str() }),
    )
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
        // The central lifecycle fence refused (issue #80 / #52): a waitlisted, blocked,
        // disabled, or pending-verification account. Render the SAME uniform invalid-code
        // result a wrong/expired code returns, so a fenced-but-correct code is not an
        // account-state oracle.
        Err(interaction::EstablishSessionError::NotAuthenticatable) => invalid_code(),
        Err(interaction::EstablishSessionError::Store) => server_error(),
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
