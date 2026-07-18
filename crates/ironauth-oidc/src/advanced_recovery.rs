// SPDX-License-Identifier: MIT OR Apache-2.0

//! Advanced recovery modes (issue #82, PR 3, EXPLORATORY): the three recovery methods that
//! plug into the issue #81 recovery flow's method seam.
//!
//! The account-recovery subsystem (issue #81) is a first-class state machine with a DELAY
//! window, NOTIFICATION on every channel, and the DOWNGRADE INVARIANT (recovery can never
//! silently remove a factor STRONGER than the one used to recover). This module adds three
//! ways to SATISFY a recovery's method precondition, each of which then completes THROUGH the
//! existing gate, never around it:
//!
//! - Admin-approved: the recovery lands in a control-plane admin queue; an admin approval
//!   satisfies the method (the admin management surface, [`crate`]'s sibling admin crate,
//!   runs the completion after approving).
//! - Trusted-contact: the user's designated contacts confirm out of band with single-use,
//!   case+contact-bound links; the recovery completes once `required_confirmations` DISTINCT
//!   contacts have confirmed.
//! - IDV-gated: a generic external-verification step redirects to a configured provider and
//!   consumes a single-use, case-bound, JOSE-verified signed callback; only a PASS completes.
//!
//! THE COMPLETION GATE is [`finalize_recovery`]: it checks the mode's `method_satisfied`
//! precondition AND then calls [`ironauth_store::ActingRecoveryFlowRepo::complete`], whose
//! `hold_until <= now` guard is the #81 delay. Because `hold_until` is present exactly for a
//! security-reducing recovery, a mode can never complete a downgrade before the notified
//! delay window has elapsed, and the live [`crate::recovery::gate_factor_removal`] invariant
//! still guards any factor removal while the flow is pending. A mode is a strictly ADDITIVE
//! precondition.
//!
//! The whole surface is gated by the `advanced-recovery` experimental feature
//! ([`OidcState::advanced_recovery_enabled`]) plus each mode's config sub-toggle; with the
//! feature off every entry point here is inert (`None`) and every route answers a 404.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ironauth_jose::{
    JwsAlgorithm, VerificationPolicy, VerifiedToken, trusted_keys_from_jwks, verify,
};
use ironauth_store::{
    CorrelationId, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod, Scope, UserId,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::interaction;
use crate::recovery::{self, RecoveryFactor, RecoveryInitiation};
use crate::state::OidcState;
use crate::verification::VerificationPurpose;
use crate::wellknown::{not_found, parse_scope};

/// The CSPRNG secret length (256 bits) of a confirmation / IDV-state token.
const TOKEN_BYTES: usize = 32;
/// The default lifetime of a trusted-contact confirmation link, in microseconds (24 hours).
const CONFIRMATION_TTL_MICROS: i64 = 24 * 60 * 60 * 1_000_000;
/// A cap on the IDV callback body size, before any JOSE work.
const MAX_CALLBACK_BYTES: usize = 16 * 1024;

/// Mint a high-entropy URL-safe token and its SHA-256 digest (issue #82, PR 3): only the
/// digest is stored, so a database dump reveals no usable confirmation / state secret.
fn mint_token(state: &OidcState) -> (String, Vec<u8>) {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0_u8; TOKEN_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let digest = Sha256::digest(token.as_bytes()).to_vec();
    (token, digest)
}

/// The SHA-256 digest of a presented token.
fn token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// The outcome of initiating a trusted-contact recovery (issue #82, PR 3): the new flow id
/// and one single-use confirmation token per designated contact (the real M11 transport
/// embeds each in the delivered confirmation link; they are surfaced here for the delivery
/// owner and the tests).
#[derive(Debug)]
pub struct TrustedContactInitiation {
    /// The new recovery flow's `rcv_` id.
    pub flow_id: RecoveryFlowId,
    /// One single-use confirmation token per designated contact.
    pub tokens: Vec<String>,
}

/// The outcome of initiating an IDV-gated recovery (issue #82, PR 3): the new flow id, the
/// absolute provider redirect URL carrying the case binding, and the case-binding values a
/// (fixture) provider echoes into its signed callback.
#[derive(Debug)]
pub struct IdvInitiation {
    /// The new recovery flow's `rcv_` id.
    pub flow_id: RecoveryFlowId,
    /// The absolute provider redirect URL the user is sent to.
    pub redirect_url: String,
    /// The single-use redirect state the provider must echo (its digest is the flow-bound
    /// key).
    pub state: String,
    /// The case nonce the provider's callback must carry (the case binding).
    pub callback_nonce: String,
}

/// INITIATE an admin-approved recovery (issue #82, PR 3): create the recovery flow with
/// `method=admin_approved` and open a pending admin-approval queue row. Returns the flow id,
/// or [`None`] when the mode is inert (the feature is off or the sub-toggle is disabled) or
/// the initiation was suppressed (anti-enumeration / cooldown / risk block).
pub async fn initiate_admin_approved(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    entry_point: RecoveryEntryPoint,
    recover_factor: RecoveryFactor,
    recipient: &str,
    client_ip: Option<&str>,
) -> Option<RecoveryFlowId> {
    if !state.advanced_recovery_enabled()
        || !state.advanced_recovery_config().admin_approved_enabled
    {
        return None;
    }
    let RecoveryInitiation::Created { flow_id, .. } = recovery::initiate_recovery(
        state,
        scope,
        subject,
        entry_point,
        recover_factor,
        recipient,
        client_ip,
        RecoveryMethod::AdminApproved,
    )
    .await
    else {
        return None;
    };
    // Land the case in the admin queue. On a store fault the flow still exists (held); the
    // admin queue simply has no row, so the recovery cannot be approved (fail closed).
    state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_approvals()
        .open(state.env(), &flow_id, subject)
        .await
        .ok()?;
    Some(flow_id)
}

/// INITIATE a trusted-contact recovery (issue #82, PR 3): create the recovery flow with
/// `method=trusted_contact`, mint one single-use confirmation per DESIGNATED contact
/// (storing only the digest), and notify each contact out of band. Returns the flow id and
/// the confirmation tokens, or [`None`] when the mode is inert, the initiation was
/// suppressed, or the subject has designated no contacts (an unreachable recovery).
pub async fn initiate_trusted_contact(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    entry_point: RecoveryEntryPoint,
    recover_factor: RecoveryFactor,
    recipient: &str,
    client_ip: Option<&str>,
) -> Option<TrustedContactInitiation> {
    if !state.advanced_recovery_enabled()
        || !state.advanced_recovery_config().trusted_contact_enabled
    {
        return None;
    }
    // The designated contacts (opened for the out-of-band send). No contacts means the
    // threshold is unreachable, so the mode does not apply.
    let contacts = state
        .store()
        .scoped(scope)
        .recovery_trusted_contacts()
        .list_opened(subject)
        .await
        .ok()?;
    if contacts.is_empty() {
        return None;
    }
    let RecoveryInitiation::Created { flow_id, .. } = recovery::initiate_recovery(
        state,
        scope,
        subject,
        entry_point,
        recover_factor,
        recipient,
        client_ip,
        RecoveryMethod::TrustedContact,
    )
    .await
    else {
        return None;
    };
    let now_micros = crate::util::epoch_micros(state.now());
    let expires_at = now_micros.saturating_add(CONFIRMATION_TTL_MICROS);
    let mut tokens = Vec::with_capacity(contacts.len());
    for contact in &contacts {
        let (token, digest) = mint_token(state);
        // Store only the digest, keyed to (flow, contact): single-use and no-double-count.
        if state
            .store()
            .scoped(scope)
            .acting(
                interaction::user_actor(subject),
                CorrelationId::generate(state.env()),
            )
            .recovery_contact_confirmations()
            .create_pending(state.env(), &flow_id, &contact.id, &digest, expires_at)
            .await
            .is_err()
        {
            continue;
        }
        // Notify the contact out of band (the real transport embeds the confirm link).
        state.dispatch_verification(scope, VerificationPurpose::Recovery, &contact.address, true);
        tokens.push(token);
    }
    // Every designated contact was alerted; the account owner was already notified by the
    // standard initiation fan-out.
    Some(TrustedContactInitiation { flow_id, tokens })
}

/// INITIATE an IDV-gated recovery (issue #82, PR 3): create the recovery flow with
/// `method=idv`, mint a single-use redirect state bound to the flow and a case nonce, create
/// the IDV session, and build the provider redirect URL carrying the case binding. Returns
/// the initiation, or [`None`] when the mode is inert, the provider is unknown/disabled, or
/// the initiation was suppressed.
#[allow(clippy::too_many_arguments)]
pub async fn initiate_idv(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    entry_point: RecoveryEntryPoint,
    recover_factor: RecoveryFactor,
    recipient: &str,
    client_ip: Option<&str>,
    provider_slug: &str,
) -> Option<IdvInitiation> {
    if !state.advanced_recovery_enabled() || !state.advanced_recovery_config().idv_enabled {
        return None;
    }
    let provider = state
        .advanced_recovery_config()
        .idv_provider(provider_slug)?
        .clone();
    let RecoveryInitiation::Created { flow_id, .. } = recovery::initiate_recovery(
        state,
        scope,
        subject,
        entry_point,
        recover_factor,
        recipient,
        client_ip,
        RecoveryMethod::Idv,
    )
    .await
    else {
        return None;
    };
    let (redirect_state, state_digest) = mint_token(state);
    let (callback_nonce, _nonce_digest) = mint_token(state);
    let now_micros = crate::util::epoch_micros(state.now());
    let ttl_micros = i64::try_from(provider.session_ttl_secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    let expires_at = now_micros.saturating_add(ttl_micros);
    state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_idv_sessions()
        .create(
            state.env(),
            &flow_id,
            &provider.slug,
            &state_digest,
            &callback_nonce,
            expires_at,
        )
        .await
        .ok()?;
    let redirect_url = format!(
        "{}{}state={}&flow={}&nonce={}",
        provider.redirect_url,
        if provider.redirect_url.contains('?') {
            "&"
        } else {
            "?"
        },
        crate::util::percent_encode_query(&redirect_state),
        crate::util::percent_encode_query(&flow_id.to_string()),
        crate::util::percent_encode_query(&callback_nonce),
    );
    Some(IdvInitiation {
        flow_id,
        redirect_url,
        state: redirect_state,
        callback_nonce,
    })
}

/// THE COMPLETION GATE (issue #82, PR 3): complete a recovery flow ONLY when its method
/// precondition is satisfied AND the #81 delay/downgrade gate passes. Reads the flow, checks
/// `method_satisfied` for its method, then calls
/// [`ironauth_store::ActingRecoveryFlowRepo::complete`], whose `hold_until <= now` guard
/// enforces the delay (present exactly for a security-reducing recovery). Returns whether the
/// flow was completed. A flow whose method is not yet satisfied, or whose delay window has not
/// elapsed, is NOT completed (the mode can never bypass the delay or the downgrade block).
pub async fn finalize_recovery(state: &OidcState, scope: Scope, flow_id: &RecoveryFlowId) -> bool {
    let Ok(Some(flow)) = state
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(flow_id)
        .await
    else {
        return false;
    };
    if !flow.state.is_pending() {
        return false;
    }
    if !method_satisfied(state, scope, flow_id, flow.method).await {
        return false;
    }
    let Ok(subject) = state.store().scoped(scope).users().parse_id(&flow.subject) else {
        return false;
    };
    // Complete THROUGH the #81 gate: complete() refuses while `hold_until` is in the future,
    // so a security-reducing recovery can never complete before the notified delay elapses.
    state
        .store()
        .scoped(scope)
        .acting(
            interaction::user_actor(&subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_flows()
        .complete(state.env(), flow_id, &flow.recover_acr)
        .await
        .unwrap_or(false)
}

/// Whether a recovery flow's method precondition is satisfied (issue #82, PR 3): an approved
/// admin approval, `required_confirmations` distinct trusted-contact confirmations (capped at
/// the designated-contact count), or a consumed PASS IDV callback. The standard method is
/// never satisfied here (it does not use this gate). A store fault fails CLOSED (not
/// satisfied).
async fn method_satisfied(
    state: &OidcState,
    scope: Scope,
    flow_id: &RecoveryFlowId,
    method: RecoveryMethod,
) -> bool {
    match method {
        RecoveryMethod::Standard => false,
        RecoveryMethod::AdminApproved => state
            .store()
            .scoped(scope)
            .recovery_approvals()
            .is_approved(flow_id)
            .await
            .unwrap_or(false),
        RecoveryMethod::TrustedContact => {
            let confirmations = state.store().scoped(scope).recovery_contact_confirmations();
            let Ok(total) = confirmations.count_total(flow_id).await else {
                return false;
            };
            if total <= 0 {
                return false;
            }
            let Ok(confirmed) = confirmations.count_confirmed(flow_id).await else {
                return false;
            };
            let required = i64::from(state.advanced_recovery_config().required_confirmations);
            // Cap the threshold at the designated-contact count so an over-large requirement
            // never deadlocks the recovery; at least one confirmation is always required.
            let threshold = required.min(total).max(1);
            confirmed >= threshold
        }
        RecoveryMethod::Idv => state
            .store()
            .scoped(scope)
            .recovery_idv_sessions()
            .passed_for_flow(flow_id)
            .await
            .unwrap_or(false),
    }
}

/// The posted trusted-contact confirmation form.
#[derive(serde::Deserialize)]
pub struct ConfirmForm {
    /// The single-use confirmation token from the out-of-band link.
    pub token: Option<String>,
}

/// `POST /t/{tenant}/e/{env}/recover/trusted-contact/confirm`: a designated contact confirms
/// a recovery out of band (issue #82, PR 3). Resolves the single-use token to its
/// (flow, contact), LATCHES the confirmation (single-use, no-double-count), notifies the
/// account owner, and attempts completion THROUGH the #81 gate. Feature-gated: a uniform 404
/// when the surface is off. Always returns the SAME acknowledgment (a valid token confirms, a
/// forged/spent/expired one is a no-op), so the endpoint is no oracle.
pub(crate) async fn trusted_contact_confirm(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    axum::extract::Form(form): axum::extract::Form<ConfirmForm>,
) -> Response {
    if !state.advanced_recovery_enabled()
        || !state.advanced_recovery_config().trusted_contact_enabled
    {
        return not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let token = form.token.as_deref().unwrap_or_default();
    if !token.is_empty() {
        let _ = consume_trusted_contact_confirmation(&state, scope, token).await;
    }
    confirmation_ack()
}

/// Consume a trusted-contact confirmation token (issue #82, PR 3): resolve it to its
/// (flow, contact), latch the single-use confirmation, notify the account owner, and attempt
/// completion THROUGH the #81 gate. Returns whether the recovery COMPLETED as a result.
pub async fn consume_trusted_contact_confirmation(
    state: &OidcState,
    scope: Scope,
    token: &str,
) -> bool {
    let digest = token_digest(token);
    let now_micros = crate::util::epoch_micros(state.now());
    let Ok(Some((flow_id, contact_id))) = state
        .store()
        .scoped(scope)
        .recovery_contact_confirmations()
        .pending_for_digest(&digest, now_micros)
        .await
    else {
        return false;
    };
    // Resolve the flow's owner (its subject) for the audit actor and the owner notification.
    let Ok(Some(flow)) = state
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&flow_id)
        .await
    else {
        return false;
    };
    let latched = state
        .store()
        .scoped(scope)
        .acting(
            interaction::subject_actor(state, scope, &flow.subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_contact_confirmations()
        .confirm(state.env(), &flow_id, &contact_id, &digest)
        .await
        .unwrap_or(false);
    if !latched {
        return false;
    }
    // Every confirmation notifies the account owner (issue #81 notification pillar).
    if let Ok(owner) = state.store().scoped(scope).users().parse_id(&flow.subject) {
        recovery::notify_owner_channels(state, scope, &owner).await;
    }
    finalize_recovery(state, scope, &flow_id).await
}

/// `POST /t/{tenant}/e/{env}/recover/idv/callback`: consume a provider's signed IDV callback
/// (issue #82, PR 3). The body is the compact JWS the provider returns. Verifies the
/// signature against the provider's REGISTERED key through the hardened JOSE core, binds the
/// callback to its recovery case (the flow-bound single-use state nonce and the case nonce),
/// consumes it single-use, records the verdict, and completes the recovery THROUGH the #81
/// gate ONLY on a PASS. Feature-gated: a uniform 404 when off; every rejection is a uniform
/// 400 (no oracle).
#[allow(clippy::too_many_lines)]
pub(crate) async fn idv_callback(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: String,
) -> Response {
    if !state.advanced_recovery_enabled() || !state.advanced_recovery_config().idv_enabled {
        return not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    if body.len() > MAX_CALLBACK_BYTES {
        return callback_rejected();
    }
    let token = body.trim();
    if token.is_empty() {
        return callback_rejected();
    }
    // Select the candidate provider by the callback's (unverified) `iss`; verify() below
    // re-enforces expected_iss == provider.iss exactly, so a lying iss only selects a provider
    // whose registered key cannot verify the forged signature.
    let Some(iss) = unverified_iss(token) else {
        return callback_rejected();
    };
    let Some(provider) = state
        .advanced_recovery_config()
        .idv_providers
        .iter()
        .find(|provider| provider.enabled && provider.iss == iss)
        .cloned()
    else {
        return callback_rejected();
    };
    // Build the per-provider verification policy from the REGISTERED public key(s) and the
    // provider's algorithm allowlist; the expected audience is THIS env's issuer.
    let keys = trusted_keys_from_jwks(provider.jwks.as_bytes());
    let algorithms: Vec<JwsAlgorithm> = provider
        .algorithms
        .iter()
        .filter_map(|name| JwsAlgorithm::from_jose_name(name))
        .collect();
    if keys.is_empty() || algorithms.is_empty() {
        return callback_rejected();
    }
    let audience = state.issuer_for(&scope);
    let Ok(policy) = VerificationPolicy::new(algorithms, keys, provider.iss.clone(), audience)
    else {
        return callback_rejected();
    };
    // THE ONE signature verification: allowlist-driven algorithm, key only from the registered
    // set, alg=none/HMAC inexpressible, iss/aud/exp/nbf/iat enforced. An unsigned, wrong-key,
    // wrong-algorithm, expired, or wrong-audience callback is a uniform rejection here.
    let Ok(verified) = verify(token, &policy, state.env().clock()) else {
        return callback_rejected();
    };
    let Some(claims) = parse_callback_claims(&verified) else {
        return callback_rejected();
    };
    let Ok(flow_id) = RecoveryFlowId::parse_in_scope(&claims.flow, &scope) else {
        return callback_rejected();
    };
    // Bind the callback to its recovery case: the flow-bound single-use state nonce selects the
    // session (a state minted for another flow selects nothing), and the case nonce must match.
    let state_digest = token_digest(&claims.state);
    let Ok(Some(session)) = state
        .store()
        .scoped(scope)
        .recovery_idv_sessions()
        .by_flow_state(&flow_id, &state_digest)
        .await
    else {
        return callback_rejected();
    };
    if session.consumed || session.callback_nonce != claims.nonce {
        return callback_rejected();
    }
    let verdict = if claims.result == "pass" {
        "pass"
    } else {
        "fail"
    };
    // The audit actor is the recovery flow's owner (subject), resolved with a fallback.
    let actor_subject = state
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&flow_id)
        .await
        .ok()
        .flatten()
        .map_or_else(|| flow_id.to_string(), |flow| flow.subject);
    // Consume single-use (the consumed_at latch): a replayed callback latches nothing.
    let latched = state
        .store()
        .scoped(scope)
        .acting(
            interaction::subject_actor(&state, scope, &actor_subject),
            CorrelationId::generate(state.env()),
        )
        .recovery_idv_sessions()
        .consume(
            state.env(),
            &flow_id,
            &state_digest,
            &provider.slug,
            verdict,
        )
        .await
        .unwrap_or(false);
    if !latched {
        return callback_rejected();
    }
    // Only a PASS satisfies the method; then completion runs THROUGH the #81 delay gate.
    if verdict == "pass" {
        let _completed = finalize_recovery(&state, scope, &flow_id).await;
    }
    callback_accepted()
}

/// The verified IDV callback claims (issue #82, PR 3). Every field is read only AFTER the
/// signature verified.
struct CallbackClaims {
    flow: String,
    state: String,
    nonce: String,
    result: String,
}

/// Parse and validate the IDV callback's case-binding and result claims from a verified JWS
/// (issue #82, PR 3). Returns [`None`] when a required claim is absent or empty.
fn parse_callback_claims(verified: &VerifiedToken) -> Option<CallbackClaims> {
    let claims = verified.claims();
    let field = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    Some(CallbackClaims {
        flow: field("flow")?,
        state: field("state")?,
        nonce: field("nonce")?,
        result: field("result")?,
    })
}

/// Extract the `iss` from a compact JWS payload WITHOUT verifying it (issue #82, PR 3), to
/// SELECT the candidate provider whose registered key the signature is then verified against.
/// Reads NO trust: [`verify`] re-enforces `expected_iss == provider.iss`.
fn unverified_iss(token: &str) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    const MAX_HINT_PAYLOAD_B64: usize = 8 * 1024;
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    if payload_b64.is_empty() || payload_b64.len() > MAX_HINT_PAYLOAD_B64 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    match value.get("iss") {
        Some(Value::String(iss)) => Some(iss.clone()),
        _ => None,
    }
}

/// The uniform trusted-contact confirmation acknowledgment: the SAME body whether the token
/// confirmed a recovery or was a no-op.
fn confirmation_ack() -> Response {
    crate::pages::secure_html(
        StatusCode::OK,
        crate::pages::notice_page(
            "Thank you",
            "If this confirmation link was valid, we have recorded your confirmation and \
             alerted the account owner.",
        ),
    )
}

/// The uniform IDV callback rejection: a plain 400 disclosing nothing about which check
/// failed (an unknown provider, a bad signature, a wrong algorithm, a replay, a cross-case
/// nonce, or a fail result all look identical), so the endpoint is no oracle.
fn callback_rejected() -> Response {
    (StatusCode::BAD_REQUEST, "idv callback rejected\n").into_response()
}

/// The IDV callback success response: the callback was verified and consumed (a PASS may have
/// completed the recovery, a FAIL was recorded). `202 Accepted` with an empty body.
fn callback_accepted() -> Response {
    StatusCode::ACCEPTED.into_response()
}
