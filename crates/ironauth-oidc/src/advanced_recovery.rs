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
//!
//! # The HOSTED flow (issue #295)
//!
//! PR 3 shipped the completion machinery and left the user-facing INITIATION library-only.
//! It is now mounted, as three public endpoints:
//!
//! - `POST .../recover/admin-approved/initiate` and `.../recover/idv/initiate` open a case in
//!   the corresponding mode;
//! - `POST .../recover/finalize` establishes the recovered subject's session, the other half
//!   of PR 3's deferred session mint.
//!
//! ## Why the TRUSTED-CONTACT mode has no hosted entry point
//!
//! Two of the three modes are mounted; the trusted-contact one is not, and neither is a
//! self-service contact-enrollment surface. The reason is a delivery seam this repository
//! does not have yet. [`crate::recovery::notify_owner_channels`] sends a COARSE per-channel
//! alert and takes no URL, and the standard initiation's own cancellation link binds into a
//! discarded local for the same reason. A trusted-contact recovery completes only when
//! `required_confirmations` DISTINCT contacts each present the single-use token minted by
//! [`initiate_trusted_contact`], and there is no transport that can put that token in front
//! of a contact. A mounted initiation would therefore open cases that can never reach
//! [`trusted_contact_confirm`], and an enrollment surface would let a user designate contacts
//! for a mode that cannot run while creating a durable new path to their account.
//!
//! The library seams stay: [`initiate_trusted_contact`], [`consume_trusted_contact_confirmation`],
//! the `/recover/trusted-contact/confirm` route PR 3 mounted, and the whole distinct-contact
//! threshold are unchanged and still covered. Only the self-service ENTRY POINTS are absent,
//! and they arrive with the transport (issue #295 stays open for exactly that half).
//!
//! ## The recover factor is minted, not accepted
//!
//! Each initiation begins by PROVING control of the account's email channel through
//! [`recovery_proof::prove_email_otp`], which drives the ONE email-OTP verify core on the
//! recovery purpose and mints a [`ProvenFactor`] at the `pwd` rung. The subject comes from
//! that proof (resolved by the verify core from the presented identifier, never from a
//! request field), and so does the rung. There is no request field, and no parameter on any
//! of the three initiation functions, that could name a stronger factor: see
//! [`crate::recovery_proof`] for the two compiler errors that enforce it.
//!
//! The hosted surface therefore covers the user who lost their AUTHENTICATION factors and
//! still reads their mail. A user who has also lost the channel is the admin-approved mode's
//! management-plane case, which shipped in PR 3; no self-service endpoint can identify such a
//! user, and inventing one that could would be the hole this module exists to avoid.
//!
//! ## Uniform refusal
//!
//! The statement that holds across the whole module is narrower than "three shapes", and the
//! narrower one is the one worth writing down: EVERY endpoint here answers a refusal with a
//! SINGLE shape that does not vary with the reason, so no endpoint is an oracle. Which shape
//! that is differs by endpoint, because the surfaces have different callers:
//!
//! - the three issue #295 endpoints ([`admin_approved_initiate`], [`idv_initiate`],
//!   [`finalize`]) answer `200` with a JSON body on success and ONE
//!   [`recovery_unavailable`] `401` for every refusal: an unknown identifier, a wrong,
//!   expired, over-attempted or spent code, a throttled verify, a suppressed initiation
//!   (cooldown, risk block), an unknown or disabled IDV provider, no pending flow, an
//!   unsatisfied method, an unelapsed delay window, the account-lifecycle fence, and a store
//!   fault alike;
//! - [`idv_callback`] (PR 3) answers `202` on a consumed callback and ONE uniform `400`
//!   ([`callback_rejected`]) for every rejection, because its caller is a provider rather
//!   than a browser and it establishes nothing;
//! - [`trusted_contact_confirm`] (PR 3) answers the SAME `200` acknowledgment page whether
//!   the token confirmed anything or was a no-op, which is the same property expressed as a
//!   single SUCCESS shape rather than a single refusal one.
//!
//! Across all five, a `404` when the feature or the mode sub-toggle is off, or the scope path
//! does not parse: a deployment-wide constant, identical for every tenant and every subject.
//!
//! ## The session mint is downstream of the gate, never beside it
//!
//! [`finalize_recovery`] is the ONLY thing that can turn a pending case into a completed one,
//! and it refuses unless the method precondition holds AND
//! [`ironauth_store::ActingRecoveryFlowRepo::complete`]'s `hold_until <= now` guard passes.
//! The hosted finalize endpoint mints a session ONLY on its `true`, so a session cannot exist
//! for a case whose delay window has not elapsed or whose mode is unsatisfied.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, VerificationPolicy, VerifiedToken, trusted_keys_from_jwks, verify,
};
use ironauth_store::{CorrelationId, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod, Scope};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::interaction;
use crate::recovery::{self, RecoveryInitiation};
use crate::recovery_proof::{self, ProvenFactor, RecoveryProofSurface};
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
///
/// SECURITY (issue #295): the recovery's factor, scope, and subject all come from `proven`,
/// a [`ProvenFactor`] the caller cannot fabricate (private fields, module-private mint, no
/// production constructor that takes a rung). The `hold_until` delay is gated on that rung,
/// so this entry point no longer HAS an argument position an inflated factor could occupy.
pub async fn initiate_admin_approved(
    state: &OidcState,
    proven: &ProvenFactor,
    entry_point: RecoveryEntryPoint,
    recipient: &str,
    client_ip: Option<&str>,
) -> Option<RecoveryFlowId> {
    if !state.advanced_recovery_enabled()
        || !state.advanced_recovery_config().admin_approved_enabled
    {
        return None;
    }
    let scope = proven.scope();
    let subject = proven.subject();
    let RecoveryInitiation::Created { flow_id, .. } = recovery::initiate_recovery(
        state,
        proven,
        entry_point,
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
///
/// SECURITY (issue #295): the recovery's factor, scope, and subject all come from `proven`,
/// a [`ProvenFactor`] the caller cannot fabricate. See [`initiate_admin_approved`].
pub async fn initiate_trusted_contact(
    state: &OidcState,
    proven: &ProvenFactor,
    entry_point: RecoveryEntryPoint,
    recipient: &str,
    client_ip: Option<&str>,
) -> Option<TrustedContactInitiation> {
    if !state.advanced_recovery_enabled()
        || !state.advanced_recovery_config().trusted_contact_enabled
    {
        return None;
    }
    let scope = proven.scope();
    let subject = proven.subject();
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
        proven,
        entry_point,
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
///
/// SECURITY (issue #295): the recovery's factor, scope, and subject all come from `proven`,
/// a [`ProvenFactor`] the caller cannot fabricate. See [`initiate_admin_approved`].
pub async fn initiate_idv(
    state: &OidcState,
    proven: &ProvenFactor,
    entry_point: RecoveryEntryPoint,
    recipient: &str,
    client_ip: Option<&str>,
    provider_slug: &str,
) -> Option<IdvInitiation> {
    if !state.advanced_recovery_enabled() || !state.advanced_recovery_config().idv_enabled {
        return None;
    }
    let scope = proven.scope();
    let subject = proven.subject();
    let provider = state
        .advanced_recovery_config()
        .idv_provider(provider_slug)?
        .clone();
    let RecoveryInitiation::Created { flow_id, .. } = recovery::initiate_recovery(
        state,
        proven,
        entry_point,
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
    // The callback assertion is the registered EXTERNAL provider's, minted under its
    // own keys with no media type IronAuth can dictate, so `typ` is not the separator
    // here (issue #192): the provider's registered JWKS plus its pinned `iss` and this
    // environment's issuer as the `aud` are. As at the other operator-registered sites
    // that is a CONFIGURATION property, not a structural one: a provider registered
    // with this environment's own issuer and JWKS would let IronAuth's tokens reach the
    // signature check with `typ` unread. No default configuration reaches here at all.
    let Ok(policy) = VerificationPolicy::new(
        algorithms,
        keys,
        provider.iss.clone(),
        audience,
        ExpectedTyp::ForeignIssuer,
    ) else {
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

// ---------------------------------------------------------------------------------------
// The HOSTED initiation and finalization surface (issue #295).
// ---------------------------------------------------------------------------------------

/// The posted body of a hosted advanced-recovery INITIATION (issue #295).
///
/// It carries the channel proof and, for the IDV mode, the provider slug. It carries NO
/// subject and NO recovery factor: both are established server side from the proof, which is
/// the entire point of the surface.
#[derive(serde::Deserialize)]
pub struct InitiateBody {
    /// The identifier the recovery is for. Used ONLY to resolve the account inside the
    /// email-OTP verify core; the resolved subject comes back from that core.
    pub identifier: Option<String>,
    /// The email one-time code, issued for the `recovery` purpose, that proves channel
    /// control.
    pub code: Option<String>,
    /// The registered IDV provider slug (the IDV mode only). Ignored by the other two modes.
    pub provider: Option<String>,
}

/// The posted body of a hosted recovery FINALIZATION (issue #295): the same channel proof the
/// initiation took, re-presented with a fresh code (the initiation's was consumed single-use).
#[derive(serde::Deserialize)]
pub struct FinalizeBody {
    /// The identifier the recovery is for.
    pub identifier: Option<String>,
    /// A fresh email one-time code, issued for the `recovery` purpose.
    pub code: Option<String>,
}

/// THE single refusal the three issue #295 endpoints answer with.
///
/// One constant response for an unknown identifier, a wrong / expired / over-attempted /
/// spent code, a throttled or pool-rejected verify, a suppressed initiation (the per-account
/// cooldown or a risk block), an unknown or disabled IDV provider, no pending flow, an
/// unsatisfied method, an unelapsed delay window, the account-lifecycle fence, and a store
/// fault alike. The endpoint is therefore no oracle for account existence, account
/// protection posture, account lifecycle state, recovery-case state, or provider
/// configuration.
///
/// The ONLY other refusal shape on those three is the feature/mode/scope `404`, which is a
/// deployment-wide constant identical for every tenant and every subject.
fn recovery_unavailable() -> Response {
    no_store(
        StatusCode::UNAUTHORIZED,
        json!({ "error": "recovery_unavailable" }),
    )
}

/// A JSON response at `status` with the hardened no-store header, mirroring the email-factor
/// surfaces.
fn no_store(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// Resolve the scope and PROVE the channel for a hosted initiation / finalization (issue
/// #295), or return the uniform refusal.
///
/// `armed` is the mode's own gate, evaluated by the caller. It is taken as a bool rather than
/// probed here so each endpoint states its own sub-toggle at its own call site.
// Eight parameters, one more than the lint allows. Every one of them is a distinct fact the
// endpoint knows and this helper does not: which scope path was routed, whether THIS mode's
// sub-toggle is armed, which surface to attribute the proof to, and the two presented
// credential fields. Bundling them into a struct would move the argument list rather than
// shorten it, and the point of the helper is that no endpoint re-implements the proof.
#[allow(clippy::too_many_arguments)]
async fn proven_or_refused(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    armed: bool,
    surface: RecoveryProofSurface,
    identifier: Option<&str>,
    code: Option<&str>,
    headers: &HeaderMap,
) -> Result<ProvenFactor, Response> {
    if !state.advanced_recovery_enabled() || !armed {
        return Err(not_found());
    }
    let Some(scope) = parse_scope(tenant_id, environment_id) else {
        return Err(not_found());
    };
    let identifier = identifier.map(str::trim).unwrap_or_default();
    let code = code.map(str::trim).unwrap_or_default();
    if identifier.is_empty() || code.is_empty() {
        return Err(recovery_unavailable());
    }
    // THE mint. It resolves the subject and attests the rung; this handler supplies neither.
    recovery_proof::prove_email_otp(state, scope, surface, identifier, code, headers)
        .await
        .ok_or_else(recovery_unavailable)
}

/// `POST /t/{tenant}/e/{env}/recover/admin-approved/initiate`: open an ADMIN-APPROVED recovery
/// case (issue #295). Proves channel control, mints the server-derived `pwd`-rung
/// [`ProvenFactor`], creates the flow (HELD whenever that rung does not reach the account's
/// strongest factor), and lands a pending row in the control-plane approval queue. Uniform
/// refusal on everything else.
pub(crate) async fn admin_approved_initiate(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<InitiateBody>,
) -> Response {
    let armed = state.advanced_recovery_config().admin_approved_enabled;
    let proven = match proven_or_refused(
        &state,
        &tenant_id,
        &environment_id,
        armed,
        RecoveryProofSurface::AdminApprovedInitiate,
        body.identifier.as_deref(),
        body.code.as_deref(),
        &headers,
    )
    .await
    {
        Ok(proven) => proven,
        Err(response) => return response,
    };
    let client_ip = crate::abuse::resolved_client_ip(&headers);
    let recipient = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    match initiate_admin_approved(
        &state,
        &proven,
        RecoveryEntryPoint::LostAllFactors,
        recipient,
        client_ip.as_deref(),
    )
    .await
    {
        Some(_flow_id) => initiated(None),
        None => recovery_unavailable(),
    }
}

/// `POST /t/{tenant}/e/{env}/recover/idv/initiate`: open an IDV-GATED recovery case (issue
/// #295) and return the provider redirect URL carrying the case binding. The redirect URL is
/// returned ONLY on success; every refusal is the uniform shape, so the presence of a URL
/// discloses nothing an actor who did not already prove the channel could read.
pub(crate) async fn idv_initiate(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<InitiateBody>,
) -> Response {
    let armed = state.advanced_recovery_config().idv_enabled;
    let proven = match proven_or_refused(
        &state,
        &tenant_id,
        &environment_id,
        armed,
        RecoveryProofSurface::IdvInitiate,
        body.identifier.as_deref(),
        body.code.as_deref(),
        &headers,
    )
    .await
    {
        Ok(proven) => proven,
        Err(response) => return response,
    };
    let provider = body.provider.as_deref().map(str::trim).unwrap_or_default();
    if provider.is_empty() {
        return recovery_unavailable();
    }
    let client_ip = crate::abuse::resolved_client_ip(&headers);
    let recipient = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    match initiate_idv(
        &state,
        &proven,
        RecoveryEntryPoint::LostAllFactors,
        recipient,
        client_ip.as_deref(),
        provider,
    )
    .await
    {
        Some(initiation) => initiated(Some(&initiation.redirect_url)),
        None => recovery_unavailable(),
    }
}

/// The uniform initiation acknowledgment: the SAME body for all three modes, plus the IDV
/// redirect URL when there is one. It carries NO flow id: the flow id rides the IDV redirect
/// to a third party and appears in the admin queue, so it is not a secret and must never be
/// the thing that authorizes anything.
fn initiated(redirect_url: Option<&str>) -> Response {
    let body = match redirect_url {
        Some(url) => json!({ "status": "initiated", "redirect_url": url }),
        None => json!({ "status": "initiated" }),
    };
    no_store(StatusCode::OK, body)
}

/// `POST /t/{tenant}/e/{env}/recover/finalize`: establish the RECOVERED subject's session
/// (issue #295), the other half of PR 3's deferred session mint.
///
/// # Why a session may exist here, and only here
///
/// The mint is guarded by three things IN ORDER, and every one of them must pass:
///
/// 1. The caller PROVES channel control with a fresh recovery-purpose email one-time code, so
///    the session can only ever go to someone who reads the account's mail. The proof also
///    RESOLVES the subject; the endpoint reads no subject from the request.
/// 2. The proven subject must have a PENDING recovery flow, which
///    [`ironauth_store::RecoveryFlowRepo::pending_for_subject`] looks up under the proof's own
///    scope. A caller cannot name a flow, so a flow id leaked through the IDV redirect or the
///    admin queue authorizes nothing.
/// 3. [`finalize_recovery`] must return `true`. That is the #81 gate: it refuses unless the
///    mode's `method_satisfied` precondition holds AND
///    [`ironauth_store::ActingRecoveryFlowRepo::complete`]'s `hold_until <= now` guard passes.
///    A case whose delay window has not elapsed, whose mode is unsatisfied, or whose method is
///    `Standard` (never satisfiable through this gate) mints nothing.
///
/// # What the recovered session can and cannot then do
///
/// The session is an ORDINARY email-OTP session, `amr = ["otp"]` at the `pwd` rung, exactly
/// what [`crate::recovery::fresh_session_reverify_acr`] already documents recovered access to
/// be. It cannot itself re-verify a stronger factor, so it can never present the fresh
/// equal-or-stronger proof that is [`crate::recovery::FactorChangeDecision::AllowedByReverify`].
///
/// It is worth being exact about what that does and does not buy, because an earlier draft of
/// this comment said the recovered session "can never unblock a downgrade under
/// `gate_factor_removal`", which was true as written and misleading in effect. The recovered
/// session does not need to unblock anything: COMPLETING the case is what ends the pending
/// flow the gate keys on, and the delay the gate exists to impose was already served before
/// `complete` would return `true` at all. So a passkey removal after this endpoint succeeds is
/// PERMITTED, and always was going to be, on the same reasoning that permits it once
/// `hold_until` has elapsed with the flow still pending.
///
/// What must NOT change across the completion is the other arm of that permission: the
/// `recovery.factor_change` audit row and the notification to every channel.
/// [`crate::recovery::gate_factor_removal`] keeps them alive with its post-recovery
/// audit-and-notify window, so a factor removal in the window after a recovery is announced to
/// the owner rather than silent. See that function's doc.
///
/// The issue #267 no-silent-downgrade gate deliberately does NOT decide this mint. Its
/// question is whether a weak factor may SILENTLY take a protected account, and this mint is
/// the opposite of silent: it is the terminus of a notified, delay-held, mode-gated recovery
/// case. (Not a CANCELLABLE one, on this surface: `initiate_recovery` mints a cancellation
/// token, but the notification seam carries a coarse per-channel alert with nowhere to put the
/// link, so the token reaches nobody today. That gap is a delivery one, tracked with the rest
/// of issue #295's transport work, and it is a reason to keep the notification arm above
/// intact rather than to weaken it.) Refusing here would leave a passkey holder who lost their
/// passkey with no recovery at all, which is the case this whole subsystem exists to serve.
pub(crate) async fn finalize(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<FinalizeBody>,
) -> Response {
    // The finalize surface is armed by the FEATURE alone: a case opened while a mode was armed
    // must stay finalizable, and which mode it used is a property of the flow, not the request.
    let proven = match proven_or_refused(
        &state,
        &tenant_id,
        &environment_id,
        true,
        RecoveryProofSurface::Finalize,
        body.identifier.as_deref(),
        body.code.as_deref(),
        &headers,
    )
    .await
    {
        Ok(proven) => proven,
        Err(response) => return response,
    };
    let scope = proven.scope();
    let Ok(Some(flow)) = state
        .store()
        .scoped(scope)
        .recovery_flows()
        .pending_for_subject(proven.subject())
        .await
    else {
        return recovery_unavailable();
    };
    // THE gate. Nothing below runs unless the method precondition AND the delay window both
    // passed inside `complete`.
    if !finalize_recovery(&state, scope, &flow.id).await {
        return recovery_unavailable();
    }
    let event =
        crate::authn::AuthenticationEvent::email_otp(crate::util::epoch_micros(state.now()));
    let subject = proven.subject().to_string();
    match interaction::establish_session(
        &state,
        scope,
        &subject,
        &event,
        interaction::user_actor(proven.subject()),
        &headers,
    )
    .await
    {
        Ok(cookies) => {
            // Completion notifies every channel again, so the owner sees the case closed and
            // the recovered access announced (the #81 notification pillar).
            recovery::notify_owner_channels(&state, scope, proven.subject()).await;
            let body = no_store(
                StatusCode::OK,
                json!({ "recovered": true, "authenticated": true, "amr": ["otp"] }),
            );
            interaction::attach_session_cookies(body, &cookies)
        }
        // Both refusals are named rather than collapsed into `Err(_)`, because
        // `every_session_mint_tells_the_lifecycle_fence_apart_from_a_store_fault` requires every
        // mint to have CONSIDERED them separately: a fence is a deliberate administrative state
        // and must never be reported as a server fault. This surface then deliberately renders
        // the SAME uniform refusal for each, which is a stronger answer than that sweep asks for.
        //
        // `NotAuthenticatable` is the fence: a blocked, disabled, or absent account. Rendering
        // the uniform refusal keeps it from being an account-state oracle, exactly as
        // `email_otp`'s `invalid_code()` does for the same fence.
        //
        // `Store` is a fault, and unlike `email_otp` this surface deliberately does NOT render a
        // 500 for it: the recovered subject was resolved from PROVEN evidence and the flow is
        // already completed, so a distinguishable fault here would tell an attacker their
        // evidence was accepted. The fault is not swallowed; the store layer logs it.
        //
        // They share one arm because they share one answer. An or-pattern rather than `Err(_)`
        // is what makes that a decision a reader can see, and it is why clippy's
        // `match_same_arms` is satisfied without the two collapsing back into a wildcard.
        Err(
            interaction::EstablishSessionError::NotAuthenticatable
            | interaction::EstablishSessionError::Store,
        ) => recovery_unavailable(),
    }
}
