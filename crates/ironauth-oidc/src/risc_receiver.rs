// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Google Cross-Account Protection receiver (issue #144, criteria 4 and 5).
//!
//! Google Cross-Account Protection is a RISC transmitter. When a Google account is believed
//! compromised, disabled or purged, Google pushes a signed Security Event Token to the
//! receivers registered for it. For a deployment whose users sign in WITH Google, consuming
//! that stream closes a real account-takeover path: the attacker holds the upstream account,
//! and without this the local sessions minted from it keep working until they expire.
//!
//! # This is the Google consumer, not a general-purpose receiver
//!
//! Issue #144 puts the general case out of scope in as many words: "only the Google
//! Cross-Account Protection consumer ships here", and this receiver "deliberately applies
//! its own fixed, per-environment configured action set so the Google consumer never depends
//! on an experimental feature". So it has its own configuration, its own replay table and its
//! own action set, and it deliberately does NOT route through the experimental third-party
//! risk-signal seam. A protection that ends sessions must not be reachable only when an
//! experiment happens to be switched on.
//!
//! # What makes a token acceptable
//!
//! Five things, and criterion 5 names the first four:
//!
//! - the `iss` is the CONFIGURED transmitter. It is never read off the token to select a
//!   key, because a value read off an unverified token choosing the key that checks it is
//!   not a check;
//! - the `aud` is this environment's issuer, so a token minted for a different deployment is
//!   refused here;
//! - the signature verifies against the transmitter's REGISTERED public keys, under an
//!   algorithm from the configured allowlist;
//! - the `iat` is within the configured window;
//! - and the `jti` has not been seen before.
//!
//! Every refusal is the same `400` with no detail. A receiver that said WHICH check failed
//! would tell an attacker whether they had guessed a real subject, a real connector, or a
//! live `jti`.
//!
//! # Why the replay check is durable and the issuance check is not the same thing
//!
//! `max_issuance_age_secs` bounds how old a token may be. It is not an expiry on the SET:
//! this codebase holds that SETs must not expire (SSF 1.0 section 4.1.7, and see
//! [`VerificationPolicy::allow_absent_exp`](ironauth_jose::VerificationPolicy::allow_absent_exp)),
//! because a receiver that was down through the window would discard exactly the events it
//! most needs. The bound is generous for that reason, and the durable defence against replay
//! is the `jti` table, which never forgets.
//!
//! # Why the subject has to resolve through the account link
//!
//! The token names a subject in GOOGLE's namespace. Acting on it means finding the local
//! user who signs in with that Google account, which is what `account_links` records. A
//! signal whose subject resolves to nobody is accepted and does nothing: the transmitter is
//! entitled to tell us about accounts we have never seen, and answering an error would
//! invite it to retry forever.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, VerificationPolicy, VerifiedToken, trusted_keys_from_jwks, verify,
};
use ironauth_store::{
    ActorRef, CorrelationId, Scope, ServiceId, TrustedDeviceRevokeReason, UserId,
};
use serde_json::Value;

use crate::risc;
use crate::state::OidcState;
use crate::wellknown::{not_found, parse_scope};

/// A cap on the SET body size, before any JOSE work. A compact JWS SET is small; this stops
/// a hostile body forcing a large decode, and the JOSE core additionally caps each segment.
const MAX_SET_BYTES: usize = 16 * 1024;

/// The RISC event types this receiver ACTS on.
///
/// Both are "this account is no longer safe to trust". `account-purged` and
/// `identifier-changed` are deliberately absent: a purge upstream does not mean the local
/// account is compromised, and an identifier change is a fact to re-read rather than a
/// reason to end sessions. Issue #144 names these two.
const PROTECTIVE_EVENTS: [&str; 2] = [risc::CREDENTIAL_COMPROMISE, risc::ACCOUNT_DISABLED];

/// The uniform refusal: a plain `400` disclosing nothing about which check failed.
///
/// A receiver that distinguished "unknown subject" from "bad signature" would answer the
/// question an attacker is actually asking.
fn rejected() -> Response {
    (StatusCode::BAD_REQUEST, "security event token rejected\n").into_response()
}

/// Seconds since the Unix epoch, from the environment clock seam.
fn epoch_secs(at: std::time::SystemTime) -> i64 {
    at.duration_since(std::time::UNIX_EPOCH).map_or(0, |since| {
        i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
    })
}

/// What one accepted token asks this deployment to do.
struct Signal {
    /// The RISC event type, the key under `events`.
    event_type: String,
    /// The upstream issuer naming the subject (the `iss` inside `sub_id`).
    subject_issuer: String,
    /// The upstream subject.
    subject: String,
    /// The token's dedup handle.
    jti: String,
}

/// Accept one pushed Security Event Token from the configured transmitter.
pub(crate) async fn receive(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: String,
) -> Response {
    let cfg = state.risc_receiver_config().clone();
    if !cfg.enabled {
        return not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    if body.len() > MAX_SET_BYTES {
        return rejected();
    }
    let token = body.trim();
    if token.is_empty() {
        return rejected();
    }

    // THE KEYS AND THE ALGORITHMS COME FROM CONFIGURATION, never from the token. The
    // expected `iss` is the configured transmitter, so a token claiming to be from anyone
    // else fails the claim check rather than selecting its own key.
    let keys = trusted_keys_from_jwks(cfg.jwks.as_bytes());
    let algorithms: Vec<JwsAlgorithm> = cfg
        .algorithms
        .iter()
        .filter_map(|name| JwsAlgorithm::from_jose_name(name))
        .collect();
    if keys.is_empty() || algorithms.is_empty() {
        return rejected();
    }
    let Ok(policy) = VerificationPolicy::new(
        algorithms,
        keys,
        cfg.issuer.clone(),
        state.issuer_for(&scope),
        // A SET from a FOREIGN issuer: `secevent+jwt` is only RECOMMENDED by RFC 8417
        // section 2.2 and transmitters vary, so requiring the media type would refuse
        // conforming tokens for no gain. The registered keys and the pinned `iss` and `aud`
        // are what separate this token from every other.
        ExpectedTyp::ForeignIssuer,
    ) else {
        return rejected();
    };
    // SETs CARRY NO `exp`, and SSF 1.0 section 4.1.7 makes that a MUST NOT. Requiring one
    // would refuse every conforming token Google sends.
    let policy = policy.allow_absent_exp(true);

    let Ok(verified) = verify(token, &policy, state.env().clock()) else {
        return rejected();
    };

    // THE ISSUANCE WINDOW (criterion 5). See the module header for why this is a bound and
    // not an expiry, and why the durable replay defence is the `jti` table below.
    let Some(iat) = verified.claims().issued_at() else {
        return rejected();
    };
    let max_age = i64::try_from(cfg.max_issuance_age_secs).unwrap_or(i64::MAX);
    let skew = i64::try_from(VerificationPolicy::DEFAULT_SKEW.as_secs()).unwrap_or(i64::MAX);
    if epoch_secs(state.now()).saturating_sub(iat) > max_age.saturating_add(skew) {
        return rejected();
    }

    let Some(signal) = parse_signal(&verified) else {
        return rejected();
    };

    // THE REPLAY CLAIM, taken BEFORE anything is acted on and never after. Claiming after
    // acting would leave a window in which two concurrent deliveries both revoke.
    match state
        .store()
        .scoped(scope)
        .risc_received_sets()
        .claim(state.env(), &cfg.issuer, &signal.jti)
        .await
    {
        // ALREADY SEEN. A 202 rather than a 400: the transmitter did nothing wrong and must
        // not retry, and RFC 8935 treats a 2xx as delivered.
        Ok(false) => return accepted(),
        Ok(true) => {}
        Err(_) => return server_error(),
    }

    if !PROTECTIVE_EVENTS.contains(&signal.event_type.as_str()) {
        return accepted();
    }

    let Ok(linked) = resolve_linked_user(&state, scope, &cfg.connector_id, &signal).await else {
        return server_error();
    };
    // A SUBJECT WE DO NOT KNOW is not an error. The transmitter may tell us about accounts
    // that never signed in here, and answering an error would have it retry forever.
    let Some(user) = linked else {
        return accepted();
    };

    if apply_protections(&state, scope, &cfg, &user).await.is_err() {
        return server_error();
    }
    accepted()
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, "").into_response()
}

fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
}

/// Read the RFC 8417 `events` map and the RFC 9493 `sub_id`, after verification.
///
/// EXACTLY ONE EVENT. RFC 8417 permits several in one SET, and this refuses that shape
/// rather than acting on the first: a token carrying a protective event alongside others
/// would have this deployment act on one and silently drop the rest, and "we acted on part
/// of it" is not a state the audit trail can express.
///
/// THE SUBJECT'S DECLARED FORMAT IS CHECKED, not merely the members it happens to carry.
/// Only RFC 9493 `iss_sub` is accepted, which is what Google sends and what `account_links`
/// is keyed on.
///
/// Reading `iss` and `sub` while ignoring the label would accept a subject declaring
/// `email` that also carried them, and resolve it as though the transmitter had named an
/// account pair. A receiver that trusts members while ignoring the label put on them is
/// reading a different subject from the one that was sent. It also keeps address-matching
/// structurally out of reach: nothing here ever resolves a local user from an email, so a
/// transmitter cannot end the sessions of everyone whose address it can name.
fn parse_signal(verified: &VerifiedToken) -> Option<Signal> {
    let claims = verified.claims();
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|jti| !jti.is_empty())?
        .to_owned();
    let events = claims.get("events").and_then(Value::as_object)?;
    if events.len() != 1 {
        return None;
    }
    let (event_type, _body) = events.iter().next()?;
    let sub_id = claims.get("sub_id").and_then(Value::as_object)?;
    if sub_id.get("format").and_then(Value::as_str)? != "iss_sub" {
        return None;
    }
    let subject_issuer = sub_id
        .get("iss")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|iss| !iss.is_empty())?
        .to_owned();
    let subject = sub_id
        .get("sub")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|sub| !sub.is_empty())?
        .to_owned();
    Some(Signal {
        event_type: event_type.clone(),
        subject_issuer,
        subject,
        jti,
    })
}

/// Find the local user who signs in with the upstream account this signal names.
///
/// The composite is built by [`crate::federation::federated_external_id`], the SAME helper
/// the login path uses to WRITE the link, so a lookup and an enrolment cannot disagree about
/// how an issuer and subject combine into a key.
async fn resolve_linked_user(
    state: &OidcState,
    scope: Scope,
    connector_id: &str,
    signal: &Signal,
) -> Result<Option<UserId>, ()> {
    let external_id =
        crate::federation::federated_external_id(&signal.subject_issuer, &signal.subject);
    let link = state
        .store()
        .scoped(scope)
        .account_links()
        .resolve(connector_id, &external_id)
        .await
        .map_err(|_| ())?;
    let Some(link) = link else {
        return Ok(None);
    };
    Ok(state
        .store()
        .scoped(scope)
        .users()
        .parse_id(&link.user_id)
        .ok())
}

/// Apply the configured protections to the linked user.
///
/// BOTH HALVES MATTER. Ending sessions removes what the attacker already holds; revoking
/// remembered devices is what stops them walking back in, because a remembered device is
/// precisely the thing that lets the next sign-in skip the strong factor. The pair is
/// criterion 4's "session revocation and step-up flag".
///
/// Each write is audited by the store under a synthetic service actor: the SET's signature
/// IS the authorization, and there is no human or client principal to attribute it to.
async fn apply_protections(
    state: &OidcState,
    scope: Scope,
    cfg: &ironauth_config::RiscReceiverConfig,
    user: &UserId,
) -> Result<(), ()> {
    let env = state.env();
    let actor = ActorRef::service(ServiceId::generate(env));
    let acting = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env));

    if cfg.revoke_sessions {
        // HARD KILL. A compromise is exactly the case where leaving the user's offline
        // families alive would let the attacker mint fresh access tokens from a refresh
        // token they already hold.
        acting
            .sessions()
            .revoke_all_for_user(env, user, true, None)
            .await
            .map_err(|_| ())?;
    }
    if cfg.revoke_trusted_devices {
        acting
            .trusted_devices()
            .self_revoke_all(env, user, TrustedDeviceRevokeReason::UpstreamCompromise)
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}
