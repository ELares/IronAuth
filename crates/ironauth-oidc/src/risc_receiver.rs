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

//! Every VALIDATION refusal is the same `400` with no detail. A receiver that said WHICH
//! check failed would tell an attacker whether they had guessed a real subject, a real
//! connector, or a live `jti`.
//!
//! The endpoint does answer other statuses, and each says something deliberately: `404`
//! when the receiver is not enabled at all (a transmitter probing an unconfigured
//! deployment learns it does not implement this, which is true), `202` for a token that
//! was handled -- including one that resolved to nobody or asked for nothing -- and `500`
//! for a fault on our side that the transmitter SHOULD retry. None of those distinguish
//! one failed check from another.
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
/// TAKEN FROM WHAT GOOGLE ACTUALLY SENDS, not from what the vocabulary defines. Google
/// Cross-Account Protection documents its event set as `sessions-revoked`,
/// `tokens-revoked`, `token-revoked`, `account-disabled`, `account-enabled`,
/// `account-credential-change-required` and `verification`. It does NOT send
/// `credential-compromise`, though issue #144 names that type and RISC 1.0 defines it, so
/// it is accepted here for any other RISC transmitter and for the issue's own wording.
///
/// Every entry means "what this deployment holds for that account can no longer be
/// trusted":
///
/// - `sessions-revoked` and `tokens-revoked`/`token-revoked`: the upstream ended its own
///   sessions, so ours were minted against something that is gone;
/// - `account-disabled`: the upstream account cannot be used, so neither should the local
///   one;
/// - `account-credential-change-required`: Google's phrasing for a credential that must
///   be replaced, which is the closest thing it sends to a compromise;
/// - `credential-compromise`: the RISC 1.0 type, for transmitters that do send it.
///
/// DELIBERATELY ABSENT: `account-enabled` (a restoration, not a threat), `account-purged`
/// (an upstream deletion does not make the local account compromised),
/// `identifier-changed` (a fact to re-read), and `verification` (the stream ping, which is
/// acknowledged and does nothing).
const PROTECTIVE_EVENTS: [&str; 6] = [
    "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
    "https://schemas.openid.net/secevent/risc/event-type/tokens-revoked",
    "https://schemas.openid.net/secevent/risc/event-type/token-revoked",
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
    risc::CREDENTIAL_COMPROMISE,
    risc::ACCOUNT_DISABLED,
];

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
        cfg.audience.clone(),
        // A SET from a FOREIGN issuer: `secevent+jwt` is only RECOMMENDED by RFC 8417
        // section 2.2 and transmitters vary, so requiring the media type would refuse
        // conforming tokens for no gain. The registered keys and the pinned `iss` and `aud`
        // are what separate this token from every other.
        //
        // THE `aud` IS THE OAUTH CLIENT ID, from configuration. Google stamps the
        // receiving app's client id rather than a URL; pinning this environment's issuer
        // here, which is the SSF 1.0 shape, refused every genuine Google token.
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

    let Some(signal) = parse_signal(&verified, &cfg.issuer) else {
        return rejected();
    };

    // THE REPLAY CHECK, which is a READ here and a WRITE only after the work succeeds.
    //
    // The ordering was the other way round and it was wrong. Claiming first makes a
    // TRANSIENT failure permanent: the row commits, the revocation then fails on a dropped
    // connection, the transmitter retries, and the retry is refused as a replay. The
    // compromise signal is lost for good, and the audit trail shows the token as handled.
    //
    // Recording afterwards trades that for a much smaller risk: two deliveries of one
    // token arriving CONCURRENTLY can both act. That is harmless in a way the other
    // failure is not, because the two are microseconds apart -- there is no interval in
    // which the user could have re-established anything for a second pass to destroy. The
    // failure the table exists to prevent is a token replayed HOURS later, after recovery,
    // and recording on success closes that just as completely.
    match state
        .store()
        .scoped(scope)
        .risc_received_sets()
        .seen(&cfg.issuer, &signal.jti)
        .await
    {
        // ALREADY ACTED ON. A 202 rather than a 400: the transmitter did nothing wrong and
        // must not retry, and RFC 8935 treats a 2xx as delivered.
        Ok(true) => return accepted(),
        Ok(false) => {}
        Err(_) => return server_error(),
    }

    // NOT PROTECTIVE, so there is nothing to do and nothing to remember. Recording it
    // would fill the table with every `verification` ping the transmitter ever sends.
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
    // RECORDED ONLY NOW. A failure to record is not a failure of the protection, which has
    // already happened; the cost is that a later replay would revoke again, which is the
    // safe direction.
    let _ = state
        .store()
        .scoped(scope)
        .risc_received_sets()
        .claim(state.env(), &cfg.issuer, &signal.jti)
        .await;
    accepted()
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, "").into_response()
}

fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
}

/// Read the RFC 8417 `events` map and the subject, after verification.
///
/// EXACTLY ONE EVENT. RFC 8417 permits several in one SET, and this refuses that shape
/// rather than acting on the first: a token carrying a protective event alongside others
/// would have this deployment act on one and silently drop the rest, and "we acted on part
/// of it" is not a state the audit trail can express.
///
/// # The subject is read from where the transmitter actually puts it
///
/// Google Cross-Account Protection carries the subject INSIDE the event object, as
/// `subject` with a `subject_type` of `iss-sub` -- the older RISC shape, with a hyphen.
/// SSF 1.0 section 3.1.2 instead puts an RFC 9493 `sub_id` at the TOP level with a `format`
/// of `iss_sub`, with an underscore, which is what this deployment's own transmitter emits.
///
/// Both are accepted, and the in-event form is tried first because it is the one the only
/// transmitter in scope sends. An earlier version of this receiver read only the top-level
/// form and would have refused every genuine Google token while passing its own tests,
/// because those tests were written from the same wrong assumption as the code.
///
/// # The subject's issuer must be the transmitter
///
/// Whichever shape carries it, `iss` is a value inside the token, so it is chosen by
/// whoever minted it, and it feeds straight into the account-link lookup that decides
/// WHOSE sessions end. A transmitter may speak only about its own subjects.
///
/// The comparison ignores a trailing slash: Google's documented example issues tokens with
/// `iss` as `https://accounts.google.com/` while its OpenID discovery document uses
/// `https://accounts.google.com`, and an operator who configured either spelling means the
/// same transmitter.
fn parse_signal(verified: &VerifiedToken, transmitter: &str) -> Option<Signal> {
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
    let (event_type, body) = events.iter().next()?;
    let (subject_issuer, subject) = read_subject(body, claims.get("sub_id"), transmitter)?;
    Some(Signal {
        event_type: event_type.clone(),
        subject_issuer,
        subject,
        jti,
    })
}

/// Whether two issuer spellings name the same transmitter, ignoring a trailing slash.
fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// The `(issuer, subject)` pair, from the in-event Google shape or the top-level SSF one.
///
/// The DECLARED type is checked in both shapes, not merely the members present. Reading
/// `iss` and `sub` while ignoring the label would accept a subject declaring `email` that
/// also carried them, and resolve it as though an account pair had been named. It also
/// keeps address-matching structurally out of reach: nothing here ever resolves a local
/// user from an email, so a transmitter cannot end the sessions of everyone whose address
/// it can name.
fn read_subject(
    event_body: &Value,
    top_level: Option<&Value>,
    transmitter: &str,
) -> Option<(String, String)> {
    // GOOGLE'S SHAPE FIRST: `events[type].subject` with `subject_type: "iss-sub"`.
    if let Some(subject) = event_body.get("subject").and_then(Value::as_object)
        && subject.get("subject_type").and_then(Value::as_str) == Some("iss-sub")
    {
        return issuer_and_subject(subject, transmitter);
    }
    // THE SSF 1.0 SHAPE: a top-level RFC 9493 `sub_id` with `format: "iss_sub"`.
    let sub_id = top_level?.as_object()?;
    if sub_id.get("format").and_then(Value::as_str) != Some("iss_sub") {
        return None;
    }
    issuer_and_subject(sub_id, transmitter)
}

/// Pull `iss` and `sub` out of either subject object, refusing an issuer that is not the
/// transmitter's own.
fn issuer_and_subject(
    subject: &serde_json::Map<String, Value>,
    transmitter: &str,
) -> Option<(String, String)> {
    let iss = subject
        .get("iss")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|iss| !iss.is_empty() && same_issuer(iss, transmitter))?
        .to_owned();
    let sub = subject
        .get("sub")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|sub| !sub.is_empty())?
        .to_owned();
    Some((iss, sub))
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
    // BOTH ISSUER SPELLINGS ARE TRIED, and this is not belt-and-braces.
    //
    // Google's tokens write `iss` as `https://accounts.google.com/` while its discovery
    // document uses `https://accounts.google.com`, so the composite the LOGIN path stored
    // when the user linked their account may carry either. `same_issuer` already treats
    // the two as one transmitter for the fence above; doing that for the fence and NOT for
    // the lookup is what made the first version of this accept a genuine Google token and
    // then silently resolve nobody -- a 202, no protection, and no way to tell from the
    // outside that anything was wrong.
    //
    // At most two indexed reads, and only for an event that is actually protective.
    let trimmed = signal.subject_issuer.trim_end_matches('/');
    let spellings = [trimmed.to_owned(), format!("{trimmed}/")];

    let mut found = None;
    for issuer in spellings {
        let external_id = crate::federation::federated_external_id(&issuer, &signal.subject);
        if let Some(link) = state
            .store()
            .scoped(scope)
            .account_links()
            .resolve(connector_id, &external_id)
            .await
            .map_err(|_| ())?
        {
            found = Some(link);
            break;
        }
    }
    let Some(link) = found else {
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
/// BOTH HALVES MATTER, and it is worth being exact about what the second one buys, because
/// the obvious claim overreaches for the very users this receiver serves.
///
/// Ending sessions removes what the attacker already holds. Revoking remembered devices
/// removes this deployment's standing assertion that the device is known, which is what
/// lets a sign-in skip the strong factor and what a step-up policy consults.
///
/// It does NOT by itself prevent re-entry for a purely federated user. Someone who signs
/// in only through Google re-enters by satisfying GOOGLE, and whether they still can is
/// Google's decision, not ours -- which is the whole reason the signal arrives. What the
/// pair guarantees locally is that nothing minted before the compromise is still honoured
/// and that the next sign-in is treated as untrusted rather than familiar. For an account
/// that ALSO carries local credentials or a step-up policy, that second half is a real
/// barrier; for one that does not, it is correct hygiene rather than a lock.
///
/// Each write is audited by the store under a synthetic service actor: the SET's signature
/// IS the authorization, and there is no human or client principal to attribute it to.
///
/// # The two writes are separate transactions, and the half-state is transient
///
/// `revoke_all_for_user` and `self_revoke_all` each commit on their own, so the second
/// can fail with the first already done: sessions ended, device trust intact, which is
/// exactly the combination the config doc calls dangerous.
///
/// It does not survive, and the reason is the ORDER the caller records the `jti` in. An
/// `Err` here returns a 500 BEFORE anything is recorded, so no replay row exists, the
/// transmitter retries, and the retry re-runs BOTH writes. Each is idempotent -- revoking
/// an already-ended session and an already-revoked device are both no-ops -- so the
/// second attempt completes the pair and leaves the audit trail describing what actually
/// happened.
///
/// This is worth writing down because it is not visible from here: a reader looking at
/// these two calls alone sees an un-atomic pair and no compensation, and a reviewer did.
/// The compensation is the caller's ordering, not a transaction.
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
