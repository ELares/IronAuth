// SPDX-License-Identifier: MIT OR Apache-2.0

//! The third-party risk-signal ingestion endpoint (issue #82, PR 1, EXPLORATORY).
//!
//! An external fraud/risk source delivers a signal about a subject as a SIGNED Security
//! Event Token (RFC 8417 SET, a compact JWS) pushed to `POST .../risk/signals`. The
//! delivery is AUTHENTICATED by its SIGNATURE, never a shared bearer secret: the SET `iss`
//! selects the registered source in the env `RiskConfig`, and the JWS is verified through
//! the hardened JOSE core ([`ironauth_jose::verify`]) against that source's REGISTERED
//! public key(s), with the algorithm taken from the source's allowlist (never the token
//! header) and `alg=none`/HMAC structurally inexpressible. Only a verified SET from a
//! listed, enabled source is ingested; every rejection is a UNIFORM `400` with no oracle.
//!
//! Ingestion writes ONE `risk_signals` row (migration 0064), idempotent on
//! `(source, source_jti)` so a re-delivery is a no-op (never a duplicate). The #79 risk
//! engine later folds a subject's FRESH signals in as WEIGHTED policy inputs; nothing here
//! resolves an action, so an ingested signal is structurally a policy input, never a
//! verdict.
//!
//! The whole surface is gated by the `risk-signals` experimental feature
//! ([`OidcState::risk_signals_enabled`]): with the flag off the endpoint answers a uniform
//! `404` and no signal path runs.
//!
//! # The SET contract (CAEP-aligned)
//!
//! The verified SET carries the standard `iss` (the source), `aud` (this env's issuer),
//! `exp`/`iat`, and `jti` (the single-delivery dedup key), plus:
//!
//! - `sub_id`: an RFC 9493 Subject Identifier `{ "format": <format>, "subject": <raw> }`.
//!   The `format` is pinned to the closed set the store CHECK enforces; the raw `subject`
//!   is blind-indexed before it lands (never a plaintext column) and, for an identifier
//!   format, resolved to a local `usr_` id through the user identifier blind index.
//! - `signal_type`: a free-text, URI-capable event-type token (a CAEP event-type URI fits).
//! - `event_timestamp`: the source's event instant in seconds since the epoch (freshness).
//! - `payload`: the tagged `{ "kind": "verdict"|"score", ... }` body the per-source config
//!   maps to a `RiskLevel`.
//!
//! This is a SUPERSET of a CAEP SET, so an M14 RISC/CAEP receiver becomes a second writer of
//! `risk_signals` rows with no schema change: the `events` map key maps to `signal_type` and
//! the per-event claims map to `payload`, `sub_id`/`event_timestamp`/`jti` map verbatim.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ironauth_jose::{
    JwsAlgorithm, VerificationPolicy, VerifiedToken, trusted_keys_from_jwks, verify,
};
use ironauth_store::{ActorRef, CorrelationId, NewRiskSignal, ServiceId, StoreError, UserId};
use serde_json::Value;

use crate::state::OidcState;
use crate::wellknown::{not_found, parse_scope};

/// The closed RFC 9493 subject-identifier formats the store CHECK admits (issue #82). A SET
/// whose `sub_id.format` is outside this set is rejected before any write.
const SUBJECT_FORMATS: [&str; 5] = ["account", "email", "phone_number", "iss_sub", "opaque"];

/// The identifier formats whose raw subject the ingestion attempts to RESOLVE to a local
/// `usr_` id through the user identifier blind index (issue #82). The remaining formats
/// (`iss_sub`, `opaque`) name a source-scoped subject with no local login handle, so the row
/// is stored with a NULL local subject and is inert until (a future release) resolves it.
const RESOLVABLE_FORMATS: [&str; 3] = ["account", "email", "phone_number"];

/// A cap on the SET body size, before any JOSE work (issue #82). A compact JWS SET is small;
/// this stops a hostile body from forcing a large decode. The JOSE core additionally caps
/// each segment.
const MAX_SET_BYTES: usize = 16 * 1024;

/// The uniform ingestion refusal: a plain `400` disclosing nothing about which check failed
/// (an unknown source, a bad signature, a wrong algorithm, an expired SET, or a malformed
/// claim all look identical), so the endpoint is no oracle. Distinct from the flag-off
/// `404`, but it never leaks.
fn rejected() -> Response {
    (StatusCode::BAD_REQUEST, "risk signal rejected\n").into_response()
}

/// The uniform server-error response: a signal was well formed and verified but a store
/// fault prevented ingestion. A retry (with the same `jti`) is idempotent.
fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "risk signal ingestion failed\n",
    )
        .into_response()
}

/// The success response: the SET was verified and ingested (or was an idempotent
/// re-delivery). `202 Accepted`, the CAEP SET-push (RFC 8935) accept response, with an empty
/// body (the endpoint returns no data about the subject or the decision).
fn accepted() -> Response {
    StatusCode::ACCEPTED.into_response()
}

/// INGEST a signed third-party risk-signal SET (issue #82, PR 1).
///
/// Feature-gated: answers a uniform `404` unless [`OidcState::risk_signals_enabled`]. The
/// body is the compact JWS SET. On success (or an idempotent re-delivery) the response is
/// `202 Accepted`; every rejection is a uniform `400` (no oracle) and a store fault is a
/// `500`.
pub(crate) async fn ingest(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: String,
) -> Response {
    if !state.risk_signals_enabled() {
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

    // 1. Select the candidate source by the SET's (unverified) `iss`. This reads NO trust
    //    from the token: `iss` is a bare selector, and verify() below re-enforces
    //    expected_iss == source.iss EXACTLY, so a lying iss only selects a source whose
    //    registered key cannot verify the forged signature.
    let Some(iss) = unverified_iss(token) else {
        return rejected();
    };
    let Some(source) = state
        .risk_config()
        .signal_sources
        .iter()
        .find(|source| source.enabled && source.iss == iss)
    else {
        return rejected();
    };

    // 2. Build the per-source verification policy from the REGISTERED public key(s) and the
    //    source's algorithm allowlist. The expected audience is THIS env's issuer, so a SET
    //    minted for another audience is rejected.
    let keys = trusted_keys_from_jwks(source.jwks.as_bytes());
    let algorithms: Vec<JwsAlgorithm> = source
        .algorithms
        .iter()
        .filter_map(|name| JwsAlgorithm::from_jose_name(name))
        .collect();
    if keys.is_empty() || algorithms.is_empty() {
        return rejected();
    }
    let audience = state.issuer_for(&scope);
    let Ok(policy) = VerificationPolicy::new(algorithms, keys, source.iss.clone(), audience) else {
        return rejected();
    };

    // 3. The ONE signature verification: allowlist-driven algorithm, key only from the
    //    registered set, `alg=none`/HMAC inexpressible, `iss`/`aud`/`exp`/`nbf`/`iat`
    //    enforced. An unsigned, wrong-key, wrong-algorithm, expired, or wrong-audience SET
    //    is a uniform rejection here.
    let Ok(verified) = verify(token, &policy, state.env().clock()) else {
        return rejected();
    };

    // 4. Extract and validate the SET's signal claims (all read AFTER verification).
    let Some(signal) = parse_signal_claims(&verified) else {
        return rejected();
    };

    // 5. Resolve the raw external subject to a local `usr_` id for an identifier format
    //    (the engine keys on this), through the user identifier blind index. A format with
    //    no local login handle, or a raw subject that matches no local account, leaves the
    //    row's local subject NULL (an inert row).
    let Ok(resolved_subject) = resolve_local_subject(&state, scope, &signal).await else {
        return server_error();
    };

    // 6. Ingest ONE row, idempotent on (source, source_jti): a re-delivery is a no-op. The
    //    actor is a synthetic service principal attributed to the risk-signal subsystem
    //    (the SET signature IS the authorization); the audit detail records the source, the
    //    event type, and the resolved subject, never the raw external subject.
    let actor = ActorRef::service(ServiceId::generate(state.env()));
    let event_timestamp_micros = signal.event_timestamp_secs.saturating_mul(1_000_000);
    let ingest = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .risk_signals()
        .ingest(
            state.env(),
            NewRiskSignal {
                source: &source.iss,
                signal_type: &signal.signal_type,
                subject_format: &signal.subject_format,
                subject_raw: &signal.subject_raw,
                resolved_subject: resolved_subject.as_ref(),
                payload_json: &signal.payload_json,
                event_timestamp_micros,
                source_jti: &signal.jti,
            },
        )
        .await;
    match ingest {
        // A first delivery ingested the row; a re-delivery (Ok(false)) was an idempotent
        // no-op. Both are a successful accept (the signal is single-delivered).
        Ok(_) => accepted(),
        Err(StoreError::NotFound) => rejected(),
        Err(_) => server_error(),
    }
}

/// The verified signal claims extracted from a SET (issue #82). Every field is read only
/// after the signature verified, so no unverified payload is ever trusted.
struct SignalClaims {
    jti: String,
    signal_type: String,
    subject_format: String,
    subject_raw: String,
    payload_json: String,
    event_timestamp_secs: i64,
}

/// Parse and validate the signal-specific claims of a verified SET (issue #82). Returns
/// [`None`] when a required claim is absent or malformed, or the subject format is outside
/// the closed set, so a structurally invalid SET is a uniform rejection.
fn parse_signal_claims(verified: &VerifiedToken) -> Option<SignalClaims> {
    let claims = verified.claims();
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|jti| !jti.is_empty())?
        .to_owned();
    let signal_type = claims
        .get("signal_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|signal_type| !signal_type.is_empty())?
        .to_owned();
    let sub_id = claims.get("sub_id").and_then(Value::as_object)?;
    let subject_format = sub_id.get("format").and_then(Value::as_str)?.to_owned();
    if !SUBJECT_FORMATS.contains(&subject_format.as_str()) {
        return None;
    }
    let subject_raw = sub_id
        .get("subject")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|subject| !subject.is_empty())?
        .to_owned();
    let payload = claims
        .get("payload")
        .filter(|payload| payload.is_object())?;
    let payload_json = serde_json::to_string(payload).ok()?;
    let event_timestamp_secs = claims.get("event_timestamp").and_then(Value::as_i64)?;
    Some(SignalClaims {
        jti,
        signal_type,
        subject_format,
        subject_raw,
        payload_json,
        event_timestamp_secs,
    })
}

/// Resolve the raw external subject to a local `usr_` id (issue #82), for an identifier
/// format only, through the user identifier blind index (the same lookup the login surface
/// uses). Returns `Ok(None)` when the format has no local handle or the raw subject matches
/// no local account (an inert row), and `Err(())` on a store fault the caller maps to a 500.
async fn resolve_local_subject(
    state: &OidcState,
    scope: ironauth_store::Scope,
    signal: &SignalClaims,
) -> Result<Option<UserId>, ()> {
    if !RESOLVABLE_FORMATS.contains(&signal.subject_format.as_str()) {
        return Ok(None);
    }
    match state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(&signal.subject_raw)
        .await
    {
        Ok(Some(record)) => Ok(Some(record.id)),
        Ok(None) => Ok(None),
        Err(_) => Err(()),
    }
}

/// Extract the `iss` from a compact JWS/JWT's payload WITHOUT verifying the token (issue
/// #82), the narrow purpose being to SELECT the candidate source whose registered key the
/// signature is then verified against. This reads NO trust: the returned `iss` is a bare
/// selector, and [`verify`] re-enforces `expected_iss == source.iss` exactly, so a lying
/// `iss` only selects a source whose key cannot verify the forged signature. Bounded (an
/// oversized payload segment yields [`None`]) and touches no key material. Returns [`None`]
/// when the token is malformed, the payload is not a JSON object, or no string `iss` is
/// present.
fn unverified_iss(token: &str) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // A generous cap for the PAYLOAD segment of a small SET, small enough that a hostile
    // token cannot force a large base64/JSON decode here.
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
