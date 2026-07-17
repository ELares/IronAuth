// SPDX-License-Identifier: MIT OR Apache-2.0

//! Remember-device (trusted-device) cookie issuance and server-side validation
//! (issue #71).
//!
//! After a COMPLETED multi-factor login (a genuine second factor, or a user-verified
//! passkey), a tenant may REMEMBER the device so a subsequent login from it SKIPS the
//! second factor while STILL requiring primary authentication. The remembered device is
//! a `__Host-` prefixed, `Secure`, `HttpOnly` cookie carrying `<tdv_ id>.<secret>`; the
//! server stores ONLY the SHA-256 digest of the secret (server-side state, see
//! [`crate::session::TRUSTED_DEVICE_COOKIE`]). The cookie proves nothing on its own:
//!
//! - a FORGED or TAMPERED cookie whose secret does not hash to a stored digest finds no
//!   row (the digest match stands in for a signature check);
//! - a cookie for another SUBJECT is rejected (the row is subject-bound), so a device
//!   cookie for user A can never skip for user B;
//! - a REPLAYED cookie after revocation fails IMMEDIATELY (the row's `revoked_at` is
//!   checked in the same read), not merely by signature;
//! - an out-of-policy cookie (past its max-age or idle window) is rejected server-side.
//!
//! The honest acr/amr contribution lives in [`crate::authn`]: a remembered-device login
//! records `[<primary>, TrustedDevice]`, so the token's `acr` is the DISTINCT, weaker
//! `mfa_remembered` and its `amr` carries NO fabricated `mfa`/`otp`.

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_store::{
    CorrelationId, NewTrustedDevice, Scope, SessionId, TrustedDeviceId, TrustedDeviceRevokeReason,
    UserId,
};
use sha2::{Digest, Sha256};

use crate::interaction;
use crate::session;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The number of random bytes in a device secret (issue #71). 256 bits puts the secret
/// out of guessing reach, exactly like a session id's payload; the cookie value is the
/// device id plus this secret, and only the secret's digest is stored.
const DEVICE_SECRET_BYTES: usize = 32;

/// The SHA-256 digest of a presented (or freshly minted) device secret (issue #71): the
/// server-side state a cookie is validated against. A one-way digest, so a database dump
/// reveals no usable cookie value; the match stands in for a signature check.
fn secret_digest(secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

/// Mint a fresh high-entropy device secret from the entropy seam (issue #71),
/// URL-safe base64 encoded so it is a valid cookie-value token and contains no `.`
/// (the id/secret separator).
fn mint_secret(state: &OidcState) -> String {
    let mut bytes = [0_u8; DEVICE_SECRET_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The observed User-Agent at enrollment, or a stable placeholder when the header is
/// absent or not UTF-8 (the device metadata is a UI/audit convenience, never a security
/// input, so an absent UA never fails the remember).
fn observed_user_agent(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| "unknown".to_owned(), str::to_owned)
}

/// The coarse network locality at enrollment (a /24 or /48 prefix, never a host), or a
/// placeholder when the resolved client IP is absent or unparseable.
fn observed_geo(headers: &HeaderMap) -> String {
    crate::account::coarse_location(crate::abuse::resolved_client_ip(headers).as_deref())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// REMEMBER this browser's device after a completed multi-factor login (issue #71) and
/// return the `Set-Cookie` value that plants the remember-device cookie, or [`None`]
/// when the feature is disabled or the device could not be persisted (best-effort: a
/// failed remember never fails the already-successful login).
///
/// `session_id` is the multi-factor session the trust descends from (the lineage
/// recorded for the account UI and audit). The duration policy (max-age cap and idle
/// window) comes from tenant config; the caller has already decided the tenant wants to
/// remember this device (the opt-in checkbox or the tenant-decides policy).
pub(crate) async fn remember_device(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    session_id: &SessionId,
    headers: &HeaderMap,
) -> Option<String> {
    if !state.trusted_devices_enabled() {
        return None;
    }
    let secret = mint_secret(state);
    let digest = secret_digest(&secret);
    let now = state.now();
    let max_age_micros = epoch_micros(
        now.checked_add(state.trusted_device_max_age())
            .unwrap_or(now),
    );
    let idle_micros = epoch_micros(now.checked_add(state.trusted_device_idle()).unwrap_or(now));
    let user_agent = observed_user_agent(headers);
    let geo = observed_geo(headers);
    let actor = interaction::user_actor(subject);
    let device_id = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .trusted_devices()
        .remember(
            state.env(),
            subject,
            NewTrustedDevice {
                device_secret_hash: &digest,
                session_lineage: &session_id.to_string(),
                user_agent: &user_agent,
                coarse_location: &geo,
                max_age_expires_micros: max_age_micros,
                idle_expires_micros: idle_micros,
            },
        )
        .await
        .ok()?;
    let value = format!(
        "{}{}{}",
        device_id,
        session::TRUSTED_DEVICE_COOKIE_SEP,
        secret
    );
    Some(session::build_trusted_device_cookie(
        &value,
        state.trusted_device_max_age(),
    ))
}

/// Split a presented trusted-device cookie value into its `<tdv_ id>.<secret>` halves
/// (issue #71). A value missing the separator, or with an empty half, is [`None`] (a
/// malformed cookie can never validate).
fn split_cookie(value: &str) -> Option<(&str, &str)> {
    let (id, secret) = value.split_once(session::TRUSTED_DEVICE_COOKIE_SEP)?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id, secret))
}

/// VALIDATE the presented remember-device cookie against server-side state and, when it
/// is a LIVE device for `subject`, CONSUME the use by sliding its idle window and
/// stamping last-seen; return the validated device id (issue #71).
///
/// Returns [`None`] when the feature is disabled, no cookie is present, the cookie is
/// malformed/tampered (its secret does not hash to a stored digest, or its id is not a
/// `tdv_` id in scope), it belongs to another subject, it was revoked, or it is out of
/// its max-age/idle policy. Every one of those is a SERVER-SIDE check, so a replayed
/// cookie after revocation FAILS here, not merely by signature.
pub(crate) async fn validate_and_consume(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    headers: &HeaderMap,
) -> Option<TrustedDeviceId> {
    if !state.trusted_devices_enabled() {
        return None;
    }
    let raw = session::trusted_device_from_cookie_header(interaction::cookie_header(headers))?;
    let (id_str, secret) = split_cookie(raw)?;
    let read = state.store().scoped(scope).trusted_devices();
    let device_id = read.parse_id(id_str).ok()?;
    let digest = secret_digest(secret);
    let now_micros = epoch_micros(state.now());
    let validated = read
        .validate(&device_id, subject, &digest, now_micros)
        .await
        .ok()
        .flatten()?;
    // Consume the use: slide the idle window and stamp last-seen (capped at the absolute
    // max-age in SQL). Best-effort: a failed slide never invalidates an otherwise-valid
    // skip, exactly as the session idle slide is best-effort.
    let new_idle_micros = epoch_micros(
        state
            .now()
            .checked_add(state.trusted_device_idle())
            .unwrap_or_else(|| state.now()),
    );
    let actor = interaction::user_actor(subject);
    let _ = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .trusted_devices()
        .touch(subject, &validated, now_micros, new_idle_micros)
        .await;
    Some(validated)
}

/// INVALIDATE every remembered device of `subject` (issue #71): the server-side kill
/// switch a password change/reset (per tenant policy) or an admin action runs. A
/// best-effort bulk revoke; a fault never blocks the credential change that triggered
/// it. Returns the number of devices revoked.
pub(crate) async fn invalidate_all(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    reason: TrustedDeviceRevokeReason,
) -> u64 {
    if !state.trusted_devices_enabled() {
        return 0;
    }
    let actor = interaction::user_actor(subject);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .trusted_devices()
        .self_revoke_all(state.env(), subject, reason)
        .await
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_digest_is_stable_and_distinguishes_secrets() {
        // The digest is deterministic (a presented secret hashes to the same stored
        // value) and collision-distinct (a tampered secret hashes to a different value,
        // so it never matches the stored digest).
        assert_eq!(secret_digest("abc"), secret_digest("abc"));
        assert_ne!(secret_digest("abc"), secret_digest("abd"));
        // A digest is a full SHA-256 (32 bytes).
        assert_eq!(secret_digest("anything").len(), 32);
    }

    #[test]
    fn split_cookie_requires_both_halves() {
        assert_eq!(split_cookie("tdv_id.secret"), Some(("tdv_id", "secret")));
        assert_eq!(split_cookie("no-separator"), None);
        assert_eq!(split_cookie(".secret"), None);
        assert_eq!(split_cookie("tdv_id."), None);
    }
}
