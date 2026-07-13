// SPDX-License-Identifier: MIT OR Apache-2.0

//! Idempotency-Key support for every POST (draft-ietf-httpapi-idempotency-key).
//!
//! The header is required on every POST. The key is scoped to the acting
//! credential (which, for an environment-scoped management key, embeds the
//! tenant and environment). The original response is stored in the SAME
//! transaction as the mutation, so a replay returns that response verbatim
//! without re-running the mutation (and therefore writes no second audit row). A
//! key reused with a different request (a different fingerprint) is rejected.

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use crate::error::ApiError;
use crate::hash::sha256_hex;
use crate::response::json;
use crate::state::AdminState;

/// The Idempotency-Key header name (lowercase for the header map).
pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";

/// Extract the required Idempotency-Key from a POST request.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if the header is absent, non-ASCII, empty, or longer
/// than 255 characters.
pub fn required_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers.get(IDEMPOTENCY_HEADER).ok_or_else(|| {
        ApiError::BadRequest("the Idempotency-Key header is required on POST".to_owned())
    })?;
    let key = value
        .to_str()
        .map_err(|_| ApiError::BadRequest("Idempotency-Key must be ASCII".to_owned()))?;
    if key.is_empty() || key.len() > 255 {
        return Err(ApiError::BadRequest(
            "Idempotency-Key must be 1 to 255 characters".to_owned(),
        ));
    }
    Ok(key.to_owned())
}

/// A fingerprint of the request that a key guards: method, path, and body.
///
/// A replay with the same key but a different fingerprint is a key reused for a
/// different operation, which is rejected rather than served the wrong result.
/// The path is the concrete request path (with real identifiers), so the same
/// key used against two different resources does not collide.
#[must_use]
pub fn fingerprint(method: &str, path: &str, body: &[u8]) -> String {
    let mut buf = Vec::with_capacity(method.len() + path.len() + body.len() + 2);
    buf.extend_from_slice(method.as_bytes());
    buf.push(0);
    buf.extend_from_slice(path.as_bytes());
    buf.push(0);
    buf.extend_from_slice(body);
    sha256_hex(&buf)
}

/// If `(credential_ref, key)` already has a stored response, return it as an
/// idempotent replay (without executing any mutation).
///
/// A stored response whose fingerprint differs from this request is a key reused
/// for a different operation and is rejected. Returns `None` when there is no
/// stored response and the caller should proceed to execute.
///
/// # Errors
///
/// [`ApiError::IdempotencyKeyConflict`] on a fingerprint mismatch;
/// [`ApiError::Internal`] on a store failure.
pub async fn replay_if_stored(
    state: &AdminState,
    credential_ref: &str,
    key: &str,
    fingerprint: &str,
) -> Result<Option<Response>, ApiError> {
    let Some(stored) = state
        .store()
        .management()
        .idempotency()
        .lookup(credential_ref, key)
        .await?
    else {
        return Ok(None);
    };
    if stored.request_fingerprint != fingerprint {
        return Err(ApiError::IdempotencyKeyConflict);
    }
    let status = StatusCode::from_u16(stored.response_status).unwrap_or(StatusCode::OK);
    Ok(Some(json(status, stored.response_body)))
}

/// Resolve a concurrent Idempotency-Key race: the mutation reported a conflict
/// because another request stored the same key first, so re-read and replay the
/// now-committed original response.
///
/// # Errors
///
/// [`ApiError::Internal`] if the row is unexpectedly absent (a stored response
/// must exist after a conflict);
/// [`ApiError::IdempotencyKeyConflict`] on a fingerprint mismatch.
pub async fn replay_after_conflict(
    state: &AdminState,
    credential_ref: &str,
    key: &str,
    fingerprint: &str,
) -> Result<Response, ApiError> {
    replay_if_stored(state, credential_ref, key, fingerprint)
        .await?
        .ok_or(ApiError::Internal)
}
