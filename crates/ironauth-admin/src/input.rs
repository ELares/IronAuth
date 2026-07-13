// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small request-body validation helpers shared by the resource handlers.

use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// Parse a JSON request body, mapping any decode failure to a 400.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if the body is not valid JSON for `T`.
pub fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|error| ApiError::BadRequest(format!("invalid JSON body: {error}")))
}

/// Require a non-empty, non-whitespace display value, mapping absence to a 400.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if `value` is empty or only whitespace.
pub fn require_non_empty(value: &str, field: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(trimmed.to_owned())
}
