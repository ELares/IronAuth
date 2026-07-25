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

/// The longest slug the `org_roles_slug_valid` and `org_groups_slug_valid` CHECK
/// constraints accept: one leading character plus up to 62 more.
const SLUG_MAX_LEN: usize = 63;

/// Require a stable-name slug matching the schema's `^[a-z0-9][a-z0-9._-]{0,62}$`
/// CHECK (issue #97), mapping any violation to a 400.
///
/// This is the MANAGEMENT EDGE the store's `NewOrgRole::slug` and
/// `NewOrgGroup::slug` doc comments delegate to. The CHECK constraint is the real
/// guarantee, but a value that reaches it and is refused surfaces as an opaque
/// database error, so validating here is what turns "that slug is not allowed"
/// into a caller-facing message naming the field and the rule.
///
/// The slug is NOT trimmed and NOT case folded, unlike a display name: it is the
/// immutable name a later authorization decision keys on, so accepting `"Admin "`
/// and silently storing `"admin"` would make two visibly different requests
/// collide on the uniqueness index. A value that is not already canonical is
/// refused instead.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if `value` is empty, longer than 63 characters, or
/// contains a character outside the allowed set (or leads with `.`, `-`, or `_`).
pub fn require_slug(value: &str, field: &str) -> Result<String, ApiError> {
    let bad = || {
        ApiError::BadRequest(format!(
            "{field} must be 1 to {SLUG_MAX_LEN} characters matching \
             ^[a-z0-9][a-z0-9._-]{{0,62}}$ (lowercase, no leading punctuation)"
        ))
    };
    if value.is_empty() || value.len() > SLUG_MAX_LEN {
        return Err(bad());
    }
    let mut chars = value.chars();
    let first = chars.next().ok_or_else(bad)?;
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(bad());
    }
    for ch in chars {
        let allowed =
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_' || ch == '-';
        if !allowed {
            return Err(bad());
        }
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{ApiError, require_slug};

    #[test]
    fn a_slug_matching_the_check_constraint_is_accepted_verbatim() {
        let at_the_bound = "x".repeat(63);
        for raw in ["admin", "a", "0", "team.eu-west_1", &at_the_bound] {
            assert_eq!(
                require_slug(raw, "slug").expect("valid slug"),
                raw,
                "{raw:?} must be accepted unchanged"
            );
        }
    }

    #[test]
    fn a_slug_the_check_constraint_would_refuse_is_a_bad_request() {
        // Each of these is refused by `^[a-z0-9][a-z0-9._-]{0,62}$`. Letting one
        // through would trade a caller-facing 400 for an opaque 500 from the CHECK.
        let one_over_the_bound = "x".repeat(64);
        for raw in [
            "",               // empty
            "Admin",          // uppercase
            ".leading",       // leading punctuation
            "-leading",       //
            "_leading",       //
            "has space",      //
            "has/slash",      //
            "emoji\u{1F600}", // non-ASCII
            " admin",         // an untrimmed value is refused, never silently trimmed
            "admin ",         //
            &one_over_the_bound,
        ] {
            assert!(
                matches!(require_slug(raw, "slug"), Err(ApiError::BadRequest(_))),
                "{raw:?} must be a structured bad request"
            );
        }
    }
}
