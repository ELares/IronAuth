// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared HTTP-cache discipline for the per-issuer well-known surfaces.
//!
//! Both the JWKS endpoint ([`crate::jwks`]) and the discovery endpoints
//! ([`crate::discovery`]) answer under the per-environment issuer path, and both
//! carry the SAME operational caching discipline the #19 JWKS work established:
//! an explicit `Cache-Control` (a `max-age` bounded to the 300-to-900-second
//! range) and a strong `ETag`, with a conditional request (`If-None-Match`) that
//! matches returning `304 Not Modified` with no body. Sharing one helper keeps the
//! two surfaces byte-for-byte consistent, so a relying party caches either the key
//! set or the metadata by exactly the same rules.
//!
//! An unknown or malformed `(tenant, environment)` scope is a uniform `404`
//! ([`not_found`]) with no oracle for which of the two it was.

use std::fmt::Write as _;

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{EnvironmentId, Scope, TenantId};
use sha2::{Digest, Sha256};

/// Resolve the `(tenant, environment)` path parameters to a [`Scope`], or `None`
/// if either does not parse (a uniform not-found for the caller, with no oracle
/// for which half was malformed).
pub(crate) fn parse_scope(tenant_id: &str, environment_id: &str) -> Option<Scope> {
    let tenant = TenantId::parse(tenant_id).ok()?;
    let environment = EnvironmentId::parse(environment_id).ok()?;
    Some(Scope::new(tenant, environment))
}

/// Build a cacheable `200`/`304` response: a strong `ETag` over the body, an
/// explicit `Cache-Control: public, max-age=<secs>`, and `304 Not Modified` when
/// the request's `If-None-Match` matches the `ETag`.
pub(crate) fn cacheable_response(
    headers: &HeaderMap,
    content_type: &str,
    max_age: u64,
    body: &str,
) -> Response {
    let etag = strong_etag(body.as_bytes());
    let cache_control = format!("public, max-age={max_age}");

    // Conditional request: an exact ETag match is a 304 with no body. The header
    // may carry several comma-separated validators; a match on any is sufficient.
    let inm = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok());
    if inm.is_some_and(|value| if_none_match_matches(value, &etag)) {
        return (
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag), (header::CACHE_CONTROL, cache_control)],
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (header::CACHE_CONTROL, cache_control),
            (header::ETAG, etag),
        ],
        body.to_owned(),
    )
        .into_response()
}

/// Whether an `If-None-Match` header value matches `etag`. Handles the `*`
/// wildcard and a comma-separated list of validators.
fn if_none_match_matches(header_value: &str, etag: &str) -> bool {
    let trimmed = header_value.trim();
    if trimmed == "*" {
        return true;
    }
    trimmed.split(',').any(|candidate| {
        let candidate = candidate.trim();
        // Compare ignoring a weak-validator prefix on the request side.
        candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

/// A strong `ETag` over `body`: a quoted hex SHA-256.
fn strong_etag(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut hex = String::with_capacity(digest.len() * 2 + 2);
    hex.push('"');
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex.push('"');
    hex
}

/// A uniform `404` for an unknown or malformed issuer scope.
pub(crate) fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_none_match_handles_wildcard_and_lists() {
        assert!(if_none_match_matches("*", "\"abc\""));
        assert!(if_none_match_matches("\"abc\"", "\"abc\""));
        assert!(if_none_match_matches("\"x\", \"abc\"", "\"abc\""));
        assert!(if_none_match_matches("W/\"abc\"", "\"abc\""));
        assert!(!if_none_match_matches("\"other\"", "\"abc\""));
    }

    #[test]
    fn strong_etag_is_stable_and_quoted() {
        let a = strong_etag(b"body");
        let b = strong_etag(b"body");
        assert_eq!(a, b);
        assert!(a.starts_with('"') && a.ends_with('"'));
        assert_ne!(a, strong_etag(b"other"));
    }
}
