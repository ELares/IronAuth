// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rate-limit response headers on every response.
//!
//! This wires the HEADER CONTRACT to a PLACEHOLDER limiter. The real layered,
//! per-tenant limiter is later ops work; fixing the header shape now means
//! clients and generated SDKs can depend on it from the first endpoint, and the
//! limiter can be swapped in behind these headers without a wire change. Every
//! response, success or error, carries the structured `RateLimit` and
//! `RateLimit-Policy` fields (draft-ietf-httpapi-ratelimit-headers) plus the
//! legacy `X-RateLimit-*` triplet for older clients.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// The placeholder budget. Fixed values until the real limiter lands; the point
/// here is the header shape, not the numbers.
const LIMIT: u64 = 1000;
/// Remaining requests in the current window (placeholder).
const REMAINING: u64 = 999;
/// Seconds until the window resets (placeholder).
const RESET_SECONDS: u64 = 60;

/// Middleware that stamps the rate-limit headers on every response.
pub async fn rate_limit_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    stamp(response.headers_mut());
    response
}

/// Insert the structured and legacy rate-limit headers.
fn stamp(headers: &mut HeaderMap) {
    // Structured fields (draft-ietf-httpapi-ratelimit-headers).
    set(
        headers,
        HeaderName::from_static("ratelimit"),
        &format!("limit={LIMIT}, remaining={REMAINING}, reset={RESET_SECONDS}"),
    );
    set(
        headers,
        HeaderName::from_static("ratelimit-policy"),
        &format!("{LIMIT};w={RESET_SECONDS}"),
    );
    // Legacy X-RateLimit-* for clients that predate the draft.
    set(
        headers,
        HeaderName::from_static("x-ratelimit-limit"),
        &LIMIT.to_string(),
    );
    set(
        headers,
        HeaderName::from_static("x-ratelimit-remaining"),
        &REMAINING.to_string(),
    );
    set(
        headers,
        HeaderName::from_static("x-ratelimit-reset"),
        &RESET_SECONDS.to_string(),
    );
}

/// Insert a header, silently skipping a value that is not a valid header value
/// (the values here are always valid ASCII digits and tokens).
fn set(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamped() -> HeaderMap {
        let mut headers = HeaderMap::new();
        stamp(&mut headers);
        headers
    }

    fn value(headers: &HeaderMap, name: &str) -> String {
        headers
            .get(name)
            .unwrap_or_else(|| panic!("{name} missing"))
            .to_str()
            .expect("header value is not valid UTF-8")
            .to_owned()
    }

    /// THE SECOND RENDERER OF ONE WIRE CONTRACT, pinned to the same revision as the first.
    ///
    /// `ironauth-quota`'s `RateLimitSnapshot::headers` renders these fields for the data
    /// plane and this module renders them independently for the management plane. Nothing
    /// tied the two together, so this one could drift to the later policy-name grammar
    /// (`"name";r=999;t=60`) while the other kept the dictionary form, and a client talking to
    /// both planes would need two parsers for one header name.
    ///
    /// The revision is pinned in `ironauth_quota::RateLimitSnapshot::headers`'s doc comment
    /// (issue #1268). This is the assertion that keeps this copy on it.
    #[test]
    fn the_management_plane_renders_the_same_pinned_draft_revision() {
        let headers = stamped();

        assert_eq!(
            value(&headers, "ratelimit"),
            format!("limit={LIMIT}, remaining={REMAINING}, reset={RESET_SECONDS}"),
            "dictionary grammar, not the later `\"name\";r=..;t=..` structured field"
        );
        assert_eq!(
            value(&headers, "ratelimit-policy"),
            format!("{LIMIT};w={RESET_SECONDS}"),
            "dictionary grammar, not the later `\"name\";q=..;w=..` structured field"
        );
    }

    /// `x-ratelimit-reset` is DELTA-SECONDS here too (issue #1268).
    ///
    /// The legacy header is unspecified and much of the ecosystem sends an epoch. If this
    /// renderer followed that convention while the data plane sent a delta, one deployment
    /// would answer the same question two ways depending on which plane was asked.
    ///
    /// Asserted as an equality against the structured field's own `reset=` parameter rather
    /// than against the constant, so it keeps meaning the same thing if the placeholder
    /// budget changes.
    #[test]
    fn the_management_plane_reset_is_a_delta_and_agrees_with_the_structured_field() {
        let headers = stamped();
        let structured = value(&headers, "ratelimit");
        let legacy = value(&headers, "x-ratelimit-reset");

        let structured_reset = structured
            .split(", ")
            .find_map(|part| part.strip_prefix("reset="))
            .expect("the structured field must carry a reset= parameter");

        assert_eq!(
            structured_reset, legacy,
            "the two families must carry the same number in the same units: \
             got structured {structured} against legacy {legacy}"
        );
        assert_eq!(
            legacy,
            RESET_SECONDS.to_string(),
            "a delta, not an epoch: an epoch here reads as a 50-year sleep to a client \
             that expects a delta"
        );
    }
}
