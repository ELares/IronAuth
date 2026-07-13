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
