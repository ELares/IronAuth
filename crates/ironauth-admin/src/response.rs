// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building JSON responses whose body bytes are fixed, so an idempotent replay
//! returns exactly what the original request returned.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// A JSON response with an explicit status and a pre-serialized body. The body
/// is stored verbatim for idempotent replay, so it must be built once and reused
/// for both the original response and its stored copy.
#[must_use]
pub fn json(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// A `204 No Content` response, for a successful idempotent delete.
#[must_use]
pub fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// A newline-delimited JSON (`application/x-ndjson`) response with a pre-built
/// body: one JSON record per line, the format the full identity export (issue #58)
/// serves and the streaming bulk import consumes. An empty body (no records) is a
/// valid `200`.
#[must_use]
pub fn ndjson(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(body.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
