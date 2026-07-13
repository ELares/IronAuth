// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-issuer JWKS and discovery HTTP surface.
//!
//! Serving JWKS with operational discipline is where OSS providers are ad hoc.
//! Every JWKS response here carries an explicit `Cache-Control` (a `max-age`
//! bounded to the 300-to-900-second range) and a strong `ETag`, and a conditional
//! request (`If-None-Match`) that matches returns `304 Not Modified` with no body.
//! That is what lets a relying party cache the key set, refetch cheaply on a
//! `kid` miss (the documented RP contract), and never hammer the endpoint.
//!
//! The routes are per issuer, since every environment has its own issuer and key
//! set:
//!
//! - `GET /t/{tenant_id}/e/{environment_id}/.well-known/openid-configuration`
//! - `GET /t/{tenant_id}/e/{environment_id}/jwks.json`
//!
//! Both resolve the environment through the [`IssuerRegistry`]; an unknown or
//! malformed scope is a `404`, with no oracle for which of the two it was.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ironauth_env::Env;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use sha2::{Digest, Sha256};

use crate::issuer::IssuerRegistry;

/// The media type for a JWK Set (RFC 7517).
const JWK_SET_MEDIA_TYPE: &str = "application/jwk-set+json";
/// The media type for the discovery document.
const DISCOVERY_MEDIA_TYPE: &str = "application/json";

/// The shared state for the issuer surface: the registry and the clock seam.
#[derive(Clone)]
pub struct IssuerState {
    registry: Arc<IssuerRegistry>,
    env: Env,
}

impl IssuerState {
    /// Build the issuer state from a registry and the environment seam.
    #[must_use]
    pub fn new(registry: Arc<IssuerRegistry>, env: Env) -> Self {
        Self { registry, env }
    }

    /// The issuer registry.
    #[must_use]
    pub fn registry(&self) -> &IssuerRegistry {
        &self.registry
    }
}

impl std::fmt::Debug for IssuerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerState").finish_non_exhaustive()
    }
}

/// Build the per-issuer JWKS and discovery router.
///
/// Mount it on the PUBLIC data plane alongside the protocol router.
pub fn issuer_router(state: IssuerState) -> Router {
    Router::new()
        .route(
            "/t/{tenant_id}/e/{environment_id}/.well-known/openid-configuration",
            get(discovery),
        )
        .route("/t/{tenant_id}/e/{environment_id}/jwks.json", get(jwks))
        .with_state(state)
}

/// Resolve the `(tenant, environment)` path parameters to a [`Scope`], or `None`
/// if either does not parse (a uniform not-found for the caller).
fn parse_scope(tenant_id: &str, environment_id: &str) -> Option<Scope> {
    let tenant = TenantId::parse(tenant_id).ok()?;
    let environment = EnvironmentId::parse(environment_id).ok()?;
    Some(Scope::new(tenant, environment))
}

/// `GET .../jwks.json`: the environment's published JWKS, with explicit
/// `Cache-Control`, a strong `ETag`, and `304` on a matching `If-None-Match`.
async fn jwks(
    State(state): State<IssuerState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let now = state.env.clock().now_utc();
    let body = match state.registry.jwks_json(&scope, now) {
        Some(Ok(body)) => body,
        // Unregistered environment: a uniform not-found.
        None => return not_found(),
        // A malformed stored key is an internal fault, not a caller error.
        Some(Err(_)) => return server_error(),
    };
    cacheable_response(
        &headers,
        JWK_SET_MEDIA_TYPE,
        state.registry.cache().max_age_secs(),
        &body,
    )
}

/// `GET .../.well-known/openid-configuration`: the environment's discovery
/// document, with the same caching discipline as the JWKS.
async fn discovery(
    State(state): State<IssuerState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let now = state.env.clock().now_utc();
    let Some(body) = state.registry.discovery_json(&scope, now) else {
        return not_found();
    };
    cacheable_response(
        &headers,
        DISCOVERY_MEDIA_TYPE,
        state.registry.cache().max_age_secs(),
        &body,
    )
}

/// Build a cacheable `200`/`304` response: a strong `ETag` over the body, an
/// explicit `Cache-Control: public, max-age=<secs>`, and `304 Not Modified` when
/// the request's `If-None-Match` matches the `ETag`.
fn cacheable_response(
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
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

/// A `500` for an internal fault (a malformed stored key).
fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "server error\n").into_response()
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
