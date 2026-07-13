// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-issuer JWKS HTTP surface.
//!
//! Serving JWKS with operational discipline is where OSS providers are ad hoc.
//! Every JWKS response here carries an explicit `Cache-Control` (a `max-age`
//! bounded to the 300-to-900-second range) and a strong `ETag`, and a conditional
//! request (`If-None-Match`) that matches returns `304 Not Modified` with no body
//! (the shared [`crate::wellknown`] discipline). That is what lets a relying party
//! cache the key set, refetch cheaply on a `kid` miss (the documented RP
//! contract), and never hammer the endpoint.
//!
//! The route is per issuer, since every environment has its own issuer and key
//! set:
//!
//! - `GET /t/{tenant_id}/e/{environment_id}/jwks.json`
//!
//! It resolves the environment through the [`IssuerRegistry`]; an unknown or
//! malformed scope is a `404`.
//!
//! # Relationship to discovery and to key loading (issue #194)
//!
//! Discovery (both well-known forms) is served independently by
//! [`crate::discovery`], which needs only live config, the issuer string, and the
//! per-environment algorithm policy: NOT the loaded signing keys. This JWKS
//! surface DOES need the loaded keys, so it is mounted on the live data plane only
//! once per-environment key loading lands (issue #194). The [`IssuerRegistry`]
//! that backs it is built at composition time from the persisted keys and
//! policies.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ironauth_env::Env;

use crate::issuer::IssuerRegistry;
use crate::wellknown::{cacheable_response, not_found, parse_scope};

/// The media type for a JWK Set (RFC 7517).
const JWK_SET_MEDIA_TYPE: &str = "application/jwk-set+json";

/// The shared state for the JWKS surface: the registry and the clock seam.
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

/// Build the per-issuer JWKS router.
///
/// Mount it on the PUBLIC data plane alongside the protocol and discovery routers
/// once per-environment signing keys are loaded (issue #194).
pub fn issuer_router(state: IssuerState) -> Router {
    Router::new()
        .route("/t/{tenant_id}/e/{environment_id}/jwks.json", get(jwks))
        .with_state(state)
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

/// A `500` for an internal fault (a malformed stored key).
fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "server error\n").into_response()
}
