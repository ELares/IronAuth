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
//! surface DOES need the loaded keys, and is now mounted on the live data plane
//! (issue #194). The [`IssuerRegistry`] that backs it is store-backed and LAZY: it
//! reads a scope's keys through the RLS-forced [`ironauth_store::Store::scoped`] on
//! the first request for that issuer and caches the result, so an unprovisioned or
//! cross-tenant environment loads zero rows and yields a uniform 404.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ironauth_env::Env;

use ironauth_jose::{JwkSet, SigningKey};

use crate::issuer::IssuerRegistry;
use crate::session_tokenizer;
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
        // ONE TEMPLATE'S OWN key set (issue #119). Mounted here rather than beside the tokenize
        // endpoint because it is the same kind of document with the same caching discipline,
        // and because a reader looking for "which JWKS does this deployment publish" must find
        // both in one place.
        .route(
            "/t/{tenant_id}/e/{environment_id}/session-tokens/{template}/jwks.json",
            get(template_jwks),
        )
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
    let body = match state.registry.jwks_json(&scope, now).await {
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

/// `GET /t/{tenant}/e/{environment}/session-tokens/{template}/jwks.json`: one template's OWN
/// published key set.
///
/// This is the URL criterion 1 rests on: a verifier fetches it, caches it, and checks a
/// tokenized session JWT against it with NO database call and no IronAuth involvement.
///
/// It is a SEPARATE document from the environment's `jwks.json`, and a template's key never
/// appears in that one. See migration 0173 for why the separation is structural rather than a
/// filter, and `id::SessionTokenKeyKind` for why the identifiers cannot be confused either.
async fn template_jwks(
    State(state): State<IssuerState>,
    Path((tenant_id, environment_id, template)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    let Some(store) = state.registry().store() else {
        return not_found();
    };
    let now_micros = crate::util::epoch_micros(state.env.clock().now_utc());
    // The template must EXIST for its JWKS to answer. Without this check a misspelled name
    // would return an empty key set with a 200, which a verifier caches as "this issuer
    // publishes no keys" and then rejects every token against for the whole cache window --
    // an outage that reads as a signing problem rather than as a typo.
    match store
        .scoped(scope)
        .session_token_templates()
        .get(&template)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(),
        Err(_) => return server_error(),
    }
    let Ok(keys) = store
        .scoped(scope)
        .session_token_templates()
        .published_keys(&template, now_micros)
        .await
    else {
        return server_error();
    };
    let loaded: Result<Vec<SigningKey>, session_tokenizer::MintError> = keys
        .iter()
        .map(session_tokenizer::load_template_key)
        .collect();
    let Ok(loaded) = loaded else {
        return server_error();
    };
    let Ok(set) = JwkSet::from_signing_keys(loaded.iter()) else {
        return server_error();
    };
    let Ok(body) = set.to_json() else {
        return server_error();
    };
    cacheable_response(
        &headers,
        JWK_SET_MEDIA_TYPE,
        state.registry().cache().max_age_secs(),
        &body,
    )
}

/// A `500` for an internal fault (a malformed stored key).
fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "server error\n").into_response()
}
