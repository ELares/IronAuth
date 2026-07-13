// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth OpenAPI-first management API (issue #11).
//!
//! This crate establishes the management API CONTRACT and DISCIPLINE once, so the
//! later milestones (the admin SPA, CLI, Terraform, generated SDKs, the MCP
//! server) inherit it as thin clients rather than relitigating it. It mounts on
//! the MANAGEMENT plane (never the public data plane) and is served on the
//! management port.
//!
//! The contract, all enforced from the first endpoint:
//!
//! - **OpenAPI 3.1 is the source of truth.** The spec is derived from the
//!   `#[utoipa::path]` annotations on the handlers ([`management_openapi`]); the
//!   same handlers are wired to the same paths by [`management_router`], a
//!   contract test pins the documented (method, path) set, and CI diffs the
//!   generated spec against the committed `docs/openapi/management.json`
//!   (`scripts/openapi-check.sh`).
//! - **Cursor pagination on every list endpoint.** Opaque cursors over a stable
//!   `(created_at, id)` key, a config-capped page size, and no offset pagination
//!   anywhere.
//! - **Idempotency-Key on every POST.** Keys are scoped to the acting credential
//!   and stored with the original response in the same transaction as the
//!   mutation, so a replay returns the original result and writes no second audit
//!   row.
//! - **RateLimit headers on every response.** The structured `RateLimit` fields
//!   plus the legacy `X-RateLimit-*` triplet, wired to a placeholder limiter so
//!   the header contract is fixed before the real limiter lands.
//! - **Environment-scoped credentials, two wrong-scope behaviors.** Management
//!   keys are bound to `(tenant, environment)`; a cross-scope resource probe is a
//!   uniform not-found (the anti-oracle), while a credential against the wrong
//!   environment or plane fails LOUD, naming expected and actual scope.
//! - **Audit on every mutation.** Every management mutation writes its audit row
//!   in the same transaction, through the store's audited-write primitive.
//!
//! In production the management repositories connect as the control-plane
//! database role (`ironauth_control`), a distinct credential class from the
//! data-plane role, selected from `admin.control_database_url`. When that knob is
//! unset the API fails closed in production and, only in `dev_mode`, falls back to
//! `database.url` with the role separation and the `management_credentials`
//! FORCE-RLS backstop not enforced (a startup warning says so). See
//! `ironauth_store::Store::management` and `docs/adr/0005-management-api.md`.

mod auth;
mod environments;
mod error;
mod hash;
mod idempotency;
mod input;
mod keys;
mod openapi;
mod pagination;
mod ratelimit;
mod response;
mod state;
mod tenants;
mod views;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::Response;
use axum::routing::{get, post};

pub use auth::Principal;
pub use error::{ApiError, ErrorBody};
pub use openapi::{management_openapi, openapi_json};
pub use pagination::ListQuery;
pub use state::{AdminState, StateError};

/// Build the management API router.
///
/// Mount the returned router on the management plane (for example by merging it
/// into `ironauth_server`'s management router). The `state` carries a
/// control-plane store, which in production authenticates as `ironauth_control`
/// (a `dev_mode` fallback to `database.url` is possible, with the role separation
/// not enforced). The router serves the resource endpoints plus
/// `GET /openapi.json` (the served spec), and stamps the rate-limit headers on
/// every response.
///
/// Each route path here is the same string as the corresponding handler's
/// `#[utoipa::path]`; the `documented_paths_are_the_expected_set` contract test
/// pins that documented set, so the router and the spec cannot silently diverge.
pub fn management_router(state: AdminState) -> Router {
    Router::new()
        .route(
            "/v1/tenants",
            post(tenants::create_tenant).get(tenants::list_tenants),
        )
        .route(
            "/v1/tenants/{tenant_id}",
            get(tenants::get_tenant).delete(tenants::delete_tenant),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments",
            post(environments::create_environment).get(environments::list_environments),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}",
            get(environments::get_environment).delete(environments::delete_environment),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/keys",
            post(keys::create_key).get(keys::list_keys),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            get(keys::get_key).delete(keys::delete_key),
        )
        .route("/openapi.json", get(serve_openapi))
        .layer(from_fn(ratelimit::rate_limit_headers))
        .with_state(state)
}

/// `GET /openapi.json`: the served OpenAPI 3.1 document, byte-identical to the
/// committed `docs/openapi/management.json`. Unauthenticated so tooling can
/// fetch the contract; it still carries the rate-limit headers.
async fn serve_openapi() -> Response {
    response::json(StatusCode::OK, openapi_json())
}
