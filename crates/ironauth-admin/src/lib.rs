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
mod bans;
mod config;
mod dcr;
mod environments;
mod error;
mod export;
mod hash;
mod idempotency;
mod input;
mod invitations;
mod keys;
mod migration;
mod migration_runs;
mod migration_status;
mod openapi;
mod operators;
mod organizations;
mod pagination;
mod password_hashing;
mod promotion;
mod provision;
mod ratelimit;
mod resource_types;
mod response;
mod sessions;
mod state;
mod tenants;
mod users;
mod views;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::Response;
use axum::routing::{get, post, put};

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
// This is a single flat route-registration list, one `.route(...)` per endpoint;
// it grows by one line per endpoint and reads top-to-bottom as the URL map. There
// is no logic to extract, so the length lint is not meaningful here.
#[allow(clippy::too_many_lines)]
pub fn management_router(state: AdminState) -> Router {
    Router::new()
        // The operator plane: the root of the four-level resource model (issue
        // #41), a documented read surface above tenants.
        .route("/v1/operators", get(operators::list_operators))
        .route("/v1/operators/{operator_id}", get(operators::get_operator))
        // The resource-type classification catalog (issue #41): machine-readable
        // promotable/runtime/environment-identity metadata the snapshot and
        // promotion engines consume.
        .route(
            "/v1/resource-types",
            get(resource_types::list_resource_types),
        )
        .route(
            "/v1/tenants",
            post(tenants::create_tenant).get(tenants::list_tenants),
        )
        .route(
            "/v1/tenants/{tenant_id}",
            get(tenants::get_tenant).delete(tenants::delete_tenant),
        )
        // Tenant lifecycle transitions (issue #46): reversible suspend/resume as
        // documented operator-plane POSTs. Static suffixes, so they are matched
        // before the parameterized environments/keys routes below.
        .route(
            "/v1/tenants/{tenant_id}/suspend",
            post(tenants::suspend_tenant),
        )
        .route(
            "/v1/tenants/{tenant_id}/resume",
            post(tenants::resume_tenant),
        )
        // Restore a soft-deleted (offboarded) tenant inside its retention window
        // (issue #46). A static suffix, matched before the parameterized routes.
        .route(
            "/v1/tenants/{tenant_id}/restore",
            post(tenants::restore_tenant),
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
        // Canonical secret-free config snapshot export (issue #43): the read half
        // of the config-promotion flagship. A static suffix, matched before the
        // parameterized keys/organizations routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/config/snapshot",
            get(config::export_config_snapshot),
        )
        // Full identity export (issue #58): the exit-friendliness covenant. A static
        // suffix, matched before the parameterized keys/organizations routes. Streams
        // every identity as the line-delimited import format, permission-gated and
        // audited.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/export",
            get(export::export_identities),
        )
        // Outbound lazy-migration credential verification (issue #58): the mirror of
        // the inbound migration hook, so a successor system can migrate away. A static
        // suffix; disabled by default and gated by an environment-scoped shared token
        // (never a management key), so it does not take the management Principal.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/verify-credential",
            post(migration::verify_credential),
        )
        // Inbound lazy-migration progress (issue #56): the queryable JSON view of how far
        // an environment's lazy migration has come, plus this node's circuit-breaker
        // state. Environment-scoped read (operator plane or the environment's own key). A
        // static suffix, matched before the parameterized keys/organizations routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/progress",
            get(migration_status::get_migration_progress),
        )
        // The in-admin Argon2id tuning probe (issue #62): a host-measured parameter
        // recommendation, the same probe the CLI wraps. Environment-scoped, read-only.
        // Static `password-hashing` suffix, matched before the parameterized routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/password-hashing/probe",
            post(password_hashing::probe_password_hashing),
        )
        // The migration state-machine operator view (issue #59): list a scope's runs,
        // read one run's state with its per-state counts and LIVE invariant evaluations,
        // and page the records violating an invariant. Environment-scoped reads. Static
        // `migration-runs` suffix, matched before the parameterized keys/organizations routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs",
            get(migration_runs::list_migration_runs),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}",
            get(migration_runs::get_migration_run),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}/violations",
            get(migration_runs::list_migration_run_violations),
        )
        // Server-side config promotion (issue #44): the write half of the flagship.
        // A dry-run PLAN and a transactional APPLY into the target environment.
        // Static suffixes, matched before the parameterized keys/organizations routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/plan",
            post(promotion::plan_config_promotion),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/apply",
            post(promotion::apply_config_promotion),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            get(keys::get_key).delete(keys::delete_key),
        )
        // Organizations: the fourth level of the resource model (issue #41), a
        // minimal per-environment shell M10 extends with membership.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
            post(organizations::create_organization).get(organizations::list_organizations),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
            get(organizations::get_organization).delete(organizations::delete_organization),
        )
        // Dynamic Client Registration abuse controls (issue #31).
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
            post(dcr::create_dcr_policy).get(dcr::list_dcr_policies),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/initial-access-tokens",
            post(dcr::create_initial_access_token),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}",
            get(dcr::get_dcr_client),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/verify",
            post(dcr::verify_dcr_client),
        )
        // Session and refresh-family fleet operations (issue #32). The static
        // `/sessions/revoke` (the bulk surface) and the parameterized
        // `/sessions/{session_id}` are siblings; the router matches the static segment
        // first, so a bulk revoke can never be read as a session id.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions",
            get(sessions::list_sessions),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions/revoke",
            post(sessions::bulk_revoke_sessions),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}",
            get(sessions::get_session),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}/revoke",
            post(sessions::revoke_session),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/sessions/revoke",
            post(sessions::revoke_user_sessions),
        )
        // Admin user CRUD, lifecycle, and external ids (issue #52). The static
        // suffixes (`/state`, `/external-id`) are siblings of the parameterized
        // `/users/{user_id}`; the router matches the static segments first.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users",
            post(users::create_user).get(users::list_users),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
            get(users::get_user)
                .patch(users::update_user)
                .delete(users::delete_user),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/state",
            post(users::set_user_state),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
            put(users::link_user_external_id).delete(users::unlink_user_external_id),
        )
        // Admin user-invitation CRUD (issue #60): create (provisioning a
        // pending_verification user and a single-use, expiring, unguessable token),
        // list, get, and the static-suffix revoke / resend POSTs (siblings of the
        // parameterized `/invitations/{invitation_id}`; the router matches the static
        // segments first). The token-authenticated ACCEPT is an invitee action on the
        // public data plane (ironauth-oidc), not here.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
            post(invitations::create_invitation).get(invitations::list_invitations),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}",
            get(invitations::get_invitation),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/revoke",
            post(invitations::revoke_invitation),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/resend",
            post(invitations::resend_invitation),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families",
            get(sessions::list_refresh_families),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families/{family_id}",
            get(sessions::get_refresh_family),
        )
        // Credential-abuse ban management (issue #64). The static `/lift` suffix is
        // registered before it could be read as a parameterized sibling.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans/lift",
            post(bans::lift_ban),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans",
            post(bans::create_ban).get(bans::list_bans),
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
