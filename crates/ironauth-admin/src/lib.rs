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
mod brand_assets;
mod client_admin_grants;
mod config;
mod connectors;
mod consents;
mod dcr;
mod diagnostics;
mod environments;
mod error;
mod export;
mod flow_versions;
mod hash;
mod idempotency;
mod input;
mod invitations;
mod keys;
mod locales;
mod mds3_health;
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
mod recovery_approvals;
mod resource_types;
mod response;
mod sessions;
mod signup_forms;
mod signup_quarantine;
mod state;
mod sudo;
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
pub use state::{AdminOidcBridge, AdminState, StateError};

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
        // The FIDO MDS3 metadata cache health (issue #66 PR B): the cached BLOB
        // sequence number, verify time, nextUpdate, and a fresh/stale verdict.
        // Environment-scoped, read-only. Static `webauthn/mds3/health` suffix.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webauthn/mds3/health",
            get(mds3_health::get_mds3_health),
        )
        // The client authentication diagnostics read (issue #91, M9 flow inspector):
        // the rich, structured record of WHY a client authentication failed, kept off
        // the wire while the token endpoint's response stays the opaque invalid_client.
        // Environment scoped, read only, filterable by client and time. Static
        // `diagnostics/client-auth` suffix, matched before the parameterized routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/client-auth",
            get(diagnostics::get_client_auth_diagnostics),
        )
        // The policy decision traces read (issue #91, M9 flow inspector): the step up, risk,
        // and claim mapping decisions recorded off the request path. Environment scoped, read
        // only, filterable by policy and subject and time. Static suffix, matched before the
        // parameterized routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/policy-traces",
            get(diagnostics::get_policy_traces),
        )
        // The operational warnings read (issue #91, M9 flow inspector): the connector health
        // and token size (claim bloat) warnings, COMPUTED LIVE from the existing seams.
        // Environment scoped, read only. Static suffix, matched before the parameterized routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/warnings",
            get(diagnostics::get_diagnostics_warnings),
        )
        // The flow inspector DRY REPLAY (issue #91, PR4): a zero side effect policy dry run
        // over a supplied context. Despite the POST verb it is READ ONLY (it writes no row),
        // and its static `diagnostics/flow/dry-run` suffix is registered before the
        // parameterized `diagnostics/flow/{flow_id}` observe route so the literal wins.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/dry-run",
            post(diagnostics::post_flow_dry_run),
        )
        // The flow inspector OBSERVE read (issue #91, PR4): the read only projection of an
        // existing flow's current position, plan, redacted context, node render, and recorded
        // policy traces. Environment scoped, IDOR safe; never calls the mutating flow engine.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/{flow_id}",
            get(diagnostics::get_flow_observation),
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
        // Declarative federation connectors (issue #75): CRUD plus a capability-matrix
        // read endpoint. The static `.../capabilities` suffix is a sibling of the
        // parameterized `.../connectors/{connector_id}`; the router matches the static
        // segment first.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
            post(connectors::create_connector).get(connectors::list_connectors),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/capabilities",
            get(connectors::get_connector_capabilities),
        )
        // The per-connector health-diagnostics read (issue #76): another static suffix sibling
        // of the parameterized `.../{connector_id}`, matched before it.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/health",
            get(connectors::get_connector_health),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
            get(connectors::get_connector)
                .put(connectors::update_connector)
                .delete(connectors::delete_connector),
        )
        // Per-environment locale bundles (issue #86, PR 2): set (create or overwrite), get, and
        // delete a bundle keyed on its BCP47 tag.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
            put(locales::set_locale)
                .get(locales::get_locale)
                .delete(locales::delete_locale),
        )
        // Per-environment, per-client signup forms as data (issue #87): set (fail-fast validated
        // against the active trait schema), get, and delete a form keyed on the authorize client
        // id.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
            put(signup_forms::set_signup_form)
                .get(signup_forms::get_signup_form)
                .delete(signup_forms::delete_signup_form),
        )
        // Per-environment custom-journey versions (issue #92, PR 5): create a new immutable version
        // (POST, append-only, Idempotency-Key required) and list a journey's versions.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions",
            post(flow_versions::create_flow_version).get(flow_versions::list_flow_versions),
        )
        // Get one version of a custom journey by its version number.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions/{version}",
            get(flow_versions::get_flow_version),
        )
        // Pin a version of a custom journey as the active version a fresh custom flow runs against.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions/{version}/pin",
            post(flow_versions::pin_flow_version),
        )
        // Per-environment, per-client admin consent pre-authorizations (issue #88, PR 4): set
        // (create or overwrite), get, and delete (revoke) the scope an admin pre-authorized for a
        // third-party client, keyed on the authorize client id.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
            put(client_admin_grants::set_client_admin_consent)
                .get(client_admin_grants::get_client_admin_consent)
                .delete(client_admin_grants::delete_client_admin_consent),
        )
        // Per-environment brand assets (issue #86, PR 3): upload (magic-byte sniffed, size capped,
        // sudo gated) or delete a brand's logo / favicon. The `/logo` and `/favicon` static
        // suffixes are siblings of the parameterized `{slug}`; the router matches them as fixed
        // segments.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/logo",
            put(brand_assets::set_brand_logo).delete(brand_assets::delete_brand_logo),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/favicon",
            put(brand_assets::set_brand_favicon).delete(brand_assets::delete_brand_favicon),
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
        // User consent (connected apps) management (issue #88): list a user's
        // remembered consents and revoke one. The revoke cascades to the (subject,
        // client) refresh families in the store transaction and is sudo-gated. Keyed by
        // SUBJECT, distinct from the client-keyed admin consent pre-authorization
        // surface (`applications/{client_id}/admin-consent`).
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/consents",
            get(consents::list_user_consents),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/consents/{client_id}/revoke",
            post(consents::revoke_user_consent),
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
        // Signup fraud review queue (issue #82, PR 2). The static action suffixes
        // (/approve, /reject, /extend) are registered before their parameterized sibling so
        // the router matches them first. Every handler 404s until the signup-quarantine
        // feature is enabled AND acknowledged.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine",
            get(signup_quarantine::list_signup_quarantines),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/approve",
            post(signup_quarantine::approve_signup_quarantine),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/reject",
            post(signup_quarantine::reject_signup_quarantine),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/extend",
            post(signup_quarantine::extend_signup_quarantine),
        )
        // Admin-approved recovery review queue (issue #82, PR 3). The static action suffixes
        // (/approve, /reject) are registered on their parameterized sibling. Every handler
        // 404s until the advanced-recovery feature is enabled AND acknowledged.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals",
            get(recovery_approvals::list_recovery_approvals),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/approve",
            post(recovery_approvals::approve_recovery_approval),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/reject",
            post(recovery_approvals::reject_recovery_approval),
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
        // Admin session privilege separation (sudo mode, issue #73): the
        // re-authentication endpoint that records a fresh elevation, opening the
        // freshness window admin mutations in this environment require. A uniform
        // not-found when the sudo_mode flag is off (fully inert).
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/admin/sudo/elevate",
            post(sudo::elevate_sudo),
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
