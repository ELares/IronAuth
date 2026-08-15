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

mod api_keys;
mod auth;
mod authzen;
mod backfill;
mod bans;
mod brand_assets;
mod brands;
mod client_admin_grants;
mod client_scopes;
mod config;
mod connectors;
mod consents;
mod dcr;
mod diagnostics;
mod environments;
mod error;
mod event_feed;
pub mod events;
mod export;
mod flow_versions;
mod hash;
mod idempotency;
mod identifiers;
mod impersonation;
mod imports;
mod input;
mod invitations;
mod keys;
mod locales;
pub mod usage;

/// SIEM log stream delivery (issue #110): the sink interface, the HTTP sink, and the
/// shipper that reads audit rows forward from each stream's cursor. Public because the
/// binary wires the shipper and a deployment may add its own sink.
pub mod log_shipper;

mod log_streams;
mod mds3_health;
mod memberships;
mod migration;
mod migration_runs;
mod migration_status;
pub mod offboarding_worker;
mod openapi;
mod operators;
mod org_context;
mod org_effective_roles;
mod org_group_members;
mod org_groups;
mod org_role_assignments;
mod org_role_permissions;
mod org_roles;
mod organizations;
mod pagination;
mod password_hashing;
mod permissions;
mod personal_access_tokens;
mod postures;
mod project_grants;
mod promotion;
mod provision;
mod queues;
mod ratelimit;
mod recovery_approvals;
mod resource_servers;
mod resource_types;
mod response;
mod routing_rules;
mod secrets;
mod service_account_keys;
mod sessions;
mod signing_algorithm;
mod signing_interop;
mod signup_forms;
mod signup_quarantine;
/// AWS SigV4 signing for the S3 log sink (issue #110).
pub mod sigv4;
mod sms_otp;
mod state;
mod step_up_policies;
mod sudo;
mod tenants;
pub mod trait_migration_worker;
mod trait_schemas;
mod users;
mod variables;
mod views;
pub mod webhook_delivery;
mod webhook_endpoints;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::Response;
use axum::routing::{delete, get, post, put};

pub use auth::{ManagementGrants, ManagementPermission, ManagementPersona, Principal};
pub use backfill::{BackfillError, BackfillReport, backfill_signing_algorithms};
pub use error::{ApiError, ErrorBody};
/// The permission-slug grammar (issue #98), exported because its PARITY ORACLE lives
/// in an integration test and an integration test is an external consumer of this
/// crate.
///
/// The grammar has two enforcement points that must never drift: migration 0091's
/// `permissions_slug_valid` CHECK and this function. The only thing in the tree that
/// would catch a drift is a test able to see BOTH, and a test able to see this one
/// has to reach it through the crate's public surface. Its three siblings in
/// `input` stay private because nothing outside the crate needs to pin them.
pub use input::require_permission_slug;
pub use openapi::{management_openapi, openapi_json};
pub use pagination::ListQuery;
pub use provision::{DayOneSigningKeys, ProvisionError};
pub use state::{AdminOidcBridge, AdminState, StateError, bootstrap_operator_id};

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
        // The compatibility-wizard interop table (issue #93): an operator-plane read of
        // the per-verifier signing-algorithm recommendations. Unscoped and read only.
        .route(
            "/v1/interop/signing-recommendations",
            get(signing_algorithm::get_signing_recommendations),
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
        // The TERMINAL offboarding stage (issues #46, #49): crypto-shred a grace tenant
        // whose window has elapsed. `hard_delete` shipped with no caller, so a
        // soft-deleted tenant stayed in grace forever and its sealed data was never
        // erased. Operator-triggered rather than automatic: irreversible destruction is a
        // deliberate act, and nothing here fires on a timer.
        .route(
            "/v1/tenants/{tenant_id}/purge",
            post(tenants::purge_tenant),
        )
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
        // suffix; disabled by default and gated by the ADDRESSED ENVIRONMENT's own
        // sealed shared token (issue #250, never a management key), so it does not take
        // the management Principal. Every refusal is one uniform not-found.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/verify-credential",
            post(migration::verify_credential),
        )
        // The management half of that credential (issue #250): read whether this
        // environment has outbound verification armed (metadata only, never the token),
        // enable or rotate it, and disable it. Ordinary management endpoints on the
        // environment prefix, taking the management Principal. A static suffix, matched
        // before the parameterized keys/organizations routes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/outbound-verification",
            get(migration::get_outbound_verification)
                .put(migration::set_outbound_verification)
                .delete(migration::delete_outbound_verification),
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
        // The risk posture reads (issue #79). `credentials_flagged_for_review`,
        // `latest_decision` and `get_decision` all had zero production callers, so the
        // "your credentials are flagged for review" the disavowal page promises a user was
        // unreviewable: nothing could find the accounts a user had reported. Migration 0054
        // already granted the control role SELECT on both risk tables, so no new grant is
        // needed; only the surface was missing. Both static suffixes sit under
        // `diagnostics/risk/` and neither is parameterized at the same position, so the
        // ordering carries no ranking hazard.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/risk/users/{user_id}",
            get(diagnostics::get_user_risk_posture),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/risk/decisions/{decision_id}",
            get(diagnostics::get_risk_decision),
        )
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
        // The streaming bulk-import JOB (issue #55): the WRITE half of the migration
        // on-ramp. `POST .../imports` creates a run and streams a newline-delimited
        // identity record set into it; `POST .../imports/{run_id}` resumes that run.
        // Progress is NOT served here: it is the migration-run view below, which is the
        // one projection of a run's counters. A static `imports` suffix, matched before
        // the parameterized keys/organizations routes, and its `{run_id}` sits at a
        // position no sibling parameterizes.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/imports",
            post(imports::create_identity_import),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/imports/{run_id}",
            post(imports::resume_identity_import),
        )
        // The migration state-machine operator view (issue #59): list a scope's runs,
        // read one run's state with its per-state counts and LIVE invariant evaluations,
        // and page the records violating an invariant. Environment-scoped reads, plus the
        // ONE write (issue #55): abandoning a run that cannot finish, which is the only
        // exit from a run whose invariants can never be satisfied, because nothing on this
        // plane may rewrite a run's declared ground truth or delete a ledger row. Static
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
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}/abandon",
            post(migration_runs::abandon_migration_run),
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
        // The permission vocabulary (issue #98): the named API capabilities an
        // ENVIRONMENT defines. Deliberately NOT nested under an organization, and no
        // handler takes one: `permissions` carries no `organization_id`, because a
        // permission names an API capability and one string cannot mean different
        // things to two organizations calling the same API (migration 0091). That
        // makes the row-level-security policy the complete fence for the table.
        // Uncapped in number by covenant.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions",
            post(permissions::create_permission).get(permissions::list_permissions),
        )
        // Environment VARIABLE management (issue #235, follow-up to #45). The variable half
        // only: a variable is non-secret by construction, so the control plane manages it with
        // no envelope master key, using the grants 0100 already gave `ironauth_control`. The
        // SECRET half needs a plane and master-key decision and is tracked separately.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/secrets",
            get(secrets::list_secrets),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/secrets/{name}",
            get(secrets::get_secret)
                .put(secrets::set_secret)
                .delete(secrets::delete_secret),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/variables",
            get(variables::list_variables),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/variables/{name}",
            get(variables::get_variable)
                .put(variables::set_variable)
                .delete(variables::delete_variable),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
            get(permissions::get_permission)
                .patch(permissions::update_permission)
                .delete(permissions::delete_permission),
        )
        // The resource-server registry (issue #98): the audience-to-format registry
        // issue #29 shipped, given a management surface for the first time. Like the
        // permission vocabulary this is ENVIRONMENT level and takes no organization:
        // a registered protected API belongs to the environment. Addressed by `rsv_`
        // id, never by audience, because an audience is an absolute URI carrying `:`
        // and `/` and cannot be a path segment. The PATCH writes exactly one column,
        // the permission-claim opt-in; full resource-server CRUD is not this issue's
        // business.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers",
            get(resource_servers::list_resource_servers),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers/{resource_server_id}",
            get(resource_servers::get_resource_server)
                .patch(resource_servers::update_resource_server_permission_claims),
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
        // Organization lifecycle actions (issue #94): disable and re-enable. Static
        // suffixes, matched before the parameterized membership routes below.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/disable",
            post(organizations::disable_organization),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/enable",
            post(organizations::enable_organization),
        )
        // Organization membership (issue #94): the M10 user-to-organization join.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships",
            post(memberships::create_membership).get(memberships::list_memberships),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}",
            delete(memberships::delete_membership),
        )
        // Direct membership role assignments (issue #97): the NON-inheriting
        // assignment surface, and the effective-role view that explains where each
        // of a member's roles came from. Both are static suffixes below an existing
        // parameter, so they add no ambiguity to the item route above; the
        // pair-addressed unassign adds its parameter at a position that has none.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles",
            post(org_role_assignments::assign_org_membership_role)
                .get(org_role_assignments::list_org_membership_roles),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles/{role_id}",
            delete(org_role_assignments::unassign_org_membership_role),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/effective-roles",
            get(org_effective_roles::get_org_membership_effective_roles),
        )
        // Project grants (issue #102): the bound on what a DELEGATED administrator of
        // this organization may assign. Vendor-managed; see the module header for why a
        // confined credential is refused on every one of these.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants",
            post(project_grants::create_project_grant).get(project_grants::list_project_grants),
        )
        // API keys owned by an organization (issue #99, criterion 6). Read-only for now;
        // create, rotate and revoke follow. The store operations behind them all exist and
        // are audited, so this is the HTTP layer catching up rather than new capability.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys",
            axum::routing::get(api_keys::list_organization_api_keys)
                .post(api_keys::create_organization_api_key),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys/{key_id}",
            delete(api_keys::revoke_organization_api_key),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys/{key_id}/rotate",
            post(api_keys::rotate_organization_api_key),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/service-account",
            axum::routing::get(service_account_keys::get_client_service_account),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys",
            axum::routing::get(service_account_keys::list_service_account_api_keys)
                .post(service_account_keys::create_service_account_api_key),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys/{key_id}",
            delete(service_account_keys::revoke_service_account_api_key),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys/{key_id}/rotate",
            post(service_account_keys::rotate_service_account_api_key),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/.well-known/authzen-configuration",
            get(authzen::get_authzen_configuration),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/access/v1/evaluation",
            post(authzen::authzen_evaluation),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/access/v1/evaluations",
            post(authzen::authzen_evaluations),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/impersonation",
            post(impersonation::authorize_user_impersonation),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens",
            axum::routing::get(personal_access_tokens::list_user_personal_access_tokens)
                .post(personal_access_tokens::create_user_personal_access_token),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens/{key_id}",
            delete(personal_access_tokens::revoke_user_personal_access_token),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens/{key_id}/rotate",
            post(personal_access_tokens::rotate_user_personal_access_token),
        )
        // Enterprise inbound routing (issue #96). The store and the data plane have
        // shipped since migration 0059; this is the first time an operator can reach it.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/routing-rules",
            post(routing_rules::create_routing_rule).get(routing_rules::list_routing_rules),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/routing-rules/{rule_id}/verify-domain",
            post(routing_rules::verify_routing_rule_domain),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants/{grant_id}",
            delete(project_grants::withdraw_project_grant),
        )
        // The per-tenant usage export (issue #107): folded from the feed on request, so
        // asking for usage costs a feed read and no work on the authentication path.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/usage",
            get(usage::export_usage),
        )
        // The ordered event feed (issue #107): the cursor-paginated READ surface over the
        // log, recommended over webhooks for data synchronisation. An aged-out cursor is a
        // 410 carrying the oldest cursor that still resolves, never an empty 200.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/events",
            get(event_feed::read_event_feed),
        )
        // Organization roles (issue #97): first-class, per-organization named roles.
        // A role in M10 is a NAME only; what it grants is issue #98. There is no cap
        // on how many an organization may define.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles",
            post(org_roles::create_org_role).get(org_roles::list_org_roles),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
            get(org_roles::get_org_role)
                .patch(org_roles::update_org_role)
                .delete(org_roles::delete_org_role),
        )
        // The organization's DEFAULT role (issue #98): the role every live active
        // member holds without an assignment row existing for it. A per-organization
        // SINGLETON, so it is addressed at the ORGANIZATION and not once per role;
        // `PUT` designates (moving the designation if one is already held) and
        // `DELETE` clears. Reading it is `is_default` on the role views above, which
        // is where the value is stored.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/default-role",
            put(org_roles::set_org_default_role).delete(org_roles::clear_org_default_role),
        )
        // The role-to-permission MAPPING (issue #98): which permissions of the
        // ENVIRONMENT'S vocabulary this ORGANIZATION'S role grants. Nested under the
        // organization because the ROLE half is, while the permission half hangs off
        // the environment and carries no organization at all. PAIR addressed, so the
        // `rpm_` id never appears in a path. Uncapped in both directions by covenant.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions",
            post(org_role_permissions::assign_org_role_permission)
                .get(org_role_permissions::list_org_role_permissions),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions/{permission_id}",
            delete(org_role_permissions::unassign_org_role_permission),
        )
        // Organization groups (issue #97): first-class, per-organization named groups
        // holding a position in that organization's group forest. Uncapped in number,
        // bounded only in nesting DEPTH.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups",
            post(org_groups::create_org_group).get(org_groups::list_org_groups),
        )
        // The static `/parent` suffix sits next to the group routes for READABILITY.
        // Registration order selects nothing here: axum ranks a static segment above a
        // parameter whichever was registered first, and this pair cannot even compete,
        // because `.../groups/{group_id}/parent` carries one more path segment than
        // `.../groups/{group_id}`. (The organization lifecycle actions above are in
        // fact registered AFTER their parameterized item route and match for the same
        // reason.) So what PR 5 has to respect when it lands `/members` and `/roles`
        // siblings under this prefix is not an ordering: a static suffix is always
        // safe, and the one real hazard, a SECOND parameter at a position that already
        // has one, is refused at router construction with a panic naming both routes
        // rather than silently shadowed by whichever came first.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/parent",
            put(org_groups::set_org_group_parent),
        )
        // Group membership and the INHERITING role-assignment surface (issue #97).
        // `members` and `roles` are STATIC suffixes under `{group_id}`, exactly like
        // `parent` above, so they are safe wherever they are registered; the two
        // pair-addressed deletes each add their parameter at a position that has
        // none, which is the one hazard the note above names and is what makes them
        // safe rather than merely untested.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members",
            post(org_group_members::add_org_group_member)
                .get(org_group_members::list_org_group_members),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members/{membership_id}",
            delete(org_group_members::remove_org_group_member),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles",
            post(org_role_assignments::assign_org_group_role)
                .get(org_role_assignments::list_org_group_roles),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles/{role_id}",
            delete(org_role_assignments::unassign_org_group_role),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
            get(org_groups::get_org_group)
                .patch(org_groups::update_org_group)
                .delete(org_groups::delete_org_group),
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
        // The compatibility wizard (issue #93): pin a client's ID-token signing
        // algorithm, validated against the wizard set and the environment's actually
        // signable set. A static `.../signing-algorithm` suffix under the client.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/par-requirement",
            axum::routing::put(postures::set_client_par_requirement),
        )
        // The per-environment account-linking posture (issue #78, FORK B): the store
        // write and its audit action shipped with no caller.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/auto-link-posture",
            axum::routing::put(postures::set_auto_link_posture),
        )
        // The per-client PAR requirement (issue #27, RFC 9126): enforced at
        // authorize.rs:509 and settable by nothing until now.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/signing-algorithm",
            put(signing_algorithm::set_client_signing_algorithm),
        )
        // The per-client OAuth scope allowlist (issue #98): which scope tokens a
        // machine grant may request for this client. Another static suffix under the
        // client, a sibling of `.../signing-algorithm`. ENVIRONMENT level and taking
        // no organization, because a `clients` row carries none. The PUT writes
        // exactly one column and is sudo gated; the GET is not, matching every other
        // read on this surface.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/allowed-scopes",
            get(client_scopes::get_client_allowed_scopes)
                .put(client_scopes::set_client_allowed_scopes),
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
        // Per-environment brands (issues #86, #475): list, and set (create or overwrite) / get /
        // delete a branding definition keyed on its slug. This is the brand's birth path: before
        // it, `brands` had a store-level writer and no management endpoint, so the asset PUTs
        // below (which 404 on an absent brand) could never be reached for a new brand.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/brands",
            get(brands::list_brands),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}",
            put(brands::set_brand)
                .get(brands::get_brand)
                .delete(brands::delete_brand),
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
        // The user's identity-traits document (issue #53). A static suffix under
        // `{user_id}`, a sibling of `/state` and `/external-id`, so it is safe wherever it
        // is registered. Read only on this plane: traits are WRITTEN through the create body
        // and the PATCH body, which is where they are validated against the active schema.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/traits",
            get(users::get_user_traits),
        )
        // The user's typed login identifiers (issue #54, epic #514). A static suffix under
        // `{user_id}`, a sibling of `/traits`, `/state` and `/external-id`. This is the first
        // production WRITER of `user_identifiers`: before it the table was written only by
        // tests, so the shipped readers in federation, recovery and account resolution ran
        // against an empty table in every real deployment.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers",
            get(identifiers::list_user_identifiers).post(identifiers::add_user_identifier),
        )
        // The remove (epic #514), which is what M6 criterion 2's "end to end" still
        // lacked. A HARD delete, because the row is the claim on the uniqueness slot;
        // migration 0104 grants the DELETE to the control role only.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers/{identifier_id}",
            delete(identifiers::remove_user_identifier),
        )
        // The identifier uniqueness MODE change path (issue #54, epic #514). The store
        // has carried the two-step preview and apply since #54 and neither had a
        // production caller, so an operator could pick a mode at boot and had no way to
        // migrate a populated environment onto it. The read evaluates any candidate mode;
        // the apply runs the CONFIGURED one only.
        // Guarded SMS OTP configuration (issue #70). The store has carried the enable
        // switch, the downgrade opt-in and the country allowlist since #50 and NONE of the
        // four management methods had a production caller, so migration 0050's stated
        // requirement (turn it on AND populate the allowlist) could not be met by any
        // deployment. Migration 0105 adds the control-plane grants these routes need.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/config",
            get(sms_otp::get_sms_otp_config).put(sms_otp::set_sms_otp_config),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist",
            get(sms_otp::list_sms_allowlist),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist/{country_code}",
            put(sms_otp::allow_sms_country).delete(sms_otp::deny_sms_country),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/identifier-uniqueness",
            get(identifiers::get_identifier_uniqueness),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/identifier-uniqueness/apply",
            post(identifiers::apply_identifier_uniqueness),
        )
        // Per-environment identity trait-schema versions (issue #53): the append-only registry
        // (create / list / get) plus the two pointers, the ACTIVE read that is also the schema
        // introspection endpoint, and the cutover-gated activate. `/active` is a STATIC segment
        // sibling of the parameterized `/{version}`; the router ranks a static segment above a
        // parameter, and `parse_version` answers the uniform not-found for the literal anyway,
        // so the pair cannot silently mis-route in either direction.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas",
            post(trait_schemas::create_trait_schema_version)
                .get(trait_schemas::list_trait_schema_versions),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/active",
            get(trait_schemas::get_active_trait_schema),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/{version}",
            get(trait_schemas::get_trait_schema_version),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/{version}/activate",
            post(trait_schemas::activate_trait_schema_version),
        )
        // Trait MIGRATION jobs (issue #53): the store shipped create/get/advance with no
        // caller, so this is where an operator starts one and watches it.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/migrations",
            post(trait_schemas::create_trait_migration_job),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/migrations/{job_id}",
            axum::routing::get(trait_schemas::get_trait_migration_job),
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
        // Per-scope step-up policy management (RFC 9470, issue #262): the management
        // parity for the `ironauth step-up-policy` CLI, over the same audited repos.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies",
            post(step_up_policies::set_step_up_policy)
                .get(step_up_policies::list_step_up_policies),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies/{scope_token}",
            axum::routing::delete(step_up_policies::remove_step_up_policy),
        )
        // Queue depth for every async consumer in the environment (issue #104): the
        // reader its `depth` primitive shipped without.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/queues",
            axum::routing::get(queues::list_queue_depths),
        )
        // Standard Webhooks endpoint registration (issue #105).
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams",
            axum::routing::get(log_streams::list_log_streams)
                .post(log_streams::create_log_stream),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}",
            axum::routing::delete(log_streams::delete_log_stream),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints",
            post(webhook_endpoints::create_webhook_endpoint)
                .get(webhook_endpoints::list_webhook_endpoints),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/rotate-secret",
            post(webhook_endpoints::rotate_webhook_endpoint_secret),
        )
        // Pause and resume, distinct from delete: the endpoint and its sealed signing
        // secret survive, so resuming needs no re-registration and no consumer has to
        // adopt a new secret. `active` is what the deliverer's own read filters on.
        // The dead-letter view and replay (issue #106): nothing is ever silently dropped,
        // so the deliveries that exhausted their retry schedule stay listable and an
        // operator can put them back on the queue once the endpoint is healthy.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/attempts",
            axum::routing::get(webhook_endpoints::list_webhook_delivery_attempts),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/dead-letters",
            axum::routing::get(webhook_endpoints::list_webhook_dead_letters),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/replay",
            post(webhook_endpoints::replay_webhook_dead_letters),
        )
        // The per-endpoint event-type subscription (issue #106): which events this
        // endpoint receives. Applied at fan-out, so a non-matching event never has a
        // delivery attempt created for it.
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/event-types",
            axum::routing::put(webhook_endpoints::set_webhook_event_types),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/pause",
            post(webhook_endpoints::pause_webhook_endpoint),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/resume",
            post(webhook_endpoints::resume_webhook_endpoint),
        )
        .route(
            "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}",
            axum::routing::delete(webhook_endpoints::delete_webhook_endpoint),
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
