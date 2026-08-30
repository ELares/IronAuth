// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ABSENT-ENVIRONMENT contract for the whole management surface (issue #409).
//!
//! `org_context::resolve_scope` (and the private copies of it several older modules
//! carry) proves only that the `{tenant_id}` and `{environment_id}` path segments
//! PARSE. It never proves the environment ROW is there. Every table an
//! environment-scoped write touches carries a composite foreign key to
//! `environments`, so a well-formed identifier naming an environment that was never
//! created reaches the write, violates that constraint, and surfaces as an opaque 500
//! for an input the caller fully controls.
//!
//! # Why this file sweeps rather than testing a handful of handlers
//!
//! The defect's scope cannot be settled by reading the code, because a handler is
//! protected by ANY read that cannot succeed in an absent environment, not only by an
//! explicit `require_live_environment` call. Most environment-scoped writes address a
//! child row first (an organization, a client, a user, a connector), and no such row
//! can exist under an environment that does not, so the answer is already the uniform
//! not-found. What is left is the writes that reach a constraint with nothing read
//! first, and those are found by DRIVING every route, which is what
//! [`every_environment_scoped_write_at_an_absent_environment_is_the_uniform_not_found`]
//! does.
//!
//! # Why the sweep can fail on a route it does not drive
//!
//! A sweep over a hand-maintained list reports on whatever the list happens to contain,
//! and says nothing about what it omits. This one is checked against the COMMITTED
//! contract instead: [`every_documented_environment_scoped_write_is_driven_by_a_case`]
//! reads `docs/openapi/management.json`, enumerates every non-GET operation under the
//! environment prefix, resolves each case against it by method and templated path, and
//! fails when the two sets disagree in EITHER direction. A new environment-scoped write
//! therefore fails this file the moment it is documented, and a case whose path drifts
//! matches no template and fails too.
//!
//! # How the absent case is reachable at all
//!
//! `Principal::require_environment` refuses a management key any scope but its own
//! with the LOUD 403 wrong-scope, before any addressing happens. So a management key
//! only ever reaches the absent case inside its OWN environment, which means only
//! after that environment's row is gone. The OPERATOR plane is the reachable shape: it
//! is authorized for every environment, so a mistyped or stale environment id in an
//! operator script, a console, or the CLI addresses a live route with an environment
//! that does not exist. Every request in this file is driven with the bootstrap
//! operator token for exactly that reason.
//!
//! # Why the answer is the uniform not-found and not the 403 wrong-scope
//!
//! The issue asks whether the absent case should be uniform with the foreign-tenant
//! case, which answers 403 `wrong_scope`. It should not, and the two are not
//! alternatives. `wrong_scope` is an AUTHORIZATION verdict about the credential,
//! reached before the request addresses anything; the absent environment is an
//! ADDRESSING verdict, reached only by a credential already authorized for the
//! environment named. No credential can observe both for the same request: a
//! management key gets 403 for every environment but its own whether or not that
//! environment exists (so there is no existence oracle to close), and the operator is
//! authorized everywhere, so answering it `wrong_scope` would assert something false
//! about its own credential. The project's idiom for every addressing failure is the
//! uniform not-found, and that is what this file pins.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use common::{Harness, OPERATOR_TOKEN, bearer};
use ironauth_admin::ApiError;
use ironauth_env::Env;
use ironauth_store::{
    ClientId, ConnectorId, CorrelationId, EnvironmentId, InvitationId, ManagementKeyId,
    MigrationRunId, NewRecoveryFlow, OrgGroupId, OrgMembershipId, OrgRoleId, OrganizationId,
    PermissionId, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod, ResourceServerId, Scope,
    SessionId, SignupQuarantineReason, TenantId, UserId,
};
use sqlx::PgPool;

/// A well-formed environment segment that cannot PARSE. The reference answer: this is
/// refused by `resolve_scope` alone, and every absent environment must be
/// indistinguishable from it.
const MALFORMED_ENVIRONMENT: &str = "env_not-a-real-id";

/// The COMMITTED management contract, embedded at compile time: the same artifact and
/// the same idiom `tests/openapi_contract.rs` uses, and the reason this file can fail on
/// a route it does not drive (see
/// [`every_documented_environment_scoped_write_is_driven_by_a_case`]).
///
/// The document is a trustworthy inventory rather than a wish list, because
/// `openapi_contract::served_routes_match_documented_routes` already pins it against the
/// live router in BOTH directions: every documented method and path is wired, and no
/// documented path serves an undocumented method.
const COMMITTED_SPEC: &str = include_str!("../../../docs/openapi/management.json");

/// The templated prefix every environment-scoped route hangs off.
const ENVIRONMENT_PREFIX: &str = "/v1/tenants/{tenant_id}/environments/{environment_id}/";

/// One environment-scoped write, addressed at whichever environment the caller names.
///
/// `label` is `module.operationId`, and the `operationId` half is NOT decoration: the
/// coverage test resolves each case against the document by method and path and then
/// requires the label to name the operation it resolved to, so a label that drifts from
/// the route it drives is a failure rather than a comment.
struct Case {
    label: &'static str,
    method: &'static str,
    path: String,
    body: Option<String>,
}

/// One documented environment-scoped write, as the committed contract publishes it.
struct DocumentedWrite {
    operation_id: String,
    method: String,
    template: String,
}

/// Every non-GET operation the committed contract publishes under the environment
/// prefix: the inventory this sweep must cover in full.
fn documented_environment_writes() -> Vec<DocumentedWrite> {
    let doc: serde_json::Value =
        serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let mut writes = Vec::new();
    for (template, operations) in doc["paths"].as_object().expect("paths") {
        if !template.starts_with(ENVIRONMENT_PREFIX) {
            continue;
        }
        for (method, operation) in operations.as_object().expect("operations") {
            if method.eq_ignore_ascii_case("get") {
                continue;
            }
            writes.push(DocumentedWrite {
                operation_id: operation["operationId"]
                    .as_str()
                    .expect("every operation carries an id")
                    .to_owned(),
                method: method.to_uppercase(),
                template: template.clone(),
            });
        }
    }
    writes
}

/// Whether a CONCRETE request path is addressed by a TEMPLATED document path: the same
/// segment count, with every templated segment either a `{placeholder}` (which matches
/// any one segment) or an exact literal.
fn template_matches(template: &str, path: &str) -> bool {
    // An OpenAPI path template carries no query string, so a concrete path's query is
    // stripped before the segment comparison: it addresses the same template. The
    // bulk-import create is the one case here that carries one, and without this it
    // would match NO template and fail the coverage check rather than resolve.
    let path = path.split('?').next().unwrap_or(path);
    let expected: Vec<&str> = template.split('/').collect();
    let actual: Vec<&str> = path.split('/').collect();
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual.iter())
        .all(|(pattern, segment)| pattern.starts_with('{') || pattern == segment)
}

/// The uniform not-found EXACTLY as the wire carries it, rendered from the one type that
/// produces it rather than transcribed into a literal here.
///
/// This is what stops a case from passing on the wrong 404. Axum answers a path that
/// matches NO route with a bare 404 and an EMPTY body, so a sweep that asserts only the
/// status cannot tell a real refusal from a request that never reached a handler; the
/// live pass's `assert_ne!(METHOD_NOT_ALLOWED)` guard does not close that either, since
/// an unmatched path is a 404 and not a 405.
async fn uniform_not_found() -> (StatusCode, String) {
    let response = ApiError::NotFound.into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the not-found body is finite");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("the not-found body is utf-8"),
    )
}

fn body_of(value: &serde_json::Value) -> String {
    value.to_string()
}

/// The `(tenant, environment)` pair a pair of path segments names.
fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant parses"),
        EnvironmentId::parse(environment).expect("environment parses"),
    )
}

/// Every table's row count, read as the database OWNER so row-level security can never
/// hide a write. The same instrument the flow inspector's zero-side-effect proof uses.
async fn snapshot(pool: &PgPool) -> BTreeMap<String, i64> {
    let tables: Vec<(String,)> =
        sqlx::query_as("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            .fetch_all(pool)
            .await
            .expect("list public tables");
    let mut counts = BTreeMap::new();
    for (table,) in tables {
        let (count,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM \"{table}\""))
            .fetch_one(pool)
            .await
            .expect("count table rows");
        counts.insert(table, count);
    }
    counts
}

/// The scope-bound identifiers a route's sub-resource segments need. Minted UNDER the
/// environment the case addresses, so every id is in scope by construction and the
/// only thing wrong with the request is the environment itself.
struct Ids {
    client: String,
    user: String,
    session: String,
    org: String,
    group: String,
    role: String,
    membership: String,
    permission: String,
    resource_server: String,
    invitation: String,
    flow: String,
    connector: String,
    management_key: String,
    migration_run: String,
}

impl Ids {
    fn mint(tenant: &str, environment: &str) -> Self {
        let env = Env::system();
        let scope = scope_of(tenant, environment);
        Self {
            client: ClientId::generate(&env, &scope).to_string(),
            user: UserId::generate(&env, &scope).to_string(),
            session: SessionId::generate(&env, &scope).to_string(),
            org: OrganizationId::generate(&env, &scope).to_string(),
            group: OrgGroupId::generate(&env, &scope).to_string(),
            role: OrgRoleId::generate(&env, &scope).to_string(),
            membership: OrgMembershipId::generate(&env, &scope).to_string(),
            permission: PermissionId::generate(&env, &scope).to_string(),
            resource_server: ResourceServerId::generate(&env, &scope).to_string(),
            invitation: InvitationId::generate(&env, &scope).to_string(),
            flow: RecoveryFlowId::generate(&env, &scope).to_string(),
            connector: ConnectorId::generate(&env, &scope).to_string(),
            management_key: ManagementKeyId::generate(&env, &scope).to_string(),
            migration_run: MigrationRunId::generate(&env, &scope).to_string(),
        }
    }
}

/// The HTTP flow target registration writes (issue #112).
fn flow_target_cases(base: &str) -> Vec<Case> {
    vec![
        Case {
            label: "flow_targets.createFlowTarget",
            method: "POST",
            path: format!("{base}/flow-targets"),
            body: Some(
                serde_json::json!({
                    "name": "absent-environment-probe",
                    "target_class": "request",
                    "invocation": "sync",
                    "timing": "pre_persist",
                    "endpoint": "https://target.example/check",
                    "timeout_ms": 500,
                    "failure_policy": "fail_closed",
                })
                .to_string(),
            ),
        },
        Case {
            label: "flow_targets.deleteFlowTarget",
            method: "DELETE",
            path: format!("{base}/flow-targets/ftg_absent"),
            body: None,
        },
        // Asking for a dead-letter replay is a WRITE and must meet the same fence. The
        // LISTING is deliberately absent from this file: it is a read, and this surface's
        // rule is that reads stay readable at a soft-deleted environment.
        //
        // The liveness fence runs BEFORE the id parse in that handler, so the synthetic id
        // here does not shortcut the case: what answers is the environment check.
        Case {
            label: "flow_targets.replayFlowTargetDeadLetters",
            method: "POST",
            path: format!("{base}/flow-targets/ftg_absent/replay"),
            body: Some("{}".to_owned()),
        },
    ]
}

/// The workload-federation trust anchor and subject-mapping writes (issue #126).
///
/// The liveness fence runs before the id parse in all four by-id handlers, so at a live
/// environment these synthetic ids reach the fence first. Be honest about what that buys: with
/// the fence REMOVED, a `xai_absent` id fails `parse_in_scope` and yields the same
/// `ApiError::NotFound`, so the four by-id cases here cannot DISCRIMINATE a missing fence. They
/// are an inventory obligation (every documented environment-scoped write is driven) rather
/// than a measurement, exactly like the pre-existing `ftg_absent` case above.
///
/// Nor are the two POSTs, and an earlier draft of this comment claimed they were. Every
/// handler in this module opens with `resolve_scope`, which calls `exists_in_any_state` and
/// answers `ApiError::NotFound` for an environment that was never created. This sweep's
/// environment is generated and never created, so `resolve_scope` refuses first and
/// `require_live_environment` is never reached by ANY case here. All six are inventory.
///
/// The two LISTINGS are deliberately absent, following this file's rule: they are reads, and
/// a soft-deleted environment stays readable so it stays auditable. They are driven at the
/// soft-deleted environment by the live-surface sweep instead, which asserts they keep
/// answering the LIVE status and carrying their rows.
fn external_issuer_cases(base: &str) -> Vec<Case> {
    vec![
        Case {
            label: "external_issuers.registerExternalIssuer",
            method: "POST",
            path: format!("{base}/external-issuers"),
            body: Some(
                serde_json::json!({
                    "issuer": "https://absent-environment.example/oidc",
                    "jwks_uri": "https://absent-environment.example/keys",
                })
                .to_string(),
            ),
        },
        Case {
            label: "external_issuers.setExternalIssuerEnabled",
            method: "PATCH",
            path: format!("{base}/external-issuers/xai_absent"),
            body: Some(serde_json::json!({ "enabled": false }).to_string()),
        },
        Case {
            label: "external_issuers.createSubjectMapping",
            method: "POST",
            path: format!("{base}/subject-mappings"),
            body: Some(
                serde_json::json!({
                    "issuer": "https://absent-environment.example/oidc",
                    "external_subject": "absent-environment-probe",
                    "principal": "sva_absent",
                })
                .to_string(),
            ),
        },
        Case {
            label: "external_issuers.setSubjectMappingEnabled",
            method: "PATCH",
            path: format!("{base}/subject-mappings/asm_absent"),
            body: Some(serde_json::json!({ "enabled": false }).to_string()),
        },
        Case {
            label: "external_issuers.deleteExternalIssuer",
            method: "DELETE",
            path: format!("{base}/external-issuers/xai_absent"),
            body: None,
        },
        Case {
            label: "external_issuers.deleteSubjectMapping",
            method: "DELETE",
            path: format!("{base}/subject-mappings/asm_absent"),
            body: None,
        },
    ]
}

/// The message resend write (issue #111 criterion 1).
///
/// Its own function rather than an entry appended to a neighbouring list, because these case
/// lists sit near the 100-line clippy ceiling and growing one pushes it over -- which a
/// targeted `cargo test` does not catch and only the lint reports.
fn message_cases(base: &str) -> Vec<Case> {
    vec![Case {
        label: "messages.resendMessage",
        method: "POST",
        path: format!("{base}/messages/msg_absentmessage/resend"),
        body: None,
    }]
}

/// The SIEM log stream configuration writes (issue #110).
fn log_stream_cases(base: &str) -> Vec<Case> {
    vec![
        Case {
            label: "log_streams.createLogStream",
            method: "POST",
            path: format!("{base}/log-streams"),
            body: Some(
                serde_json::json!({
                    "source": "both",
                    "sink_type": "http",
                    "sink_config": {"endpoint": "https://sink.example/in"},
                })
                .to_string(),
            ),
        },
        Case {
            label: "log_streams.replayLogStreamDeadLetters",
            method: "POST",
            path: format!("{base}/log-streams/lgs_absent/dead-letters/replay"),
            body: None,
        },
        Case {
            label: "log_streams.deleteLogStream",
            method: "DELETE",
            path: format!("{base}/log-streams/lgs_absent"),
            body: None,
        },
    ]
}

/// The credential-abuse and sudo-elevation writes: the two that hang off nothing but
/// the environment itself.
fn abuse_and_sudo_cases(base: &str) -> Vec<Case> {
    let ban = body_of(&serde_json::json!({
        "subject_kind": "ip", "subject": "203.0.113.7", "auth_path": "password"
    }));
    vec![
        Case {
            label: "bans.createBan",
            method: "POST",
            path: format!("{base}/abuse/bans"),
            body: Some(ban.clone()),
        },
        Case {
            label: "bans.liftBan",
            method: "POST",
            path: format!("{base}/abuse/bans/lift"),
            body: Some(ban),
        },
        Case {
            // The usage PUBLISH, not the export: the export is a GET and this sweep covers
            // writes. It appends to the event feed every webhook subscriber receives, so an
            // absent environment reaching it would make subscribers receive a billing record
            // for a scope that does not exist.
            label: "usage.publishUsage",
            method: "POST",
            path: format!("{base}/usage/publish"),
            body: None,
        },
        Case {
            label: "webhook_endpoints.createWebhookEndpoint",
            method: "POST",
            path: format!("{base}/webhook-endpoints"),
            body: Some(serde_json::json!({ "url": "https://example.test/hook" }).to_string()),
        },
        Case {
            label: "webhook_endpoints.rotateWebhookEndpointSecret",
            method: "POST",
            path: format!("{base}/webhook-endpoints/whe_absent/rotate-secret"),
            body: None,
        },
        Case {
            label: "webhook_endpoints.replayWebhookDeadLetters",
            method: "POST",
            path: format!("{base}/webhook-endpoints/whe_absent/replay"),
            body: Some(serde_json::json!({}).to_string()),
        },
        Case {
            label: "webhook_endpoints.setWebhookEventTypes",
            method: "PUT",
            path: format!("{base}/webhook-endpoints/whe_absent/event-types"),
            body: Some(body_of(
                &serde_json::json!({ "event_types": ["user.created"] }),
            )),
        },
        Case {
            label: "webhook_endpoints.pauseWebhookEndpoint",
            method: "POST",
            path: format!("{base}/webhook-endpoints/whe_absent/pause"),
            body: None,
        },
        Case {
            label: "webhook_endpoints.resumeWebhookEndpoint",
            method: "POST",
            path: format!("{base}/webhook-endpoints/whe_absent/resume"),
            body: None,
        },
        Case {
            label: "webhook_endpoints.deleteWebhookEndpoint",
            method: "DELETE",
            path: format!("{base}/webhook-endpoints/whe_absent"),
            body: None,
        },
        Case {
            label: "step_up_policies.setStepUpPolicy",
            method: "POST",
            path: format!("{base}/step-up-policies"),
            body: Some(
                serde_json::json!({ "scope_token": "payments:write", "min_acr": "aal2" })
                    .to_string(),
            ),
        },
        Case {
            label: "step_up_policies.removeStepUpPolicy",
            method: "DELETE",
            path: format!("{base}/step-up-policies/payments:write"),
            body: None,
        },
        Case {
            label: "sudo.elevateAdminSudo",
            method: "POST",
            path: format!("{base}/admin/sudo/elevate"),
            body: None,
        },
    ]
}

/// The smallest byte string the brand-asset upload's MAGIC-BYTE sniff accepts: a RIFF
/// container tagged WEBP. The sniff reads the BYTES and never the declared header, so a
/// body that fails it would be a 400 at every environment and the case would measure the
/// sniff rather than the environment.
const RASTER_UPLOAD: &str = "RIFF\0\0\0\0WEBP";

/// The environment-scoped writes that address a CLIENT.
/// The two security postures the data plane enforces (issues #27, #78), in their own
/// builder because they belong to no existing group: one is per client and one is per
/// environment, and folding them into `client_cases` pushed it past the readable-length
/// lint.
fn posture_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let client = &ids.client;
    vec![
        Case {
            label: "postures.setClientParRequirement",
            method: "PUT",
            path: format!("{base}/clients/{client}/par-requirement"),
            body: Some(body_of(&serde_json::json!({ "required": true }))),
        },
        Case {
            label: "postures.setAutoLinkPosture",
            method: "PUT",
            path: format!("{base}/auto-link-posture"),
            body: Some(body_of(&serde_json::json!({ "posture": "off" }))),
        },
    ]
}

/// The environment SECRET writes (issue #235), lifted out of [`client_cases`] because adding
/// them inline pushed that function past the readable-length lint. They are their own frame in
/// any case: every other case there hangs off a CLIENT, and these hang off the environment.
fn secret_cases(base: &str) -> Vec<Case> {
    vec![
        // Environment SECRET management (issue #235), the same two shapes as the variable
        // writes above. The uniform not-found matters more here: an answer that distinguished
        // "no such environment" from "no such secret" would let an unauthenticated-for-this-
        // scope caller enumerate secret NAMES, which is metadata this surface otherwise only
        // gives to a credential holding the scope.
        Case {
            label: "secrets.setSecret",
            method: "PUT",
            path: format!("{base}/secrets/ABSENT_ENV_PROBE"),
            body: Some(body_of(&serde_json::json!({ "value": "x" }))),
        },
        Case {
            label: "secrets.deleteSecret",
            method: "DELETE",
            path: format!("{base}/secrets/ABSENT_ENV_PROBE"),
            body: None,
        },
    ]
}

/// The per-client DECLARATIVE CLAIM MAPPING writes (issue #113).
///
/// Their own function rather than two more entries in `client_cases`, which is already at the
/// line ceiling. The ceiling is worth keeping rather than raising: this list is a catalogue, and
/// a catalogue nobody finishes reading is one where a missing case hides.
///
/// An EMPTY rule list on the write, because the question these sweeps ask is whether an ABSENT
/// environment answers the uniform not-found. A body that could be refused on its own contents
/// would answer a different question, and would answer it identically whether or not the
/// environment was checked at all.
fn claims_mapping_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids { client, .. } = ids;
    vec![
        Case {
            label: "claims_mappings.setClaimsMapping",
            method: "PUT",
            path: format!("{base}/applications/{client}/claims-mapping"),
            body: Some(body_of(&serde_json::json!({ "rules": [] }))),
        },
        Case {
            label: "claims_mappings.deleteClaimsMapping",
            method: "DELETE",
            path: format!("{base}/applications/{client}/claims-mapping"),
            body: None,
        },
        Case {
            label: "token_hooks.deployTokenHook",
            method: "PUT",
            path: format!("{base}/applications/{client}/token-hook?payload_version=1"),
            body: Some(body_of(&serde_json::json!({}))),
        },
        Case {
            label: "token_hooks.deleteTokenHook",
            method: "DELETE",
            path: format!("{base}/applications/{client}/token-hook"),
            body: None,
        },
        Case {
            label: "token_hooks.rollbackTokenHook",
            method: "POST",
            path: format!("{base}/applications/{client}/token-hook/rollback"),
            body: Some(body_of(&serde_json::json!({ "version": 1 }))),
        },
        // The DRAFT RUN. A POST that stores nothing, and it is here because this sweep
        // classifies by METHOD, not by effect: a write-shaped door that skipped
        // `require_live_environment` would RUN A HOOK in a decommissioned environment, which
        // is exactly what a fence is for even when the run leaves no trace.
        Case {
            label: "token_hooks.testTokenHook",
            method: "POST",
            path: format!("{base}/applications/{client}/token-hook/test"),
            body: Some(body_of(
                &serde_json::json!({ "grant_type": "authorization_code" }),
            )),
        },
        Case {
            label: "token_hooks.reorderTokenHooks",
            method: "POST",
            path: format!("{base}/applications/{client}/token-hook/order"),
            body: Some(body_of(&serde_json::json!({ "order": ["default"] }))),
        },
        // THE GRANT AND THE REVOKE. Both are writes to a decommissioned environment's grant
        // table, and the grant is the one that matters most: it is the door that WIDENS what
        // code can read, so a fence it slipped past would let an operator hand a hook in a
        // decommissioned environment a secret it could not read before.
        Case {
            label: "token_hooks.grantTokenHookSecret",
            method: "PUT",
            path: format!("{base}/applications/{client}/token-hook/secrets?secret_name=api_key"),
            body: None,
        },
        Case {
            label: "token_hooks.revokeTokenHookSecret",
            method: "DELETE",
            path: format!("{base}/applications/{client}/token-hook/secrets?secret_name=api_key"),
            body: None,
        },
    ]
}

fn client_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids { client, .. } = ids;
    vec![
        Case {
            label: "client_admin_grants.setClientAdminConsent",
            method: "PUT",
            path: format!("{base}/applications/{client}/admin-consent"),
            body: Some(body_of(&serde_json::json!({ "scope": "openid profile" }))),
        },
        Case {
            label: "client_admin_grants.deleteClientAdminConsent",
            method: "DELETE",
            path: format!("{base}/applications/{client}/admin-consent"),
            body: None,
        },
        Case {
            label: "signup_forms.setSignupForm",
            method: "PUT",
            path: format!("{base}/applications/{client}/signup-form"),
            body: Some(body_of(&serde_json::json!({ "fields": [] }))),
        },
        // Environment VARIABLE management (issue #235). Both writes are environment scoped
        // and neither takes a parent beyond the environment itself, so an absent environment
        // must be the uniform not-found on each rather than a name-specific answer that would
        // tell a caller whether the variable exists.
        Case {
            label: "variables.setVariable",
            method: "PUT",
            path: format!("{base}/variables/ABSENT_ENV_PROBE"),
            body: Some(body_of(&serde_json::json!({ "value": "x" }))),
        },
        Case {
            label: "variables.deleteVariable",
            method: "DELETE",
            path: format!("{base}/variables/ABSENT_ENV_PROBE"),
            body: None,
        },
        Case {
            label: "signup_forms.deleteSignupForm",
            method: "DELETE",
            path: format!("{base}/applications/{client}/signup-form"),
            body: None,
        },
        Case {
            label: "brands.setBrand",
            method: "PUT",
            path: format!("{base}/brands/default"),
            body: Some(body_of(&serde_json::json!({ "product_name": "Sweep" }))),
        },
        Case {
            label: "brands.deleteBrand",
            method: "DELETE",
            path: format!("{base}/brands/default"),
            body: None,
        },
        Case {
            label: "brand_assets.deleteBrandFavicon",
            method: "DELETE",
            path: format!("{base}/brands/default/favicon"),
            body: None,
        },
        Case {
            label: "brand_assets.setBrandFavicon",
            method: "PUT",
            path: format!("{base}/brands/default/favicon"),
            body: Some(RASTER_UPLOAD.to_owned()),
        },
        Case {
            label: "brand_assets.deleteBrandLogo",
            method: "DELETE",
            path: format!("{base}/brands/default/logo"),
            body: None,
        },
        Case {
            label: "brand_assets.setBrandLogo",
            method: "PUT",
            path: format!("{base}/brands/default/logo"),
            body: Some(RASTER_UPLOAD.to_owned()),
        },
        Case {
            label: "client_scopes.setClientAllowedScopes",
            method: "PUT",
            path: format!("{base}/clients/{client}/allowed-scopes"),
            body: Some(body_of(
                &serde_json::json!({ "allowed_scopes": ["openid"] }),
            )),
        },
        Case {
            label: "signing_algorithm.setClientSigningAlgorithm",
            method: "PUT",
            path: format!("{base}/clients/{client}/signing-algorithm"),
            body: Some(body_of(&serde_json::json!({ "algorithm": "EdDSA" }))),
        },
        Case {
            label: "dcr.verifyDcrClient",
            method: "POST",
            path: format!("{base}/clients/{client}/verify"),
            body: None,
        },
    ]
}

/// The config-promotion, connector, dynamic-registration, and flow-inspector writes.
fn config_and_connector_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let connector = body_of(&serde_json::json!({
        "connector_id": "sweep-connector",
        "display_name": "Sweep",
        "protocol": "oidc",
        "endpoints": { "issuer": "https://idp.example" },
        "scopes": ["openid"],
        "client_id": "abc",
        "client_secret": "shhh"
    }));
    let Ids {
        connector: connector_id,
        ..
    } = ids;
    vec![
        Case {
            label: "promotion.applyConfigPromotion",
            method: "POST",
            path: format!("{base}/config/promotion/apply"),
            body: Some(body_of(&serde_json::json!({
                "source": { "tenant_id": "ten_x", "environment_id": "env_x" },
                "base_revision": "0"
            }))),
        },
        Case {
            label: "promotion.planConfigPromotion",
            method: "POST",
            path: format!("{base}/config/promotion/plan"),
            body: Some(body_of(&serde_json::json!({}))),
        },
        Case {
            label: "connectors.createConnector",
            method: "POST",
            path: format!("{base}/connectors"),
            body: Some(connector.clone()),
        },
        Case {
            label: "connectors.updateConnector",
            method: "PUT",
            path: format!("{base}/connectors/{connector_id}"),
            body: Some(connector),
        },
        Case {
            label: "connectors.deleteConnector",
            method: "DELETE",
            path: format!("{base}/connectors/{connector_id}"),
            body: None,
        },
        Case {
            label: "dcr.createDcrInitialAccessToken",
            method: "POST",
            path: format!("{base}/dcr/initial-access-tokens"),
            body: Some(body_of(&serde_json::json!({ "expires_in_secs": 3600 }))),
        },
        Case {
            label: "dcr.createDcrPolicy",
            method: "POST",
            path: format!("{base}/dcr/policies"),
            body: Some(body_of(&serde_json::json!({
                "name": "sweep", "primitives": []
            }))),
        },
        Case {
            label: "diagnostics.postFlowDryRun",
            method: "POST",
            path: format!("{base}/diagnostics/flow/dry-run"),
            body: Some(body_of(&serde_json::json!({
                "journey": "login", "achieved_acr": "pwd"
            }))),
        },
    ]
}

/// The environment-scoped writes over invitations, journeys, trait schemas, keys,
/// locales, and the two operator probes.
///
/// A flat case LIST, so its length is the number of routes it drives and nothing else.
/// Splitting it to satisfy the line lint would put the sweep's coverage in two places,
/// which is the property `every_documented_environment_scoped_write_is_driven_by_a_case`
/// exists to keep in one.
#[allow(clippy::too_many_lines)]
fn environment_child_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids {
        management_key,
        invitation,
        migration_run,
        ..
    } = ids;
    vec![
        // The streaming bulk-import job (issue #55). Its body is newline-delimited
        // records rather than a JSON object, which changes nothing here: at an absent
        // environment neither route reads a byte of it.
        Case {
            label: "imports.createIdentityImport",
            method: "POST",
            path: format!("{base}/imports?source_total=1"),
            body: Some("{\"identifier\":\"sweep-import@example.test\"}\n".to_owned()),
        },
        Case {
            label: "imports.resumeIdentityImport",
            method: "POST",
            path: format!("{base}/imports/{migration_run}"),
            body: Some("{\"identifier\":\"sweep-import@example.test\"}\n".to_owned()),
        },
        // Abandoning a run is the ONE write on the migration-run surface (issue #55), and
        // it refuses an absent environment exactly like every other one.
        Case {
            label: "migration_runs.abandonMigrationRun",
            method: "POST",
            path: format!("{base}/migration-runs/{migration_run}/abandon"),
            body: Some("{\"reason\":\"sweeping an absent environment\"}".to_owned()),
        },
        Case {
            label: "invitations.createInvitation",
            method: "POST",
            path: format!("{base}/invitations"),
            body: Some(body_of(
                &serde_json::json!({ "identifier": "sweep@example.test" }),
            )),
        },
        Case {
            label: "invitations.resendInvitation",
            method: "POST",
            path: format!("{base}/invitations/{invitation}/resend"),
            body: None,
        },
        Case {
            label: "invitations.revokeInvitation",
            method: "POST",
            path: format!("{base}/invitations/{invitation}/revoke"),
            body: None,
        },
        Case {
            label: "flow_versions.createFlowVersion",
            method: "POST",
            path: format!("{base}/journeys/login/versions"),
            body: Some(body_of(&serde_json::json!({ "artifact": {} }))),
        },
        Case {
            label: "flow_versions.pinFlowVersion",
            method: "POST",
            path: format!("{base}/journeys/login/versions/1/pin"),
            body: None,
        },
        Case {
            label: "trait_schemas.createTraitMigrationJob",
            method: "POST",
            path: format!("{base}/trait-schemas/migrations"),
            body: Some(body_of(&serde_json::json!({
                "kind": "dry_run",
                "from_version": 1,
                "to_version": 1
            }))),
        },
        Case {
            label: "trait_schemas.createTraitSchemaVersion",
            method: "POST",
            path: format!("{base}/trait-schemas"),
            body: Some(body_of(
                &serde_json::json!({ "schema": {"type": "object"} }),
            )),
        },
        Case {
            label: "trait_schemas.activateTraitSchemaVersion",
            method: "POST",
            path: format!("{base}/trait-schemas/1/activate"),
            body: None,
        },
        Case {
            label: "keys.createManagementKey",
            method: "POST",
            path: format!("{base}/keys"),
            body: Some(body_of(&serde_json::json!({ "display_name": "Sweep" }))),
        },
        Case {
            label: "keys.deleteManagementKey",
            method: "DELETE",
            path: format!("{base}/keys/{management_key}"),
            body: None,
        },
        Case {
            label: "locales.setLocale",
            method: "PUT",
            path: format!("{base}/locales/en"),
            body: Some(body_of(&serde_json::json!({
                "entries": { "login.title": "Sign in" }
            }))),
        },
        Case {
            label: "locales.deleteLocale",
            method: "DELETE",
            path: format!("{base}/locales/en"),
            body: None,
        },
        Case {
            label: "migration.verifyMigrationCredential",
            method: "POST",
            path: format!("{base}/migration/verify-credential"),
            body: Some(body_of(&serde_json::json!({
                "identifier": "sweep@example.test", "password": "hunter2hunter2"
            }))),
        },
        Case {
            label: "migration.setOutboundVerification",
            method: "PUT",
            path: format!("{base}/migration/outbound-verification"),
            body: Some(body_of(&serde_json::json!({
                "token": "an-outbound-token-of-at-least-32-bytes"
            }))),
        },
        Case {
            label: "migration.deleteOutboundVerification",
            method: "DELETE",
            path: format!("{base}/migration/outbound-verification"),
            body: None,
        },
        Case {
            label: "password_hashing.probePasswordHashing",
            method: "POST",
            path: format!("{base}/password-hashing/probe"),
            body: Some(body_of(&serde_json::json!({}))),
        },
    ]
}

/// The environment-scoped writes that address a session, a quarantined signup, a
/// permission, a resource server, or a recovery approval.
fn resource_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids {
        user,
        session,
        permission,
        resource_server,
        flow,
        ..
    } = ids;
    vec![
        Case {
            label: "sessions.bulkRevokeSessions",
            method: "POST",
            path: format!("{base}/sessions/revoke"),
            body: Some(body_of(&serde_json::json!({ "session_ids": [session] }))),
        },
        Case {
            label: "sessions.revokeSession",
            method: "POST",
            path: format!("{base}/sessions/{session}/revoke"),
            body: Some(body_of(&serde_json::json!({}))),
        },
        Case {
            label: "signup_quarantine.approveSignupQuarantine",
            method: "POST",
            path: format!("{base}/signup-quarantine/{user}/approve"),
            body: None,
        },
        Case {
            label: "signup_quarantine.extendSignupQuarantine",
            method: "POST",
            path: format!("{base}/signup-quarantine/{user}/extend"),
            body: Some(body_of(&serde_json::json!({ "extend_secs": 3600 }))),
        },
        Case {
            label: "signup_quarantine.rejectSignupQuarantine",
            method: "POST",
            path: format!("{base}/signup-quarantine/{user}/reject"),
            body: None,
        },
        Case {
            label: "permissions.createPermission",
            method: "POST",
            path: format!("{base}/permissions"),
            body: Some(body_of(&serde_json::json!({
                "slug": "sweep.read", "display_name": "Sweep"
            }))),
        },
        Case {
            label: "permissions.updatePermission",
            method: "PATCH",
            path: format!("{base}/permissions/{permission}"),
            body: Some(body_of(&serde_json::json!({ "display_name": "Sweep" }))),
        },
        Case {
            label: "permissions.deletePermission",
            method: "DELETE",
            path: format!("{base}/permissions/{permission}"),
            body: None,
        },
        Case {
            label: "recovery_approvals.approveRecoveryApproval",
            method: "POST",
            path: format!("{base}/recovery-approvals/{flow}/approve"),
            body: None,
        },
        Case {
            label: "recovery_approvals.rejectRecoveryApproval",
            method: "POST",
            path: format!("{base}/recovery-approvals/{flow}/reject"),
            body: None,
        },
        Case {
            label: "resource_servers.updateResourceServerPermissionClaims",
            method: "PATCH",
            path: format!("{base}/resource-servers/{resource_server}"),
            body: Some(body_of(
                &serde_json::json!({ "permission_claims_enabled": true }),
            )),
        },
    ]
}

/// The environment-scoped writes that address a USER.
fn user_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids { client, user, .. } = ids;
    vec![
        Case {
            label: "users.createUser",
            method: "POST",
            path: format!("{base}/users"),
            body: Some(body_of(
                &serde_json::json!({ "identifier": "sweep@example.test" }),
            )),
        },
        Case {
            label: "users.updateUser",
            method: "PATCH",
            path: format!("{base}/users/{user}"),
            body: Some(body_of(&serde_json::json!({ "claims": {} }))),
        },
        Case {
            label: "users.deleteUser",
            method: "DELETE",
            path: format!("{base}/users/{user}"),
            body: None,
        },
        Case {
            label: "consents.revokeUserConsent",
            method: "POST",
            path: format!("{base}/users/{user}/consents/{client}/revoke"),
            body: None,
        },
        Case {
            label: "sms_otp.setSmsOtpConfig",
            method: "PUT",
            path: format!("{base}/sms-otp/config"),
            body: Some(body_of(&serde_json::json!({ "enabled": true }))),
        },
        Case {
            label: "sms_otp.allowSmsCountry",
            method: "PUT",
            path: format!("{base}/sms-otp/allowlist/44"),
            body: None,
        },
        Case {
            label: "sms_otp.denySmsCountry",
            method: "DELETE",
            path: format!("{base}/sms-otp/allowlist/44"),
            body: None,
        },
        Case {
            label: "identifiers.applyIdentifierUniqueness",
            method: "POST",
            path: format!("{base}/identifier-uniqueness/apply"),
            body: None,
        },
        Case {
            label: "users.addUserIdentifier",
            method: "POST",
            path: format!("{base}/users/{user}/identifiers"),
            body: Some(body_of(
                &serde_json::json!({ "type": "email", "value": "absent@example.test" }),
            )),
        },
        Case {
            label: "users.removeUserIdentifier",
            method: "DELETE",
            path: format!("{base}/users/{user}/identifiers/uid_absentidentifierprobe00000"),
            body: None,
        },
        Case {
            label: "users.linkUserExternalId",
            method: "PUT",
            path: format!("{base}/users/{user}/external-id"),
            body: Some(body_of(&serde_json::json!({ "external_id": "ext-1" }))),
        },
        Case {
            label: "users.unlinkUserExternalId",
            method: "DELETE",
            path: format!("{base}/users/{user}/external-id"),
            body: None,
        },
        Case {
            label: "users.revokeUserSessions",
            method: "POST",
            path: format!("{base}/users/{user}/sessions/revoke"),
            body: Some(body_of(&serde_json::json!({}))),
        },
        Case {
            label: "users.setUserState",
            method: "POST",
            path: format!("{base}/users/{user}/state"),
            body: Some(body_of(&serde_json::json!({ "state": "blocked" }))),
        },
    ]
}

/// The organization and GROUP writes. Every one of them resolves the parent
/// organization first, and `organizations` carries the same foreign key to
/// `environments`, so none of them can reach a constraint in an absent environment.
fn organization_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids {
        org,
        group,
        role,
        membership,
        ..
    } = ids;
    let named = body_of(&serde_json::json!({ "slug": "sweep", "display_name": "Sweep" }));
    let relabel = body_of(&serde_json::json!({ "display_name": "Sweep" }));
    let role_ref = body_of(&serde_json::json!({ "role_id": role }));
    vec![
        Case {
            label: "organizations.createOrganization",
            method: "POST",
            path: format!("{base}/organizations"),
            body: Some(body_of(&serde_json::json!({ "display_name": "Sweep" }))),
        },
        Case {
            label: "organizations.deleteOrganization",
            method: "DELETE",
            path: format!("{base}/organizations/{org}"),
            body: None,
        },
        Case {
            label: "organizations.disableOrganization",
            method: "POST",
            path: format!("{base}/organizations/{org}/disable"),
            body: None,
        },
        Case {
            label: "organizations.enableOrganization",
            method: "POST",
            path: format!("{base}/organizations/{org}/enable"),
            body: None,
        },
        Case {
            label: "org_roles.setOrgDefaultRole",
            method: "PUT",
            path: format!("{base}/organizations/{org}/default-role"),
            body: Some(role_ref.clone()),
        },
        Case {
            label: "org_roles.clearOrgDefaultRole",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/default-role"),
            body: None,
        },
        Case {
            label: "org_groups.createOrgGroup",
            method: "POST",
            path: format!("{base}/organizations/{org}/groups"),
            body: Some(named.clone()),
        },
        Case {
            label: "org_groups.updateOrgGroup",
            method: "PATCH",
            path: format!("{base}/organizations/{org}/groups/{group}"),
            body: Some(relabel.clone()),
        },
        Case {
            label: "org_groups.deleteOrgGroup",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/groups/{group}"),
            body: None,
        },
        Case {
            label: "org_groups.setOrgGroupParent",
            method: "PUT",
            path: format!("{base}/organizations/{org}/groups/{group}/parent"),
            body: Some(body_of(&serde_json::json!({ "parent_id": null }))),
        },
        Case {
            label: "org_group_members.addOrgGroupMember",
            method: "POST",
            path: format!("{base}/organizations/{org}/groups/{group}/members"),
            body: Some(body_of(&serde_json::json!({ "membership_id": membership }))),
        },
        Case {
            label: "org_group_members.removeOrgGroupMember",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/groups/{group}/members/{membership}"),
            body: None,
        },
        Case {
            label: "org_role_assignments.assignOrgGroupRole",
            method: "POST",
            path: format!("{base}/organizations/{org}/groups/{group}/roles"),
            body: Some(role_ref.clone()),
        },
        Case {
            label: "org_role_assignments.unassignOrgGroupRole",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/groups/{group}/roles/{role}"),
            body: None,
        },
    ]
}

/// The MEMBERSHIP writes under an organization.
/// The personal-access-token writes. Their own function because they are not organization
/// membership cases and the list they were appended to had outgrown the length lint.
fn impersonation_cases(base: &str) -> Vec<Case> {
    vec![Case {
        label: "impersonation.authorizeUserImpersonation",
        method: "POST",
        path: format!("{base}/users/usr_absent/impersonation"),
        body: Some("{\"reason_code\":\"support_ticket\",\"reason_text\":\"absent\"}".to_owned()),
    }]
}

/// The `AuthZEN` PDP's two evaluation endpoints (issue #100).
///
/// They are POSTs that decide rather than write, but the property this file is about is the
/// one they share with every write: an absent environment must be refused by `resolve_scope`
/// before anything downstream runs. Both bodies are well formed and name an organization, so a
/// pass here is the SCOPE refusing and not the handler's own 400 for a malformed request.
fn authzen_cases(base: &str) -> Vec<Case> {
    let body = |batch: bool| {
        let mut request = serde_json::json!({
            "subject": { "type": "user", "id": "usr_absent" },
            "resource": { "type": "billing.invoice" },
            "action": { "name": "read" },
            "context": { "organization_id": "org_absent" },
        });
        if batch {
            request["evaluations"] = serde_json::json!([{}]);
        }
        Some(request.to_string())
    };
    vec![
        Case {
            label: "authzen.authzenEvaluation",
            method: "POST",
            path: format!("{base}/access/v1/evaluation"),
            body: body(false),
        },
        Case {
            label: "authzen.authzenEvaluations",
            method: "POST",
            path: format!("{base}/access/v1/evaluations"),
            body: body(true),
        },
    ]
}

fn personal_access_token_cases(base: &str) -> Vec<Case> {
    vec![
        Case {
            label: "personal_access_tokens.createUserPersonalAccessToken",
            method: "POST",
            path: format!("{base}/users/usr_absent/personal-access-tokens"),
            body: Some("{\"display_name\":\"absent\"}".to_owned()),
        },
        Case {
            label: "personal_access_tokens.rotateUserPersonalAccessToken",
            method: "POST",
            path: format!("{base}/users/usr_absent/personal-access-tokens/akey_absent/rotate"),
            body: None,
        },
        Case {
            label: "personal_access_tokens.revokeUserPersonalAccessToken",
            method: "DELETE",
            path: format!("{base}/users/usr_absent/personal-access-tokens/akey_absent"),
            body: None,
        },
    ]
}

fn org_membership_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids {
        user,
        org,
        role,
        membership,
        ..
    } = ids;
    let role_ref = body_of(&serde_json::json!({ "role_id": role }));
    vec![
        Case {
            label: "memberships.createMembership",
            method: "POST",
            path: format!("{base}/organizations/{org}/memberships"),
            body: Some(body_of(&serde_json::json!({ "user_id": user }))),
        },
        Case {
            label: "memberships.deleteMembership",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/memberships/{membership}"),
            body: None,
        },
        Case {
            label: "org_role_assignments.assignOrgMembershipRole",
            method: "POST",
            path: format!("{base}/organizations/{org}/memberships/{membership}/roles"),
            body: Some(role_ref),
        },
        Case {
            label: "org_role_assignments.unassignOrgMembershipRole",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/memberships/{membership}/roles/{role}"),
            body: None,
        },
        // Project grants (issue #102). The environment fence must answer BEFORE the
        // confinement fence these handlers add: an absent environment is not a place to
        // report that a credential is confined.
        // Enterprise inbound routing (issue #96).
        Case {
            label: "routing_rules.verifyRoutingRuleDomain",
            method: "POST",
            path: format!("{base}/routing-rules/rrl_absent/verify-domain"),
            body: None,
        },
        Case {
            label: "routing_rules.createRoutingRule",
            method: "POST",
            path: format!("{base}/routing-rules"),
            body: Some(
                "{\"kind\":\"domain\",\"value\":\"absent.example\",\"org_connection_id\":\"ocn_absent\"}"
                    .to_owned(),
            ),
        },
        Case {
            label: "api_keys.rotateOrganizationApiKey",
            method: "POST",
            path: format!("{base}/organizations/{org}/api-keys/akey_absent/rotate"),
            body: None,
        },
        Case {
            label: "api_keys.revokeOrganizationApiKey",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/api-keys/akey_absent"),
            body: None,
        },
        Case {
            label: "api_keys.createOrganizationApiKey",
            method: "POST",
            path: format!("{base}/organizations/{org}/api-keys"),
            body: Some("{\"display_name\":\"absent\"}".to_owned()),
        },
        // The service-account surface is NOT nested under an organization, so its cases
        // address the environment directly. The principal id is a literal that names nothing;
        // the point of the sweep is that the absent ENVIRONMENT is refused before the path
        // gets far enough for that to matter.
        Case {
            label: "service_account_keys.createServiceAccountApiKey",
            method: "POST",
            path: format!("{base}/service-accounts/sva_absent/api-keys"),
            body: Some("{\"display_name\":\"absent\"}".to_owned()),
        },
        Case {
            label: "service_account_keys.rotateServiceAccountApiKey",
            method: "POST",
            path: format!("{base}/service-accounts/sva_absent/api-keys/akey_absent/rotate"),
            body: None,
        },
        Case {
            label: "service_account_keys.revokeServiceAccountApiKey",
            method: "DELETE",
            path: format!("{base}/service-accounts/sva_absent/api-keys/akey_absent"),
            body: None,
        },
        Case {
            label: "project_grants.createProjectGrant",
            method: "POST",
            path: format!("{base}/organizations/{org}/project-grants"),
            body: Some("{\"client_id\":\"cli_absent\",\"role_ids\":[]}".to_owned()),
        },
        Case {
            label: "project_grants.withdrawProjectGrant",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/project-grants/pgt_absent"),
            body: None,
        },
    ]
}

/// The ROLE writes under an organization, and the role-to-permission mapping.
fn org_role_cases(base: &str, ids: &Ids) -> Vec<Case> {
    let Ids {
        org,
        role,
        permission,
        ..
    } = ids;
    let named = body_of(&serde_json::json!({ "slug": "sweep", "display_name": "Sweep" }));
    let relabel = body_of(&serde_json::json!({ "display_name": "Sweep" }));
    vec![
        Case {
            label: "org_roles.createOrgRole",
            method: "POST",
            path: format!("{base}/organizations/{org}/roles"),
            body: Some(named),
        },
        Case {
            label: "org_roles.updateOrgRole",
            method: "PATCH",
            path: format!("{base}/organizations/{org}/roles/{role}"),
            body: Some(relabel),
        },
        Case {
            label: "org_roles.deleteOrgRole",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/roles/{role}"),
            body: None,
        },
        Case {
            label: "org_role_permissions.assignOrgRolePermission",
            method: "POST",
            path: format!("{base}/organizations/{org}/roles/{role}/permissions"),
            body: Some(body_of(&serde_json::json!({ "permission_id": permission }))),
        },
        Case {
            label: "org_role_permissions.unassignOrgRolePermission",
            method: "DELETE",
            path: format!("{base}/organizations/{org}/roles/{role}/permissions/{permission}"),
            body: None,
        },
    ]
}

/// Every environment-scoped write in the management surface, addressed at
/// `environment`.
fn all_cases(tenant: &str, environment: &str) -> Vec<Case> {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let ids = Ids::mint(tenant, environment);
    let mut cases = abuse_and_sudo_cases(&base);
    cases.extend(flow_target_cases(&base));
    cases.extend(external_issuer_cases(&base));
    cases.extend(log_stream_cases(&base));
    cases.extend(message_cases(&base));
    cases.extend(client_cases(&base, &ids));
    cases.extend(claims_mapping_cases(&base, &ids));
    cases.extend(secret_cases(&base));
    cases.extend(posture_cases(&base, &ids));
    cases.extend(config_and_connector_cases(&base, &ids));
    cases.extend(environment_child_cases(&base, &ids));
    cases.extend(resource_cases(&base, &ids));
    cases.extend(user_cases(&base, &ids));
    cases.extend(organization_cases(&base, &ids));
    cases.extend(org_membership_cases(&base, &ids));
    cases.extend(personal_access_token_cases(&base));
    cases.extend(impersonation_cases(&base));
    cases.extend(authzen_cases(&base));
    cases.extend(org_role_cases(&base, &ids));
    cases
}

/// Drive one case with the bootstrap operator token, carrying an Idempotency-Key on
/// every request (the routes that require one get it; the rest ignore it).
async fn drive(h: &Harness, case: &Case, key: &str) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(case.method)
        .uri(&case.path)
        .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
        .header("idempotency-key", key);
    if case.body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let request = builder
        .body(case.body.clone().map_or_else(Body::empty, Body::from))
        .expect("request builds");
    let (status, _, body) = h.send(request).await;
    (status, body)
}

/// The ONE route whose answer at an absent environment is not the uniform not-found, and
/// the reason it is exempt. It is listed rather than silently tolerated: a route that
/// stops matching its entry, or a NEW route that answers anything but the not-found,
/// fails the sweep and gets a decision.
///
/// Two entries that USED to be here are gone, and both were removed by changing the
/// server rather than by writing a better justification:
///
/// - `consents.revokeUserConsent` answered 200 `{"revoked":false}` and wrote nothing,
///   which was safe but told an operator with a mistyped environment id that there was
///   nothing to revoke. It now carries the precondition.
/// - `signing_algorithm.setClientSigningAlgorithm` was pinned at 422 with the reasoning
///   that an environment which does not exist signs nothing. That pin was an artifact of
///   [`Harness::start`], which installs NO issuer registry, so a LIVE environment answers
///   the identical 422 there and the pin measured nothing about the environment. Driven
///   under `start_with_signing_registry` with the scope fully provisioned, an absent
///   environment answered 422 while a malformed one answered 404, which made it the one
///   place on this surface where the two were distinguishable. It now carries the
///   precondition, and
///   [`the_signing_algorithm_pin_refuses_an_absent_environment_under_an_armed_registry`]
///   drives it under the armed harness so the change is measured where the defect lived.
fn documented_exceptions() -> BTreeMap<&'static str, StatusCode> {
    BTreeMap::from([
        // A pure evaluation of the shipped policies against a submitted hypothetical.
        // It reads no row and writes none (its own test snapshots every table to prove
        // that), so there is nothing for the environment to be the parent OF, and
        // refusing would make the inspector unusable for planning an environment that
        // does not exist yet.
        ("diagnostics.postFlowDryRun", StatusCode::OK),
    ])
}

/// The routes whose LIVE answer is pinned exactly, rather than merely checked for being
/// routed at the method this sweep drives.
///
/// These two entries were both pinned at 500 when this file was written, because
/// `createBan` and `liftBan` were DEAD on this plane rather than merely unsatisfied by the
/// fixture: the relation behind them was granted to the data-plane role alone while the
/// management surface connects as the control role, so both were refused by Postgres for a
/// LIVE environment and an absent one alike. Issue #441 settled that (migration 0098), and
/// the pins now carry the answers a live environment actually gives.
///
/// The mechanism did exactly what it was put here to do. The comment it replaces said that
/// the day the grant changed this test would go red and force the answers to be
/// re-derived, and that is how the change was noticed. Keeping the pins, rather than
/// deleting them along with the deadness they described, is what keeps that true for the
/// next change.
fn documented_live_answers() -> BTreeMap<&'static str, StatusCode> {
    BTreeMap::from([
        ("bans.createBan", StatusCode::CREATED),
        ("bans.liftBan", StatusCode::OK),
    ])
}

#[test]
fn every_documented_environment_scoped_write_is_driven_by_a_case() {
    // The guard on the guard, and the finding that motivated it: the case list below was
    // hand-maintained, so deleting an entry outright left the suite GREEN and the list
    // had drifted to 73 of the 75 environment-scoped writes the published contract
    // defines (`setBrandLogo` and `setBrandFavicon` were never driven). A sweep whose
    // completeness nothing checks reports on whatever it happens to contain.
    //
    // This resolves every case against the COMMITTED contract by method and templated
    // path, and then requires the two sets to agree exactly. It needs no database, so it
    // is the cheapest thing in the file and the first thing to fail.
    let env = Env::system();
    let tenant = TenantId::generate(&env).to_string();
    let environment = EnvironmentId::generate(&env).to_string();
    let cases = all_cases(&tenant, &environment);
    let documented = documented_environment_writes();

    // 1. Every case addresses exactly ONE documented operation. A case whose path has a
    //    typo in a LITERAL segment matches no template at all and fails here, which is
    //    the hole a status-only sweep cannot see: axum answers an unrouted path with a
    //    404, the same status the uniform not-found carries.
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for case in &cases {
        let addressed: Vec<&DocumentedWrite> = documented
            .iter()
            .filter(|write| {
                write.method == case.method && template_matches(&write.template, &case.path)
            })
            .collect();
        let named: Vec<&str> = addressed
            .iter()
            .map(|write| write.operation_id.as_str())
            .collect();
        assert_eq!(
            addressed.len(),
            1,
            "{} drives {} {}, which addresses {} documented operations rather than exactly one: {named:?}",
            case.label,
            case.method,
            case.path,
            addressed.len()
        );
        let operation = addressed[0].operation_id.clone();
        assert!(
            case.label.ends_with(&format!(".{operation}")),
            "the case label `{}` must name the operation it actually drives (`{operation}`)",
            case.label
        );
        assert!(
            covered.insert(operation.clone()),
            "{operation} is driven by more than one case"
        );
    }

    // 2. And every documented operation is driven by a case. This is the direction that
    //    makes a NEW environment-scoped write fail the sweep the moment it is documented,
    //    rather than being silently absent from it.
    let published: BTreeSet<String> = documented
        .iter()
        .map(|write| write.operation_id.clone())
        .collect();
    let undriven: Vec<&String> = published.difference(&covered).collect();
    assert!(
        undriven.is_empty(),
        "the committed contract publishes {} environment-scoped writes and this sweep drives {}; \
         add a case for each of these before the sweep can claim to cover the surface: {undriven:?}",
        published.len(),
        covered.len()
    );
}

#[tokio::test]
async fn every_environment_scoped_write_at_an_absent_environment_is_the_uniform_not_found() {
    // The whole-surface guard, and the measurement that decided this issue's size. It
    // drives EVERY environment-scoped write twice: once at a live environment, then once
    // at a well-formed environment id that was never created.
    let h = Harness::start(50).await;
    let (tenant, live) = h.create_tenant("sweep", "k-tenant").await;
    let absent = EnvironmentId::generate(&Env::system()).to_string();

    // The live pass. Most statuses are not asserted one by one (many of these routes need
    // a parent this fixture does not create, and their own test files own those
    // contracts); what it establishes is that the same route set was exercised against a
    // REAL environment, so the snapshot taken after it is a settled baseline and the
    // absent pass below is the only thing that could move it. The routes in
    // `documented_live_answers` are the exception and are pinned exactly.
    let live_answers = documented_live_answers();
    for (index, case) in all_cases(&tenant, &live).iter().enumerate() {
        let (status, body) = drive(&h, case, &format!("k-live-{index}")).await;
        if let Some(&expected) = live_answers.get(case.label) {
            assert_eq!(
                status, expected,
                "{} answered {status} at a LIVE environment; its pinned answer is {expected} \
                 (see documented_live_answers): {body}",
                case.label
            );
        } else {
            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{} is not routed at the method this sweep drives: {body}",
                case.label
            );
        }
        // No route may answer a server error at a LIVE environment, whatever else it
        // answers. This is the property the two ban entries above used to violate, and
        // leaving it unasserted is how they got to a release: a dead surface looks
        // identical to a healthy one in a pass that only checks the route is wired.
        // `tests/live_surface.rs` owns the whole-surface version of this, GETs included;
        // the one line here keeps the sibling sweep from re-introducing what it found.
        assert!(
            !status.is_server_error(),
            "{} answered a server error at a LIVE environment: {status} {body}",
            case.label
        );
    }

    let before = snapshot(h.db().owner_pool()).await;

    // The reference answer, rendered from `ApiError::NotFound` itself. Every refusal below
    // must match it in STATUS AND BODY: a status-only assertion passes on axum's bare 404
    // for a path that matched no route at all, so a case whose path drifted would stop
    // measuring anything while staying green.
    let (not_found_status, not_found_body) = uniform_not_found().await;

    let exceptions = documented_exceptions();
    let mut observed: Vec<String> = Vec::new();
    for (index, case) in all_cases(&tenant, &absent).iter().enumerate() {
        let (status, body) = drive(&h, case, &format!("k-absent-{index}")).await;
        observed.push(format!("{} {} -> {status}", case.method, case.label));
        assert!(
            !status.is_server_error(),
            "{} answered a server error for an absent environment: {status} {body}",
            case.label
        );
        if let Some(&expected) = exceptions.get(case.label) {
            assert_eq!(
                status, expected,
                "{} answered {status}, expected the documented exception {expected}: {body}",
                case.label
            );
        } else {
            assert_eq!(
                status, not_found_status,
                "{} answered {status}, expected the uniform not-found: {body}",
                case.label
            );
            assert_eq!(
                body, not_found_body,
                "{} answered the uniform not-found STATUS with a different body, which is what \
                 an unrouted path looks like; check the case's path against the contract",
                case.label
            );
        }
    }

    // Nothing the absent pass touched wrote a row ANYWHERE, audit log included. This is
    // read as the database owner, so row-level security cannot hide a write, and it
    // covers the one documented exception as well as every refusal.
    let after = snapshot(h.db().owner_pool()).await;
    assert_eq!(
        before,
        after,
        "a write into an absent environment landed a row:\n{}",
        observed.join("\n")
    );
}

/// Drive one route at the MALFORMED environment segment and then at an ABSENT one, and
/// assert the two answers are byte identical and that neither wrote a row anywhere. The
/// malformed segment is refused by `resolve_scope`'s parse alone, so it is the reference
/// the absent case must be indistinguishable from.
async fn assert_absent_matches_malformed(
    h: &Harness,
    tenant: &str,
    absent: &str,
    method: &'static str,
    suffix: &str,
    body: Option<&str>,
) {
    let malformed_case = Case {
        label: "malformed",
        method,
        path: format!("/v1/tenants/{tenant}/environments/{MALFORMED_ENVIRONMENT}{suffix}"),
        body: body.map(ToOwned::to_owned),
    };
    let absent_case = Case {
        label: "absent",
        method,
        path: format!("/v1/tenants/{tenant}/environments/{absent}{suffix}"),
        body: body.map(ToOwned::to_owned),
    };

    let before = snapshot(h.db().owner_pool()).await;
    let (malformed_status, malformed_body) = drive(h, &malformed_case, "k-malformed").await;
    assert_eq!(
        malformed_status,
        StatusCode::NOT_FOUND,
        "a malformed environment segment is the uniform not-found: {malformed_body}"
    );

    let (status, response) = drive(h, &absent_case, "k-absent").await;
    assert_eq!(
        status, malformed_status,
        "{method} {suffix} at an absent environment must not be a server error: {response}"
    );
    assert_eq!(
        response, malformed_body,
        "{method} {suffix} must give the SAME answer as a malformed segment"
    );

    // Neither refusal wrote anything: no resource row, and no audit row.
    let after = snapshot(h.db().owner_pool()).await;
    assert_eq!(
        before, after,
        "{method} {suffix} wrote a row while refusing an absent environment"
    );
}

/// A tenant, its live environment, and a well-formed environment id under the same
/// tenant that was never created.
async fn fixture(h: &Harness) -> (String, String, String) {
    let (tenant, live) = h.create_tenant("acme", "k-tenant").await;
    let absent = EnvironmentId::generate(&Env::system()).to_string();
    (tenant, live, absent)
}

#[tokio::test]
async fn placing_a_ban_in_an_absent_environment_is_the_uniform_not_found() {
    // MEASURED before the precondition existed: a 500. A ban SUBJECT is PII, so placing
    // one seals it, and sealing mints the scope's envelope key into `tenant_keks`, whose
    // composite foreign key to `environments` is the constraint the write violated.
    //
    // There is no live positive control on this route, and that is a finding rather than
    // an omission: `abuse_bans` is granted to `ironauth_app` only (migration 0046) while
    // the management plane connects as `ironauth_control`, so createBan and liftBan
    // answer 500 for a LIVE environment too, with a `42501` insufficient-privilege refusal
    // on `abuse_bans`. That is a separate, pre-existing defect on this surface, out of
    // this issue's scope, and not what the assertions below are about. Issue #441 records it,
    // and the sweep's live pass PINS the 500 (`documented_live_answers`) so this
    // paragraph cannot quietly stop being true.
    let h = Harness::start(50).await;
    let (tenant, _live, absent) = fixture(&h).await;
    let body = body_of(&serde_json::json!({
        "subject_kind": "ip", "subject": "203.0.113.7", "auth_path": "password"
    }));
    assert_absent_matches_malformed(&h, &tenant, &absent, "POST", "/abuse/bans", Some(&body)).await;
}

#[tokio::test]
async fn lifting_a_ban_in_an_absent_environment_is_the_uniform_not_found() {
    // Unlike its sibling, the lift's precondition is FUTURE PROOFING and not a repair,
    // and this test asserts the uniform answer without claiming a measurement that was
    // never taken.
    //
    // Neutering the precondition does NOT restore a 500 attributable to the environment:
    // the lift opens with a scoped SELECT over `abuse_bans`, which is granted to
    // `ironauth_app` alone (migration 0046) while this plane connects as
    // `ironauth_control`, so a `42501` insufficient-privilege refusal naming `abuse_bans`
    // comes back for a LIVE environment and an absent one alike. The environment's absence is
    // MASKED behind that grant gap, which issue #441 records. What the assertions below
    // pin is the answer the route must give once the precondition is reached, which is
    // the same uniform not-found a malformed segment gets, byte for byte.
    let h = Harness::start(50).await;
    let (tenant, _live, absent) = fixture(&h).await;
    let body = body_of(&serde_json::json!({
        "subject_kind": "ip", "subject": "203.0.113.7", "auth_path": "password"
    }));
    assert_absent_matches_malformed(
        &h,
        &tenant,
        &absent,
        "POST",
        "/abuse/bans/lift",
        Some(&body),
    )
    .await;
}

#[tokio::test]
async fn revoking_a_session_in_an_absent_environment_is_the_uniform_not_found() {
    // MEASURED before the precondition existed: a 500 from
    // `audit_log_environment_id_tenant_id_fkey`. A revoke is deliberately idempotent
    // over the session (an absent session is a 200), so the AUDIT row is the first thing
    // to reach a constraint and the environment is the only absence the caller can see.
    let h = Harness::start(50).await;
    let (tenant, live, absent) = fixture(&h).await;

    // The positive control, first: the same route against the live environment revokes
    // and answers 200, so the refusal below is attributable to the environment.
    let session = h
        .seed_session(scope_of(&tenant, &live), "usr-control")
        .await;
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{live}/sessions/{session}/revoke"),
            "k-control",
            "{}",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the live revoke still works: {body}"
    );

    let absent_session = SessionId::generate(&Env::system(), &scope_of(&tenant, &absent));
    assert_absent_matches_malformed(
        &h,
        &tenant,
        &absent,
        "POST",
        &format!("/sessions/{absent_session}/revoke"),
        Some("{}"),
    )
    .await;
}

#[tokio::test]
async fn bulk_revoking_sessions_in_an_absent_environment_is_the_uniform_not_found() {
    // The batch reaches the same audit row as the single revoke, and MEASURED the same
    // 500.
    let h = Harness::start(50).await;
    let (tenant, live, absent) = fixture(&h).await;

    // The positive control: a batch against the live environment is accepted.
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{live}/sessions/revoke"),
            "k-control",
            "{\"session_ids\":[]}",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the live batch still works: {body}");

    assert_absent_matches_malformed(
        &h,
        &tenant,
        &absent,
        "POST",
        "/sessions/revoke",
        Some("{\"session_ids\":[]}"),
    )
    .await;
}

#[tokio::test]
async fn revoking_a_users_sessions_in_an_absent_environment_is_the_uniform_not_found() {
    // This route never reads the user (revoking every session of a subject that owns
    // none is a legitimate no-op), so the audit row was the first thing to reach the
    // foreign key and an absent environment MEASURED as a 500.
    let h = Harness::start(50).await;
    let (tenant, live, absent) = fixture(&h).await;
    let live_user = UserId::generate(&Env::system(), &scope_of(&tenant, &live));

    // The positive control: the same shape against the live environment is accepted.
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{live}/users/{live_user}/sessions/revoke"),
            "k-control",
            "{}",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the live user revoke still works: {body}"
    );

    let absent_user = UserId::generate(&Env::system(), &scope_of(&tenant, &absent));
    assert_absent_matches_malformed(
        &h,
        &tenant,
        &absent,
        "POST",
        &format!("/users/{absent_user}/sessions/revoke"),
        Some("{}"),
    )
    .await;
}

#[tokio::test]
async fn linking_an_external_id_in_an_absent_environment_is_the_uniform_not_found() {
    // MEASURED before the precondition existed: a 500 carrying the store's envelope
    // failure. An external id is PII, so linking one seals it, and the seal resolves the
    // scope's envelope key BEFORE the user is looked up, which is why this route alone
    // among the user routes could not fall through to the user's own not-found.
    let h = Harness::start(50).await;
    let (tenant, live, absent) = fixture(&h).await;

    // The positive control: a real user in the live environment, whose external id the
    // same route links. It is created through the API rather than seeded because the
    // create is what mints the scope's envelope key, and the seal this route performs
    // needs one.
    let (status, _, created) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{live}/users"),
            "k-user",
            "{\"identifier\":\"ada@example.test\"}",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create the control user: {created}"
    );
    let live_user = serde_json::from_str::<serde_json::Value>(&created).expect("json")["id"]
        .as_str()
        .expect("user id")
        .to_owned();
    let (status, _, body) = h
        .put(
            &format!("/v1/tenants/{tenant}/environments/{live}/users/{live_user}/external-id"),
            "{\"external_id\":\"ext-1\"}",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the live link still works: {body}");

    // And an absent USER in that same live environment is the user's own not-found, so
    // the refusal below is attributable to the ENVIRONMENT and not to the user.
    let absent_live_user = UserId::generate(&Env::system(), &scope_of(&tenant, &live));
    let (status, _, body) = h
        .put(
            &format!(
                "/v1/tenants/{tenant}/environments/{live}/users/{absent_live_user}/external-id"
            ),
            "{\"external_id\":\"ext-2\"}",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an absent user in a LIVE environment is the user's not-found, never a 500: {body}"
    );

    let absent_user = UserId::generate(&Env::system(), &scope_of(&tenant, &absent));
    assert_absent_matches_malformed(
        &h,
        &tenant,
        &absent,
        "PUT",
        &format!("/users/{absent_user}/external-id"),
        Some("{\"external_id\":\"ext-1\"}"),
    )
    .await;
}

#[tokio::test]
async fn elevating_sudo_in_an_absent_environment_is_the_uniform_not_found() {
    // The one route the DEFAULT sweep cannot reach: sudo mode is off by default, and a
    // disabled deployment answers the uniform not-found before it resolves anything, so
    // the absent environment is invisible behind the flag. Driven ARMED it MEASURED a
    // 500 from `admin_sudo_elevations_environment_id_tenant_id_fkey`.
    let (h, _clock) = Harness::start_with_sudo(300).await;
    let (tenant, live) = h.create_tenant("acme", "k-tenant").await;
    let absent = EnvironmentId::generate(&Env::system()).to_string();

    // The positive control: armed, the live environment elevates.
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{live}/admin/sudo/elevate"),
            "k-control",
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the live elevation works: {body}");

    assert_absent_matches_malformed(&h, &tenant, &absent, "POST", "/admin/sudo/elevate", None)
        .await;
}

#[tokio::test]
async fn a_soft_deleted_environment_reads_exactly_like_an_absent_one() {
    // The behavior the precondition CHANGES, asserted rather than left to be discovered.
    // A soft delete leaves the `environments` row in place, so the foreign key stayed
    // satisfied and these writes LANDED into a deleted environment. The precondition
    // resolves the environment through the repository's own `get`, which filters
    // `deleted_at`, so a deleted environment now reads exactly like one that never
    // existed. That is the choice `permissions.rs` and `keys.rs` already made, and it is
    // the one an operator winding an environment down needs: a deleted environment
    // accepts no new state.
    let h = Harness::start(50).await;
    let (tenant, _live) = h.create_tenant("acme", "k-tenant").await;
    let doomed = h.create_environment(&tenant, "doomed", "k-env-2").await;
    let session = h
        .seed_session(scope_of(&tenant, &doomed), "usr-doomed")
        .await;

    // Before the delete the revoke is accepted.
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{doomed}/sessions/{session}/revoke"),
            "k-before",
            "{}",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, _) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{doomed}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the environment is deleted");

    let (malformed_status, _, malformed_body) = h
        .post(
            &format!(
                "/v1/tenants/{tenant}/environments/{MALFORMED_ENVIRONMENT}/sessions/{session}/revoke"
            ),
            "k-malformed",
            "{}",
        )
        .await;
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{doomed}/sessions/{session}/revoke"),
            "k-after",
            "{}",
        )
        .await;
    assert_eq!(
        status, malformed_status,
        "a deleted environment is the same answer as a malformed one: {body}"
    );
    assert_eq!(body, malformed_body, "and it is byte identical");
}

#[tokio::test]
async fn a_replay_survives_the_environment_going_away() {
    // The ORDERING the precondition must respect, and the only thing that pins it. The
    // Idempotency-Key replay runs BEFORE the environment-existence check, so a genuine
    // retry of a request that ALREADY SUCCEEDED returns the original response even
    // though the environment has since been deleted. Moving the check ahead of the
    // replay would turn that retry into a 404, which a client cannot tell from "my
    // revocation never landed".
    let h = Harness::start(50).await;
    let (tenant, _live) = h.create_tenant("acme", "k-tenant").await;
    let doomed = h.create_environment(&tenant, "doomed", "k-env-2").await;
    let session = h
        .seed_session(scope_of(&tenant, &doomed), "usr-doomed")
        .await;
    let path = format!("/v1/tenants/{tenant}/environments/{doomed}/sessions/{session}/revoke");

    let (status, _, first) = h.post(&path, "k-replay", "{}").await;
    assert_eq!(status, StatusCode::OK, "{first}");

    let (status, _, _) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{doomed}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the environment is deleted");

    let (status, _, replay) = h.post(&path, "k-replay", "{}").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a replay must survive the parent going away: {replay}"
    );
    assert_eq!(first, replay, "and it is byte identical to the original");
}

/// The current instant in Unix microseconds, through the environment's clock seam.
fn now_micros() -> i64 {
    let env = Env::system();
    i64::try_from(
        ironauth_env::Clock::now_utc(env.clock())
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Why every ARMED test in this file opens with a positive control.
///
/// The two review queues and the compatibility wizard are all DISABLED by default, and a
/// disabled surface answers the uniform not-found BEFORE it resolves anything. That
/// refusal is BYTE IDENTICAL to the absent-environment refusal these tests exist to pin,
/// so a test that only drives the absent case passes just as well with the flag OFF, and
/// its name is then asserted by nothing. That was measured rather than supposed: flipping
/// `start_with_signup_quarantine(50, true)` and `start_with_advanced_recovery(50, true)`
/// to `false` left the original combined test green.
///
/// The control closes it. Each test drives the SAME route at the LIVE environment against
/// a REAL queued case and requires a non-404, which only an armed deployment can produce.
/// With that established, the refusal at the absent environment is attributable to the
/// environment rather than to the flag. `Harness::start_with_sudo` is the pattern being
/// copied: it is why the sudo precondition is genuinely pinned even though the sweep's own
/// sudo case is masked by the disabled flag.
#[tokio::test]
async fn the_signup_quarantine_queue_refuses_an_absent_environment_when_armed() {
    let env = Env::system();
    let quarantine = Harness::start_with_signup_quarantine(50, true).await;
    let (tenant, live, absent) = fixture(&quarantine).await;
    let queued = quarantine
        .store()
        .scoped(scope_of(&tenant, &live))
        .acting(quarantine.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .register_quarantined(
            &env,
            "risky@example.test",
            "$argon2id$dummy",
            SignupQuarantineReason::RiskOutput,
            None,
        )
        .await
        .expect("seed a quarantined signup");
    let (status, _, body) = quarantine
        .post(
            &format!("/v1/tenants/{tenant}/environments/{live}/signup-quarantine/{queued}/approve"),
            "k-armed-control",
            "",
        )
        .await;
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "the signup-quarantine queue must be ARMED for the refusals below to mean anything, \
         and a 404 here is what the DISABLED flag answers: {body}"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "the armed queue releases a real quarantined signup: {body}"
    );

    let user = UserId::generate(&env, &scope_of(&tenant, &absent));
    for (action, body) in [
        ("approve", None),
        ("reject", None),
        ("extend", Some("{\"extend_secs\":3600}")),
    ] {
        assert_absent_matches_malformed(
            &quarantine,
            &tenant,
            &absent,
            "POST",
            &format!("/signup-quarantine/{user}/{action}"),
            body,
        )
        .await;
    }
}

/// The recovery-approval half of the same contract, under the same positive-control rule
/// recorded on [`the_signup_quarantine_queue_refuses_an_absent_environment_when_armed`].
#[tokio::test]
async fn the_recovery_approval_queue_refuses_an_absent_environment_when_armed() {
    let env = Env::system();
    let recovery = Harness::start_with_advanced_recovery(50, true).await;
    let (tenant, live, absent) = fixture(&recovery).await;
    let live_scope = scope_of(&tenant, &live);
    // A HELD admin-approved flow whose delay window has already elapsed, plus its pending
    // approval row: the shape the review queue exists to decide.
    let subject = UserId::generate(&env, &live_scope);
    let held = RecoveryFlowId::generate(&env, &live_scope);
    let digest = vec![7_u8; 32];
    recovery
        .store()
        .scoped(live_scope)
        .acting(recovery.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .initiate(
            &env,
            NewRecoveryFlow {
                id: &held,
                subject: &subject,
                entry_point: RecoveryEntryPoint::LostAllFactors,
                recover_acr: "urn:ironauth:acr:pwd",
                cancel_token_digest: &digest,
                recipient: "recover@example.test",
                hold_until_unix_micros: Some(now_micros() - 1_000_000),
                method: RecoveryMethod::AdminApproved,
            },
            0,
        )
        .await
        .expect("seed the recovery flow");
    recovery
        .store()
        .scoped(live_scope)
        .acting(recovery.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .open(&env, &held, &subject)
        .await
        .expect("open the pending approval");
    let (status, _, body) = recovery
        .post(
            &format!("/v1/tenants/{tenant}/environments/{live}/recovery-approvals/{held}/approve"),
            "k-armed-control",
            "",
        )
        .await;
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "the recovery-approval queue must be ARMED for the refusals below to mean anything, \
         and a 404 here is what the DISABLED flag answers: {body}"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "the armed queue approves a real held recovery: {body}"
    );

    let flow = RecoveryFlowId::generate(&env, &scope_of(&tenant, &absent));
    for action in ["approve", "reject"] {
        assert_absent_matches_malformed(
            &recovery,
            &tenant,
            &absent,
            "POST",
            &format!("/recovery-approvals/{flow}/{action}"),
            None,
        )
        .await;
    }
}

#[tokio::test]
async fn the_signing_algorithm_pin_refuses_an_absent_environment_under_an_armed_registry() {
    // The route whose sweep entry USED to be a documented 422 exception, re-driven where
    // the exception could actually be examined.
    //
    // Under `Harness::start` the state holds NO issuer registry, so layer 2 fails closed
    // at 422 for EVERY environment, live or not, and pinning the absent case at 422 there
    // measured the harness rather than the server. Under an ARMED registry with the live
    // scope fully provisioned the three answers separate: a live environment with an
    // absent CLIENT is the client's own not-found, a malformed environment segment is the
    // uniform not-found, and an absent environment WAS the 422. That made this the one
    // environment-scoped write where an absent environment was distinguishable from a
    // malformed one, which is precisely the property the rest of this file rules out, so
    // the route now carries the same precondition and answers the uniform not-found.
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, live, absent) = fixture(&h).await;
    let live_scope = scope_of(&tenant, &live);
    h.provision_all_algorithms(live_scope).await;
    let body = body_of(&serde_json::json!({ "algorithm": "EdDSA" }));

    // The positive control that the registry is genuinely armed for this scope: a REAL
    // client in the live environment takes the pin. Without it, every assertion below
    // would pass just as well against the registry-less harness that produced the
    // original 422, and the test would be measuring nothing again.
    let client = h.seed_quarantined_dcr_client(live_scope).await;
    let (status, _, response) = h
        .put_with_key(
            &format!("/v1/tenants/{tenant}/environments/{live}/clients/{client}/signing-algorithm"),
            "k-armed-control",
            &body,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the armed registry pins a real client's algorithm, so layer 2 resolves here: {response}"
    );

    // A live environment with an ABSENT client is the CLIENT's not-found, so the refusal
    // below is attributable to the environment and not to the client.
    let absent_client = Harness::fresh_client_id(live_scope);
    let (status, _, response) = h
        .put_with_key(
            &format!(
                "/v1/tenants/{tenant}/environments/{live}/clients/{absent_client}/signing-algorithm"
            ),
            "k-absent-client",
            &body,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an absent client in a LIVE environment is the client's not-found: {response}"
    );

    let scoped_client = ClientId::generate(&Env::system(), &scope_of(&tenant, &absent));
    assert_absent_matches_malformed(
        &h,
        &tenant,
        &absent,
        "PUT",
        &format!("/clients/{scoped_client}/signing-algorithm"),
        Some(&body),
    )
    .await;
}
