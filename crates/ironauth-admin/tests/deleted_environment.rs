// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SOFT-DELETED-ENVIRONMENT contract for the organization surface (issue #411).
//!
//! Deleting an environment does not cascade to its organizations: the
//! `organizations` rows keep their own live `deleted_at IS NULL`, so
//! `org_context::resolve_live_org` still resolved and every write nested under
//! `/organizations/{organization_id}` still LANDED in an environment an operator
//! believed they had decommissioned. `POST .../permissions` refused the same request,
//! because issue #98 PR 7 gave the environment-scoped vocabulary create a
//! `require_live_environment` precondition for an unrelated reason. The tree therefore
//! had two answers to "may I write into a deleted environment", decided by which route
//! the caller happened to pick.
//!
//! # The policy this file pins
//!
//! A WRITE addressed at an organization refuses, with the uniform not-found. A READ
//! keeps working.
//!
//! The split is not incidental. It is the same line issue #409 drew when it made an
//! ABSENT environment the uniform not-found: that sweep enumerates every NON-GET
//! operation under the environment prefix and fences exactly those, and every GET on
//! the surface is deliberately outside it. An operator who decommissions an
//! environment still has to be able to see what is inside it, and the resurrection
//! question this issue raises (a restored environment comes back carrying whatever was
//! written while it was deleted) is only auditable if the listings still answer.
//! Refusing reads too would close nothing that the write fence does not already close,
//! and would make the decommissioned environment unauditable.
//!
//! # Why this file sweeps rather than testing a handful of handlers
//!
//! The issue names "roles, groups, group members, role assignments, memberships and
//! invitations, plus the two surfaces #98 added". That list is wrong in both
//! directions, which is why nothing here trusts it. Invitations are not nested under an
//! organization at all. The organization's OWN lifecycle writes (`deleteOrganization`,
//! `disableOrganization`, `enableOrganization`) are nested under it and were affected,
//! and a grep for `resolve_live_org` would have missed all three because they addressed
//! their organization with a bare `parse_id`; they resolve through it now. The
//! `default-role` pair was affected too and is named nowhere in the issue.
//!
//! The set is taken from the COMMITTED contract instead:
//! [`every_documented_organization_operation_is_driven_by_a_case`] reads
//! `docs/openapi/management.json`, enumerates every operation whose templated path
//! starts with the organization prefix, resolves each case against it by method and
//! path, and fails when the two sets disagree in EITHER direction. A new
//! organization-nested route therefore fails this file the moment it is documented,
//! and a case whose path drifts matches no template and fails too.
//!
//! # Why the sweep cannot pass vacuously
//!
//! Every case is driven TWICE, against two identically seeded fixtures. The LIVE pass
//! pins each case's answer at a live environment EXACTLY, so a case whose body or path
//! could never have been satisfied fails there rather than passing the deleted pass by
//! being broken. The DELETED pass then requires the uniform not-found for every write,
//! byte for byte against the status, headers and body `ApiError::NotFound` itself
//! renders (a status-only assertion would pass on axum's bare 404 for a path that
//! matched no route), the LIVE answer for every read, and an unchanged row count for
//! every table in the database.
//!
//! A read is required to NAME its rows and not merely to answer 200, in both passes.
//! That is not belt and braces: the reads are here because a decommissioned environment
//! has to stay auditable, and a 200 carrying an empty page is not an audit.
//! `list_memberships` returning `Vec::new()` used to leave this whole file green.
//!
//! # This file is the ORGANIZATION subtree of a larger contract
//!
//! Issue #451 found that the same defect ran through twenty six more writes, spread over
//! fourteen handler modules and twelve URL groups, none of them the organization subtree
//! this file drives. The whole-prefix version of this sweep is
//! `live_surface::every_environment_scoped_write_refuses_a_soft_deleted_environment`,
//! which drives all the documented environment-scoped writes rather than the
//! organization-addressed ones here. This file stays, and is not redundant with it, because it pins two
//! things that one does not pin as far. It requires EVERY read in its subtree to NAME its
//! rows rather than merely to answer 200, where the whole-prefix sweep requires that of a
//! named subset (`getUser`, `listUsers` and `listUserConsents`) and compares only the
//! status of the rest; and it requires the keyed writes' idempotent replay to survive the
//! deletion, which nothing else measures.
//!
//! # What this file assumes about the configuration
//!
//! Everything here is driven at the DEFAULT configuration, in which sudo mode is off.
//! With sudo mode armed, `sudo::require_fresh_privilege` runs BEFORE the environment
//! precondition in every write it drives, so a caller whose elevation has lapsed is
//! answered 401 `insufficient_user_authentication` and the environment is never read at
//! all. The property that matters survives that, because an ABSENT environment answers a
//! lapsed elevation identically and the two therefore stay indistinguishable; what does
//! not survive is the claim that the answer is THIS not-found.
//!
//! The challenge path also writes an `admin.privilege.challenged` row into the
//! decommissioned environment's `audit_log` (MEASURED: three rows to four). Issue #452
//! asked whether the ordering should move ahead of the fence to stop that; the owner
//! decided it should not and the row should stay, because an audit record of a REJECTED
//! attempt against an environment an operator believes is gone is worth having. The
//! reasoning lives on `ironauth_admin::sudo::require_fresh_privilege`, and it is the one
//! documented exception to "no write lands in a soft-deleted environment".

mod common;

use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use common::{Harness, OPERATOR_TOKEN, bearer};
use ironauth_admin::ApiError;
use ironauth_env::Env;
use ironauth_store::{ActorRef, CorrelationId, EnvironmentId, Scope, ServiceId, TenantId};
use serde_json::Value;
use sqlx::PgPool;

/// The COMMITTED management contract, embedded at compile time: the same artifact and
/// the same idiom `tests/absent_environment.rs` uses, and the reason this file can fail
/// on a route it does not drive.
const COMMITTED_SPEC: &str = include_str!("../../../docs/openapi/management.json");

/// The templated prefix every organization-addressed route hangs off. It includes the
/// organization's OWN address, so `deleteOrganization` and the two lifecycle actions
/// are inside the sweep rather than adjacent to it.
const ORGANIZATION_PREFIX: &str =
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}";

/// Whether a case WRITES into the organization or only READS it: the one axis the
/// policy turns on, declared per case and asserted rather than inferred from the
/// method at the point of use.
#[derive(Clone, Eq, PartialEq)]
enum Intent {
    /// The request only READS, and carries the identifiers its answer must NAME.
    ///
    /// The payload is not decoration. A read's contract here is that a decommissioned
    /// environment stays AUDITABLE, and a status-only assertion cannot tell an audit
    /// from an empty page: `list_memberships` returning `Vec::new()` left this whole
    /// file green while the status stayed 200. Each read therefore names rows the seed
    /// created while the environment was LIVE and requires the answer to carry them, in
    /// both passes.
    Read(Vec<String>),
    Write,
}

/// One organization-addressed operation, with the answer it gives at a LIVE
/// environment.
struct Case {
    /// `module.operationId`. The `operationId` half is not decoration: the coverage
    /// test resolves each case against the document and then requires the label to name
    /// the operation it resolved to.
    label: &'static str,
    method: &'static str,
    path: String,
    body: Option<String>,
    intent: Intent,
    /// The status this case answers at a LIVE environment, pinned exactly.
    live: StatusCode,
}

/// One documented organization-addressed operation, as the committed contract
/// publishes it.
struct DocumentedOperation {
    operation_id: String,
    method: String,
    template: String,
}

/// Every operation the committed contract publishes under the organization prefix: the
/// inventory this sweep must cover in full, reads included.
fn documented_organization_operations() -> Vec<DocumentedOperation> {
    let doc: Value = serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let mut operations = Vec::new();
    for (template, entries) in doc["paths"].as_object().expect("paths") {
        if !template.starts_with(ORGANIZATION_PREFIX) {
            continue;
        }
        for (method, entry) in entries.as_object().expect("operations") {
            operations.push(DocumentedOperation {
                operation_id: entry["operationId"]
                    .as_str()
                    .expect("every operation carries an id")
                    .to_owned(),
                method: method.to_uppercase(),
                template: template.clone(),
            });
        }
    }
    operations
}

/// Whether a CONCRETE request path is addressed by a TEMPLATED document path: the same
/// segment count, with every templated segment either a `{placeholder}` (which matches
/// any one segment) or an exact literal.
fn template_matches(template: &str, path: &str) -> bool {
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

/// The uniform not-found EXACTLY as the wire carries it, rendered from the one type
/// that produces it rather than transcribed into a literal here: its status, the headers
/// that renderer emits, and its body.
///
/// This is what stops a case from passing on the wrong 404. Axum answers a path that
/// matches NO route with a bare 404 and an EMPTY body, so a sweep that asserts only the
/// status cannot tell a real refusal from a request that never reached a handler.
async fn uniform_not_found() -> (StatusCode, BTreeMap<String, Vec<String>>, String) {
    let response = ApiError::NotFound.into_response();
    let status = response.status();
    let headers = header_fields(response.headers());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the not-found body is finite");
    (
        status,
        headers,
        String::from_utf8(bytes.to_vec()).expect("the not-found body is utf-8"),
    )
}

/// A response's headers as a sorted, printable map, so a divergence names the header
/// rather than dumping an opaque `HeaderMap`.
///
/// The value is a `Vec` rather than a `String` because a `HeaderMap` may carry a name
/// more than once; collapsing to one value per name would hide exactly the kind of
/// divergence this instrument exists to see.
fn header_fields(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        fields
            .entry(name.as_str().to_owned())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    fields
}

/// Every table's row count, read as the database OWNER so row-level security can never
/// hide a write. The same instrument the absent-environment sweep uses.
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

/// The `id` field of a JSON response body.
fn id_of(response: &str) -> String {
    serde_json::from_str::<Value>(response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// POST one seed row, assert the 201, and return its id. Every seeding failure names the
/// row it was creating, so a fixture that stops being satisfiable says which step broke
/// rather than surfacing later as a case answering the wrong status.
async fn seed_row(h: &Harness, path: &str, key: &str, body: &str, what: &str) -> String {
    let (status, _, response) = h.post(path, key, body).await;
    assert_eq!(status, StatusCode::CREATED, "seed {what}: {response}");
    id_of(&response)
}

/// The rows every case addresses, all created through the API while the environment was
/// LIVE. Nothing is minted rather than created, and every relation a DESTRUCTIVE case
/// removes is seeded here rather than being left for an earlier case to create.
///
/// That second property was measured rather than designed in. An earlier revision seeded
/// only the entities, so in the deleted pass the five withdrawal cases
/// (`unassignOrgGroupRole`, `unassignOrgMembershipRole`, `removeOrgGroupMember`,
/// `unassignOrgRolePermission`, `clearOrgDefaultRole`) addressed a relation that had
/// never been created and would have answered the uniform not-found with the fence
/// removed. Neutering the fence at each of those five call sites left the sweep GREEN.
/// Seeding the relations is what makes every write case discriminating.
struct Fixture {
    base: String,
    org: String,
    /// Seeded ALREADY assigned to the group, to the membership, mapped to `permission`,
    /// and designated as the organization's default: the target of every withdrawal.
    role: String,
    /// Seeded unattached: the target of every fresh assignment, so an assign case is a
    /// 201 rather than a 409 against what the seed already did.
    spare_role: String,
    group: String,
    child_group: String,
    /// Seeded a member of `group` and holding `role`.
    membership: String,
    /// Seeded a membership of the organization but bound to no group.
    spare_membership: String,
    /// Seeded a user of the environment with no membership at all.
    spare_user: String,
    /// Seeded already mapped to `role`.
    permission: String,
    /// Seeded unmapped.
    spare_permission: String,
    /// A second application, so the create case is a 201 rather than a 409 against the
    /// live grant the seed already holds: migration 0120 allows at most one LIVE grant
    /// per (client, organization) pair.
    spare_client: String,
    /// Seeded live: the target of the withdrawal case.
    grant: String,
    /// The user behind `membership`, so the agent cases can link a user who is a MEMBER of
    /// this organization.
    ///
    /// `register_agent` does NOT require that today: it checks only that the user exists in
    /// the scope. These cases link a member anyway, because an agent acting for someone with
    /// no standing in the organization is the thing that check would be added for, and a case
    /// that depends on its absence would start failing the day it arrives.
    member_user: String,
    /// An agent registered in this organization (issue #130), linked to `member_user`.
    /// Declares one tool, `google`, because storing a vault connection refuses a provider
    /// the agent never declared and refuses one that is not a lowercase identifier.
    agent: String,
    /// A PENDING vault approval for `agent` (issue #132), seeded through the store because
    /// nothing on the management plane raises one: an approval is raised by the agent's own
    /// token exchange when it names a sensitive action. The listing case names this row and
    /// the decision case answers it, in that order, because a decided approval leaves the
    /// pending queue.
    approval: String,
    /// The REAL service-account principal of `spare_client`, minted rather than made
    /// up. An absent `sva_` id answers the uniform not-found at a HEALTHY environment
    /// too, which would leave the soft-deleted fence unmeasurable through the
    /// service-account membership route: the case would pass without distinguishing
    /// anything.
    service_account: String,
    /// A live SCIM connection (issue #135), seeded while the environment is LIVE so the
    /// listing case has a row to NAME. Without it the read case answers an empty page at both
    /// environments and the "a decommissioned environment stays auditable" contract would be
    /// unmeasurable on this route -- which is the exact vacuity `Intent::Read` carries a
    /// payload to prevent.
    scim_connection: String,
}

impl Fixture {
    /// The rows that hang off the ENVIRONMENT rather than off the organization: three
    /// users and two permissions, in that order. Split out from [`Fixture::seed`] only
    /// because the two together exceed the crate's function-length lint.
    async fn seed_environment_rows(h: &Harness, env_base: &str, key: &str) -> [String; 5] {
        let mut rows = Vec::new();
        for (index, identifier) in ["member", "other", "spare"].iter().enumerate() {
            rows.push(
                seed_row(
                    h,
                    &format!("{env_base}/users"),
                    &format!("{key}-u{index}"),
                    &serde_json::json!({ "identifier": format!("{identifier}@example.test") })
                        .to_string(),
                    "user",
                )
                .await,
            );
        }
        for (index, slug) in ["billing.invoice.read", "billing.invoice.write"]
            .iter()
            .enumerate()
        {
            rows.push(
                seed_row(
                    h,
                    &format!("{env_base}/permissions"),
                    &format!("{key}-p{index}"),
                    &serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string(),
                    "permission",
                )
                .await,
            );
        }
        <[String; 5]>::try_from(rows).expect("five environment rows were seeded")
    }

    /// Seed one environment with the entities above AND the relations between them.
    async fn seed(h: &Harness, tenant: &str, environment: &str, key: &str) -> Self {
        let env_base = format!("/v1/tenants/{tenant}/environments/{environment}");
        let [user, other_user, spare_user, permission, spare_permission] =
            Self::seed_environment_rows(h, &env_base, key).await;
        let org = seed_row(
            h,
            &format!("{env_base}/organizations"),
            &format!("{key}-o"),
            &serde_json::json!({ "display_name": "Globex" }).to_string(),
            "organization",
        )
        .await;
        let base = format!("{env_base}/organizations/{org}");

        // The rows that hang off the ORGANIZATION: two roles, two groups, two
        // memberships. Paired throughout, because every pair is one row a case AMENDS
        // and one row a case DESTROYS.
        let mut org_rows = Vec::new();
        for (index, slug) in ["billing.admin", "billing.viewer"].iter().enumerate() {
            org_rows.push(
                seed_row(
                    h,
                    &format!("{base}/roles"),
                    &format!("{key}-r{index}"),
                    &serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string(),
                    "role",
                )
                .await,
            );
        }
        for (index, slug) in ["engineering", "platform"].iter().enumerate() {
            org_rows.push(
                seed_row(
                    h,
                    &format!("{base}/groups"),
                    &format!("{key}-g{index}"),
                    &serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string(),
                    "group",
                )
                .await,
            );
        }
        for (index, member) in [&user, &other_user].iter().enumerate() {
            org_rows.push(
                seed_row(
                    h,
                    &format!("{base}/memberships"),
                    &format!("{key}-m{index}"),
                    &serde_json::json!({ "user_id": member }).to_string(),
                    "membership",
                )
                .await,
            );
        }
        let [
            role,
            spare_role,
            group,
            child_group,
            membership,
            spare_membership,
        ] = <[String; 6]>::try_from(org_rows).expect("six organization rows were seeded");

        let (spare_client, grant, service_account) =
            Self::seed_project_grant(h, tenant, environment, &base, &role, key).await;
        let (agent, approval) = Self::seed_agent(h, tenant, environment, &base, &user, key).await;
        let member_user = user.clone();

        let scim_connection = seed_row(
            h,
            &format!("{base}/scim-connections"),
            &format!("{key}-sc"),
            &serde_json::json!({ "display_name": "Seeded Okta", "provider": "okta" }).to_string(),
            "scim connection",
        )
        .await;

        let fixture = Self {
            base,
            org,
            role,
            spare_role,
            group,
            child_group,
            membership,
            spare_membership,
            spare_user,
            permission,
            spare_permission,
            spare_client,
            grant,
            member_user,
            agent,
            approval,
            service_account,
            scim_connection,
        };
        fixture.seed_relations(h, key).await;
        fixture
    }

    /// Two applications and one live project grant (issue #102), returning the SPARE
    /// application and the grant.
    ///
    /// The clients go through the STORE because clients have no create endpoint. The
    /// grant goes through the API, so the seed drives the same path a caller would and a
    /// broken create surfaces here rather than as a puzzling withdrawal failure later.
    ///
    /// Two applications rather than one because migration 0120 permits at most one LIVE
    /// grant per (client, organization) pair: the create case needs an application this
    /// organization does not already hold a grant on, or it would answer 409 and pin a
    /// conflict instead of a create.
    ///
    /// Split out from [`Fixture::seed`] only because the two together exceed the crate's
    /// function-length lint.
    async fn seed_project_grant(
        h: &Harness,
        tenant: &str,
        environment: &str,
        base: &str,
        role: &str,
        key: &str,
    ) -> (String, String, String) {
        let scope = Scope::new(
            TenantId::parse(tenant).expect("tenant id"),
            EnvironmentId::parse(environment).expect("environment id"),
        );
        let sys = Env::system();
        let mut clients = Vec::new();
        for name in ["vendor-app", "vendor-app-spare"] {
            clients.push(
                h.store()
                    .scoped(scope)
                    .acting(
                        ActorRef::service(ServiceId::generate(&sys)),
                        CorrelationId::generate(&sys),
                    )
                    .clients()
                    .create(&sys, name)
                    .await
                    .expect("seed a client")
                    .to_string(),
            );
        }
        let [client, spare_client] =
            <[String; 2]>::try_from(clients).expect("two clients were seeded");
        let grant = seed_row(
            h,
            &format!("{base}/project-grants"),
            &format!("{key}-pgt"),
            &serde_json::json!({ "client_id": client, "role_ids": [role] }).to_string(),
            "project grant",
        )
        .await;
        // The service-account principal of the spare client, minted through the same
        // `ensure` the token path uses rather than invented, so the membership case
        // addresses something that actually exists.
        let service_account = h
            .store()
            .scoped(scope)
            .acting(
                ActorRef::service(ServiceId::generate(&sys)),
                CorrelationId::generate(&sys),
            )
            .service_accounts()
            .ensure(
                &sys,
                &ironauth_store::ClientId::parse_in_scope(&spare_client, &scope)
                    .expect("the spare client id parses in scope"),
            )
            .await
            .expect("mint the service-account principal")
            .to_string();
        (spare_client, grant, service_account)
    }

    /// An agent in this organization and one PENDING approval for it (issues #130, #132).
    ///
    /// The agent goes through the API, so the seed drives the same path a caller would and a
    /// broken registration surfaces here rather than as a puzzling 404 in a later case. It
    /// declares exactly one tool, `google`, because storing a vault connection refuses a
    /// provider the agent never declared AND refuses one that is not a lowercase identifier,
    /// so the declared tool and the connection case's provider have to be the same shaped
    /// string.
    ///
    /// The APPROVAL goes through the store, and that is not a shortcut: nothing on the
    /// management plane raises one. An approval is raised by the AGENT's own token exchange
    /// when it names a sensitive action, which is a data-plane path this suite does not
    /// drive. The queue's listing and decision routes are management-plane, so the row has to
    /// exist before either can address it.
    ///
    /// Split out from [`Fixture::seed`] for the same reason [`Fixture::seed_project_grant`]
    /// is: the crate's function-length lint.
    async fn seed_agent(
        h: &Harness,
        tenant: &str,
        environment: &str,
        base: &str,
        linked_user: &str,
        key: &str,
    ) -> (String, String) {
        let agent = seed_row(
            h,
            &format!("{base}/agents"),
            &format!("{key}-agt"),
            &serde_json::json!({
                "linked_user_id": linked_user,
                "display_name": "Deploy bot",
                "tool_scopes": ["google"],
            })
            .to_string(),
            "agent",
        )
        .await;

        let scope = Scope::new(
            TenantId::parse(tenant).expect("tenant id"),
            EnvironmentId::parse(environment).expect("environment id"),
        );
        let sys = Env::system();
        let approval = ironauth_store::AgentVaultApprovalId::generate(&sys, &scope);
        h.store()
            .scoped(scope)
            .acting(
                ActorRef::service(ServiceId::generate(&sys)),
                CorrelationId::generate(&sys),
            )
            .agent_vault_approvals()
            .request(
                &sys,
                ironauth_store::NewVaultApproval {
                    id: &approval,
                    agent_id: &ironauth_store::AgentPrincipalId::parse_in_scope(&agent, &scope)
                        .expect("the registered agent id parses in scope"),
                    provider: "google",
                    requested_details: &serde_json::json!([{ "type": "google", "actions": ["send"] }]),
                    // 64 lowercase hex characters, which is what the column accepts.
                    action_digest: &"a1".repeat(32),
                    // Far enough out that the row is still PENDING when the cases run. The
                    // listing does not retire anything -- `pending_for_organization` is a
                    // plain SELECT filtered on `expires_at > now`, and the only caller of
                    // `retire_timed_out` is the data-plane exchange this suite never drives --
                    // so an expired row would simply not be returned and the listing case
                    // would read an empty queue.
                    expires_at_unix_micros: i64::from(u32::MAX) * 1_000_000,
                },
            )
            .await
            .expect("seed a pending vault approval");
        (agent, approval.to_string())
    }

    /// Bind the entities together, so every WITHDRAWAL case has something live to
    /// withdraw. Split out from [`Fixture::seed`] only because the two together exceed
    /// the crate's function-length lint.
    async fn seed_relations(&self, h: &Harness, key: &str) {
        let Self {
            base,
            role,
            group,
            membership,
            permission,
            ..
        } = self;
        let _ = seed_row(
            h,
            &format!("{base}/groups/{group}/members"),
            &format!("{key}-bind"),
            &serde_json::json!({ "membership_id": membership }).to_string(),
            "group binding",
        )
        .await;
        let _ = seed_row(
            h,
            &format!("{base}/groups/{group}/roles"),
            &format!("{key}-grole"),
            &serde_json::json!({ "role_id": role }).to_string(),
            "group role grant",
        )
        .await;
        let _ = seed_row(
            h,
            &format!("{base}/memberships/{membership}/roles"),
            &format!("{key}-mrole"),
            &serde_json::json!({ "role_id": role }).to_string(),
            "direct role grant",
        )
        .await;
        let _ = seed_row(
            h,
            &format!("{base}/roles/{role}/permissions"),
            &format!("{key}-map"),
            &serde_json::json!({ "permission_id": permission }).to_string(),
            "permission mapping",
        )
        .await;
        let (status, _, response) = h
            .put(
                &format!("{base}/default-role"),
                &serde_json::json!({ "role_id": role }).to_string(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "seed default role designation: {response}"
        );
    }

    /// Every organization-addressed operation the contract publishes, in an order the
    /// LIVE pass can drive end to end: the reads first, then the writes that create or
    /// amend, then the writes that destroy, with the organization's own delete last.
    ///
    /// The order matters only for the LIVE pass, which is the point of having one: a
    /// case whose expected answer depends on a row an earlier case removed would fail
    /// there rather than quietly agreeing with the deleted pass for the wrong reason.
    fn cases(&self) -> Vec<Case> {
        let mut cases = self.read_cases();
        cases.extend(self.amending_write_cases());
        // BEFORE the destructive cases, not after. The live pass runs these in order and
        // `destructive_write_cases` ends by DELETING the organization every path here hangs
        // off, so a case appended after it addresses an organization that is already gone and
        // answers 404 at a LIVE environment. Measured, by putting them there first.
        cases.extend(
            self.scim_connection_cases()
                .into_iter()
                .filter(|case| case.method != "GET"),
        );
        cases.extend(self.destructive_write_cases());
        cases
    }

    /// The READS. Every one of them keeps working in a deleted environment, and every
    /// one of them names the rows its answer must still CARRY.
    ///
    /// The identifiers are all rows the seed created while the environment was live, so
    /// a read that answers 200 with an empty page fails here rather than passing as an
    /// audit. The effective-roles view is the one read whose body carries no row id at
    /// all (it is keyed on slugs, deliberately), so it names the GROUP its inherited
    /// grant reports as `via_group_id`; its full content is asserted separately in
    /// [`a_soft_deleted_environments_organization_content_is_still_readable`].
    fn read_cases(&self) -> Vec<Case> {
        let mut cases = self.organization_read_cases();
        cases.extend(
            self.scim_connection_cases()
                .into_iter()
                .filter(|case| case.method == "GET"),
        );
        cases.extend(self.group_and_membership_read_cases());
        cases.extend(self.agent_read_cases());
        cases
    }

    /// The two AGENT listings (issues #130, #132), each naming the row it must still carry.
    ///
    /// Both come BEFORE the writes, and for the approvals queue that ordering is load
    /// bearing: `listAgentVaultApprovals` returns the approvals AWAITING a decision, and
    /// `decideAgentVaultApproval` below answers this very row. Run the other way round, the
    /// listing would read an empty queue and the case would prove nothing.
    fn agent_read_cases(&self) -> Vec<Case> {
        let Self {
            base,
            agent,
            approval,
            ..
        } = self;
        vec![
            Case {
                label: "agents.listAgents",
                method: "GET",
                path: format!("{base}/agents"),
                body: None,
                intent: Intent::Read(vec![agent.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "agents.listAgentVaultApprovals",
                method: "GET",
                path: format!("{base}/agent-approvals"),
                body: None,
                intent: Intent::Read(vec![approval.clone()]),
                live: StatusCode::OK,
            },
        ]
    }

    /// The SCIM connection surface (issue #135), split out only because the reads together
    /// exceed the crate's function-length lint.
    fn scim_connection_cases(&self) -> Vec<Case> {
        let Self {
            base,
            scim_connection,
            ..
        } = self;
        vec![
            Case {
                label: "scim_connections.createScimConnection",
                method: "POST",
                path: format!("{base}/scim-connections"),
                body: Some(
                    "{\"display_name\":\"sweep connection\",\"provider\":\"okta\"}".to_owned(),
                ),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "scim_connections.revokeScimConnection",
                method: "DELETE",
                path: format!("{base}/scim-connections/{scim_connection}"),
                body: None,
                // The SEEDED connection, not an absent handle. An absent one answers the
                // uniform not-found at a LIVE environment too, so driving it at a
                // soft-deleted one would measure nothing about the fence. The api-key revoke
                // beside it predates that lesson.
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "scim_connections.listScimConnections",
                method: "GET",
                path: format!("{base}/scim-connections"),
                body: None,
                // The listing must stay AUDITABLE at a decommissioned environment, which is
                // what `EnvironmentAccess::Read` buys. It names the connection the create
                // above landed, so an empty page cannot pass for an audit.
                intent: Intent::Read(vec!["Seeded Okta".to_owned()]),
                live: StatusCode::OK,
            },
        ]
    }

    /// The reads over the organization itself and its ROLES. Split from
    /// [`Fixture::group_and_membership_read_cases`] only because they together
    /// exceed the crate's function-length lint.
    fn organization_read_cases(&self) -> Vec<Case> {
        let Self {
            base,
            org,
            role,
            spare_role,
            permission,
            grant,
            ..
        } = self;
        vec![
            // --- The READS. Every one of them keeps working in a deleted environment.
            Case {
                label: "organizations.getOrganization",
                method: "GET",
                path: base.clone(),
                body: None,
                intent: Intent::Read(vec![org.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_roles.listOrgRoles",
                method: "GET",
                path: format!("{base}/roles"),
                body: None,
                intent: Intent::Read(vec![role.clone(), spare_role.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "api_keys.createOrganizationApiKey",
                method: "POST",
                path: format!("{base}/api-keys"),
                body: Some("{\"display_name\":\"sweep key\"}".to_owned()),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "api_keys.rotateOrganizationApiKey",
                method: "POST",
                path: format!("{base}/api-keys/akey_absent/rotate"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NOT_FOUND,
            },
            Case {
                label: "api_keys.revokeOrganizationApiKey",
                method: "DELETE",
                path: format!("{base}/api-keys/akey_absent"),
                body: None,
                // A handle that does not exist. The point is the ENVIRONMENT fence, which
                // must answer before the key is looked up, so a live environment answers
                // 404 for the key and a deleted one answers the same uniform refusal for
                // the environment. Indistinguishable, which is the property.
                intent: Intent::Write,
                live: StatusCode::NOT_FOUND,
            },
            Case {
                label: "api_keys.listOrganizationApiKeys",
                method: "GET",
                path: format!("{base}/api-keys"),
                body: None,
                // No seeded key, so this asserts only the ADDRESSABILITY behaviour the
                // sweep exists for: 200 while the environment is live, and the uniform
                // refusal once it is deleted. An empty page is the correct live answer
                // here, unlike the grants case below, which seeds a row precisely because
                // a 200 carrying nothing would pass as an audit of a dead surface.
                intent: Intent::Read(Vec::new()),
                live: StatusCode::OK,
            },
            Case {
                label: "project_grants.listProjectGrants",
                method: "GET",
                path: format!("{base}/project-grants"),
                body: None,
                // Names the seeded grant, so a 200 carrying an EMPTY page fails here
                // rather than passing as an audit of a surface that answers nothing.
                intent: Intent::Read(vec![grant.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_roles.getOrgRole",
                method: "GET",
                path: format!("{base}/roles/{role}"),
                body: None,
                intent: Intent::Read(vec![role.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_role_permissions.listOrgRolePermissions",
                method: "GET",
                path: format!("{base}/roles/{role}/permissions"),
                body: None,
                intent: Intent::Read(vec![permission.clone()]),
                live: StatusCode::OK,
            },
        ]
    }

    /// The reads over the organization's GROUP forest and its memberships. Split from
    /// [`Fixture::organization_read_cases`] only because they together exceed the
    /// crate's function-length lint.
    fn group_and_membership_read_cases(&self) -> Vec<Case> {
        let Self {
            base,
            role,
            group,
            child_group,
            membership,
            spare_membership,
            ..
        } = self;
        vec![
            Case {
                label: "org_groups.listOrgGroups",
                method: "GET",
                path: format!("{base}/groups"),
                body: None,
                intent: Intent::Read(vec![group.clone(), child_group.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_groups.getOrgGroup",
                method: "GET",
                path: format!("{base}/groups/{group}"),
                body: None,
                intent: Intent::Read(vec![group.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_group_members.listOrgGroupMembers",
                method: "GET",
                path: format!("{base}/groups/{group}/members"),
                body: None,
                intent: Intent::Read(vec![membership.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_role_assignments.listOrgGroupRoles",
                method: "GET",
                path: format!("{base}/groups/{group}/roles"),
                body: None,
                intent: Intent::Read(vec![role.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "memberships.listMemberships",
                method: "GET",
                path: format!("{base}/memberships"),
                body: None,
                intent: Intent::Read(vec![membership.clone(), spare_membership.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_role_assignments.listOrgMembershipRoles",
                method: "GET",
                path: format!("{base}/memberships/{membership}/roles"),
                body: None,
                intent: Intent::Read(vec![role.clone()]),
                live: StatusCode::OK,
            },
            Case {
                label: "org_effective_roles.getOrgMembershipEffectiveRoles",
                method: "GET",
                path: format!("{base}/memberships/{membership}/effective-roles"),
                body: None,
                intent: Intent::Read(vec![group.clone()]),
                live: StatusCode::OK,
            },
        ]
    }

    /// The WRITES that create or amend.
    fn amending_write_cases(&self) -> Vec<Case> {
        let mut cases = self.amending_group_write_cases();
        cases.extend(self.amending_role_write_cases());
        cases.extend(self.agent_write_cases());
        cases
    }

    /// The four AGENT writes (issues #130, #132).
    ///
    /// All four are amending rather than destructive, and the ORDER inside this vector is the
    /// order they run in. `storeAgentVaultConnection` refuses a provider the agent has not
    /// declared and refuses one that is not a lowercase identifier, so it names the single
    /// tool the seed declared.
    ///
    /// `setAgentState` goes to `suspended` rather than `revoked` because suspension is the
    /// REVERSIBLE state and revocation additionally revokes the agent's grants. Nothing later
    /// in the sweep addresses this agent today -- the destructive writes are all grants,
    /// roles, groups, memberships and the organization -- so `revoked` would answer 200 here
    /// too; the choice is about not having the sweep leave a terminal row behind, not about
    /// a case that would break.
    fn agent_write_cases(&self) -> Vec<Case> {
        let Self {
            base,
            agent,
            approval,
            member_user,
            ..
        } = self;
        vec![
            Case {
                // A SECOND agent for the SAME member. `agents` has no uniqueness on
                // `linked_user_id`, so this is a 201 rather than a conflict against the row
                // the seed already created.
                label: "agents.registerAgent",
                method: "POST",
                path: format!("{base}/agents"),
                body: Some(
                    serde_json::json!({
                        "linked_user_id": member_user,
                        "display_name": "Second bot",
                        "tool_scopes": ["google"],
                    })
                    .to_string(),
                ),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "agents.storeAgentVaultConnection",
                method: "PUT",
                path: format!("{base}/agents/{agent}/vault-connections"),
                body: Some(
                    serde_json::json!({
                        "provider": "google",
                        "access_token": "downstream-access-token",
                        "granted_scopes": ["send"],
                    })
                    .to_string(),
                ),
                intent: Intent::Write,
                live: StatusCode::OK,
            },
            Case {
                label: "agents.decideAgentVaultApproval",
                method: "POST",
                path: format!("{base}/agent-approvals/{approval}/decision"),
                body: Some(serde_json::json!({ "approve": true }).to_string()),
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "agents.setAgentState",
                method: "PUT",
                path: format!("{base}/agents/{agent}/state"),
                body: Some(serde_json::json!({ "state": "suspended" }).to_string()),
                intent: Intent::Write,
                live: StatusCode::OK,
            },
        ]
    }

    /// The amending writes over the organization's GROUP forest.
    fn amending_group_write_cases(&self) -> Vec<Case> {
        let Self {
            base,
            group,
            child_group,
            spare_membership,
            spare_role,
            ..
        } = self;
        // A fresh assignment names the SPARE role, so an assign case is a 201 rather
        // than a 409 against what the seed already granted; a withdrawal names the
        // SEEDED role, so it removes something that is live.
        let spare_role_ref = serde_json::json!({ "role_id": spare_role }).to_string();
        let relabel = serde_json::json!({ "display_name": "Relabelled" }).to_string();
        vec![
            // A SECOND grant, on the spare application: migration 0120 allows at most
            // one LIVE grant per (client, organization) pair, so reusing `client` here
            // would answer 409 and the case would pin a conflict rather than a create.
            Case {
                label: "project_grants.createProjectGrant",
                method: "POST",
                path: format!("{}/project-grants", self.base),
                body: Some(
                    serde_json::json!({
                        "client_id": self.spare_client,
                        "role_ids": [&self.spare_role],
                    })
                    .to_string(),
                ),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "org_groups.createOrgGroup",
                method: "POST",
                path: format!("{base}/groups"),
                body: Some(
                    serde_json::json!({ "slug": "sweep.new", "display_name": "New" }).to_string(),
                ),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "org_groups.updateOrgGroup",
                method: "PATCH",
                path: format!("{base}/groups/{group}"),
                body: Some(relabel.clone()),
                intent: Intent::Write,
                live: StatusCode::OK,
            },
            Case {
                label: "org_groups.setOrgGroupParent",
                method: "PUT",
                path: format!("{base}/groups/{child_group}/parent"),
                body: Some(serde_json::json!({ "parent_id": group }).to_string()),
                intent: Intent::Write,
                live: StatusCode::OK,
            },
            Case {
                label: "org_group_members.addOrgGroupMember",
                method: "POST",
                path: format!("{base}/groups/{group}/members"),
                body: Some(serde_json::json!({ "membership_id": spare_membership }).to_string()),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "org_role_assignments.assignOrgGroupRole",
                method: "POST",
                path: format!("{base}/groups/{group}/roles"),
                body: Some(spare_role_ref),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
        ]
    }

    /// The amending writes over the organization's ROLES, its memberships, and its own
    /// lifecycle state.
    fn amending_role_write_cases(&self) -> Vec<Case> {
        let Self {
            base,
            membership,
            role,
            spare_role,
            spare_user,
            spare_permission,
            service_account,
            ..
        } = self;
        let spare_role_ref = serde_json::json!({ "role_id": spare_role }).to_string();
        let relabel = serde_json::json!({ "display_name": "Relabelled" }).to_string();
        vec![
            Case {
                label: "org_roles.createOrgRole",
                method: "POST",
                path: format!("{base}/roles"),
                body: Some(
                    serde_json::json!({ "slug": "sweep.role", "display_name": "New" }).to_string(),
                ),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "org_roles.updateOrgRole",
                method: "PATCH",
                path: format!("{base}/roles/{role}"),
                body: Some(relabel),
                intent: Intent::Write,
                live: StatusCode::OK,
            },
            Case {
                label: "org_role_permissions.assignOrgRolePermission",
                method: "POST",
                path: format!("{base}/roles/{role}/permissions"),
                body: Some(serde_json::json!({ "permission_id": spare_permission }).to_string()),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "memberships.createMembership",
                method: "POST",
                path: format!("{base}/memberships"),
                body: Some(serde_json::json!({ "user_id": spare_user }).to_string()),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "memberships.createServiceAccountMembership",
                method: "POST",
                path: format!("{base}/service-account-memberships"),
                body: Some(
                    serde_json::json!({ "service_account_id": service_account }).to_string(),
                ),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "org_role_assignments.assignOrgMembershipRole",
                method: "POST",
                path: format!("{base}/memberships/{membership}/roles"),
                body: Some(spare_role_ref.clone()),
                intent: Intent::Write,
                live: StatusCode::CREATED,
            },
            Case {
                label: "org_roles.setOrgDefaultRole",
                method: "PUT",
                path: format!("{base}/default-role"),
                body: Some(spare_role_ref),
                intent: Intent::Write,
                live: StatusCode::OK,
            },
            Case {
                label: "organizations.disableOrganization",
                method: "POST",
                path: format!("{base}/disable"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::OK,
            },
            Case {
                label: "organizations.enableOrganization",
                method: "POST",
                path: format!("{base}/enable"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::OK,
            },
        ]
    }

    /// The WRITES that destroy, each undoing one of the amendments above.
    fn destructive_write_cases(&self) -> Vec<Case> {
        let Self {
            base,
            role,
            group,
            child_group,
            membership,
            permission,
            grant,
            ..
        } = self;
        vec![
            // --- The WRITES that destroy, each undoing one of the amendments above.
            Case {
                label: "project_grants.withdrawProjectGrant",
                method: "DELETE",
                path: format!("{base}/project-grants/{grant}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "org_role_assignments.unassignOrgMembershipRole",
                method: "DELETE",
                path: format!("{base}/memberships/{membership}/roles/{role}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "org_role_permissions.unassignOrgRolePermission",
                method: "DELETE",
                path: format!("{base}/roles/{role}/permissions/{permission}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "org_role_assignments.unassignOrgGroupRole",
                method: "DELETE",
                path: format!("{base}/groups/{group}/roles/{role}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "org_group_members.removeOrgGroupMember",
                method: "DELETE",
                path: format!("{base}/groups/{group}/members/{membership}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "org_roles.clearOrgDefaultRole",
                method: "DELETE",
                path: format!("{base}/default-role"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "memberships.deleteMembership",
                method: "DELETE",
                path: format!("{base}/memberships/{membership}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "org_roles.deleteOrgRole",
                method: "DELETE",
                path: format!("{base}/roles/{role}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            Case {
                label: "org_groups.deleteOrgGroup",
                method: "DELETE",
                path: format!("{base}/groups/{child_group}"),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
            // Last: it removes the parent every other case addresses.
            Case {
                label: "organizations.deleteOrganization",
                method: "DELETE",
                path: base.clone(),
                body: None,
                intent: Intent::Write,
                live: StatusCode::NO_CONTENT,
            },
        ]
    }
}

/// Drive one case with the bootstrap operator token, carrying an Idempotency-Key on
/// every request (the routes that require one get it; the rest ignore it).
///
/// The HEADERS come back too, because "the uniform not-found" is a claim about the whole
/// response and not only about its status and body.
async fn drive(h: &Harness, case: &Case, key: &str) -> (StatusCode, HeaderMap, String) {
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
    h.send(request).await
}

/// The identifiers a read's answer failed to carry, if any.
///
/// A substring match over the rendered body, which is enough and is uniform across the
/// read shapes (a page under `items`, a bare object, and the effective-roles view
/// under `roles`). The identifiers are freshly generated per run and appear nowhere else
/// in a response, so a hit is the row.
fn missing_ids<'a>(body: &str, expected: &'a [String]) -> Vec<&'a str> {
    expected
        .iter()
        .filter(|id| !body.contains(id.as_str()))
        .map(String::as_str)
        .collect()
}

/// Soft-delete an environment through the shipped route, asserting it took.
async fn delete_environment(h: &Harness, tenant: &str, environment: &str) {
    let (status, _, body) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the environment is soft-deleted: {body}"
    );
    // And it now reads as absent, which is the whole reason an operator believes it is
    // gone. Without this the sweep below could be measuring an environment that was
    // never deleted at all.
    let (status, _, body) = h
        .get(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a soft-deleted environment reads as absent: {body}"
    );
}

#[test]
fn every_documented_organization_operation_is_driven_by_a_case() {
    // The guard on the guard. A sweep over a hand-maintained list reports on whatever
    // the list happens to contain and says nothing about what it omits, and the issue's
    // own list was wrong in both directions. This resolves every case against the
    // COMMITTED contract by method and templated path and then requires the two sets to
    // agree exactly. It needs no database, so it is the cheapest thing in the file and
    // the first thing to fail.
    let fixture = Fixture {
        base: "/v1/tenants/ten_x/environments/env_x/organizations/org_x".to_owned(),
        org: "org_x".to_owned(),
        role: "rol_x".to_owned(),
        spare_role: "rol_y".to_owned(),
        group: "grp_x".to_owned(),
        child_group: "grp_y".to_owned(),
        membership: "omb_x".to_owned(),
        spare_membership: "omb_y".to_owned(),
        spare_user: "usr_x".to_owned(),
        permission: "prm_x".to_owned(),
        spare_permission: "prm_y".to_owned(),
        spare_client: "cli_y".to_owned(),
        grant: "pgt_x".to_owned(),
        member_user: "usr_m".to_owned(),
        agent: "agp_x".to_owned(),
        approval: "ava_x".to_owned(),
        service_account: "sva_x".to_owned(),
        scim_connection: "scim_x".to_owned(),
    };
    let cases = fixture.cases();
    let documented = documented_organization_operations();

    // 1. Every case addresses exactly ONE documented operation. A case whose path has a
    //    typo in a LITERAL segment matches no template at all and fails here, which is
    //    the hole a status-only sweep cannot see: axum answers an unrouted path with a
    //    404, the same status the uniform not-found carries.
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for case in &cases {
        let addressed: Vec<&DocumentedOperation> = documented
            .iter()
            .filter(|operation| {
                operation.method == case.method && template_matches(&operation.template, &case.path)
            })
            .collect();
        let named: Vec<&str> = addressed
            .iter()
            .map(|operation| operation.operation_id.as_str())
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
    //    makes a NEW organization-nested route fail the sweep the moment it is
    //    documented, rather than being silently absent from it.
    let published: BTreeSet<String> = documented
        .iter()
        .map(|operation| operation.operation_id.clone())
        .collect();
    let undriven: Vec<&String> = published.difference(&covered).collect();
    assert!(
        undriven.is_empty(),
        "the committed contract publishes {} organization-addressed operations and this sweep \
         drives {}; add a case for each of these before the sweep can claim to cover the \
         surface: {undriven:?}",
        published.len(),
        covered.len()
    );

    // 3. And the method is what decides the intent. The policy is "a write refuses, a
    //    read keeps working", so a case that declared a GET a write (or a mutation a
    //    read) would pin the wrong contract for that route while every assertion still
    //    passed.
    for case in &cases {
        let declares_read = matches!(case.intent, Intent::Read(_));
        assert_eq!(
            declares_read,
            case.method == "GET",
            "{} drives {} but declares the opposite intent",
            case.label,
            case.method
        );
    }
}

/// The organization-addressed writes whose answer at a soft-deleted environment is NOT the
/// uniform not-found, and the reason each one cannot be.
///
/// `live_surface.rs::documented_write_exceptions` is the same list for the environment-scoped
/// surface, granted for the same reason and on the same terms.
fn documented_write_exceptions() -> BTreeMap<&'static str, StatusCode> {
    BTreeMap::from([
        // REVOKING a SCIM provisioning credential, which is the CLOSING direction, and a
        // closing write never requires its parent to be live.
        //
        // `ScimConnectionRepo::authenticate` joins only `organizations` and checks
        // `deleted_at`/`state` there. Soft-deleting an ENVIRONMENT cascades to neither, so a
        // minted token goes on provisioning an organization's whole user population after the
        // environment is decommissioned -- measured, by presenting one to the real
        // `scim_router` after the delete. Fencing the route that DESTROYS that credential
        // would turn the soft delete into a one-way door on the strongest credential this
        // surface issues, with no remedy short of a direct database write.
        //
        // It still requires the environment to EXIST, and `resolve_scope` is what provides
        // that: its `exists_in_any_state` read runs before any of this. `absent_environment.rs`
        // drives the same route at an environment that was never created and requires the
        // uniform not-found, which is the test that would fail if that read were removed.
        //
        // This is the one exempted write here that LANDS A ROW CHANGE, which is the whole
        // point of it, so it is also the one entry in [`documented_write_row_effects`].
        (
            "scim_connections.revokeScimConnection",
            StatusCode::NO_CONTENT,
        ),
    ])
}

/// The row-count deltas the documented write exceptions are permitted to leave behind, per
/// table. Nothing else may move.
///
/// The revoke UPDATEs `scim_connections` in place, so that table's COUNT does not change; what
/// it adds is the audit row and the announcement, both in the same transaction. Recorded
/// exactly rather than as a tolerance: a producer quietly dropped from the revoke leaves one of
/// these at zero and fails here.
fn documented_write_row_effects() -> BTreeMap<String, i64> {
    BTreeMap::from([
        ("audit_log".to_owned(), 1),
        ("outbox_messages".to_owned(), 1),
    ])
}

#[tokio::test]
async fn every_organization_nested_write_refuses_a_soft_deleted_environment() {
    // The whole-surface guard. It drives every organization-addressed operation twice:
    // once against a live environment, where each answer is pinned exactly, and once
    // against an identically seeded environment that has since been soft-deleted.
    let h = Harness::start(50).await;
    let (tenant, live) = h.create_tenant("acme", "k-tenant").await;

    // The LIVE pass, in its own environment because it ends by deleting the
    // organization it addresses. Each answer is pinned exactly, so no case can reach
    // the deleted pass having never been satisfiable in the first place.
    let control = Fixture::seed(&h, &tenant, &live, "k-live").await;
    for (index, case) in control.cases().iter().enumerate() {
        let (status, _, body) = drive(&h, case, &format!("k-live-{index}")).await;
        assert_eq!(
            status, case.live,
            "{} answered {status} at a LIVE environment; its pinned answer is {}: {body}",
            case.label, case.live
        );
        // And a READ names its rows at a LIVE environment, which is what makes the same
        // assertion in the deleted pass attributable: a read that could never have named
        // them would fail here first rather than reporting a content regression that had
        // nothing to do with the environment.
        if let Intent::Read(expected) = &case.intent {
            let missing = missing_ids(&body, expected);
            assert!(
                missing.is_empty(),
                "{} answered 200 at a LIVE environment without naming {missing:?}: {body}",
                case.label
            );
        }
    }

    // The DELETED pass.
    let doomed = h.create_environment(&tenant, "doomed", "k-env").await;
    let fixture = Fixture::seed(&h, &tenant, &doomed, "k-doomed").await;
    delete_environment(&h, &tenant, &doomed).await;

    let before = snapshot(h.db().owner_pool()).await;
    let (not_found_status, not_found_headers, not_found_body) = uniform_not_found().await;

    // Collected rather than asserted one at a time, so one run reports the whole table
    // instead of stopping at the first divergence.
    let mut observed: Vec<String> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    let mut refusals: Vec<(&str, BTreeMap<String, Vec<String>>)> = Vec::new();
    let exceptions = documented_write_exceptions();
    for (index, case) in fixture.cases().iter().enumerate() {
        let (status, headers, body) = drive(&h, case, &format!("k-doomed-{index}")).await;
        observed.push(format!("{:7} {:55} {status}", case.method, case.label));
        match &case.intent {
            Intent::Write => {
                if let Some(&expected) = exceptions.get(case.label) {
                    if status != expected {
                        wrong.push(format!(
                            "{} answered {status}, expected the documented exception \
                             {expected}: {body}",
                            case.label
                        ));
                    }
                    // NOT pushed into `refusals`: it is not a refusal, and comparing its
                    // headers against the uniform not-found's would be comparing a 204 to
                    // a 404.
                    continue;
                }
                if status != not_found_status || body != not_found_body {
                    wrong.push(format!(
                        "{} answered {status} for a WRITE into a soft-deleted environment, \
                         expected the uniform not-found: {body}",
                        case.label
                    ));
                }
                refusals.push((case.label, header_fields(&headers)));
            }
            Intent::Read(expected) => {
                if status == case.live {
                    // A decommissioned environment is only AUDITABLE if the listings
                    // answer with the rows, so a 200 alone is not the contract. This is
                    // the assertion `list_memberships` returning an empty vector used to
                    // slip past.
                    let missing = missing_ids(&body, expected);
                    if !missing.is_empty() {
                        wrong.push(format!(
                            "{} answered 200 for a READ of a soft-deleted environment but did \
                             not name {missing:?}: {body}",
                            case.label
                        ));
                    }
                } else {
                    wrong.push(format!(
                        "{} answered {status} for a READ of a soft-deleted environment, \
                         expected its live answer {}: {body}",
                        case.label, case.live
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "the organization surface disagrees about a soft-deleted environment:\n{}\n\nthe whole \
         table:\n{}",
        wrong.join("\n"),
        observed.join("\n")
    );

    // What "the uniform not-found" means includes the HEADERS, and not only the status
    // and the body. Two things are required, because neither alone is the claim.
    //
    // First, every refusal carries every header the ONE renderer emits, with the same
    // value. That is what rules out axum's bare 404, which reaches no handler and
    // carries no content type at all.
    let (canonical, canonical_headers) = refusals
        .first()
        .map(|(label, fields)| (*label, fields.clone()))
        .expect("the sweep drives at least one write");
    for (name, values) in &not_found_headers {
        assert_eq!(
            canonical_headers.get(name),
            Some(values),
            "{canonical} answered a refusal whose `{name}` is not the one the uniform \
             not-found renders: {canonical_headers:?}"
        );
    }
    // Second, all of the refusals carry the SAME headers as each other, down to the
    // middleware's stamp. That is what rules out one route adding or dropping a header
    // the others do not, which no comparison against the bare rendered error
    // could see (the router's rate-limit layer stamps headers the renderer never emits).
    for (label, fields) in &refusals {
        assert_eq!(
            fields, &canonical_headers,
            "{label} refused with different headers from {canonical}"
        );
    }

    // And nothing the deleted pass touched wrote a row ANYWHERE, audit log included.
    // This is read as the database owner, so row-level security cannot hide a write,
    // and it covers the reads as well as the refusals.
    assert_only_the_documented_rows_moved(&before, &after_snapshot(&h).await, &observed);
}

/// Assert that the only rows the deleted pass moved are the ones a documented write exception
/// is permitted to move.
///
/// Split out of the sweep only because the two together exceed the crate's function-length
/// lint.
fn assert_only_the_documented_rows_moved(
    before: &BTreeMap<String, i64>,
    after: &BTreeMap<String, i64>,
    observed: &[String],
) {
    //
    // "Nothing" is no longer literally nothing, because one exempted write DESTROYS a
    // credential and audits doing so. The permitted deltas are enumerated per table in
    // [`documented_write_row_effects`], so a write that starts touching something ELSE shows
    // up as an unexpected table rather than being absorbed by a tolerance.
    let permitted = documented_write_row_effects();
    let mut unexpected: Vec<String> = Vec::new();
    for (table, before_count) in before {
        let after_count = after.get(table).copied().unwrap_or(0);
        let delta = after_count - before_count;
        let allowed = permitted.get(table).copied().unwrap_or(0);
        if delta != allowed {
            unexpected.push(format!(
                "{table}: {before_count} -> {after_count} (delta {delta}, permitted {allowed})"
            ));
        }
    }
    assert!(
        unexpected.is_empty(),
        "a request into a soft-deleted environment moved rows it may not:\n{}\n\nthe whole \
         table:\n{}",
        unexpected.join("\n"),
        observed.join("\n")
    );
    // And every table the exceptions DO name actually moved, so an exception that stopped
    // writing what it documents fails here instead of quietly passing the check above.
    for (table, allowed) in &permitted {
        let delta =
            after.get(table).copied().unwrap_or(0) - before.get(table).copied().unwrap_or(0);
        assert_eq!(
            delta, *allowed,
            "{table} was permitted a delta of {allowed} and moved by {delta}, so a documented \
             write exception has stopped writing what it claims to"
        );
    }
}

/// The owner-pool row snapshot, named so the sweep reads as a before and an after.
async fn after_snapshot(h: &Harness) -> BTreeMap<String, i64> {
    snapshot(h.db().owner_pool()).await
}

#[tokio::test]
async fn a_nested_create_and_the_vocabulary_create_agree_about_a_soft_deleted_environment() {
    // The divergence this issue exists to close, driven in ONE fixture the way issue
    // #98 PR 8 asked. `POST .../organizations/{org}/roles` is the shipped nested create;
    // `POST .../permissions` is the ENVIRONMENT-scoped vocabulary create that already
    // refused, because issue #98 PR 7 gave it a `require_live_environment` precondition
    // for an unrelated reason. Before this change the two answered 201 and 404
    // respectively for the same environment.
    //
    // The test is the backstop and not the guarantee. The guarantee is structural: the
    // vocabulary create and every organization-addressed write now reach the SAME
    // `org_context::require_live_environment`, the nested writes through the single
    // `resolve_live_org` call every one of them already made. There is one copy of the
    // check and one code path through it, so the two cannot be given different answers
    // without editing that one function.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let fixture = Fixture::seed(&h, &tenant, &environment, "k-seed").await;
    let vocabulary = format!("/v1/tenants/{tenant}/environments/{environment}/permissions");
    let nested = format!("{}/roles", fixture.base);

    // The positive control, while the environment is live: both creates succeed, so the
    // refusals below are attributable to the environment and not to a request either
    // route would have rejected anyway.
    let (status, _, body) = h
        .post(
            &nested,
            "k-live-role",
            &serde_json::json!({ "slug": "live.role", "display_name": "Live" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the live nested create: {body}"
    );
    let (status, _, body) = h
        .post(
            &vocabulary,
            "k-live-perm",
            &serde_json::json!({ "slug": "live.permission", "display_name": "Live" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the live vocabulary create: {body}"
    );

    delete_environment(&h, &tenant, &environment).await;

    let (nested_status, nested_headers, nested_body) = h
        .post(
            &nested,
            "k-dead-role",
            &serde_json::json!({ "slug": "after.delete", "display_name": "After" }).to_string(),
        )
        .await;
    let (vocabulary_status, vocabulary_headers, vocabulary_body) = h
        .post(
            &vocabulary,
            "k-dead-perm",
            &serde_json::json!({ "slug": "after.delete", "display_name": "After" }).to_string(),
        )
        .await;

    assert_eq!(
        nested_status, vocabulary_status,
        "the nested create and the vocabulary create must agree about a soft-deleted \
         environment: {nested_body} vs {vocabulary_body}"
    );
    assert_eq!(
        nested_body, vocabulary_body,
        "and they must agree byte for byte, not merely on the status"
    );
    assert_eq!(
        header_fields(&nested_headers),
        header_fields(&vocabulary_headers),
        "and byte for byte includes the HEADERS, which is the rest of what a client sees"
    );
    let (not_found_status, not_found_headers, not_found_body) = uniform_not_found().await;
    assert_eq!(
        nested_status, not_found_status,
        "and what they agree on is the uniform refusal: {nested_body}"
    );
    assert_eq!(nested_body, not_found_body);
    let nested_fields = header_fields(&nested_headers);
    for (name, values) in &not_found_headers {
        assert_eq!(
            nested_fields.get(name),
            Some(values),
            "and the refusal carries the `{name}` the one renderer emits: {nested_fields:?}"
        );
    }
}

#[tokio::test]
async fn a_soft_deleted_environment_answers_a_write_exactly_as_an_absent_one_does() {
    // Soft-deleted and absent are ONE answer on this surface, which is what issue #409
    // established for the handlers it fenced and is the property that keeps a caller
    // from using the organization surface as an existence oracle over an environment it
    // cannot otherwise see.
    //
    // The three references are driven side by side: a MALFORMED environment segment
    // (refused by `resolve_scope`'s parse alone, before any row is read), a well-formed
    // environment id that was never created, and one that was created and then deleted.
    // The organization id is held FIXED across all three, so the only thing that varies
    // is the environment.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let fixture = Fixture::seed(&h, &tenant, &environment, "k-seed").await;
    let absent = ironauth_store::EnvironmentId::generate(&ironauth_env::Env::system()).to_string();
    let create = serde_json::json!({ "slug": "sweep.role", "display_name": "Sweep" }).to_string();
    let roles_in = |env: &str| {
        format!(
            "/v1/tenants/{tenant}/environments/{env}/organizations/{}/roles",
            fixture.org
        )
    };

    let (malformed_status, _, malformed_body) = h
        .post(&roles_in("env_not-a-real-id"), "k-malformed", &create)
        .await;
    assert_eq!(
        malformed_status,
        StatusCode::NOT_FOUND,
        "a malformed environment segment is the uniform not-found: {malformed_body}"
    );

    let (absent_status, _, absent_body) = h.post(&roles_in(&absent), "k-absent", &create).await;
    assert_eq!(
        absent_status, malformed_status,
        "an absent environment answers as a malformed one: {absent_body}"
    );
    assert_eq!(absent_body, malformed_body);

    delete_environment(&h, &tenant, &environment).await;

    let (deleted_status, _, deleted_body) =
        h.post(&roles_in(&environment), "k-deleted", &create).await;
    assert_eq!(
        deleted_status, malformed_status,
        "and a soft-deleted environment answers as both: {deleted_body}"
    );
    assert_eq!(deleted_body, malformed_body);
}

/// The organization-addressed keyed writes this test drives, each with a request that
/// succeeds against a freshly seeded [`Fixture`] and against no other case in this test.
///
/// NOT all of them, and that used to be claimed here: "the SEVEN ... are the routes that call
/// `idempotency::replay_if_stored`". That is false. The committed contract records the
/// `Idempotency-Key` header per operation, and FOURTEEN organization-addressed operations carry
/// it. The seven were never derived from anything, so the number could not notice the six it
/// was missing.
///
/// It is derived now: `the_keyed_write_list_is_measured_against_the_contract` reads the header
/// out of the document, subtracts what this list drives, and pins the remainder EXACTLY. The
/// gap is a number in an assertion that fails when it moves, rather than a sentence claiming
/// there is no gap.
fn keyed_writes(fixture: &Fixture) -> Vec<(&'static str, String, String)> {
    let Fixture {
        base,
        role,
        spare_role,
        group,
        membership,
        spare_membership,
        spare_user,
        spare_permission,
        member_user,
        ..
    } = fixture;
    let spare_role_ref = serde_json::json!({ "role_id": spare_role }).to_string();
    vec![
        (
            "org_roles.createOrgRole",
            format!("{base}/roles"),
            serde_json::json!({ "slug": "replay.role", "display_name": "Replay" }).to_string(),
        ),
        (
            "org_groups.createOrgGroup",
            format!("{base}/groups"),
            serde_json::json!({ "slug": "replay.group", "display_name": "Replay" }).to_string(),
        ),
        (
            "memberships.createMembership",
            format!("{base}/memberships"),
            serde_json::json!({ "user_id": spare_user }).to_string(),
        ),
        (
            "org_role_assignments.assignOrgGroupRole",
            format!("{base}/groups/{group}/roles"),
            spare_role_ref.clone(),
        ),
        (
            "org_role_assignments.assignOrgMembershipRole",
            format!("{base}/memberships/{membership}/roles"),
            spare_role_ref,
        ),
        (
            "org_role_permissions.assignOrgRolePermission",
            format!("{base}/roles/{role}/permissions"),
            serde_json::json!({ "permission_id": spare_permission }).to_string(),
        ),
        (
            "org_group_members.addOrgGroupMember",
            format!("{base}/groups/{group}/members"),
            serde_json::json!({ "membership_id": spare_membership }).to_string(),
        ),
        // The SCIM connection mint (issue #135). It is here rather than in the undriven
        // remainder because it needs nothing the fixture does not already seed -- just the
        // organization at `base` -- and a review measured exactly that: the remainder's stated
        // reason ("needs seed rows this fixture does not have") did not cover this entry.
        (
            "scim_connections.createScimConnection",
            format!("{base}/scim-connections"),
            serde_json::json!({ "display_name": "Replay Okta", "provider": "okta" }).to_string(),
        ),
        // Added with the agent cases, because this change is what brings `registerAgent` into
        // the sweep: a keyed write reaching the surface without reaching the replay fence is
        // the gap the derived assertion below exists to make visible.
        (
            "agents.registerAgent",
            format!("{base}/agents"),
            serde_json::json!({
                "linked_user_id": member_user,
                "display_name": "Replay bot",
                "tool_scopes": ["google"],
            })
            .to_string(),
        ),
    ]
}

/// The keyed-write list is measured against the CONTRACT, not asserted in prose.
///
/// The document records `Idempotency-Key` as a header parameter per operation, so "which
/// organization-addressed writes are keyed" is derivable, and the list above is therefore
/// checkable. Two directions, and the second is the one that matters:
///
/// 1. everything the list drives really is a keyed organization operation, so a stale entry
///    fails rather than quietly testing a route that no longer takes a key;
/// 2. the operations NOT driven are pinned EXACTLY. A hand-written list with no such pin
///    silently stops covering the surface every time a keyed route is added, which is what
///    happened here: the doc claimed seven were all of them while six went undriven, and
///    again when `createScimConnection` landed keyed and undriven.
///
/// The remainder is a pin, not an aspiration. Driving the other six needs seed rows this
/// fixture does not have (an API key, a service-account membership, a second organization to
/// disable), and inventing them is a bigger change than the one that found this. Adding a
/// keyed route without driving it now fails HERE, with its name in the message.
///
/// A review checked that reason against the remainder and found it did not cover every entry:
/// `createScimConnection` had been added to the undriven set while needing nothing beyond the
/// organization the fixture already seeds. It is driven now. The lesson is the one this whole
/// doc block is about -- a remainder with a prose reason is a place a new entry hides behind
/// somebody else's justification.
#[test]
fn the_keyed_write_list_is_measured_against_the_contract() {
    const ORGANIZATION_PREFIX_LOCAL: &str = ORGANIZATION_PREFIX;
    // MEASURED, not chosen: the contract records 15 and this list drives 9. Both halves come
    // out of the assertion below, so neither is a number anybody typed from memory.
    const UNDRIVEN: usize = 6;
    let doc: Value = serde_json::from_str(COMMITTED_SPEC).expect("the committed spec parses");
    let mut keyed: BTreeSet<String> = BTreeSet::new();
    for (template, entries) in doc["paths"].as_object().expect("paths") {
        if !template.starts_with(ORGANIZATION_PREFIX_LOCAL) {
            continue;
        }
        for (_method, entry) in entries.as_object().expect("operations") {
            let carries_key =
                entry["parameters"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|parameter| {
                        parameter["in"] == "header"
                            && parameter["name"]
                                .as_str()
                                .is_some_and(|name| name.eq_ignore_ascii_case("Idempotency-Key"))
                    });
            if carries_key {
                keyed.insert(
                    entry["operationId"]
                        .as_str()
                        .expect("every operation carries an id")
                        .to_owned(),
                );
            }
        }
    }
    assert!(
        !keyed.is_empty(),
        "the scan found no keyed organization operation at all, which is a broken scan rather \
         than a clean result"
    );

    // A scan that found nothing to subtract would pass direction 2 vacuously.
    let fixture = replay_fixture();
    let driven: BTreeSet<String> = keyed_writes(&fixture)
        .iter()
        .map(|(label, _, _)| {
            label
                .split_once('.')
                .expect("every label is module.operationId")
                .1
                .to_owned()
        })
        .collect();

    let unknown: Vec<&String> = driven.difference(&keyed).collect();
    assert!(
        unknown.is_empty(),
        "these entries name operations the contract does not record as keyed organization \
         writes: {unknown:?}"
    );

    let undriven: Vec<&String> = keyed.difference(&driven).collect();
    assert_eq!(
        undriven.len(),
        UNDRIVEN,
        "the contract records {} keyed organization operations and this test drives {}. If a \
         keyed route was ADDED, either drive it or raise the pin in the same change and say \
         why; if one was removed, lower it. Not driven: {undriven:?}",
        keyed.len(),
        driven.len()
    );
}

/// The one keyed create whose replay is NOT its original response.
///
/// Named once, here, rather than spelled at each of the three places that branch on it: a
/// string repeated at three sites is three places for it to stop matching the route.
const SECRET_BEARING_CREATE: &str = "scim_connections.createScimConnection";

/// A [`Fixture`] with placeholder ids, for the database-free checks.
///
/// The keyed-write list only needs the SHAPE of each request, and building it needs a fixture.
/// The ids never reach a database here.
fn replay_fixture() -> Fixture {
    Fixture {
        base: "/v1/tenants/ten_x/environments/env_x/organizations/org_x".to_owned(),
        org: "org_x".to_owned(),
        role: "rol_x".to_owned(),
        spare_role: "rol_y".to_owned(),
        group: "grp_x".to_owned(),
        child_group: "grp_y".to_owned(),
        membership: "omb_x".to_owned(),
        spare_membership: "omb_y".to_owned(),
        spare_user: "usr_x".to_owned(),
        permission: "prm_x".to_owned(),
        spare_permission: "prm_y".to_owned(),
        spare_client: "cli_y".to_owned(),
        grant: "pgt_x".to_owned(),
        member_user: "usr_m".to_owned(),
        agent: "agp_x".to_owned(),
        approval: "ava_x".to_owned(),
        service_account: "sva_x".to_owned(),
        scim_connection: "scim_x".to_owned(),
    }
}

#[tokio::test]
async fn a_keyed_writes_replay_survives_the_environments_deletion() {
    // The ORDERING the fence inherits, pinned rather than merely observed.
    //
    // `org_context::resolve_live_org` runs the environment precondition, and every one of
    // the keyed writes it drives calls it AFTER its idempotency replay. That ordering is what
    // keeps a retry of a request that ALREADY SUCCEEDED from turning into a 404 the
    // client cannot tell from "my write never landed", and it is the whole reason the
    // precondition was put inside the resolution each handler already called rather than
    // at the top of each handler.
    //
    // Nothing in the sweep above held it there: every request in that file uses a fresh
    // key, so the replay path was never driven against a deleted environment at all, and
    // hoisting the precondition above the replay in `create_org_role` left 126 tests
    // across 12 admin targets green. This test is the pin. It was verified to fail by
    // that exact hoist, and by nothing else in this file.
    //
    // Issue #409 established the same pin for the environment-scoped surface in
    // `tests/absent_environment.rs::a_replay_survives_the_environment_going_away`, on one
    // route. This drives EIGHT of the fourteen organization-addressed keyed writes (the
    // remainder is pinned by `the_keyed_write_list_is_measured_against_the_contract`), and adds
    // the FRESH-key control that one has no room for: without it a replay returning 201
    // is equally consistent with there being no fence at all.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let fixture = Fixture::seed(&h, &tenant, &environment, "k-seed").await;
    let writes = keyed_writes(&fixture);

    // Each keyed write once, while the environment is LIVE. The response it stores is
    // what the replay after the delete has to reproduce, byte for byte -- with the one
    // documented exception named at `SECRET_BEARING_CREATE`, whose stored body deliberately
    // differs from the response it first gave.
    let mut stored: Vec<(String, String)> = Vec::new();
    for (index, (label, path, body)) in writes.iter().enumerate() {
        let key = format!("k-replay-{index}");
        let (status, _, response) = h.post(path, &key, body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{label} at a LIVE environment: {response}"
        );
        if *label == SECRET_BEARING_CREATE {
            // The FIRST response carries the credential exactly once; the replay below must
            // not. Storing the first response here would make the "no token" assertion after
            // the delete compare against a body that had one, so the stored value is what the
            // replay is expected to be, and the difference is asserted right now.
            assert!(
                response.contains("\"token\""),
                "{label} must hand back the credential on the FIRST response: {response}"
            );
            let (replay_status, _, replayed) = h.post(path, &key, body).await;
            assert_eq!(
                replay_status,
                StatusCode::OK,
                "{label} replays 200 rather than 201: {replayed}"
            );
            stored.push((key, replayed));
            continue;
        }
        stored.push((key, response));
    }

    delete_environment(&h, &tenant, &environment).await;

    let (not_found_status, _, not_found_body) = uniform_not_found().await;
    for (index, (label, path, body)) in writes.iter().enumerate() {
        let (key, original) = &stored[index];
        // The SAME key and the same body: a genuine replay of a request that already
        // succeeded, which must still answer with what it answered the first time.
        let (status, _, response) = h.post(path, key, body).await;
        let expected = if *label == SECRET_BEARING_CREATE {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        assert_eq!(
            status, expected,
            "{label} replayed its original Idempotency-Key after the environment was \
             soft-deleted and got {status} instead of the response it already gave; the \
             environment precondition has been hoisted above the replay: {response}"
        );
        if *label == SECRET_BEARING_CREATE {
            // THE ONE ROUTE WHOSE REPLAY IS DELIBERATELY NOT THE ORIGINAL RESPONSE, and the
            // exemption is pinned rather than merely skipped.
            //
            // `idempotency_keys.response_body` is plaintext retained 24 hours. Storing this
            // route's 201 verbatim would put a live provisioning credential there -- the
            // recoverable copy migration 0183 exists to prevent, in a different table. So the
            // stored body carries `token_already_issued` and no token, and it is a 200 because
            // a 201 announcing a resource whose credential is absent is a worse lie than an
            // honest "you already have this".
            //
            // What this file's property actually is, and what still holds here: a replay of a
            // request that ALREADY SUCCEEDED never becomes a 404 because the environment went
            // away. The status and body below are asserted so the exemption cannot widen into
            // "this route answers whatever it likes".
            assert_eq!(&response, original, "{label} replayed a DIFFERENT body");
            assert!(
                response.contains("\"token_already_issued\":true"),
                "{label}'s replay must say the credential was already issued: {response}"
            );
            assert!(
                !response.contains("\"token\""),
                "{label}'s replay handed back the provisioning credential again: {response}"
            );
        } else {
            assert_eq!(
                &response, original,
                "{label} replayed a DIFFERENT body than the one it stored"
            );
        }

        // And the anchor, without which the assertion above would pass just as well with
        // no fence at all: the same route, the same body, a FRESH key, refused. So the
        // 201 above is the replay path surviving the fence, not the fence being absent.
        let (status, _, response) = h.post(path, &format!("k-fresh-{index}"), body).await;
        assert_eq!(
            status, not_found_status,
            "{label} with a FRESH key must be refused, or this test proves nothing about \
             the replay: {response}"
        );
        assert_eq!(response, not_found_body);
    }
}

#[tokio::test]
async fn a_soft_deleted_environments_organization_content_is_still_readable() {
    // The READ half of the policy, and the reason it is not merely "we did not get
    // round to fencing the reads". An operator who decommissions an environment has to
    // be able to see what is inside it, and the resurrection question this issue raises
    // (a restored environment comes back carrying whatever was written while deleted)
    // is only auditable if the listings still answer with the ROWS and not just a 200.
    //
    // So this asserts CONTENT and not status: the roles, the memberships and the role
    // assignments created while the environment was live are all still ENUMERABLE
    // afterwards, and enumerable is meant literally. An earlier revision claimed it for
    // the membership while only RESOLVING one (through `require_membership_in_org`,
    // inside the effective-roles read); the membership listing below is what makes the
    // word true.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    // The seed already defines two roles and grants one of them to the membership, both
    // while the environment is live. Nothing extra is written here, so everything the
    // reads below return was written BEFORE the delete.
    let fixture = Fixture::seed(&h, &tenant, &environment, "k-seed").await;
    let base = fixture.base.clone();

    delete_environment(&h, &tenant, &environment).await;

    let (status, _, body) = h.get(&format!("{base}/roles")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the role list still answers: {body}"
    );
    let listed: Vec<String> = serde_json::from_str::<Value>(&body).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(
        listed,
        vec![fixture.role.clone(), fixture.spare_role.clone()],
        "and it still names both roles defined while the environment was live"
    );

    let (status, _, body) = h.get(&format!("{base}/memberships")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the membership list still answers: {body}"
    );
    let listed: Vec<String> = serde_json::from_str::<Value>(&body).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(
        listed,
        vec![fixture.membership.clone(), fixture.spare_membership.clone()],
        "and it still ENUMERATES both memberships created while the environment was live"
    );

    let (status, _, body) = h
        .get(&format!(
            "{base}/memberships/{}/effective-roles",
            fixture.membership
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the effective-roles view still answers: {body}"
    );
    // Every one of the three grant PATHS the seed created is still resolved: the direct
    // grant, the one inherited through the group the membership was bound into, and the
    // organization's default-role designation. A list that answered 200 with an empty
    // array would satisfy a status-only assertion and would tell an operator auditing a
    // decommissioned environment exactly nothing.
    let mut paths: Vec<(String, String)> =
        serde_json::from_str::<Value>(&body).expect("json")["roles"]
            .as_array()
            .expect("roles")
            .iter()
            .map(|role| {
                (
                    role["slug"].as_str().expect("slug").to_owned(),
                    role["source"].as_str().expect("source").to_owned(),
                )
            })
            .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            ("billing.admin".to_owned(), "default".to_owned()),
            ("billing.admin".to_owned(), "direct".to_owned()),
            ("billing.admin".to_owned(), "group".to_owned()),
        ],
        "and it still resolves every grant path created while the environment was live"
    );
}

/// The case counts the prose used to state as numerals, measured.
///
/// # Why this exists
///
/// This file carried at least six hand-written counts ("all twenty two writes", "the other
/// twenty one", "the eleven together", "the seven keyed writes"). Every one of them was
/// written when it was true and none of them was derived, so adding cases moved the surface
/// and left the sentences behind: by the time a reviewer measured, the writes were 28 and the
/// reads 13, and this change would have made it 32 and 15 without touching a word.
///
/// The prose no longer states them. This does, so the numbers exist in exactly one place and
/// a change that moves them fails here rather than quietly making a paragraph wrong.
#[test]
fn the_case_counts_are_pinned_where_they_can_be_measured() {
    const WRITES: usize = 34;
    const READS: usize = 16;

    let cases = replay_fixture_cases();
    let writes = cases
        .iter()
        .filter(|case| matches!(case.intent, Intent::Write))
        .count();
    let reads = cases.len() - writes;
    assert_eq!(
        (writes, reads),
        (WRITES, READS),
        "the sweep drives {writes} writes and {reads} reads, not {WRITES} and {READS}. Update \
         these two constants in the change that moves them; nothing else in this file states \
         a count any more."
    );
}

/// Every case, built against placeholder ids. See [`replay_fixture`].
fn replay_fixture_cases() -> Vec<Case> {
    replay_fixture().cases()
}
