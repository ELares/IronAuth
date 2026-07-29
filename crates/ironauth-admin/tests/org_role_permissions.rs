// SPDX-License-Identifier: MIT OR Apache-2.0

//! The role-to-permission MAPPING and the organization DEFAULT ROLE over HTTP
//! (issue #98, PR 8), driven through the management router against a real database.
//!
//! Two properties have to be proved here that no earlier suite of this issue proves,
//! and they pull in opposite directions, which is why the fixtures below are built
//! the way they are.
//!
//!   * CROSS ORGANIZATION containment, exactly as #97's suite proves it. Row-level
//!     security fences `(tenant, environment)` and nothing finer, so inside one
//!     environment the `organization_id` predicate is the whole fence between two
//!     organizations. Every containment test stands up a SECOND organization holding
//!     its own rows.
//!   * CROSS ENVIRONMENT containment, exactly as the vocabulary suite proves it,
//!     because the PERMISSION half of a mapping hangs off the environment and has no
//!     organization at all. Every cross-scope fixture differs from its counterpart in
//!     the ENVIRONMENT ALONE, under ONE tenant. A second tenant would also be refused
//!     by the tenant predicate, so it would prove nothing about the environment half.
//!
//! A mapping joins one to the other, so a CROSS PAIRING has two directions and both
//! are exercised: this organization's path with a role of a sibling ORGANIZATION, and
//! this organization's role with a permission of a sibling ENVIRONMENT. Both must be
//! the same uniform not-found, or the difference tells a caller which half was wrong
//! and turns either vocabulary into an enumeration oracle.
//!
//! # The read a nested route must NOT use
//!
//! `OrgRolePermissionRepo::get` is deliberately organization-blind: given a
//! well-formed mapping id of this scope it returns that row whatever organization it
//! belongs to. A management route nested under an organization must resolve through
//! `get_in_org` or `get_assignment` instead, or it hands back and then detaches a
//! sibling organization's capability grant with nothing in front of it. Two things
//! here hold that:
//!
//!   * No route accepts an `rpm_` id at all: the mapping is PAIR addressed, so there
//!     is no wire shape that could reach the by-id read.
//!   * `a_mapping_of_a_sibling_organization_is_unreachable_through_this_path` drives
//!     the pair address from the wrong organization and asserts the uniform 404 with
//!     the mapping still live and the audit multiset unchanged.

mod common;

use std::collections::HashSet;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// Create a tenant with an environment.
async fn tenant_env(h: &Harness) -> (String, String) {
    h.create_tenant("acme", "k-tenant").await
}

/// The `id` field of a JSON response body.
fn id_of(response: &str) -> String {
    serde_json::from_str::<Value>(response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Create an organization and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    id_of(&response)
}

/// The `.../organizations/{org}/roles` base path.
fn roles_base(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/roles")
}

/// The `.../organizations/{org}/default-role` path: ONE address for a single-valued
/// property of the organization.
fn default_role_path(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/default-role")
}

/// The ENVIRONMENT-level permission vocabulary base path. No organization segment,
/// by design (migration 0091).
fn permissions_base(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/permissions")
}

/// The `.../organizations/{org}/roles/{role}/permissions` base path: the mapping.
fn mapping_base(tenant: &str, environment: &str, org: &str, role: &str) -> String {
    format!(
        "{}/{role}/permissions",
        roles_base(tenant, environment, org)
    )
}

/// Define a role in an organization, asserting a 201, and return its id.
async fn create_role(h: &Harness, base: &str, slug: &str, key: &str) -> String {
    let body = serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string();
    let (status, _, response) = h.post(base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create role: {response}");
    id_of(&response)
}

/// Define a permission in an environment, asserting a 201, and return its id.
async fn create_permission(h: &Harness, base: &str, slug: &str, key: &str) -> String {
    let body = serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string();
    let (status, _, response) = h.post(base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create permission: {response}");
    id_of(&response)
}

/// An attach body.
fn attach_body(permission: &str) -> String {
    serde_json::json!({ "permission_id": permission }).to_string()
}

/// A designate body.
fn designate_body(role: &str) -> String {
    serde_json::json!({ "role_id": role }).to_string()
}

/// Attach a permission to a role, asserting a 201, and return the mapping id.
async fn attach(h: &Harness, base: &str, permission: &str, key: &str) -> String {
    let (status, _, response) = h.post(base, key, &attach_body(permission)).await;
    assert_eq!(status, StatusCode::CREATED, "attach: {response}");
    id_of(&response)
}

/// The sorted set of `id` values on a list page, so an assertion pins the WHOLE set
/// rather than a membership.
async fn list_ids(h: &Harness, base: &str) -> Vec<String> {
    let (status, _, response) = h.get(base).await;
    assert_eq!(status, StatusCode::OK, "list {base}: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let mut ids: Vec<String> = value["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect();
    ids.sort();
    ids
}

/// The sorted set of `permission_id` values a role's mapping list reports.
async fn granted_permissions(h: &Harness, base: &str) -> Vec<String> {
    let (status, _, response) = h.get(base).await;
    assert_eq!(status, StatusCode::OK, "list {base}: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let mut ids: Vec<String> = value["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["permission_id"].as_str().expect("id").to_owned())
        .collect();
    ids.sort();
    ids
}

/// A field of a resource read back through its own address.
async fn field(h: &Harness, path: &str, name: &str) -> Value {
    let (status, _, response) = h.get(path).await;
    assert_eq!(status, StatusCode::OK, "get {path}: {response}");
    serde_json::from_str::<Value>(&response).expect("json")[name].clone()
}

/// The ids of the roles an organization's role list reports as its DEFAULT, which is
/// the whole of what the designation is observable as through the API.
async fn default_roles(h: &Harness, base: &str) -> Vec<String> {
    let (status, _, response) = h.get(base).await;
    assert_eq!(status, StatusCode::OK, "list roles: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let mut ids: Vec<String> = value["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|item| item["is_default"].as_bool().expect("is_default"))
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect();
    ids.sort();
    ids
}

/// The `(tenant, environment)` scope parsed from two id path segments.
fn scope_of(tenant: &str, environment: &str) -> ironauth_store::Scope {
    use ironauth_store::{EnvironmentId, Scope, TenantId};
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// A well-formed permission id in the given scope that was never created.
fn fresh_in_scope_permission(tenant: &str, environment: &str) -> String {
    ironauth_store::PermissionId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// A well-formed role id in the given scope that was never created.
fn fresh_in_scope_role(tenant: &str, environment: &str) -> String {
    ironauth_store::OrgRoleId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// A well-formed ORGANIZATION id in the given scope: the right scope and the WRONG
/// KIND, which must be as unaddressable as nonsense.
fn fresh_in_scope_org(tenant: &str, environment: &str) -> String {
    ironauth_store::OrganizationId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// Every audit action in one scope whose name starts with `prefix`, sorted: the audit
/// MULTISET, compared whole so an extra row is as visible as a missing one.
async fn audit_actions(h: &Harness, tenant: &str, environment: &str, prefix: &str) -> Vec<String> {
    let mut actions: Vec<String> = h
        .control_store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .filter(|action| action.starts_with(prefix))
        .collect();
    actions.sort();
    actions
}

/// The `target_id` of every audit row carrying `action`, in the order they were
/// written: what the audit trail says each write ACTED ON, which for the two
/// designation actions is the only place the outgoing and incoming role are named.
async fn audit_targets(h: &Harness, tenant: &str, environment: &str, action: &str) -> Vec<String> {
    h.control_store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .filter(|row| row.action == action)
        .map(|row| row.target_id)
        .collect()
}

/// The mapping audit multiset.
async fn mapping_audit(h: &Harness, tenant: &str, environment: &str) -> Vec<String> {
    audit_actions(h, tenant, environment, "organization.role.permission.").await
}

/// The default-role audit multiset.
async fn default_role_audit(h: &Harness, tenant: &str, environment: &str) -> Vec<String> {
    audit_actions(h, tenant, environment, "organization.default_role.").await
}

/// Assert a response is the LOUD wrong-scope refusal: a 403 whose body names the
/// error. A credential presented against an environment it is not authorized for is
/// the LOUD case, never the uniform not-found.
fn assert_wrong_scope(label: &str, status: StatusCode, body: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{label}: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(body).expect("json")["error"],
        "wrong_scope",
        "{label} must be the LOUD wrong-scope refusal: {body}"
    );
}

/// Walk a list endpoint at `limit` rows per page, returning every id seen and the
/// number of pages. Asserts that no page exceeds the limit, that no row is returned
/// twice, and that the walk terminates.
async fn walk_pages(h: &Harness, base: &str, limit: usize) -> (HashSet<String>, usize) {
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(value) => format!("{base}?limit={limit}&cursor={value}"),
            None => format!("{base}?limit={limit}"),
        };
        let (status, _, response) = h.get(&path).await;
        assert_eq!(status, StatusCode::OK, "page {pages}: {response}");
        let value: Value = serde_json::from_str(&response).expect("json");
        let items = value["items"].as_array().expect("items");
        assert!(
            items.len() <= limit,
            "a page never exceeds the requested limit: {response}"
        );
        for item in items {
            let id = item["id"].as_str().expect("id").to_owned();
            assert!(seen.insert(id), "no row appears on two pages: {response}");
        }
        pages += 1;
        assert!(pages <= 20, "the walk did not terminate");
        match value["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    (seen, pages)
}

// One test rather than three: the audit MULTISET is checked at every step, and a
// multiset assertion only means anything if every step before it ran against the same
// scope in the same order.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn mapping_attach_list_and_detach_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let perms = permissions_base(&tenant, &environment);
    let role = create_role(&h, &roles, "billing.admin", "k-role").await;
    let read = create_permission(&h, &perms, "billing.invoice.read", "k-p1").await;
    let write = create_permission(&h, &perms, "billing.invoice.write", "k-p2").await;
    let base = mapping_base(&tenant, &environment, &org, &role);

    assert!(
        mapping_audit(&h, &tenant, &environment).await.is_empty(),
        "the mapping audit trail starts empty"
    );
    assert!(
        list_ids(&h, &base).await.is_empty(),
        "a role grants nothing until something is attached"
    );

    let (status, _, response) = h.post(&base, "k-a1", &attach_body(&read)).await;
    assert_eq!(status, StatusCode::CREATED, "attach: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let mapping = value["id"].as_str().expect("id").to_owned();
    assert!(
        mapping.starts_with("rpm_"),
        "the mapping id is typed: {mapping}"
    );
    assert_eq!(value["organization_id"], org.as_str());
    assert_eq!(value["role_id"], role.as_str());
    assert_eq!(value["permission_id"], read.as_str());
    assert_eq!(
        mapping_audit(&h, &tenant, &environment).await,
        vec!["organization.role.permission.assign"],
        "the attach audits exactly once"
    );

    // The attach response is composed BEFORE the write from values the handler holds,
    // so a divergence between what it promised and what it stored would be invisible
    // without reading the row back through the list.
    let (status, _, listed) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "list: {listed}");
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"][0],
        value,
        "the attach response must describe the row the list returns"
    );
    assert_eq!(
        mapping_audit(&h, &tenant, &environment).await,
        vec!["organization.role.permission.assign"],
        "reads audit nothing"
    );

    // A SECOND permission on the same role, and the same permission on a SECOND role:
    // both directions are uncapped and neither is a conflict.
    let second_role = create_role(&h, &roles, "billing.viewer", "k-role2").await;
    let second_base = mapping_base(&tenant, &environment, &org, &second_role);
    attach(&h, &base, &write, "k-a2").await;
    attach(&h, &second_base, &read, "k-a3").await;
    assert_eq!(
        granted_permissions(&h, &base).await,
        {
            let mut expected = vec![read.clone(), write.clone()];
            expected.sort();
            expected
        },
        "the role carries both permissions"
    );
    assert_eq!(
        granted_permissions(&h, &second_base).await,
        vec![read.clone()],
        "and the second role carries the shared one"
    );

    // A duplicate attach of a LIVE pair is the documented 409. Without the handler's
    // conflict arm the partial unique index surfaces as an opaque 500.
    let (status, _, response) = h.post(&base, "k-dup", &attach_body(&read)).await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate attach: {response}");
    assert_eq!(
        granted_permissions(&h, &base).await.len(),
        2,
        "the refused attach wrote no row"
    );

    // Detach: 204, gone from the list, and the pair is free again with a FRESH id.
    let detach_path = format!("{base}/{read}");
    let (status, _, _) = h.delete(&detach_path).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        granted_permissions(&h, &base).await,
        vec![write.clone()],
        "the detached permission is gone from this role"
    );
    assert_eq!(
        granted_permissions(&h, &second_base).await,
        vec![read.clone()],
        "and the OTHER role's mapping of the same permission is untouched"
    );
    let reattached = attach(&h, &base, &read, "k-a4").await;
    assert_ne!(
        reattached, mapping,
        "a re-attach mints a FRESH mapping rather than reviving the withdrawn one"
    );

    let after = mapping_audit(&h, &tenant, &environment).await;
    assert_eq!(
        after,
        vec![
            "organization.role.permission.assign",
            "organization.role.permission.assign",
            "organization.role.permission.assign",
            "organization.role.permission.assign",
            "organization.role.permission.unassign",
        ],
        "four attaches and one detach; the refused duplicate audited nothing"
    );

    // A repeat detach matches no live row and audits nothing.
    let (status, _, _) = h.delete(&detach_path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the re-attached pair");
    let (status, _, _) = h.delete(&detach_path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat detach is 404");
    let mut expected = after.clone();
    expected.push("organization.role.permission.unassign".to_owned());
    expected.sort();
    assert_eq!(
        mapping_audit(&h, &tenant, &environment).await,
        expected,
        "the refused repeat detach audits nothing"
    );
}

#[tokio::test]
async fn deleting_a_permission_leaves_the_mapping_detachable_and_writes_no_detach() {
    // Migration 0092: deleting a permission does NOT cascade here. Two consequences
    // an operator depends on, and neither is implied by the other:
    //
    //   * The detach audit action is NOT written, so its absence never means the
    //     mapping is still in force.
    //   * The orphaned mapping row stays DETACHABLE through its own pair address. If
    //     the detach resolved the permission as live first, that row would be
    //     unreachable forever, which is the shape of defect that leaves a table
    //     accumulating rows no supported path can remove.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let perms = permissions_base(&tenant, &environment);
    let role = create_role(&h, &roles, "billing.admin", "k-role").await;
    let permission = create_permission(&h, &perms, "billing.invoice.read", "k-p").await;
    let base = mapping_base(&tenant, &environment, &org, &role);
    attach(&h, &base, &permission, "k-a").await;

    let (status, _, _) = h.delete(&format!("{perms}/{permission}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the permission is deleted");
    assert_eq!(
        mapping_audit(&h, &tenant, &environment).await,
        vec!["organization.role.permission.assign"],
        "deleting a permission writes no detach action"
    );
    assert_eq!(
        granted_permissions(&h, &base).await,
        vec![permission.clone()],
        "the mapping row is still LIVE; the resolution stops selecting it on the \
         permission's own liveness filter instead"
    );

    let (status, _, response) = h.delete(&format!("{base}/{permission}")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the orphaned mapping is still detachable: {response}"
    );
    assert!(granted_permissions(&h, &base).await.is_empty());
    assert_eq!(
        mapping_audit(&h, &tenant, &environment).await,
        vec![
            "organization.role.permission.assign",
            "organization.role.permission.unassign",
        ],
    );
}

// The parallel `*_one` / `*_two` names track the two organizations; the test is one
// indivisible proof over three endpoints, so it is not split.
#[allow(clippy::similar_names, clippy::too_many_lines)]
#[tokio::test]
async fn a_mapping_of_a_sibling_organization_is_unreachable_through_this_path() {
    // The constraint the store PR's review wrote for this one. `OrgRolePermissionRepo::get`
    // is organization-blind by design, so a nested route that resolved through it
    // would hand back and then detach a sibling organization's capability grant with
    // no fence in front of it: row-level security cannot refuse that, because it
    // fences `(tenant, environment)` and cannot see `organization_id`.
    //
    // Both cross pairings are driven, in both directions, and the assertion is always
    // the same uniform 404 with NOTHING mutated:
    //
    //   1. this organization's path, the OTHER organization's role;
    //   2. the OTHER organization's path, this organization's role, over a mapping
    //      that genuinely exists.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org_one = create_org(&h, &tenant, &environment, "k-org-1").await;
    let org_two = create_org(&h, &tenant, &environment, "k-org-2").await;
    let perms = permissions_base(&tenant, &environment);
    let role_one = create_role(
        &h,
        &roles_base(&tenant, &environment, &org_one),
        "billing.admin",
        "k-r1",
    )
    .await;
    let role_two = create_role(
        &h,
        &roles_base(&tenant, &environment, &org_two),
        "billing.admin",
        "k-r2",
    )
    .await;
    let permission = create_permission(&h, &perms, "billing.invoice.read", "k-p").await;

    let base_one = mapping_base(&tenant, &environment, &org_one, &role_one);
    let base_two = mapping_base(&tenant, &environment, &org_two, &role_two);
    let mapping_one = attach(&h, &base_one, &permission, "k-a1").await;
    attach(&h, &base_two, &permission, "k-a2").await;

    // The reference answer: a pair that is simply not attached, addressed inside the
    // caller's own organization with both halves live and visible.
    let unattached = create_permission(&h, &perms, "billing.invoice.write", "k-p2").await;
    let (absent_status, _, absent_body) = h.delete(&format!("{base_one}/{unattached}")).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_str::<Value>(&absent_body).expect("json")["error"],
        "not_found"
    );

    // --- Direction 1: organization one's path, organization TWO's role. ---
    let crossed_one = mapping_base(&tenant, &environment, &org_one, &role_two);
    let (status, _, body) = h.delete(&format!("{crossed_one}/{permission}")).await;
    assert_eq!(status, absent_status, "cross-organization detach: {body}");
    assert_eq!(body, absent_body, "cross-organization detach body");
    let (status, _, body) = h.get(&crossed_one).await;
    assert_eq!(status, absent_status, "cross-organization list: {body}");
    assert_eq!(body, absent_body, "cross-organization list body");
    let (status, _, body) = h
        .post(&crossed_one, "k-x1", &attach_body(&unattached))
        .await;
    assert_eq!(status, absent_status, "cross-organization attach: {body}");
    assert_eq!(body, absent_body, "cross-organization attach body");

    // --- Direction 2: organization TWO's path, organization one's role, over a
    //     mapping that genuinely exists. ---
    let crossed_two = mapping_base(&tenant, &environment, &org_two, &role_one);
    let (status, _, body) = h.delete(&format!("{crossed_two}/{permission}")).await;
    assert_eq!(status, absent_status, "reverse cross detach: {body}");
    assert_eq!(body, absent_body, "reverse cross detach body");
    let (status, _, body) = h.get(&crossed_two).await;
    assert_eq!(status, absent_status, "reverse cross list: {body}");
    assert_eq!(body, absent_body, "reverse cross list body");
    assert!(
        !body.contains(&mapping_one) && !body.contains(&role_one),
        "the refusal must not echo the other organization's mapping: {body}"
    );

    // NOTHING moved. Both organizations still grant exactly what they granted, the
    // mapping the cross detaches named is still live under its own id, and no probe
    // wrote an audit row.
    assert_eq!(
        list_ids(&h, &base_one).await,
        vec![mapping_one],
        "organization one still holds its mapping"
    );
    assert_eq!(
        granted_permissions(&h, &base_two).await,
        vec![permission],
        "and organization two holds its own"
    );
    assert_eq!(
        mapping_audit(&h, &tenant, &environment).await,
        vec![
            "organization.role.permission.assign",
            "organization.role.permission.assign",
        ],
        "the two seeded attaches and nothing else: no probe wrote an audit row"
    );
}

#[allow(clippy::similar_names)]
#[tokio::test]
async fn attaching_a_permission_of_a_sibling_environment_is_the_uniform_not_found() {
    // The OTHER half of the cross pairing, and the one #97's suite has no shape for:
    // the permission side of a mapping hangs off the ENVIRONMENT, so the wrong-parent
    // case there is a sibling ENVIRONMENT rather than a sibling organization. The two
    // environments share a tenant, so the environment half of the fence is the only
    // thing that can be doing the work.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let org = create_org(&h, &tenant, &env_one, "k-org").await;
    let role = create_role(
        &h,
        &roles_base(&tenant, &env_one, &org),
        "billing.admin",
        "k-r",
    )
    .await;
    let base = mapping_base(&tenant, &env_one, &org, &role);

    // A permission that genuinely EXISTS, in the other environment. Probing an id
    // nobody ever minted would pass with the environment fence deleted.
    let foreign = create_permission(
        &h,
        &permissions_base(&tenant, &env_two),
        "billing.invoice.read",
        "k-seed-foreign",
    )
    .await;
    // The reference: a well-formed, in-scope permission id that was never created.
    let absent = fresh_in_scope_permission(&tenant, &env_one);

    let (absent_status, _, absent_body) = h.post(&base, "k-absent", &attach_body(&absent)).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    let (status, _, body) = h.post(&base, "k-foreign", &attach_body(&foreign)).await;
    assert_eq!(
        status, absent_status,
        "a permission of a sibling environment must be the same answer: {body}"
    );
    assert_eq!(body, absent_body, "cross-environment attach body");
    assert!(
        list_ids(&h, &base).await.is_empty(),
        "neither refused attach wrote a row"
    );
    assert!(
        mapping_audit(&h, &tenant, &env_one).await.is_empty(),
        "and neither wrote an audit row"
    );

    // The positive control: the SAME slug defined in THIS environment attaches, so
    // the two refusals are attributable to the environment fence rather than to an
    // attach that never works.
    let own = create_permission(
        &h,
        &permissions_base(&tenant, &env_one),
        "billing.invoice.read",
        "k-own",
    )
    .await;
    attach(&h, &base, &own, "k-ok").await;
}

#[tokio::test]
async fn attaching_a_soft_deleted_permission_is_the_uniform_not_found() {
    // The layer the sibling-environment test CANNOT reach, and the reason it needs its
    // own case. A permission of another environment is refused at the edge, because its
    // typed id fails to parse in this scope, so that test says nothing about the
    // store's liveness resolution. A permission of THIS environment that has been
    // DELETED parses perfectly and reaches the write, where `require_live_permission`
    // is the only thing between it and a mapping onto a capability name nobody can see
    // any more. The foreign key would not refuse it: a soft-deleted row is retained, so
    // it satisfies the constraint exactly like a live one.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let perms = permissions_base(&tenant, &environment);
    let role = create_role(&h, &roles, "billing.admin", "k-r").await;
    let deleted = create_permission(&h, &perms, "billing.invoice.read", "k-p").await;
    let base = mapping_base(&tenant, &environment, &org, &role);

    let (status, _, _) = h.delete(&format!("{perms}/{deleted}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the permission is deleted");

    // The reference: a well-formed, in-scope permission id that was never created.
    let absent = fresh_in_scope_permission(&tenant, &environment);
    let (absent_status, _, absent_body) = h.post(&base, "k-absent", &attach_body(&absent)).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);

    let (status, _, body) = h.post(&base, "k-deleted", &attach_body(&deleted)).await;
    assert_eq!(
        status, absent_status,
        "a soft-deleted permission must be the same answer as one that never \
         existed: {body}"
    );
    assert_eq!(body, absent_body, "soft-deleted attach body");
    assert!(
        list_ids(&h, &base).await.is_empty(),
        "and it attached nothing"
    );
    assert!(mapping_audit(&h, &tenant, &environment).await.is_empty());

    // The positive control: the slug is free again, and a FRESH permission of the same
    // name attaches, so the refusal is attributable to the liveness resolution rather
    // than to an attach that stopped working.
    let fresh = create_permission(&h, &perms, "billing.invoice.read", "k-p2").await;
    attach(&h, &base, &fresh, "k-ok").await;
}

// The test is one indivisible proof over three endpoints and six id shapes, so it is
// not split.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn every_mapping_addressing_failure_is_the_uniform_not_found_byte_for_byte() {
    // A capability grant is exactly the thing an enumeration oracle must not leak, so
    // every unreachable address collapses to ONE answer, byte for byte in status AND
    // body, on the list, the attach, and the detach.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let org = create_org(&h, &tenant, &env_one, "k-org").await;
    let other_org = create_org(&h, &tenant, &env_one, "k-org-2").await;
    let roles = roles_base(&tenant, &env_one, &org);
    let role = create_role(&h, &roles, "billing.admin", "k-r").await;
    let other_role = create_role(
        &h,
        &roles_base(&tenant, &env_one, &other_org),
        "billing.admin",
        "k-r2",
    )
    .await;
    let permission = create_permission(
        &h,
        &permissions_base(&tenant, &env_one),
        "billing.invoice.read",
        "k-p",
    )
    .await;
    let foreign_permission = create_permission(
        &h,
        &permissions_base(&tenant, &env_two),
        "billing.invoice.read",
        "k-fp",
    )
    .await;

    // A role of this organization that has been soft-deleted.
    let deleted_role = create_role(&h, &roles, "gone", "k-gone").await;
    let (status, _, _) = h.delete(&format!("{roles}/{deleted_role}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The reference: a well-formed, in-scope ROLE id that was never created.
    let absent_role = fresh_in_scope_role(&tenant, &env_one);

    let role_probes = [
        ("soft-deleted role", deleted_role.clone()),
        ("sibling organization's role", other_role.clone()),
        ("malformed", "rol_not-a-real-id".to_owned()),
        // Well formed and of THIS scope, but the wrong KIND of id.
        ("wrong prefix", fresh_in_scope_org(&tenant, &env_one)),
        (
            "wrong prefix, sibling family",
            format!("prm_{}", &absent_role[4..]),
        ),
        // A segment that is present but carries nothing addressable. Percent encoded
        // so it REACHES the handler as a one-character id.
        ("blank", "%20".to_owned()),
    ];

    // --- The LIST, addressed by an unreachable role. ---
    let absent_base = mapping_base(&tenant, &env_one, &org, &absent_role);
    let (absent_status, _, absent_body) = h.get(&absent_base).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_str::<Value>(&absent_body).expect("json")["error"],
        "not_found"
    );
    for (label, probe) in &role_probes {
        let base = mapping_base(&tenant, &env_one, &org, probe);
        let (status, _, body) = h.get(&base).await;
        assert_eq!(status, absent_status, "list probe {label}: {body}");
        assert_eq!(body, absent_body, "list probe {label} body");
    }

    // --- The ATTACH, with a body every layer accepts, so nothing about the request
    //     itself can be what refuses it. ---
    let (absent_status, _, absent_body) = h
        .post(&absent_base, "k-ref", &attach_body(&permission))
        .await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    for (index, (label, probe)) in role_probes.iter().enumerate() {
        let base = mapping_base(&tenant, &env_one, &org, probe);
        let (status, _, body) = h
            .post(&base, &format!("k-att-{index}"), &attach_body(&permission))
            .await;
        assert_eq!(status, absent_status, "attach probe {label}: {body}");
        assert_eq!(body, absent_body, "attach probe {label} body");
    }
    // A body the EDGE alone would refuse must still answer on the ADDRESS. This is
    // the ordering assertion and the only thing that pins it: the probes above carry
    // a body every layer accepts, so they pass whether the address is resolved first
    // or last. A body that is not JSON at all becomes a distinguishing 400 the moment
    // parsing runs before the organization resolves, and a caller could then separate
    // "not yours" from "does not exist" by the status alone.
    let unreachable_org = mapping_base(
        &tenant,
        &env_one,
        &fresh_in_scope_org(&tenant, &env_one),
        &role,
    );
    for (label, base) in [
        ("unreachable role", absent_base.clone()),
        ("unreachable organization", unreachable_org.clone()),
    ] {
        for (shape, request) in [
            ("unparseable", "not json at all"),
            ("no permission_id", "{}"),
        ] {
            let (status, _, body) = h
                .post(&base, &format!("k-body-{label}-{shape}"), request)
                .await;
            assert_eq!(
                status, absent_status,
                "attach at an {label} with an {shape} body must answer on the address: {body}"
            );
            assert_eq!(body, absent_body, "attach {label}, {shape} body");
        }
    }

    // --- The DETACH, over the PERMISSION segment as well as the role segment. ---
    let base = mapping_base(&tenant, &env_one, &org, &role);
    let unattached = fresh_in_scope_permission(&tenant, &env_one);
    let (absent_status, _, absent_body) = h.delete(&format!("{base}/{unattached}")).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    for (label, probe) in &role_probes {
        let probe_base = mapping_base(&tenant, &env_one, &org, probe);
        let (status, _, body) = h.delete(&format!("{probe_base}/{permission}")).await;
        assert_eq!(status, absent_status, "detach role probe {label}: {body}");
        assert_eq!(body, absent_body, "detach role probe {label} body");
    }
    for (label, probe) in [
        // A permission that EXISTS in this environment but is not attached.
        ("live but unattached", permission.clone()),
        ("sibling environment", foreign_permission.clone()),
        ("malformed", "prm_not-a-real-id".to_owned()),
        ("wrong prefix", fresh_in_scope_org(&tenant, &env_one)),
        ("blank", "%20".to_owned()),
    ] {
        let (status, _, body) = h.delete(&format!("{base}/{probe}")).await;
        assert_eq!(
            status, absent_status,
            "detach permission probe {label}: {body}"
        );
        assert_eq!(body, absent_body, "detach permission probe {label} body");
    }

    // --- The EMPTY path segment, stated separately and honestly. ---
    //
    // `.../permissions/` matches no route, so axum refuses it before any handler, any
    // scope check, and any store read run: the answer is a 404 with an EMPTY body
    // rather than this API's structured one. That is a genuine difference and it is
    // not papered over. It is also not an oracle, and this is the assertion that
    // proves it: the refusal is identical whichever ORGANIZATION the path names, so it
    // reveals only that no route exists, which is true for every caller alike.
    let (one_status, _, one_body) = h.delete(&format!("{base}/")).await;
    let other_base = mapping_base(&tenant, &env_one, &other_org, &other_role);
    let (two_status, _, two_body) = h.delete(&format!("{other_base}/")).await;
    assert_eq!(
        one_status,
        StatusCode::NOT_FOUND,
        "an empty final segment is a 404: {one_body}"
    );
    assert_eq!(one_status, two_status, "empty-segment status");
    assert_eq!(one_body, two_body, "empty-segment body");

    // Nothing anywhere was touched.
    assert!(list_ids(&h, &base).await.is_empty());
    assert!(list_ids(&h, &other_base).await.is_empty());
    assert!(
        mapping_audit(&h, &tenant, &env_one).await.is_empty(),
        "no probe wrote a mapping audit row"
    );
}

#[allow(clippy::similar_names)]
#[tokio::test]
async fn an_idempotency_key_replay_is_byte_identical_and_never_crosses_a_scope_or_credential() {
    // An idempotency key is namespaced by the ACTING CREDENTIAL alone: the stored rows
    // carry no scope column, and the OPERATOR is one credential across every tenant
    // and environment. The only thing keeping one credential's stored response from
    // being served for a DIFFERENT resource is that the fingerprint covers the
    // concrete request PATH.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let perms = permissions_base(&tenant, &environment);
    let role_one = create_role(&h, &roles, "billing.admin", "k-r1").await;
    let role_two = create_role(&h, &roles, "billing.viewer", "k-r2").await;
    let read = create_permission(&h, &perms, "billing.invoice.read", "k-p1").await;
    let write = create_permission(&h, &perms, "billing.invoice.write", "k-p2").await;
    let base_one = mapping_base(&tenant, &environment, &org, &role_one);
    let base_two = mapping_base(&tenant, &environment, &org, &role_two);

    let (status, _, first) = h.post(&base_one, "shared-key", &attach_body(&read)).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let mapping = id_of(&first);

    // 1. A genuine replay: byte-identical, and no second row or audit row.
    let (status, _, replay) = h.post(&base_one, "shared-key", &attach_body(&read)).await;
    assert_eq!(status, StatusCode::CREATED, "a replay repeats the original");
    assert_eq!(first, replay, "byte-identical replay");
    assert_eq!(list_ids(&h, &base_one).await, vec![mapping.clone()]);
    assert_eq!(
        mapping_audit(&h, &tenant, &environment).await,
        vec!["organization.role.permission.assign"],
        "the replay wrote no second audit row"
    );

    // 2. The SAME key with a DIFFERENT body is the 422 key-conflict, not a second
    //    mapping and not the first one handed back.
    let (status, _, response) = h.post(&base_one, "shared-key", &attach_body(&write)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
    assert_eq!(list_ids(&h, &base_one).await, vec![mapping.clone()]);

    // 3. The same key and the same body under a DIFFERENT ROLE, under the same
    //    operator credential. This is the case the credential-only namespace makes
    //    possible, so it is asserted directly rather than inferred: the fingerprint
    //    covers the path, and the path is what differs.
    let (status, _, response) = h.post(&base_two, "shared-key", &attach_body(&read)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "cross-role replay: {response}"
    );
    assert!(
        !response.contains(&mapping),
        "the refusal must not echo the first role's mapping: {response}"
    );
    assert!(
        list_ids(&h, &base_two).await.is_empty(),
        "and it attached nothing to the second role"
    );

    // 4. A DIFFERENT CREDENTIAL replaying the same key against the SAME path and body
    //    EXECUTES rather than reading the operator's stored response. It reaches the
    //    store and collides with the live pair, and a 409 is only reachable from the
    //    write, so it is the proof that no replay happened.
    let key = h.create_key(&tenant, &environment, "ci", "k-key").await;
    let (status, _, response) = h
        .post_as(&base_one, &key, "shared-key", &attach_body(&read))
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "another credential executes rather than replaying: {response}"
    );
    assert_eq!(
        list_ids(&h, &base_one).await,
        vec![mapping],
        "and it created no second mapping"
    );
}

#[tokio::test]
async fn a_replay_survives_the_parent_organization_going_away() {
    // The ORDERING of the two preconditions on the attach path, and the only thing
    // that pins it. The Idempotency-Key replay runs BEFORE the parent-existence
    // check, so a genuine replay returns the original response even if the
    // organization was deleted in between. Moving the parent check ahead of the
    // replay would turn a retry of a request that ALREADY SUCCEEDED into a 404, which
    // a retrying client cannot distinguish from "my write never landed".
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let role = create_role(
        &h,
        &roles_base(&tenant, &environment, &org),
        "billing.admin",
        "k-r",
    )
    .await;
    let permission = create_permission(
        &h,
        &permissions_base(&tenant, &environment),
        "billing.invoice.read",
        "k-p",
    )
    .await;
    let base = mapping_base(&tenant, &environment, &org, &role);

    let (status, _, first) = h.post(&base, "k-replay", &attach_body(&permission)).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    let (status, _, _) = h
        .delete(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}"
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the organization is deleted"
    );

    let (status, _, replay) = h.post(&base, "k-replay", &attach_body(&permission)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a replay must survive the parent going away: {replay}"
    );
    assert_eq!(first, replay, "and it is byte-identical to the original");
}

#[tokio::test]
async fn an_attach_into_an_unreachable_environment_is_never_a_server_error() {
    // `org_role_permissions` carries a composite foreign key to `environments`, which
    // is the constraint that turns a well-formed but absent environment into an opaque
    // 500 on the ENVIRONMENT-scoped vocabulary create, and is why that create gained a
    // `require_live_environment` precondition. This handler has none, and the claim
    // that it needs none is MEASURED here rather than reasoned about.
    //
    // `organizations` carries the same foreign key, so `resolve_live_org` cannot
    // succeed in an environment whose row does not exist, and the insert can never
    // reach the constraint. The absent and the malformed environment are therefore one
    // answer, and neither is a 500.
    //
    // The SOFT-DELETED environment is the case that is NOT a refusal, and it is
    // asserted rather than quietly left out. Deleting an environment does not cascade
    // to its organizations, so `resolve_live_org` still resolves and the write lands.
    // That is a property of every ORGANIZATION-NESTED write in the tree and not
    // something this surface introduces, which is why the shipped
    // `POST .../organizations/{org}/roles` is driven side by side in the same fixture:
    // the two agreeing is the mechanical form of that claim, and if a later change
    // makes one of them refuse, this test says so instead of the prose quietly going
    // stale.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let role = create_role(
        &h,
        &roles_base(&tenant, &environment, &org),
        "billing.admin",
        "k-r",
    )
    .await;
    let permission = create_permission(
        &h,
        &permissions_base(&tenant, &environment),
        "billing.invoice.read",
        "k-p",
    )
    .await;

    // The reference: a malformed environment segment, refused by the parse alone.
    let (malformed_status, _, malformed_body) = h
        .post(
            &mapping_base(&tenant, "env_not-a-real-id", &org, &role),
            "k-malformed",
            &attach_body(&permission),
        )
        .await;
    assert_eq!(malformed_status, StatusCode::NOT_FOUND);

    // A well-formed environment id that was never created.
    let absent = ironauth_store::EnvironmentId::generate(&ironauth_env::Env::system()).to_string();
    let (status, _, body) = h
        .post(
            &mapping_base(&tenant, &absent, &org, &role),
            "k-absent",
            &attach_body(&permission),
        )
        .await;
    assert_eq!(
        status, malformed_status,
        "an absent environment must not be a 500: {body}"
    );
    assert_eq!(body, malformed_body, "and it must be the SAME answer");

    // --- The soft-deleted environment, side by side with the shipped role create. ---
    let doomed = h.create_environment(&tenant, "doomed", "k-env-2").await;
    let doomed_org = create_org(&h, &tenant, &doomed, "k-org-2").await;
    let doomed_roles = roles_base(&tenant, &doomed, &doomed_org);
    let doomed_role = create_role(&h, &doomed_roles, "billing.admin", "k-r2").await;
    let doomed_permission = create_permission(
        &h,
        &permissions_base(&tenant, &doomed),
        "billing.invoice.read",
        "k-p2",
    )
    .await;
    let (status, _, _) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{doomed}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (role_status, _, role_body) = h
        .post(
            &doomed_roles,
            "k-role-after-delete",
            &serde_json::json!({ "slug": "after.delete", "display_name": "Label" }).to_string(),
        )
        .await;
    let (status, _, body) = h
        .post(
            &mapping_base(&tenant, &doomed, &doomed_org, &doomed_role),
            "k-deleted",
            &attach_body(&doomed_permission),
        )
        .await;
    assert_eq!(
        status, role_status,
        "the attach and the shipped role create agree about a soft-deleted \
         environment: {body} vs {role_body}"
    );
    assert_eq!(
        status,
        StatusCode::CREATED,
        "and what they agree on today is that the write LANDS, because deleting an \
         environment does not cascade to its organizations: {body}"
    );

    // The positive control: the live environment still accepts an attach, so the two
    // refusals above are attributable to the addressing and not to an attach that
    // stopped working.
    attach(
        &h,
        &mapping_base(&tenant, &environment, &org, &role),
        &permission,
        "k-live",
    )
    .await;
}

#[tokio::test]
async fn a_mapping_list_pages_across_a_cursor() {
    // The cursor key must be the SORT key, which is `(created_at, id)`. The mutant
    // that matters elsewhere, a cursor built from `updated_at`, is NOT observable on
    // this table and that is a property of the table rather than a gap in the test:
    // migration 0092 grants the control role UPDATE on exactly `updated_at` and
    // `deleted_at`, and the only write that touches either is the DETACH, which
    // removes the row from every live read in the same statement. So `updated_at`
    // equals `created_at` on every row this list can return, which the assertion
    // below pins directly rather than leaving implied. The walk still kills the
    // mutants that ARE reachable: a cursor that does not advance, or one that drops
    // the id tiebreaker, both make a row appear on two pages.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let role = create_role(
        &h,
        &roles_base(&tenant, &environment, &org),
        "billing.admin",
        "k-r",
    )
    .await;
    let base = mapping_base(&tenant, &environment, &org, &role);
    let perms = permissions_base(&tenant, &environment);

    let mut created = HashSet::new();
    for index in 0..5 {
        let permission = create_permission(
            &h,
            &perms,
            &format!("scope{index}.read"),
            &format!("k-p{index}"),
        )
        .await;
        let mapping = attach(&h, &base, &permission, &format!("k-a{index}")).await;
        assert!(created.insert(mapping), "each mapping id is unique");
    }

    let (status, _, response) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    for item in serde_json::from_str::<Value>(&response).expect("json")["items"]
        .as_array()
        .expect("items")
    {
        assert_eq!(
            item["created_at_unix_ms"], item["updated_at_unix_ms"],
            "a live mapping is never updated in place, which is WHY an updated_at \
             cursor cannot be told apart here: {item}"
        );
    }

    let (seen, pages) = walk_pages(&h, &base, 2).await;
    assert_eq!(
        seen, created,
        "every mapping is returned exactly once across the walk"
    );
    assert_eq!(pages, 3, "5 rows at 2 per page is exactly three pages");
}

// The parallel `*_one` / `*_two` names track the two environments; the test is one
// indivisible proof over five endpoints, so it is not split.
#[allow(clippy::similar_names, clippy::too_many_lines)]
#[tokio::test]
async fn an_environment_scoped_key_reaches_only_its_own_environments_mappings() {
    // Every other test in this file drives the OPERATOR, which passes every scope
    // check by design, so those prove containment of IDS and nothing about the
    // CREDENTIAL. This one drives a real `mak_` management key, the credential class
    // whose confinement rests entirely on `Principal::require_environment` inside
    // `crate::org_context::resolve_scope`, the ONE copy of that call. Deleting it is
    // one edit, and without this test the whole admin suite stays green while a key
    // minted for environment one administers environment two.
    //
    // Each endpoint is driven TWICE with the SAME key: once inside the environment the
    // key was minted for, which must succeed, and once against a sibling environment,
    // which must be the LOUD 403. The positive half is what makes the negative half
    // attributable to the scope check alone rather than to a broken credential. The
    // two environments share a tenant, so the environment half of the fence is the
    // only thing that can be doing the work.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let key = h.create_key(&tenant, &env_one, "ci", "k-key").await;

    let org_one = create_org(&h, &tenant, &env_one, "k-org-1").await;
    let role_one = create_role(
        &h,
        &roles_base(&tenant, &env_one, &org_one),
        "billing.admin",
        "k-r1",
    )
    .await;
    let permission_one = create_permission(
        &h,
        &permissions_base(&tenant, &env_one),
        "billing.invoice.read",
        "k-p1",
    )
    .await;
    let base_one = mapping_base(&tenant, &env_one, &org_one, &role_one);

    // Environment two is seeded BY THE OPERATOR, so every probe below names rows that
    // genuinely exist there: with the scope check gone the reads answer 200 and the
    // mutations execute, rather than collapsing to a 404 that could be mistaken for
    // containment.
    let org_two = create_org(&h, &tenant, &env_two, "k-org-2").await;
    let roles_two = roles_base(&tenant, &env_two, &org_two);
    let role_two = create_role(&h, &roles_two, "billing.admin", "k-r2").await;
    let permission_two = create_permission(
        &h,
        &permissions_base(&tenant, &env_two),
        "billing.invoice.read",
        "k-p2",
    )
    .await;
    let base_two = mapping_base(&tenant, &env_two, &org_two, &role_two);
    attach(&h, &base_two, &permission_two, "k-seed").await;
    let default_two = default_role_path(&tenant, &env_two, &org_two);
    let (status, _, body) = h.put(&default_two, &designate_body(&role_two)).await;
    assert_eq!(status, StatusCode::OK, "seed the default role: {body}");

    // --- The key is authorized on all five endpoints INSIDE environment one. ---
    let (status, _, body) = h
        .post_as(&base_one, &key, "mk-1", &attach_body(&permission_one))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "own-environment attach: {body}"
    );
    let (status, _, body) = h.get_as(&base_one, &key).await;
    assert_eq!(status, StatusCode::OK, "own-environment list: {body}");
    let (status, _, body) = h
        .delete_as(&format!("{base_one}/{permission_one}"), &key)
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "own-environment detach: {body}"
    );
    let default_one = default_role_path(&tenant, &env_one, &org_one);
    let (status, _, body) = h
        .put_as(&default_one, &key, &designate_body(&role_one))
        .await;
    assert_eq!(status, StatusCode::OK, "own-environment designate: {body}");
    let (status, _, body) = h.delete_as(&default_one, &key).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "own-environment clear: {body}"
    );

    // --- The SAME key against environment two: the LOUD 403 on every one. ---
    let (status, _, body) = h
        .post_as(&base_two, &key, "mk-x1", &attach_body(&permission_two))
        .await;
    assert_wrong_scope("cross-environment attach", status, &body);
    let (status, _, body) = h.get_as(&base_two, &key).await;
    assert_wrong_scope("cross-environment list", status, &body);
    let (status, _, body) = h
        .delete_as(&format!("{base_two}/{permission_two}"), &key)
        .await;
    assert_wrong_scope("cross-environment detach", status, &body);
    let (status, _, body) = h
        .put_as(&default_two, &key, &designate_body(&role_two))
        .await;
    assert_wrong_scope("cross-environment designate", status, &body);
    let (status, _, body) = h.delete_as(&default_two, &key).await;
    assert_wrong_scope("cross-environment clear", status, &body);

    // Environment two is exactly as the operator left it: the refused attach added no
    // row, the refused detach removed none, and the refused designate and clear left
    // the designation standing.
    assert_eq!(
        granted_permissions(&h, &base_two).await,
        vec![permission_two],
        "no refused request touched environment two's mappings"
    );
    assert_eq!(
        default_roles(&h, &roles_two).await,
        vec![role_two],
        "and none touched its default role"
    );
    assert_eq!(
        mapping_audit(&h, &tenant, &env_two).await,
        vec!["organization.role.permission.assign"],
        "the only audited mapping write in environment two is the operator's seed"
    );
    assert_eq!(
        default_role_audit(&h, &tenant, &env_two).await,
        vec!["organization.default_role.set"],
        "and the only audited designation is the operator's seed"
    );
}

// One test rather than four: the audit MULTISET is checked at every step, and a
// multiset assertion only means anything if every step before it ran against the same
// scope in the same order.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn the_default_role_designation_moves_atomically_and_clears() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let path = default_role_path(&tenant, &environment, &org);
    let first = create_role(&h, &roles, "member", "k-r1").await;
    let second = create_role(&h, &roles, "guest", "k-r2").await;

    assert!(
        default_role_audit(&h, &tenant, &environment)
            .await
            .is_empty(),
        "the designation audit trail starts empty"
    );
    assert!(
        default_roles(&h, &roles).await.is_empty(),
        "an organization has no default role until an operator designates one"
    );
    // A clear with nothing designated matches no live row and is the uniform 404.
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "clearing nothing is a 404");
    assert!(
        default_role_audit(&h, &tenant, &environment)
            .await
            .is_empty()
    );

    let (status, _, response) = h.put(&path, &designate_body(&first)).await;
    assert_eq!(status, StatusCode::OK, "designate: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["id"], first.as_str(), "the response names the role");
    assert_eq!(value["is_default"], true);
    assert_eq!(
        field(&h, &format!("{roles}/{first}"), "is_default").await,
        true,
        "and the stored row agrees with the response"
    );
    assert_eq!(default_roles(&h, &roles).await, vec![first.clone()]);
    assert_eq!(
        default_role_audit(&h, &tenant, &environment).await,
        vec!["organization.default_role.set"],
    );

    // Designating the SAME role again is idempotent in effect, not a conflict.
    let (status, _, response) = h.put(&path, &designate_body(&first)).await;
    assert_eq!(status, StatusCode::OK, "re-designate: {response}");
    assert_eq!(default_roles(&h, &roles).await, vec![first.clone()]);

    // The SECOND designation MOVES the designation rather than being refused by the
    // partial unique index. This is the semantic choice, and it is what makes `PUT`
    // on a singleton mean idempotent replacement: exactly one role is the default
    // afterwards, and it is the new one.
    let (status, _, response) = h.put(&path, &designate_body(&second)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a second designation MOVES it rather than colliding: {response}"
    );
    assert_eq!(
        default_roles(&h, &roles).await,
        vec![second.clone()],
        "exactly one role is the default, and it is the new one"
    );
    assert_eq!(
        field(&h, &format!("{roles}/{first}"), "is_default").await,
        false,
        "the outgoing role is no longer the default"
    );
    assert_eq!(
        default_role_audit(&h, &tenant, &environment).await,
        vec![
            "organization.default_role.set",
            "organization.default_role.set",
            "organization.default_role.set",
        ],
        "one set per request; the move is ONE transaction and ONE audit row"
    );

    // Clearing: 204, no role is the default, and the role itself is untouched.
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(default_roles(&h, &roles).await.is_empty());
    assert_eq!(
        field(&h, &format!("{roles}/{second}"), "slug").await,
        "guest",
        "clearing the designation does not delete the role"
    );
    let after = default_role_audit(&h, &tenant, &environment).await;
    assert_eq!(
        after,
        vec![
            "organization.default_role.clear",
            "organization.default_role.set",
            "organization.default_role.set",
            "organization.default_role.set",
        ],
    );
    // WHICH role each row names, which the action alone cannot say. The three sets
    // name the role that BECAME the default, in order, so the move from the first to
    // the second is legible from the trail; the clear names the role that WAS the
    // default, which is the only place the outgoing role appears at all. A clear that
    // targeted the organization, or targeted whatever role it happened to scan first,
    // would leave the multiset above completely unchanged.
    assert_eq!(
        audit_targets(&h, &tenant, &environment, "organization.default_role.set").await,
        vec![first.clone(), first.clone(), second.clone()],
    );
    assert_eq!(
        audit_targets(&h, &tenant, &environment, "organization.default_role.clear").await,
        vec![second.clone()],
        "the clear names the role that WAS the default"
    );
    // A repeat clear matches no live row and audits nothing.
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat clear is 404");
    assert_eq!(
        default_role_audit(&h, &tenant, &environment).await,
        after,
        "the refused repeat clear audits nothing"
    );
}

#[tokio::test]
async fn a_soft_deleted_default_role_frees_the_designation_slot() {
    // Migration 0093's claim, checked rather than quoted: a deleted role KEEPS its
    // `is_default` value, and that value is inert in both directions because every
    // read filters `deleted_at IS NULL` and the unique index is partial over the same
    // live set. Two observable consequences, and the second is the one that would
    // break loudly if the index predicate lost its `deleted_at` conjunct: a fresh role
    // can be designated the moment the old one is deleted, with no clearing pass.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let path = default_role_path(&tenant, &environment, &org);
    let first = create_role(&h, &roles, "member", "k-r1").await;
    let second = create_role(&h, &roles, "guest", "k-r2").await;

    let (status, _, body) = h.put(&path, &designate_body(&first)).await;
    assert_eq!(status, StatusCode::OK, "designate: {body}");
    let (status, _, _) = h.delete(&format!("{roles}/{first}")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the default role is deleted"
    );

    // The dead row keeps the flag. Nothing in the API can show this, because every
    // read filters deleted rows out, so it is read directly: the point of the
    // assertion is that no clearing pass exists and none is needed.
    let stored: bool = sqlx::query_scalar("SELECT is_default FROM org_roles WHERE id = $1")
        .bind(&first)
        .fetch_one(h.db().owner_pool())
        .await
        .expect("read the deleted role");
    assert!(
        stored,
        "a soft-deleted role keeps its is_default value; nothing clears it"
    );

    assert!(
        default_roles(&h, &roles).await.is_empty(),
        "and it does not resolve: the organization has no live default role"
    );
    // Clearing has nothing to clear, for the same reason: the dead role does not hold
    // the designation, so this is the uniform not-found and not a 204 that would claim
    // a removal it did not perform. Without the clear statement's own liveness filter
    // it would answer 204 and write a clear row naming a role that was already gone.
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deleted default role leaves nothing to clear"
    );

    // The slot is free. Without the index's `deleted_at IS NULL` conjunct this would
    // be a 23505 reaching the caller.
    let (status, _, body) = h.put(&path, &designate_body(&second)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a deleted default frees the slot immediately: {body}"
    );
    assert_eq!(default_roles(&h, &roles).await, vec![second]);
    assert_eq!(
        default_role_audit(&h, &tenant, &environment).await,
        vec![
            "organization.default_role.set",
            "organization.default_role.set",
        ],
        "deleting the default role writes no clear action, so the absence of one \
         never means an organization still has a default"
    );
}

#[allow(clippy::similar_names)]
#[tokio::test]
async fn clearing_one_organizations_designation_leaves_a_siblings_standing() {
    // The clear takes NO role: it resolves the outgoing one from the statement that
    // clears it. So the ONLY thing keeping it inside the organization the path names is
    // that statement's `organization_id` predicate, and row-level security cannot help,
    // because it fences `(tenant, environment)` and cannot see that column. Two
    // organizations of ONE environment each hold a designation, and clearing one must
    // leave the other exactly as it was, including its audit trail.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org_one = create_org(&h, &tenant, &environment, "k-org-1").await;
    let org_two = create_org(&h, &tenant, &environment, "k-org-2").await;
    let roles_one = roles_base(&tenant, &environment, &org_one);
    let roles_two = roles_base(&tenant, &environment, &org_two);
    let role_one = create_role(&h, &roles_one, "member", "k-r1").await;
    let role_two = create_role(&h, &roles_two, "member", "k-r2").await;

    for (path, role) in [
        (
            default_role_path(&tenant, &environment, &org_one),
            &role_one,
        ),
        (
            default_role_path(&tenant, &environment, &org_two),
            &role_two,
        ),
    ] {
        let (status, _, body) = h.put(&path, &designate_body(role)).await;
        assert_eq!(status, StatusCode::OK, "designate: {body}");
    }
    assert_eq!(default_roles(&h, &roles_one).await, vec![role_one.clone()]);
    assert_eq!(default_roles(&h, &roles_two).await, vec![role_two.clone()]);

    let (status, _, _) = h
        .delete(&default_role_path(&tenant, &environment, &org_one))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        default_roles(&h, &roles_one).await.is_empty(),
        "the addressed organization lost its designation"
    );
    assert_eq!(
        default_roles(&h, &roles_two).await,
        vec![role_two],
        "and the SIBLING organization kept its own"
    );
    assert_eq!(
        default_role_audit(&h, &tenant, &environment).await,
        vec![
            "organization.default_role.clear",
            "organization.default_role.set",
            "organization.default_role.set",
        ],
        "exactly ONE clear was written"
    );
}

#[allow(clippy::similar_names)]
#[tokio::test]
async fn every_default_role_addressing_failure_is_the_uniform_not_found_byte_for_byte() {
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let org_one = create_org(&h, &tenant, &env_one, "k-org-1").await;
    let org_two = create_org(&h, &tenant, &env_one, "k-org-2").await;
    let roles_one = roles_base(&tenant, &env_one, &org_one);
    let role_one = create_role(&h, &roles_one, "member", "k-r1").await;
    let role_two = create_role(
        &h,
        &roles_base(&tenant, &env_one, &org_two),
        "member",
        "k-r2",
    )
    .await;
    let foreign_role = create_role(
        &h,
        &roles_base(
            &tenant,
            &env_two,
            &create_org(&h, &tenant, &env_two, "k-org-3").await,
        ),
        "member",
        "k-r3",
    )
    .await;
    let path = default_role_path(&tenant, &env_one, &org_one);

    // A role of this organization that has been soft-deleted.
    let deleted = create_role(&h, &roles_one, "gone", "k-gone").await;
    let (status, _, _) = h.delete(&format!("{roles_one}/{deleted}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The reference: a well-formed, in-scope role id that was never created.
    let absent = fresh_in_scope_role(&tenant, &env_one);
    let (absent_status, _, absent_body) = h.put(&path, &designate_body(&absent)).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_str::<Value>(&absent_body).expect("json")["error"],
        "not_found"
    );

    for (label, probe) in [
        ("soft-deleted", deleted.clone()),
        ("sibling organization", role_two.clone()),
        ("sibling environment", foreign_role.clone()),
        ("malformed", "rol_not-a-real-id".to_owned()),
        ("wrong prefix", fresh_in_scope_org(&tenant, &env_one)),
        ("blank", " ".to_owned()),
    ] {
        let (status, _, body) = h.put(&path, &designate_body(&probe)).await;
        assert_eq!(status, absent_status, "designate probe {label}: {body}");
        assert_eq!(body, absent_body, "designate probe {label} body");
    }

    // The ORGANIZATION segment, on both methods. The address resolves BEFORE the body
    // is parsed, so a body the edge alone would refuse still answers on the address:
    // otherwise a caller could separate "that organization is not yours" from "that
    // organization does not exist" by the status alone.
    let unreachable = default_role_path(&tenant, &env_one, &fresh_in_scope_org(&tenant, &env_one));
    for (shape, request) in [
        ("valid", designate_body(&role_one)),
        ("unparseable", "not json at all".to_owned()),
        ("no role_id", "{}".to_owned()),
    ] {
        let (status, _, body) = h.put(&unreachable, &request).await;
        assert_eq!(
            status, absent_status,
            "an unreachable organization with a {shape} body must answer on the \
             address: {body}"
        );
        assert_eq!(body, absent_body, "unreachable organization, {shape} body");
    }
    let (status, _, body) = h.delete(&unreachable).await;
    assert_eq!(status, absent_status, "clear on an unreachable org: {body}");
    assert_eq!(body, absent_body, "clear on an unreachable org body");

    // Nothing anywhere was designated.
    assert!(default_roles(&h, &roles_one).await.is_empty());
    assert!(
        default_roles(&h, &roles_base(&tenant, &env_one, &org_two))
            .await
            .is_empty()
    );
    assert!(
        default_role_audit(&h, &tenant, &env_one).await.is_empty(),
        "no probe wrote a designation audit row"
    );

    // The positive control: a live role of THIS organization is designated, so every
    // refusal above is attributable to the addressing rather than to a designate that
    // never works.
    let (status, _, body) = h.put(&path, &designate_body(&role_one)).await;
    assert_eq!(status, StatusCode::OK, "the control designate: {body}");
}

#[tokio::test]
async fn a_disabled_organization_still_accepts_a_default_role_designation() {
    // A DISABLED (not deleted) organization is LIVE for management writes, because
    // `OrganizationRepo::get` filters `deleted_at` and does NOT filter `state`. That
    // is deliberate and it is asserted here so it reads as a decision rather than as
    // an accident nobody noticed: an operator winding an organization back up must not
    // have to remember to re-do the configuration they set while it was down, and
    // every other management write under a disabled organization already behaves this
    // way.
    //
    // What this does NOT mean, and the reason the assertion stops where it does:
    // nothing on the token-issuance path relies on this endpoint refusing. The closure
    // seed is the only organization-liveness fence there.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let role = create_role(&h, &roles, "member", "k-r").await;
    let permission = create_permission(
        &h,
        &permissions_base(&tenant, &environment),
        "billing.invoice.read",
        "k-p",
    )
    .await;

    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/disable"),
            "k-disable",
            "{}",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "disable the organization: {body}");

    let path = default_role_path(&tenant, &environment, &org);
    let (status, _, body) = h.put(&path, &designate_body(&role)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a disabled organization is live for management writes: {body}"
    );
    assert_eq!(default_roles(&h, &roles).await, vec![role.clone()]);

    // The mapping surface behaves the same way, for the same reason.
    let base = mapping_base(&tenant, &environment, &org, &role);
    attach(&h, &base, &permission, "k-a").await;

    let (status, _, _) = h.delete(&path).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "and it can be cleared again"
    );
}
