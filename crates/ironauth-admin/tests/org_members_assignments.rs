// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization group members, role assignments, and the effective-role view over
//! HTTP (issue #97, PR 5), driven through the management router against a real
//! database.
//!
//! This surface is where the containment problem gets HARDER than it was for roles
//! and groups, and every test here is shaped by that. A role or a group is ONE
//! resource under ONE organization. A binding or an assignment is a RELATIONSHIP
//! between THREE ids (organization, group or membership, role or membership), and
//! each of the three can independently be a row the caller can legitimately see.
//! So the property to prove is not only "a foreign id is refused" but the sharper
//! one: a PAIRING of two ids that are each individually visible, but that belong to
//! DIFFERENT organizations, must be refused too. Row-level security fences
//! `(tenant, environment)` and nothing finer, so nothing but the explicit
//! `organization_id` predicate refuses it, and a test that only probed absent ids
//! would pass with that predicate deleted.
//!
//! Every containment test therefore stands up a SECOND organization in the SAME
//! environment holding its own group, membership, and role, and asserts each
//! request reaches (and mutates) exactly its own rows.
//!
//! One consequence of that shape is worth stating so nobody weakens a test on the
//! strength of a surviving mutant. On the three removal paths the organization is
//! carried TWICE, once by the pair lookup and once by the soft-delete statement, and
//! the two are NOT interchangeable. Deleting the PAIR LOOKUP's copy alone is
//! invisible everywhere, because the soft delete still refuses the request. Deleting
//! the SOFT DELETE's copy alone is invisible only HERE: it reds two tests in
//! `crates/ironauth-store/tests/org_assignments.rs`, which remove by an assignment id
//! with no pair lookup in front of them. Deleting BOTH lets a nested route remove a
//! sibling organization's row, and
//! `every_cross_organization_pairing_is_refused_and_mutates_nothing` below is what
//! turns red when it happens. The census, with the full mutation table, lives on
//! `ironauth_store::OrgGroupMemberRepo::get_binding`.
//!
//! The second load-bearing property is ANTI-ORACLE UNIFORMITY: the refusal for a
//! cross-organization pairing must be byte-identical to the refusal for an id that
//! never existed, one from another environment, a malformed one, and one carrying
//! another resource's prefix. Those are asserted on the body, not only the status.

mod common;

use std::collections::HashSet;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

// ------------------------------------------------------------- fixtures ------

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

/// The `.../organizations/{org}` base path.
fn org_base(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}")
}

/// Create an organization and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    id_of(&response)
}

/// Create an active user and return its id.
async fn create_user(
    h: &Harness,
    tenant: &str,
    environment: &str,
    ident: &str,
    key: &str,
) -> String {
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": ident }).to_string();
    let (status, _, response) = h.post(&users, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create user: {response}");
    id_of(&response)
}

/// Create a user and add them to `org`, returning the MEMBERSHIP id.
async fn create_membership(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    ident: &str,
    key: &str,
) -> String {
    let user = create_user(h, tenant, environment, ident, &format!("{key}-u")).await;
    let base = format!("{}/memberships", org_base(tenant, environment, org));
    let body = serde_json::json!({ "user_id": user }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "add membership: {response}");
    id_of(&response)
}

/// Define a role in `org` and return its id.
async fn create_role(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    slug: &str,
    key: &str,
) -> String {
    let base = format!("{}/roles", org_base(tenant, environment, org));
    let body = serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create role: {response}");
    id_of(&response)
}

/// Define a group in `org` (optionally under a parent) and return its id.
async fn create_group(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    slug: &str,
    parent: Option<&str>,
    key: &str,
) -> String {
    let base = format!("{}/groups", org_base(tenant, environment, org));
    let mut body = serde_json::json!({ "slug": slug, "display_name": "Label" });
    if let Some(parent) = parent {
        body["parent_id"] = Value::String(parent.to_owned());
    }
    let (status, _, response) = h.post(&base, key, &body.to_string()).await;
    assert_eq!(status, StatusCode::CREATED, "create group: {response}");
    id_of(&response)
}

/// A whole organization worth of fixtures, so a containment test can stand up TWO
/// of them in one environment without eight lines of setup each.
struct Fixture {
    org: String,
    group: String,
    membership: String,
    role: String,
}

impl Fixture {
    /// Seed one organization with one group, one membership, and one role.
    async fn seed(h: &Harness, tenant: &str, environment: &str, tag: &str) -> Self {
        let org = create_org(h, tenant, environment, &format!("k-{tag}-org")).await;
        // The SAME slugs in both organizations deliberately: a leak that was
        // detected only by comparing names would be invisible.
        let group = create_group(
            h,
            tenant,
            environment,
            &org,
            "team",
            None,
            &format!("k-{tag}-g"),
        )
        .await;
        let membership = create_membership(
            h,
            tenant,
            environment,
            &org,
            &format!("{tag}@x.test"),
            &format!("k-{tag}-m"),
        )
        .await;
        let role = create_role(h, tenant, environment, &org, "admin", &format!("k-{tag}-r")).await;
        Self {
            org,
            group,
            membership,
            role,
        }
    }

    /// `.../groups/{group}/members`.
    fn members(&self, tenant: &str, environment: &str) -> String {
        format!(
            "{}/groups/{}/members",
            org_base(tenant, environment, &self.org),
            self.group
        )
    }

    /// `.../groups/{group}/roles`.
    fn group_roles(&self, tenant: &str, environment: &str) -> String {
        format!(
            "{}/groups/{}/roles",
            org_base(tenant, environment, &self.org),
            self.group
        )
    }

    /// `.../memberships/{membership}/roles`.
    fn membership_roles(&self, tenant: &str, environment: &str) -> String {
        format!(
            "{}/memberships/{}/roles",
            org_base(tenant, environment, &self.org),
            self.membership
        )
    }

    /// `.../memberships/{membership}/effective-roles`.
    fn effective(&self, tenant: &str, environment: &str) -> String {
        format!(
            "{}/memberships/{}/effective-roles",
            org_base(tenant, environment, &self.org),
            self.membership
        )
    }
}

/// The `id` values on a list page, sorted, so an assertion pins the WHOLE set.
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

/// The values of `field` on a list page, in RETURNED order (not sorted), so an
/// assertion can pin the ordering the cursor key implies.
async fn list_field_in_order(h: &Harness, base: &str, field: &str) -> Vec<String> {
    let (status, _, response) = h.get(base).await;
    assert_eq!(status, StatusCode::OK, "list {base}: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item[field].as_str().expect("field").to_owned())
        .collect()
}

/// The effective-role entries as `(slug, source, via_group_id)` triples, in the
/// order the endpoint returned them.
async fn effective_roles(h: &Harness, path: &str) -> Vec<(String, String, Option<String>)> {
    let (status, _, response) = h.get(path).await;
    assert_eq!(status, StatusCode::OK, "effective roles: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    value["roles"]
        .as_array()
        .expect("roles is an array under a named field, never a bare array body")
        .iter()
        .map(|entry| {
            (
                entry["slug"].as_str().expect("slug").to_owned(),
                entry["source"].as_str().expect("source").to_owned(),
                entry["via_group_id"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

/// Assert a response is the LOUD wrong-scope refusal: a 403 naming the error. A
/// credential presented against an environment it is not authorized for is the LOUD
/// case, never the uniform not-found.
fn assert_wrong_scope(label: &str, status: StatusCode, body: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{label}: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(body).expect("json")["error"],
        "wrong_scope",
        "{label} must be the LOUD wrong-scope refusal: {body}"
    );
}

/// Walk a list endpoint at `limit` rows per page, returning every id seen and the
/// number of pages. Asserts on the way that no page exceeds the limit, that no row
/// is returned twice, and that the walk terminates.
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

/// The `(tenant, environment)` scope parsed from two id path segments.
fn scope_of(tenant: &str, environment: &str) -> ironauth_store::Scope {
    use ironauth_store::{EnvironmentId, Scope, TenantId};
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// A well-formed group id in the given scope that was never created.
fn fresh_group(tenant: &str, environment: &str) -> String {
    ironauth_store::OrgGroupId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// A well-formed membership id in the given scope that was never created.
fn fresh_membership(tenant: &str, environment: &str) -> String {
    ironauth_store::OrgMembershipId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// A well-formed role id in the given scope that was never created.
fn fresh_role(tenant: &str, environment: &str) -> String {
    ironauth_store::OrgRoleId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// Every audit action recorded in one scope, read through the control store.
async fn audit_actions(h: &Harness, tenant: &str, environment: &str) -> Vec<String> {
    h.control_store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .collect()
}

// -------------------------------------------------------- round trips --------

#[tokio::test]
async fn group_member_add_list_and_remove_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let f = Fixture::seed(&h, &tenant, &environment, "a").await;
    let members = f.members(&tenant, &environment);

    let body = serde_json::json!({ "membership_id": f.membership }).to_string();
    let (status, _, response) = h.post(&members, "k-add", &body).await;
    assert_eq!(status, StatusCode::CREATED, "add member: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    let binding = view["id"].as_str().expect("id").to_owned();
    assert!(
        binding.starts_with("gmb_"),
        "binding id is typed: {binding}"
    );
    assert_eq!(view["organization_id"], f.org);
    assert_eq!(view["group_id"], f.group);
    assert_eq!(view["membership_id"], f.membership);

    // The create response describes the row the LIST returns. The response body is
    // composed before the write, so a divergence would otherwise be invisible.
    let (status, _, listed) = h.get(&members).await;
    assert_eq!(status, StatusCode::OK, "list members: {listed}");
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"].clone();
    assert_eq!(items.as_array().expect("items").len(), 1);
    assert_eq!(
        items[0], view,
        "the list row must equal the create response"
    );

    // Remove by the PAIR address: 204, then gone, then a repeat remove is the
    // uniform 404 rather than a second 204.
    let pair = format!("{members}/{}", f.membership);
    let (status, _, _) = h.delete(&pair).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(list_ids(&h, &members).await.is_empty());
    let (status, _, _) = h.delete(&pair).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat remove is 404");

    // The pair is free again, and re-adding mints a FRESH binding id: a removed
    // binding is never revived, so the audit history of the removal stands.
    let (status, _, response) = h.post(&members, "k-readd", &body).await;
    assert_eq!(status, StatusCode::CREATED, "re-add: {response}");
    assert_ne!(id_of(&response), binding, "the re-add gets a fresh id");

    // The remove is addressed by the PAIR, so the GROUP half of that address has to
    // select the row as much as the membership half does. A SECOND group of the SAME
    // organization is what tells the two halves apart, and the sharp probe is the
    // membership that is bound into the OTHER one: it is individually visible, it has
    // a live binding, both ids are of this organization, and the group segment is the
    // only thing saying that binding is not the one this path names. Every other test
    // here keeps its membership in exactly ONE group, where a lookup that ignored the
    // group segment would still find that one binding and still remove the right row.
    let second = create_group(&h, &tenant, &environment, &f.org, "second", None, "k-g2").await;
    let second_members = format!(
        "{}/groups/{second}/members",
        org_base(&tenant, &environment, &f.org)
    );
    let (status, _, response) = h
        .delete(&format!("{second_members}/{}", f.membership))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a membership bound into ANOTHER group of this organization is not removable \
         through this group's path: {response}"
    );
    assert_eq!(
        list_ids(&h, &members).await.len(),
        1,
        "and that refusal removed nothing: the binding into the other group stands"
    );
}

#[tokio::test]
async fn group_role_assign_list_and_unassign_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let f = Fixture::seed(&h, &tenant, &environment, "a").await;
    let roles = f.group_roles(&tenant, &environment);

    let body = serde_json::json!({ "role_id": f.role }).to_string();
    let (status, _, response) = h.post(&roles, "k-assign", &body).await;
    assert_eq!(status, StatusCode::CREATED, "assign: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert!(
        view["id"].as_str().expect("id").starts_with("grl_"),
        "assignment id is typed: {response}"
    );
    assert_eq!(view["organization_id"], f.org);
    assert_eq!(view["group_id"], f.group);
    assert_eq!(view["role_id"], f.role);

    let (status, _, listed) = h.get(&roles).await;
    assert_eq!(status, StatusCode::OK, "list: {listed}");
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"].clone();
    assert_eq!(
        items[0], view,
        "the list row must equal the assign response"
    );

    let pair = format!("{roles}/{}", f.role);
    let (status, _, _) = h.delete(&pair).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(list_ids(&h, &roles).await.is_empty());
    let (status, _, _) = h.delete(&pair).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat unassign is 404");
}

#[tokio::test]
async fn membership_role_assign_list_and_unassign_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let f = Fixture::seed(&h, &tenant, &environment, "a").await;
    let roles = f.membership_roles(&tenant, &environment);

    let body = serde_json::json!({ "role_id": f.role }).to_string();
    let (status, _, response) = h.post(&roles, "k-assign", &body).await;
    assert_eq!(status, StatusCode::CREATED, "assign: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert!(
        view["id"].as_str().expect("id").starts_with("mrl_"),
        "assignment id is typed: {response}"
    );
    assert_eq!(view["organization_id"], f.org);
    assert_eq!(view["membership_id"], f.membership);
    assert_eq!(view["role_id"], f.role);

    let (status, _, listed) = h.get(&roles).await;
    assert_eq!(status, StatusCode::OK, "list: {listed}");
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"].clone();
    assert_eq!(
        items[0], view,
        "the list row must equal the assign response"
    );

    let pair = format!("{roles}/{}", f.role);
    let (status, _, _) = h.delete(&pair).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(list_ids(&h, &roles).await.is_empty());
    let (status, _, _) = h.delete(&pair).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat unassign is 404");
}

#[tokio::test]
async fn a_live_duplicate_is_a_conflict_on_all_three_surfaces() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let f = Fixture::seed(&h, &tenant, &environment, "a").await;

    for (label, base, body) in [
        (
            "group member",
            f.members(&tenant, &environment),
            serde_json::json!({ "membership_id": f.membership }).to_string(),
        ),
        (
            "group role",
            f.group_roles(&tenant, &environment),
            serde_json::json!({ "role_id": f.role }).to_string(),
        ),
        (
            "membership role",
            f.membership_roles(&tenant, &environment),
            serde_json::json!({ "role_id": f.role }).to_string(),
        ),
    ] {
        let (status, _, response) = h.post(&base, &format!("k-{label}-1"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "{label} first: {response}");
        // A DISTINCT second write (a different Idempotency-Key, so not a replay) of
        // the same pair is the documented 409. Without the handler's conflict arm
        // the partial unique index surfaces as an opaque 500.
        let (status, _, response) = h.post(&base, &format!("k-{label}-2"), &body).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{label} duplicate: {response}"
        );
        assert_eq!(
            list_ids(&h, &base).await.len(),
            1,
            "{label}: the refused write added no row"
        );
    }
}

// ----------------------------------------------------------- idempotency -----

#[tokio::test]
async fn a_replayed_write_returns_the_original_and_cannot_cross_a_path_or_a_credential() {
    // An idempotency key is namespaced by the ACTING CREDENTIAL alone: the stored
    // rows carry no scope column, and the OPERATOR is one credential across every
    // tenant and environment. The only thing keeping one credential's stored
    // response from being served for a DIFFERENT resource is that the fingerprint
    // covers the concrete request PATH. These cases pin that on the new surface.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let a = Fixture::seed(&h, &tenant, &env_one, "a").await;
    let b = Fixture::seed(&h, &tenant, &env_one, "b").await;
    let c = Fixture::seed(&h, &tenant, &env_two, "c").await;

    let members_a = a.members(&tenant, &env_one);
    let body_a = serde_json::json!({ "membership_id": a.membership }).to_string();

    // A genuine replay: byte-identical, and no second row.
    let (status, _, first) = h.post(&members_a, "shared-key", &body_a).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let binding_a = id_of(&first);
    let (status, _, replay) = h.post(&members_a, "shared-key", &body_a).await;
    assert_eq!(status, StatusCode::CREATED, "a replay repeats the original");
    assert_eq!(first, replay, "byte-identical replay");
    assert_eq!(
        list_ids(&h, &members_a).await,
        vec![binding_a.clone()],
        "the replay wrote no second binding"
    );

    // 1. The same key under a SIBLING ORGANIZATION's group. The path is part of the
    //    fingerprint, so this is the key-reuse 422, never a replay handing back
    //    organization A's binding as organization B's response.
    let members_b = b.members(&tenant, &env_one);
    let body_b = serde_json::json!({ "membership_id": b.membership }).to_string();
    let (status, _, response) = h.post(&members_b, "shared-key", &body_b).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "cross-organization replay: {response}"
    );
    assert!(
        !response.contains(&binding_a),
        "the refusal must not echo organization A's binding: {response}"
    );
    assert!(
        list_ids(&h, &members_b).await.is_empty(),
        "and it created nothing in organization B"
    );

    // 2. The same key in ANOTHER ENVIRONMENT under the same operator credential:
    //    the case the credential-only namespace makes possible, asserted directly.
    let members_c = c.members(&tenant, &env_two);
    let body_c = serde_json::json!({ "membership_id": c.membership }).to_string();
    let (status, _, response) = h.post(&members_c, "shared-key", &body_c).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "cross-environment replay: {response}"
    );
    assert!(
        !response.contains(&binding_a),
        "the refusal must not echo environment one's binding: {response}"
    );
    assert!(
        list_ids(&h, &members_c).await.is_empty(),
        "and it created nothing in environment two"
    );

    // 3. A DIFFERENT CREDENTIAL replaying the same key against the SAME path and
    //    body EXECUTES rather than reading the operator's stored response. It
    //    reaches the store and collides with the live pair, and a 409 is only
    //    reachable from the write, so it proves no replay happened.
    let key = h.create_key(&tenant, &env_one, "ci", "k-key").await;
    let (status, _, response) = h.post_as(&members_a, &key, "shared-key", &body_a).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "another credential executes rather than replaying: {response}"
    );
    assert_eq!(
        list_ids(&h, &members_a).await,
        vec![binding_a],
        "and it created no second binding"
    );

    // 4. The same key on a DIFFERENT SURFACE under the same organization: the two
    //    assignment POSTs share everything but their path, so this is the case a
    //    fingerprint over the body alone would get wrong.
    let group_roles_a = a.group_roles(&tenant, &env_one);
    let role_body = serde_json::json!({ "role_id": a.role }).to_string();
    let (status, _, response) = h.post(&group_roles_a, "shared-key", &role_body).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "cross-surface replay: {response}"
    );
    assert!(
        list_ids(&h, &group_roles_a).await.is_empty(),
        "and it granted nothing"
    );
}

// ------------------------------------------------------------ pagination -----

// Three list surfaces, three properties, and the ordering proof all run against
// ONE seeded organization; splitting them would re-seed it three times and lose
// the cross-list cursor check at the end.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn each_list_pages_across_a_cursor_with_no_loss_duplication_or_reordering() {
    // Three properties, on all three lists.
    //
    // 1. The multi-page walk returns EVERY row EXACTLY once and terminates. That is
    //    what a dropped `after` predicate (an infinite loop), a `>=` instead of `>`
    //    (a duplicate), or an off-by-one between the fetch limit and the page slice
    //    (a lost row) each break.
    // 2. The page count is exact, so a silently truncated list is not mistaken for
    //    a short one.
    // 3. The order is CREATION order, pinned by removing a middle row and re-adding
    //    the same pair: the re-add is a FRESH row with a fresh `created_at`, so it
    //    must come LAST rather than reappearing in its old position. A cursor keyed
    //    on the row id rather than on `(created_at, id)` reorders that.
    //
    // Honest limitation, stated so nobody reads more into this than it proves: the
    // sibling role and group lists pin their cursor key by PATCHING the row that
    // ends page one, which moves `updated_at` past every remaining `created_at` and
    // truncates the walk if the cursor is keyed on the wrong column. These three
    // join tables have NO update surface at all (the only mutable columns are the
    // soft-delete pair), so a LIVE row here always has `updated_at == created_at`
    // and the created/updated mutant is not observable through this API. It is
    // covered where it is observable, in the store's own list tests.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let group = create_group(&h, &tenant, &environment, &org, "team", None, "k-g").await;
    let base = org_base(&tenant, &environment, &org);
    let members = format!("{base}/groups/{group}/members");
    let group_roles = format!("{base}/groups/{group}/roles");

    // Five members and five roles, so both group-scoped lists page.
    let mut memberships = Vec::new();
    let mut member_bindings = Vec::new();
    for index in 0..5 {
        let membership = create_membership(
            &h,
            &tenant,
            &environment,
            &org,
            &format!("m{index}@x.test"),
            &format!("k-m{index}"),
        )
        .await;
        let body = serde_json::json!({ "membership_id": membership }).to_string();
        let (status, _, response) = h.post(&members, &format!("k-b{index}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "bind {index}: {response}");
        member_bindings.push(id_of(&response));
        memberships.push(membership);
    }
    let mut roles = Vec::new();
    for index in 0..5 {
        let role = create_role(
            &h,
            &tenant,
            &environment,
            &org,
            &format!("role{index}"),
            &format!("k-r{index}"),
        )
        .await;
        let body = serde_json::json!({ "role_id": role }).to_string();
        let (status, _, response) = h.post(&group_roles, &format!("k-gr{index}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "grant {index}: {response}");
        roles.push(role);
    }
    // And five DIRECT grants on one membership.
    let membership_roles = format!("{base}/memberships/{}/roles", memberships[0]);
    for (index, role) in roles.iter().enumerate() {
        let body = serde_json::json!({ "role_id": role }).to_string();
        let (status, _, response) = h
            .post(&membership_roles, &format!("k-mr{index}"), &body)
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "direct grant {index}: {response}"
        );
    }

    for (label, path) in [
        ("group members", members.clone()),
        ("group roles", group_roles),
        ("membership roles", membership_roles),
    ] {
        let expected: HashSet<String> = list_ids(&h, &path).await.into_iter().collect();
        assert_eq!(expected.len(), 5, "{label}: five rows before the walk");
        let (seen, pages) = walk_pages(&h, &path, 2).await;
        assert_eq!(
            seen, expected,
            "{label}: every row is returned exactly once across the walk"
        );
        assert_eq!(
            pages, 3,
            "{label}: 5 rows at 2 per page is exactly three pages"
        );
    }

    // Creation order, pinned. Remove the binding that ends page one at limit 2 and
    // re-add the same pair: the fresh row must come LAST.
    let before = list_field_in_order(&h, &members, "membership_id").await;
    assert_eq!(before, memberships, "the list is in creation order");
    let (status, _, _) = h.delete(&format!("{members}/{}", memberships[1])).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let body = serde_json::json!({ "membership_id": memberships[1] }).to_string();
    let (status, _, response) = h.post(&members, "k-reorder", &body).await;
    assert_eq!(status, StatusCode::CREATED, "re-add: {response}");
    let after = list_field_in_order(&h, &members, "membership_id").await;
    let mut expected_order = memberships.clone();
    let moved = expected_order.remove(1);
    expected_order.push(moved);
    assert_eq!(
        after, expected_order,
        "a re-added pair is a NEW row and sorts last, not back into its old slot"
    );

    // A cursor minted on THIS group's member list, replayed against a SECOND
    // group's, must not carry rows across: the cursor is a position in one filtered
    // sequence, never a global one.
    let other = create_group(&h, &tenant, &environment, &org, "other", None, "k-g2").await;
    let other_members = format!("{base}/groups/{other}/members");
    let (status, _, page_one) = h.get(&format!("{members}?limit=2")).await;
    assert_eq!(status, StatusCode::OK, "{page_one}");
    let cursor = serde_json::from_str::<Value>(&page_one).expect("json")["next_cursor"]
        .as_str()
        .expect("a next cursor")
        .to_owned();
    let (status, _, response) = h
        .get(&format!("{other_members}?limit=10&cursor={cursor}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        serde_json::from_str::<Value>(&response).expect("json")["items"]
            .as_array()
            .expect("items")
            .is_empty(),
        "a cursor from one group's list must never surface another group's rows: {response}"
    );
}

// ------------------------------------------------------------- containment ---

// The test is one indivisible proof over all ten endpoints and reads worse split.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn every_cross_organization_pairing_is_refused_and_mutates_nothing() {
    // TWO organizations in ONE environment, each holding its own group, membership,
    // and role, all under the SAME slugs. Row-level security fences the environment
    // and nothing finer, so `organization_id` is the only separator, and every
    // assertion below fails if it is dropped from any one of the three join
    // surfaces.
    //
    // The sharp case is the PAIRING: each id below is individually visible to the
    // caller (it lives in an organization the same credential administers), so a
    // check that only validated ids one at a time would pass every one of them.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let a = Fixture::seed(&h, &tenant, &environment, "a").await;
    let b = Fixture::seed(&h, &tenant, &environment, "b").await;
    let members_a = a.members(&tenant, &environment);
    let members_b = b.members(&tenant, &environment);
    let group_roles_a = a.group_roles(&tenant, &environment);
    let membership_roles_a = a.membership_roles(&tenant, &environment);
    let base_a = org_base(&tenant, &environment, &a.org);
    let base_b = org_base(&tenant, &environment, &b.org);

    // --- Adds and assigns that pair across organizations are all 404. ---
    for (label, path, body) in [
        // A's group, B's membership.
        (
            "A group + B membership",
            members_a.clone(),
            serde_json::json!({ "membership_id": b.membership }).to_string(),
        ),
        // B's group addressed under A's organization, A's membership.
        (
            "B group under A + A membership",
            format!("{base_a}/groups/{}/members", b.group),
            serde_json::json!({ "membership_id": a.membership }).to_string(),
        ),
        // A's group, B's role.
        (
            "A group + B role",
            group_roles_a.clone(),
            serde_json::json!({ "role_id": b.role }).to_string(),
        ),
        // A's membership, B's role.
        (
            "A membership + B role",
            membership_roles_a.clone(),
            serde_json::json!({ "role_id": b.role }).to_string(),
        ),
        // B's membership addressed under A's organization, A's role.
        (
            "B membership under A + A role",
            format!("{base_a}/memberships/{}/roles", b.membership),
            serde_json::json!({ "role_id": a.role }).to_string(),
        ),
    ] {
        let (status, _, response) = h.post(&path, &format!("k-{label}"), &body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label}: {response}");
    }

    // Nothing was written anywhere by any of those.
    for path in [
        members_a.clone(),
        members_b.clone(),
        group_roles_a.clone(),
        membership_roles_a.clone(),
        b.group_roles(&tenant, &environment),
        b.membership_roles(&tenant, &environment),
    ] {
        assert!(
            list_ids(&h, &path).await.is_empty(),
            "no refused pairing wrote a row: {path}"
        );
    }

    // --- Now seed REAL rows in both organizations and prove the reads, the
    //     removals, and the effective-role view stay on their own side. ---
    let (status, _, _) = h
        .post(
            &members_a,
            "k-bind-a",
            &serde_json::json!({ "membership_id": a.membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = h
        .post(
            &members_b,
            "k-bind-b",
            &serde_json::json!({ "membership_id": b.membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = h
        .post(
            &group_roles_a,
            "k-gr-a",
            &serde_json::json!({ "role_id": a.role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = h
        .post(
            &membership_roles_a,
            "k-mr-a",
            &serde_json::json!({ "role_id": a.role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Each list returns EXACTLY its own set.
    assert_eq!(list_ids(&h, &members_a).await.len(), 1);
    assert_eq!(list_ids(&h, &members_b).await.len(), 1);
    assert_ne!(
        list_ids(&h, &members_a).await,
        list_ids(&h, &members_b).await
    );

    // Reading a list through the WRONG organization's path is the uniform 404, not
    // an empty 200 that would assert the group exists there and is empty.
    for (label, path) in [
        (
            "A group members via B",
            format!("{base_b}/groups/{}/members", a.group),
        ),
        (
            "A group roles via B",
            format!("{base_b}/groups/{}/roles", a.group),
        ),
        (
            "A membership roles via B",
            format!("{base_b}/memberships/{}/roles", a.membership),
        ),
        (
            "A effective roles via B",
            format!("{base_b}/memberships/{}/effective-roles", a.membership),
        ),
    ] {
        let (status, _, response) = h.get(&path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label}: {response}");
        assert!(
            !response.contains(&a.role) && !response.contains(&a.group),
            "{label} must leak nothing about organization A: {response}"
        );
    }

    // Removing across organizations, three ways, each of which must remove NOTHING.
    for (label, path) in [
        // A's binding addressed from B's organization path.
        (
            "A binding via B path",
            format!("{base_b}/groups/{}/members/{}", a.group, a.membership),
        ),
        // A's group under A, paired with B's membership.
        (
            "A group + B membership",
            format!("{members_a}/{}", b.membership),
        ),
        // A's group role under A, paired with B's role.
        ("A group + B role", format!("{group_roles_a}/{}", b.role)),
        // A's membership under A, paired with B's role.
        (
            "A membership + B role",
            format!("{membership_roles_a}/{}", b.role),
        ),
        // A's membership role addressed from B's organization path.
        (
            "A direct grant via B path",
            format!("{base_b}/memberships/{}/roles/{}", a.membership, a.role),
        ),
    ] {
        let (status, _, response) = h.delete(&path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label}: {response}");
    }
    assert_eq!(
        list_ids(&h, &members_a).await.len(),
        1,
        "no cross-organization remove touched organization A's binding"
    );
    assert_eq!(
        list_ids(&h, &members_b).await.len(),
        1,
        "nor organization B's"
    );
    assert_eq!(list_ids(&h, &group_roles_a).await.len(), 1);
    assert_eq!(list_ids(&h, &membership_roles_a).await.len(), 1);

    // And the effective view of each organization's own member names only its own
    // roles: both organizations use the slug "admin", so this fails only on a real
    // leak, never on a name collision.
    let a_roles = effective_roles(&h, &a.effective(&tenant, &environment)).await;
    assert_eq!(
        a_roles,
        vec![
            ("admin".to_owned(), "direct".to_owned(), None),
            (
                "admin".to_owned(),
                "group".to_owned(),
                Some(a.group.clone())
            ),
        ],
        "organization A's member resolves A's grants only"
    );
    assert!(
        effective_roles(&h, &b.effective(&tenant, &environment))
            .await
            .is_empty(),
        "organization B's member holds nothing, and A's grants do not reach it"
    );
}

// The uniformity matrix is one proof over five probe shapes on six endpoints.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn every_refusal_is_byte_identical_across_every_shape_of_unreachable_id() {
    // The anti-oracle rule in its sharpest form on this surface. A caller must not
    // be able to tell "that id belongs to another organization" from "that id never
    // existed" from "that id is nonsense", on ANY endpoint, or the nested paths
    // become an enumeration oracle over a sibling organization's ids. The reference
    // answer is the one for a well-formed, in-scope id that was never created, and
    // every other shape must match it BYTE for byte, body included.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let a = Fixture::seed(&h, &tenant, &env_one, "a").await;
    let b = Fixture::seed(&h, &tenant, &env_one, "b").await;
    let other = Fixture::seed(&h, &tenant, &env_two, "c").await;
    let base_a = org_base(&tenant, &env_one, &a.org);

    // The five shapes, per id kind: never created in this scope, another
    // organization's, another ENVIRONMENT's, malformed, and one carrying a
    // different resource's prefix.
    let group_probes = [
        fresh_group(&tenant, &env_one),
        b.group.clone(),
        other.group.clone(),
        "grp_not-a-real-id".to_owned(),
        a.role.clone(),
    ];
    let membership_probes = [
        fresh_membership(&tenant, &env_one),
        b.membership.clone(),
        other.membership.clone(),
        "omb_not-a-real-id".to_owned(),
        a.role.clone(),
    ];
    let role_probes = [
        fresh_role(&tenant, &env_one),
        b.role.clone(),
        other.role.clone(),
        "rol_not-a-real-id".to_owned(),
        a.group.clone(),
    ];

    // 1. Every GET whose path names a group.
    for suffix in ["members", "roles"] {
        let reference = format!("{base_a}/groups/{}/{suffix}", group_probes[0]);
        let (ref_status, _, ref_body) = h.get(&reference).await;
        assert_eq!(ref_status, StatusCode::NOT_FOUND, "{ref_body}");
        for probe in &group_probes[1..] {
            let (status, _, body) = h.get(&format!("{base_a}/groups/{probe}/{suffix}")).await;
            assert_eq!(status, ref_status, "group list {suffix} probe {probe:?}");
            assert_eq!(body, ref_body, "group list {suffix} probe {probe:?} body");
        }
    }

    // 2. Every GET whose path names a membership.
    for suffix in ["roles", "effective-roles"] {
        let reference = format!("{base_a}/memberships/{}/{suffix}", membership_probes[0]);
        let (ref_status, _, ref_body) = h.get(&reference).await;
        assert_eq!(ref_status, StatusCode::NOT_FOUND, "{ref_body}");
        for probe in &membership_probes[1..] {
            let (status, _, body) = h
                .get(&format!("{base_a}/memberships/{probe}/{suffix}"))
                .await;
            assert_eq!(status, ref_status, "membership {suffix} probe {probe:?}");
            assert_eq!(body, ref_body, "membership {suffix} probe {probe:?} body");
        }
    }

    // 3. The three POST bodies. The probe rides the BODY here, so this is the case
    //    where a handler that validated the body id separately (a 400 for
    //    "malformed", a 404 for "absent") would split the answers apart.
    let members_a = a.members(&tenant, &env_one);
    let reference_body = serde_json::json!({ "membership_id": membership_probes[0] }).to_string();
    let (ref_status, _, ref_body) = h.post(&members_a, "k-ref-1", &reference_body).await;
    assert_eq!(ref_status, StatusCode::NOT_FOUND, "{ref_body}");
    for (index, probe) in membership_probes[1..].iter().enumerate() {
        let body = serde_json::json!({ "membership_id": probe }).to_string();
        let (status, _, response) = h.post(&members_a, &format!("k-p1-{index}"), &body).await;
        assert_eq!(status, ref_status, "add member probe {probe:?}");
        assert_eq!(response, ref_body, "add member probe {probe:?} body");
    }

    for (label, base) in [
        ("group role", a.group_roles(&tenant, &env_one)),
        ("membership role", a.membership_roles(&tenant, &env_one)),
    ] {
        let reference_body = serde_json::json!({ "role_id": role_probes[0] }).to_string();
        let (ref_status, _, ref_body) = h
            .post(&base, &format!("k-ref-{label}"), &reference_body)
            .await;
        assert_eq!(ref_status, StatusCode::NOT_FOUND, "{label}: {ref_body}");
        for (index, probe) in role_probes[1..].iter().enumerate() {
            let body = serde_json::json!({ "role_id": probe }).to_string();
            let (status, _, response) = h.post(&base, &format!("k-{label}-{index}"), &body).await;
            assert_eq!(status, ref_status, "{label} assign probe {probe:?}");
            assert_eq!(response, ref_body, "{label} assign probe {probe:?} body");
        }
    }

    // 4. The three pair-addressed DELETEs, probing the SECOND half of the pair
    //    against a group and a membership that genuinely exist in organization A.
    let (status, _, _) = h
        .post(
            &members_a,
            "k-seed",
            &serde_json::json!({ "membership_id": a.membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let reference = format!("{members_a}/{}", membership_probes[0]);
    let (ref_status, _, ref_body) = h.delete(&reference).await;
    assert_eq!(ref_status, StatusCode::NOT_FOUND, "{ref_body}");
    for probe in &membership_probes[1..] {
        let (status, _, body) = h.delete(&format!("{members_a}/{probe}")).await;
        assert_eq!(status, ref_status, "remove member probe {probe:?}");
        assert_eq!(body, ref_body, "remove member probe {probe:?} body");
    }

    for (label, base) in [
        ("group role", a.group_roles(&tenant, &env_one)),
        ("membership role", a.membership_roles(&tenant, &env_one)),
    ] {
        let reference = format!("{base}/{}", role_probes[0]);
        let (ref_status, _, ref_body) = h.delete(&reference).await;
        assert_eq!(ref_status, StatusCode::NOT_FOUND, "{label}: {ref_body}");
        for probe in &role_probes[1..] {
            let (status, _, body) = h.delete(&format!("{base}/{probe}")).await;
            assert_eq!(status, ref_status, "{label} unassign probe {probe:?}");
            assert_eq!(body, ref_body, "{label} unassign probe {probe:?} body");
        }
    }

    // The seeded binding survived every probe above.
    assert_eq!(list_ids(&h, &members_a).await.len(), 1);
}

// ------------------------------------------------------ credential scope -----

// The parallel `*_one` / `*_two` names track the two environments; the test is one
// indivisible proof over ten endpoints and is not split.
#[allow(clippy::similar_names, clippy::too_many_lines)]
#[tokio::test]
async fn an_environment_scoped_key_reaches_only_its_own_environments_members_and_assignments() {
    // The containment tests above drive the OPERATOR, which passes every scope check
    // by design, so they prove containment of IDS and nothing about the CREDENTIAL.
    // This one drives a real `mak_` management key, the credential class whose
    // confinement rests entirely on `Principal::require_environment` in
    // `crate::org_context::resolve_scope`. docs/THREAT-MODEL.md names that call as
    // the control for this surface, so it is exercised here on all TEN endpoints
    // rather than assumed.
    //
    // Each endpoint runs TWICE with the SAME key: once inside the environment the
    // key was minted for, which must succeed, and once against a sibling
    // environment, which must be the LOUD 403. The positive half is what makes the
    // negative half attributable to the scope check alone rather than to a broken
    // credential or a path that 404s for an unrelated reason.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let one = Fixture::seed(&h, &tenant, &env_one, "a").await;
    let two = Fixture::seed(&h, &tenant, &env_two, "b").await;
    let key = h.create_key(&tenant, &env_one, "ci", "k-key").await;

    let members_one = one.members(&tenant, &env_one);
    let group_roles_one = one.group_roles(&tenant, &env_one);
    let membership_roles_one = one.membership_roles(&tenant, &env_one);
    let effective_one = one.effective(&tenant, &env_one);
    let members_two = two.members(&tenant, &env_two);
    let group_roles_two = two.group_roles(&tenant, &env_two);
    let membership_roles_two = two.membership_roles(&tenant, &env_two);
    let effective_two = two.effective(&tenant, &env_two);

    // Environment two is seeded BY THE OPERATOR, so every probe below names rows
    // that genuinely exist there: with the scope check gone the reads answer 200 and
    // the mutations execute, rather than collapsing to a 404 that could be mistaken
    // for containment.
    let (status, _, _) = h
        .post(
            &members_two,
            "k-seed-m2",
            &serde_json::json!({ "membership_id": two.membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = h
        .post(
            &group_roles_two,
            "k-seed-gr2",
            &serde_json::json!({ "role_id": two.role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = h
        .post(
            &membership_roles_two,
            "k-seed-mr2",
            &serde_json::json!({ "role_id": two.role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // --- The key is authorized on all ten endpoints INSIDE environment one. ---
    let (status, _, body) = h
        .post_as(
            &members_one,
            &key,
            "mk-1",
            &serde_json::json!({ "membership_id": one.membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "own-environment add: {body}");
    let (status, _, body) = h.get_as(&members_one, &key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "own-environment member list: {body}"
    );
    let (status, _, body) = h
        .post_as(
            &group_roles_one,
            &key,
            "mk-2",
            &serde_json::json!({ "role_id": one.role }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "own-environment assign: {body}"
    );
    let (status, _, body) = h.get_as(&group_roles_one, &key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "own-environment group role list: {body}"
    );
    let (status, _, body) = h
        .post_as(
            &membership_roles_one,
            &key,
            "mk-3",
            &serde_json::json!({ "role_id": one.role }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "own-environment direct assign: {body}"
    );
    let (status, _, body) = h.get_as(&membership_roles_one, &key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "own-environment direct role list: {body}"
    );
    let (status, _, body) = h.get_as(&effective_one, &key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "own-environment effective roles: {body}"
    );
    let (status, _, body) = h
        .delete_as(&format!("{membership_roles_one}/{}", one.role), &key)
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "own-environment direct unassign: {body}"
    );
    let (status, _, body) = h
        .delete_as(&format!("{group_roles_one}/{}", one.role), &key)
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "own-environment unassign: {body}"
    );
    let (status, _, body) = h
        .delete_as(&format!("{members_one}/{}", one.membership), &key)
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "own-environment remove: {body}"
    );

    // --- The SAME key against environment two: the LOUD 403 on every one. ---
    let (status, _, body) = h
        .post_as(
            &members_two,
            &key,
            "mk-x1",
            &serde_json::json!({ "membership_id": two.membership }).to_string(),
        )
        .await;
    assert_wrong_scope("cross-environment add member", status, &body);
    let (status, _, body) = h.get_as(&members_two, &key).await;
    assert_wrong_scope("cross-environment member list", status, &body);
    let (status, _, body) = h
        .delete_as(&format!("{members_two}/{}", two.membership), &key)
        .await;
    assert_wrong_scope("cross-environment remove member", status, &body);
    let (status, _, body) = h
        .post_as(
            &group_roles_two,
            &key,
            "mk-x2",
            &serde_json::json!({ "role_id": two.role }).to_string(),
        )
        .await;
    assert_wrong_scope("cross-environment assign group role", status, &body);
    let (status, _, body) = h.get_as(&group_roles_two, &key).await;
    assert_wrong_scope("cross-environment group role list", status, &body);
    let (status, _, body) = h
        .delete_as(&format!("{group_roles_two}/{}", two.role), &key)
        .await;
    assert_wrong_scope("cross-environment unassign group role", status, &body);
    let (status, _, body) = h
        .post_as(
            &membership_roles_two,
            &key,
            "mk-x3",
            &serde_json::json!({ "role_id": two.role }).to_string(),
        )
        .await;
    assert_wrong_scope("cross-environment assign membership role", status, &body);
    let (status, _, body) = h.get_as(&membership_roles_two, &key).await;
    assert_wrong_scope("cross-environment membership role list", status, &body);
    let (status, _, body) = h
        .delete_as(&format!("{membership_roles_two}/{}", two.role), &key)
        .await;
    assert_wrong_scope("cross-environment unassign membership role", status, &body);
    let (status, _, body) = h.get_as(&effective_two, &key).await;
    assert_wrong_scope("cross-environment effective roles", status, &body);

    // Environment two is exactly as the operator left it: the refused writes added
    // nothing and the refused removes took nothing away.
    assert_eq!(
        list_ids(&h, &members_two).await.len(),
        1,
        "no refused request touched environment two's group members"
    );
    assert_eq!(list_ids(&h, &group_roles_two).await.len(), 1);
    assert_eq!(list_ids(&h, &membership_roles_two).await.len(), 1);
    assert_eq!(
        effective_roles(&h, &effective_two).await.len(),
        2,
        "and its member still resolves both of its grants"
    );
}

// -------------------------------------------------------- effective roles ----

// One member, four grant paths, one assertion over the WHOLE ordered result: the
// proof does not decompose without losing the ordering property.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn effective_roles_resolves_direct_group_and_ancestor_grants_each_with_its_provenance() {
    // The whole point of the endpoint: not WHICH roles, which the flat store read
    // already answered, but WHY each one is held. Four grants reach one member by
    // four different paths, and each must be reported with the path that carries it,
    // because the remedy for taking a role away is different in each case.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = org_base(&tenant, &environment, &org);

    // A three-level chain: grandparent > parent > child, with the member in child.
    let grandparent = create_group(&h, &tenant, &environment, &org, "gp", None, "k-gp").await;
    let parent = create_group(
        &h,
        &tenant,
        &environment,
        &org,
        "parent",
        Some(&grandparent),
        "k-p",
    )
    .await;
    let child = create_group(
        &h,
        &tenant,
        &environment,
        &org,
        "child",
        Some(&parent),
        "k-c",
    )
    .await;
    // A sibling branch the member is NOT in, holding a role that must NOT appear.
    let outsider = create_group(&h, &tenant, &environment, &org, "outsider", None, "k-o").await;

    let membership = create_membership(&h, &tenant, &environment, &org, "m@x.test", "k-m").await;
    let (status, _, _) = h
        .post(
            &format!("{base}/groups/{child}/members"),
            "k-bind",
            &serde_json::json!({ "membership_id": membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let direct = create_role(&h, &tenant, &environment, &org, "direct.only", "k-r1").await;
    let own = create_role(&h, &tenant, &environment, &org, "child.role", "k-r2").await;
    let inherited = create_role(&h, &tenant, &environment, &org, "ancestor.role", "k-r3").await;
    let both = create_role(&h, &tenant, &environment, &org, "both.ways", "k-r4").await;
    let unreachable = create_role(&h, &tenant, &environment, &org, "unreachable", "k-r5").await;

    for (path, role, key) in [
        (
            format!("{base}/memberships/{membership}/roles"),
            &direct,
            "k-a1",
        ),
        (format!("{base}/groups/{child}/roles"), &own, "k-a2"),
        (
            format!("{base}/groups/{grandparent}/roles"),
            &inherited,
            "k-a3",
        ),
        // The SAME role by two paths: directly, and through the parent group.
        (
            format!("{base}/memberships/{membership}/roles"),
            &both,
            "k-a4",
        ),
        (format!("{base}/groups/{parent}/roles"), &both, "k-a5"),
        // And one on a branch the member is not in.
        (
            format!("{base}/groups/{outsider}/roles"),
            &unreachable,
            "k-a6",
        ),
    ] {
        let body = serde_json::json!({ "role_id": role }).to_string();
        let (status, _, response) = h.post(&path, key, &body).await;
        assert_eq!(status, StatusCode::CREATED, "grant: {response}");
    }

    let resolved = effective_roles(
        &h,
        &format!("{base}/memberships/{membership}/effective-roles"),
    )
    .await;

    // The WHOLE list, in order, pinned: ordered by (slug, via_group_id) with direct
    // first, so two reads of unchanged state are byte-identical.
    assert_eq!(
        resolved,
        vec![
            (
                "ancestor.role".to_owned(),
                "group".to_owned(),
                Some(grandparent.clone())
            ),
            ("both.ways".to_owned(), "direct".to_owned(), None),
            (
                "both.ways".to_owned(),
                "group".to_owned(),
                Some(parent.clone())
            ),
            (
                "child.role".to_owned(),
                "group".to_owned(),
                Some(child.clone())
            ),
            ("direct.only".to_owned(), "direct".to_owned(), None),
        ],
        "every grant path is reported, with the group that carries each inherited one"
    );

    // The two properties the ordering assertion above could hide if it were a set
    // comparison, stated separately so a failure says which one broke.
    assert!(
        !resolved.iter().any(|(slug, _, _)| slug == "unreachable"),
        "a role granted to a group the member is not in must not resolve: {resolved:?}"
    );
    assert_eq!(
        resolved
            .iter()
            .filter(|(slug, _, _)| slug == "both.ways")
            .count(),
        2,
        "a role reachable two ways is reported TWICE, once per path, so an operator \
         withdrawing one grant is not told the role will go away: {resolved:?}"
    );

    // Provenance is not decorative: withdrawing the DIRECT half of `both.ways`
    // leaves the group half, exactly as the two entries said it would.
    let (status, _, _) = h
        .delete(&format!("{base}/memberships/{membership}/roles/{both}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let after = effective_roles(
        &h,
        &format!("{base}/memberships/{membership}/effective-roles"),
    )
    .await;
    assert_eq!(
        after
            .iter()
            .filter(|(slug, _, _)| slug == "both.ways")
            .collect::<Vec<_>>(),
        vec![&(
            "both.ways".to_owned(),
            "group".to_owned(),
            Some(parent.clone())
        )],
        "the direct grant is gone and the inherited one remains: {after:?}"
    );

    // And the response is an OBJECT with a named `roles` field, never a bare array,
    // so issue #98 can add `permissions` without breaking a consumer.
    let (_, _, raw) = h
        .get(&format!("{base}/memberships/{membership}/effective-roles"))
        .await;
    let value: Value = serde_json::from_str(&raw).expect("json");
    assert!(value.is_object(), "the body is an object: {raw}");
    assert!(value["roles"].is_array(), "with a named roles array: {raw}");
}

// Four withdrawal paths over ONE arrangement. Splitting them would re-seed the same
// organization four times to assert the same emptiness four ways.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn effective_roles_is_empty_by_default_and_drops_every_withdrawn_path() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = org_base(&tenant, &environment, &org);
    let group = create_group(&h, &tenant, &environment, &org, "team", None, "k-g").await;
    let membership = create_membership(&h, &tenant, &environment, &org, "m@x.test", "k-m").await;
    let role = create_role(&h, &tenant, &environment, &org, "admin", "k-r").await;
    let effective = format!("{base}/memberships/{membership}/effective-roles");

    // A member with nothing resolves to the empty list, not an error and not a 404.
    assert!(
        effective_roles(&h, &effective).await.is_empty(),
        "a member with no grants resolves to the empty set"
    );

    let (status, _, _) = h
        .post(
            &format!("{base}/groups/{group}/members"),
            "k-bind",
            &serde_json::json!({ "membership_id": membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = h
        .post(
            &format!("{base}/groups/{group}/roles"),
            "k-grant",
            &serde_json::json!({ "role_id": role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        effective_roles(&h, &effective).await,
        vec![("admin".to_owned(), "group".to_owned(), Some(group.clone()))]
    );

    // Each of the four ways a path can be broken removes it, and each is asserted
    // on its own so a single over-broad filter cannot pass for four.
    //
    // 1. Withdraw the grant from the group.
    let (status, _, _) = h
        .delete(&format!("{base}/groups/{group}/roles/{role}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        effective_roles(&h, &effective).await.is_empty(),
        "a withdrawn group grant stops resolving"
    );

    // 2. Re-grant, then remove the MEMBER from the group.
    let (status, _, _) = h
        .post(
            &format!("{base}/groups/{group}/roles"),
            "k-grant-2",
            &serde_json::json!({ "role_id": role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(effective_roles(&h, &effective).await.len(), 1);
    let (status, _, _) = h
        .delete(&format!("{base}/groups/{group}/members/{membership}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        effective_roles(&h, &effective).await.is_empty(),
        "removing the member from the group stops resolving its grants"
    );

    // 3. Re-bind, then DELETE the role itself: the assignment rows stay live, so
    //    only the role's own liveness filter keeps it out of the answer.
    let (status, _, _) = h
        .post(
            &format!("{base}/groups/{group}/members"),
            "k-bind-2",
            &serde_json::json!({ "membership_id": membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(effective_roles(&h, &effective).await.len(), 1);
    let (status, _, _) = h.delete(&format!("{base}/roles/{role}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        effective_roles(&h, &effective).await.is_empty(),
        "a deleted role stops resolving even though its assignment row is still live"
    );

    // 4. The same two questions asked of the DIRECT branch of the provenance
    //    projection, which carries its OWN copy of each predicate. Steps 1 to 3 all
    //    reach the role through a GROUP, so not one of them touches that copy, and a
    //    projection that answered "every direct grant in the organization, whatever
    //    its role's liveness" would pass all three.
    //
    //    First: WHOSE grant it is. A SECOND live membership of the SAME organization
    //    holds nothing while the first holds a live direct grant. The two rows agree
    //    on tenant, environment, and organization, so the only thing separating them
    //    is the direct branch's join back to the resolved membership; with one member
    //    per organization no assertion can tell "this member's direct grants" from
    //    "every direct grant here".
    let direct = create_role(&h, &tenant, &environment, &org, "direct.only", "k-r2").await;
    let bystander = create_membership(&h, &tenant, &environment, &org, "b@x.test", "k-m2").await;
    let direct_roles = format!("{base}/memberships/{membership}/roles");
    let (status, _, _) = h
        .post(
            &direct_roles,
            "k-direct",
            &serde_json::json!({ "role_id": direct }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        effective_roles(&h, &effective).await,
        vec![("direct.only".to_owned(), "direct".to_owned(), None)],
        "the direct grant resolves, with no group in its provenance"
    );
    assert!(
        effective_roles(
            &h,
            &format!("{base}/memberships/{bystander}/effective-roles")
        )
        .await
        .is_empty(),
        "a member who holds nothing resolves nothing, even while a SIBLING member of \
         the same organization holds a direct grant"
    );

    //    Second: the ROLE's liveness on that same branch. A role delete does not
    //    cascade its assignment rows, so the grant below stays LIVE and only the
    //    direct branch's own filter on the role keeps it out of the answer. The
    //    assertion on the direct-role LIST is what makes this a liveness proof rather
    //    than a cascade proof.
    let (status, _, _) = h.delete(&format!("{base}/roles/{direct}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        list_ids(&h, &direct_roles).await.len(),
        1,
        "the direct assignment row is still LIVE after the role delete"
    );
    assert!(
        effective_roles(&h, &effective).await.is_empty(),
        "a deleted role stops resolving on the DIRECT path too, even though its \
         assignment row is still live"
    );
}

#[tokio::test]
async fn a_deleted_group_detaches_its_subtree_and_stops_inheriting() {
    // The delete-DETACHES rule, seen from the resolution side. Deleting a mid-tree
    // group must only ever REMOVE inherited roles, never add one, and every walk
    // must treat the orphaned child as a root rather than following a stored
    // parent_id into a dead row.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = org_base(&tenant, &environment, &org);

    let root = create_group(&h, &tenant, &environment, &org, "root", None, "k-root").await;
    let middle = create_group(&h, &tenant, &environment, &org, "mid", Some(&root), "k-mid").await;
    let leaf = create_group(
        &h,
        &tenant,
        &environment,
        &org,
        "leaf",
        Some(&middle),
        "k-leaf",
    )
    .await;
    let membership = create_membership(&h, &tenant, &environment, &org, "m@x.test", "k-m").await;
    let (status, _, _) = h
        .post(
            &format!("{base}/groups/{leaf}/members"),
            "k-bind",
            &serde_json::json!({ "membership_id": membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let root_role = create_role(&h, &tenant, &environment, &org, "root.role", "k-r1").await;
    let middle_role = create_role(&h, &tenant, &environment, &org, "mid.role", "k-r2").await;
    for (group, role, key) in [(&root, &root_role, "k-a1"), (&middle, &middle_role, "k-a2")] {
        let (status, _, response) = h
            .post(
                &format!("{base}/groups/{group}/roles"),
                key,
                &serde_json::json!({ "role_id": role }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
    }

    let effective = format!("{base}/memberships/{membership}/effective-roles");
    assert_eq!(
        effective_roles(&h, &effective).await,
        vec![
            (
                "mid.role".to_owned(),
                "group".to_owned(),
                Some(middle.clone())
            ),
            (
                "root.role".to_owned(),
                "group".to_owned(),
                Some(root.clone())
            ),
        ],
        "both ancestors' grants are inherited through the chain"
    );

    // Delete the MIDDLE group. The leaf keeps its stored parent_id naming the dead
    // group, so a walk that did not filter dead rows would still reach the root.
    let (status, _, _) = h.delete(&format!("{base}/groups/{middle}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        effective_roles(&h, &effective).await.is_empty(),
        "the leaf is now a ROOT: it inherits neither the dead group's grant nor, \
         through it, the root's"
    );
}

// -------------------------------------------------------------- audit --------

#[tokio::test]
async fn every_mutation_audits_its_own_action_and_a_refusal_audits_nothing() {
    // Per the issue's resolved delta-event decision the audit log IS the delta
    // record until M11 ships delivery, so each of the six mutations must carry its
    // OWN action: a consumer that cannot tell a group grant from a direct one cannot
    // reconstruct who could do what, and the two have different blast radii.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let f = Fixture::seed(&h, &tenant, &environment, "a").await;
    let members = f.members(&tenant, &environment);
    let group_roles = f.group_roles(&tenant, &environment);
    let membership_roles = f.membership_roles(&tenant, &environment);

    for (path, body, key) in [
        (
            &members,
            serde_json::json!({ "membership_id": f.membership }).to_string(),
            "k-1",
        ),
        (
            &group_roles,
            serde_json::json!({ "role_id": f.role }).to_string(),
            "k-2",
        ),
        (
            &membership_roles,
            serde_json::json!({ "role_id": f.role }).to_string(),
            "k-3",
        ),
    ] {
        let (status, _, response) = h.post(path, key, &body).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
    }
    for path in [
        format!("{members}/{}", f.membership),
        format!("{group_roles}/{}", f.role),
        format!("{membership_roles}/{}", f.role),
    ] {
        let (status, _, response) = h.delete(&path).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
    }

    let actions = audit_actions(&h, &tenant, &environment).await;
    for expected in [
        "organization.group.member.add",
        "organization.group.member.remove",
        "organization.group.role.assign",
        "organization.group.role.unassign",
        "organization.membership.role.assign",
        "organization.membership.role.unassign",
    ] {
        assert_eq!(
            actions.iter().filter(|action| *action == expected).count(),
            1,
            "the audit log must record exactly one {expected}: {actions:?}"
        );
    }

    // A REFUSED write audits NOTHING: the endpoint resolutions run inside the
    // audited write transaction, so a refusal rolls the attempted write and its
    // audit row back together. An implementation that checked before opening the
    // transaction would leave a row describing a grant that never happened.
    let before = actions.len();
    let (status, _, _) = h
        .post(
            &group_roles,
            "k-refused",
            &serde_json::json!({ "role_id": fresh_role(&tenant, &environment) }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = h.delete(&format!("{members}/{}", f.membership)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat remove is refused");
    assert_eq!(
        audit_actions(&h, &tenant, &environment).await.len(),
        before,
        "a refused write and a refused remove each audit nothing"
    );
}

// ------------------------------------------------------------- covenant ------

#[tokio::test]
async fn nothing_caps_how_many_members_or_assignments_may_exist() {
    // The project covenant: no count cap, quota, or paywall gate anywhere on this
    // surface. Page-size clamping bounds ONE RESPONSE and is not a cap on stored
    // rows, which is what the paged read below shows.
    let h = Harness::start(3).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = org_base(&tenant, &environment, &org);
    let group = create_group(&h, &tenant, &environment, &org, "team", None, "k-g").await;
    let members = format!("{base}/groups/{group}/members");
    let group_roles = format!("{base}/groups/{group}/roles");

    for index in 0..25 {
        let membership = create_membership(
            &h,
            &tenant,
            &environment,
            &org,
            &format!("m{index}@x.test"),
            &format!("k-m{index}"),
        )
        .await;
        let (status, _, response) = h
            .post(
                &members,
                &format!("k-b{index}"),
                &serde_json::json!({ "membership_id": membership }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "member {index}: {response}");

        let role = create_role(
            &h,
            &tenant,
            &environment,
            &org,
            &format!("role{index}"),
            &format!("k-r{index}"),
        )
        .await;
        let (status, _, response) = h
            .post(
                &group_roles,
                &format!("k-gr{index}"),
                &serde_json::json!({ "role_id": role }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "role {index}: {response}");
    }

    // Every row is retrievable; the default page size of 3 bounds the RESPONSE and
    // nothing else.
    for (label, path) in [("members", members), ("group roles", group_roles)] {
        let (seen, pages) = walk_pages(&h, &path, 3).await;
        assert_eq!(
            seen.len(),
            25,
            "{label}: all 25 rows are stored and readable"
        );
        assert_eq!(pages, 9, "{label}: 25 rows at 3 per page is nine pages");
    }
}

// --------------------------------------------------------- parent guards -----

#[tokio::test]
async fn an_absent_or_soft_deleted_organization_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let f = Fixture::seed(&h, &tenant, &environment, "a").await;
    let members = f.members(&tenant, &environment);
    let (status, _, _) = h
        .post(
            &members,
            "k-bind",
            &serde_json::json!({ "membership_id": f.membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // A never-created organization: every nested endpoint is a 404.
    let absent = ironauth_store::OrganizationId::generate(
        &ironauth_env::Env::system(),
        &scope_of(&tenant, &environment),
    )
    .to_string();
    let absent_base = org_base(&tenant, &environment, &absent);
    for path in [
        format!("{absent_base}/groups/{}/members", f.group),
        format!("{absent_base}/groups/{}/roles", f.group),
        format!("{absent_base}/memberships/{}/roles", f.membership),
        format!("{absent_base}/memberships/{}/effective-roles", f.membership),
    ] {
        let (status, _, response) = h.get(&path).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "absent org: {path} {response}"
        );
    }

    // A SOFT-DELETED organization reads exactly like the absent one: its bindings
    // and assignments become unreachable rather than merely unlisted.
    let (status, _, _) = h.delete(&org_base(&tenant, &environment, &f.org)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for path in [
        members.clone(),
        f.group_roles(&tenant, &environment),
        f.membership_roles(&tenant, &environment),
        f.effective(&tenant, &environment),
    ] {
        let (status, _, response) = h.get(&path).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "deleted org: {path} {response}"
        );
    }
    let (status, _, _) = h.delete(&format!("{members}/{}", f.membership)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "and a remove under a deleted organization removes nothing"
    );
}
