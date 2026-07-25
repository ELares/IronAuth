// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization roles and groups over HTTP (issue #97, PR 4), driven through the
//! management router against a real database.
//!
//! The whole surface is NESTED under an organization, and row-level security
//! fences `(tenant, environment)` and nothing finer, so the property that has to
//! be proved on every endpoint is the same one: two organizations in the SAME
//! environment are mutually invisible through each other's path. Every containment
//! test here therefore stands up a SECOND organization holding its own rows and
//! asserts each request returns (and mutates) exactly its own set. A test that
//! only checked "an absent id is a 404" would pass with the organization filter
//! deleted, which is precisely the defect that has to be caught.
//!
//! The second load-bearing property is ANTI-ORACLE UNIFORMITY. The reparent
//! endpoint has two informative refusals (cycle, depth) that the four not-found
//! cases must never be distinguishable from, or a caller could probe a sibling
//! organization's group graph. Those tests assert the exact status AND that the
//! body says nothing about structure.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// Create a tenant with an environment.
async fn tenant_env(h: &Harness) -> (String, String) {
    h.create_tenant("acme", "k-tenant").await
}

/// Create an organization and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    id_of(&response)
}

/// The `id` field of a JSON response body.
fn id_of(response: &str) -> String {
    serde_json::from_str::<Value>(response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// The `.../organizations/{org}/roles` base path.
fn roles_base(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/roles")
}

/// The `.../organizations/{org}/groups` base path.
fn groups_base(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/groups")
}

/// Define a role, asserting a 201, and return its id.
async fn create_role(h: &Harness, base: &str, slug: &str, key: &str) -> String {
    let body = serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string();
    let (status, _, response) = h.post(base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create role: {response}");
    id_of(&response)
}

/// Define a group (optionally under a parent), asserting a 201, and return its id.
async fn create_group(
    h: &Harness,
    base: &str,
    slug: &str,
    parent: Option<&str>,
    key: &str,
) -> String {
    let mut body = serde_json::json!({ "slug": slug, "display_name": "Label" });
    if let Some(parent) = parent {
        body["parent_id"] = Value::String(parent.to_owned());
    }
    let (status, _, response) = h.post(base, key, &body.to_string()).await;
    assert_eq!(status, StatusCode::CREATED, "create group: {response}");
    id_of(&response)
}

/// The set of `id` values on a list page, as a sorted vector so an assertion pins
/// the WHOLE set rather than a membership.
async fn list_ids(h: &Harness, base: &str) -> Vec<String> {
    let (status, _, response) = h.get(base).await;
    assert_eq!(status, StatusCode::OK, "list: {response}");
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

/// A field of a resource read back through its own organization's path.
async fn field(h: &Harness, path: &str, name: &str) -> Value {
    let (status, _, response) = h.get(path).await;
    assert_eq!(status, StatusCode::OK, "get {path}: {response}");
    serde_json::from_str::<Value>(&response).expect("json")[name].clone()
}

// ---------------------------------------------------------------- roles ------

#[tokio::test]
async fn role_create_get_list_rename_and_delete_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = roles_base(&tenant, &environment, &org);

    let body = serde_json::json!({
        "slug": "billing.admin",
        "display_name": "Billing Administrator",
        "metadata": { "tier": "gold" },
    })
    .to_string();
    let (status, _, response) = h.post(&base, "k-role", &body).await;
    assert_eq!(status, StatusCode::CREATED, "create role: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let role = value["id"].as_str().expect("id").to_owned();
    assert!(role.starts_with("rol_"), "role id is typed: {role}");
    assert_eq!(value["organization_id"], org);
    assert_eq!(value["slug"], "billing.admin");
    assert_eq!(value["display_name"], "Billing Administrator");
    assert_eq!(value["metadata"]["tier"], "gold");

    // The create response and the stored row agree (the create body is composed
    // before the write, so a divergence here would be invisible otherwise).
    let path = format!("{base}/{role}");
    let (status, _, stored) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get role: {stored}");
    assert_eq!(
        serde_json::from_str::<Value>(&stored).expect("json"),
        value,
        "the create response must describe the row the get returns"
    );

    assert_eq!(list_ids(&h, &base).await, vec![role.clone()]);

    // Rename: the display name moves, the SLUG does not.
    let (status, _, response) = h
        .patch(
            &path,
            &serde_json::json!({ "display_name": "Billing" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "rename role: {response}");
    let renamed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(renamed["display_name"], "Billing");
    assert_eq!(
        renamed["slug"], "billing.admin",
        "the slug is immutable across a rename"
    );
    assert_eq!(
        renamed["metadata"]["tier"], "gold",
        "an omitted metadata field leaves the stored document unchanged"
    );

    // Delete: 204, then absent, and a repeat delete is the uniform 404.
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = h.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a deleted role reads absent");
    assert!(list_ids(&h, &base).await.is_empty());
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat delete is 404");
}

#[tokio::test]
async fn a_live_slug_collides_and_a_deleted_one_is_free_again() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = roles_base(&tenant, &environment, &org);

    let first = create_role(&h, &base, "admin", "k-1").await;
    // A distinct second create (a different Idempotency-Key) of the same slug is a 409.
    let body = serde_json::json!({ "slug": "admin", "display_name": "Other" }).to_string();
    let (status, _, response) = h.post(&base, "k-2", &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate slug: {response}");

    // Deleting frees the slug, and re-using it mints a FRESH id: a deleted role is
    // never revived, so its authorization effect cannot be quietly restored.
    let (status, _, _) = h.delete(&format!("{base}/{first}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, response) = h.post(&base, "k-3", &body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "slug freed by delete: {response}"
    );
    assert_ne!(id_of(&response), first, "the revived slug gets a fresh id");
}

#[tokio::test]
async fn a_slug_the_stable_name_rule_refuses_is_a_bad_request() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let groups = groups_base(&tenant, &environment, &org);

    // Each of these is refused by the schema CHECK. The management edge must report
    // it as a caller-facing 400; without the edge check it would reach the CHECK and
    // surface as an opaque 500.
    for (index, slug) in ["Admin", ".leading", "has space", ""].iter().enumerate() {
        let body = serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string();
        let (status, _, response) = h.post(&roles, &format!("k-r{index}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "role slug {slug:?}: {response}"
        );
        let (status, _, response) = h.post(&groups, &format!("k-g{index}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "group slug {slug:?}: {response}"
        );
    }

    // An empty display name is likewise a 400, on create and on rename.
    let body = serde_json::json!({ "slug": "ok", "display_name": "  " }).to_string();
    let (status, _, _) = h.post(&roles, "k-blank", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let role = create_role(&h, &roles, "renameable", "k-ok").await;
    let (status, _, _) = h
        .patch(
            &format!("{roles}/{role}"),
            &serde_json::json!({ "display_name": "" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_replayed_role_create_returns_the_original_and_writes_no_second_role() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = roles_base(&tenant, &environment, &org);
    let body = serde_json::json!({ "slug": "admin", "display_name": "Admin" }).to_string();

    let (status, _, first) = h.post(&base, "k-same", &body).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, replay) = h.post(&base, "k-same", &body).await;
    assert_eq!(status, StatusCode::CREATED, "a replay repeats the original");
    assert_eq!(first, replay, "byte-identical replay");
    assert_eq!(
        list_ids(&h, &base).await.len(),
        1,
        "the replay must not have created a second role"
    );

    // The SAME key with a DIFFERENT body is the 422 key-conflict, not a second role.
    let other = serde_json::json!({ "slug": "other", "display_name": "Other" }).to_string();
    let (status, _, _) = h.post(&base, "k-same", &other).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(list_ids(&h, &base).await.len(), 1);
}

#[tokio::test]
async fn roles_are_partitioned_by_organization_on_every_endpoint() {
    // TWO organizations in ONE environment, each holding its own role. Row-level
    // security fences the environment and nothing finer, so `organization_id` is the
    // only thing separating them: every assertion below fails if that filter or the
    // nested-address guard is removed.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org_a = create_org(&h, &tenant, &environment, "k-org-a").await;
    let org_b = create_org(&h, &tenant, &environment, "k-org-b").await;
    let base_a = roles_base(&tenant, &environment, &org_a);
    let base_b = roles_base(&tenant, &environment, &org_b);

    let role_a = create_role(&h, &base_a, "shared.slug", "k-a").await;
    let role_b = create_role(&h, &base_b, "shared.slug", "k-b").await;
    assert_ne!(role_a, role_b);

    // 1. Each list returns EXACTLY its own set. The same slug lives in both, so a
    //    leak would be invisible to an assertion on slugs alone.
    assert_eq!(list_ids(&h, &base_a).await, vec![role_a.clone()]);
    assert_eq!(list_ids(&h, &base_b).await, vec![role_b.clone()]);

    // 2. Reading A's role through B's path is the uniform not-found, identical to an
    //    id that never existed.
    let (status, _, _) = h.get(&format!("{base_b}/{role_a}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org get");
    let (status, _, _) = h.get(&format!("{base_a}/{role_b}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org get, other way");

    // 3. Renaming A's role through B's path is a 404 and MUTATES NOTHING.
    let (status, _, _) = h
        .patch(
            &format!("{base_b}/{role_a}"),
            &serde_json::json!({ "display_name": "Pwned" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org rename");
    assert_eq!(
        field(&h, &format!("{base_a}/{role_a}"), "display_name").await,
        "Label",
        "the cross-org rename must not have touched org A's role"
    );

    // 4. An EMPTY patch supplies no mutable field, so the write is skipped entirely
    //    and the READ is the only guard left. Cross-organization it must still be the
    //    uniform 404, never a 200 that hands back the sibling's role as its body.
    let (status, _, response) = h.patch(&format!("{base_b}/{role_a}"), "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org empty patch");
    assert!(
        !response.contains(&role_a),
        "the refused patch must not echo org A's role: {response}"
    );

    // 5. Deleting A's role through B's path is a 404 and REMOVES NOTHING.
    let (status, _, _) = h.delete(&format!("{base_b}/{role_a}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org delete");
    assert_eq!(
        list_ids(&h, &base_a).await,
        vec![role_a],
        "the cross-org delete must not have removed org A's role"
    );
}

// --------------------------------------------------------------- groups ------

#[tokio::test]
async fn group_create_nest_get_list_rename_and_delete_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = groups_base(&tenant, &environment, &org);

    let root = create_group(&h, &base, "engineering", None, "k-root").await;
    assert!(root.starts_with("grp_"), "group id is typed: {root}");
    assert_eq!(
        field(&h, &format!("{base}/{root}"), "parent_id").await,
        Value::Null,
        "a group created with no parent is a root"
    );

    let child = create_group(&h, &base, "platform", Some(&root), "k-child").await;
    assert_eq!(
        field(&h, &format!("{base}/{child}"), "parent_id").await,
        root.as_str(),
        "the create honored the requested parent"
    );

    // The list is FLAT: both groups, each carrying its parent_id.
    let mut expected = vec![root.clone(), child.clone()];
    expected.sort();
    assert_eq!(list_ids(&h, &base).await, expected);

    // Rename leaves the slug and the parent alone.
    let (status, _, response) = h
        .patch(
            &format!("{base}/{child}"),
            &serde_json::json!({ "display_name": "Platform" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "rename group: {response}");
    let renamed: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(renamed["display_name"], "Platform");
    assert_eq!(renamed["slug"], "platform", "the slug is immutable");
    assert_eq!(
        renamed["parent_id"], root,
        "a rename must not reshape the tree"
    );

    // Deleting the ROOT DETACHES the child rather than cascading: the child stays
    // live and readable, and its stored parent_id still names the dead group.
    let (status, _, _) = h.delete(&format!("{base}/{root}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        list_ids(&h, &base).await,
        vec![child.clone()],
        "the child survives its parent's delete"
    );
    assert_eq!(
        field(&h, &format!("{base}/{child}"), "parent_id").await,
        root.as_str(),
        "a delete detaches without rewriting the child's parent_id"
    );
    let (status, _, _) = h.delete(&format!("{base}/{root}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat delete is 404");
}

#[tokio::test]
async fn reparent_moves_a_group_and_promoting_to_a_root_is_always_allowed() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = groups_base(&tenant, &environment, &org);

    let a = create_group(&h, &base, "a", None, "k-a").await;
    let b = create_group(&h, &base, "b", None, "k-b").await;

    // Move b under a.
    let (status, _, response) = h
        .put(
            &format!("{base}/{b}/parent"),
            &serde_json::json!({ "parent_id": a }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "reparent: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["parent_id"],
        a
    );
    assert_eq!(field(&h, &format!("{base}/{b}"), "parent_id").await, a);

    // Promote b back to a root with an explicit null: always admissible.
    let (status, _, response) = h
        .put(
            &format!("{base}/{b}/parent"),
            &serde_json::json!({ "parent_id": Value::Null }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "promote to root: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["parent_id"],
        Value::Null
    );
}

#[tokio::test]
async fn reparent_refuses_a_cycle_as_a_422_and_writes_nothing() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = groups_base(&tenant, &environment, &org);

    let root = create_group(&h, &base, "root", None, "k-root").await;
    let child = create_group(&h, &base, "child", Some(&root), "k-child").await;

    // Moving the root under its own child would make it its own ancestor.
    let (status, _, response) = h
        .put(
            &format!("{base}/{root}/parent"),
            &serde_json::json!({ "parent_id": child }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a cycle is a typed 422, never a 500: {response}"
    );
    let body: Value = serde_json::from_str(&response).expect("json");
    assert!(
        body["message"].as_str().expect("message").contains("cycle"),
        "the refusal must name the cycle: {response}"
    );

    // A one-node cycle (a group its own parent) is refused too.
    let (status, _, _) = h
        .put(
            &format!("{base}/{root}/parent"),
            &serde_json::json!({ "parent_id": root }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "self-parent");

    // Nothing was written: the root is still a root and the child still hangs off it.
    assert_eq!(
        field(&h, &format!("{base}/{root}"), "parent_id").await,
        Value::Null
    );
    assert_eq!(
        field(&h, &format!("{base}/{child}"), "parent_id").await,
        root.as_str()
    );
}

#[tokio::test]
async fn the_depth_bound_refuses_an_over_deep_create_and_reparent_with_an_at_least_floor() {
    // A bound of 1 admits exactly one edge: a root and one child. It caps DEPTH, not
    // COUNT, which the sibling assertion below pins.
    let h = Harness::start_with_group_depth(50, 1).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = groups_base(&tenant, &environment, &org);

    let root = create_group(&h, &base, "root", None, "k-root").await;
    let child = create_group(&h, &base, "child", Some(&root), "k-child").await;

    // A grandchild would be depth 2, one past the bound: refused on CREATE.
    let body = serde_json::json!({
        "slug": "grandchild",
        "display_name": "Label",
        "parent_id": child,
    })
    .to_string();
    let (status, _, response) = h.post(&base, "k-deep", &body).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an over-deep create is a typed 422: {response}"
    );
    let message = serde_json::from_str::<Value>(&response).expect("json")["message"]
        .as_str()
        .expect("message")
        .to_owned();
    assert!(
        message.contains("at least"),
        "a saturating walk reports a FLOOR, so the message must say \"at least\": {message}"
    );
    assert!(
        message.contains('2') && message.contains('1'),
        "the message must carry both the attempted depth and the bound: {message}"
    );
    assert!(
        !message.contains("cycle"),
        "a depth refusal is not a cycle refusal: {message}"
    );

    // The same move as a REPARENT is refused identically.
    let orphan = create_group(&h, &base, "orphan", None, "k-orphan").await;
    let (status, _, response) = h
        .put(
            &format!("{base}/{orphan}/parent"),
            &serde_json::json!({ "parent_id": child }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
    assert!(
        serde_json::from_str::<Value>(&response).expect("json")["message"]
            .as_str()
            .expect("message")
            .contains("at least")
    );
    assert_eq!(
        field(&h, &format!("{base}/{orphan}"), "parent_id").await,
        Value::Null,
        "the refused reparent wrote nothing"
    );

    // The COVENANT: the bound is on depth, never on count. Many more siblings at an
    // admissible depth are all accepted.
    for index in 0..12 {
        create_group(
            &h,
            &base,
            &format!("sibling{index}"),
            Some(&root),
            &format!("k-sib{index}"),
        )
        .await;
    }
    assert_eq!(
        list_ids(&h, &base).await.len(),
        15,
        "root + child + orphan + 12 siblings: no count cap anywhere"
    );
}

#[tokio::test]
async fn groups_are_partitioned_by_organization_on_every_endpoint() {
    // The same two-organization proof as for roles, extended to the two mutations
    // that only groups have (reparent, and a cross-organization PARENT).
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org_a = create_org(&h, &tenant, &environment, "k-org-a").await;
    let org_b = create_org(&h, &tenant, &environment, "k-org-b").await;
    let base_a = groups_base(&tenant, &environment, &org_a);
    let base_b = groups_base(&tenant, &environment, &org_b);

    let group_a = create_group(&h, &base_a, "shared.slug", None, "k-a").await;
    let group_b = create_group(&h, &base_b, "shared.slug", None, "k-b").await;

    // 1. Each list returns EXACTLY its own set.
    assert_eq!(list_ids(&h, &base_a).await, vec![group_a.clone()]);
    assert_eq!(list_ids(&h, &base_b).await, vec![group_b.clone()]);

    // 2. Cross-organization get.
    let (status, _, _) = h.get(&format!("{base_b}/{group_a}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org get");

    // 3. Cross-organization rename: a 404 that MUTATES NOTHING. This is the exact
    //    hole PR 2's review found in the store (`update` addressed by id alone), so
    //    it is asserted on the state, not only on the status.
    let (status, _, _) = h
        .patch(
            &format!("{base_b}/{group_a}"),
            &serde_json::json!({ "display_name": "Pwned" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org rename");
    assert_eq!(
        field(&h, &format!("{base_a}/{group_a}"), "display_name").await,
        "Label",
        "the cross-org rename must not have touched org A's group"
    );

    // 3b. An EMPTY patch supplies no mutable field, so the store write is skipped and
    //     the READ is the only guard left on that path. It must still be the uniform
    //     404, never a 200 handing back the sibling organization's group.
    let (status, _, response) = h.patch(&format!("{base_b}/{group_a}"), "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org empty patch");
    assert!(
        !response.contains(&group_a),
        "the refused patch must not echo org A's group: {response}"
    );

    // 4. Cross-organization reparent, addressed from B: a 404 that moves nothing.
    let (status, _, _) = h
        .put(
            &format!("{base_b}/{group_a}/parent"),
            &serde_json::json!({ "parent_id": group_b }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org reparent");
    assert_eq!(
        field(&h, &format!("{base_a}/{group_a}"), "parent_id").await,
        Value::Null,
        "the cross-org reparent must not have moved org A's group"
    );

    // 5. Cross-organization delete: a 404 that removes nothing.
    let (status, _, _) = h.delete(&format!("{base_b}/{group_a}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org delete");
    assert_eq!(
        list_ids(&h, &base_a).await,
        vec![group_a],
        "the cross-org delete must not have removed org A's group"
    );
}

#[tokio::test]
async fn a_cross_organization_parent_is_the_uniform_not_found_and_never_a_structure_error() {
    // The anti-oracle rule in its sharpest form. Both typed refusals (cycle, depth)
    // are INFORMATIVE, so if either could be returned for a group the caller cannot
    // address, a caller could probe a sibling organization's ids and learn which of
    // them are ancestors of which. The store resolves both endpoints as live groups
    // of THIS organization first, and this asserts the whole chain end to end: the
    // status is the SAME 404 an absent id gets, and the body says nothing structural.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org_a = create_org(&h, &tenant, &environment, "k-org-a").await;
    let org_b = create_org(&h, &tenant, &environment, "k-org-b").await;
    let base_a = groups_base(&tenant, &environment, &org_a);
    let base_b = groups_base(&tenant, &environment, &org_b);

    let a_root = create_group(&h, &base_a, "root", None, "k-a-root").await;
    let a_child = create_group(&h, &base_a, "child", Some(&a_root), "k-a-child").await;
    let b_group = create_group(&h, &base_b, "b", None, "k-b").await;

    // The reference 404: a well-formed, in-scope group id that was never created.
    let absent = fresh_in_scope_group(&tenant, &environment);
    let (absent_status, _, absent_body) = h
        .put(
            &format!("{base_a}/{a_child}/parent"),
            &serde_json::json!({ "parent_id": absent }).to_string(),
        )
        .await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);

    // A parent in ANOTHER organization must be indistinguishable from that.
    let (status, _, body) = h
        .put(
            &format!("{base_a}/{a_child}/parent"),
            &serde_json::json!({ "parent_id": b_group }).to_string(),
        )
        .await;
    assert_eq!(status, absent_status, "cross-org parent status is uniform");
    assert_eq!(body, absent_body, "cross-org parent body is uniform");

    // A parent in another SCOPE, and a malformed one, land on the same answer: no
    // input distinguishes "wrong organization" from "never existed" from "nonsense".
    let other_env = h.create_environment(&tenant, "second", "k-env-2").await;
    let other_scope = fresh_in_scope_group(&tenant, &other_env);
    for probe in [other_scope.as_str(), "grp_not-a-real-id", "", "org_abc"] {
        let (status, _, probe_body) = h
            .put(
                &format!("{base_a}/{a_child}/parent"),
                &serde_json::json!({ "parent_id": probe }).to_string(),
            )
            .await;
        assert_eq!(status, absent_status, "parent probe {probe:?} status");
        assert_eq!(probe_body, absent_body, "parent probe {probe:?} body");
    }

    // And the CREATE path answers identically for a cross-organization parent.
    let create = serde_json::json!({
        "slug": "nested",
        "display_name": "Label",
        "parent_id": b_group,
    })
    .to_string();
    let (status, _, response) = h.post(&base_a, "k-cross", &create).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "cross-org parent on create");
    assert!(
        !response.contains("cycle") && !response.contains("levels deep"),
        "the refusal must not leak structure: {response}"
    );

    // The graph is untouched by every probe above.
    assert_eq!(
        field(&h, &format!("{base_a}/{a_child}"), "parent_id").await,
        a_root.as_str()
    );
}

#[tokio::test]
async fn every_mutation_audits_its_own_action_and_a_refusal_audits_nothing() {
    // Two properties, both falsifiable.
    //
    // 1. The audit VOCABULARY. Per the issue's resolved delta-event decision, the
    //    audit log IS the delta record until M11 ships delivery, so a reparent must
    //    carry its OWN action and not be folded into the rename's: a consumer that
    //    cannot tell a rename from a move cannot reconstruct the tree.
    // 2. A REFUSED reparent audits NOTHING. The cycle check runs inside the audited
    //    write transaction, so a refusal rolls the attempted write and its audit row
    //    back together. An implementation that checked before opening the transaction
    //    would leave an audit row describing a move that never happened.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let roles = roles_base(&tenant, &environment, &org);
    let groups = groups_base(&tenant, &environment, &org);

    let role = create_role(&h, &roles, "admin", "k-role").await;
    let (status, _, _) = h
        .patch(
            &format!("{roles}/{role}"),
            &serde_json::json!({ "display_name": "Renamed" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = h.delete(&format!("{roles}/{role}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let root = create_group(&h, &groups, "root", None, "k-root").await;
    let child = create_group(&h, &groups, "child", Some(&root), "k-child").await;
    let (status, _, _) = h
        .patch(
            &format!("{groups}/{child}"),
            &serde_json::json!({ "display_name": "Renamed" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // One SUCCESSFUL reparent (promote the child to a root).
    let (status, _, _) = h
        .put(
            &format!("{groups}/{child}/parent"),
            &serde_json::json!({ "parent_id": Value::Null }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let actions = audit_actions(&h, &tenant, &environment).await;
    for expected in [
        "organization.role.create",
        "organization.role.update",
        "organization.role.delete",
        "organization.group.create",
        "organization.group.update",
        "organization.group.reparent",
    ] {
        assert!(
            actions.iter().any(|action| action == expected),
            "the audit log must record {expected}: {actions:?}"
        );
    }
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "organization.group.reparent")
            .count(),
        1,
        "exactly one reparent so far: {actions:?}"
    );

    // A REFUSED reparent (the child is now a root again; move the root under it,
    // then move it under itself) writes no further audit row.
    let (status, _, _) = h
        .put(
            &format!("{groups}/{root}/parent"),
            &serde_json::json!({ "parent_id": root }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let after_refusal = audit_actions(&h, &tenant, &environment).await;
    assert_eq!(
        after_refusal
            .iter()
            .filter(|action| *action == "organization.group.reparent")
            .count(),
        1,
        "a refused reparent must roll its audit row back with the write: {after_refusal:?}"
    );

    // And the group delete audits its own action.
    let (status, _, _) = h.delete(&format!("{groups}/{root}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let final_actions = audit_actions(&h, &tenant, &environment).await;
    assert!(
        final_actions
            .iter()
            .any(|action| action == "organization.group.delete"),
        "the audit log must record organization.group.delete: {final_actions:?}"
    );
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

#[tokio::test]
async fn a_second_scope_cannot_reach_the_first_scopes_roles_or_groups() {
    // Cross-ENVIRONMENT containment, above the cross-organization case: a typed id
    // embeds its scope, so an id minted in environment 1 never parses in environment
    // 2 and the nested path is the uniform not-found in both directions.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let org_one = create_org(&h, &tenant, &env_one, "k-org-1").await;
    let org_two = create_org(&h, &tenant, &env_two, "k-org-2").await;

    let roles_one = roles_base(&tenant, &env_one, &org_one);
    let groups_one = groups_base(&tenant, &env_one, &org_one);
    let role = create_role(&h, &roles_one, "admin", "k-role").await;
    let group = create_group(&h, &groups_one, "team", None, "k-group").await;

    // Environment 2's paths cannot address environment 1's rows, whichever
    // organization segment is used.
    for org in [org_one.as_str(), org_two.as_str()] {
        let roles_two = roles_base(&tenant, &env_two, org);
        let groups_two = groups_base(&tenant, &env_two, org);
        let (status, _, _) = h.get(&format!("{roles_two}/{role}")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-env role get via {org}"
        );
        let (status, _, _) = h.delete(&format!("{groups_two}/{group}")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-env group delete via {org}"
        );
    }

    // Environment 2's lists are empty; environment 1's are intact.
    assert!(
        list_ids(&h, &roles_base(&tenant, &env_two, &org_two))
            .await
            .is_empty()
    );
    assert!(
        list_ids(&h, &groups_base(&tenant, &env_two, &org_two))
            .await
            .is_empty()
    );
    assert_eq!(list_ids(&h, &roles_one).await, vec![role]);
    assert_eq!(list_ids(&h, &groups_one).await, vec![group]);
}

#[tokio::test]
async fn an_absent_or_soft_deleted_organization_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = roles_base(&tenant, &environment, &org);
    let role = create_role(&h, &base, "admin", "k-role").await;

    // A never-created organization: every nested endpoint is a 404.
    let absent = fresh_in_scope_org(&tenant, &environment);
    let absent_roles = roles_base(&tenant, &environment, &absent);
    let absent_groups = groups_base(&tenant, &environment, &absent);
    let (status, _, _) = h.get(&absent_roles).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = h.get(&format!("{absent_roles}/{role}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = h
        .post(
            &absent_groups,
            "k-absent",
            &serde_json::json!({ "slug": "g", "display_name": "L" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A SOFT-DELETED organization reads exactly like the absent one, and its roles
    // become unreachable rather than merely unlisted.
    let (status, _, _) = h
        .delete(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}"
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = h.get(&base).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "list under a deleted org");
    let (status, _, _) = h.get(&format!("{base}/{role}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "get under a deleted org");
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
fn fresh_in_scope_group(tenant: &str, environment: &str) -> String {
    ironauth_store::OrgGroupId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// A well-formed organization id in the given scope that was never created.
fn fresh_in_scope_org(tenant: &str, environment: &str) -> String {
    ironauth_store::OrganizationId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}
