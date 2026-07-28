// SPDX-License-Identifier: MIT OR Apache-2.0

//! The permission vocabulary over HTTP (issue #98, PR 7), driven through the
//! management router against a real database.
//!
//! The property that has to be proved on every endpoint here is DIFFERENT from the
//! one #97's suite proves, and confusing the two would leave the real fence
//! untested. `permissions` carries no `organization_id`, so there is no sibling
//! organization to be invisible to: the vocabulary is scoped to `(tenant,
//! environment)` and to nothing finer, and the row-level-security policy is its
//! complete fence. What must therefore be proved is CROSS ENVIRONMENT containment,
//! and every cross-scope fixture below differs from its counterpart in the
//! ENVIRONMENT alone, under one tenant. A second tenant would also be refused by
//! the tenant predicate, so it would prove nothing about the environment half.
//!
//! Three properties get their own tests because each has been a real defect on a
//! surface of exactly this shape:
//!
//!   * The CREDENTIAL scope check. A test driving the operator proves containment
//!     of IDS and nothing about the credential, because the operator passes every
//!     scope check by design. `an_environment_scoped_key_reaches_only_its_own_...`
//!     drives a real `mak_` key on all five endpoints.
//!   * ANTI-ORACLE uniformity. Six shapes must be ONE answer, byte for byte, in
//!     status AND body, on the read and on BOTH mutations: never created,
//!     soft-deleted, another environment's, malformed, carrying another resource
//!     type's prefix, and blank. A seventh, an empty final path segment, is refused
//!     by the router before any handler runs and so is NOT byte-identical; it is
//!     asserted separately, on the property that makes it harmless.
//!   * The cursor KEY. The list orders by `(created_at, id)`; a cursor built from
//!     `updated_at` truncates a walk with everything green. `permissions` has an
//!     update surface, so a relabel makes that observable and the pagination test
//!     performs one on the row that ends page one.

mod common;

use std::collections::HashSet;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// Create a tenant with an environment.
async fn tenant_env(h: &Harness) -> (String, String) {
    h.create_tenant("acme", "k-tenant").await
}

/// The `.../environments/{environment}/permissions` base path. There is NO
/// organization segment, by design: see the module docs and migration 0091.
fn permissions_base(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/permissions")
}

/// The `id` field of a JSON response body.
fn id_of(response: &str) -> String {
    serde_json::from_str::<Value>(response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// A create body carrying the two required fields.
fn create_body(slug: &str) -> String {
    serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string()
}

/// A relabel body.
fn relabel_body(display_name: &str) -> String {
    serde_json::json!({ "display_name": display_name }).to_string()
}

/// Define a permission, asserting a 201, and return its id.
async fn create_permission(h: &Harness, base: &str, slug: &str, key: &str) -> String {
    let (status, _, response) = h.post(base, key, &create_body(slug)).await;
    assert_eq!(status, StatusCode::CREATED, "create permission: {response}");
    id_of(&response)
}

/// The sorted set of `id` values on a list page, so an assertion pins the WHOLE
/// set rather than a membership.
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

/// A field of a permission read back through its own environment's path.
async fn field(h: &Harness, path: &str, name: &str) -> Value {
    let (status, _, response) = h.get(path).await;
    assert_eq!(status, StatusCode::OK, "get {path}: {response}");
    serde_json::from_str::<Value>(&response).expect("json")[name].clone()
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

/// A well-formed ORGANIZATION id in the given scope: a well-formed identifier of
/// the right scope and the WRONG KIND, which must be as unaddressable as nonsense.
fn fresh_in_scope_org(tenant: &str, environment: &str) -> String {
    ironauth_store::OrganizationId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// Every `permission.*` audit action recorded in one scope, sorted: the audit
/// MULTISET, compared whole so an extra row is as visible as a missing one.
async fn permission_audit(h: &Harness, tenant: &str, environment: &str) -> Vec<String> {
    let mut actions: Vec<String> = h
        .control_store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .filter(|action| action.starts_with("permission."))
        .collect();
    actions.sort();
    actions
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

// One test rather than five: the audit MULTISET is checked at every step, and a
// multiset assertion only means anything if every step before it ran against the
// same scope in the same order.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn permission_create_get_list_relabel_and_delete_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = permissions_base(&tenant, &environment);

    assert!(
        permission_audit(&h, &tenant, &environment).await.is_empty(),
        "the vocabulary audit trail starts empty"
    );

    let body = serde_json::json!({
        "slug": "billing.invoice.read",
        "display_name": "Read invoices",
        "metadata": { "tier": "gold" },
    })
    .to_string();
    let (status, _, response) = h.post(&base, "k-create", &body).await;
    assert_eq!(status, StatusCode::CREATED, "create: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let permission = value["id"].as_str().expect("id").to_owned();
    assert!(
        permission.starts_with("prm_"),
        "the permission id is typed: {permission}"
    );
    assert_eq!(value["slug"], "billing.invoice.read");
    assert_eq!(value["display_name"], "Read invoices");
    assert_eq!(value["metadata"]["tier"], "gold");
    assert_eq!(
        value["kind"], "permission",
        "issue #98 defines no entitlements, so every row this API creates is a permission"
    );
    assert!(
        value.get("organization_id").is_none(),
        "the vocabulary is per ENVIRONMENT: no organization appears anywhere in it: {response}"
    );
    assert_eq!(
        permission_audit(&h, &tenant, &environment).await,
        vec!["permission.create"],
        "the create audits exactly once"
    );

    // The create response and the stored row agree. The create body is composed
    // BEFORE the write from values the handler holds, so a divergence between what
    // it promised and what it stored would be invisible without this.
    let path = format!("{base}/{permission}");
    let (status, _, stored) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get: {stored}");
    assert_eq!(
        serde_json::from_str::<Value>(&stored).expect("json"),
        value,
        "the create response must describe the row the get returns"
    );
    assert_eq!(list_ids(&h, &base).await, vec![permission.clone()]);
    assert_eq!(
        permission_audit(&h, &tenant, &environment).await,
        vec!["permission.create"],
        "reads audit nothing"
    );

    // Relabel: the display name moves, the SLUG and the KIND do not.
    let (status, _, response) = h.patch(&path, &relabel_body("Invoices")).await;
    assert_eq!(status, StatusCode::OK, "relabel: {response}");
    let relabeled: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(relabeled["display_name"], "Invoices");
    assert_eq!(
        relabeled["slug"], "billing.invoice.read",
        "the slug is immutable across a relabel"
    );
    assert_eq!(relabeled["kind"], "permission", "the kind is immutable too");
    assert_eq!(
        relabeled["metadata"]["tier"], "gold",
        "an omitted metadata field leaves the stored document unchanged"
    );
    assert_eq!(
        permission_audit(&h, &tenant, &environment).await,
        vec!["permission.create", "permission.update"],
    );

    // Metadata is a whole-document REPLACE, not a merge.
    let (status, _, response) = h
        .patch(
            &path,
            &serde_json::json!({ "metadata": { "tier": "free" } }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "replace metadata: {response}");
    assert_eq!(
        field(&h, &path, "metadata").await,
        serde_json::json!({ "tier": "free" })
    );

    // Delete: 204, then absent, and a repeat delete is the uniform 404 that audits
    // nothing (a soft delete that could be repeated would write a second row).
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = h.get(&path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deleted permission reads absent"
    );
    assert!(list_ids(&h, &base).await.is_empty());
    let after_delete = permission_audit(&h, &tenant, &environment).await;
    assert_eq!(
        after_delete,
        vec![
            "permission.create",
            "permission.delete",
            "permission.update",
            "permission.update",
        ],
    );
    let (status, _, _) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a repeat delete is 404");
    assert_eq!(
        permission_audit(&h, &tenant, &environment).await,
        after_delete,
        "the refused repeat delete audits nothing"
    );
}

#[tokio::test]
async fn a_patch_naming_the_immutable_slug_or_kind_is_refused_at_the_edge() {
    // `slug` and `kind` are absent from migration 0091's control-role UPDATE grant,
    // so a statement naming either is refused by Postgres as SQLSTATE 42501 and
    // reaches the caller as an opaque 500. The refusal therefore has to happen at
    // the edge. A 400 (never a 500, and never a 200 that silently ignored the field)
    // is what proves the value never reached a statement.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = permissions_base(&tenant, &environment);
    let permission = create_permission(&h, &base, "billing.invoice.read", "k-1").await;
    let path = format!("{base}/{permission}");

    // The positive control FIRST: an ordinary relabel through the same handler
    // succeeds, so every refusal below is attributable to the immutable-field rule
    // rather than to a PATCH that cannot work at all.
    let (status, _, response) = h.patch(&path, &relabel_body("Invoices")).await;
    assert_eq!(status, StatusCode::OK, "the control relabel: {response}");

    for (label, body) in [
        (
            "slug",
            serde_json::json!({ "slug": "billing.invoice.write" }),
        ),
        ("kind", serde_json::json!({ "kind": "entitlement" })),
        // Named ALONGSIDE a legitimate edit: the whole request must be refused, or a
        // caller could smuggle an immutable field in behind a valid one.
        (
            "slug",
            serde_json::json!({ "display_name": "Pwned", "slug": "billing.invoice.write" }),
        ),
        (
            "kind",
            serde_json::json!({ "display_name": "Pwned", "kind": "entitlement" }),
        ),
        // Named with an EXPLICIT NULL. This is the case a value test cannot see:
        // under `#[serde(default)]` a plain `Option` maps both an absent key and a
        // key carrying `null` to `None`, so `is_some()` waves this body through, the
        // handler answers 200, and a caller who wrote `"slug": null` is told their
        // request about the slug succeeded. That IS the silent ignore this rule
        // exists to prevent, so presence and not value is what must be refused.
        ("slug", serde_json::json!({ "slug": null })),
        ("kind", serde_json::json!({ "kind": null })),
        // The null smuggled in behind a legitimate edit, which is how the value test
        // was observably wrong: it returned 200 AND applied the display name.
        (
            "slug",
            serde_json::json!({ "display_name": "Pwned", "slug": null }),
        ),
        (
            "kind",
            serde_json::json!({ "display_name": "Pwned", "kind": null }),
        ),
    ] {
        let (status, _, response) = h.patch(&path, &body.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} in {body} must be a typed 400, never a 500 from the grant \
             and never a 200 that dropped it: {response}"
        );
        let message = serde_json::from_str::<Value>(&response).expect("json")["message"]
            .as_str()
            .expect("message")
            .to_owned();
        assert!(
            message.contains(label) && message.contains("immutable"),
            "the refusal must name the field and the rule: {message}"
        );
    }

    // Nothing moved: not the slug, not the kind, and not the display name the two
    // smuggling bodies also carried. The last of those is the load-bearing one: it
    // proves the refusal happens BEFORE the write rather than after it.
    assert_eq!(field(&h, &path, "slug").await, "billing.invoice.read");
    assert_eq!(field(&h, &path, "kind").await, "permission");
    assert_eq!(
        field(&h, &path, "display_name").await,
        "Invoices",
        "a refused patch must not have applied its legitimate half"
    );
    assert_eq!(
        permission_audit(&h, &tenant, &environment).await,
        vec!["permission.create", "permission.update"],
        "exactly one create and the ONE control relabel: no refusal wrote an audit row"
    );
}

#[tokio::test]
async fn a_permission_slug_the_namespaced_rule_refuses_is_a_bad_request() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = permissions_base(&tenant, &environment);

    // Each of these is refused by migration 0091's `permissions_slug_valid` CHECK.
    // The management edge must report it as a caller-facing 400; without the edge
    // check it reaches the CHECK and surfaces as an opaque 500.
    //
    // The first three are the cases that ONLY the permission grammar refuses: the
    // shipped role charset accepts `billing`, `trailing.` and `double..dot`
    // outright. They are what proves this endpoint calls `require_permission_slug`
    // and not `require_slug`; every other case below would be refused by either.
    for (index, slug) in [
        "billing",
        "trailing.",
        "double..dot",
        ".leading",
        "Billing.Read",
        "billing.reaD",
        "read:orders",
        "has space.read",
        "billing.invoice/read",
        "",
    ]
    .iter()
    .enumerate()
    {
        let (status, _, response) = h
            .post(&base, &format!("k-{index}"), &create_body(slug))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "slug {slug:?}: {response}");
    }

    // An empty display name is likewise a 400, on create and on relabel.
    let (status, _, _) = h
        .post(
            &base,
            "k-blank",
            &serde_json::json!({ "slug": "billing.read", "display_name": "  " }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert!(
        list_ids(&h, &base).await.is_empty(),
        "no refused create wrote a row"
    );
    assert!(
        permission_audit(&h, &tenant, &environment).await.is_empty(),
        "no refused create wrote an audit row"
    );

    // The positive control: a namespaced slug at the far end of the same validator
    // is accepted, so the refusals above are attributable to the grammar rather than
    // to a create that never works.
    let permission = create_permission(&h, &base, "team-eu.west-1.read", "k-ok").await;
    let (status, _, _) = h
        .patch(
            &format!("{base}/{permission}"),
            &serde_json::json!({ "display_name": "" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an empty relabel is a 400");
}

#[tokio::test]
async fn a_live_slug_collides_and_a_deleted_one_is_free_again() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = permissions_base(&tenant, &environment);

    // The SAME slug in a SIBLING ENVIRONMENT of the same tenant is not a conflict at
    // all: the live uniqueness index is scoped to `(tenant, environment, kind, slug)`.
    // This is asserted first, and it is not decoration. A 409 raised across
    // environments would be a cross-environment EXISTENCE ORACLE over capability
    // names, reachable by any caller who may define a permission in one environment,
    // and it would be invisible to every other test in this file.
    let other_env = h.create_environment(&tenant, "second", "k-env-2").await;
    let other_base = permissions_base(&tenant, &other_env);
    create_permission(&h, &other_base, "billing.read", "k-other").await;

    let first = create_permission(&h, &base, "billing.read", "k-1").await;
    // A distinct second create (a different Idempotency-Key) of the same slug is the
    // documented 409. Without the handler's conflict arm the partial unique index
    // surfaces as an opaque 500 that says nothing a caller can act on.
    let (status, _, response) = h.post(&base, "k-2", &create_body("billing.read")).await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate slug: {response}");
    assert_eq!(
        list_ids(&h, &base).await,
        vec![first.clone()],
        "the refused create wrote no row"
    );

    // Deleting frees the slug, and re-using it mints a FRESH id: a deleted
    // permission is never revived, so the role grants that will hang off a
    // permission id cannot be quietly restored with it.
    let (status, _, _) = h.delete(&format!("{base}/{first}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, response) = h.post(&base, "k-3", &create_body("billing.read")).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the slug freed by the delete: {response}"
    );
    let second = id_of(&response);
    assert_ne!(second, first, "the re-created slug gets a FRESH id");
    assert_eq!(
        list_ids(&h, &base).await,
        vec![second],
        "exactly one LIVE row holds the slug"
    );
}

#[tokio::test]
async fn an_entitlement_row_reads_as_what_is_stored_and_stays_out_of_the_permission_list() {
    // `permissions.kind` is shipped headroom: migration 0091 admits `entitlement`
    // from day one and NOTHING in issue #98 writes one. The only production INSERT
    // into the table binds `PermissionEntryKind::Permission`, so no sequence of
    // requests against these five endpoints can produce a row of the other kind, and
    // hard coding `"permission"` into the view would be indistinguishable from
    // projecting the column. This test plants the row directly, exactly as the store
    // suite does, so the projection is pinned rather than merely plausible.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = permissions_base(&tenant, &environment);

    let permission = create_permission(&h, &base, "plan.enterprise", "k-perm").await;
    let entitlement = ironauth_store::PermissionId::generate(
        &ironauth_env::Env::system(),
        &scope_of(&tenant, &environment),
    )
    .to_string();
    // The SAME slug under the other kind. It is admissible precisely because `kind`
    // is part of the live uniqueness key, which is the property migration 0091's
    // header rests issue #103's "no migration needed" claim on.
    h.db()
        .execute_owner_sql(&format!(
            "INSERT INTO permissions (id, tenant_id, environment_id, kind, slug, display_name) \
             VALUES ('{entitlement}', '{tenant}', '{environment}', 'entitlement', \
                     'plan.enterprise', 'Enterprise plan')"
        ))
        .await;

    // The item read is addressed by id, which is the primary key and therefore unique
    // across kinds. It reports what is STORED.
    let (status, _, response) = h.get(&format!("{base}/{entitlement}")).await;
    assert_eq!(status, StatusCode::OK, "get the entitlement: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        value["kind"], "entitlement",
        "the view must project the stored discriminator, not assume one: {response}"
    );
    assert_eq!(value["slug"], "plan.enterprise");

    // The list serves the PERMISSION half of the vocabulary and only that half, so a
    // planted entitlement is absent from it while the permission of the same slug is
    // present.
    assert_eq!(
        list_ids(&h, &base).await,
        vec![permission.clone()],
        "the list must not carry the entitlement row"
    );
    assert_eq!(
        field(&h, &format!("{base}/{permission}"), "kind").await,
        "permission"
    );

    // Deliberately NOT asserted, and named so a reader does not mistake the silence
    // for coverage: whether the item PATCH and DELETE should refuse an entitlement.
    // Both are id-addressed and kind-blind here, exactly as the store's own update
    // and delete are, and nothing reachable in issue #98 can create the row they
    // would act on. Issue #103 owns that decision, and pinning either answer now
    // would be inventing a contract for a surface that does not exist yet.
}

// The parallel `env_one` / `env_two` names track the two environments and are
// clearer here than contrived distinct ones; the test is one indivisible proof over
// three endpoints and six id shapes, so it is not split.
#[allow(clippy::similar_names, clippy::too_many_lines)]
#[tokio::test]
async fn every_addressing_failure_is_the_uniform_not_found_byte_for_byte() {
    // The anti-oracle rule in its sharpest form. A permission slug is a capability
    // NAME, so an endpoint that answered differently for "belongs to another
    // environment" than for "never existed" would let a caller enumerate a sibling
    // environment's capabilities one id at a time. Status AND body must be identical
    // across every shape, on the read and on BOTH mutations.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    // The foreign scope differs in the ENVIRONMENT ALONE, under one tenant. A second
    // tenant would also be refused by the tenant predicate, so it would prove
    // nothing about the environment half of the fence.
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let base_one = permissions_base(&tenant, &env_one);
    let base_two = permissions_base(&tenant, &env_two);

    // A live row in env_one, so the reference reads below are not answering out of an
    // empty table, and a live row in env_two, so the foreign probe names a permission
    // that genuinely EXISTS. Probing an id nobody ever minted would pass with the
    // scope fence deleted.
    let own = create_permission(&h, &base_one, "own.read", "k-own").await;
    let foreign = create_permission(&h, &base_two, "foreign.read", "k-foreign").await;

    // A row of env_one that has been soft deleted.
    let deleted = create_permission(&h, &base_one, "gone.read", "k-gone").await;
    let (status, _, _) = h.delete(&format!("{base_one}/{deleted}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The reference: a well-formed, in-scope permission id that was never created.
    let absent = fresh_in_scope_permission(&tenant, &env_one);

    let probes = [
        ("soft-deleted", deleted.clone()),
        ("foreign environment", foreign.clone()),
        ("malformed", "prm_not-a-real-id".to_owned()),
        // Well formed and of THIS scope, but the wrong KIND of id.
        ("wrong prefix", fresh_in_scope_org(&tenant, &env_one)),
        (
            "wrong prefix, sibling family",
            format!("rol_{}", &absent[4..]),
        ),
        // A segment that is present but carries nothing addressable. Percent encoded
        // so it REACHES the handler as a one-character id, unlike the empty segment
        // below, which the router refuses before any handler runs.
        ("blank", "%20".to_owned()),
    ];

    // --- The READ. ---
    let (absent_status, _, absent_body) = h.get(&format!("{base_one}/{absent}")).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_str::<Value>(&absent_body).expect("json")["error"],
        "not_found"
    );
    for (label, probe) in &probes {
        let (status, _, body) = h.get(&format!("{base_one}/{probe}")).await;
        assert_eq!(status, absent_status, "get probe {label}: {body}");
        assert_eq!(body, absent_body, "get probe {label} body");
    }

    // --- The RELABEL. The body names a legitimate mutable field, so nothing about
    //     the request itself can be what refuses it. ---
    let (absent_status, _, absent_body) = h
        .patch(&format!("{base_one}/{absent}"), &relabel_body("Pwned"))
        .await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    for (label, probe) in &probes {
        let (status, _, body) = h
            .patch(&format!("{base_one}/{probe}"), &relabel_body("Pwned"))
            .await;
        assert_eq!(status, absent_status, "patch probe {label}: {body}");
        assert_eq!(body, absent_body, "patch probe {label} body");
    }
    // An EMPTY patch supplies no mutable field, so the store write is skipped and the
    // READ is the only guard left on that path. It must still be the uniform 404,
    // never a 200 handing back the foreign environment's permission as its body.
    let (status, _, body) = h.patch(&format!("{base_one}/{foreign}"), "{}").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-environment empty patch"
    );
    assert!(
        !body.contains(&foreign) && !body.contains("foreign.read"),
        "the refused patch must not echo the foreign permission: {body}"
    );

    // A PATCH the BODY alone would refuse must still answer on the ADDRESS when the
    // address is unreachable. This is the ordering assertion, and it is the only
    // thing that pins it: the relabel probes above carry a body every layer accepts,
    // so they pass whether the address is checked first or last. A body that names
    // the immutable slug (a 400) and a body that is not JSON at all (also a 400)
    // each become a distinguishing signal the moment validation runs before the
    // address resolves, and a caller could then separate "that permission is not
    // yours" from "that permission does not exist" by the status alone.
    for (label, probe) in probes
        .iter()
        .chain(std::iter::once(&("never created", absent.clone())))
    {
        for (shape, request) in [
            ("immutable field", r#"{"slug":"pwned.read"}"#),
            // The immutable field named with an explicit NULL. It belongs here for
            // the same reason and it is the sharper case of the two: it is refused
            // on PRESENCE alone, so the moment the body ran first it would separate
            // "not yours" from "does not exist" for a request that asks for nothing
            // at all. The address resolving first is what keeps it a 404.
            ("immutable field, null", r#"{"slug":null}"#),
            ("unparseable", "not json at all"),
        ] {
            let (status, _, body) = h.patch(&format!("{base_one}/{probe}"), request).await;
            assert_eq!(
                status, absent_status,
                "patch probe {label} with an {shape} body must answer on the address: {body}"
            );
            assert_eq!(body, absent_body, "patch probe {label}, {shape} body");
        }
    }

    // --- The DELETE. ---
    let (absent_status, _, absent_body) = h.delete(&format!("{base_one}/{absent}")).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    for (label, probe) in &probes {
        let (status, _, body) = h.delete(&format!("{base_one}/{probe}")).await;
        assert_eq!(status, absent_status, "delete probe {label}: {body}");
        assert_eq!(body, absent_body, "delete probe {label} body");
    }

    // --- The EMPTY path segment, stated separately and honestly. ---
    //
    // `.../permissions/` matches no route, so axum refuses it before any handler,
    // any scope check, and any store read run: the answer is a 404 with an EMPTY
    // body rather than this API's structured one. That is a genuine difference from
    // every probe above and it is not papered over here. It is also not an oracle,
    // and this is the assertion that proves it: the refusal is identical whichever
    // environment the path names, so it reveals only that no route exists, which is
    // true for every caller alike.
    for method in ["GET", "PATCH", "DELETE"] {
        let (one_status, one_body) = match method {
            "GET" => {
                let (s, _, b) = h.get(&format!("{base_one}/")).await;
                (s, b)
            }
            "PATCH" => {
                let (s, _, b) = h
                    .patch(&format!("{base_one}/"), &relabel_body("Pwned"))
                    .await;
                (s, b)
            }
            _ => {
                let (s, _, b) = h.delete(&format!("{base_one}/")).await;
                (s, b)
            }
        };
        let (two_status, two_body) = match method {
            "GET" => {
                let (s, _, b) = h.get(&format!("{base_two}/")).await;
                (s, b)
            }
            "PATCH" => {
                let (s, _, b) = h
                    .patch(&format!("{base_two}/"), &relabel_body("Pwned"))
                    .await;
                (s, b)
            }
            _ => {
                let (s, _, b) = h.delete(&format!("{base_two}/")).await;
                (s, b)
            }
        };
        assert_eq!(
            one_status,
            StatusCode::NOT_FOUND,
            "{method} on an empty segment is a 404: {one_body}"
        );
        assert_eq!(one_status, two_status, "{method} empty-segment status");
        assert_eq!(one_body, two_body, "{method} empty-segment body");
    }

    // Neither environment was touched by any probe. The foreign row is still live,
    // still named as it was, and still labeled as it was.
    assert_eq!(list_ids(&h, &base_one).await, vec![own]);
    assert_eq!(list_ids(&h, &base_two).await, vec![foreign.clone()]);
    let foreign_path = format!("{base_two}/{foreign}");
    assert_eq!(field(&h, &foreign_path, "slug").await, "foreign.read");
    assert_eq!(field(&h, &foreign_path, "display_name").await, "Label");
    assert!(
        permission_audit(&h, &tenant, &env_two)
            .await
            .iter()
            .all(|action| action == "permission.create"),
        "no probe wrote a mutation audit row in the foreign environment"
    );
}

#[allow(clippy::similar_names)]
#[tokio::test]
async fn an_idempotency_key_replay_is_byte_identical_and_never_crosses_a_scope_or_credential() {
    // An idempotency key is namespaced by the ACTING CREDENTIAL alone: the stored
    // rows carry no scope column, and the OPERATOR is one credential across every
    // tenant and environment. The only thing keeping one credential's stored response
    // from being served for a DIFFERENT resource is that the fingerprint covers the
    // concrete request PATH.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let base_one = permissions_base(&tenant, &env_one);
    let base_two = permissions_base(&tenant, &env_two);
    let body = create_body("billing.read");

    let (status, _, first) = h.post(&base_one, "shared-key", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let permission = id_of(&first);

    // 1. A genuine replay: byte-identical, and no second row or audit row.
    let (status, _, replay) = h.post(&base_one, "shared-key", &body).await;
    assert_eq!(status, StatusCode::CREATED, "a replay repeats the original");
    assert_eq!(first, replay, "byte-identical replay");
    assert_eq!(list_ids(&h, &base_one).await, vec![permission.clone()]);
    assert_eq!(
        permission_audit(&h, &tenant, &env_one).await,
        vec!["permission.create"],
        "the replay wrote no second audit row"
    );

    // 2. The SAME key with a DIFFERENT body is the 422 key-conflict, not a second
    //    permission and not the first one handed back.
    let (status, _, response) = h
        .post(&base_one, "shared-key", &create_body("other.read"))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
    assert_eq!(list_ids(&h, &base_one).await, vec![permission.clone()]);

    // 3. The same key and the same body in ANOTHER ENVIRONMENT, under the same
    //    operator credential. This is the case the credential-only namespace makes
    //    possible, so it is asserted directly rather than inferred.
    let (status, _, response) = h.post(&base_two, "shared-key", &body).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "cross-environment replay: {response}"
    );
    assert!(
        !response.contains(&permission),
        "the refusal must not echo environment one's permission: {response}"
    );
    assert!(
        list_ids(&h, &base_two).await.is_empty(),
        "and it created nothing in environment two"
    );

    // 4. A DIFFERENT CREDENTIAL replaying the same key against the SAME path and body
    //    EXECUTES rather than reading the operator's stored response. It reaches the
    //    store and collides with the live slug, and a 409 is only reachable from the
    //    write, so it is the proof that no replay happened.
    let key = h.create_key(&tenant, &env_one, "ci", "k-key").await;
    let (status, _, response) = h.post_as(&base_one, &key, "shared-key", &body).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "another credential executes rather than replaying: {response}"
    );
    assert_eq!(
        list_ids(&h, &base_one).await,
        vec![permission],
        "and it created no second permission"
    );
}

#[tokio::test]
async fn a_permission_list_pages_across_a_cursor_including_a_row_a_relabel_touched() {
    // The cursor key must be the SORT key. The list orders by `(created_at, id)`, so a
    // cursor built from any other timestamp column points at a position the ordering
    // does not use. The relabel below is what makes that observable: it moves ONLY
    // `updated_at`, and moves it PAST every remaining row's `created_at`, so a cursor
    // keyed on `updated_at` lands beyond the rest of the list and the walk stops two
    // rows in, returning a truncated list with no error anywhere.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = permissions_base(&tenant, &environment);

    let mut created = HashSet::new();
    let mut ordered = Vec::new();
    for index in 0..5 {
        let id = create_permission(
            &h,
            &base,
            &format!("scope{index}.read"),
            &format!("k-{index}"),
        )
        .await;
        assert!(created.insert(id.clone()), "each permission id is unique");
        ordered.push(id);
    }

    // Relabel the row that ENDS page one at limit 2, after every other row exists.
    let (status, _, response) = h
        .patch(
            &format!("{base}/{}", ordered[1]),
            &relabel_body("Relabeled"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "relabel: {response}");

    let (seen, pages) = walk_pages(&h, &base, 2).await;
    assert_eq!(
        seen, created,
        "every permission is returned exactly once across the walk"
    );
    assert_eq!(pages, 3, "5 rows at 2 per page is exactly three pages");
}

// The parallel `*_one` / `*_two` names track the two environments; the test is one
// indivisible proof over five endpoints, so it is not split.
#[allow(clippy::similar_names, clippy::too_many_lines)]
#[tokio::test]
async fn an_environment_scoped_key_reaches_only_its_own_environments_permissions() {
    // Every other test in this file drives the OPERATOR, which passes every scope
    // check by design, so those prove containment of IDS and nothing about the
    // CREDENTIAL. This one drives a real `mak_` management key, the credential class
    // whose confinement rests entirely on `Principal::require_environment` inside
    // `crate::org_context::resolve_scope`, the ONE copy of that call. Deleting it is
    // one edit, and without this test the whole admin suite stays green while a key
    // minted for environment one administers environment two.
    //
    // Each endpoint is driven TWICE with the SAME key: once inside the environment
    // the key was minted for, which must succeed, and once against a sibling
    // environment, which must be the LOUD 403. The positive half is what makes the
    // negative half attributable to the scope check alone rather than to a broken
    // credential. The two environments share a tenant, so the environment half of the
    // fence is the only thing that can be doing the work.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let base_one = permissions_base(&tenant, &env_one);
    let base_two = permissions_base(&tenant, &env_two);
    let key = h.create_key(&tenant, &env_one, "ci", "k-key").await;

    // Environment two is seeded BY THE OPERATOR, so every id-addressed probe below
    // names a row that genuinely exists there: with the scope check gone the read
    // answers 200 and the mutations execute, rather than collapsing to a 404 that
    // could be mistaken for containment.
    let seeded_two = create_permission(&h, &base_two, "seeded.read", "k-seed").await;
    let seeded_two_path = format!("{base_two}/{seeded_two}");

    // --- The key is authorized on all five endpoints INSIDE environment one. ---
    let (status, _, body) = h
        .post_as(&base_one, &key, "mk-1", &create_body("own.read"))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "own-environment create: {body}"
    );
    let own_path = format!("{base_one}/{}", id_of(&body));
    let (status, _, body) = h.get_as(&base_one, &key).await;
    assert_eq!(status, StatusCode::OK, "own-environment list: {body}");
    let (status, _, body) = h.get_as(&own_path, &key).await;
    assert_eq!(status, StatusCode::OK, "own-environment get: {body}");
    let (status, _, body) = h
        .patch_as(&own_path, &key, &relabel_body("Relabeled"))
        .await;
    assert_eq!(status, StatusCode::OK, "own-environment relabel: {body}");
    let (status, _, body) = h.delete_as(&own_path, &key).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "own-environment delete: {body}"
    );

    // --- The SAME key against environment two: the LOUD 403 on every one. ---
    let (status, _, body) = h
        .post_as(&base_two, &key, "mk-x1", &create_body("pwned.read"))
        .await;
    assert_wrong_scope("cross-environment create", status, &body);
    let (status, _, body) = h.get_as(&base_two, &key).await;
    assert_wrong_scope("cross-environment list", status, &body);
    let (status, _, body) = h.get_as(&seeded_two_path, &key).await;
    assert_wrong_scope("cross-environment get", status, &body);
    let (status, _, body) = h
        .patch_as(&seeded_two_path, &key, &relabel_body("Pwned"))
        .await;
    assert_wrong_scope("cross-environment relabel", status, &body);
    let (status, _, body) = h.delete_as(&seeded_two_path, &key).await;
    assert_wrong_scope("cross-environment delete", status, &body);

    // Environment two is exactly as the operator left it: the refused create added no
    // row, the refused delete removed none, and the refused relabel moved nothing.
    assert_eq!(
        list_ids(&h, &base_two).await,
        vec![seeded_two],
        "no refused request touched environment two"
    );
    assert_eq!(field(&h, &seeded_two_path, "display_name").await, "Label");
    assert_eq!(
        permission_audit(&h, &tenant, &env_two).await,
        vec!["permission.create"],
        "the only audited write in environment two is the operator's seed"
    );
}

#[tokio::test]
async fn a_replay_survives_the_parent_environment_going_away() {
    // The ORDERING of the two preconditions on the create path, and the only thing
    // that pins it. The Idempotency-Key replay runs BEFORE the parent-existence
    // check, so a genuine replay returns the original response even if the
    // environment was deleted in between. Moving the parent check ahead of the
    // replay would turn a retry of a request that ALREADY SUCCEEDED into a 404,
    // which is exactly the failure mode a retrying client cannot distinguish from
    // "my write never landed".
    let h = Harness::start(50).await;
    let (tenant, _environment) = tenant_env(&h).await;
    let doomed = h.create_environment(&tenant, "doomed", "k-env-2").await;
    let base = permissions_base(&tenant, &doomed);
    let body = create_body("billing.read");

    let (status, _, first) = h.post(&base, "k-replay", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    let (status, _, _) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{doomed}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the environment is deleted");

    let (status, _, replay) = h.post(&base, "k-replay", &body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a replay must survive the parent going away: {replay}"
    );
    assert_eq!(first, replay, "and it is byte-identical to the original");
}

#[tokio::test]
async fn a_define_into_an_absent_or_deleted_environment_is_the_uniform_not_found() {
    // `permissions` carries a composite foreign key to `environments`, and
    // `resolve_scope` proves only that the two path segments PARSE. Without the
    // parent-existence precondition a well-formed identifier naming an environment
    // that does not exist reaches the INSERT, violates that constraint, and comes
    // back as an opaque 500 for an input the caller fully controls. It must be the
    // same not-found a MALFORMED environment segment already gets, or the two are
    // distinguishable and one of them is a server error.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;

    // The reference: a malformed environment segment, refused by the parse alone.
    let (malformed_status, _, malformed_body) = h
        .post(
            &permissions_base(&tenant, "env_not-a-real-id"),
            "k-malformed",
            &create_body("billing.read"),
        )
        .await;
    assert_eq!(malformed_status, StatusCode::NOT_FOUND);

    // A well-formed environment id that was never created.
    let absent = ironauth_store::EnvironmentId::generate(&ironauth_env::Env::system()).to_string();
    let (status, _, body) = h
        .post(
            &permissions_base(&tenant, &absent),
            "k-absent",
            &create_body("billing.read"),
        )
        .await;
    assert_eq!(
        status, malformed_status,
        "an absent environment must not be a 500: {body}"
    );
    assert_eq!(body, malformed_body, "and it must be the SAME answer");

    // A SOFT-DELETED environment reads exactly like the absent one, even though its
    // row survives and would satisfy the foreign key.
    let doomed = h.create_environment(&tenant, "doomed", "k-env-2").await;
    create_permission(
        &h,
        &permissions_base(&tenant, &doomed),
        "before.delete",
        "k-b",
    )
    .await;
    let (status, _, _) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{doomed}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, body) = h
        .post(
            &permissions_base(&tenant, &doomed),
            "k-deleted",
            &create_body("after.delete"),
        )
        .await;
    assert_eq!(
        status, malformed_status,
        "a deleted environment is the same answer: {body}"
    );
    assert_eq!(body, malformed_body);

    // The positive control: the live environment still accepts a define, so the
    // three refusals above are attributable to the precondition and not to a create
    // that stopped working.
    create_permission(
        &h,
        &permissions_base(&tenant, &environment),
        "billing.read",
        "k-live",
    )
    .await;
}
