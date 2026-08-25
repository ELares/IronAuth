// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin session privilege separation (sudo mode) over HTTP (issue #73).
//!
//! The lifecycle (elevate, act, expire, challenge, re-elevate), the acceptance-critical
//! STOLEN-COOKIE adversarial case (a valid credential whose recorded elevation is stale
//! or absent cannot mutate, and no client-supplied header can forge freshness, while
//! reads still work), the inert-when-off posture, and the elevation/expiry audit trail.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, bearer};
use ironauth_store::{EnvironmentId, Scope, TenantId};

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn revoke_path(tenant: &str, environment: &str, session: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/sessions/{session}/revoke")
}

fn elevate_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/admin/sudo/elevate")
}

fn snapshot_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/config/snapshot")
}

fn plan_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/config/promotion/plan")
}

fn apply_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/config/promotion/apply")
}

fn invitations_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/invitations")
}

fn dcr_policies_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/dcr/policies")
}

fn locale_path(tenant: &str, environment: &str, locale: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/locales/{locale}")
}

fn signup_form_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/signup-form")
}

fn trait_schemas_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/trait-schemas")
}

fn brand_path(tenant: &str, environment: &str, slug: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/brands/{slug}")
}

fn organizations_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations")
}

fn org_roles_path(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/roles")
}

fn org_groups_path(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/groups")
}

fn permissions_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/permissions")
}

fn org_role_permissions_path(tenant: &str, environment: &str, org: &str, role: &str) -> String {
    format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/roles/{role}/permissions"
    )
}

fn org_default_role_path(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/default-role")
}

/// The resource-server registry base path (issue #98, PR 11).
fn resource_servers_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/resource-servers")
}

/// The per-client scope-allowlist path (issue #98, PR 15).
fn allowed_scopes_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/clients/{client}/allowed-scopes")
}

/// The `id` of a JSON response body.
fn id_of(response: &str) -> String {
    serde_json::from_str::<serde_json::Value>(response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Create a role or group (both take the same two required fields), asserting a 201,
/// and return its id. Used only inside an open elevation window.
async fn create_named(harness: &Harness, base: &str, slug: &str, key: &str) -> String {
    let body = serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string();
    let (status, _, response) = harness.post(base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create {slug}: {response}");
    id_of(&response)
}

async fn audit_actions(harness: &Harness, scope: Scope) -> Vec<String> {
    harness
        .control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .collect()
}

/// The full sudo lifecycle: a mutation is challenged until a fresh elevation is
/// recorded, succeeds while the window holds, is challenged again once it lapses, and
/// succeeds after a re-elevation.
#[tokio::test]
async fn sudo_lifecycle_elevate_act_expire_challenge_reelevate() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let elevate = elevate_path(&tenant, &env);

    // A seeded session, and a mutation attempted WITHOUT a fresh elevation: the RFC 9470
    // challenge, and the session is untouched (nothing executed).
    let s1 = harness.seed_session(scope, &subject).await;
    let (status, headers, body) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "stale mutation is challenged: {body}"
    );
    assert!(
        body.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {body}"
    );
    let www = headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        www.contains("insufficient_user_authentication") && www.contains("max_age=600"),
        "the WWW-Authenticate header carries the challenge and max_age: {www}"
    );
    assert!(
        harness.session_resolves(scope, &s1).await,
        "the challenged revoke executed nothing"
    );

    // Elevate, then the same class of mutation succeeds.
    let (status, _, body) = harness.post(&elevate, "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    assert!(body.contains("\"elevated\":true"), "elevate body: {body}");

    let (status, _, body) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r2", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "elevated revoke succeeds: {body}");
    assert!(
        !harness.session_resolves(scope, &s1).await,
        "the elevated revoke executed"
    );

    // Advance the clock past the window: the elevation lapses.
    clock.advance(Duration::from_secs(601));

    let s2 = harness.seed_session(scope, &subject).await;
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s2.to_string()), "r3", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the lapsed window challenges again"
    );
    assert!(
        harness.session_resolves(scope, &s2).await,
        "the challenged revoke executed nothing after expiry"
    );

    // Re-elevate: the mutation succeeds again.
    let (status, _, _) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s2.to_string()), "r4", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "the re-elevated revoke succeeds");
    assert!(!harness.session_resolves(scope, &s2).await);
}

/// A locale bundle write rewrites the plain text of the auth pages (login, recovery, error
/// copy), a social engineering surface, so it is sudo gated exactly like the other environment
/// scoped management mutations (issue #86 PR 2): challenged without a fresh elevation, and it
/// succeeds after one.
#[tokio::test]
async fn a_locale_write_is_sudo_gated() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = locale_path(&tenant, &env, "fr");
    let body = format!(
        "{{\"entries\":{{\"{}\":\"Se connecter\"}}}}",
        ironauth_oidc::flow::message::LOGIN_TITLE.0
    );

    // Without a fresh elevation the write is challenged and nothing is stored.
    let (status, _, challenge) = harness.put(&path, &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale locale write is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );

    // After elevation the same write succeeds.
    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, stored) = harness.put(&path, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated locale write succeeds: {stored}"
    );
    assert!(
        stored.contains("Se connecter"),
        "the write persisted: {stored}"
    );
}

/// A signup form write is sudo-gated exactly like the other environment-scoped config writes
/// (issue #87): a stale write is challenged and stored nothing; the same write succeeds after a
/// fresh elevation.
#[tokio::test]
async fn a_signup_form_write_is_sudo_gated() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = signup_form_path(&tenant, &env, &client);
    // An empty form needs no active trait schema, so this isolates the sudo gate.
    let body = "{\"fields\":[]}";

    // Without a fresh elevation the write is challenged and nothing is stored.
    let (status, _, challenge) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale signup form write is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );

    // After elevation the same write succeeds.
    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, stored) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated signup form write succeeds: {stored}"
    );
    assert!(stored.contains(&client), "the write persisted: {stored}");
}

/// The organization ROLE and GROUP mutations (issue #97, PR 4) are sudo gated exactly
/// like every other environment-scoped mutator. Five route entries carry SEVEN mutating
/// handlers (role create, rename, delete; group create, rename, reparent, delete), so
/// there are seven `require_fresh_privilege` call sites, and every one is challenged
/// here with the elevation window lapsed, writes nothing, and succeeds after a fresh
/// elevation. Without this row a refactor could drop the gate from `delete_org_role` and
/// let the stolen-cookie case this file calls acceptance-critical delete an
/// organization's roles with no re-authentication, with CI still green.
///
/// One test rather than five: the challenged half and the elevated half have to run
/// against the SAME seeded rows for "wrote nothing" to mean anything.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn an_org_role_or_group_write_is_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let elevate = elevate_path(&tenant, &env);

    // The fixture itself needs an open window: creating the organization is a gated
    // mutation too. Seed inside one, then let it lapse so the probes below run against
    // the exact state the gate is supposed to protect.
    let (status, _, body) = harness.post(&elevate, "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    let (status, _, response) = harness
        .post(
            &organizations_path(&tenant, &env),
            "org-1",
            &serde_json::json!({ "display_name": "Globex" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    let org = id_of(&response);
    let roles = org_roles_path(&tenant, &env, &org);
    let groups = org_groups_path(&tenant, &env, &org);
    let role = create_named(&harness, &roles, "seeded", "r-seed").await;
    let group = create_named(&harness, &groups, "seeded", "g-seed").await;
    let sibling = create_named(&harness, &groups, "sibling", "g-sib").await;
    let role_path = format!("{roles}/{role}");
    let group_path = format!("{groups}/{group}");

    clock.advance(Duration::from_secs(601));

    let create_body = serde_json::json!({ "slug": "fresh", "display_name": "Label" }).to_string();
    let rename_body = serde_json::json!({ "display_name": "Pwned" }).to_string();
    let reparent_body = serde_json::json!({ "parent_id": sibling }).to_string();

    // --- With the window lapsed, every mutating endpoint is challenged. ---
    for (label, path, key, body) in [
        ("create_org_role", roles.clone(), "r-1", create_body.clone()),
        (
            "create_org_group",
            groups.clone(),
            "g-1",
            create_body.clone(),
        ),
    ] {
        let (status, _, resp) = harness.post(&path, key, &body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} is challenged without an elevation: {resp}"
        );
        assert!(
            resp.contains("insufficient_user_authentication"),
            "{label} carries the RFC 9470 challenge: {resp}"
        );
    }
    for (label, path, body) in [
        ("update_org_role", role_path.clone(), rename_body.clone()),
        ("update_org_group", group_path.clone(), rename_body.clone()),
    ] {
        let (status, _, resp) = harness.patch(&path, &body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} is challenged without an elevation: {resp}"
        );
        assert!(
            resp.contains("insufficient_user_authentication"),
            "{label} carries the RFC 9470 challenge: {resp}"
        );
    }
    let (status, _, resp) = harness
        .put(&format!("{group_path}/parent"), &reparent_body)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "set_org_group_parent is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");
    for (label, path) in [
        ("delete_org_role", role_path.clone()),
        ("delete_org_group", group_path.clone()),
    ] {
        let (status, _, resp) = harness.delete(&path).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} is challenged without an elevation: {resp}"
        );
        assert!(
            resp.contains("insufficient_user_authentication"),
            "{label} carries the RFC 9470 challenge: {resp}"
        );
    }

    // Nothing executed: no row was added, none removed, none renamed, none moved.
    // Reads are ungated, so this is observable without elevating first.
    let (_, _, listed_roles) = harness.get(&roles).await;
    assert_eq!(
        item_count(&listed_roles),
        1,
        "the challenged role create and delete wrote nothing: {listed_roles}"
    );
    let (_, _, listed_groups) = harness.get(&groups).await;
    assert_eq!(
        item_count(&listed_groups),
        2,
        "the challenged group create and delete wrote nothing: {listed_groups}"
    );
    let (_, _, stored_role) = harness.get(&role_path).await;
    assert!(
        stored_role.contains("\"display_name\":\"Label\""),
        "the challenged role rename wrote nothing: {stored_role}"
    );
    let (_, _, stored_group) = harness.get(&group_path).await;
    assert!(
        stored_group.contains("\"display_name\":\"Label\""),
        "the challenged group rename wrote nothing: {stored_group}"
    );
    assert!(
        stored_group.contains("\"parent_id\":null"),
        "the challenged reparent left the group a root: {stored_group}"
    );

    // --- After a fresh elevation, every one of the same requests succeeds. ---
    let (status, _, body) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK, "re-elevate: {body}");

    let (status, _, resp) = harness.post(&roles, "r-2", &create_body).await;
    assert_eq!(status, StatusCode::CREATED, "elevated role create: {resp}");
    let (status, _, resp) = harness.post(&groups, "g-2", &create_body).await;
    assert_eq!(status, StatusCode::CREATED, "elevated group create: {resp}");
    let (status, _, resp) = harness.patch(&role_path, &rename_body).await;
    assert_eq!(status, StatusCode::OK, "elevated role rename: {resp}");
    let (status, _, resp) = harness.patch(&group_path, &rename_body).await;
    assert_eq!(status, StatusCode::OK, "elevated group rename: {resp}");
    let (status, _, resp) = harness
        .put(&format!("{group_path}/parent"), &reparent_body)
        .await;
    assert_eq!(status, StatusCode::OK, "elevated group reparent: {resp}");
    let (status, _, resp) = harness.delete(&group_path).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "elevated group delete: {resp}"
    );
    let (status, _, resp) = harness.delete(&role_path).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "elevated role delete: {resp}"
    );
}

/// The permission VOCABULARY mutations (issue #98, PR 7) are sudo gated exactly like
/// every other environment-scoped mutator. Two route entries carry THREE mutating
/// handlers (define, relabel, delete), so there are three `require_fresh_privilege`
/// call sites, and every one is challenged here with the elevation window lapsed,
/// writes nothing, and succeeds after a fresh elevation. Without this row a refactor
/// could drop the gate from `delete_permission` and let the stolen-cookie case this
/// file calls acceptance-critical destroy an environment's capability names with no
/// re-authentication, with CI still green.
///
/// The two READS (list and get) are deliberately NOT gated and are exercised below
/// with the window lapsed, because sudo gates mutations only; asserting that keeps a
/// future "gate everything" refactor from silently breaking the console's ability to
/// show an operator what they are about to change. They are also what makes "wrote
/// nothing" observable without elevating first.
///
/// One test rather than three: the challenged half and the elevated half have to run
/// against the SAME seeded rows for "wrote nothing" to mean anything.
#[tokio::test]
async fn a_permission_vocabulary_write_is_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let elevate = elevate_path(&tenant, &env);
    let base = permissions_path(&tenant, &env);

    // Seed inside an open window (defining a permission is itself a gated mutation),
    // then let it lapse so the probes below run against the exact state the gate is
    // supposed to protect.
    let (status, _, body) = harness.post(&elevate, "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    let seed_body =
        serde_json::json!({ "slug": "seeded.read", "display_name": "Label" }).to_string();
    let (status, _, response) = harness.post(&base, "p-seed", &seed_body).await;
    assert_eq!(status, StatusCode::CREATED, "seed permission: {response}");
    let permission = id_of(&response);
    let path = format!("{base}/{permission}");

    clock.advance(Duration::from_secs(601));

    let create_body =
        serde_json::json!({ "slug": "fresh.read", "display_name": "Label" }).to_string();
    let relabel_body = serde_json::json!({ "display_name": "Pwned" }).to_string();

    // --- With the window lapsed, every mutating endpoint is challenged. ---
    let (status, _, resp) = harness.post(&base, "p-1", &create_body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "create_permission is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");
    let (status, _, resp) = harness.patch(&path, &relabel_body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "update_permission is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");
    let (status, _, resp) = harness.delete(&path).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "delete_permission is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");

    // Nothing executed: no row was added, none removed, none relabeled. Reads are
    // ungated, so this is observable without elevating first.
    let (status, _, listed) = harness.get(&base).await;
    assert_eq!(status, StatusCode::OK, "the list is ungated: {listed}");
    assert_eq!(
        item_count(&listed),
        1,
        "the challenged create and delete wrote nothing: {listed}"
    );
    let (status, _, stored) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "the get is ungated: {stored}");
    assert!(
        stored.contains("\"display_name\":\"Label\""),
        "the challenged relabel wrote nothing: {stored}"
    );

    // --- After a fresh elevation, every one of the same requests succeeds. ---
    let (status, _, body) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK, "re-elevate: {body}");

    let (status, _, resp) = harness.post(&base, "p-2", &create_body).await;
    assert_eq!(status, StatusCode::CREATED, "elevated create: {resp}");
    let (status, _, resp) = harness.patch(&path, &relabel_body).await;
    assert_eq!(status, StatusCode::OK, "elevated relabel: {resp}");
    let (status, _, resp) = harness.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "elevated delete: {resp}");
}

/// The role-to-permission MAPPING and the organization DEFAULT-ROLE mutations (issue
/// #98, PR 8) are sudo gated exactly like every other organization-nested mutator.
/// Three route entries carry FOUR mutating handlers (attach, detach, designate,
/// clear), so there are four `require_fresh_privilege` call sites, and every one is
/// challenged here with the elevation window lapsed, writes nothing, and succeeds
/// after a fresh elevation. Each is dropped INDIVIDUALLY: without a per-handler probe
/// a refactor could take the gate off `clear_org_default_role` alone and let the
/// stolen-cookie case this file calls acceptance-critical take a role away from every
/// member of an organization at once with no re-authentication, with CI still green.
///
/// The READS are deliberately NOT gated and are exercised below with the window
/// lapsed, because sudo gates mutations only. They are also what makes "wrote nothing"
/// observable without elevating first, which is why the designation is asserted
/// through the ungated role list rather than through a second write.
///
/// One test rather than four: the challenged half and the elevated half have to run
/// against the SAME seeded rows for "wrote nothing" to mean anything.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn an_org_role_permission_or_default_role_write_is_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let elevate = elevate_path(&tenant, &env);

    // Seed inside an open window (every one of these is itself a gated mutation),
    // then let it lapse so the probes below run against the exact state the gate is
    // supposed to protect.
    let (status, _, body) = harness.post(&elevate, "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    let (status, _, response) = harness
        .post(
            &organizations_path(&tenant, &env),
            "o-seed",
            &serde_json::json!({ "display_name": "Globex" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed org: {response}");
    let org = id_of(&response);
    let roles = org_roles_path(&tenant, &env, &org);
    let role = create_named(&harness, &roles, "billing.admin", "r-seed").await;
    let permissions = permissions_path(&tenant, &env);
    let (status, _, response) = harness
        .post(
            &permissions,
            "p-seed",
            &serde_json::json!({ "slug": "billing.invoice.read", "display_name": "Label" })
                .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed permission: {response}");
    let seeded_permission = id_of(&response);
    let (status, _, response) = harness
        .post(
            &permissions,
            "p-seed-2",
            &serde_json::json!({ "slug": "billing.invoice.write", "display_name": "Label" })
                .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed permission 2: {response}");
    let fresh_permission = id_of(&response);
    let mappings = org_role_permissions_path(&tenant, &env, &org, &role);
    let (status, _, response) = harness
        .post(
            &mappings,
            "m-seed",
            &serde_json::json!({ "permission_id": seeded_permission }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed mapping: {response}");
    let default_role = org_default_role_path(&tenant, &env, &org);
    let (status, _, response) = harness
        .put(
            &default_role,
            &serde_json::json!({ "role_id": role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed the designation: {response}");

    clock.advance(Duration::from_secs(601));

    let attach = serde_json::json!({ "permission_id": fresh_permission }).to_string();
    let designate = serde_json::json!({ "role_id": role }).to_string();

    // --- With the window lapsed, every mutating endpoint is challenged. ---
    let (status, _, resp) = harness.post(&mappings, "m-1", &attach).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "assign_org_role_permission is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");
    let (status, _, resp) = harness
        .delete(&format!("{mappings}/{seeded_permission}"))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unassign_org_role_permission is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");
    let (status, _, resp) = harness.put(&default_role, &designate).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "set_org_default_role is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");
    let (status, _, resp) = harness.delete(&default_role).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "clear_org_default_role is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");

    // Nothing executed: no mapping was added or removed, and the designation still
    // stands. Reads are ungated, so this is observable without elevating first.
    let (status, _, listed) = harness.get(&mappings).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the mapping list is ungated: {listed}"
    );
    assert_eq!(
        item_count(&listed),
        1,
        "the challenged attach and detach wrote nothing: {listed}"
    );
    assert!(
        listed.contains(&seeded_permission) && !listed.contains(&fresh_permission),
        "and the surviving mapping is the seeded one: {listed}"
    );
    let (status, _, roles_listed) = harness.get(&roles).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the role list is ungated: {roles_listed}"
    );
    assert!(
        roles_listed.contains("\"is_default\":true"),
        "the challenged clear did not remove the designation: {roles_listed}"
    );

    // --- After a fresh elevation, every one of the same requests succeeds. ---
    let (status, _, body) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK, "re-elevate: {body}");

    let (status, _, resp) = harness.post(&mappings, "m-2", &attach).await;
    assert_eq!(status, StatusCode::CREATED, "elevated attach: {resp}");
    let (status, _, resp) = harness
        .delete(&format!("{mappings}/{seeded_permission}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "elevated detach: {resp}");
    let (status, _, resp) = harness.put(&default_role, &designate).await;
    assert_eq!(status, StatusCode::OK, "elevated designate: {resp}");
    let (status, _, resp) = harness.delete(&default_role).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "elevated clear: {resp}");
}

/// The organization group-MEMBER and role-ASSIGNMENT mutations (issue #97, PR 5) are
/// sudo gated exactly like the role and group mutations above. Six route entries carry
/// six mutating handlers (bind a member and unbind one; grant a role to a group and
/// withdraw it; grant a role to a membership and withdraw it), so there are six
/// `require_fresh_privilege` call sites, and every one is challenged here with the
/// elevation window lapsed, writes nothing, and succeeds after a fresh elevation.
///
/// This is the surface where the gate matters MOST, and the reason is worth stating: a
/// role create is inert until it is assigned, whereas one call here is what actually
/// grants privilege to a person. A stolen console cookie that could reach these six
/// endpoints could add itself to a group that grants administrator and be done, with no
/// re-authentication anywhere in the sequence.
///
/// The four READS on this surface (three lists and the effective-role view) are
/// deliberately NOT gated and are exercised below with the window lapsed, because sudo
/// gates mutations only; asserting that keeps a future "gate everything" refactor from
/// silently breaking the console's ability to show an operator what they are about to
/// change.
///
/// One test rather than six: the challenged half and the elevated half have to run
/// against the SAME seeded rows for "wrote nothing" to mean anything.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn an_org_member_or_assignment_write_is_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let elevate = elevate_path(&tenant, &env);

    // Seed inside an open window (every fixture write is itself a gated mutation),
    // then let it lapse so the probes below run against the exact state the gate is
    // supposed to protect.
    let (status, _, body) = harness.post(&elevate, "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    let (status, _, response) = harness
        .post(
            &organizations_path(&tenant, &env),
            "org-1",
            &serde_json::json!({ "display_name": "Globex" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    let org = id_of(&response);
    let org_base = format!("/v1/tenants/{tenant}/environments/{env}/organizations/{org}");
    let group = create_named(
        &harness,
        &org_groups_path(&tenant, &env, &org),
        "team",
        "g-1",
    )
    .await;
    let role = create_named(
        &harness,
        &org_roles_path(&tenant, &env, &org),
        "admin",
        "r-1",
    )
    .await;
    let spare = create_named(
        &harness,
        &org_roles_path(&tenant, &env, &org),
        "spare",
        "r-2",
    )
    .await;

    let (status, _, response) = harness
        .post(
            &format!("/v1/tenants/{tenant}/environments/{env}/users"),
            "u-1",
            &serde_json::json!({ "identifier": "member@x.test" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {response}");
    let user = id_of(&response);
    let (status, _, response) = harness
        .post(
            &format!("{org_base}/memberships"),
            "m-1",
            &serde_json::json!({ "user_id": user }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "add membership: {response}");
    let membership = id_of(&response);

    let members = format!("{org_base}/groups/{group}/members");
    let group_roles = format!("{org_base}/groups/{group}/roles");
    let membership_roles = format!("{org_base}/memberships/{membership}/roles");
    let effective = format!("{org_base}/memberships/{membership}/effective-roles");

    // Seed ONE row on each surface, so the three DELETE probes below address a row
    // that genuinely exists: with the gate gone they would remove it, rather than
    // 404ing for an unrelated reason.
    let (status, _, response) = harness
        .post(
            &members,
            "b-1",
            &serde_json::json!({ "membership_id": membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed binding: {response}");
    let (status, _, response) = harness
        .post(
            &group_roles,
            "gr-1",
            &serde_json::json!({ "role_id": role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed group grant: {response}");
    let (status, _, response) = harness
        .post(
            &membership_roles,
            "mr-1",
            &serde_json::json!({ "role_id": role }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed direct grant: {response}");

    clock.advance(Duration::from_secs(601));

    // --- With the window lapsed, every mutating endpoint is challenged. ---
    for (label, path, key, body) in [
        (
            "add_org_group_member",
            members.clone(),
            "b-2",
            serde_json::json!({ "membership_id": membership }).to_string(),
        ),
        (
            "assign_org_group_role",
            group_roles.clone(),
            "gr-2",
            serde_json::json!({ "role_id": spare }).to_string(),
        ),
        (
            "assign_org_membership_role",
            membership_roles.clone(),
            "mr-2",
            serde_json::json!({ "role_id": spare }).to_string(),
        ),
    ] {
        let (status, _, resp) = harness.post(&path, key, &body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} is challenged without an elevation: {resp}"
        );
        assert!(
            resp.contains("insufficient_user_authentication"),
            "{label} carries the RFC 9470 challenge: {resp}"
        );
    }
    for (label, path) in [
        ("remove_org_group_member", format!("{members}/{membership}")),
        ("unassign_org_group_role", format!("{group_roles}/{role}")),
        (
            "unassign_org_membership_role",
            format!("{membership_roles}/{role}"),
        ),
    ] {
        let (status, _, resp) = harness.delete(&path).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} is challenged without an elevation: {resp}"
        );
        assert!(
            resp.contains("insufficient_user_authentication"),
            "{label} carries the RFC 9470 challenge: {resp}"
        );
    }

    // Nothing executed. Reads are ungated, so this is observable without elevating,
    // which is itself the assertion that the four reads stayed open.
    for (label, path, expected) in [
        ("group members", members.clone(), 1),
        ("group roles", group_roles.clone(), 1),
        ("membership roles", membership_roles.clone(), 1),
    ] {
        let (status, _, listed) = harness.get(&path).await;
        assert_eq!(status, StatusCode::OK, "{label} read is ungated: {listed}");
        assert_eq!(
            item_count(&listed),
            expected,
            "{label}: the challenged write and delete changed nothing: {listed}"
        );
    }
    let (status, _, resolved) = harness.get(&effective).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the effective-role view is an ungated read: {resolved}"
    );
    assert!(
        resolved.contains("\"direct\"") && resolved.contains("\"group\""),
        "and the member still resolves both seeded grants: {resolved}"
    );

    // --- After a fresh elevation, every one of the same requests succeeds. ---
    let (status, _, body) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK, "re-elevate: {body}");

    let (status, _, resp) = harness
        .post(
            &group_roles,
            "gr-3",
            &serde_json::json!({ "role_id": spare }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "elevated group grant: {resp}");
    let (status, _, resp) = harness
        .post(
            &membership_roles,
            "mr-3",
            &serde_json::json!({ "role_id": spare }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "elevated direct grant: {resp}");
    let (status, _, resp) = harness.delete(&format!("{membership_roles}/{role}")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "elevated direct unassign: {resp}"
    );
    let (status, _, resp) = harness.delete(&format!("{group_roles}/{role}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "elevated unassign: {resp}");
    let (status, _, resp) = harness.delete(&format!("{members}/{membership}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "elevated remove: {resp}");
    let (status, _, resp) = harness
        .post(
            &members,
            "b-3",
            &serde_json::json!({ "membership_id": membership }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "elevated add: {resp}");
}

/// The resource-server permission-claim OPT-IN (issue #98, PR 11) is sudo gated.
///
/// It is the one mutating handler that surface adds, and it is worth its own probe
/// rather than a line in another test: the column it writes decides whether tokens
/// minted for a registered audience may carry permission claims, so a stolen console
/// cookie that could flip it without re-authentication would widen what an entire
/// audience's tokens assert.
///
/// The scope is narrower than
/// `a_stale_credential_cannot_mutate_but_can_read_and_no_header_forges_elevation`
/// below, which is this file's designated acceptance-critical case: this test sends
/// no forged header and uses no stale credential, it only lets the window lapse. The
/// forging half is that test's business and is not re-proved here.
///
/// The resource server is seeded through the STORE rather than through the API,
/// because issue #98 adds no create endpoint, so unlike the sibling tests here the
/// seed does not itself need an open elevation window.
///
/// The two READS are deliberately NOT gated and are exercised with the window lapsed,
/// which is also what makes "wrote nothing" observable without elevating first.
#[tokio::test]
async fn a_resource_server_opt_in_write_is_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let elevate = elevate_path(&tenant, &env);
    let base = resource_servers_path(&tenant, &env);

    let system = ironauth_env::Env::system();
    let scope = scope_of(&tenant, &env);
    let id = ironauth_store::ResourceServerId::generate(&system, &scope);
    harness
        .control_store()
        .scoped(scope)
        .acting(
            harness.test_actor(&system),
            ironauth_store::CorrelationId::generate(&system),
        )
        .resource_servers()
        .register(
            &system,
            ironauth_store::NewResourceServer {
                id: &id,
                audience: "https://api.example.test/billing",
                token_format: ironauth_store::TokenFormat::AtJwt,
                access_token_ttl_secs: None,
            },
        )
        .await
        .expect("seed the resource server");
    let path = format!("{base}/{id}");
    let opt_in = serde_json::json!({ "permission_claims_enabled": true }).to_string();

    clock.advance(Duration::from_secs(601));

    // --- With the window lapsed, the one mutating endpoint is challenged. ---
    let (status, _, resp) = harness.patch(&path, &opt_in).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "updateResourceServerPermissionClaims is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");

    // Nothing executed. The reads are ungated, so this is observable without
    // elevating first, and the assertion is on the FLAG rather than on the row's
    // existence: this table has no soft delete, so a leaked write changes one boolean
    // in place and leaves the row perfectly readable.
    let (status, _, listed) = harness.get(&base).await;
    assert_eq!(status, StatusCode::OK, "the list is ungated: {listed}");
    let (status, _, stored) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "the get is ungated: {stored}");
    assert!(
        stored.contains("\"permission_claims_enabled\":false"),
        "the challenged opt-in wrote nothing: {stored}"
    );
    // And it is unattributed in the audit log too, which is the half the state read
    // above cannot see: a refused mutation must leave no trace suggesting it ran.
    // Only the seed registration is present.
    assert_eq!(
        opt_in_audit(&harness, scope).await,
        vec!["resource_server.register"],
        "a challenged opt-in must write no audit row"
    );

    // --- After a fresh elevation, the same request succeeds. ---
    let (status, _, body) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK, "re-elevate: {body}");
    let (status, _, resp) = harness.patch(&path, &opt_in).await;
    assert_eq!(status, StatusCode::OK, "elevated opt-in: {resp}");
    assert!(
        resp.contains("\"permission_claims_enabled\":true"),
        "the elevated opt-in landed: {resp}"
    );
    // The ELEVATED write does audit, so the assertion above is a real absence rather
    // than an action this suite can never observe.
    assert_eq!(
        opt_in_audit(&harness, scope).await,
        vec![
            "resource_server.permission_claims.set",
            "resource_server.register"
        ],
        "the elevated opt-in is audited"
    );
}

/// The per-client SCOPE ALLOWLIST write (issue #98, PR 15) is sudo gated.
///
/// It is the one mutating handler that surface adds, and it deserves its own probe
/// for the same reason the resource-server opt-in above does, in the opposite
/// direction: a stolen console cookie that could write an allowlist without
/// re-authentication would cut a machine client down to whatever scopes the attacker
/// named, breaking every token it issues, or (on a client already restricted) widen
/// it. Both directions are damage and neither should be reachable without a fresh
/// elevation.
///
/// The scope is narrower than
/// `a_stale_credential_cannot_mutate_but_can_read_and_no_header_forges_elevation`:
/// this test sends no forged header and uses no stale credential, it only lets the
/// window lapse.
///
/// The client is seeded through the STORE, because the management contract documents
/// no client create, so unlike the sibling tests here the seed needs no open window.
///
/// The READ is deliberately NOT gated and is exercised with the window lapsed, which
/// is also what makes "wrote nothing" observable without elevating first.
#[tokio::test]
async fn a_client_scope_allowlist_write_is_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let elevate = elevate_path(&tenant, &env);

    let system = ironauth_env::Env::system();
    let scope = scope_of(&tenant, &env);
    let client = harness
        .store()
        .scoped(scope)
        .acting(
            harness.test_actor(&system),
            ironauth_store::CorrelationId::generate(&system),
        )
        .clients()
        .create(&system, "acme worker")
        .await
        .expect("seed the client");
    let path = allowed_scopes_path(&tenant, &env, &client.to_string());
    let body = serde_json::json!({ "allowed_scopes": ["read:orders"] }).to_string();

    clock.advance(Duration::from_secs(601));

    // --- With the window lapsed, the write is challenged. ---
    let (status, _, resp) = harness.put(&path, &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "setClientAllowedScopes is challenged without an elevation: {resp}"
    );
    assert!(resp.contains("insufficient_user_authentication"), "{resp}");

    // Nothing executed. The read is ungated, so this is observable without elevating
    // first, and it asserts on the VALUE: `clients` has no soft delete, so a leaked
    // write changes one column in place and leaves the row perfectly readable.
    let (status, _, stored) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "the get is ungated: {stored}");
    assert!(
        stored.contains("\"allowed_scopes\":null"),
        "the challenged write stored nothing: {stored}"
    );
    // And it is unattributed in the audit log too, which is the half the state read
    // cannot see: a refused mutation must leave no trace suggesting it ran.
    assert_eq!(
        allowed_scopes_audit(&harness, scope).await,
        Vec::<String>::new(),
        "a challenged allowlist write must write no audit row"
    );

    // --- After a fresh elevation, the same request succeeds. ---
    let (status, _, resp) = harness.post(&elevate, "e2", "{}").await;
    assert_eq!(status, StatusCode::OK, "re-elevate: {resp}");
    let (status, _, resp) = harness.put(&path, &body).await;
    assert_eq!(status, StatusCode::OK, "elevated write: {resp}");
    assert!(
        resp.contains("read:orders"),
        "the elevated write landed: {resp}"
    );
    // The ELEVATED write does audit, so the assertion above is a real absence rather
    // than an action this suite can never observe.
    assert_eq!(
        allowed_scopes_audit(&harness, scope).await,
        vec!["client.allowed_scopes.set"],
        "the elevated write is audited"
    );
}

/// Every `client.allowed_scopes.*` audit action recorded in `scope`, sorted.
async fn allowed_scopes_audit(harness: &Harness, scope: Scope) -> Vec<String> {
    let mut actions: Vec<String> = audit_actions(harness, scope)
        .await
        .into_iter()
        .filter(|action| action.starts_with("client.allowed_scopes."))
        .collect();
    actions.sort();
    actions
}

/// Every `resource_server.*` audit action recorded in `scope`, sorted: the audit
/// MULTISET, so an extra row is as visible as a missing one.
async fn opt_in_audit(harness: &Harness, scope: Scope) -> Vec<String> {
    let mut actions: Vec<String> = audit_actions(harness, scope)
        .await
        .into_iter()
        .filter(|action| action.starts_with("resource_server."))
        .collect();
    actions.sort();
    actions
}

/// The acceptance-critical adversarial case: a valid credential whose recorded elevation
/// is stale or absent CANNOT mutate once the window lapses, and NO client-supplied
/// header can forge the elevation (it derives only from a server-recorded event), while
/// reads are unaffected.
#[tokio::test]
async fn a_stale_credential_cannot_mutate_but_can_read_and_no_header_forges_elevation() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let s1 = harness.seed_session(scope, &subject).await;

    // Reads are unaffected by the flag: the operator can list sessions.
    let (status, _, _) = harness
        .get(&format!("/v1/tenants/{tenant}/environments/{env}/sessions"))
        .await;
    assert_eq!(status, StatusCode::OK, "reads work without an elevation");

    // A mutation with a valid credential but no recorded elevation: challenged.
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no elevation, no mutation"
    );
    assert!(harness.session_resolves(scope, &s1).await);

    // A forged freshness claim in the request (a client-asserted header AND body field)
    // does NOTHING: the elevation is server-side only, so the mutation is still refused
    // and the session is untouched.
    let forged = Request::builder()
        .method("POST")
        .uri(revoke_path(&tenant, &env, &s1.to_string()))
        .header(header::AUTHORIZATION, bearer(common::OPERATOR_TOKEN))
        .header("idempotency-key", "r2")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-privileged", "true")
        .header("x-auth-time", "9999999999999999")
        .header("x-sudo", "1")
        .body(Body::from(
            "{\"elevated\":true,\"acr\":\"urn:ironauth:acr:mfa\"}",
        ))
        .expect("request builds");
    let (status, _, body) = harness.send(forged).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a client-asserted elevation is ignored: {body}"
    );
    assert!(
        harness.session_resolves(scope, &s1).await,
        "the forged-header mutation executed nothing"
    );
}

/// With the flag off (the default), the admin surface behaves exactly as before: a
/// mutation succeeds with no elevation, and the elevate endpoint is a uniform not-found.
#[tokio::test]
async fn sudo_mode_off_by_default_is_fully_inert() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let s1 = harness.seed_session(scope, &subject).await;

    // A mutation succeeds with no elevation (no freshness gate).
    let (status, _, body) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "no gate when the flag is off: {body}"
    );
    assert!(!harness.session_resolves(scope, &s1).await);

    // The elevate endpoint is a uniform not-found when sudo mode is disabled.
    let (status, _, _) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "elevate is inert when off");
}

/// Elevation and expiry (challenge) events are audited (issue #73).
#[tokio::test]
async fn elevation_and_expiry_are_audited() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let subject = Harness::fresh_user_id(scope).to_string();
    let s1 = harness.seed_session(scope, &subject).await;

    // A challenged mutation writes the expiry/challenge audit event.
    let (status, _, _) = harness
        .post(&revoke_path(&tenant, &env, &s1.to_string()), "r1", "{}")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // An elevation writes the elevation audit event.
    let (status, _, _) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK);

    let actions = audit_actions(&harness, scope).await;
    assert!(
        actions.iter().any(|a| a == "admin.privilege.challenged"),
        "the challenge (expiry) event is audited: {actions:?}"
    );
    assert!(
        actions.iter().any(|a| a == "admin.privilege.elevated"),
        "the elevation event is audited: {actions:?}"
    );
}

/// Count the items in a management list response body.
fn item_count(body: &str) -> usize {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("list json");
    parsed["items"].as_array().map_or(0, Vec::len)
}

/// Build a valid, no-op config-promotion apply body for `(tenant, env)`: export the
/// current snapshot, plan it (a dry run, ungated) to capture the `base_revision`, and
/// pair the two. Applying it is a genuine no-op the sudo gate must still guard.
async fn noop_apply_body(harness: &Harness, tenant: &str, env: &str) -> String {
    let (status, _, snapshot) = harness.get(&snapshot_path(tenant, env)).await;
    assert_eq!(status, StatusCode::OK, "export snapshot: {snapshot}");
    let (status, _, plan) = harness
        .post(&plan_path(tenant, env), "plan-1", &snapshot)
        .await;
    assert_eq!(status, StatusCode::OK, "plan (dry run, ungated): {plan}");
    let plan_json: serde_json::Value = serde_json::from_str(&plan).expect("plan json");
    let base_revision = plan_json["base_revision"]
        .as_str()
        .expect("base_revision")
        .to_owned();
    let source: serde_json::Value = serde_json::from_str(&snapshot).expect("snapshot json");
    serde_json::json!({ "source": source, "base_revision": base_revision }).to_string()
}

/// The sudo gate covers the WHOLE environment-scoped mutation surface, not just the
/// sessions example: the config-promotion apply flagship, invitation creation, and DCR
/// policy creation are all challenged without a fresh elevation (writing nothing) and
/// succeed after one. This is the MEDIUM-1 coverage guarantee (issue #73): the gate is
/// on every environment-scoped audited mutator, including the highest-risk apply.
#[tokio::test]
async fn sudo_gate_covers_apply_promotion_invitations_and_dcr() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);

    let apply_body = noop_apply_body(&harness, &tenant, &env).await;
    let invitation_body = serde_json::json!({ "identifier": "ada@example.test" }).to_string();
    let policy_body = serde_json::json!({
        "name": "force-private-key-jwt",
        "primitives": [{
            "kind": "force",
            "property": "token_endpoint_auth_method",
            "value": "private_key_jwt"
        }]
    })
    .to_string();

    // --- Without a fresh elevation, every one of these environment-scoped mutators is
    // challenged with the RFC 9470 401 and writes NOTHING. ---
    for (label, path, key, body) in [
        (
            "apply_config_promotion",
            apply_path(&tenant, &env),
            "apply-1",
            apply_body.clone(),
        ),
        (
            "create_invitation",
            invitations_path(&tenant, &env),
            "inv-1",
            invitation_body.clone(),
        ),
        (
            "create_dcr_policy",
            dcr_policies_path(&tenant, &env),
            "pol-1",
            policy_body.clone(),
        ),
    ] {
        let (status, _, resp) = harness.post(&path, key, &body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label} is challenged without an elevation: {resp}"
        );
        assert!(
            resp.contains("insufficient_user_authentication"),
            "{label} carries the RFC 9470 challenge: {resp}"
        );
    }

    // Nothing was written: no invitation, no policy exists.
    let (_, _, invitations) = harness.get(&invitations_path(&tenant, &env)).await;
    assert_eq!(
        item_count(&invitations),
        0,
        "the challenged create_invitation wrote nothing: {invitations}"
    );
    let (_, _, policies) = harness.get(&dcr_policies_path(&tenant, &env)).await;
    assert_eq!(
        item_count(&policies),
        0,
        "the challenged create_dcr_policy wrote nothing: {policies}"
    );
    // The challenge (expiry) event is audited for these attempts.
    let actions = audit_actions(&harness, scope).await;
    assert!(
        actions.iter().any(|a| a == "admin.privilege.challenged"),
        "a challenged env-scoped mutator is audited: {actions:?}"
    );

    // --- After a fresh elevation, each mutator succeeds. ---
    let (status, _, body) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");

    let (status, _, resp) = harness
        .post(&apply_path(&tenant, &env), "apply-2", &apply_body)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "elevated apply_config_promotion succeeds (no-op): {resp}"
    );
    assert!(
        resp.contains("no_op"),
        "the elevated apply is the expected no-op: {resp}"
    );

    let (status, _, resp) = harness
        .post(&invitations_path(&tenant, &env), "inv-2", &invitation_body)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "elevated create_invitation succeeds: {resp}"
    );

    let (status, _, resp) = harness
        .post(&dcr_policies_path(&tenant, &env), "pol-2", &policy_body)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "elevated create_dcr_policy succeeds: {resp}"
    );
}

/// A brand write is SUDO-gated on BOTH mutating verbs, and the read is NOT.
///
/// The gate was wired on `PUT` and `DELETE` and nothing measured it, so removing either
/// `require_fresh_privilege` call would have left CI green. A brand is the visible chrome of the
/// auth pages, so rewriting one (or deleting it, which drops the environment back to the neutral
/// default) is a social-engineering surface and demands fresh privilege exactly as the locale
/// writes and the brand asset uploads do. The ungated `GET` is the control at the other end: it
/// shows the gate is on the MUTATIONS rather than on the route prefix.
#[tokio::test]
async fn a_brand_write_is_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = brand_path(&tenant, &env, "acme");
    let body = r#"{"product_name":"Acme"}"#;

    // Without a fresh elevation the write is challenged and NOTHING is stored.
    let (status, _, challenge) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale brand write is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the challenged write executed nothing"
    );

    // After elevation the same write succeeds.
    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, stored) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated brand write succeeds: {stored}"
    );

    // The READ is ungated: it works with the same credential either side of the window.
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "reading a brand needs no elevation");

    // DELETE is gated on the SAME elevation, measured by letting the window lapse: the brand
    // exists, the credential is unchanged, and only the freshness has gone.
    clock.advance(Duration::from_secs(601));
    let (status, _, challenge) = harness.delete(&path).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the lapsed window challenges the delete: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "{challenge}"
    );
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the challenged delete executed nothing"
    );

    // Re-elevate and the delete lands, which rules out "the delete was refused for some other
    // reason".
    let (status, _, _) = harness.post(&elevate_path(&tenant, &env), "e2", "{}").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = harness.delete(&path).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the re-elevated delete lands"
    );
}

/// The two trait-schema MUTATIONS (issue #53) are sudo gated exactly like every other
/// environment-scoped config write. Which schema an environment serves decides what every
/// identity write is validated against and which of its fields are admin-only, so a stolen
/// cookie that could append and activate a version could redefine the visibility split
/// itself; that is at least as security-relevant as a journey artifact.
///
/// ONE test rather than two, and in this order on purpose: the create must be challenged
/// FIRST and prove it stored nothing, because if it had stored a version the activate half
/// would be testing a different tree than the one the create half left behind.
#[tokio::test]
async fn the_trait_schema_create_and_activate_are_sudo_gated() {
    let (harness, clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = trait_schemas_path(&tenant, &env);
    let body = r#"{"schema":{"type":"object","properties":{"nickname":{"type":"string"}}}}"#;

    // CREATE, with the elevation window lapsed: challenged, and the registry stays empty.
    let (status, _, challenge) = harness.post(&path, "c1", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale trait-schema create is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );
    let (status, _, empty) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {empty}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&empty)
            .expect("json")
            .as_array()
            .expect("array")
            .len(),
        0,
        "the challenged create stored nothing: {empty}"
    );

    // Elevate once, and the SAME create succeeds.
    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, created) = harness.post(&path, "c2", body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated create succeeds: {created}"
    );
    assert!(
        created.contains("\"version\":1"),
        "the write persisted: {created}"
    );

    // Let the elevation lapse again and prove the ACTIVATE carries its own gate rather
    // than riding on the create's. Without this half, dropping
    // `require_fresh_privilege` from the activate handler alone would stay green.
    clock.advance(Duration::from_secs(601));
    let activate = format!("{path}/1/activate");
    let (status, _, challenge) = harness.post(&activate, "a1", "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale trait-schema activate is challenged: {challenge}"
    );
    let (status, _, still) = harness.get(&format!("{path}/1")).await;
    assert_eq!(status, StatusCode::OK, "{still}");
    assert!(
        still.contains("\"active\":false"),
        "the challenged activate moved nothing: {still}"
    );

    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e2", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, activated) = harness.post(&activate, "a2", "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated activate succeeds: {activated}"
    );
    assert!(
        activated.contains("\"active\":true"),
        "the activation landed: {activated}"
    );
}

/// Elevating to sudo announces it, over the real route, carrying the window and the acr.
///
/// A management credential just gained the authority the freshness gate otherwise refuses:
/// a privilege escalation by design, and what an oversight consumer watches for.
///
/// The EXPIRY is the load-bearing field. An elevation is a WINDOW, not a state, so a receiver
/// that could not see the window would have to treat every elevation as permanent -- and the
/// whole point of sudo mode is that the authority lapses. The test asserts the announced
/// expiry agrees with the window the response reports, so a producer that shipped a
/// plausible-looking constant instead of the real one fails here.
#[tokio::test]
async fn elevating_to_sudo_announces_the_elevation_with_its_window() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k-sudo-evt").await;
    let scope = scope_of(&tenant, &env);

    // Anything the fixture's own provisioning enqueued, discarded.
    let _ = queued_events(&harness, scope).await;

    let (status, _, body) = harness
        .post(&elevate_path(&tenant, &env), "e-evt", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    let expires_micros = view["expires_at_unix_micros"].as_i64().expect("expiry");

    let events = queued_events(&harness, scope).await;
    assert_eq!(events.len(), 1, "the elevation announced {events:?}");
    assert_eq!(events[0]["type"], "sudo.elevated");
    assert_eq!(
        events[0]["payload"]["acr"], view["acr"],
        "the announced acr must be what the re-authentication actually proved"
    );
    assert_eq!(
        events[0]["payload"]["expires_at_unix_ms"],
        expires_micros / 1000,
        "the announced window must be the window the elevation actually got; a constant \
         here would look right and expire at the wrong time for every consumer"
    );
    assert!(
        events[0]["payload"]["actor_id"]
            .as_str()
            .is_some_and(|actor| !actor.is_empty()),
        "the elevation must say WHO gained the authority: {events:?}"
    );
}

/// Everything queued for the webhook fan-out in this scope, claimed and completed.
async fn queued_events(harness: &Harness, scope: Scope) -> Vec<serde_json::Value> {
    let env = ironauth_env::Env::system();
    let claimed = harness
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events");
    for message in &claimed {
        harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .complete(&env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().map(|message| message.payload).collect()
}

/// Publishing a usage snapshot is sudo gated (issues #73, #107).
///
/// The guard was added in the same round that added the endpoint, and nothing measured it:
/// `Harness::start` uses `AdminConfig::default()`, where sudo mode is off, so deleting
/// `require_fresh_privilege` from `publish_usage` left the whole `usage_export` suite green.
/// This file is where that measurement lives, and the route was not in it.
///
/// Both halves, as every test in this file has: without a fresh elevation the publish is
/// challenged and NOTHING is appended, and after elevation the same call succeeds. Asserting
/// only the challenge would also pass against an endpoint that refused everyone.
#[tokio::test]
async fn a_usage_publish_is_sudo_gated() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k-usage-sudo").await;
    let path = format!("/v1/tenants/{tenant}/environments/{env}/usage/publish");

    let (status, _, challenge) = harness.post(&path, "k-sudo-stale", "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the stale publish is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );

    // Nothing was appended by the challenged call. A challenge that still published would
    // be the worst of both, and this endpoint's output is a billing record.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = 'usage.reported'",
    )
    .bind(&tenant)
    .bind(&env)
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count");
    assert_eq!(count, 0, "a challenged publish must announce nothing");

    let (status, _, elevated) = harness
        .post(&elevate_path(&tenant, &env), "e-usage", "{}")
        .await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, published) = harness.post(&path, "k-sudo-fresh", "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the elevated publish succeeds: {published}"
    );
}

/// A message resend is sudo-gated, like every other environment-scoped mutation (issue #111).
///
/// THE GATE THIS TEST EXISTS FOR. `resend_message` shipped without `require_fresh_privilege`,
/// and what a resend re-delivers is a CREDENTIAL: the original payload, which for an
/// `email_otp` carries the code and for a magic link the token. So with sudo armed, a stale
/// credential could not change a translation string but could re-mail a live one-time secret.
///
/// The challenge must fire BEFORE the endpoint looks at anything: a stale request must not
/// discover whether the message exists, and must not write.
#[tokio::test]
async fn a_message_resend_is_sudo_gated() {
    let (harness, _clock) = Harness::start_with_sudo(600).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    // The identifier names no row, deliberately: a gated request is refused before it is
    // parsed, so the challenge below cannot be the endpoint merely failing to find it.
    let path = format!("/v1/tenants/{tenant}/environments/{env}/messages/msg_absent/resend");

    let (status, _, challenge) = harness.post(&path, "r1", "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a stale resend is challenged: {challenge}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "the challenge body carries the RFC 9470 error: {challenge}"
    );

    // After elevation the same request reaches the handler, which then reports the absent
    // message. 401 -> 404 is the transition that shows the gate opened rather than the route
    // answering the same way for a different reason.
    let (status, _, elevated) = harness.post(&elevate_path(&tenant, &env), "e1", "{}").await;
    assert_eq!(status, StatusCode::OK, "elevate: {elevated}");
    let (status, _, body) = harness.post(&path, "r2", "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the elevated resend reaches the handler: {body}"
    );
}
