// SPDX-License-Identifier: MIT OR Apache-2.0

//! Project grants bounding a delegated administrator (issue #102, migration 0120).
//!
//! The B2B delegation contract: a vendor owns an application, a customer organization
//! self-administers its own users, and the vendor bounds which of that organization's
//! roles the customer's administrators may hand out.
//!
//! Four things here are easy to get wrong and each has its own test.
//!
//!   1. NO grant is not an empty grant. Absence means unrestricted, so applying 0120 to
//!      a live environment changes nothing for anybody; a grant naming no roles means
//!      assign nothing. Collapsing the two in the safe-looking direction breaks every
//!      delegated administrator at upgrade, and in the other direction makes the most
//!      restrictive contract in the model impossible to express.
//!   2. The VENDOR is not bounded by the grant they authored. Bounding the author would
//!      make a grant impossible to widen, because widening it is itself an assignment.
//!   3. BOTH assignment surfaces are bounded. Migration 0089 ships two, membership and
//!      group, and a bound on one is not a bound: roles flow DOWN the group forest, so
//!      the group path is the one that reaches more users per call.
//!   4. Withdrawing a grant stops it bounding, without walking the subset.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    ActorRef, CorrelationId, EnvironmentId, ProjectGrantId, ProjectGrantRoleId, Scope, ServiceId,
    TenantId,
};
use serde_json::Value;

// ------------------------------------------------------------- fixtures ------

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn id_of(response: &str) -> String {
    serde_json::from_str::<Value>(response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

fn org_base(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}")
}

/// Create a client through the store (there is no create endpoint) and return its id.
async fn create_client(h: &Harness, tenant: &str, environment: &str, name: &str) -> String {
    let env = Env::system();
    h.store()
        .scoped(scope_of(tenant, environment))
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, name)
        .await
        .expect("create client")
        .to_string()
}

async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    id_of(&response)
}

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

async fn create_membership(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    ident: &str,
    key: &str,
) -> String {
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": ident }).to_string();
    let (status, _, response) = h.post(&users, &format!("{key}-u"), &body).await;
    assert_eq!(status, StatusCode::CREATED, "create user: {response}");
    let user = id_of(&response);

    let base = format!("{}/memberships", org_base(tenant, environment, org));
    let body = serde_json::json!({ "user_id": user }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "add membership: {response}");
    id_of(&response)
}

async fn create_group(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    slug: &str,
    key: &str,
) -> String {
    let base = format!("{}/groups", org_base(tenant, environment, org));
    let body = serde_json::json!({ "slug": slug, "display_name": "Label" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create group: {response}");
    id_of(&response)
}

/// Mint a management key through the API and return `(key_id, secret)`.
async fn mint_key(h: &Harness, tenant: &str, environment: &str, idem: &str) -> (String, String) {
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/keys"),
            idem,
            &serde_json::json!({ "display_name": "delegated" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "mint management key: {body}");
    let created: Value = serde_json::from_str(&body).expect("json");
    (
        created["id"].as_str().expect("id").to_owned(),
        created["secret"].as_str().expect("secret").to_owned(),
    )
}

/// Confine `key_id` to one organization: this is what makes it a DELEGATED
/// administrator rather than the vendor (migration 0119).
async fn confine(h: &Harness, tenant: &str, environment: &str, key_id: &str, org: &str) {
    sqlx::query(
        "UPDATE management_credentials SET organization_id = $1 \
         WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
    )
    .bind(org)
    .bind(key_id)
    .bind(tenant)
    .bind(environment)
    .execute(h.db().owner_pool())
    .await
    .expect("write the confinement");
}

/// Create a project grant over `roles` and return its id. Written with SQL rather than
/// through an endpoint because the management surface for defining grants is not built
/// yet: this PR delivers the BOUND, which is what the acceptance criterion names.
async fn grant(
    h: &Harness,
    tenant: &str,
    environment: &str,
    client: &str,
    org: &str,
    roles: &[&str],
) -> String {
    // Real scoped ids, minted the way the write surface will mint them. A hand-rolled
    // string would parse as nothing and would make these fixtures unlike any row the
    // product can actually produce.
    let env = Env::system();
    let scope = scope_of(tenant, environment);
    let grant_id = ProjectGrantId::generate(&env, &scope).to_string();
    sqlx::query(
        "INSERT INTO project_grants (id, tenant_id, environment_id, client_id, organization_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&grant_id)
    .bind(tenant)
    .bind(environment)
    .bind(client)
    .bind(org)
    .execute(h.db().owner_pool())
    .await
    .expect("create the grant");

    for role in roles {
        sqlx::query(
            "INSERT INTO project_grant_roles \
             (id, tenant_id, environment_id, grant_id, organization_id, role_id) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(ProjectGrantRoleId::generate(&env, &scope).to_string())
        .bind(tenant)
        .bind(environment)
        .bind(&grant_id)
        .bind(org)
        .bind(role)
        .execute(h.db().owner_pool())
        .await
        .expect("grant the role");
    }
    grant_id
}

/// Assign `role` to `membership`, returning the status.
async fn assign_to_membership(h: &Harness, w: &World, role: &str, idem: &str) -> StatusCode {
    let base = format!(
        "{}/memberships/{}/roles",
        org_base(&w.tenant, &w.environment, &w.org),
        w.membership
    );
    let body = serde_json::json!({ "role_id": role }).to_string();
    h.post_as(&base, &w.secret, idem, &body).await.0
}

/// Assign `role` to `group`, returning the status.
async fn assign_to_group(h: &Harness, w: &World, role: &str, idem: &str) -> StatusCode {
    let base = format!(
        "{}/groups/{}/roles",
        org_base(&w.tenant, &w.environment, &w.org),
        w.group
    );
    let body = serde_json::json!({ "role_id": role }).to_string();
    h.post_as(&base, &w.secret, idem, &body).await.0
}

/// One organization with two roles, a membership, a group, a client, and a key confined
/// to it. Returned in the order a test reads them.
struct World {
    tenant: String,
    environment: String,
    org: String,
    client: String,
    granted: String,
    ungranted: String,
    membership: String,
    group: String,
    key_id: String,
    secret: String,
}

async fn world(h: &Harness) -> World {
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(h, &tenant, &environment, "k-org").await;
    let client = create_client(h, &tenant, &environment, "vendor-app").await;
    let granted = create_role(h, &tenant, &environment, &org, "support", "k-r1").await;
    let ungranted = create_role(h, &tenant, &environment, &org, "billing", "k-r2").await;
    let membership =
        create_membership(h, &tenant, &environment, &org, "a@example.com", "k-m").await;
    let group = create_group(h, &tenant, &environment, &org, "team", "k-g").await;
    let (key_id, secret) = mint_key(h, &tenant, &environment, "k-mint").await;
    World {
        tenant,
        environment,
        org,
        client,
        granted,
        ungranted,
        membership,
        group,
        key_id,
        secret,
    }
}

// ---------------------------------------------------------------- tests ------

/// Point 1, the upgrade-safety half. Applying 0120 changes nothing until somebody opts
/// in, so a confined administrator with NO grant assigns whatever they could before.
#[tokio::test]
async fn an_organization_under_no_grant_is_administered_exactly_as_before() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;

    let status = assign_to_membership(&h, &w, &w.ungranted, "k-a1").await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "absence of a grant means unrestricted; a delegated administrator of an \
         ungranted organization must be able to assign any of its roles, or applying \
         this migration would revoke authority that was never taken away"
    );
}

/// The criterion itself: inside the subset succeeds, outside it fails, and the refusal
/// is the typed 403 rather than a 404 or a 500.
#[tokio::test]
async fn a_grant_bounds_a_delegated_administrator_to_the_roles_it_names() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    grant(
        &h,
        &w.tenant,
        &w.environment,
        &w.client,
        &w.org,
        &[&w.granted],
    )
    .await;
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;

    let inside = assign_to_membership(&h, &w, &w.granted, "k-a2").await;
    assert_eq!(
        inside,
        StatusCode::CREATED,
        "a role the grant names must remain assignable, or the grant is a denial \
         rather than a bound"
    );

    let outside = assign_to_membership(&h, &w, &w.ungranted, "k-outside").await;
    assert_eq!(
        outside,
        StatusCode::FORBIDDEN,
        "a role outside the granted subset must be refused"
    );
}

/// Point 3. Both surfaces migration 0089 ships are bounded. The group path is the one
/// that matters more: a role assigned to a group reaches every member of it and of
/// every descendant, so a bound that covered only the membership path would leave the
/// higher-leverage escape open.
#[tokio::test]
async fn the_group_assignment_surface_is_bounded_too() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    grant(
        &h,
        &w.tenant,
        &w.environment,
        &w.client,
        &w.org,
        &[&w.granted],
    )
    .await;
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;

    let outside = assign_to_group(&h, &w, &w.ungranted, "k-g-outside").await;
    assert_eq!(
        outside,
        StatusCode::FORBIDDEN,
        "roles flow down the group forest, so an unbounded group assignment hands the \
         ungranted role to every member of the group and of its descendants at once"
    );
}

/// Point 1, the other half. A grant naming NO roles is a real contract (a customer who
/// administers membership but never roles) and is NOT the same as having no grant.
#[tokio::test]
async fn a_grant_naming_no_roles_permits_no_assignment_at_all() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    grant(&h, &w.tenant, &w.environment, &w.client, &w.org, &[]).await;
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;

    let status = assign_to_membership(&h, &w, &w.granted, "k-a2").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an empty subset must deny everything; reading it as unrestricted would make \
         the most restrictive contract in the model expressible only by DELETING the \
         grant, which is backwards"
    );
}

/// Point 2. The vendor authored the grant and is not bounded by it, or widening a grant
/// would require an authority the grant itself withholds.
#[tokio::test]
async fn the_vendor_is_not_bounded_by_the_grant_it_authored() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    grant(
        &h,
        &w.tenant,
        &w.environment,
        &w.client,
        &w.org,
        &[&w.granted],
    )
    .await;
    // Deliberately NOT confined: this is the vendor's own key.

    let status = assign_to_membership(&h, &w, &w.ungranted, "k-a1").await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "an unconfined credential is the vendor, who owns the grant; bounding it by \
         its own grant would make the contract unwidenable"
    );
}

/// Point 4. Withdrawing the grant lifts the bound immediately, without anything walking
/// the subset to soft-delete each member: the read repeats the liveness filter on the
/// grant itself.
#[tokio::test]
async fn withdrawing_a_grant_lifts_the_bound_without_touching_its_roles() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    let grant_id = grant(
        &h,
        &w.tenant,
        &w.environment,
        &w.client,
        &w.org,
        &[&w.granted],
    )
    .await;
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;

    let before = assign_to_membership(&h, &w, &w.ungranted, "k-before").await;
    assert_eq!(
        before,
        StatusCode::FORBIDDEN,
        "bounded while the grant lives"
    );

    sqlx::query("UPDATE project_grants SET deleted_at = now() WHERE id = $1")
        .bind(&grant_id)
        .execute(h.db().owner_pool())
        .await
        .expect("withdraw the grant");

    let after = assign_to_membership(&h, &w, &w.ungranted, "k-after").await;
    assert_eq!(
        after,
        StatusCode::CREATED,
        "a withdrawn grant stops bounding, and its role rows are deliberately left \
         alone: the read filters on the GRANT's liveness so withdrawal is one write"
    );
}

/// The role union filters on the GRANT's liveness, and this is the only shape in which
/// that conjunct does any work.
///
/// A mutation removing `g.deleted_at IS NULL` from the union survived every other test
/// here, because with ONE grant the existence check answers first: no live grant means
/// unrestricted and the union never runs. It takes an organization holding TWO grants,
/// one live and one withdrawn, for the union to be reached while a dead grant's roles
/// are still sitting in the subset table. Then a withdrawn grant would keep making its
/// roles assignable, which is the bug: withdrawal is a single write on the grant and it
/// deliberately does NOT walk the subset.
#[tokio::test]
async fn a_withdrawn_grant_stops_contributing_while_a_live_one_remains() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    let withdrawn = grant(
        &h,
        &w.tenant,
        &w.environment,
        &w.client,
        &w.org,
        &[&w.ungranted],
    )
    .await;
    // A SECOND client, because at most one LIVE grant may exist per (client,
    // organization) pair and both of these are live until the first is withdrawn.
    let other = create_client(&h, &w.tenant, &w.environment, "second-app").await;
    grant(&h, &w.tenant, &w.environment, &other, &w.org, &[&w.granted]).await;
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;

    sqlx::query("UPDATE project_grants SET deleted_at = now() WHERE id = $1")
        .bind(&withdrawn)
        .execute(h.db().owner_pool())
        .await
        .expect("withdraw the first grant");

    // The live grant keeps the organization bounded, so the union IS reached.
    let still_granted = assign_to_membership(&h, &w, &w.granted, "k-two-live").await;
    assert_eq!(
        still_granted,
        StatusCode::CREATED,
        "the surviving grant must still make its own roles assignable"
    );

    let from_dead_grant = assign_to_membership(&h, &w, &w.ungranted, "k-two-dead").await;
    assert_eq!(
        from_dead_grant,
        StatusCode::FORBIDDEN,
        "a WITHDRAWN grant must stop contributing its roles even while another grant \
         keeps the organization bounded; otherwise withdrawal silently does nothing \
         unless it happens to be the last grant"
    );
}

// ------------------------------------------------- the management surface ------

/// The `.../project-grants` collection path.
fn grants_base(w: &World) -> String {
    format!(
        "{}/project-grants",
        org_base(&w.tenant, &w.environment, &w.org)
    )
}

/// Create a grant over the HTTP surface, returning `(status, body)`.
async fn create_grant_api(
    h: &Harness,
    w: &World,
    secret: &str,
    idem: &str,
    roles: &[&str],
) -> (StatusCode, String) {
    let body = serde_json::json!({ "client_id": w.client, "role_ids": roles }).to_string();
    let (status, _, response) = h.post_as(&grants_base(w), secret, idem, &body).await;
    (status, response)
}

/// The round trip: create through the API, and the bound it declares is the bound the
/// assignment path actually enforces. A grant that lists correctly but does not bind
/// would be the dormant-layer defect this project keeps producing.
#[tokio::test]
async fn a_grant_created_through_the_api_lists_and_binds() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    let (vendor_id, vendor) = mint_key(&h, &w.tenant, &w.environment, "k-vendor").await;
    let _ = vendor_id;

    let (status, body) = create_grant_api(&h, &w, &vendor, "k-c1", &[&w.granted]).await;
    assert_eq!(status, StatusCode::CREATED, "create the grant: {body}");

    let (status, _, listed) = h.get_as(&grants_base(&w), &vendor).await;
    assert_eq!(status, StatusCode::OK, "list the grants: {listed}");
    assert!(
        listed.contains(&w.granted),
        "the created grant must list its role subset: {listed}"
    );
    assert!(
        !listed.contains(&w.ungranted),
        "listing must not report a role the grant never named: {listed}"
    );

    // The bound is REAL, not merely recorded.
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;
    assert_eq!(
        assign_to_membership(&h, &w, &w.ungranted, "k-c1-deny").await,
        StatusCode::FORBIDDEN,
        "a grant created through the API must bind the assignment path"
    );
}

/// THE privilege-escalation fence, and the reason it is on confinement rather than on a
/// permission.
///
/// A confined credential holding `write_organizations` can already reach its OWN
/// organization: `resolve_live_org` is built to let it. If grant management were governed
/// by the permission alone, that credential could WITHDRAW the grant that bounds it and,
/// because absence of a grant means unrestricted, silently become able to assign every
/// role in its organization. The bound would be editable by the party it exists to bind.
#[tokio::test]
async fn a_confined_credential_cannot_touch_the_grant_that_bounds_it() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    let (_vendor_id, vendor) = mint_key(&h, &w.tenant, &w.environment, "k-vendor").await;

    let (status, body) = create_grant_api(&h, &w, &vendor, "k-c2", &[&w.granted]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "vendor creates the grant: {body}"
    );
    let grant_id = id_of(&body);

    // Now confine the OTHER key to that organization: it is the bound party.
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;

    let (status, _, denied) = h
        .post_as(
            &grants_base(&w),
            &w.secret,
            "k-c2-create",
            &serde_json::json!({ "client_id": w.client, "role_ids": [w.ungranted] }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a confined credential CREATED a grant, so it can widen its own authority: {denied}"
    );

    let (status, _, denied) = h
        .delete_as(&format!("{}/{grant_id}", grants_base(&w)), &w.secret)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a confined credential WITHDREW the grant that bounds it, which makes it \
         unrestricted: {denied}"
    );

    // And the bound still holds afterwards, which is the property the two refusals exist
    // to protect. Asserting the refusals alone would not prove the grant survived.
    assert_eq!(
        assign_to_membership(&h, &w, &w.ungranted, "k-c2-after").await,
        StatusCode::FORBIDDEN,
        "the grant must still bind after both attempts to remove it"
    );
}

/// Same-organization containment. `org_roles` carries its own `organization_id` and the
/// foreign key only proves a role EXISTS, so without an explicit check a grant could name
/// a SIBLING organization's role and make it assignable to people who were never in it.
#[tokio::test]
async fn a_grant_cannot_name_a_sibling_organizations_role() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    let (_vendor_id, vendor) = mint_key(&h, &w.tenant, &w.environment, "k-vendor").await;

    let sibling = create_org(&h, &w.tenant, &w.environment, "k-sib-org").await;
    let foreign = create_role(
        &h,
        &w.tenant,
        &w.environment,
        &sibling,
        "support",
        "k-sib-r",
    )
    .await;

    let (status, body) = create_grant_api(&h, &w, &vendor, "k-c3", &[&foreign]).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a grant naming another organization's role must be refused as the uniform \
         not-found, not created: {body}"
    );
}

/// Withdrawing through the API lifts the bound, which is the whole point of the endpoint
/// and is also the dangerous direction: it WIDENS authority.
#[tokio::test]
async fn withdrawing_through_the_api_lifts_the_bound() {
    let h = Harness::start(50).await;
    let w = world(&h).await;
    let (_vendor_id, vendor) = mint_key(&h, &w.tenant, &w.environment, "k-vendor").await;

    let (status, body) = create_grant_api(&h, &w, &vendor, "k-c4", &[&w.granted]).await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let grant_id = id_of(&body);
    confine(&h, &w.tenant, &w.environment, &w.key_id, &w.org).await;
    assert_eq!(
        assign_to_membership(&h, &w, &w.ungranted, "k-c4-before").await,
        StatusCode::FORBIDDEN,
        "bounded while the grant lives"
    );

    let (status, _, body) = h
        .delete_as(&format!("{}/{grant_id}", grants_base(&w)), &vendor)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "withdraw: {body}");

    assert_eq!(
        assign_to_membership(&h, &w, &w.ungranted, "k-c4-after").await,
        StatusCode::CREATED,
        "withdrawal must lift the bound"
    );
}
