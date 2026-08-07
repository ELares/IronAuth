// SPDX-License-Identifier: MIT OR Apache-2.0

//! Delegated administration confines at ALL THREE levels, and every delegated mutation is
//! attributable (issue #102, acceptance criteria 4 and 5).
//!
//! The three levels are not one mechanism with three settings, which is why this file
//! drives all of them rather than trusting that one implies the others:
//!
//!   * TENANT and ENVIRONMENT come from the credential's own `Scope`. A management key
//!     declares its scope in the clear in its id half, and `require_environment` refuses a
//!     request addressed anywhere else. That refusal is the LOUD 403, deliberately: a key
//!     naming a scope it does not hold is a misconfiguration the operator must see, not a
//!     resource that might or might not exist.
//!   * ORGANIZATION comes from confinement (migration 0119) and answers the uniform 404
//!     instead. The asymmetry is the point and is asserted here rather than assumed:
//!     answering 403 for a sibling organization would confirm that organization EXISTS,
//!     turning a denied call into an enumeration oracle over the environment's
//!     organizations. A wrong SCOPE is not an oracle in the same way, because the caller
//!     already knows the scope it asked for.
//!
//! Criterion 5 is the other half: a delegated mutation must be attributable. The audit
//! stream is `audit_log`, which carries actor, scope and target as columns. The actor is
//! NOT the key id, and assuming it was is how the first draft of this file failed against
//! a correct system: `AdminState` derives a stable `ServiceId` from the credential's
//! unique bytes, so the row carries `svc_<derived>`. What is asserted is therefore the
//! property that derivation exists to provide, that two administrators are TELLABLE
//! APART, rather than the spelling of the value.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

// ------------------------------------------------------------- fixtures ------

/// Mint a management key in `(tenant, environment)` and return `(key_id, secret)`.
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

/// Confine `key_id` to one organization.
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

/// Create an organization and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, idem: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, idem, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

// ---------------------------------------------------------------- tests ------

/// Level 1 and 2: the credential's own scope. A key minted in one environment cannot
/// reach a sibling environment of the SAME tenant.
#[tokio::test]
async fn an_environment_scoped_key_cannot_reach_a_sibling_environment() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;

    // A SECOND environment under the same tenant.
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments"),
            "k-env-two",
            &serde_json::json!({ "display_name": "Staging", "kind": "staging" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create the sibling: {body}");
    let sibling = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // The key works in its OWN environment. The control, without which the refusal
    // below could be any unrelated failure.
    let (status, _, body) = h
        .get_as(
            &format!("/v1/tenants/{tenant}/environments/{environment}/users"),
            &secret,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the key's own environment: {body}");

    let (status, _, body) = h
        .get_as(
            &format!("/v1/tenants/{tenant}/environments/{sibling}/users"),
            &secret,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an environment-scoped key reached a SIBLING environment of its own tenant: {body}"
    );
}

/// Level 1: the tenant. A key from one tenant cannot reach another tenant's environment,
/// which is a different failure from the sibling-environment case above because BOTH path
/// segments differ.
#[tokio::test]
async fn an_environment_scoped_key_cannot_reach_another_tenant() {
    let h = Harness::start(50).await;
    let (tenant_one, environment_one) = h.create_tenant("acme", "k-t1").await;
    let (tenant_two, environment_two) = h.create_tenant("globex", "k-t2").await;
    let (_id, secret) = mint_key(&h, &tenant_one, &environment_one, "k-mint").await;

    let (status, _, body) = h
        .get_as(
            &format!("/v1/tenants/{tenant_two}/environments/{environment_two}/users"),
            &secret,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key minted under one tenant reached ANOTHER tenant: {body}"
    );
}

/// Level 3: the organization, and the deliberately DIFFERENT status. A confined key
/// answers the uniform not-found for a sibling organization, because a 403 would confirm
/// that organization exists and let a confined caller enumerate the environment.
#[tokio::test]
async fn a_confined_key_answers_not_found_for_a_sibling_organization() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "k-org-mine").await;
    let theirs = create_org(&h, &tenant, &environment, "k-org-theirs").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;
    confine(&h, &tenant, &environment, &key_id, &mine).await;

    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");

    // Its OWN organization is reachable: the control.
    let (status, _, body) = h.get_as(&format!("{base}/{mine}"), &secret).await;
    assert_eq!(status, StatusCode::OK, "its own organization: {body}");

    let (status, _, body) = h.get_as(&format!("{base}/{theirs}"), &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a confined key must answer NOT-FOUND for a sibling organization, or comparing \
         403 against 404 enumerates the environment's organizations: {body}"
    );
}

/// The audit actor of the row that created `target`, with its scope.
async fn actor_of(
    h: &Harness,
    tenant: &str,
    environment: &str,
    target: &str,
) -> (String, String, String) {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT actor_id::text, tenant_id::text, environment_id::text FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(tenant)
    .bind(environment)
    .bind(target)
    .fetch_optional(h.db().owner_pool())
    .await
    .expect("read the audit stream");
    row.expect("the delegated write left an audit row")
}
async fn write_user(h: &Harness, users: &str, secret: &str, idem: &str, who: &str) -> String {
    let (status, _, body) = h
        .post_as(
            users,
            secret,
            idem,
            &serde_json::json!({ "identifier": format!("{who}@example.test") }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "the delegated write: {body}");
    serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Criterion 5: a delegated mutation is attributable to the CREDENTIAL that made it.
///
/// What "attributable" means here, measured rather than assumed. The audit actor is NOT
/// the key id: `AdminState` derives a stable `ServiceId` from the credential's unique
/// bytes, so the row carries `svc_<derived>`. A first draft of this test asserted the key
/// id appeared literally and failed against a system that is in fact correct.
///
/// The property that matters is the one the audit stream exists to answer once
/// administration is delegated: WHICH administrator did this. So this drives two
/// different confined credentials and requires their audit actors to DIFFER, and each
/// credential's own actor to be stable across its writes. A derivation that collapsed
/// every key onto one platform actor would satisfy a substring check and fail this.
#[tokio::test]
async fn delegated_mutations_are_attributable_to_the_credential_that_made_them() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;

    let (first_id, first) = mint_key(&h, &tenant, &environment, "k-mint-1").await;
    let (second_id, second) = mint_key(&h, &tenant, &environment, "k-mint-2").await;
    confine(&h, &tenant, &environment, &first_id, &org).await;
    confine(&h, &tenant, &environment, &second_id, &org).await;

    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");

    let a1 = write_user(&h, &users, &first, "k-w-a1", "a1").await;
    let a2 = write_user(&h, &users, &first, "k-w-a2", "a2").await;
    let b1 = write_user(&h, &users, &second, "k-w-b1", "b1").await;

    let (first_actor, audited_tenant, audited_environment) =
        actor_of(&h, &tenant, &environment, &a1).await;
    let (first_actor_again, _, _) = actor_of(&h, &tenant, &environment, &a2).await;
    let (second_actor, _, _) = actor_of(&h, &tenant, &environment, &b1).await;

    // SCOPE, the second third of the criterion.
    assert_eq!(audited_tenant, tenant, "the audit row carries its tenant");
    assert_eq!(
        audited_environment, environment,
        "the audit row carries its environment"
    );

    // ACTOR: stable per credential, and distinct BETWEEN credentials.
    assert_eq!(
        first_actor, first_actor_again,
        "one credential's writes must carry ONE actor, or the stream cannot group an \
         administrator's actions"
    );
    assert_ne!(
        first_actor, second_actor,
        "two different delegated credentials produced the SAME audit actor, so the \
         stream cannot answer which administrator did it, which is the only question it \
         exists for once administration is delegated"
    );
}

/// Criterion 2 says a confined administrator cannot LIST sibling organizations, and the
/// list is the half that the per-resource 404 cannot cover.
///
/// Answering the uniform not-found on a sibling READ exists so that a confined caller
/// cannot learn whether that organization exists. An unfiltered LIST hands over every
/// organization's id and display name in one call, which makes the read fence decorative:
/// the enumeration it prevents is available one endpoint over.
#[tokio::test]
async fn a_confined_credential_lists_only_its_own_organization() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "k-org-mine").await;
    let theirs = create_org(&h, &tenant, &environment, "k-org-theirs").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;
    confine(&h, &tenant, &environment, &key_id, &mine).await;

    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let (status, _, body) = h.get_as(&base, &secret).await;
    assert_eq!(status, StatusCode::OK, "the confined list: {body}");

    assert!(
        body.contains(&mine),
        "a confined credential must still see its OWN organization: {body}"
    );
    assert!(
        !body.contains(&theirs),
        "a confined credential ENUMERATED a sibling organization through the list, so \
         the uniform not-found on the individual read is decoration: the id and display \
         name it hides are available one endpoint over. Body: {body}"
    );
}

/// The control for the narrowing above. An UNCONFINED credential still lists every
/// organization, and a confined one whose organization is gone gets an empty page rather
/// than a not-found.
///
/// Without this, the narrowing could be implemented as "return nothing" and the test
/// above would still pass.
#[tokio::test]
async fn the_narrowing_applies_only_to_a_confined_credential() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let first = create_org(&h, &tenant, &environment, "k-org-1").await;
    let second = create_org(&h, &tenant, &environment, "k-org-2").await;
    let (_id, unconfined) = mint_key(&h, &tenant, &environment, "k-mint").await;

    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let (status, _, body) = h.get_as(&base, &unconfined).await;
    assert_eq!(status, StatusCode::OK, "the unconfined list: {body}");
    assert!(
        body.contains(&first) && body.contains(&second),
        "an unconfined credential must still see EVERY organization, or the confinement \
         narrowing has leaked into the vendor's own view: {body}"
    );

    // A confined credential whose organization is disabled still gets a page, not a 404:
    // the collection is reachable, and the honest answer is that it administers nothing.
    let (key_id, confined) = mint_key(&h, &tenant, &environment, "k-mint-2").await;
    confine(&h, &tenant, &environment, &key_id, &first).await;
    let (status, _, body) = h
        .post_as(
            &format!("{base}/{first}/disable"),
            &unconfined,
            "k-disable",
            "{}",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "disable the organization: {body}");

    let (status, _, body) = h.get_as(&base, &confined).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a confined credential whose organization is not live must still get a PAGE: \
         the collection is reachable and the answer is that it administers nothing. \
         Body: {body}"
    );
    assert!(
        !body.contains(&second),
        "even with its own organization gone, a confined credential must not see a \
         sibling: {body}"
    );
}
