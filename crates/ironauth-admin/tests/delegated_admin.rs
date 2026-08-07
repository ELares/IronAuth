// SPDX-License-Identifier: MIT OR Apache-2.0

//! A RESTRICTED management credential is refused what it was not granted (issue #102).
//!
//! The unit tests on `require_permission` prove the decision, and the store test proves the
//! grant survives the authentication read. This proves the two are actually connected over
//! HTTP, which is the part neither of them can show: a seam that decides correctly and a
//! column that reads correctly still add up to nothing if no handler calls the seam.

mod common;

use axum::http::StatusCode;
use common::{Harness, OPERATOR_TOKEN};
use serde_json::Value;

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

/// Restrict `key_id` to exactly `slugs`.
async fn restrict(h: &Harness, tenant: &str, environment: &str, key_id: &str, slugs: &[&str]) {
    sqlx::query(
        "UPDATE management_credentials SET permissions = $1 \
         WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
    )
    .bind(
        slugs
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<String>>(),
    )
    .bind(key_id)
    .bind(tenant)
    .bind(environment)
    .execute(h.db().owner_pool())
    .await
    .expect("write the grant");
}

#[tokio::test]
async fn a_read_only_credential_lists_users_and_cannot_create_one() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;

    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");

    // UNRESTRICTED first. This is the control: every credential minted before migration 0118
    // is unrestricted, and if this failed the feature would be an upgrade outage rather than
    // a permission system.
    let (status, _, body) = h.get_as(&users, &secret).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unrestricted key was refused a read: {body}"
    );

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    // The granted operation still works.
    let (status, _, body) = h.get_as(&users, &secret).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a read-granted key was refused the read it holds: {body}"
    );

    // The ungranted one is refused, and with the 403 rather than a 404: this is an
    // authorization decision about a credential, not a claim that the route is absent.
    let (status, _, body) = h
        .post_as(
            &users,
            &secret,
            "k-denied",
            &serde_json::json!({ "identifier": "denied@example.test" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential CREATED a user: the grant is stored and read but no handler \
         consults it, which is the exact shape this issue exists to close. Body: {body}"
    );
    assert!(
        body.contains("management.write_users"),
        "the refusal does not name the permission that was required: {body}"
    );

    // And the OPERATOR is unaffected: permissions restrict management keys, not the operator
    // plane, which has no grant model.
    let (status, _, body) = h
        .post(
            &users,
            "k-operator",
            &serde_json::json!({ "identifier": "operator@example.test" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the operator was caught by a management-key restriction: {body}"
    );
    let _ = OPERATOR_TOKEN;
}

#[tokio::test]
async fn a_user_granted_credential_cannot_touch_organizations() {
    // The two write permissions are SEPARATE, and this is what that separation buys: a
    // credential trusted to manage people is not thereby trusted to create or disable the
    // organizations they belong to. A single `write` permission would have collapsed these.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.read", "management.write_users"],
    )
    .await;

    let orgs = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");

    // Reading organizations is granted (`management.read`).
    let (status, _, body) = h.get_as(&orgs, &secret).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the read grant does not cover organizations: {body}"
    );

    // Creating one is not.
    let (status, _, body) = h
        .post_as(
            &orgs,
            &secret,
            "k-org-denied",
            &serde_json::json!({ "display_name": "Denied" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential created an ORGANIZATION: the two write permissions have          collapsed into one. Body: {body}"
    );
    assert!(
        body.contains("management.write_organizations"),
        "the refusal does not name the permission required: {body}"
    );

    // The SHARED state-change body is enforced too. `disableOrganization` and
    // `enableOrganization` delegate to one function, so this is the case that would silently
    // stay open if the check had been copied into each handler and one copy was missed.
    let (status, _, created) = h
        .post(
            &orgs,
            "k-org-operator",
            &serde_json::json!({ "display_name": "Operated" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "operator creates the org: {created}"
    );
    let org_id = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, _, body) = h
        .post_as(
            &format!("{orgs}/{org_id}/disable"),
            &secret,
            "k-org-disable",
            "{}",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential DISABLED an organization through the shared state-change          path: {body}"
    );
}
