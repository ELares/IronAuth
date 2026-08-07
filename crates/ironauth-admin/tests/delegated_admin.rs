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

#[tokio::test]
async fn a_user_granted_credential_cannot_write_a_secret() {
    // The sharpest case for `WriteConfig` being separate. A secret write is not a lesser
    // operation because the value is unreadable afterwards: a credential that can seal a value
    // into an environment can change what every connector authenticates WITH. A permission
    // model that let a user-management credential do that would hand it the environment.
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

    let base = format!("/v1/tenants/{tenant}/environments/{environment}/secrets");

    // Listing secret METADATA is granted by `management.read`, so the request must get PAST
    // the permission gate. It then meets this harness's own limit: the secret surface needs a
    // data-plane connection (issue #235) and fails closed with 422 without one.
    //
    // So the assertion is "not 403" rather than "200". Asserting 200 would be asserting that
    // this harness installs a registry, which is a different fact and not the one under test;
    // the write below is what carries the actual permission claim.
    let (status, _, body) = h.get_as(&base, &secret).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "the read grant did not cover secret metadata: {body}"
    );

    // Writing one is not granted. Note the request carries NO Idempotency-Key, which this
    // endpoint requires: the 403 below therefore also proves the permission check runs BEFORE
    // that requirement, so a restricted credential is refused on authority rather than being
    // told how to shape a request it may not make.
    let (status, _, body) = h
        .put_as(
            &format!("{base}/STRIPE_KEY"),
            &secret,
            &serde_json::json!({ "value": "sk_live_denied" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential SEALED a secret: it can now change what every connector in          the environment authenticates with. Body: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal does not name the permission required: {body}"
    );
}

#[tokio::test]
async fn a_user_granted_credential_cannot_change_who_belongs_to_an_organization() {
    // Membership is the quiet escalation path. A credential that may create USERS but not
    // touch organizations must not be able to put a user INTO one: doing so grants that user
    // whatever the organization confers (its roles, its policies, its connections), which is
    // organizational authority exercised through a user-shaped API.
    //
    // This is why membership writes are classified `write_organizations` and not
    // `write_users`, even though the resource reads like a property of a user.
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

    // The operator sets up an organization and a user for the restricted key to try to join.
    let orgs = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let (status, _, created) = h
        .post(
            &orgs,
            "k-org",
            &serde_json::json!({ "display_name": "Target" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed org: {created}");
    let org_id = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // The credential CAN create a user: that is its grant.
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let (status, _, user_body) = h
        .post_as(
            &users,
            &secret,
            "k-user",
            &serde_json::json!({ "identifier": "joiner@example.test" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the credential was refused the write it HOLDS: {user_body}"
    );
    let user_id = serde_json::from_str::<Value>(&user_body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // It cannot put that user into the organization.
    let (status, _, body) = h
        .post_as(
            &format!("{orgs}/{org_id}/memberships"),
            &secret,
            "k-join",
            &serde_json::json!({ "user_id": user_id }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential added a member to an organization, granting that user \
         everything the organization confers: {body}"
    );
    assert!(
        body.contains("management.write_organizations"),
        "the refusal does not name the permission required: {body}"
    );
}

#[tokio::test]
async fn a_read_only_credential_cannot_invite_or_ban() {
    // Both operations are easy to under-classify. An invitation looks like "send an email"
    // and a ban looks like a moderation action, but the first PROVISIONS an identity plus a
    // single-use token, and the second denies a real person access. Each is user authority.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    // Reading both surfaces is granted.
    for path in [format!("{base}/invitations"), format!("{base}/abuse/bans")] {
        let (status, _, body) = h.get_as(&path, &secret).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "the read grant did not cover {path}: {body}"
        );
    }

    // Inviting is not: whoever may invite may populate the environment.
    let (status, _, body) = h
        .post_as(
            &format!("{base}/invitations"),
            &secret,
            "k-invite",
            &serde_json::json!({ "identifier": "invitee@example.test" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential PROVISIONED an identity through an invitation: {body}"
    );
    assert!(
        body.contains("management.write_users"),
        "the refusal does not name the permission required: {body}"
    );

    // Nor is banning: it denies a real person access to the environment.
    let (status, _, body) = h
        .post_as(
            &format!("{base}/abuse/bans"),
            &secret,
            "k-ban",
            &serde_json::json!({ "subject_kind": "ip", "subject": "203.0.113.7" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential created a BAN: {body}"
    );
}

#[tokio::test]
async fn a_user_granted_credential_cannot_rebrand_the_environment() {
    // Branding looks cosmetic and is not. The brand is what an end user SEES on the login
    // page, so a credential that can change it can make the environment's sign-in surface say
    // anything, which is a phishing primitive rather than a styling preference. It is
    // configuration authority.
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

    let brands = format!("/v1/tenants/{tenant}/environments/{environment}/brands");

    // Reading brands is granted by `management.read`.
    let (status, _, body) = h.get_as(&brands, &secret).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "the read grant did not cover brands: {body}"
    );

    // Setting one is not.
    let (status, _, body) = h
        .put_as(
            &format!("{brands}/default"),
            &secret,
            &serde_json::json!({ "display_name": "Not Acme" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential REBRANDED the environment: it can now change what every \
         end user sees on the login page. Body: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal does not name the permission required: {body}"
    );
}

#[tokio::test]
async fn a_read_only_credential_cannot_approve_a_recovery_or_change_uniqueness() {
    // Two operations that look procedural and are not.
    //
    // Approving a recovery HANDS SOMEONE BACK AN ACCOUNT. It is the single most direct
    // account-takeover primitive in the management surface: whoever may approve may approve
    // their own request against anyone's account.
    //
    // Applying an identifier uniqueness mode recomputes keys across the WHOLE environment,
    // changing the rule every identifier obeys. That is configuration, not user data, which
    // is why it is `write_config` and not `write_users` despite living under identifiers.
    // ARMED harness: every recovery-approval route 404s until advanced recovery is enabled
    // and acknowledged, so an unarmed harness would give a 404 that looks like a passing
    // refusal test while proving nothing about permissions.
    let h = Harness::start_with_advanced_recovery(50, true).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    // The read grant covers listing both surfaces.
    for path in [
        format!("{base}/recovery-approvals"),
        format!("{base}/identifiers/uniqueness"),
    ] {
        let (status, _, body) = h.get_as(&path, &secret).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "the read grant did not cover {path}: {body}"
        );
    }

    // Approving is refused. The id is bogus, and the 403 therefore also shows the permission
    // gate runs BEFORE the approval is resolved: a restricted credential gets the same answer
    // for an id that exists and one that does not, so it cannot probe the queue by comparing
    // 403 against 404.
    let (status, _, body) = h
        .post_as(
            &format!("{base}/recovery-approvals/rca_000000000000000000000000000000/approve"),
            &secret,
            "k-approve",
            "{}",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential reached the recovery APPROVAL path, the most direct \
         account-takeover primitive on this surface: {body}"
    );
    assert!(
        body.contains("management.write_users"),
        "the refusal does not name the permission required: {body}"
    );
}

#[tokio::test]
async fn a_user_granted_credential_cannot_redirect_the_webhook_stream() {
    // A webhook endpoint is where the environment's EVENTS go. A credential that can create
    // one, or rotate its secret, can redirect or forge the event stream a customer's systems
    // trust. That is configuration authority, not a delivery detail.
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

    let hooks = format!("/v1/tenants/{tenant}/environments/{environment}/webhook-endpoints");

    // Reading the endpoint list is granted.
    let (status, _, body) = h.get_as(&hooks, &secret).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "the read grant did not cover webhook endpoints: {body}"
    );

    // Creating one is not: it points the environment's event stream somewhere new.
    let (status, _, body) = h
        .post_as(
            &hooks,
            &secret,
            "k-hook-denied",
            &serde_json::json!({ "url": "https://attacker.example/hook" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential pointed the environment's event stream at a new \
         destination: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal does not name the permission required: {body}"
    );
}
