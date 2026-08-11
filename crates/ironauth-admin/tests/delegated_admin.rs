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

#[tokio::test]
async fn a_credential_with_no_read_grant_cannot_export_identities_or_manage_org_roles() {
    // `exportIdentities` drains every identity in the environment, credential material
    // included. It is classified `management.read` because that is honestly what it is, and
    // the consequence is worth stating: a persona that must not be able to export the
    // environment must not hold `read` at all. There is no narrower read today.
    //
    // A write-only credential is the case that shows it: it can create users and cannot read
    // them back, nor export them.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_users"],
    )
    .await;

    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    // It holds write_users, so creating a user works.
    let (status, _, body) = h
        .post_as(
            &format!("{base}/users"),
            &secret,
            "k-user",
            &serde_json::json!({ "identifier": "writeonly@example.test" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the write grant does not work: {body}"
    );

    // It does not hold read, so the export is refused.
    let (status, _, body) = h.get_as(&format!("{base}/export"), &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a credential with no read grant EXPORTED every identity in the environment: {body}"
    );

    // Nor may it create an organization ROLE, which would let it grant permissions inside an
    // organization it has no authority over.
    let (status, _, created) = h
        .post(
            &format!("{base}/organizations"),
            "k-org",
            &serde_json::json!({ "display_name": "Target" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed org: {created}");
    let org_id = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let (status, _, body) = h
        .post_as(
            &format!("{base}/organizations/{org_id}/roles"),
            &secret,
            "k-role",
            &serde_json::json!({ "slug": "admin", "display_name": "Admin" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential created an organization ROLE: {body}"
    );
}

#[tokio::test]
async fn a_confined_credential_reaches_its_own_organization_and_no_other() {
    // Issue #102 criterion 2. Permissions say WHAT a credential may do; confinement says
    // WHERE. Without the second dimension a credential granted `write_organizations` may
    // write EVERY organization in the environment, so an "org admin" persona was not
    // expressible at all.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let orgs = format!("{base}/organizations");

    // Two organizations, both real, so the refusal below is about MEMBERSHIP of the
    // confinement rather than about the sibling not existing.
    let mut ids = Vec::new();
    for (n, name) in ["Mine", "Theirs"].into_iter().enumerate() {
        let (status, _, created) = h
            .post(
                &orgs,
                &format!("k-org-{n}"),
                &serde_json::json!({ "display_name": name }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed {name}: {created}");
        ids.push(
            serde_json::from_str::<Value>(&created).expect("json")["id"]
                .as_str()
                .expect("id")
                .to_owned(),
        );
    }
    let (mine, theirs) = (&ids[0], &ids[1]);

    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.read", "management.write_organizations"],
    )
    .await;
    confine(&h, &tenant, &environment, &key_id, mine).await;

    // Its OWN organization is reachable, and it holds the permission, so this works.
    let (status, _, body) = h
        .post_as(
            &format!("{orgs}/{mine}/roles"),
            &secret,
            "k-mine-role",
            &serde_json::json!({ "slug": "auditor", "display_name": "Auditor" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a confined credential was refused inside its OWN organization: {body}"
    );

    // The sibling is NOT reachable, despite holding the same permission.
    let (status, _, body) = h
        .post_as(
            &format!("{orgs}/{theirs}/roles"),
            &secret,
            "k-theirs-role",
            &serde_json::json!({ "slug": "auditor", "display_name": "Auditor" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a credential confined to one organization reached a SIBLING: permissions alone do \
         not bound reach, which is why confinement is a separate dimension. Body: {body}"
    );

    // NOT-FOUND rather than 403, deliberately. A 403 would confirm the sibling EXISTS, so a
    // confined credential could enumerate the environment's organizations by comparing
    // statuses. Reading the sibling must be equally uninformative.
    let (status, _, body) = h.get_as(&format!("{orgs}/{theirs}"), &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "reading a sibling organization did not answer the uniform not-found, so a confined \
         credential can enumerate what it may not reach: {body}"
    );
}

#[tokio::test]
async fn a_confinement_that_will_not_parse_denies_the_credential_rather_than_widening_it() {
    // The failure direction that matters. A confinement column holding an id this scope
    // cannot parse (a foreign tenant's organization, or corruption) has two possible
    // readings: treat it as ABSENT, which silently converts a confined credential into one
    // with environment-wide reach, or refuse the credential.
    //
    // Refusing is the only safe reading. A credential must never end up with MORE authority
    // than its row claims, and "I could not understand the restriction" is not a licence to
    // ignore it. This is the same rule the grant parser follows for an unknown permission
    // slug, in the same direction.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "k-mint").await;

    // The credential works before the confinement is corrupted.
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let (status, _, body) = h.get_as(&users, &secret).await;
    assert_eq!(status, StatusCode::OK, "the key works unconfined: {body}");

    // A confinement the foreign key accepts (a real organization) but which this SCOPE
    // cannot parse is the hard case, so write a syntactically impossible one directly. The
    // foreign key is deferred to the end of the statement, so this uses a raw update against
    // a value that will fail `parse_in_scope`.
    sqlx::query(
        "ALTER TABLE management_credentials DROP CONSTRAINT management_credentials_organization_fk",
    )
    .execute(h.db().owner_pool())
    .await
    .expect("drop the fk for this probe");
    confine(
        &h,
        &tenant,
        &environment,
        &key_id,
        "org_not_a_real_scoped_identifier",
    )
    .await;

    let (status, _, body) = h.get_as(&users, &secret).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a credential whose confinement could not be parsed AUTHENTICATED, and did so with \
         environment-wide reach: an unreadable restriction became no restriction. Body: {body}"
    );
}

/// A read-only credential may LIST API keys and may not create, rotate or revoke one.
///
/// This closes a gap I documented in three separate handlers and did not close at the time.
/// `management_permissions.rs` classifies these operations as `WriteCredentials` and
/// separately asserts each handler calls `require_permission`, but nothing compares the two:
/// its own comment says it "cannot tell WHICH permission a handler demands, only that it
/// demands one". A mutation downgrading any of them to `Read` passed every pin.
///
/// The refusal-body assertions are what make this verify the SPECIFIC permission rather than
/// merely some permission. A handler demanding `Read` would answer 200 here, and one
/// demanding the wrong write permission would name that one instead.
#[tokio::test]
async fn a_read_only_credential_can_list_api_keys_and_cannot_mint_or_kill_one() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-mint").await;

    // An organization, and one key inside it, created while the credential is still
    // unrestricted. The restriction below is what the test is about; the fixture must exist
    // before it applies.
    let orgs = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let (status, _, body) = h
        .post(
            &orgs,
            "ak-org",
            &serde_json::json!({ "display_name": "Acme" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {body}");
    let org = serde_json::from_str::<serde_json::Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let base = format!("{orgs}/{org}/api-keys");
    let (status, _, body) = h
        .post(
            &base,
            "ak-seed",
            &serde_json::json!({ "display_name": "seed" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed key: {body}");
    let seeded = serde_json::from_str::<serde_json::Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    // The READ it holds still works.
    let (status, _, body) = h.get_as(&base, &secret).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a read-granted key was refused the key listing it holds: {body}"
    );

    // CREATE is refused, and the refusal names write_credentials rather than any other write.
    let (status, _, body) = h
        .post_as(
            &base,
            &secret,
            "ak-denied-create",
            &serde_json::json!({ "display_name": "should not exist" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential MINTED an API key: {body}"
    );
    assert!(
        body.contains("management.write_credentials"),
        "the refusal does not name write_credentials, so the handler may be demanding a \
         different permission than the classification records: {body}"
    );

    // ROTATE is refused, and names the same permission.
    let (status, _, body) = h
        .post_as(
            &format!("{base}/{seeded}/rotate"),
            &secret,
            "ak-denied-rotate",
            "",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential ROTATED an API key: {body}"
    );
    assert!(
        body.contains("management.write_credentials"),
        "rotate: {body}"
    );

    // REVOKE is refused, and names the same permission.
    let (status, _, body) = h.delete_as(&format!("{base}/{seeded}"), &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential REVOKED an API key: {body}"
    );
    assert!(
        body.contains("management.write_credentials"),
        "revoke: {body}"
    );

    // And nothing changed: the seeded key is still live and still the only one.
    let (_, _, listed) = h.get_as(&base, &secret).await;
    let items = serde_json::from_str::<serde_json::Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .clone();
    assert_eq!(
        items.len(),
        1,
        "a refused write changed the key set: {listed}"
    );
    assert!(
        items[0].get("revoked_at_unix_ms").is_none(),
        "the refused revoke revoked it anyway: {listed}"
    );
}

/// A read-only credential may LIST a service account's keys and may not mint, rotate or
/// revoke one, and the refusals NAME `management.write_credentials` (issue #99, criterion 6).
///
/// The sibling of `a_read_only_credential_can_list_api_keys_and_cannot_mint_or_kill_one`, and
/// it exists for the reason that one gives: `management_permissions.rs` is a text scan and can
/// only see THAT a handler demands a permission, never WHICH. A downgrade of these three to
/// `Read` would satisfy every pin in that file. This is what refuses it.
///
/// The listing is checked in both directions for the same reason. That it succeeds under
/// `management.read` says the route does not silently demand more; that it is refused to a
/// credential holding only `management.write_credentials`, naming `management.read`, says it
/// demands that specific one rather than merely something.
#[tokio::test]
async fn a_read_only_credential_cannot_mint_or_kill_a_service_accounts_key() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "sak-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "sak-mint").await;

    // The principal, and one key on it, seeded while the credential is still unrestricted.
    // A service account is minted for a client and has no create route of its own, so this
    // reaches the store the way the client-credentials grant does.
    let env = ironauth_env::Env::system();
    let scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::parse(&tenant).expect("tenant id"),
        ironauth_store::EnvironmentId::parse(&environment).expect("environment id"),
    );
    let actor = ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env));
    let client = h
        .db()
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(&env))
        .clients()
        .create(&env, "a machine client")
        .await
        .expect("create the client");
    let principal = h
        .db()
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(&env))
        .service_accounts()
        .ensure(&env, &client)
        .await
        .expect("mint the principal");

    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/service-accounts/{principal}/api-keys"
    );
    let (status, _, body) = h
        .post(
            &base,
            "sak-seed",
            &serde_json::json!({ "display_name": "seed" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed key: {body}");
    let seeded = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    assert_read_only_is_refused_every_write(&h, &base, &secret, &seeded).await;

    // And the other direction on the listing: a credential holding only the WRITE authority
    // is refused the read, naming the permission the classification records for it.
    let (write_id, write_secret) = mint_key(&h, &tenant, &environment, "sak-write").await;
    restrict(
        &h,
        &tenant,
        &environment,
        &write_id,
        &["management.write_credentials"],
    )
    .await;
    let (status, _, body) = h.get_as(&base, &write_secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write-only credential LISTED the keys: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the listing's refusal does not name management.read: {body}"
    );

    // The client-to-principal read that the console uses to REACH those keys takes the same
    // authority, and is proven the same way. A route the console must call before it can call
    // any of the others is not a lesser surface for being a lookup.
    let lookup =
        format!("/v1/tenants/{tenant}/environments/{environment}/clients/{client}/service-account");
    let (status, _, body) = h.get_as(&lookup, &secret).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a read-granted key was refused the principal lookup it holds: {body}"
    );
    assert!(
        body.contains(&principal.to_string()),
        "the lookup did not answer the principal that was minted for this client: {body}"
    );
    let (status, _, body) = h.get_as(&lookup, &write_secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write-only credential read the principal lookup: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the lookup's refusal does not name management.read: {body}"
    );
}

/// The read-only half, split out because the fixture above and these four probes together
/// exceed the function-length lint, and the probes are the part worth reading.
async fn assert_read_only_is_refused_every_write(
    h: &Harness,
    base: &str,
    secret: &str,
    seeded: &str,
) {
    let (status, _, body) = h.get_as(base, secret).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a read-granted key was refused the listing it holds: {body}"
    );

    let (status, _, body) = h
        .post_as(
            base,
            secret,
            "sak-denied-create",
            &serde_json::json!({ "display_name": "should not exist" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential MINTED a service-account key: {body}"
    );
    assert!(
        body.contains("management.write_credentials"),
        "the refusal does not name write_credentials, so the handler may demand a different \
         permission than the classification records: {body}"
    );

    let (status, _, body) = h
        .post_as(
            &format!("{base}/{seeded}/rotate"),
            secret,
            "sak-denied-rotate",
            "",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential ROTATED a service-account key: {body}"
    );
    assert!(body.contains("management.write_credentials"), "{body}");

    let (status, _, body) = h.delete_as(&format!("{base}/{seeded}"), secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential REVOKED a service-account key: {body}"
    );
    assert!(body.contains("management.write_credentials"), "{body}");
}

/// A credential confined to one organization may not touch a service account's keys.
///
/// Issue #99. Confinement bounds a credential to ONE organization. A service account belongs
/// to the environment and may be a member of several organizations or none, so there is no
/// organization for the confinement to be checked against. The route fails CLOSED rather than
/// allowing the request because nothing contradicted it, which is the direction that matters:
/// the key minted here authenticates as a principal whose memberships the confined credential
/// was never granted.
#[tokio::test]
async fn a_confined_credential_cannot_reach_a_service_accounts_keys() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "cfk-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "cfk-mint").await;

    let (status, _, body) = h
        .post(
            &format!("{base}/organizations"),
            "cfk-org",
            &serde_json::json!({ "display_name": "Acme" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {body}");
    let org = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let env = ironauth_env::Env::system();
    let scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::parse(&tenant).expect("tenant id"),
        ironauth_store::EnvironmentId::parse(&environment).expect("environment id"),
    );
    let actor = ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env));
    let client = h
        .db()
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(&env))
        .clients()
        .create(&env, "a machine client")
        .await
        .expect("create the client");
    let principal = h
        .db()
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(&env))
        .service_accounts()
        .ensure(&env, &client)
        .await
        .expect("mint the principal");
    let keys = format!("{base}/service-accounts/{principal}/api-keys");

    // Unconfined, the credential reaches it. This is what makes the refusal below a statement
    // about confinement rather than about the route being broken for everyone.
    let (status, _, body) = h.get_as(&keys, &secret).await;
    assert_eq!(status, StatusCode::OK, "before confinement: {body}");

    confine(&h, &tenant, &environment, &key_id, &org).await;

    let (status, _, body) = h.get_as(&keys, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a confined credential LISTED a service account's keys: {body}"
    );
    let (status, _, body) = h
        .post_as(
            &keys,
            &secret,
            "cfk-denied",
            &serde_json::json!({ "display_name": "should not exist" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a confined credential MINTED a service-account key: {body}"
    );
}

/// Seed a user through the management API and answer its id.
async fn seed_pat_user(h: &Harness, tenant: &str, environment: &str, handle: &str) -> String {
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/users"),
            handle,
            &serde_json::json!({ "identifier": handle }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {body}");
    serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// A read-only credential may LIST personal access tokens and may not mint, rotate or revoke
/// one, and the refusals NAME `management.write_credentials` (issue #99, criterion 6).
///
/// The third of these, and it exists for the reason the other two give:
/// `management_permissions.rs` is a text scan that can see THAT a handler demands a permission,
/// never WHICH. The listing is checked in both directions, so a downgrade of its read to "any
/// permission" is refused as well as an upgrade of it.
#[tokio::test]
async fn a_read_only_credential_cannot_mint_or_kill_a_personal_access_token() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "pak-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "pak-mint").await;
    let user = seed_pat_user(&h, &tenant, &environment, "pak-user@example.test").await;
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/users/{user}/personal-access-tokens"
    );

    let (status, _, body) = h
        .post(
            &base,
            "pak-seed",
            &serde_json::json!({ "display_name": "seed" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed token: {body}");
    let seeded = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    assert_read_only_is_refused_every_write(&h, &base, &secret, &seeded).await;

    let (write_id, write_secret) = mint_key(&h, &tenant, &environment, "pak-write").await;
    restrict(
        &h,
        &tenant,
        &environment,
        &write_id,
        &["management.write_credentials"],
    )
    .await;
    let (status, _, body) = h.get_as(&base, &write_secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write-only credential LISTED the tokens: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the listing's refusal does not name management.read: {body}"
    );
}

/// A credential confined to one organization may not touch a user's personal access tokens.
///
/// A personal access token authenticates as its user everywhere that user is a member, which
/// is not a subset of any one organization, so the confinement has no boundary to check it
/// against and the route fails closed.
#[tokio::test]
async fn a_confined_credential_cannot_reach_a_users_personal_access_tokens() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "pcf-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "pcf-mint").await;
    let user = seed_pat_user(&h, &tenant, &environment, "pcf-user@example.test").await;
    let tokens = format!("{base}/users/{user}/personal-access-tokens");

    let (status, _, body) = h
        .post(
            &format!("{base}/organizations"),
            "pcf-org",
            &serde_json::json!({ "display_name": "Acme" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {body}");
    let org = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Unconfined it reaches them, which is what makes the refusal below about confinement.
    let (status, _, body) = h.get_as(&tokens, &secret).await;
    assert_eq!(status, StatusCode::OK, "before confinement: {body}");

    confine(&h, &tenant, &environment, &key_id, &org).await;

    let (status, _, body) = h.get_as(&tokens, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a confined credential LISTED a user's personal access tokens: {body}"
    );
    let (status, _, body) = h
        .post_as(
            &tokens,
            &secret,
            "pcf-denied",
            &serde_json::json!({ "display_name": "should not exist" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a confined credential MINTED a personal access token: {body}"
    );
}

/// ONLY a credential holding `management.impersonate` may authorize one (issue #101,
/// criterion 6), and a request without a typed justification is refused by CODE (criterion 3).
///
/// The permission half drives a credential holding every OTHER permission, not merely a
/// read-only one. That is the distinction that matters: impersonation escalates past every
/// write on this surface, so a credential that may edit users, configuration, organizations
/// and even credentials must still be refused. A test using a read-only key would pass against
/// an implementation that had folded impersonation into `WriteUsers`.
///
/// The justification half asserts the ERROR CODE rather than the status, because criterion 3
/// asks for a typed error. A 400 saying "bad request" tells an operator to guess.
#[tokio::test]
async fn only_a_credential_holding_impersonate_can_authorize_one() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "imp-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "imp-mint").await;
    let user = seed_pat_user(&h, &tenant, &environment, "imp-user@example.test").await;
    let route =
        format!("/v1/tenants/{tenant}/environments/{environment}/users/{user}/impersonation");
    let justified = serde_json::json!({
        "reason_code": "support_ticket",
        "reason_text": "Ticket 4417: reproducing the checkout failure as the user.",
    })
    .to_string();

    // Everything EXCEPT impersonate.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &[
            "management.read",
            "management.write_config",
            "management.write_users",
            "management.write_organizations",
            "management.write_credentials",
        ],
    )
    .await;
    let (status, _, body) = h.post_as(&route, &secret, "imp-denied", &justified).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a credential holding every other permission AUTHORIZED an impersonation: {body}"
    );
    assert!(
        body.contains("management.impersonate"),
        "the refusal must name the impersonation permission, or the handler may be demanding \
         something else entirely: {body}"
    );

    // Granted, it works.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.impersonate"],
    )
    .await;
    let (status, _, body) = h.post_as(&route, &secret, "imp-ok", &justified).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the permission alone is enough to authorize one: {body}"
    );
    let authorized: Value = serde_json::from_str(&body).expect("json");
    assert!(
        authorized["authorization_id"]
            .as_str()
            .expect("id")
            .starts_with("imp_"),
        "the handle is an impersonation authorization: {body}"
    );

    assert_each_missing_justification_names_its_rule(&h, &route, &secret).await;

    // A well-formed user id that names nobody is the uniform not-found. Without the existence
    // check the authorization would name nobody, and the failure would surface at REDEMPTION
    // as a foreign-key error on a plane that did not make the mistake.
    let absent = format!(
        "/v1/tenants/{tenant}/environments/{environment}/users/{}/impersonation",
        ironauth_store::UserId::generate(
            &ironauth_env::Env::system(),
            &ironauth_store::Scope::new(
                ironauth_store::TenantId::parse(&tenant).expect("tenant"),
                ironauth_store::EnvironmentId::parse(&environment).expect("environment"),
            ),
        )
    );
    let (status, _, body) = h.post_as(&absent, &secret, "imp-absent", &justified).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "authorizing against a user who does not exist must be the uniform not-found: {body}"
    );
}

/// The typed refusals, split out because the fixture above and these probes together exceed
/// the function-length lint.
///
/// Each case asserts the CODE, so a handler that collapsed every failure into one refusal
/// fails here rather than reading as correct.
async fn assert_each_missing_justification_names_its_rule(h: &Harness, route: &str, secret: &str) {
    for (label, body, code) in [
        (
            "no reason code",
            serde_json::json!({ "reason_code": "", "reason_text": "Ticket 4417" }),
            "reason_code_required",
        ),
        (
            "no written justification",
            serde_json::json!({ "reason_code": "support_ticket", "reason_text": "" }),
            "reason_text_required",
        ),
        (
            "whitespace passing for a justification",
            serde_json::json!({ "reason_code": "support_ticket", "reason_text": "\t\n " }),
            "reason_text_required",
        ),
        (
            "sixty-one minutes",
            serde_json::json!({
                "reason_code": "support_ticket",
                "reason_text": "Ticket 4417",
                "duration_seconds": 3661,
            }),
            "impersonation_cap_exceeded",
        ),
    ] {
        let (status, _, response) = h
            .post_as(
                route,
                secret,
                &format!("imp-{code}-{label}"),
                &body.to_string(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} was accepted: {response}"
        );
        assert!(
            response.contains(code),
            "{label} must be refused as `{code}` so an operator is told WHICH rule they broke, \
             got: {response}"
        );
    }
}

/// The log stream status read demands `management.read` in BOTH directions.
///
/// Both directions matter and only one of them is the obvious one. A credential holding a
/// DIFFERENT permission must be refused with the required one NAMED, and a credential
/// holding read must be served: without the second half, downgrading the route to "any
/// permission" would still pass, and the classification would be a comment rather than a
/// control.
///
/// The status surface reports where each export is up to and why it is failing, which is
/// operational intelligence about an environment's audit pipeline. It is a read, not a
/// public one.
#[tokio::test]
async fn the_log_stream_status_read_demands_read_and_never_answers_unauthenticated() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "lgs-mint").await;
    let streams = format!("/v1/tenants/{tenant}/environments/{environment}/log-streams");

    // Read-granted: served.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&streams, &secret).await;
    assert_eq!(status, StatusCode::OK, "log streams under read: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    assert!(
        document["items"].is_array(),
        "the listing must answer with its items array even when empty: {body}"
    );

    // A credential holding a WRITE but not read is refused, and the refusal names what it
    // wanted.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_organizations"],
    )
    .await;
    let (status, _, body) = h.get_as(&streams, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "log streams answered a credential without management.read: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the refusal must name the permission it wanted: {body}"
    );

    // And with no credential at all. An EMPTY bearer is the unauthenticated case; the
    // harness operator token would prove nothing.
    let (status, _, body) = h.get_as(&streams, "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "log streams answered an unauthenticated caller: {body}"
    );

    // The CONFIGURATION writes are a different permission from the read, and both
    // directions matter for each. `management.read` must NOT be enough to configure a
    // stream: a read-only credential that could point an audit export at a destination of
    // its choosing would make the read/write split meaningless.
    let create_body = serde_json::json!({
        "source": "both",
        "sink_type": "http",
        "sink_config": {"endpoint": "https://sink.example/in"},
    })
    .to_string();
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.post_as(&streams, &secret, "lgs-1", &create_body).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential must not configure a log stream: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal must name the permission it wanted: {body}"
    );
    let absent = format!("{streams}/lgs_absent");
    let (status, _, body) = h.delete_as(&absent, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential must not remove a log stream: {body}"
    );

    // And write_config is served, so the refusal above is the permission talking rather
    // than the route being broken.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, body) = h.post_as(&streams, &secret, "lgs-2", &create_body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "write_config must be able to configure a stream: {body}"
    );
}

/// Every `AuthZEN` endpoint demands `management.read`, and unauthenticated evaluation is never
/// served (issue #100).
///
/// The issue states that last part as a requirement, so it is asserted rather than assumed: a
/// PDP that answers without a credential hands an attacker a permission oracle for every
/// subject in the environment.
///
/// The positive half matters as much. A credential holding a WRITE but not `management.read`
/// must be refused, which is what says the endpoints demand that specific permission rather
/// than merely some permission; the classification pin cannot see the difference.
#[tokio::test]
async fn the_authzen_endpoints_demand_read_and_never_answer_unauthenticated() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "az-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "az-mint").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let evaluation = format!("{base}/access/v1/evaluation");
    let evaluations = format!("{base}/access/v1/evaluations");
    let discovery = format!("{base}/.well-known/authzen-configuration");

    // Read-granted: the discovery document is served and names the two endpoints.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&discovery, &secret).await;
    assert_eq!(status, StatusCode::OK, "discovery under read: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(document["access_evaluation_endpoint"], evaluation);
    assert_eq!(document["access_evaluations_endpoint"], evaluations);
    assert!(
        document["subject_search_endpoint"].is_null(),
        "the search APIs are deferred and the document must SAY so rather than omit the key, \
         or a PEP cannot tell `not supported` from `older document`: {body}"
    );

    // A credential holding a write but not read is refused all three.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_organizations"],
    )
    .await;
    for (label, response) in [
        ("discovery", h.get_as(&discovery, &secret).await),
        (
            "evaluation",
            h.post_as(&evaluation, &secret, "az-1", "{}").await,
        ),
        (
            "evaluations",
            h.post_as(&evaluations, &secret, "az-2", "{}").await,
        ),
    ] {
        let (status, _, body) = response;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label} answered a credential without management.read: {body}"
        );
        assert!(
            body.contains("management.read"),
            "{label} must name the permission it wanted: {body}"
        );
    }

    // And with no credential at all. `get_as` with an EMPTY bearer is the unauthenticated
    // case; `get` carries the harness operator token and would prove nothing.
    let (status, _, body) = h.get_as(&discovery, "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "discovery answered an unauthenticated caller: {body}"
    );
    let (status, _, body) = h.post_unauthenticated(&evaluation, "{}").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "evaluation answered an unauthenticated caller, which is a permission oracle for \
         every subject in the environment: {body}"
    );
}
