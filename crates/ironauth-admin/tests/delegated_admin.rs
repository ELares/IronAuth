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
use ironauth_store::log_stream::{SinkType, StreamSource};
use ironauth_store::{EnvironmentId, NewLogStream, Scope, TenantId};
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

/// Mint a registered machine identity, which a subject mapping's principal must name.
///
/// A service account has no create route of its own: it is minted for a CLIENT, the way the
/// client-credentials grant does at first issuance, so this reaches the store exactly as
/// production does.
async fn seed_machine_identity(h: &Harness, tenant: &str, environment: &str) -> String {
    let env = ironauth_env::Env::system();
    let scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::parse(tenant).expect("tenant id"),
        ironauth_store::EnvironmentId::parse(environment).expect("environment id"),
    );
    let actor = ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env));
    let client = h
        .db()
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(&env))
        .clients()
        .create(&env, "a federated workload")
        .await
        .expect("create the client");
    h.db()
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(&env))
        .service_accounts()
        .ensure(&env, &client)
        .await
        .expect("mint the machine identity")
        .to_string()
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

/// The flow-target surface splits read from configure, and both directions matter (#112).
///
/// Registering a flow target points IronAuth at an endpoint it will CALL during a live
/// signup, and a fail-closed one can refuse every signup in the environment. So a read-only
/// credential must not be able to register one, and the refusal has to name the permission it
/// wanted rather than a generic denial: substituting one write permission for another would
/// otherwise pass unnoticed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_flow_target_surface_splits_reading_from_registering() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "ftg-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ftg-mint").await;
    let targets = format!("/v1/tenants/{tenant}/environments/{environment}/flow-targets");

    // Read-granted: served.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&targets, &secret).await;
    assert_eq!(status, StatusCode::OK, "flow targets under read: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    assert!(
        document["targets"].is_array(),
        "the listing must answer with its targets array even when empty: {body}"
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
    let (status, _, body) = h.get_as(&targets, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "flow targets answered a credential without management.read: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the refusal must name the permission it wanted: {body}"
    );

    // And with no credential at all. An EMPTY bearer is the unauthenticated case.
    let (status, _, body) = h.get_as(&targets, "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "flow targets answered an unauthenticated caller: {body}"
    );
}

/// Registering a flow target demands `write_config`, and the id it returns names a real row.
///
/// Split from the read above only because the two together exceed the length lint; they are
/// one property in two halves. Registering points IronAuth at an endpoint it will CALL during
/// a live signup, and a fail-closed target refuses every signup until it answers, so a
/// read-only credential must not be able to do it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registering_a_flow_target_demands_write_config() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "ftg-write-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ftg-write-mint").await;
    let targets = format!("/v1/tenants/{tenant}/environments/{environment}/flow-targets");

    // A read-only credential that could point a signup at an endpoint of its choosing, or
    // register a fail-closed target that refuses every signup, would make the split
    // meaningless.
    let create_body = serde_json::json!({
        "name": "delegated-admin-probe",
        "target_class": "request",
        "invocation": "sync",
        "timing": "pre_persist",
        "endpoint": "https://target.example/check",
        "timeout_ms": 500,
        "failure_policy": "fail_closed",
    })
    .to_string();
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.post_as(&targets, &secret, "ftg-1", &create_body).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential must not register a flow target: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal must name the permission it wanted: {body}"
    );

    // write_config is served, so the refusal above is the permission talking rather than the
    // route being broken. The id it returns is used for the delete below, which is what makes
    // that half a real deregistration rather than a not-found.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, body) = h.post_as(&targets, &secret, "ftg-2", &create_body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "write_config must be able to register a target: {body}"
    );
    let registered: Value = serde_json::from_str(&body).expect("json");
    let target_id = registered["id"]
        .as_str()
        .expect("the registered id")
        .to_owned();

    // The id the create returned must NAME A ROW. The upsert arbitrates on name and keeps the
    // existing row's id, so a handler returning its own freshly minted candidate would hand
    // back an id that 404s here.
    //
    // The credential is re-granted READ first, because the listing is classified
    // `management.read` while the create above needed `management.write_config`, and this
    // test holds exactly one restriction at a time. Without this the listing answered 403 and
    // the assertion below read as "the create returned a phantom id" when the truth was "this
    // credential may not list". Measured: that is how this test shipped in #951, red.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&targets, &secret).await;
    assert_eq!(status, StatusCode::OK, "listing after register: {body}");
    assert!(
        body.contains(&target_id),
        "the id the create returned must appear in the listing: {body}"
    );

    // Deregistering is write_config too, and read alone must not do it. The credential is
    // already read-only from the listing above; restated rather than dropped, so this case
    // states the precondition it depends on instead of inheriting it from a neighbour.
    let one = format!("{targets}/{target_id}");
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.delete_as(&one, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential must not deregister a flow target: {body}"
    );
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, body) = h.delete_as(&one, &secret).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "write_config must be able to deregister a target: {body}"
    );
}

/// Configure one stream per SINK TYPE, each naming a credential secret.
///
/// One per type because a view field resolved only for some sink types renders no key for the
/// others: a single-fixture key set is a claim about that fixture rather than about the view,
/// and review demonstrated a `skip_serializing_if` field that leaks on Datadog while an HTTP
/// fixture reports clean.
async fn seed_one_stream_per_sink_type(h: &Harness, scope: Scope) {
    let env = ironauth_env::Env::system();
    for (sink_type, sink_config) in [
        (
            SinkType::Http,
            serde_json::json!({ "endpoint": "https://sink.example/in" }),
        ),
        (
            SinkType::Datadog,
            serde_json::json!({ "endpoint": "https://http-intake.example/api/v2/logs" }),
        ),
        (
            SinkType::SplunkHec,
            serde_json::json!({ "endpoint": "https://splunk.example/services/collector" }),
        ),
        (
            SinkType::S3,
            serde_json::json!({ "endpoint": "https://s3.example", "bucket": "audit", "region": "us-east-1" }),
        ),
    ] {
        h.control_store()
            .scoped(scope)
            .log_streams()
            .create(
                &env,
                &NewLogStream {
                    id: None,
                    description: "redaction fixture",
                    source: StreamSource::Both,
                    sink_type,
                    sink_config,
                    credential_secret_name: Some("collector_token"),
                    signing_secret_name: None,
                    event_type_filter: None,
                    organization_id: None,
                },
                None,
            )
            .await
            .expect("configure a stream that names a credential");
    }
}

/// The status read carries the credential secret's NAME and never a resolved value, over
/// HTTP (issue #110 criterion 6).
///
/// # What this adds, and what already existed
///
/// `log_streams::tests::a_status_view_never_carries_a_credential_value` already pins this at
/// the `into_view` level, and has done since the commit that wrote the module doc. What that
/// test cannot see is the HTTP path: it calls `into_view` directly, so it would still pass if
/// a handler resolved the secret and merged it into the response, or if the route stopped
/// calling `into_view` at all. This drives the real endpoint under a real `management.read`
/// grant, which is the half that was missing.
///
/// # Why an EXACT key set rather than a list of forbidden names
///
/// The unit test enumerates `credential`, `credential_value` and `secret`, and enumeration
/// only catches the names someone thought of. Review demonstrated a live secret value
/// rendered on the wire under `resolved_token` while a name-shape guard reported a clean
/// redaction, and `credentials` in the plural evades an equality check on `credential` just
/// as easily. `token` or `api_key` is what a future author would actually reach for.
///
/// So this asserts the key set EQUALS the documented one, for a stream of EVERY sink type.
/// The per-type loop is what makes that a universal rather than a claim about one fixture:
/// review demonstrated a field declared `#[serde(skip_serializing_if = "Option::is_none")]`
/// and resolved only for vendor sinks, which renders no key for an HTTP stream and ships the
/// secret on every Datadog one. A single-fixture assertion passes that; this does not.
///
/// The guarantee lives in the SHAPE of this view rather than in a check, and a shape is what
/// a later field quietly changes. `last_error` already leaves the system through this view,
/// which is the precedent for a value arriving here by accident, and it is why the fixture
/// also asserts that field is null: a secret riding inside the VALUE of a key that is already
/// in the set changes no key at all.
///
/// The first assertion stops the second passing vacuously: a listing that silently lost the
/// stream would otherwise report a clean redaction over an empty array.
#[tokio::test]
async fn a_log_stream_read_names_the_credential_secret_and_renders_no_value() {
    let h = Harness::start(56).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-redact").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "lgs-redact-mint").await;
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    seed_one_stream_per_sink_type(&h, scope).await;

    let streams = format!("/v1/tenants/{tenant}/environments/{environment}/log-streams");
    let (status, _, body) = h.get_as(&streams, &secret).await;
    assert_eq!(status, StatusCode::OK, "log streams under read: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    let items = document["items"].as_array().expect("items array");
    assert_eq!(
        items.len(),
        4,
        "one stream per sink type must be listed, or the loop below checks fewer shapes than \
         it claims: {body}"
    );

    for item in items {
        assert_eq!(
            item["credential_secret_name"], "collector_token",
            "the view must carry the NAME, and this assertion is also what keeps the one \
             below from passing on a listing that lost a stream: {body}"
        );
        assert!(
            item["last_error"].is_null(),
            "a freshly configured stream has no error, and `last_error` is the one field \
             whose VALUE leaves the system here: a secret riding inside it would change no \
             key at all: {body}"
        );

        let mut keys: Vec<&str> = item
            .as_object()
            .expect("the item is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "active",
                "consecutive_failures",
                "credential_secret_name",
                "cursor_audit_id",
                "description",
                "event_type_filter",
                "id",
                "last_error",
                "last_error_at_unix_micros",
                "last_success_at_unix_micros",
                "organization_id",
                "signing_secret_name",
                "sink_type",
                "source",
                "status",
            ],
            "the rendered stream's field set changed. A new field on a view that names a \
             credential has to be looked at before it ships, which is why this pins the SET \
             rather than a list of forbidden names, for every sink type: {body}"
        );
    }
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

/// The event feed and the usage export are `management.read`, PROVEN rather than declared
/// (issue #107).
///
/// Classification is a table entry; this is the test that makes it true. A credential
/// holding a different permission must be refused, and one holding `management.read` must
/// be allowed, because only asserting the refusal would also pass if the endpoints refused
/// everyone, and only asserting the allow would pass if they refused no one.
#[tokio::test]
async fn read_is_required_and_sufficient_for_the_event_feed_and_usage_export() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-feed").await;

    let feed = format!("/v1/tenants/{tenant}/environments/{environment}/events");
    let usage = format!("/v1/tenants/{tenant}/environments/{environment}/usage");

    // A credential restricted to a DIFFERENT permission. Not "no permissions": an empty set
    // could be refused by some earlier check and prove nothing about which permission these
    // operations actually require.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;

    for path in [&feed, &usage] {
        let (status, _, body) = h.get_as(path, &secret).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a write_config credential must not read {path}: {body}"
        );
    }

    // The same credential, now holding read, must be allowed. Without this half the test
    // would pass against endpoints that refused everybody.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    for path in [&feed, &usage] {
        let (status, _, body) = h.get_as(path, &secret).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a read credential must be allowed to read {path}: {body}"
        );
    }
}

/// Configure one stream and set a dead letter aside for it, returning `(stream_id, dead_id)`.
///
/// Seeded through the STORE rather than by driving a failing sink, because what these tests
/// are about is the operator surface over a dead letter, not the shipper's decision to
/// create one. `log_shipper.rs` drives the creation end to end.
async fn seed_dead_letter(h: &Harness, scope: Scope, error: &str) -> (String, String) {
    let env = ironauth_env::Env::system();
    let stream_id = h
        .control_store()
        .scoped(scope)
        .log_streams()
        .create(
            &env,
            &NewLogStream {
                id: None,
                description: "dead letter fixture",
                source: StreamSource::Both,
                sink_type: SinkType::Http,
                sink_config: serde_json::json!({ "endpoint": "https://sink.example/in" }),
                credential_secret_name: None,
                signing_secret_name: None,
                event_type_filter: None,
                organization_id: None,
            },
            None,
        )
        .await
        .expect("configure a stream");
    let dead_id = h
        .control_store()
        .scoped(scope)
        .log_streams()
        .dead_letter(
            &env,
            &stream_id,
            (
                1_700_000_000_000_000,
                "aud_first",
                1_700_000_009_000_000,
                "aud_last",
            ),
            7,
            error,
        )
        .await
        .expect("record a dead letter");
    (stream_id, dead_id)
}

/// An operator can READ what the shipper set aside.
///
/// Issue #938: the shipper dead-letters a batch after a bounded failure run and advances
/// past it, which is what stops one poisoned batch blocking every later event. Before this
/// surface an operator could see the COUNT of what was set aside, through the health
/// observation, and could not read WHICH events or get them delivered. A number with no
/// way to act on it is not a recovery path.
#[tokio::test]
async fn an_operator_can_list_a_streams_dead_letters() {
    let h = Harness::start(71).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-dl-list").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "lgs-dl-list-mint").await;
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let (stream_id, dead_id) = seed_dead_letter(&h, scope, "sink_refused_502").await;

    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/log-streams/{stream_id}/dead-letters"
    );
    let (status, _, body) = h.get_as(&path, &secret).await;
    assert_eq!(status, StatusCode::OK, "dead letters under read: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    let items = document["items"].as_array().expect("items array");
    assert_eq!(
        items.len(),
        1,
        "the seeded dead letter must be listed: {body}"
    );
    assert_eq!(items[0]["id"], dead_id);
    assert_eq!(items[0]["event_count"], 7, "the size of the gap: {body}");
    assert_eq!(
        items[0]["last_error"], "sink_refused_502",
        "the failure that ended the retry run: {body}"
    );
    // The RANGE, which is the whole point: without both ends an operator cannot tell which
    // events went undelivered, and a replay cannot be checked against anything.
    assert_eq!(items[0]["from_audit_id"], "aud_first", "{body}");
    assert_eq!(items[0]["to_audit_id"], "aud_last", "{body}");
    assert_eq!(
        items[0]["from_occurred_at_unix_ms"], 1_700_000_000_000_i64,
        "{body}"
    );
    assert_eq!(
        items[0]["to_occurred_at_unix_ms"], 1_700_000_009_000_i64,
        "{body}"
    );
    assert_eq!(
        document["truncated"], false,
        "one dead letter is not a truncated page: {body}"
    );
}

/// A replay REQUEST is accepted and enqueues a command for the worker.
///
/// 202 rather than 200, and a command rather than the replay itself, because a replay
/// re-ships audit ranges to a third-party sink: network work of unbounded duration that
/// must not happen inside the request asking for it. The assertion that a command was
/// ENQUEUED is what separates this from an endpoint that accepts and does nothing, which
/// is the worse failure because it looks like success.
#[tokio::test]
async fn a_replay_request_enqueues_a_command_for_the_worker() {
    let h = Harness::start(72).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-dl-replay").await;

    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let (stream_id, _dead_id) = seed_dead_letter(&h, scope, "sink_unreachable").await;

    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/log-streams/{stream_id}/dead-letters/replay"
    );
    let (status, _, body) = h.post_as(&path, OPERATOR_TOKEN, "lgs-replay-1", "").await;
    assert_eq!(status, StatusCode::ACCEPTED, "replay request: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(document["log_stream_id"], stream_id, "{body}");

    // The command is on the outbox for the replay consumer. Without this the endpoint
    // could answer 202 and drop the request on the floor.
    //
    // Claimed through the DATA store while the request went through the CONTROL-plane HTTP
    // surface, which is the same split the webhook replay test drives and for the same
    // reason. Migration 0099 gives the management plane INSERT on the queue and NOT the
    // UPDATE a claim needs, precisely so a replay is asked for by one plane and executed by
    // the other. Reading it back with the control store fails with `permission denied`,
    // which is the grant working rather than the test being wrong, and driving both halves
    // here means a grant missing on either side fails this rather than production.
    let queued = h
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &ironauth_env::Env::system(),
            ironauth_store::LOG_STREAM_REPLAY_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim the replay command");
    assert_eq!(
        queued.len(),
        1,
        "exactly one replay command must be queued for the worker"
    );
    assert_eq!(
        queued[0].payload["log_stream_id"], stream_id,
        "the command must name the stream it replays"
    );

    // And the domain event is on the feed. Without this the emission is unmeasured, and a
    // replay would be invisible to anyone watching the event stream, which for this
    // subsystem is where operator-visible actions are recorded (there is no audit row: see
    // `request_dead_letter_replay`).
    //
    // POLLED, and the wait is the semantics rather than flakiness dressed up. The feed
    // gates every row on `pg_snapshot_xmin(pg_current_snapshot())`, which is CLUSTER-wide,
    // so a just-committed event is withheld until every transaction open anywhere on the
    // instance has finished, including ones touching other databases.
    //
    // The rate is machine-dependent and worth stating as such rather than as a property of
    // the code. One reviewer measured a single-shot read here failing 5 of 12 runs, with a
    // comment-only edit enough to turn the suite red; a second could not reproduce that on
    // their machine at all, 8 of 8 green with the poll reverted. Both are consistent with a
    // watermark held down by whatever else happens to be open on the cluster, which is
    // exactly why it must not be read once. `events_cursor_ordering.rs` carries the same
    // wait for the same reason, and its comment is the one to read: the wait IS the
    // semantics.
    let feed = format!("/v1/tenants/{tenant}/environments/{environment}/events");
    let mut types: Vec<String> = Vec::new();
    for _ in 0..100 {
        let (status, _, feed_body) = h.get_as(&feed, OPERATOR_TOKEN).await;
        assert_eq!(status, StatusCode::OK, "event feed: {feed_body}");
        let feed_doc: Value = serde_json::from_str(&feed_body).expect("json");
        // `events`, and the type is inside the envelope `payload`, not a sibling field.
        types = feed_doc["events"]
            .as_array()
            .expect("events")
            .iter()
            .filter_map(|item| item["payload"]["type"].as_str())
            .map(ToOwned::to_owned)
            .collect();
        if types
            .iter()
            .any(|kind| kind == "log_stream.replay_requested")
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        types
            .iter()
            .any(|kind| kind == "log_stream.replay_requested"),
        "the replay must announce itself on the event feed: {types:?}"
    );

    // Idempotent: the same key returns the original response and queues nothing more.
    let (again, _, again_body) = h.post_as(&path, OPERATOR_TOKEN, "lgs-replay-1", "").await;
    assert_eq!(
        again,
        StatusCode::ACCEPTED,
        "idempotent replay: {again_body}"
    );
    assert_eq!(again_body, body, "the original response is returned");
}

/// A read-only credential can LIST dead letters and cannot request a replay.
///
/// The split is deliberate and it is the reason the two routes carry different permissions:
/// reading what went undelivered is a status question, and replaying it sends audit events
/// to a third party.
#[tokio::test]
async fn replaying_needs_more_than_reading() {
    let h = Harness::start(73).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-dl-perm").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "lgs-dl-perm-mint").await;
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;

    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let (stream_id, _dead) = seed_dead_letter(&h, scope, "sink_refused_500").await;

    let list = format!(
        "/v1/tenants/{tenant}/environments/{environment}/log-streams/{stream_id}/dead-letters"
    );
    let (status, _, body) = h.get_as(&list, &secret).await;
    assert_eq!(status, StatusCode::OK, "read may list: {body}");

    let replay = format!("{list}/replay");
    let (status, _, body) = h.post_as(&replay, &secret, "lgs-perm-1", "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential must not be able to ship audit events to a sink: {body}"
    );
    // The refusal must NAME the permission, which is what `PERMISSION_PROVEN` means by
    // proven: without it, asserting only the status leaves the SPECIFIC permission unpinned,
    // and substituting `write_config` for another write permission survives the whole crate.
    // An entry in that list claiming more than its test measures is a coverage registry
    // that lies, which is worse than an honest gap in it.
    assert!(
        body.contains("management.write_config"),
        "the refusal must name the permission the route requires: {body}"
    );
}

/// The GET is fenced by `management.read`, and the listing bound is real in both directions.
///
/// Every one of these was a surviving mutant. Removing the permission check on the GET,
/// forcing `truncated` to `false`, and widening the truncation each left the suite green,
/// so the commit message's claim that the listing "bounds itself at 200 and says
/// `truncated` when it did" was unmeasured. The bound itself was correct; nothing held it.
#[tokio::test]
async fn the_listing_is_fenced_and_its_bound_is_real() {
    let h = Harness::start(75).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-dl-bound").await;
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    // A credential with NO management.read cannot list.
    let (deny_id, deny_secret) = mint_key(&h, &tenant, &environment, "lgs-bound-deny").await;
    restrict(
        &h,
        &tenant,
        &environment,
        &deny_id,
        &["management.write_config"],
    )
    .await;
    let (stream_id, _dead) = seed_dead_letter(&h, scope, "sink_refused_502").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/log-streams/{stream_id}/dead-letters"
    );
    let (status, _, body) = h.get_as(&path, &deny_secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "listing undelivered audit needs management.read: {body}"
    );

    // The BOUND, at the boundary. 200 exactly is a complete page and must NOT be reported
    // truncated; 201 must be. An off-by-one in either direction is a number an operator
    // uses to decide whether they have seen their whole gap.
    let env = ironauth_env::Env::system();
    for extra in 0..200_u32 {
        h.control_store()
            .scoped(scope)
            .log_streams()
            .dead_letter(
                &env,
                &stream_id,
                (
                    1_700_000_100_000_000 + i64::from(extra),
                    "aud_bulk_from",
                    1_700_000_200_000_000 + i64::from(extra),
                    "aud_bulk_to",
                ),
                1,
                "sink_refused_502",
            )
            .await
            .expect("record a dead letter");
    }

    let (key_id, secret) = mint_key(&h, &tenant, &environment, "lgs-bound-read").await;
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&path, &secret).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        document["items"].as_array().expect("items").len(),
        200,
        "the page is capped at the documented limit: {body}"
    );
    assert_eq!(
        document["truncated"], true,
        "201 outstanding is more than one page, and an operator must be told: {body}"
    );

    // THE OTHER SIDE of the boundary. With 201 seeded, `>` and `>=` agree, so the arm above
    // alone leaves the comparison unpinned: measured, widening it to `>=` survived. Replay
    // the outstanding set down to exactly 200 and the page must report itself COMPLETE.
    // Reading `truncated: true` on a full-but-complete page tells an operator they have a
    // gap they cannot see, which is the number this endpoint exists to give them.
    let outstanding = h
        .control_store()
        .scoped(scope)
        .log_streams()
        .outstanding_dead_letters(&stream_id)
        .await
        .expect("read");
    assert_eq!(outstanding.len(), 201, "the fixture seeded 201");
    h.control_store()
        .scoped(scope)
        .log_streams()
        .mark_replayed(&env, &outstanding[0].id)
        .await
        .expect("retire one");

    let (status, _, body) = h.get_as(&path, &secret).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        document["items"].as_array().expect("items").len(),
        200,
        "exactly the limit: {body}"
    );
    assert_eq!(
        document["truncated"], false,
        "200 outstanding is a COMPLETE page and must not be reported truncated: {body}"
    );
}

/// The replay POST is sudo-fenced, environment-fenced, and requires an Idempotency-Key.
///
/// Three more surviving mutants. Removing `require_fresh_privilege`, removing
/// `require_live_environment`, and defaulting the Idempotency-Key when absent each left the
/// suite green, so all three guards were present and unmeasured.
#[tokio::test]
async fn the_replay_post_carries_its_three_guards() {
    let h = Harness::start(76).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-dl-guards").await;
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let (stream_id, _dead) = seed_dead_letter(&h, scope, "sink_refused_502").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/log-streams/{stream_id}/dead-letters/replay"
    );

    // No Idempotency-Key at all. Built inline rather than adding a helper to
    // `common/mod.rs`, which every suite in this crate appends to.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(&path)
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {OPERATOR_TOKEN}"),
        )
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::empty())
        .expect("request builds");
    let (status, _, body) = h.send(request).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a replay without an Idempotency-Key must be refused: {body}"
    );

    // A live environment still serves it, so the refusal below is the FENCE and not a
    // permanently broken route.
    let (status, _, body) = h.post_as(&path, OPERATOR_TOKEN, "lgs-guard-live", "").await;
    assert_eq!(status, StatusCode::ACCEPTED, "live control: {body}");

    // The fingerprint covers the PATH, so the same key against a DIFFERENT stream is a
    // conflict rather than a replay of the first stream's response. Without this the
    // fingerprint could be a constant and nothing would notice: one operator's key would
    // silently return another stream's answer.
    let (second_stream, _second_dead) = seed_dead_letter(&h, scope, "sink_refused_504").await;
    let second_path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/log-streams/{second_stream}/dead-letters/replay"
    );
    let (status, _, body) = h
        .post_as(&second_path, OPERATOR_TOKEN, "lgs-guard-live", "")
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "one key must not span two streams: {body}"
    );

    // Soft-delete the environment; the write must refuse.
    let deleted = format!("/v1/tenants/{tenant}/environments/{environment}");
    let (status, _, body) = h.delete_as(&deleted, OPERATOR_TOKEN).await;
    assert!(
        status.is_success(),
        "soft-delete the environment: {status} {body}"
    );
    let (status, _, body) = h
        .post_as(&path, OPERATOR_TOKEN, "lgs-guard-deleted", "")
        .await;
    assert_ne!(
        status,
        StatusCode::ACCEPTED,
        "a soft-deleted environment must not accept a replay: {body}"
    );
}

/// With sudo mode ARMED, a replay needs a fresh elevation.
///
/// `require_fresh_privilege` is a no-op while the flag is off, which is how the harness runs
/// by default, so removing the call from the handler left every other test in this file
/// green. That made the fence present and unmeasured. `Harness::start_with_sudo` arms it.
#[tokio::test]
async fn a_replay_needs_a_fresh_elevation_when_sudo_is_armed() {
    let (h, _clock) = Harness::start_with_sudo(300).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-dl-sudo").await;
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let (stream_id, _dead) = seed_dead_letter(&h, scope, "sink_refused_502").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/log-streams/{stream_id}/dead-letters/replay"
    );

    // Unelevated: refused.
    let (status, _, body) = h.post_as(&path, OPERATOR_TOKEN, "lgs-sudo-1", "").await;
    assert_ne!(
        status,
        StatusCode::ACCEPTED,
        "an unelevated replay must be refused while sudo is armed: {status} {body}"
    );

    // Elevate, then the SAME request is served. Without this arm the assertion above would
    // pass just as well against a route that refused everything.
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/admin/sudo/elevate"),
            "lgs-sudo-elevate",
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "elevate: {body}");
    let (status, _, body) = h.post_as(&path, OPERATOR_TOKEN, "lgs-sudo-2", "").await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "an elevated replay is served: {body}"
    );
}

/// A replay for a stream that does not exist in this scope is REFUSED, not accepted.
///
/// The worst available shape here is 202. `replay_dead_letters` answers `Ok(0)` for a
/// stream it cannot resolve, which is indistinguishable from a successful replay of a
/// stream with nothing outstanding, so an operator watching for their gap to close would
/// wait on a command that was never going to do anything.
///
/// The cross-scope arm is the same refusal on purpose: a stream in another tenant must be a
/// uniform not-found rather than an existence oracle over other tenants' configuration.
/// What DELIVERS that is row-level security on `log_streams`, not the scope predicate in
/// the existence check; measured, removing the predicate leaves this test passing because
/// the foreign row is already invisible to the statement. So this arm pins the OUTCOME an
/// operator sees, and deliberately does not claim to pin which layer produces it.
#[tokio::test]
async fn a_replay_for_an_unknown_stream_is_refused() {
    let h = Harness::start(74).await;
    let (tenant, environment) = h.create_tenant("acme", "lgs-dl-unknown").await;
    let (other_tenant, other_environment) = h.create_tenant("globex", "lgs-dl-other").await;

    let other_scope = Scope::new(
        TenantId::parse(&other_tenant).expect("tenant id"),
        EnvironmentId::parse(&other_environment).expect("environment id"),
    );
    // A REAL stream, in a scope the caller below is not addressing.
    let (foreign_stream, _dead) = seed_dead_letter(&h, other_scope, "sink_refused_503").await;

    for (label, stream) in [
        ("never existed", "lgs_definitely_not_a_stream"),
        ("another tenant's", foreign_stream.as_str()),
    ] {
        let base = format!(
            "/v1/tenants/{tenant}/environments/{environment}/log-streams/{stream}/dead-letters"
        );
        let (status, _, body) = h
            .post_as(
                &format!("{base}/replay"),
                OPERATOR_TOKEN,
                &format!("lgs-unknown-{label}"),
                "",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a replay for a {label} stream must be refused, not accepted: {body}"
        );

        // The LISTING answers the same way. An empty page for a stream that does not exist
        // is indistinguishable from a stream with nothing outstanding, so an operator who
        // mistypes an id reads "no gap" and believes it. Both routes document a 404 for a
        // stream in another scope, and until this the listing could not return one.
        let (status, _, body) = h.get_as(&base, OPERATOR_TOKEN).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "listing a {label} stream's dead letters must not answer an empty page: {body}"
        );
    }

    // And nothing was queued for a worker that could never have served it.
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let queued = h
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &ironauth_env::Env::system(),
            ironauth_store::LOG_STREAM_REPLAY_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert!(
        queued.is_empty(),
        "a refused replay must queue no command: {queued:?}"
    );
}

/// The dead-letter surface splits READING the tail from REPLAYING it (issue #112 criterion 2).
///
/// Both directions for both routes, which is what earns them a place in `PERMISSION_PROVEN`
/// rather than only in `CLASSIFIED`. Classification is a declaration; this is the proof.
///
/// The replay half matters more than the listing half. A replay re-POSTs real signup
/// announcements to a third party, so a credential that may only read must not be able to
/// trigger one, and the refusal has to NAME what it wanted or an operator cannot tell a
/// missing grant from a broken route.
#[tokio::test]
async fn the_flow_target_dead_letter_surface_splits_reading_from_replaying() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "ftg-dlq-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ftg-dlq-mint").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/flow-targets");

    // A live target to address, registered with the write permission the create demands.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, body) = h
        .post_as(
            &base,
            &secret,
            "ftg-dlq-1",
            &serde_json::json!({
                "name": "dlq-probe",
                "target_class": "event",
                "invocation": "async",
                "timing": "post_persist",
                "endpoint": "https://target.example/hook",
                "failure_policy": "fail_closed",
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "register a target: {body}");
    let target_id = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("the registered id")
        .to_owned();
    let dead_letters = format!("{base}/{target_id}/dead-letters");
    let replay = format!("{base}/{target_id}/replay");

    // The REPLAY under write_config is served. Asserted BEFORE the refusals, so a later 403
    // is the permission talking rather than the route being broken or the target absent.
    let (status, _, body) = h.post_as(&replay, &secret, "ftg-dlq-replay-1", "{}").await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "write_config must be able to ask for a replay: {body}"
    );

    // The LISTING is read-classified, so write_config alone is refused and the refusal names
    // what it wanted.
    let (status, _, body) = h.get_as(&dead_letters, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the dead-letter tail answered a credential without management.read: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the refusal must name the permission it wanted: {body}"
    );

    // Read-granted: the listing is served.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&dead_letters, &secret).await;
    assert_eq!(status, StatusCode::OK, "the tail under read: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    assert!(
        document["items"].is_array(),
        "the listing answers with its items array even when empty: {body}"
    );
    assert_eq!(
        document["truncated"],
        serde_json::json!(false),
        "and says whether the cap was reached, which a full page cannot otherwise reveal: {body}"
    );

    // And READ ALONE cannot ask for a replay.
    let (status, _, body) = h.post_as(&replay, &secret, "ftg-dlq-replay-2", "{}").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential asked for a replay and was served: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal must name the permission it wanted: {body}"
    );
}

/// The trust-anchor surface splits reading from registering (issue #126).
///
/// Registering an external issuer decides WHOSE SIGNATURE can mint a token in this
/// environment, which is the most consequential write on the management API: a caller who can
/// add an anchor they control can mint tokens as any principal a mapping names. A read-only
/// credential must not be able to do it, and the refusal must name what it wanted, because
/// substituting one write permission for another would otherwise pass unnoticed.
///
/// The listing is read at a SEEDED anchor rather than an empty environment. An empty
/// environment cannot tell a working listing apart from a handler that answers a constant
/// empty array, so the read half asserts the seeded issuer comes back through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_external_issuer_surface_splits_reading_from_registering() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "exi-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "exi-mint").await;
    let issuers = format!("/v1/tenants/{tenant}/environments/{environment}/external-issuers");

    // Seeded through the BOOTSTRAP operator credential, so what the delegated key can read is
    // measured against a row whose existence does not depend on the grant under test.
    let seeded_issuer = "https://token.actions.githubusercontent.com";
    let (status, _, body) = h
        .post(
            &issuers,
            "exi-seed",
            &serde_json::json!({
                "issuer": seeded_issuer,
                "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed a trust anchor: {body}");
    let seeded_id = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("the registration mints an id")
        .to_owned();

    // Read-granted: served, and the seeded anchor is IN the answer.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&issuers, &secret).await;
    assert_eq!(status, StatusCode::OK, "issuers under read: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    let listed = document["issuers"]
        .as_array()
        .unwrap_or_else(|| panic!("the listing answers with an issuers array: {body}"));
    assert!(
        listed.iter().any(|entry| {
            entry["id"] == serde_json::json!(seeded_id)
                && entry["issuer"] == serde_json::json!(seeded_issuer)
        }),
        "the listing carries the seeded anchor, so it reads the table rather than answering a \
         constant: {body}"
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
    let (status, _, body) = h.get_as(&issuers, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "issuers answered a credential without management.read: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the refusal names the permission it wanted: {body}"
    );

    // And with no credential at all.
    let (status, _, body) = h.get_as(&issuers, "").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "issuers answered an unauthenticated caller: {body}"
    );
}

/// Registering a trust anchor demands `write_config`, and so does disabling one.
///
/// BOTH directions are checked. A surface that gates adding an anchor but not removing one
/// would let a read-scoped credential revoke a federation an operator depends on, which is a
/// denial of service against every workload authenticating through it.
///
/// Each refusal is paired with the SAME request under `write_config`, which is what makes the
/// 403 attributable to the permission. A 403 on its own is also what a route answers when it
/// is misrouted, fenced, or addressing a row that does not exist, so an unpaired refusal
/// would keep passing if the surface stopped working entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn registering_and_disabling_a_trust_anchor_demand_write_config() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "exi-write-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "exi-write-mint").await;
    let issuers = format!("/v1/tenants/{tenant}/environments/{environment}/external-issuers");

    // A LIVE anchor to aim the disable at, seeded through the bootstrap credential. Addressed
    // at a fabricated id the PATCH would answer the uniform not-found for a reason that has
    // nothing to do with the grant, and the ordering of the permission check against the path
    // parse would decide what the test measured.
    let (status, _, body) = h
        .post(
            &issuers,
            "exi-write-seed",
            &serde_json::json!({
                "issuer": "https://token.actions.githubusercontent.com",
                "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed a trust anchor: {body}");
    let anchor_id = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("the registration mints an id")
        .to_owned();
    assert!(
        anchor_id.starts_with("xai_"),
        "a registered anchor is addressed by its scoped `xai_` identifier: {anchor_id}"
    );
    let anchor = format!("{issuers}/{anchor_id}");

    // A SECOND issuer string for the register attempt: the seeded one is taken, and a unique
    // violation would answer 409 for a read-only credential too.
    let register_body = serde_json::json!({
        "issuer": "https://gitlab.example/oidc",
        "jwks_uri": "https://gitlab.example/oauth/discovery/keys",
    })
    .to_string();

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h
        .post_as(&issuers, &secret, "exi-denied", &register_body)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential registered a trust anchor: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal names the permission it wanted: {body}"
    );

    // The same credential must not be able to DISABLE one either.
    let (status, _, body) = h
        .patch_as(
            &anchor,
            &secret,
            &serde_json::json!({"enabled": false}).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential disabled a trust anchor: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the disable refusal names the permission it wanted: {body}"
    );

    // Both requests, unchanged, under `write_config`. Without this half the two refusals above
    // are satisfied by a surface that refuses everyone.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.read", "management.write_config"],
    )
    .await;
    let (status, _, body) = h
        .post_as(&issuers, &secret, "exi-allowed", &register_body)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "write_config registered a trust anchor: {body}"
    );
    let (status, _, body) = h
        .patch_as(
            &anchor,
            &secret,
            &serde_json::json!({"enabled": false}).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "write_config disabled a trust anchor: {body}"
    );

    // The DELETE carries the same fence, in both directions. It is the correction path (a
    // parked row keeps its unique key, so an anchor whose issuer rotated can only be repointed
    // by removing it), which makes it as consequential as the registration: a read-scoped
    // credential able to delete could tear down a federation an operator depends on.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.delete_as(&anchor, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential deleted a trust anchor: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the delete refusal names the permission it wanted: {body}"
    );
    // And the allowed direction, so the refusal above is attributable to the permission
    // rather than to a route that refuses everyone. Aimed at the SECOND anchor this test
    // registered (`https://gitlab.example/oidc`), because the assertion below re-reads the
    // first one to prove the disable landed.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.read", "management.write_config"],
    )
    .await;
    let (status, _, body) = h.get_as(&issuers, &secret).await;
    assert_eq!(status, StatusCode::OK, "list the anchors: {body}");
    let second = serde_json::from_str::<Value>(&body).expect("json")["issuers"]
        .as_array()
        .expect("array")
        .iter()
        .find(|entry| entry["issuer"] == serde_json::json!("https://gitlab.example/oidc"))
        .expect("the second anchor this test registered")["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (status, _, body) = h.delete_as(&format!("{issuers}/{second}"), &secret).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "write_config deleted a trust anchor: {body}"
    );

    // And the disable LANDED, rather than answering 204 over an untouched row.
    let (status, _, body) = h.get_as(&issuers, &secret).await;
    assert_eq!(status, StatusCode::OK, "read the anchors back: {body}");
    let document: Value = serde_json::from_str(&body).expect("json");
    let disabled = document["issuers"]
        .as_array()
        .expect("an issuers array")
        .iter()
        .find(|entry| entry["id"] == serde_json::json!(anchor_id))
        .unwrap_or_else(|| panic!("the disabled anchor is still listed: {body}"));
    assert_eq!(
        disabled["enabled"],
        serde_json::json!(false),
        "the anchor reads back disabled, so the PATCH wrote the row: {body}"
    );
}

/// The subject-mapping surface splits reading from authoring, in both directions.
///
/// A mapping decides which principal a foreign subject BECOMES, so a caller who can author
/// one can mint tokens as any machine identity it names. That is the same authority the
/// anchor carries, and the reason this surface is fenced identically rather than treated as
/// the anchor's lesser half: an attacker who can add a mapping to an issuer they already
/// control needs nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn the_subject_mapping_surface_splits_reading_from_authoring() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "asm-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "asm-mint").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let issuers = format!("{base}/external-issuers");
    let mappings = format!("{base}/subject-mappings");

    // A registered anchor and a real machine identity, both through the bootstrap operator,
    // so a refusal below is the delegated grant rather than a mapping that could not resolve
    // its ends whoever asked.
    let seeded_issuer = "https://token.actions.githubusercontent.com";
    let (status, _, body) = h
        .post(
            &issuers,
            "asm-seed-anchor",
            &serde_json::json!({
                "issuer": seeded_issuer,
                "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "seed a trust anchor: {body}");
    let identity = seed_machine_identity(&h, &tenant, &environment).await;

    let authored = serde_json::json!({
        "issuer": seeded_issuer,
        "external_subject": "repo:acme/widgets:ref:refs/heads/main",
        "principal": identity,
    })
    .to_string();

    // Read-granted: the listing is served.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&mappings, &secret).await;
    assert_eq!(status, StatusCode::OK, "mappings under read: {body}");

    // But READ ALONE cannot author one, and the refusal names what it wanted.
    let (status, _, body) = h.post_as(&mappings, &secret, "asm-denied", &authored).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential authored a subject mapping: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the refusal names the permission it wanted: {body}"
    );

    // A credential holding a WRITE but not read cannot read the listing.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_organizations"],
    )
    .await;
    let (status, _, body) = h.get_as(&mappings, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "mappings answered a credential without management.read: {body}"
    );
    assert!(
        body.contains("management.read"),
        "the refusal names the permission it wanted: {body}"
    );

    // Under write_config both the author and the disable are served, which is what makes the
    // two refusals above attributable to the permission rather than to a broken route.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.read", "management.write_config"],
    )
    .await;
    let (status, _, body) = h
        .post_as(&mappings, &secret, "asm-allowed", &authored)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "write_config authored a subject mapping: {body}"
    );
    let mapping_id = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("the authoring mints an id")
        .to_owned();

    // The disable, refused under read alone and served under write_config.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let disable = serde_json::json!({ "enabled": false }).to_string();
    let (status, _, body) = h
        .patch_as(&format!("{mappings}/{mapping_id}"), &secret, &disable)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential disabled a subject mapping: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the disable refusal names the permission it wanted: {body}"
    );
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.read", "management.write_config"],
    )
    .await;
    let (status, _, body) = h
        .patch_as(&format!("{mappings}/{mapping_id}"), &secret, &disable)
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "write_config disabled a subject mapping: {body}"
    );

    // The DELETE, both directions. Removing a mapping frees its natural key, which is what
    // lets a rule authored against the wrong principal be replaced rather than only parked.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h
        .delete_as(&format!("{mappings}/{mapping_id}"), &secret)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only credential deleted a subject mapping: {body}"
    );
    assert!(
        body.contains("management.write_config"),
        "the delete refusal names the permission it wanted: {body}"
    );
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.read", "management.write_config"],
    )
    .await;
    let (status, _, body) = h
        .delete_as(&format!("{mappings}/{mapping_id}"), &secret)
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "write_config deleted a subject mapping: {body}"
    );
}

/// `management.read` is required AND sufficient for the per-message status endpoint (#111).
///
/// Both directions, because either half alone proves nothing: a test that only asserted the
/// refusal would pass against an endpoint that refused everybody, and one that only asserted
/// the success would pass against an endpoint with no gate at all.
///
/// The message id names no row, so the allowed half answers 404 rather than 200. That is
/// deliberate: what is under test is WHICH PERMISSION reaches the handler, and a 404 proves the
/// gate was passed just as well as a 200 would, while keeping the fixture free of a real send.
/// 403 and 404 are exactly the two answers that separate "refused at the gate" from "allowed
/// through it".
#[tokio::test]
async fn read_is_required_and_sufficient_for_message_status() {
    let h = Harness::start(51).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-message").await;

    // An identifier that reaches no row. It need not parse: the handler gates on the
    // permission BEFORE it parses, so anything past the gate answers 404 either way, and 403
    // versus 404 is exactly what separates "refused at the gate" from "allowed through it".
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/messages/msg_absentmessage");

    // A credential restricted to a DIFFERENT permission, not to none: an empty set could be
    // refused by an earlier check and would say nothing about which permission this requires.
    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, body) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_config credential must not read message status: {body}"
    );

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a read credential must reach the handler, which then reports the absent message: \
         {body}"
    );
}

/// `management.write_users` is required AND sufficient for the message resend (#111).
///
/// Both directions, for the reason the status test gives: refusal-only passes against an
/// endpoint that refuses everybody, and success-only passes against one with no gate.
///
/// The allowed half lands on 404 rather than 200 because the identifier names no message. That
/// is what is wanted here: the question is WHICH PERMISSION reaches the handler, and 403 versus
/// 404 answers it exactly. The endpoint's real outcomes are covered by the store's own tests.
#[tokio::test]
async fn write_users_is_required_and_sufficient_for_message_resend() {
    let h = Harness::start(52).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-resend").await;

    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/messages/msg_absent/resend");

    // A DIFFERENT permission, not an empty set: an empty set could be refused by an earlier
    // check and would say nothing about which permission this endpoint requires.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.post_as(&path, &secret, "k-resend-refused", "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read credential must not re-queue mail: {body}"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_users"],
    )
    .await;
    let (status, _, body) = h.post_as(&path, &secret, "k-resend-allowed", "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a write_users credential must reach the handler, which then reports the absent \
         message: {body}"
    );
}

/// The status endpoint returns the blind index and NEVER the address (issue #111 criterion 1).
///
/// THE TEST THIS FILE WAS MISSING. Every case that touched this route used an identifier that
/// fails `parse_in_scope`, so the handler answered 404 and its whole body -- the query, the
/// view, the hex fold, the serialization -- was never executed by anything. Review replaced
/// `recipient_bidx` with the opened plaintext address and all 741 tests in this crate passed.
/// The behaviour was correct and guarded by nothing, which is the shape a later edit removes.
///
/// So this drives a real 200 and asserts the VALUE, not the shape: a 64-character hex string
/// would be satisfied by a constant, and "contains no address" would be satisfied by an empty
/// body.
#[tokio::test]
async fn message_status_returns_the_blind_index_and_never_the_address() {
    let h = Harness::start(53).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant"),
        EnvironmentId::parse(&environment).expect("environment"),
    );
    let env = ironauth_env::Env::system();

    // Seeded through the store, since no create route exists for a message. The address is
    // distinctive so "the body does not contain it" is a real assertion rather than a
    // coincidence about short strings.
    let address = "ada-status-probe@example.test";
    let id = ironauth_store::MessageId::generate(&env, &scope);
    let bidx: Vec<u8> = (0_u8..32).map(|n| n ^ 0x5a).collect();
    // State and reason in ONE statement: `messages_failure_reason_paired` requires them to
    // agree, so a `failed` row inserted without its reason is refused rather than patched up.
    sqlx::query(
        "INSERT INTO messages \
         (id, tenant_id, environment_id, kind, recipient_bidx, dedup_key, state, \
          failure_reason) \
         VALUES ($1, $2, $3, 'email_otp', $4, $5, 'failed', 'bounced')",
    )
    .bind(id.to_string())
    .bind(&tenant)
    .bind(&environment)
    .bind(&bidx)
    .bind(format!("probe-{id}"))
    .execute(h.db().owner_pool())
    .await
    .expect("seed a message");

    let path = format!("/v1/tenants/{tenant}/environments/{environment}/messages/{id}");
    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "the message exists: {body}");
    let view: Value = serde_json::from_str(&body).expect("a JSON body");

    // THE VALUE, not the shape. Hex of the row's OWN index, computed here from the bytes the
    // fixture inserted rather than by calling the same fold the handler calls.
    let expected: String = {
        use std::fmt::Write as _;
        bidx.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
    };
    assert_eq!(
        view["recipient_bidx"].as_str(),
        Some(expected.as_str()),
        "the index must be THIS message's: a 64-character hex constant would satisfy a \
         shape-only assertion"
    );
    assert_eq!(view["state"], "failed");
    assert_eq!(view["failure_reason"], "bounced");
    assert_eq!(view["kind"], "email_otp");
    assert!(
        view["created_at_unix_ms"].as_i64().is_some_and(|ms| ms > 0)
            && view["updated_at_unix_ms"].as_i64().is_some_and(|ms| ms > 0),
        "a failed message must be datable: {body}"
    );

    // AND NEVER THE ADDRESS. Asserted over the whole serialized body, so a leak through any
    // field fails here, not only through the one the header talks about.
    assert!(
        !body.contains(address) && !body.contains("ada-status-probe"),
        "the response must never carry the recipient: {body}"
    );
}

/// A message id from another scope is not readable, and the refusal reveals nothing.
///
/// What this does and does not prove, stated exactly. The fence is STRUCTURAL: `ScopedId`
/// exposes no scope-blind parse at all, only `parse_in_scope`, which folds "wrong prefix",
/// "not base64", "wrong length" and "wrong scope" into one `NotInScope` carrying no detail. So
/// there is no check here a mutation could delete, and a test claiming to catch one would be
/// claiming something the type system already guarantees.
///
/// What it pins is the OBSERVABLE consequence: that this handler resolves ids through that
/// path rather than by some other lookup, and that the refusal is byte-identical to a garbage
/// identifier's. Both fixtures vary ONE dimension from the caller's scope -- a sibling
/// environment of the same tenant, and a different tenant -- so neither can pass by a
/// comparison that only looks at tenants.
#[tokio::test]
async fn a_message_from_another_scope_is_not_readable_and_the_refusal_reveals_nothing() {
    let h = Harness::start(54).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (other_tenant, other_environment) = h.create_tenant("rival", "k-rival").await;
    let env = ironauth_env::Env::system();

    let sibling_environment = {
        let (status, _, body) = h
            .post(
                &format!("/v1/tenants/{tenant}/environments"),
                "k-sibling",
                &serde_json::json!({ "display_name": "sibling", "kind": "dev" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "seed a sibling env: {body}");
        let created: Value = serde_json::from_str(&body).expect("a JSON body");
        created["id"]
            .as_str()
            .expect("the new environment's id")
            .to_owned()
    };

    // Minted under a SIBLING ENVIRONMENT of the caller's own tenant, and under ANOTHER TENANT.
    let elsewhere = [
        Scope::new(
            TenantId::parse(&tenant).expect("tenant"),
            EnvironmentId::parse(&sibling_environment).expect("sibling"),
        ),
        Scope::new(
            TenantId::parse(&other_tenant).expect("other tenant"),
            EnvironmentId::parse(&other_environment).expect("other environment"),
        ),
    ];

    let (_, _, garbage) = h
        .get(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/messages/not-an-identifier"
        ))
        .await;

    for scope in elsewhere {
        let id = ironauth_store::MessageId::generate(&env, &scope);
        let (status, _, body) = h
            .get(&format!(
                "/v1/tenants/{tenant}/environments/{environment}/messages/{id}"
            ))
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an identifier minted elsewhere must not resolve here: {body}"
        );
        assert_eq!(
            body, garbage,
            "and it must answer EXACTLY as a garbage identifier does, or the difference tells \
             a caller that some other scope's message exists"
        );
    }
}

/// A resend without an Idempotency-Key is refused (issue #111 criterion 1).
///
/// This POST CAUSES MAIL, so a retry that re-executes is a recipient getting the message twice
/// -- the harm the whole `messages` ledger exists to prevent, arriving through the recovery
/// path. The header is required on every POST on this surface, and this endpoint shipped
/// without asking for one.
///
/// Driven at an absent message on purpose: the key check runs before the identifier is parsed,
/// so a 400 here cannot be the endpoint merely failing to find the row (which is a 404).
#[tokio::test]
async fn a_resend_without_an_idempotency_key_is_refused() {
    let h = Harness::start(55).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/messages/msg_absent/resend");

    let (status, _, body) = h.post(&path, "", "").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the Idempotency-Key is required on a POST that mails somebody: {body}"
    );

    // With a key, the same request reaches the handler and reports the absent message. 400 to
    // 404 is what shows the key check opened rather than the route answering the same way for
    // a different reason.
    let (status, _, body) = h.post(&path, "k-resend-present", "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "with a key it reaches the handler: {body}"
    );
}

/// `management.write_config` is required AND sufficient for a claim-mapping write (#113).
///
/// Both directions, for the reason the message-status test gives: refusal-only passes against an
/// endpoint that refuses everybody, and success-only passes against one with no gate.
///
/// The allowed half lands on 404 because the client id names no client in this scope, and that
/// is exactly what is wanted: the question here is WHICH permission reaches the handler, and 403
/// versus 404 answers it. What the endpoint then does with a real client is covered by its own
/// suite.
#[tokio::test]
async fn write_config_is_required_and_sufficient_for_a_claims_mapping_write() {
    let h = Harness::start(63).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-mapping").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/claims-mapping"
    );
    let body = r#"{"rules":[]}"#;

    // A credential restricted to a DIFFERENT permission, not to none: an empty set could be
    // refused by an earlier check and would say nothing about which permission this requires.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.put_as(&path, &secret, body).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read credential must not shape a client's tokens: {response}"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, response) = h.put_as(&path, &secret, body).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a write_config credential must reach the handler, which then reports the absent \
         client: {response}"
    );
}

/// `management.write_config` is required AND sufficient for a claim-mapping DELETE (#113).
///
/// Classified the same as the write, and pinned separately, because the reason is easy to get
/// wrong in both directions. Deleting a mapping RESTORES THE UNMAPPED TOKEN: claims the mapping
/// filtered out come back to the ID token, and a claim it had PLACED in the access token stops
/// reaching one. So a delete is not "a removal of authority" -- it is a change to the shape of
/// every token this client is issued, which is the same thing the write is.
#[tokio::test]
async fn write_config_is_required_and_sufficient_for_a_claims_mapping_delete() {
    let h = Harness::start(64).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-mapping-delete").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/claims-mapping"
    );

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.delete_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read credential must not remove a mapping: {response}"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, response) = h.delete_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a write_config credential must reach the handler: {response}"
    );
}

/// `management.read` is required AND sufficient for a claim-mapping read (#113).
#[tokio::test]
async fn read_is_required_and_sufficient_for_a_claims_mapping_read() {
    let h = Harness::start(65).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-mapping-read").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/claims-mapping"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_users"],
    )
    .await;
    let (status, _, response) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential must not read a mapping: {response}"
    );

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a read credential must reach the handler, which then reports the absent client: \
         {response}"
    );
}

/// `management.write_config` is required AND sufficient for a token-hook DEPLOY (#114).
///
/// Both directions, for the reason every sibling here gives: refusal-only passes against an
/// endpoint that refuses everybody, and success-only passes against one with no gate.
///
/// The allowed half lands on 404 because the client id names no client in this scope, and that
/// is what is wanted -- the question is WHICH permission reaches the handler, and 403 versus
/// 404 answers it. A hook is code running inside the token mint, so this is the most
/// consequential `write_config` on the surface.
#[tokio::test]
async fn write_config_is_required_and_sufficient_for_a_token_hook_deploy() {
    let h = Harness::start(212).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-hook-deploy").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/token-hook?payload_version=1"
    );
    // A real component preamble, so a refusal cannot be the structural check answering instead
    // of the permission gate.
    let body = "\u{0}asm\u{d}\u{0}\u{1}\u{0}";

    // A credential restricted to a DIFFERENT permission, not to none: an empty set could be
    // refused by an earlier check and would say nothing about which permission this requires.
    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.put_as(&path, &secret, body).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read credential must not deploy code into the token mint: {response}"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, response) = h.put_as(&path, &secret, body).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a write_config credential must reach the handler, which then reports the absent \
         client: {response}"
    );
}

/// `management.write_config` is required AND sufficient for a token-hook REMOVAL (#114).
///
/// Pinned separately from the deploy, because the reason is the one that is easy to get wrong.
/// Removing a hook restores the UNSHAPED token: a claim the hook computed stops being minted,
/// so a resource server authorizing on it starts refusing. A removal is not a tidy-up, it is a
/// change to the shape of every token this client is issued, exactly as the deploy is -- which
/// is why it must not be reachable with a weaker credential just because it deletes rather
/// than writes.
#[tokio::test]
async fn write_config_is_required_and_sufficient_for_a_token_hook_removal() {
    let h = Harness::start(213).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-hook-delete").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/token-hook"
    );

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.delete_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read credential must not remove a hook: {response}"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, response) = h.delete_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a write_config credential must reach the handler: {response}"
    );
}

/// `management.read` is required AND sufficient for a token-hook read (#114).
///
/// The read returns metadata rather than the component, but it still answers "is this client's
/// token shaped by code", which is a configuration fact and therefore `read` rather than
/// `write_config`.
#[tokio::test]
async fn read_is_required_and_sufficient_for_a_token_hook_read() {
    let h = Harness::start(214).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-hook-read").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/token-hook"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_users"],
    )
    .await;
    let (status, _, response) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential must not read a hook: {response}"
    );

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a read credential must reach the handler, which then reports the absent client: \
         {response}"
    );
}

/// `management.read` is required AND sufficient for listing a token hook's versions (#114).
#[tokio::test]
async fn read_is_required_and_sufficient_for_listing_token_hook_versions() {
    let h = Harness::start(224).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-hook-versions").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/token-hook/versions"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_users"],
    )
    .await;
    let (status, _, response) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a write_users credential must not read a hook's history: {response}"
    );

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.get_as(&path, &secret).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a read credential must reach the handler, which then reports the absent client. 403 \
         versus 404 is what distinguishes the permission gate from the handler here, exactly \
         as it does for every sibling on this surface: {response}"
    );
}

/// `management.write_config` is required AND sufficient for a token-hook ROLLBACK (#114).
///
/// Classified with the deploy rather than with the read, and pinned separately, because a
/// rollback is a DEPLOY of an older component: it changes what every token this client is
/// issued carries. An operator who can roll a client back to a hook that lacked a
/// security-relevant claim has stripped that claim from every token.
#[tokio::test]
async fn write_config_is_required_and_sufficient_for_a_token_hook_rollback() {
    let h = Harness::start(225).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-hook-rollback").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/applications/cli_absentclient/token-hook/rollback"
    );
    let body = r#"{"version":1}"#;

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, response) = h.post_as(&path, &secret, "k-rollback-denied", body).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read credential must not roll a hook back: {response}"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, response) = h.post_as(&path, &secret, "k-rollback-allowed", body).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a write_config credential reaches the handler, which reports the absent client: \
         {response}"
    );
}
