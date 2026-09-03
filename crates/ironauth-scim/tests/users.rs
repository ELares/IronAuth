// SPDX-License-Identifier: MIT OR Apache-2.0

//! `/scim/v2/Users` over the real router, and the SCIM IDOR suite (issue #135).
//!
//! # The IDOR suite is the point of this file
//!
//! Criterion 5 is that "a valid token for org A cannot read, create, or mutate any resource in
//! org B via any encoding, path traversal, filter, or bulk trick". That is a claim about every
//! door at once, so the cross-organization cases here are written against EVERY method the
//! resource routes serve rather than against the one that seemed most likely: a suite that
//! checked GET and trusted PATCH would have proved nothing about PATCH.
//!
//! # Two organizations, one environment, every time
//!
//! The harness seeds two organizations in the SAME scope, deliberately. A cross-TENANT test
//! would pass on a server whose only defence is the scoped id, and the scoped id is not the
//! interesting half: two organizations inside one environment share a scope, so the
//! membership check is the only thing standing between them.
//!
//! Needs a database.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ironauth_env::Env;
use ironauth_scim::ScimLimits;
use ironauth_scim::server::{ScimState, digest_of, mint_token, scim_router};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, EventCursor, EventPage, GrantId, IssueCode,
    NewRefreshFamily, NewScimConnection, OrganizationId, OutboxMessage, RefreshFamilyId,
    RefreshTokenId, ScimConnectionId, Scope, StoredClientId, UserId, refresh_token_digest,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// One organization and the SCIM token that provisions into it.
struct Tenant {
    token: String,
    organization: OrganizationId,
}

/// A SECOND connection into an organization that already has one.
///
/// What a credential rotation produces: `scim_connections` grants UPDATE only on
/// `(revoked_at, updated_at)`, so a token cannot be rotated in place and a rotation is a new
/// row with a new id.
async fn seed_connection_for(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    secret: &str,
) -> String {
    let id = ScimConnectionId::generate(env, &scope);
    let token = mint_token(&id, secret);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_connections()
        .create(
            env,
            NewScimConnection {
                id: &id,
                organization_id: organization,
                display_name: "rotated",
                provider: "entra",
                token_digest: &digest_of(&token),
                expires_at_unix_micros: None,
            },
            None,
        )
        .await
        .expect("create the second connection");
    token
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str, secret: &str) -> Tenant {
    let org = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &org, now_micros(env), name, None)
        .await
        .expect("create organization");
    let id = ScimConnectionId::generate(env, &scope);
    let token = mint_token(&id, secret);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_connections()
        .create(
            env,
            NewScimConnection {
                id: &id,
                organization_id: &org,
                display_name: name,
                provider: "okta",
                token_digest: &digest_of(&token),
                expires_at_unix_micros: None,
            },
            None,
        )
        .await
        .expect("create connection");
    Tenant {
        token,
        organization: org,
    }
}

/// Drive one request against the real router.
async fn call(
    db: &TestDatabase,
    env: &Env,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, String) {
    call_with(db, env, method, path, token, body, ScimLimits::default()).await
}

/// [`call`] with explicit limits, so a test can drive a bound rather than assert about it.
async fn call_with(
    db: &TestDatabase,
    env: &Env,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    limits: ScimLimits,
) -> (StatusCode, String) {
    call_configured(
        db,
        env,
        method,
        path,
        token,
        body,
        limits,
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    )
    .await
}

/// [`call`] with an explicit UNIQUENESS MODE.
///
/// Every other helper passes `EnvironmentWide`, which is how the mode-aware duplicate check
/// became a vacuous guard: a reviewer replaced its `OrgScoped | NonUnique` arm with the
/// pre-fix unconditional refusal and all 90 tests stayed green, because nothing ever entered
/// it. `ScimState` takes the deployment's mode deliberately, so the suite has to drive more
/// than one of them.
#[allow(clippy::too_many_arguments)]
async fn call_configured(
    db: &TestDatabase,
    env: &Env,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    limits: ScimLimits,
    uniqueness: ironauth_store::identifier::UniquenessMode,
) -> (StatusCode, String) {
    let state = ScimState::new(db.store().clone(), env.clone(), limits, uniqueness);
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request builds");
    let response = scim_router(state)
        .oneshot(request)
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Bind an existing person into a second organization, through the store.
///
/// A shared person cannot be built by `POST`ing the same `userName` twice: under environment-wide
/// uniqueness the second create is a 409, which is correct. In practice a person ends up in two
/// organizations through an invitation accept or an operator, both of which write the
/// membership directly, so that is what this does.
async fn also_a_member_of(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    user: &ironauth_store::UserId,
) {
    let membership = ironauth_store::OrgMembershipId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .create(
            env,
            ironauth_store::NewMembership {
                id: &membership,
                organization_id: organization,
                user_id: user,
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("bind the person into the second organization");
}

/// Create a user through the surface and return its SCIM id.
async fn provision(
    db: &TestDatabase,
    env: &Env,
    token: &str,
    user_name: &str,
    external: &str,
) -> String {
    let (status, body) = call(
        db,
        env,
        "POST",
        "/scim/v2/Users",
        Some(token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": user_name,
            "externalId": external,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a SCIM resource");
    parsed["id"].as_str().expect("an id").to_owned()
}

/// Create a user and return its id AND the `Location` header, for the one test that pins it.
async fn provision_with_location(
    db: &TestDatabase,
    env: &Env,
    token: &str,
    user_name: &str,
) -> (String, String) {
    let state = ScimState::new(
        db.store().clone(),
        env.clone(),
        ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let request = Request::builder()
        .method("POST")
        .uri("/scim/v2/Users")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(Body::from(json!({"userName": user_name}).to_string()))
        .expect("request builds");
    let response = scim_router(state)
        .oneshot(request)
        .await
        .expect("router answers");
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let parsed: Value = serde_json::from_slice(&bytes).expect("a SCIM resource");
    (parsed["id"].as_str().expect("an id").to_owned(), location)
}

#[tokio::test]
async fn a_provisioned_user_round_trips_through_every_read_shape() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let id = provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;

    // By id.
    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{id}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["userName"], "alice@example.test");
    assert_eq!(parsed["externalId"], "00u1alice");
    assert_eq!(parsed["active"], json!(true));

    // By the two filters a provisioning client actually sends, and unfiltered. All three must
    // find the same person: an index path that disagreed with the scan would make an Okta sync
    // create a duplicate on its second run.
    for query in [
        "?filter=userName%20eq%20%22alice@example.test%22",
        "?filter=externalId%20eq%20%2200u1alice%22",
        "",
    ] {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users{query}"),
            Some(&okta.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(1), "{query}: {body}");
        assert_eq!(parsed["Resources"][0]["id"], json!(id), "{query}: {body}");
    }
}

#[tokio::test]
async fn a_second_create_of_the_same_person_is_a_conflict_rather_than_a_second_account() {
    // Criterion 6's consequence at the surface. The canonicalization seam is what decides
    // this, so the second create uses a DIFFERENT spelling of the same handle: a server that
    // compared the raw strings would answer 201 and leave the operator with two accounts for
    // one human and no way to tell which is real.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;

    for spelling in [
        "ALICE@EXAMPLE.TEST",
        "  alice@example.test  ",
        "Alice@Example.Test",
    ] {
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&okta.token),
            Some(json!({"userName": spelling, "externalId": "00u1again"})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{spelling}: {body}");
        assert!(body.contains("uniqueness"), "{spelling}: {body}");
    }
}

#[tokio::test]
async fn both_vendor_patch_dialects_deactivate_the_account() {
    // Okta sends a no-path object; Entra sends a path and a STRINGLY boolean. A server that
    // handled one would answer 200 to the other and leave the account able to sign in, which
    // is the deactivate-did-not-happen failure this whole surface exists to prevent. So each
    // dialect is asserted to have CHANGED the state, not merely to have been accepted.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    for (dialect, patch) in [
        (
            "Okta",
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "value": {"active": false}}],
            }),
        ),
        (
            "Entra",
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
            }),
        ),
    ] {
        let id = provision(
            &db,
            &env,
            &okta.token,
            &format!("{}@example.test", dialect.to_lowercase()),
            &format!("00u1{dialect}"),
        )
        .await;
        let (status, body) = call(
            &db,
            &env,
            "PATCH",
            &format!("/scim/v2/Users/{id}"),
            Some(&okta.token),
            Some(patch),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{dialect}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a resource");
        assert_eq!(parsed["active"], json!(false), "{dialect}: {body}");

        // And it is not merely the rendering: a fresh read agrees.
        let (_, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users/{id}"),
            Some(&okta.token),
            None,
        )
        .await;
        let parsed: Value = serde_json::from_str(&body).expect("a resource");
        assert_eq!(
            parsed["active"],
            json!(false),
            "{dialect} after a re-read: {body}"
        );
    }
}

#[tokio::test]
async fn a_deletion_disables_the_account_and_takes_it_out_of_the_listing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let id = provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;
    let (status, body) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{id}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Gone from this connection's world: the membership is what made it visible.
    let (status, _) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{id}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, body) = call(&db, &env, "GET", "/scim/v2/Users", Some(&okta.token), None).await;
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(0), "{body}");
}

// ---------------------------------------------------------------------------------------
// THE IDOR SUITE (criterion 5).
// ---------------------------------------------------------------------------------------

/// Every path shape a caller could use to name org A's user while holding org B's token.
///
/// The encodings are the CVE-2026-32130 class: that bug was an authentication bypass through
/// URL encoding, and the generalization worth testing is that no spelling of a resource
/// identifier reaches a different authorization decision than the plain one. Percent-encoding
/// is decoded by axum BEFORE the handler runs, so `%2E%2E` and `..` arrive identically and
/// both are simply ids that parse to nothing.
fn encodings(id: &str) -> Vec<String> {
    vec![
        id.to_owned(),
        // Percent-encoded separators.
        id.replace('_', "%5F"),
        // Upper-cased, which a case-insensitive comparison would fold into a match.
        id.to_uppercase(),
        // Traversal, both raw and encoded.
        format!("..%2F{id}"),
        format!("%2E%2E%2F{id}"),
        // A trailing dot segment, which some routers normalize away.
        format!("{id}%2F."),
        // A null byte, which a C-string comparison would truncate at.
        format!("{id}%00"),
    ]
}

#[tokio::test]
async fn a_token_for_one_organization_cannot_read_another_organizations_user() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let victim = provision(
        &db,
        &env,
        &globex.token,
        "victim@example.test",
        "00u1victim",
    )
    .await;

    // The control FIRST: the id is real and its owner can read it. Without this the whole
    // suite would pass against a server that 404s every request.
    let (status, _) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{victim}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the owner can read its own user");

    for spelling in encodings(&victim) {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users/{spelling}"),
            Some(&initech.token),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "org B read org A's user as {spelling}: {body}"
        );
        // And the refusal says NOTHING about whether the resource exists. A 403 here, or a
        // detail mentioning another organization, is the existence oracle the criterion
        // forbids.
        assert!(
            !body.contains("Globex") && !body.contains("victim@example.test"),
            "the refusal leaked something about org A: {body}"
        );
    }
}

#[tokio::test]
async fn a_token_for_one_organization_cannot_mutate_another_organizations_user() {
    // Every MUTATING method, not just the one most likely to be checked. A suite that tested
    // GET and trusted the others would have proved nothing about them: they are separate
    // handlers, and each does its own authorization.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let victim = provision(
        &db,
        &env,
        &globex.token,
        "victim@example.test",
        "00u1victim",
    )
    .await;

    let attempts: Vec<(&str, Option<Value>)> = vec![
        (
            "PUT",
            Some(json!({"userName": "victim@example.test", "active": false})),
        ),
        (
            "PATCH",
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": false}],
            })),
        ),
        ("DELETE", None),
    ];
    for (method, body) in attempts {
        for spelling in encodings(&victim) {
            let (status, answer) = call(
                &db,
                &env,
                method,
                &format!("/scim/v2/Users/{spelling}"),
                Some(&initech.token),
                body.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{method} on org A's user as {spelling}: {answer}"
            );
        }
    }

    // THE POINT, asserted at the end rather than assumed from the statuses: the victim is
    // untouched. A handler that refused with a 404 AFTER writing would pass every assertion
    // above.
    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{victim}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["active"], json!(true), "still enabled: {body}");
}

#[tokio::test]
async fn no_filter_returns_a_user_from_another_organization() {
    // The FILTER trick the criterion names. Both indexed filters resolve through a global
    // index -- the identifier seam is environment-wide, and so is a userName -- so each is a
    // way to name a person by an attribute rather than by an id. The membership check has to
    // hold on that path too, and it is a different code path from the id one.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    provision(
        &db,
        &env,
        &globex.token,
        "victim@example.test",
        "00u1victim",
    )
    .await;

    for query in [
        "filter=userName%20eq%20%22victim@example.test%22",
        "filter=externalId%20eq%20%2200u1victim%22",
        "filter=userName%20co%20%22victim%22",
        "filter=userName%20pr",
        "filter=active%20eq%20true",
        "filter=userName%20ne%20%22nobody%22",
    ] {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users?{query}"),
            Some(&initech.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(0), "{query}: {body}");
        assert!(!body.contains("victim@example.test"), "{query}: {body}");
    }
}

#[tokio::test]
async fn a_create_lands_in_the_credentials_organization_and_nowhere_else() {
    // The CREATE half of the criterion. Two connections provision two people; neither may see
    // the other's, and the only thing deciding that is which credential was presented.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let theirs = provision(&db, &env, &globex.token, "ours@example.test", "00u1ours").await;
    let mine = provision(&db, &env, &initech.token, "mine@example.test", "00u1mine").await;
    assert_ne!(theirs, mine);

    for (token, own, foreign) in [
        (&globex.token, &theirs, &mine),
        (&initech.token, &mine, &theirs),
    ] {
        let (status, _) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users/{own}"),
            Some(token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users/{foreign}"),
            Some(token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, body) = call(&db, &env, "GET", "/scim/v2/Users", Some(token), None).await;
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(1), "{body}");
        assert_eq!(parsed["Resources"][0]["id"], json!(own.as_str()), "{body}");
    }
}

#[tokio::test]
async fn an_external_id_is_this_connections_alone() {
    // Two IdPs provisioning one environment WILL collide on externalId: it is their own key
    // for a person, not a shared one. Both must be able to use `00u1` for two different
    // people, and neither may resolve the other's.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let theirs = provision(&db, &env, &globex.token, "ours@example.test", "shared-key").await;
    let mine = provision(&db, &env, &initech.token, "mine@example.test", "shared-key").await;

    for (token, expected) in [(&globex.token, &theirs), (&initech.token, &mine)] {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            "/scim/v2/Users?filter=externalId%20eq%20%22shared-key%22",
            Some(token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(1), "{body}");
        assert_eq!(
            parsed["Resources"][0]["id"],
            json!(expected.as_str()),
            "{body}"
        );
    }
}

#[tokio::test]
async fn no_resource_route_answers_without_a_credential() {
    // Authentication before authorization, on every resource route. The refusal must be the
    // 401 the discovery routes give, not a 404 that would tell a caller the route exists but
    // the resource does not.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let id = provision(&db, &env, &globex.token, "alice@example.test", "00u1alice").await;

    let routes: Vec<(&str, String, Option<Value>)> = vec![
        ("GET", "/scim/v2/Users".to_owned(), None),
        (
            "POST",
            "/scim/v2/Users".to_owned(),
            Some(json!({"userName": "intruder@example.test"})),
        ),
        ("GET", format!("/scim/v2/Users/{id}"), None),
        (
            "PUT",
            format!("/scim/v2/Users/{id}"),
            Some(json!({"userName": "alice@example.test"})),
        ),
        (
            "PATCH",
            format!("/scim/v2/Users/{id}"),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "value": {"active": false}}],
            })),
        ),
        ("DELETE", format!("/scim/v2/Users/{id}"), None),
    ];
    for (method, path, body) in routes {
        for token in [None, Some("not-a-token"), Some("scim_deadbeef.wrong")] {
            let (status, answer) = call(&db, &env, method, &path, token, body.clone()).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} with {token:?}: {answer}"
            );
        }
    }

    // The control: the account was not disabled by any of the attempts above.
    let (_, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{id}"),
        Some(&globex.token),
        None,
    )
    .await;
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["active"], json!(true), "{body}");
}

// ---------------------------------------------------------------------------------------
// REVIEW ROUND 1. Each of these drives a defect a reviewer reached; each failed before the
// fix it names.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_organization_larger_than_the_scan_bound_is_refused_rather_than_truncated() {
    // BLOCKER. `max_scan` defaulted to 10 000 while the store returns at most 1001 rows from
    // one list call, so `len() > max_scan` was permanently false and the refusal was dead
    // code: 1100 seeded members answered 200 with totalResults 1001 and no sign the answer was
    // partial. A full Okta sync against that reads it as the complete member list and
    // deprovisions everybody it did not see.
    //
    // Driven at a SMALL bound rather than by seeding 1001 people: the bug was that the
    // configured bound could exceed what the store returns, and `scan_bound` now clamps it, so
    // any bound at or below the store's cap is reachable and three members prove the same
    // arithmetic as a thousand.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let limits = ScimLimits {
        max_scan: 2,
        ..ScimLimits::default()
    };

    for who in ["a", "b"] {
        provision(&db, &env, &okta.token, &format!("{who}@example.test"), who).await;
    }
    // AT the bound: answered, in full.
    let (status, body) = call_with(
        &db,
        &env,
        "GET",
        "/scim/v2/Users",
        Some(&okta.token),
        None,
        limits,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(2), "{body}");

    // ONE over: refused, and named as such.
    provision(&db, &env, &okta.token, "c@example.test", "c").await;
    let (status, body) = call_with(
        &db,
        &env,
        "GET",
        "/scim/v2/Users",
        Some(&okta.token),
        None,
        limits,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("tooMany"), "{body}");

    // And the bound is on the SCAN, not on the surface: the indexed filter still answers.
    let (status, body) = call_with(
        &db,
        &env,
        "GET",
        "/scim/v2/Users?filter=userName%20eq%20%22a@example.test%22",
        Some(&okta.token),
        None,
        limits,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(1), "{body}");
}

#[tokio::test]
async fn deactivating_a_shared_person_does_not_reach_the_other_organization() {
    // BLOCKER. `set_active` moved `users.state`, which is a property of the PERSON in the whole
    // environment. A reviewer had Initech's token issue one DELETE and Globex's user could no
    // longer sign in: a cross-organization write through a door that never names Globex.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let shared = provision(
        &db,
        &env,
        &globex.token,
        "shared@example.test",
        "00u1shared",
    )
    .await;
    let shared_id = db
        .store()
        .scoped(scope)
        .users()
        .parse_id(&shared)
        .expect("a user id");
    also_a_member_of(&db, &env, scope, &initech.organization, &shared_id).await;

    // Initech deactivates. Globex must not notice.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{shared}"),
        Some(&initech.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": false}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["active"], json!(false), "Initech's own view: {body}");

    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{shared}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Globex lost the person: {body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(
        parsed["active"],
        json!(true),
        "Globex's user was deactivated by another organization: {body}"
    );
    // And the ACCOUNT is still live, which is the half a status check would miss: the person
    // has to be able to sign in to Globex.
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .state_for_subject(&shared)
            .await
            .expect("read the account state"),
        Some(ironauth_store::UserState::Active),
        "one organization's deactivate must not disable a shared account"
    );

    // Initech's DELETE is the stronger act and must also not reach Globex.
    let (status, _) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{shared}"),
        Some(&initech.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{shared}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["active"], json!(true), "{body}");
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .state_for_subject(&shared)
            .await
            .expect("read the account state"),
        Some(ironauth_store::UserState::Active)
    );
}

#[tokio::test]
async fn a_deactivated_person_stays_addressable_and_can_be_reactivated() {
    // The reason a deactivate keeps the membership. An identity provider reactivates BY
    // RESOURCE ID after a rehire or a sync blip, so an implementation that removed the
    // membership on deactivate would answer the uniform 404 to that PATCH and leave the client
    // with no way to undo its own deactivation.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let alice = provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;

    let deactivate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": false}],
    });
    let reactivate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });

    for (what, patch, expected) in [
        ("deactivated", &deactivate, false),
        ("reactivated", &reactivate, true),
        // Twice each way: an identity provider retries, and a second deactivate of an already
        // deactivated person must not fail.
        ("deactivated again", &deactivate, false),
        ("deactivated once more", &deactivate, false),
        ("reactivated again", &reactivate, true),
    ] {
        let (status, body) = call(
            &db,
            &env,
            "PATCH",
            &format!("/scim/v2/Users/{alice}"),
            Some(&okta.token),
            Some(patch.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{what}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a resource");
        assert_eq!(parsed["active"], json!(expected), "{what}: {body}");

        // Still addressable, and a fresh read agrees with the response.
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users/{alice}"),
            Some(&okta.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{what} then read: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a resource");
        assert_eq!(parsed["active"], json!(expected), "{what}: {body}");

        // And the ACCOUNT follows, because this is the person's only organization.
        let account = db
            .store()
            .scoped(scope)
            .users()
            .state_for_subject(&alice)
            .await
            .expect("read the account state");
        let wanted = if expected {
            ironauth_store::UserState::Active
        } else {
            ironauth_store::UserState::Disabled
        };
        assert_eq!(account, Some(wanted), "{what}");
    }
}

#[tokio::test]
async fn deactivating_the_last_organizations_member_does_disable_the_account() {
    // The OTHER half of the rule, and the control for the test above: without it, the
    // isolation fix would pass on an implementation that never disabled anybody, which is the
    // opposite failure -- an identity provider that offboarded somebody would have left them
    // able to sign in.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let alone = provision(&db, &env, &globex.token, "alone@example.test", "00u1alone").await;
    let (status, _) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{alone}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let state = db
        .store()
        .scoped(scope)
        .users()
        .state_for_subject(&alone)
        .await
        .expect("read the account state");
    assert_eq!(
        state,
        Some(ironauth_store::UserState::Disabled),
        "the person's last organization deactivating them offboards the account"
    );
}

#[tokio::test]
async fn a_create_does_not_reveal_whether_another_organization_holds_the_handle() {
    // MAJOR. The duplicate pre-check searched the whole ENVIRONMENT, so a 409 told the caller
    // that somebody somewhere holds the handle. Under environment-wide uniqueness the refusal
    // is genuine -- the create really cannot succeed -- so what must not differ is the refusal
    // a caller can ATTRIBUTE: the status and body for a handle held elsewhere are identical to
    // the ones for a handle held here, and neither names an organization or a person.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    provision(
        &db,
        &env,
        &globex.token,
        "victim@example.test",
        "00u1victim",
    )
    .await;
    provision(&db, &env, &initech.token, "mine@example.test", "00u1mine").await;

    let (foreign_status, foreign_body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&initech.token),
        Some(json!({"userName": "victim@example.test"})),
    )
    .await;
    let (own_status, own_body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&initech.token),
        Some(json!({"userName": "mine@example.test"})),
    )
    .await;
    assert_eq!(
        (foreign_status, foreign_body.as_str()),
        (own_status, own_body.as_str()),
        "a handle held by another organization must be refused exactly as one held here is"
    );
    assert!(
        !foreign_body.contains("Globex") && !foreign_body.contains("victim"),
        "the refusal names nothing about the other organization: {foreign_body}"
    );
}

#[tokio::test]
async fn a_duplicate_external_id_creates_nothing() {
    // MAJOR. `bind` ran after three committed writes, so a duplicate externalId answered 409
    // with the account, its identifier row and its organization membership already created:
    // the client was told nothing was created and the organization gained a member.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    provision(&db, &env, &okta.token, "first@example.test", "shared-key").await;
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&okta.token),
        Some(json!({"userName": "second@example.test", "externalId": "shared-key"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("uniqueness"), "{body}");

    let (_, body) = call(&db, &env, "GET", "/scim/v2/Users", Some(&okta.token), None).await;
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(
        parsed["totalResults"],
        json!(1),
        "a refused create must leave the organization exactly as it was: {body}"
    );
    // And the person it refused is not resolvable by handle either, so nothing partial landed.
    let (_, body) = call(
        &db,
        &env,
        "GET",
        "/scim/v2/Users?filter=userName%20eq%20%22second@example.test%22",
        Some(&okta.token),
        None,
    )
    .await;
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(0), "{body}");
}

#[tokio::test]
async fn a_patch_that_cannot_be_completed_applies_none_of_it() {
    // MAJOR. RFC 7644 section 3.5.2: a PatchOp "SHALL be treated as atomic. If a single
    // operation encounters an error condition, the original SCIM resource MUST be restored."
    // The loop validated and applied one operation at a time, so a reviewer sent
    // [deactivate, unsupported] and got a 400 with the account deactivated.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let alice = provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;

    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "active", "value": false},
                {"op": "replace", "path": "nickName", "value": "al"},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(
        parsed["active"],
        json!(true),
        "the first operation must not have been applied: {body}"
    );

    // The control: the SAME first operation, alone, does deactivate. Without it this test
    // passes on a PATCH that never applies anything.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": false}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(
        parsed["active"],
        json!(false),
        "the same operation ALONE does deactivate: {body}"
    );
}

#[tokio::test]
async fn the_create_door_and_the_read_door_agree_on_who_exists() {
    // MAJOR. The indexed lookup canonicalizes (NFKC, case fold, whitespace and zero-width
    // stripping) and the filter evaluator only lowercases, so the list re-checked the index's
    // answer with a weaker comparison and threw it away. A reviewer found the deadlock: with
    // `admin` stored, POST "ad min" was a 409 and filter=userName eq "ad min" was empty, so a
    // client sending that spelling could neither find the person nor create them.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let admin = provision(&db, &env, &okta.token, "admin", "00u1admin").await;

    for spelling in ["ad min", "  admin  ", "ADMIN", "Ad\u{200d}min"] {
        // The create door says this person exists.
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&okta.token),
            Some(json!({"userName": spelling})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{spelling:?}: {body}");

        // So the read door must find them.
        // Percent-encode every byte that is not an unreserved character, so the spelling
        // reaches the handler exactly as written: the interesting cases are a space, a
        // zero-width joiner and surrounding whitespace, none of which survive a raw query
        // string.
        let mut encoded = String::new();
        for byte in spelling.as_bytes() {
            if byte.is_ascii_alphanumeric() {
                encoded.push(char::from(*byte));
            } else {
                use std::fmt::Write as _;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users?filter=userName%20eq%20%22{encoded}%22"),
            Some(&okta.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{spelling:?}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(1), "{spelling:?}: {body}");
        assert_eq!(
            parsed["Resources"][0]["id"],
            json!(admin.as_str()),
            "{spelling:?}: {body}"
        );
    }

    // The control: a genuinely different handle is still not this person.
    let (_, body) = call(
        &db,
        &env,
        "GET",
        "/scim/v2/Users?filter=userName%20eq%20%22admin2%22",
        Some(&okta.token),
        None,
    )
    .await;
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(0), "{body}");
}

#[tokio::test]
async fn a_create_answers_the_location_of_the_resource_it_created() {
    // RFC 7644 section 3.3 says the Location header SHALL carry the URI of the CREATED
    // RESOURCE. A constant naming the collection satisfies nothing, and Entra follows this
    // header to read the resource back.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let (id, location) =
        provision_with_location(&db, &env, &okta.token, "alice@example.test").await;
    assert_eq!(location, format!("/scim/v2/Users/{id}"));

    // And following it reaches the resource, which is the only thing the header is for.
    let (status, body) = call(&db, &env, "GET", &location, Some(&okta.token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["id"], json!(id.as_str()));
    assert_eq!(parsed["meta"]["location"], json!(location.as_str()));
}

#[tokio::test]
async fn an_external_id_is_never_read_across_connections() {
    // The `AND connection_id = $3` in `external_id_for`, which a reviewer removed with every
    // suite still green. Without it a read renders whichever connection's key happens to be
    // stored for the person, which is the whole thing the per-connection namespace exists to
    // prevent. Asserted on the RENDERED resource, because that is where the leak would show.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let shared = provision(
        &db,
        &env,
        &globex.token,
        "shared@example.test",
        "globex-key",
    )
    .await;
    let shared_id = db
        .store()
        .scoped(scope)
        .users()
        .parse_id(&shared)
        .expect("a user id");
    also_a_member_of(&db, &env, scope, &initech.organization, &shared_id).await;

    // Initech records its OWN key for the same person, through its own credential.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{shared}"),
        Some(&initech.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "externalId", "value": "initech-key"}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for (token, own, foreign) in [
        (&globex.token, "globex-key", "initech-key"),
        (&initech.token, "initech-key", "globex-key"),
    ] {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users/{shared}"),
            Some(token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let parsed: Value = serde_json::from_str(&body).expect("a resource");
        assert_eq!(parsed["externalId"], json!(own), "{body}");
        assert!(!body.contains(foreign), "the other key leaked: {body}");
    }

    // Nor through the filter: each connection resolves only its own key, and neither resolves
    // the other's even though both name the same person.
    for (token, own, foreign) in [
        (&globex.token, "globex-key", "initech-key"),
        (&initech.token, "initech-key", "globex-key"),
    ] {
        for (key, expected) in [(own, 1), (foreign, 0)] {
            let (status, body) = call(
                &db,
                &env,
                "GET",
                &format!("/scim/v2/Users?filter=externalId%20eq%20%22{key}%22"),
                Some(token),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{key}: {body}");
            let parsed: Value = serde_json::from_str(&body).expect("a list");
            assert_eq!(parsed["totalResults"], json!(expected), "{key}: {body}");
        }
    }
}

#[tokio::test]
async fn a_malformed_query_string_does_not_answer_an_unauthenticated_caller() {
    // `Query<T>` is a `FromRequestParts` extractor, so with typed fields it ran BEFORE
    // authentication: `?count=abc` with no credential answered a plain-text 400 "Failed to
    // deserialize query string", the one response on this surface that is neither a SCIM error
    // document nor the uniform 401.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    for query in [
        "?count=abc",
        "?startIndex=notanumber",
        "?count=-1&startIndex=",
    ] {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users{query}"),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{query}: {body}");
        assert!(
            body.contains("urn:ietf:params:scim:api:messages:2.0:Error"),
            "{query}: {body}"
        );
    }

    // Authenticated, the same values are tolerated rather than refused: a mistyped number is
    // not a reason to fail a provisioning client's list.
    provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;
    for query in ["?count=abc", "?startIndex=notanumber"] {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users{query}"),
            Some(&okta.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(1), "{query}: {body}");
    }
}

// ---------------------------------------------------------------------------------------
// REVIEW ROUND 2.
// ---------------------------------------------------------------------------------------

/// The three modes a deployment can configure, so a test that only drives one is visibly
/// incomplete rather than quietly so.
const MODES: [ironauth_store::identifier::UniquenessMode; 3] = [
    ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    ironauth_store::identifier::UniquenessMode::OrgScoped,
    ironauth_store::identifier::UniquenessMode::NonUnique,
];

#[tokio::test]
async fn a_create_works_under_every_configured_uniqueness_mode() {
    // BLOCKER. `land_account` wrote the identifier row before the membership, and
    // `ActingUserIdentifierRepo::add` refuses an identifier for a non-member under
    // `OrgScoped` -- so on an org-scoped deployment EVERY create answered 500, after
    // `register_passwordless` had already committed. The surface worked in exactly one of the
    // three modes it takes as a parameter.
    for mode in MODES {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let scope = db.seed_scope(&env).await;
        let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

        let (status, body) = call_configured(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&okta.token),
            Some(json!({"userName": "alice@example.test", "externalId": "00u1alice"})),
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{mode:?}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a resource");
        let id = parsed["id"].as_str().expect("an id");

        // And the person is fully landed, not half: resolvable by handle, which needs the
        // identifier row, and visible in the listing, which needs the membership.
        let (status, body) = call_configured(
            &db,
            &env,
            "GET",
            "/scim/v2/Users?filter=userName%20eq%20%22alice@example.test%22",
            Some(&okta.token),
            None,
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{mode:?}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(1), "{mode:?}: {body}");
        assert_eq!(parsed["Resources"][0]["id"], json!(id), "{mode:?}: {body}");
    }
}

#[tokio::test]
async fn one_handle_is_one_account_under_every_configured_mode() {
    // Round 1 asked for a mode-aware duplicate check on the reasoning that under `OrgScoped`
    // the store would accept a second organization's copy of a handle. It does not:
    // `users_identifier_bidx_unique` (migration 0028) is
    // `UNIQUE (tenant_id, environment_id, identifier_bidx)`, so one login handle is one ACCOUNT
    // per environment whatever the mode is. That mode governs `user_identifiers` -- the extra
    // identifiers an account may carry -- not the account row a create makes.
    //
    // Driving all three modes is what turned that reasoning from plausible to checked: the
    // mode-aware branch answered 500 under `OrgScoped`, because the create it let through then
    // hit the constraint inside `register_passwordless`.
    for mode in MODES {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let scope = db.seed_scope(&env).await;
        let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
        let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

        let (status, body) = call_configured(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&globex.token),
            Some(json!({"userName": "shared@example.test"})),
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{mode:?}: {body}");

        // The second organization is refused, and refused as a CONFLICT rather than as a 500
        // from a constraint it was allowed to reach.
        let (status, body) = call_configured(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&initech.token),
            Some(json!({"userName": "shared@example.test"})),
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{mode:?}: {body}");
        assert!(body.contains("uniqueness"), "{mode:?}: {body}");

        // And nothing landed: the refused organization has no members.
        let (_, body) = call_configured(
            &db,
            &env,
            "GET",
            "/scim/v2/Users",
            Some(&initech.token),
            None,
            ScimLimits::default(),
            mode,
        )
        .await;
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(0), "{mode:?}: {body}");
    }
}

#[tokio::test]
async fn a_create_cannot_pull_another_organizations_live_user_into_this_one() {
    // The re-admit's gate, and the reason it needs one. "Not currently a member of MY
    // organization" is true of every user in the environment, so a re-admit conditioned on
    // that alone lets any credential take another organization's live user by POSTing their
    // handle. An earlier version of `readmit` did exactly that, and this is the test that
    // caught it -- it answered 201 where a 409 was required.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let victim = provision(
        &db,
        &env,
        &globex.token,
        "victim@example.test",
        "00u1victim",
    )
    .await;
    for (what, body) in [
        ("by handle", json!({"userName": "victim@example.test"})),
        (
            "by handle and a fresh key",
            json!({"userName": "victim@example.test", "externalId": "00u9mine"}),
        ),
    ] {
        let (status, answer) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&initech.token),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{what}: {answer}");
        assert!(
            !answer.contains(victim.as_str()),
            "{what}: the refusal named the person: {answer}"
        );
    }

    // And the victim is untouched: still Globex's, still active, still not Initech's.
    let (_, body) = call(
        &db,
        &env,
        "GET",
        "/scim/v2/Users",
        Some(&initech.token),
        None,
    )
    .await;
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(0), "{body}");
    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{victim}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["active"], json!(true), "{body}");
}

#[tokio::test]
async fn an_environment_wide_deployment_still_refuses_a_handle_another_organization_holds() {
    // The other side of the same guard. Without this the mode-aware check would pass on an
    // implementation that never refused anything, which would break the uniqueness the
    // environment-wide mode exists to provide.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    provision(
        &db,
        &env,
        &globex.token,
        "shared@example.test",
        "00u1shared",
    )
    .await;
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&initech.token),
        Some(json!({"userName": "shared@example.test"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn a_deleted_person_can_be_provisioned_again() {
    // BLOCKER. DELETE removes the membership but nothing releases the identifier row or this
    // connection's externalId mapping, so every route back was closed: a reviewer deleted a
    // person and found the re-POST answered 409 in all three spellings and PATCH answered 404.
    // An Okta rehire was unrecoverable through SCIM.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let alice = provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;
    let (status, _) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted, so not visible");

    // Every spelling an identity provider would use for the rehire.
    for (what, body) in [
        (
            "the same handle and the same key",
            json!({"userName": "alice@example.test", "externalId": "00u1alice"}),
        ),
        // A NEW key for a person this connection already knows by another one is NOT here: it
        // is a 409 `mutability`, because the mapping cannot be repointed, and
        // `a_re_admit_with_a_different_external_id_is_refused_rather_than_silently_kept`
        // drives it. An earlier version of this test asserted 201 for that shape and so
        // encoded the defect: the client was handed a resource carrying a key it did not send.
        (
            "a new handle and the old key",
            json!({"userName": "alice2@example.test", "externalId": "00u1alice"}),
        ),
    ] {
        // Take them out again between attempts, so each spelling is driven from the same
        // state rather than the second finding the first's re-admit.
        let (status, answer) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&okta.token),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{what}: {answer}");
        let parsed: Value = serde_json::from_str(&answer).expect("a resource");
        // The SAME id they had: a re-admit is the person coming back, not a second account,
        // and the client's stored reference points at the old id.
        assert_eq!(parsed["id"], json!(alice.as_str()), "{what}: {answer}");
        // And the STORED handle, not the requested one. A rename cannot be applied here for
        // the same reason `replace_user` refuses one, so the response says what the person is
        // actually called rather than echoing what was asked for.
        assert_eq!(
            parsed["userName"],
            json!("alice@example.test"),
            "{what}: {answer}"
        );
        // And ACTIVE, because the deactivation their delete recorded must not survive the
        // re-admit: a 201 carrying `active: false` is a person the client believes it just
        // provisioned who cannot sign in.
        assert_eq!(parsed["active"], json!(true), "{what}: {answer}");
        assert_eq!(
            db.store()
                .scoped(scope)
                .users()
                .state_for_subject(&alice)
                .await
                .expect("read the account state"),
            Some(ironauth_store::UserState::Active),
            "{what}"
        );

        let (status, _) = call(
            &db,
            &env,
            "DELETE",
            &format!("/scim/v2/Users/{alice}"),
            Some(&okta.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{what}");
    }
}

#[tokio::test]
async fn a_duplicate_of_a_live_member_is_still_a_conflict() {
    // The control for the re-admit. Without it, "a deleted person can be provisioned again"
    // would pass on an implementation that answered 201 to EVERY duplicate, which would make
    // a retried create look like a success and hide a genuine collision.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;
    for (what, body) in [
        (
            "the same handle",
            json!({"userName": "alice@example.test", "externalId": "00u9new"}),
        ),
        (
            "the same externalId",
            json!({"userName": "someone@example.test", "externalId": "00u1alice"}),
        ),
    ] {
        let (status, answer) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&okta.token),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{what}: {answer}");
    }
}

#[tokio::test]
async fn a_provisioning_client_cannot_lift_an_administrative_block() {
    // The reactivation guard, which a reviewer showed was vacuous: deleting the three lines
    // that refuse to move anything but `Disabled` left all 28 tests green, and nothing in the
    // crate mentioned `Blocked`, `Waitlisted` or `ScheduledOffboarding`.
    //
    // A person in one of those states is there because an operator or another subsystem put
    // them there. `active: true` from a provisioning client must not undo that.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let alice = provision(&db, &env, &okta.token, "alice@example.test", "00u1alice").await;
    let alice_id = db
        .store()
        .scoped(scope)
        .users()
        .parse_id(&alice)
        .expect("a user id");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state(
            &env,
            &alice_id,
            ironauth_store::UserState::Blocked,
            ironauth_store::OffboardingSchedule {
                at_unix_micros: None,
                wake_payload: None,
            },
            false,
            None,
        )
        .await
        .expect("an operator blocks the account");

    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": true}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .state_for_subject(&alice)
            .await
            .expect("read the account state"),
        Some(ironauth_store::UserState::Blocked),
        "a provisioning client must not be able to lift an administrative block"
    );

    // THE CONTROL: the same PATCH DOES reactivate a merely disabled account. Without it this
    // passes on an implementation that never reactivates anybody.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state(
            &env,
            &alice_id,
            ironauth_store::UserState::Disabled,
            ironauth_store::OffboardingSchedule {
                at_unix_micros: None,
                wake_payload: None,
            },
            false,
            None,
        )
        .await
        .expect("an operator disables the account");
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{alice}"),
        Some(&okta.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": true}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .state_for_subject(&alice)
            .await
            .expect("read the account state"),
        Some(ironauth_store::UserState::Active)
    );
}

// ---------------------------------------------------------------------------------------
// REVIEW ROUND 3.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_re_admit_honours_the_active_flag_and_the_external_id_it_carries() {
    // BLOCKER. The re-admit branch returned before the `active` apply and before the
    // externalId bind, so a staged re-create came back ENABLED however the request asked, and
    // a re-admit carrying a key bound nothing: the client was handed a resource with no
    // externalId at all, or with the OLD one, and no route to the key it sent.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    // (a) a person provisioned with NO key, re-created WITH one and staged inactive.
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&okta.token),
        Some(json!({"userName": "bob@example.test"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let bob = serde_json::from_str::<Value>(&body).expect("a resource")["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (status, _) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{bob}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&okta.token),
        Some(json!({
            "userName": "bob@example.test",
            "externalId": "00uBOB",
            "active": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["id"], json!(bob.as_str()), "{body}");
    assert_eq!(
        parsed["externalId"],
        json!("00uBOB"),
        "the key the request carried must be bound: {body}"
    );
    assert_eq!(
        parsed["active"],
        json!(false),
        "a staged re-create must not enable the account: {body}"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .state_for_subject(&bob)
            .await
            .expect("read the account state"),
        Some(ironauth_store::UserState::Disabled),
        "and the account itself is disabled, not merely rendered so"
    );
}

#[tokio::test]
async fn a_re_admit_with_a_different_external_id_is_refused_rather_than_silently_kept() {
    // BLOCKER, the other half. The mapping table holds no UPDATE and no DELETE grant, so a key
    // that is bound cannot be moved. Answering 201 anyway handed the client a resource
    // carrying a key it did not send, with no route to the one it did -- and the repairing PUT
    // then answered 409.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let carol = provision(&db, &env, &okta.token, "carol@example.test", "00uOLD").await;
    let (status, _) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{carol}"),
        Some(&okta.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&okta.token),
        Some(json!({"userName": "carol@example.test", "externalId": "00uNEW"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("mutability"), "{body}");

    // The control: the SAME key succeeds, so the refusal is the disagreement and not a
    // re-admit that never works when a key is present.
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&okta.token),
        Some(json!({"userName": "carol@example.test", "externalId": "00uOLD"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["id"], json!(carol.as_str()), "{body}");
    assert_eq!(parsed["externalId"], json!("00uOLD"), "{body}");
}

#[tokio::test]
async fn a_re_admit_names_the_person_whose_handle_was_asked_for() {
    // BLOCKER. Under `OrgScoped` and `NonUnique`, `user_identifiers` can hold a handle as a
    // SECONDARY identifier of somebody whose account handle is something else. The re-admit
    // loop took the first resolution without checking, so a reviewer asked for
    // `alice@example.test` and got a 201 naming BOB. Nothing crossed an organization, but
    // every later group push and role assignment for alice would have landed on bob.
    for mode in [
        ironauth_store::identifier::UniquenessMode::OrgScoped,
        ironauth_store::identifier::UniquenessMode::NonUnique,
    ] {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let scope = db.seed_scope(&env).await;
        let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
        let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

        // Globex holds alice. Initech holds bob.
        let (status, body) = call_configured(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&globex.token),
            Some(json!({"userName": "alice@example.test"})),
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{mode:?}: {body}");
        let (status, body) = call_configured(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&initech.token),
            Some(json!({"userName": "bob@example.test"})),
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{mode:?}: {body}");
        let bob = serde_json::from_str::<Value>(&body).expect("a resource")["id"]
            .as_str()
            .expect("an id")
            .to_owned();
        let bob_id = db
            .store()
            .scoped(scope)
            .users()
            .parse_id(&bob)
            .expect("a user id");

        // An operator gives bob alice's handle as a SECOND identifier, which this mode allows.
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .user_identifiers()
            .add(
                &env,
                ironauth_store::NewUserIdentifier {
                    id: &ironauth_store::UserIdentifierId::generate(&env, &scope),
                    user_id: &bob_id,
                    identifier_type: ironauth_store::IdentifierType::Email,
                    raw: "alice@example.test",
                    verified: false,
                    mode,
                    org: Some(&initech.organization.to_string()),
                },
                None,
            )
            .await
            .expect("a second identifier for bob");

        // Initech deactivates and deletes bob, then asks for ALICE.
        let (status, _) = call_configured(
            &db,
            &env,
            "DELETE",
            &format!("/scim/v2/Users/{bob}"),
            Some(&initech.token),
            None,
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{mode:?}");

        let (status, body) = call_configured(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&initech.token),
            Some(json!({"userName": "alice@example.test"})),
            ScimLimits::default(),
            mode,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{mode:?}: asking for alice must never answer with bob: {body}"
        );
        assert!(!body.contains(bob.as_str()), "{mode:?}: {body}");
    }
}

#[tokio::test]
async fn a_deactivated_member_is_a_conflict_rather_than_a_re_admit() {
    // The membership half of `readmittable`, which a reviewer showed was vacuous: deleting it
    // left all 107 tests green. A person this organization deactivated but still HOLDS is a
    // live resource -- a client reactivates them with `active: true`, and a create naming them
    // is an ordinary duplicate.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let okta = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let frank = provision(&db, &env, &okta.token, "frank@example.test", "00uFRANK").await;

    // Deactivate WITHOUT deleting, which keeps the membership.
    let (status, _) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{frank}"),
        Some(&okta.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": false}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&okta.token),
        Some(json!({"userName": "frank@example.test", "externalId": "00uFRANK"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // THE SPECIFIC refusal, not merely a 409. Removing the membership half of `readmittable`
    // makes this a re-admit whose `restore_membership` then collides with the live membership
    // and answers its own 409, so a bare status assertion passes under the mutation it exists
    // to catch. The detail distinguishes the duplicate refusal from the collision.
    assert!(
        body.contains("a user with this userName already exists"),
        "refused as a duplicate rather than by a collision downstream: {body}"
    );
    // And the person is untouched: still deactivated, not reactivated by a re-admit that ran.
    let (_, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{frank}"),
        Some(&okta.token),
        None,
    )
    .await;
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["active"], json!(false), "{body}");

    // And exactly ONE membership, so a re-admit that ran anyway would show up here.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{frank}"),
        Some(&okta.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": true}],
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "reactivation is the route back: {body}"
    );
    let (_, body) = call(&db, &env, "GET", "/scim/v2/Users", Some(&okta.token), None).await;
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(1), "{body}");
}

/// The Enterprise User extension round-trips: sent on create, read back on GET and on the list.
///
/// `/Schemas` published this extension from the day the surface shipped and `ScimUser` parsed
/// none of it, so an Entra push carrying `employeeNumber` and `department` was answered
/// `201 Created` with the attributes silently dropped. That is the advertise-what-you-do-not-do
/// defect this crate has now been caught by twice, and a provisioning client has no way to see
/// it: the create succeeds and the read simply omits what it sent.
#[tokio::test]
async fn the_enterprise_extension_round_trips_through_create_and_read() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let body = json!({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        ],
        "userName": "ada@example.com",
        "active": true,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": "701",
            "department": "Tools",
        },
    });
    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let parsed: Value = serde_json::from_str(&created).expect("json");
    let id = parsed["id"].as_str().expect("id").to_owned();

    // THE CREATE ITSELF carries it back, which is what a client reads to confirm the write.
    let extension = &parsed["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("701"),
        "{created}"
    );
    assert_eq!(extension["department"].as_str(), Some("Tools"), "{created}");
    // AND THE SCHEMAS LIST DECLARES IT. RFC 7643 section 3 says a resource names every schema
    // its attributes come from, and a client dispatching on that list would not look for the
    // extension without it.
    assert!(
        parsed["schemas"]
            .as_array()
            .expect("schemas")
            .iter()
            .any(|urn| urn.as_str()
                == Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")),
        "the resource must declare the extension schema: {created}"
    );

    // A FRESH READ, which is the assertion that separates "echoed the request" from "stored it".
    let (status, fetched) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{id}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    let parsed: Value = serde_json::from_str(&fetched).expect("json");
    assert_eq!(
        parsed["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["employeeNumber"]
            .as_str(),
        Some("701"),
        "the extension must survive a fresh read: {fetched}"
    );

    // AND ON THE LISTING, because a client filtering on an extension attribute evaluates the
    // filter against the listed document; an omitted extension makes a legitimate filter match
    // nothing.
    let (_, listed) = call(&db, &env, "GET", "/scim/v2/Users", Some(&acme.token), None).await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        parsed["Resources"][0]["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
            ["department"]
            .as_str(),
        Some("Tools"),
        "the listing must carry the extension too: {listed}"
    );
}

/// Both vendors' PATCH dialects reach the extension, and both write the same trait.
///
/// Entra sends the URN-qualified path
/// (`urn:...:enterprise:2.0:User:employeeNumber`); Okta sends the whole extension object under
/// its URN inside a no-path value. Neither reached the extension before, so a `department`
/// change from either vendor was answered `400 unsupported attribute`.
///
/// The two are driven against the SAME person in sequence, so the second also proves the first
/// did not clear what it did not mention.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn both_vendor_patch_dialects_reach_the_enterprise_extension() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "grace@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // ENTRA: a URN-qualified path.
    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{id}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
                "value": "902",
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(
        serde_json::from_str::<Value>(&patched).expect("json")
            ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["employeeNumber"]
            .as_str(),
        Some("902"),
        "Entra's dialect must reach the extension: {patched}"
    );

    // OKTA: the whole extension object in a no-path value.
    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{id}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "value": {
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "department": "Platform",
                    },
                },
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let parsed: Value = serde_json::from_str(&patched).expect("json");
    let extension = &parsed["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(
        extension["department"].as_str(),
        Some("Platform"),
        "Okta's dialect must reach the extension: {patched}"
    );
    // AND THE EARLIER ATTRIBUTE SURVIVED. A write that replaced the traits document rather than
    // merging into it would clear this, and the client would never know: it did not mention
    // `employeeNumber`, so it has no reason to check.
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("902"),
        "a PATCH must not clear extension attributes it did not mention: {patched}"
    );

    // CASE-INSENSITIVELY, per RFC 7643 section 2.1, and onto the SAME trait. A second spelling
    // writing a second trait is the two-spellings defect the path parser refuses paths for.
    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{id}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:EMPLOYEENUMBER",
                "value": "903",
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let extension = serde_json::from_str::<Value>(&patched).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("903"),
        "a differently-cased attribute must write the SAME trait: {patched}"
    );
    assert!(
        extension.get("EMPLOYEENUMBER").is_none(),
        "a second spelling must not become a second attribute: {patched}"
    );
}

/// An extension attribute outside RFC 7643's set is REFUSED, not dropped.
///
/// `/Schemas` publishes what the extension carries, so a client that sends an attribute and
/// gets a 201 is entitled to read it back. Accepting and discarding is the defect this whole
/// change replaces, and it must not survive on the attributes the server does not know.
#[tokio::test]
async fn an_attribute_outside_the_extension_is_refused_rather_than_dropped() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, refused) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "unknown@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "favouriteColour": "blue",
            },
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an attribute outside the extension must be refused: {refused}"
    );
    // AND THE REFUSAL DOES NOT ECHO THE ATTRIBUTE NAME. Extension keys arrive as raw JSON and
    // are bounded by nothing, so reflecting one makes this surface a reflection gadget -- the
    // policy `unsupported_attribute` states for parsed paths, applied where it matters more.
    assert!(
        !refused.contains("favouriteColour"),
        "the refusal must not echo the caller's own input: {refused}"
    );

    // REFUSED BEFORE ANYTHING IS WRITTEN. The extension is validated at the top of the handler,
    // so a refusal must not leave a person behind for a retry to collide with.
    let (_, listed) = call(&db, &env, "GET", "/scim/v2/Users", Some(&acme.token), None).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["totalResults"].as_u64(),
        Some(0),
        "a refused create landed a person anyway: {listed}"
    );

    // THE CONTROL: a declared attribute is accepted, so the refusal is about the vocabulary and
    // not about a surface that refuses every extension.
    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "declared@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "2",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
}

/// One organization's Enterprise attributes are INVISIBLE to another's connection.
///
/// The attributes were identity TRAITS, which live on the `users` row and are environment
/// wide. A review drove two organizations holding one person: Acme created them with
/// `employeeNumber: "ACME-SECRET-701"`, Globex's own token READ it back, and Globex then
/// overwrote `department` -- which Acme's next read returned.
///
/// Migration 0187 keys the document on the CONNECTION for that reason: an employee number is
/// the number that person has at that organization, and two organizations provisioning one
/// human legitimately have different ones.
#[tokio::test]
async fn one_organizations_enterprise_attributes_are_invisible_to_another() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;
    let globex = seed_org(&db, &env, scope, "Globex", "s-globex").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "shared@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "ACME-SECRET-701",
                "department": "Acme Internal Tools",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // The SAME person, also a member of Globex. A shared person is how two identity providers
    // legitimately end up describing one human.
    also_a_member_of(
        &db,
        &env,
        scope,
        &globex.organization,
        &ironauth_store::UserId::parse_in_scope(&user, &scope).expect("a user id"),
    )
    .await;

    // GLOBEX READS NOTHING OF ACME'S.
    let (status, seen) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{user}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    assert!(
        !seen.contains("ACME-SECRET-701") && !seen.contains("Acme Internal Tools"),
        "one organization's Enterprise attributes leaked to another: {seen}"
    );

    // AND GLOBEX'S OWN WRITE DOES NOT DISTURB ACME'S.
    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&globex.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                "value": "Globex Sales",
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");

    let (_, acme_sees) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        None,
    )
    .await;
    let extension = serde_json::from_str::<Value>(&acme_sees).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    assert_eq!(
        extension["department"].as_str(),
        Some("Acme Internal Tools"),
        "another organization's write overwrote this one's attributes: {acme_sees}"
    );
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("ACME-SECRET-701"),
        "{acme_sees}"
    );
}

/// `remove` CLEARS an attribute, in both vendor dialects, and neither writes on a remove.
///
/// The URN-path arm mapped `remove` to a `null` value that a trait schema then refused, so a
/// remove answered 400 and left the attribute set. The no-path arm never read `op` at all, so
/// `{"op":"remove","value":{URN:{"department":"Tools"}}}` answered 200 and SET `department` --
/// a remove that writes. A review measured both.
#[tokio::test]
async fn remove_clears_an_enterprise_attribute_in_both_dialects() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "clearme@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "701",
                "department": "Tools",
                "costCenter": "CC-1",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // ENTRA'S DIALECT: a URN-qualified path.
    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "remove",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
            }],
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a remove must not be refused: {patched}"
    );
    let extension = serde_json::from_str::<Value>(&patched).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    assert!(
        extension.get("department").is_none(),
        "the removed attribute is still there: {patched}"
    );
    // AND ONLY THAT ONE. A remove that cleared the document would pass the assertion above.
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("701"),
        "{patched}"
    );

    // OKTA'S DIALECT: the extension object in a no-path value. The value names `costCenter`
    // with a real string, so a handler that ignored `op` would SET it rather than clear it --
    // which is exactly what happened.
    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "remove",
                "value": {
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "costCenter": "CC-1",
                    },
                },
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let extension = serde_json::from_str::<Value>(&patched).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    assert!(
        extension.get("costCenter").is_none(),
        "a remove in the no-path dialect SET the attribute instead of clearing it: {patched}"
    );
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("701"),
        "{patched}"
    );
}

/// Concurrent writes to one person's extension all land.
///
/// The attributes were stored by reading the traits document in one transaction and writing it
/// back in another. A review drove six concurrent `PATCH`es, each setting a different attribute:
/// all six answered 200 and ONE survived. Migration 0187 makes the write a single upsert whose
/// merge happens inside the statement, so there is no window rather than a narrower one.
#[tokio::test]
async fn concurrent_writes_to_one_persons_extension_all_land() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "concurrent@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let attributes = [
        "employeeNumber",
        "costCenter",
        "organization",
        "division",
        "department",
        "employeeType",
    ];
    // SPAWNED, not awaited in turn: a sequential loop would have passed against the
    // read-modify-write this replaces, because each read would have seen the previous write.
    // Each task takes its own connection from the pool, which is what makes them concurrent.
    let db = std::sync::Arc::new(db);
    let mut handles = Vec::new();
    for attribute in attributes {
        let db = std::sync::Arc::clone(&db);
        let env = env.clone();
        let token = acme.token.clone();
        let user = user.clone();
        handles.push(tokio::spawn(async move {
            call(
                &db,
                &env,
                "PATCH",
                &format!("/scim/v2/Users/{user}"),
                Some(&token),
                Some(json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{
                        "op": "replace",
                        "path": format!(
                            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:{attribute}"
                        ),
                        "value": format!("set-{attribute}"),
                    }],
                })),
            )
            .await
        }));
    }
    for (attribute, handle) in attributes.iter().zip(handles) {
        let (status, body) = handle.await.expect("the write task completes");
        assert_eq!(status, StatusCode::OK, "{attribute}: {body}");
    }

    // EVERY ONE OF THEM SURVIVED. This is the assertion the trait storage failed: six answers
    // of 200 and one attribute in the document.
    let (_, read) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        None,
    )
    .await;
    let extension = serde_json::from_str::<Value>(&read).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    for attribute in attributes {
        assert_eq!(
            extension[attribute].as_str(),
            Some(format!("set-{attribute}").as_str()),
            "a concurrent write answered 200 and was lost: {read}"
        );
    }
}

/// A filter on an extension attribute matches, in both the qualified and the bare spelling.
///
/// The listing renders the extension so that "a client that filters on `employeeNumber`" can
/// match -- and a review measured that neither spelling matched anything, because the filter
/// resolved names against the top level while the extension sits nested under its URN. The
/// stated benefit of rendering it was simply not obtained.
#[tokio::test]
async fn a_filter_on_an_extension_attribute_matches_in_both_spellings() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    for (handle, number) in [("found@example.com", "701984"), ("other@example.com", "2")] {
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Users",
            Some(&acme.token),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": handle,
                "active": true,
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                    "employeeNumber": number,
                },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // BOTH SPELLINGS. Entra sends the qualified one; the bare one is what a hand-written filter
    // uses, and RFC 7644 section 3.4.2.2 permits either.
    for filter in [
        "urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Aextension%3Aenterprise%3A2.0%3AUser%3AemployeeNumber%20eq%20%22701984%22",
        "employeeNumber%20eq%20%22701984%22",
    ] {
        let (status, listed) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Users?filter={filter}"),
            Some(&acme.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let parsed: Value = serde_json::from_str(&listed).expect("json");
        assert_eq!(
            parsed["totalResults"].as_u64(),
            Some(1),
            "a filter on an extension attribute matched nothing: {listed}"
        );
        assert_eq!(
            parsed["Resources"][0]["userName"].as_str(),
            Some("found@example.com"),
            "the filter matched the wrong person: {listed}"
        );
    }
}

/// A create and a PATCH spelling one attribute differently write ONE attribute.
///
/// SCIM matches attribute names case-insensitively (RFC 7643 section 2.1) and this is stored as
/// a JSON key, where the match is exact. The PATCH path canonicalized and the create path
/// inserted the caller's own casing, so a review measured a document holding BOTH:
///
/// ```json
/// {"EMPLOYEENUMBER":"701","employeeNumber":"902"}
/// ```
///
/// That is the two-spellings defect the path parser next door refuses whole paths for, on an
/// attribute instead of a path -- and the helper whose doc says it exists to prevent exactly
/// this was called from one of the two writers.
#[tokio::test]
async fn a_create_and_a_patch_spelling_one_attribute_differently_write_one_attribute() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    // CREATED in a spelling no client would choose, which is the point: it must land under the
    // canonical one, or the PATCH below writes a second key.
    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "spelling@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "EMPLOYEENUMBER": "701",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let parsed: Value = serde_json::from_str(&created).expect("json");
    let user = parsed["id"].as_str().expect("id").to_owned();
    // The CREATE already answers in the canonical spelling, which is what a client reads back.
    assert_eq!(
        parsed["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["employeeNumber"]
            .as_str(),
        Some("701"),
        "a create must store the canonical spelling: {created}"
    );

    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
                "value": "902",
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let extension = serde_json::from_str::<Value>(&patched).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    assert_eq!(
        extension.as_object().map(serde_json::Map::len),
        Some(1),
        "one attribute spelled two ways became two attributes: {patched}"
    );
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("902"),
        "the PATCH must replace what the create wrote: {patched}"
    );
}

/// A SECOND connection into the SAME organization sees what the first wrote.
///
/// This is the half the per-connection key got wrong. `scim_connections` grants UPDATE only on
/// `(revoked_at, updated_at)`, so a token rotation is necessarily a NEW connection row with a
/// new id -- and keyed per connection, every attribute the old one wrote became unreadable
/// through the surface. A review measured exactly that. An Okta-to-Entra cutover inside one
/// organization is the same shape.
///
/// An employee number is a fact the ORGANIZATION holds about the person, which is why the key
/// is the organization and not the credential that happened to write it.
#[tokio::test]
async fn a_second_connection_into_one_organization_sees_what_the_first_wrote() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let first = seed_org(&db, &env, scope, "Acme", "s-first").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&first.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "rotated@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "701",
                "department": "Tools",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // THE ROTATION: a second connection into the SAME organization, as a credential rotation
    // or a vendor cutover produces.
    let second = seed_connection_for(&db, &env, scope, &first.organization, "s-second").await;

    let (status, seen) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{user}"),
        Some(&second),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    let extension = serde_json::from_str::<Value>(&seen).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("701"),
        "a rotated credential must still see its organization's attributes: {seen}"
    );
    assert_eq!(extension["department"].as_str(), Some("Tools"), "{seen}");

    // AND IT WRITES INTO THE SAME DOCUMENT, so the first connection sees the update rather than
    // two organizations' worth of divergent state.
    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&second),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                "value": "Platform",
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let (_, first_sees) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{user}"),
        Some(&first.token),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&first_sees).expect("json")
            ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"]
            .as_str(),
        Some("Platform"),
        "{first_sees}"
    );
}

/// A `PUT` REPLACES the extension: what the body omits is gone.
///
/// RFC 7644 section 3.5.1 makes PUT a replace, and the write was a merge -- a review measured a
/// PUT carrying one attribute answering 200 and leaving the other two standing, and a PUT
/// carrying no extension at all leaving the whole document. `rebind_external_id` next door
/// writes an explicit argument for its own deviation from PUT semantics; this write had none.
#[tokio::test]
async fn a_put_replaces_the_extension_rather_than_merging_into_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "replaced@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "701",
                "department": "Tools",
                "costCenter": "CC-1",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // A PUT carrying ONE attribute: the other two are gone.
    let (status, replaced) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "replaced@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": "902",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    let extension = serde_json::from_str::<Value>(&replaced).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
        .clone();
    assert_eq!(
        extension.as_object().map(serde_json::Map::len),
        Some(1),
        "a PUT must replace the extension, not merge into it: {replaced}"
    );
    assert_eq!(
        extension["employeeNumber"].as_str(),
        Some("902"),
        "{replaced}"
    );

    // AND A PUT CARRYING NO EXTENSION CLEARS IT. That is the same rule, and it is the case a
    // bail-out on an empty document silently got wrong.
    let (status, cleared) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "replaced@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    let parsed: Value = serde_json::from_str(&cleared).expect("json");
    assert!(
        parsed
            .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
            .is_none(),
        "a PUT carrying no extension must clear it: {cleared}"
    );
}

/// `add` on the complex `manager` keeps sub-attributes it did not name.
///
/// RFC 7644 section 3.5.2.1 makes `add` on a complex attribute add SUB-attributes to the
/// existing value. `||` is a shallow merge, so a review measured
/// `{"op":"add","path":"...:manager","value":{"value":"boss-2"}}` destroying the stored
/// manager's `displayName` and `$ref` -- silently, since the client did not mention them.
///
/// `replace` is the control: it is defined to replace, and must still do so.
#[tokio::test]
async fn add_on_the_complex_manager_keeps_sub_attributes_it_did_not_name() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "managed@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "manager": {
                    "value": "boss-1",
                    "displayName": "Boss One",
                    "$ref": "https://example.test/scim/v2/Users/boss-1",
                },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, added) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "add",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                "value": { "value": "boss-2" },
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{added}");
    let manager = serde_json::from_str::<Value>(&added).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["manager"]
        .clone();
    assert_eq!(manager["value"].as_str(), Some("boss-2"), "{added}");
    assert_eq!(
        manager["displayName"].as_str(),
        Some("Boss One"),
        "an add on a complex attribute must keep sub-attributes it did not name: {added}"
    );

    // `replace` IS defined to replace, and must still do so -- otherwise the fix above would
    // have made every write a merge, which is the opposite error.
    let (status, replaced) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                "value": { "value": "boss-3" },
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    let manager = serde_json::from_str::<Value>(&replaced).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["manager"]
        .clone();
    assert!(
        manager.get("displayName").is_none(),
        "replace on a complex attribute must replace it: {replaced}"
    );
}

/// A valueless `add` or `replace` is a client error, not a remove.
///
/// The value defaulted to `Value::Null`, which feeds the null-means-remove convention: a review
/// measured `{"op":"replace","path":"...:department"}` with no `value` member answering 200 and
/// DELETING the attribute. RFC 7644 sections 3.5.2.1 and 3.5.2.3 make both a client error, and
/// the two sibling arms in the same match already refuse one.
///
/// And a WRONG-TYPED value is refused too: `/Schemas` publishes `employeeNumber` as a string,
/// and a review measured an object accepted and round-tripped verbatim.
#[tokio::test]
async fn a_valueless_or_wrong_typed_enterprise_operation_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "typed@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "department": "Tools",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    for (label, operation) in [
        (
            "a replace with no value",
            json!({"op": "replace",
                   "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"}),
        ),
        (
            "an add with no value",
            json!({"op": "add",
                   "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"}),
        ),
        (
            "a string where the document publishes complex",
            json!({"op": "replace",
                   "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                   "value": "a bare string"}),
        ),
        (
            "an object where the document publishes string",
            json!({"op": "replace",
                   "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                   "value": {"nested": true}}),
        ),
    ] {
        let (status, refused) = call(
            &db,
            &env,
            "PATCH",
            &format!("/scim/v2/Users/{user}"),
            Some(&acme.token),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [operation],
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} was accepted: {refused}"
        );
    }

    // AND NOTHING WAS DESTROYED. The first two would have deleted the attribute; the last two
    // would have stored a value the published document says cannot be there.
    let (_, after) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&after).expect("json")
            ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"]
            .as_str(),
        Some("Tools"),
        "a refused operation changed the document: {after}"
    );

    // A CREATE carrying a wrong-typed value is refused too, so the rule is not PATCH-only.
    let (status, refused) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "wrongtype@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "employeeNumber": {"nested": ["an", "object"]},
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
}

/// A `remove` against a person with NO stored document is a no-op, not a stored null.
///
/// The upsert's INSERT branch and its DO-UPDATE branch each carry `- $7::text[]`, and only the
/// second was driven: both halves of `remove_clears_an_enterprise_attribute_in_both_dialects`
/// create the document first. A review measured the INSERT branch's copy surviving deletion,
/// and the mutant stores `{"department": null}` and adds the extension URN to `schemas` -- a
/// resource carrying an attribute the client asked to remove, with a null value RFC 7643
/// section 2.5 forbids.
#[tokio::test]
async fn a_remove_against_a_person_with_no_document_stores_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    // NO extension on the create, so the remove below hits the INSERT branch.
    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "nodoc@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "remove",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let parsed: Value = serde_json::from_str(&patched).expect("json");
    assert!(
        parsed
            .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
            .is_none(),
        "a remove with nothing stored must leave no extension: {patched}"
    );
    assert!(
        !parsed["schemas"]
            .as_array()
            .expect("schemas")
            .iter()
            .any(|urn| urn.as_str()
                == Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")),
        "and must not declare the extension schema: {patched}"
    );
}

/// The extension URN is matched CASE-INSENSITIVELY at every door.
///
/// RFC 7643 section 2.1 makes attribute names case-insensitive, and the URN is how the extension
/// is named. Both PATCH doors compared it that way and the create door did not -- a serde
/// `rename` is exact bytes -- so a review measured a create carrying
/// `...enterprise:2.0:user` answering 201 with the extension SILENTLY DROPPED, while the same
/// spelling through a PATCH wrote it. Three doors, two answers.
#[tokio::test]
async fn the_extension_urn_is_matched_case_insensitively_at_every_door() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    // Only the final `User` lower-cased, which is the spelling that was dropped.
    let odd_urn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user";
    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "oddurn@example.com",
            "active": true,
            odd_urn: { "employeeNumber": "701" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    // ANSWERED UNDER THE CANONICAL URN, because that is what the document publishes and what a
    // client dispatches on.
    assert_eq!(
        serde_json::from_str::<Value>(&created).expect("json")
            ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["employeeNumber"]
            .as_str(),
        Some("701"),
        "a create must match the extension URN case-insensitively: {created}"
    );
}

/// An `add` that names a null sub-attribute stores nothing for it.
///
/// The null-means-remove convention is computed from the top-level members, which cannot see one
/// level down -- and `add` is the only mode that reaches there. A review measured
/// `{"op":"add","path":"...:manager","value":{"displayName":null}}` storing and then RENDERING
/// `"displayName": null`, which RFC 7643 section 2.5 forbids and which a client round-tripping
/// the resource sends back as a null it never wrote.
#[tokio::test]
async fn an_add_naming_a_null_sub_attribute_stores_nothing_for_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "nullsub@example.com",
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "manager": { "value": "boss", "displayName": "Boss One" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, patched) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "add",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                "value": { "displayName": null },
            }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let manager = serde_json::from_str::<Value>(&patched).expect("json")
        ["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["manager"]
        .clone();
    assert!(
        manager.get("displayName").is_none(),
        "a null sub-attribute must be removed, not stored: {patched}"
    );
    // AND THE SIBLING SURVIVED, so the null cleared one sub-attribute rather than the value.
    assert_eq!(manager["value"].as_str(), Some("boss"), "{patched}");
}

/// A SCIM DELETE ends OFFLINE consent too, when the account is going dark.
///
/// Criterion 1 of issue #136 asks that a delete revoke "all of the user's sessions and
/// refresh-token families", "verified by an integration test that holds live sessions and
/// tokens during the delete". Both halves matter and the second is why this test plants real
/// rows rather than asserting a state field.
///
/// `UserState::Disabled` is `ends_sessions()`, so `set_state` already revoked every session and
/// every SESSION-BOUND refresh family. What it did not touch is the OFFLINE families and their
/// grants -- the long-lived consent an application holds to act for the person while they are
/// away -- because `reconcile_account_state` passed `hard_kill: false`, and its own comment
/// deferred the decision to this issue.
///
/// That gap is not small. An offline grant needs no session and no interaction, so nothing else
/// would ever end it: an identity provider says the person is gone and an application goes on
/// acting for them indefinitely.
#[tokio::test]
async fn a_delete_that_takes_the_account_dark_ends_offline_consent_too() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "leaving@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let subject = UserId::parse_in_scope(&user, &scope).expect("a user id");

    // TWO LIVE FAMILIES, one of each kind, on one person. One kind alone cannot tell a cascade
    // that reached far enough from one that reached too far.
    let session_bound = plant_family(&db, &env, scope, &subject, false).await;
    let offline = plant_family(&db, &env, scope, &subject, true).await;

    // Both live BEFORE, which is what makes the assertions after the delete attributable.
    for (label, token) in [("session-bound", &session_bound), ("offline", &offline)] {
        assert!(
            db.store()
                .scoped(scope)
                .refresh()
                .load(token)
                .await
                .expect("read")
                .expect("the family is there")
                .active,
            "the {label} family must be live before the delete"
        );
    }

    let (status, body) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // BOTH are dead. The session-bound one was already covered by `ends_sessions`; the offline
    // one is what this change adds, and it is the one an application would otherwise keep using.
    for (label, token) in [("session-bound", &session_bound), ("offline", &offline)] {
        assert!(
            !db.store()
                .scoped(scope)
                .refresh()
                .load(token)
                .await
                .expect("read")
                .expect("the family row survives, revoked")
                .active,
            "the {label} refresh family outlived the deprovisioning"
        );
    }
}

/// And a person still active in ANOTHER organization keeps their offline consent.
///
/// The converse, and it is why the cascade is a condition rather than a constant. Offline
/// consent is ENVIRONMENT-WIDE, not organization-scoped: if one identity provider could end it
/// by deprovisioning from its own organization, it would be revoking consent that another
/// organization's people rely on.
#[tokio::test]
async fn a_delete_from_one_organization_leaves_a_person_active_elsewhere_untouched() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;
    let globex = seed_org(&db, &env, scope, "Globex", "s-globex").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "shared@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let subject = UserId::parse_in_scope(&user, &scope).expect("a user id");

    // The SAME person, also held by Globex. That is what makes the account not go dark.
    also_a_member_of(&db, &env, scope, &globex.organization, &subject).await;

    let offline = plant_family(&db, &env, scope, &subject, true).await;

    let (status, body) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&offline)
            .await
            .expect("read")
            .expect("the family is there")
            .active,
        "one organization's deprovisioning revoked environment-wide consent another \
         organization's people rely on"
    );
}

/// Plant a live refresh family on `subject`, returning the presented token that resolves it.
///
/// `offline` is the whole point of the parameter: the two kinds are revoked by different halves
/// of the cascade, and a test that planted only one could not tell them apart.
async fn plant_family(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &UserId,
    offline: bool,
) -> String {
    const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;
    let grant_id = GrantId::generate(env, &scope);
    let client = ClientId::generate(env, &scope);
    let subject_text = subject.to_string();
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &AuthorizationCodeId::generate(env, &scope),
                grant_id: &grant_id,
                client_id: StoredClientId::Registered(&client),
                redirect_uri: "https://client.test/cb",
                browserless: false,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject: &subject_text,
                oauth_scope: Some("openid offline_access"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: None,
                org_id: None,
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                dpop_jkt: None,
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("plant the grant");

    let family_id = RefreshFamilyId::generate(env, &scope);
    let jti = RefreshTokenId::generate(env, &scope);
    let presented = format!("ira_rt_{jti}~deprovisioning");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &jti,
                token_digest: &refresh_token_digest(&presented),
                grant_id: &grant_id,
                subject: &subject_text,
                client_id: &client.to_string(),
                scope: Some("openid offline_access"),
                auth_methods: "pwd",
                auth_time_unix_micros: None,
                offline,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
                dpop_jkt: None,
            },
        )
        .await
        .expect("plant the refresh family");
    presented
}

// =========================================================================================
// Issue #136 criterion 3: "deprovisioning emits webhook and ordered-events-API events with
// idempotency keys; consumers can replay them via cursor".
// =========================================================================================

/// The feed events about `user`, waiting until at least `want` of them are visible.
///
/// THREE THINGS ARE DELIBERATE HERE.
///
/// It reads through `events_page_after`, the ordered feed's OWN surface, not a query against
/// `outbox_messages`. The criterion is about what a CONSUMER can get: a direct query would
/// assert the rows exist and say nothing about whether anything can page over them.
///
/// It POLLS. `events_page_after` withholds a row until every transaction open anywhere on the
/// instance has finished (the `pg_snapshot_xmin` watermark on `events_after`), so a single read
/// after a write can legitimately return nothing. A missing producer never converges and panics
/// naming the watermark, which is a loud failure rather than a silently empty assertion.
///
/// It selects by USER rather than by a cursor taken before the request. A baseline cursor is
/// itself a watermarked read, so a baseline that under-read would silently widen the delta; and
/// the fixtures seed organizations and connections through the management store, which are
/// producers too. Each test creates its own person, so the person's id is an exact selector
/// that no other producer can enter.
async fn events_about(
    db: &TestDatabase,
    scope: Scope,
    user: &str,
    want: usize,
) -> Vec<OutboxMessage> {
    let outbox = db.store().scoped(scope);
    for _ in 0..100 {
        let EventPage::Page(events) = outbox
            .outbox()
            .events_page_after(EventCursor::beginning(), 200)
            .await
            .expect("read the event feed")
        else {
            panic!("the beginning cursor cannot age out; nothing here prunes")
        };
        let mine: Vec<OutboxMessage> = events
            .into_iter()
            .filter(|event| event.payload["payload"]["user_id"] == user)
            .collect();
        if mine.len() >= want {
            return mine;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "fewer than {want} events about {user} became visible on the feed within five seconds: \
         either nothing produced them, or the feed's watermark is stalled by an open transaction"
    );
}

/// One page of the feed from `cursor`, narrowed to the events about `user`.
///
/// Unpolled and deliberately so: it is only ever called after [`events_about`] has already
/// waited for the same events, so what it measures is the CURSOR -- whether a held position
/// returns the same events again, and whether one advanced past a row returns the rest.
async fn page_about(
    db: &TestDatabase,
    scope: Scope,
    user: &str,
    cursor: EventCursor,
) -> Vec<OutboxMessage> {
    let EventPage::Page(events) = db
        .store()
        .scoped(scope)
        .outbox()
        .events_page_after(cursor, 200)
        .await
        .expect("read a page from a held cursor")
    else {
        panic!("a cursor at or below a live row cannot have aged out")
    };
    events
        .into_iter()
        .filter(|event| event.payload["payload"]["user_id"] == user)
        .collect()
}

/// The `type` of each event, in feed order.
fn types(events: &[OutboxMessage]) -> Vec<String> {
    events
        .iter()
        .map(|event| {
            event.payload["type"]
                .as_str()
                .expect("every envelope carries a type")
                .to_owned()
        })
        .collect()
}

/// A SCIM DELETE announces the termination on BOTH grains, and a consumer can replay both from
/// a cursor (issue #136 criterion 3).
///
/// # Why two events and not one
///
/// The organization grain (`user.deprovisioned`) says this directory no longer holds the
/// person. The account grain (`user.state_changed`) says they can no longer sign in anywhere in
/// the environment. For a person who belongs to one organization both are true at once, which
/// is what this test drives; the test after it drives the case where only the first is, and
/// that pair is the whole reason the events are separate.
#[tokio::test]
async fn a_delete_announces_the_termination_on_both_grains_and_replays_by_cursor() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "terminated@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, body) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let events = events_about(&db, scope, &user, 2).await;
    assert_eq!(
        types(&events),
        vec!["user.deprovisioned", "user.state_changed"],
        "the delete must announce the directory removal and the account transition, in that \
         order: the organization stops holding the person before the account can go dark"
    );

    assert_eq!(events[0].payload["payload"]["user_id"], user);
    assert_eq!(
        events[0].payload["payload"]["organization_id"],
        acme.organization.to_string(),
        "a receiver cannot assume its own organization: an environment's endpoints and its feed \
         both carry every organization's events"
    );
    assert_eq!(events[1].payload["payload"]["state"], "disabled");
    assert_eq!(
        events[1].payload["payload"]["hard_kill"], true,
        "the account went dark, so offline consent ended with it, and a receiver cannot work \
         that out afterwards"
    );

    // THE IDEMPOTENCY KEY. `outbox_messages.idempotency_key` is the event id, which becomes the
    // `webhook-id` header of every delivery and the `id` on the envelope a feed reader sees. A
    // receiver deduplicates on it, so it has to be the same value in both places and different
    // between two events.
    for event in &events {
        assert_eq!(
            event.payload["id"].as_str(),
            Some(event.idempotency_key.as_str()),
            "the envelope's id and the queue's idempotency key must be one value: a receiver \
             dedups on what it was SENT"
        );
        ironauth_store::event_catalog::validate_event(&event.payload)
            .expect("the envelope validates against the registry the fan-out enforces");
    }
    assert_ne!(
        events[0].idempotency_key, events[1].idempotency_key,
        "two events under one key would make a receiver drop the second as a redelivery"
    );

    // REPLAY, which is the half of the criterion a webhook cannot satisfy. Reading again from
    // the same position returns the same events -- the feed is a position, not a drain -- and a
    // consumer that acknowledged the first resumes at the second.
    //
    // Both reads go through `events_page_after` with a REAL cursor rather than the beginning,
    // which is the shape a consumer uses and the only shape that can answer `Gone`.
    let held = EventCursor::after_sequence(events[0].sequence - 1);
    assert_eq!(
        types(&page_about(&db, scope, &user, held).await),
        types(&events),
        "re-reading from the same cursor must return the same events"
    );
    let acknowledged = EventCursor::after_sequence(events[0].sequence);
    assert_eq!(
        types(&page_about(&db, scope, &user, acknowledged).await),
        vec!["user.state_changed"],
        "a consumer that acknowledged the first event resumes at the second"
    );
}

/// `active: false` announces a DIFFERENT type from a delete (issue #136 criterion 2).
///
/// RFC 7643 section 4.1.1 makes them different acts: a deactivate leaves the membership, so the
/// person stays addressable and the same client can reactivate them by resource id, while a
/// delete removes it. A consumer reconciling its own directory has to tell those apart and
/// cannot ask afterwards -- both leave a person who cannot sign in here.
#[tokio::test]
async fn a_deactivate_announces_a_different_type_than_a_delete() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "suspended@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": false}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let events = events_about(&db, scope, &user, 2).await;
    assert_eq!(
        types(&events),
        vec!["user.deactivated", "user.state_changed"],
        "a deactivate must be distinguishable from a delete by TYPE, not by parsing a payload: \
         a receiver subscribes by type"
    );
    assert_eq!(
        events[0].payload["payload"]["organization_id"],
        acme.organization.to_string()
    );

    // AND A REACTIVATION ANNOUNCES NOTHING, which is a real gap and is asserted rather than
    // left to be discovered. A consumer mirroring this directory sees the person deactivated
    // and never learns they came back. Issue #136 asks for the termination events and nothing
    // more, and a `user.reactivated` needs a producer, a schema and a place in the published
    // catalog that nobody has settled; adding one here on the way past is how a registry fills
    // with types whose meaning was never agreed. It is recorded on the issue.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": true}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        types(&events_about(&db, scope, &user, 3).await),
        vec!["user.deactivated", "user.state_changed", "user.state_changed"],
        "the account transition back to active IS announced; the organization grain is not"
    );
}

/// A deactivate by ONE organization announces the organization grain and NOT the account grain
/// (issue #136 criteria 2 and 3).
///
/// This is the case the two grains exist for, and it is the ordinary one in any deployment
/// where a person belongs to more than one organization. Acme deactivates somebody Globex still
/// holds active: the person is gone from Acme's directory and can still sign in, so
/// `user.state_changed` would be a lie and is not emitted. A consumer watching only account
/// state learns NOTHING about this termination, which is why the organization-grain event is
/// not redundant with it.
#[tokio::test]
async fn a_deactivate_by_one_organization_announces_no_account_change() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;
    let globex = seed_org(&db, &env, scope, "Globex", "s-globex").await;

    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "shared@example.com",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Globex holds the SAME person, which is what makes the account grain false below. Added as
    // a membership rather than by a second SCIM create, because `userName` is unique across the
    // environment: a second `POST` for the same handle is answered 409, which is the create
    // door refusing to make a second account for one person, not a limit on sharing them.
    let subject = UserId::parse_in_scope(&user, &scope).expect("a user id");
    also_a_member_of(&db, &env, scope, &globex.organization, &subject).await;

    let (status, body) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Users/{user}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // THE DETERMINISTIC HALF FIRST. `user.state_changed` is emitted on exactly the path that
    // MOVES the state, so "the account is still active" and "no account-grain event was
    // emitted" are the same fact, and this read is not subject to the feed's watermark.
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .get(&subject)
            .await
            .expect("read the account")
            .state,
        ironauth_store::UserState::Active,
        "Globex still holds this person active, so the account must not have moved"
    );

    let events = events_about(&db, scope, &user, 1).await;
    assert_eq!(
        types(&events),
        vec!["user.deprovisioned"],
        "Globex still holds this person active, so the ACCOUNT did not move and announcing that \
         it had would be false. The organization grain is the only true fact here, and a \
         consumer watching account state alone would never learn the termination happened"
    );
    assert_eq!(
        events[0].payload["payload"]["organization_id"],
        acme.organization.to_string(),
        "the terminating organization, not the one that still holds them"
    );
}
