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
use ironauth_store::{CorrelationId, NewScimConnection, OrganizationId, ScimConnectionId, Scope};
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
