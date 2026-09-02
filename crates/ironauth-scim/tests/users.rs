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
        )
        .await
        .expect("create connection");
    Tenant { token }
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
    let state = ScimState::new(
        db.store().clone(),
        env.clone(),
        ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
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
