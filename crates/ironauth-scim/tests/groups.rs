// SPDX-License-Identifier: MIT OR Apache-2.0

//! `/scim/v2/Groups` over the real router: group push and its authorization (issue #135).
//!
//! # What group push actually is
//!
//! Not a PUT of a group with its members. Okta and Entra create the group once and then send a
//! long stream of PATCHes, one member at a time, in three different shapes. A server that
//! served only the shape it was tested with would appear to work and would silently fail to
//! add or remove people, which is the failure mode nobody notices until an offboarded employee
//! still has access. So every shape is driven here, and each is asserted to have CHANGED the
//! membership rather than merely to have been accepted.
//!
//! # The cross-organization cases are the point
//!
//! A group is a role-bearing object, so naming another organization's user in a member add is
//! a more attractive attack than reading their profile. Every member-carrying door is driven
//! with a foreign user id.
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

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str, secret: &str) -> String {
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
    token
}

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

async fn provision(db: &TestDatabase, env: &Env, token: &str, user_name: &str) -> String {
    let (status, body) = call(
        db,
        env,
        "POST",
        "/scim/v2/Users",
        Some(token),
        Some(json!({"userName": user_name})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    parsed["id"].as_str().expect("an id").to_owned()
}

async fn make_group(db: &TestDatabase, env: &Env, token: &str, name: &str) -> String {
    let (status, body) = call(
        db,
        env,
        "POST",
        "/scim/v2/Groups",
        Some(token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    parsed["id"].as_str().expect("an id").to_owned()
}

/// The member ids a group currently holds, read back through the surface.
async fn members(db: &TestDatabase, env: &Env, token: &str, group: &str) -> Vec<String> {
    let (status, body) = call(
        db,
        env,
        "GET",
        &format!("/scim/v2/Groups/{group}"),
        Some(token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    let mut ids: Vec<String> = parsed["members"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry["value"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

fn patch(operations: Value) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    })
}

#[tokio::test]
async fn a_group_is_created_read_renamed_and_deleted() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let group = make_group(&db, &env, &token, "Engineering Team").await;
    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["displayName"], "Engineering Team");
    assert_eq!(parsed["members"], json!([]));

    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            json!([{"op": "replace", "path": "displayName", "value": "Platform Team"}]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["displayName"], "Platform Team");
    // The id does not move on a rename: the group is the same object, which is what an
    // identity provider's stored reference to it depends on.
    assert_eq!(parsed["id"], json!(group.as_str()));

    let (status, _) = call(
        &db,
        &env,
        "DELETE",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_shape_a_provisioning_client_sends_changes_the_membership() {
    // The three PATCH shapes plus the PUT. Each is asserted on the MEMBERSHIP READ BACK, not
    // on the status: a handler that answered 200 and did nothing would pass a status check and
    // leave an offboarded person in the group.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let alice = provision(&db, &env, &token, "alice@example.test").await;
    let bob = provision(&db, &env, &token, "bob@example.test").await;
    let group = make_group(&db, &env, &token, "Engineering").await;
    let mut both = vec![alice.clone(), bob.clone()];
    both.sort();

    // 1. `add` with a path and a value array: how a member joins.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        members(&db, &env, &token, &group).await,
        vec![alice.clone()]
    );

    // An `add` must ADD, never replace: bob joins and alice stays.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            json!([{"op": "add", "path": "members", "value": [{"value": bob}]}]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(members(&db, &env, &token, &group).await, both);

    // 2. `remove` with the SELECTOR spelling and no value: how one person is dropped. A
    // handler reading only `value` would see nothing to remove and answer 200 having done
    // nothing, which is the silent non-deprovisioning this asserts against.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(json!([{
            "op": "remove",
            "path": format!("members[value eq \"{bob}\"]"),
        }]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        members(&db, &env, &token, &group).await,
        vec![alice.clone()]
    );

    // 3. `remove` with a path and a value array: the other removal spelling.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            json!([{"op": "remove", "path": "members", "value": [{"value": alice}]}]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(members(&db, &env, &token, &group).await.is_empty());

    // 4. A PUT declares the WHOLE set, so it both adds and removes.
    let (status, body) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(json!({
            "displayName": "Engineering",
            "members": [{"value": alice}, {"value": bob}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(members(&db, &env, &token, &group).await, both);

    let (status, body) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(json!({"displayName": "Engineering", "members": [{"value": alice}]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        members(&db, &env, &token, &group).await,
        vec![alice.clone()],
        "a PUT removes anybody it does not name"
    );
}

#[tokio::test]
async fn re_adding_a_member_already_in_the_group_is_not_a_duplicate() {
    // An identity provider retries. A second add must leave one member, not two, and must not
    // fail: a 409 here would stall a whole sync on a no-op.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let alice = provision(&db, &env, &token, "alice@example.test").await;
    let group = make_group(&db, &env, &token, "Engineering").await;

    for _ in 0..3 {
        let (status, body) = call(
            &db,
            &env,
            "PATCH",
            &format!("/scim/v2/Groups/{group}"),
            Some(&token),
            Some(patch(
                json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(members(&db, &env, &token, &group).await, vec![alice]);
}

#[tokio::test]
async fn a_group_cannot_hold_another_organizations_user() {
    // A group is role bearing, so naming a foreign user in a member add is a more attractive
    // attack than reading their profile. EVERY member-carrying door is driven with one.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let victim = provision(&db, &env, &globex, "victim@example.test").await;
    let group = make_group(&db, &env, &initech, "Attackers").await;

    let attempts = vec![
        (
            "PUT",
            format!("/scim/v2/Groups/{group}"),
            json!({"displayName": "Attackers", "members": [{"value": victim}]}),
        ),
        (
            "PATCH",
            format!("/scim/v2/Groups/{group}"),
            patch(json!([{"op": "add", "path": "members", "value": [{"value": victim}]}])),
        ),
        (
            "PATCH",
            format!("/scim/v2/Groups/{group}"),
            patch(json!([{"op": "replace", "value": {"members": [{"value": victim}]}}])),
        ),
        (
            "POST",
            "/scim/v2/Groups".to_owned(),
            json!({"displayName": "Fresh Attackers", "members": [{"value": victim}]}),
        ),
    ];
    for (method, path, body) in attempts {
        let (status, answer) = call(&db, &env, method, &path, Some(&initech), Some(body)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {path} naming a foreign user: {answer}"
        );
    }
    assert!(
        members(&db, &env, &initech, &group).await.is_empty(),
        "no attempt may have landed"
    );
}

#[tokio::test]
async fn a_token_for_one_organization_reaches_none_of_another_organizations_groups() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let theirs = make_group(&db, &env, &globex, "Engineering").await;
    let alice = provision(&db, &env, &globex, "alice@example.test").await;
    let (status, _) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{theirs}"),
        Some(&globex),
        Some(patch(
            json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the owner populates its own group");

    // Every method, and the encodings the CVE class is about.
    for spelling in [
        theirs.clone(),
        theirs.to_uppercase(),
        theirs.replace('_', "%5F"),
        format!("..%2F{theirs}"),
        format!("{theirs}%00"),
    ] {
        for (method, body) in [
            ("GET", None),
            (
                "PUT",
                Some(json!({"displayName": "Hijacked", "members": []})),
            ),
            (
                "PATCH",
                Some(patch(
                    json!([{"op": "replace", "path": "displayName", "value": "Hijacked"}]),
                )),
            ),
            ("DELETE", None),
        ] {
            let (status, answer) = call(
                &db,
                &env,
                method,
                &format!("/scim/v2/Groups/{spelling}"),
                Some(&initech),
                body,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{method} on another organization's group as {spelling}: {answer}"
            );
        }
    }

    // Nor through the listing, nor through a filter naming it.
    for query in [
        "",
        "?filter=displayName%20eq%20%22Engineering%22",
        "?filter=displayName%20pr",
    ] {
        let (status, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Groups{query}"),
            Some(&initech),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(0), "{query}: {body}");
        assert!(!body.contains("Engineering"), "{query}: {body}");
    }

    // THE CONTROL, at the end: none of the above changed anything.
    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Groups/{theirs}"),
        Some(&globex),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["displayName"], "Engineering", "not renamed: {body}");
    assert_eq!(members(&db, &env, &globex, &theirs).await, vec![alice]);
}

#[tokio::test]
async fn no_group_route_answers_without_a_credential() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let group = make_group(&db, &env, &token, "Engineering").await;

    let routes: Vec<(&str, String, Option<Value>)> = vec![
        ("GET", "/scim/v2/Groups".to_owned(), None),
        (
            "POST",
            "/scim/v2/Groups".to_owned(),
            Some(json!({"displayName": "Intruders"})),
        ),
        ("GET", format!("/scim/v2/Groups/{group}"), None),
        (
            "PUT",
            format!("/scim/v2/Groups/{group}"),
            Some(json!({"displayName": "Hijacked"})),
        ),
        (
            "PATCH",
            format!("/scim/v2/Groups/{group}"),
            Some(patch(
                json!([{"op": "replace", "path": "displayName", "value": "Hijacked"}]),
            )),
        ),
        ("DELETE", format!("/scim/v2/Groups/{group}"), None),
    ];
    for (method, path, body) in routes {
        for credential in [None, Some("not-a-token"), Some("scim_deadbeef.wrong")] {
            let (status, answer) = call(&db, &env, method, &path, credential, body.clone()).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} with {credential:?}: {answer}"
            );
        }
    }

    let (status, body) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["displayName"], "Engineering", "{body}");
}

#[tokio::test]
async fn a_display_name_that_cannot_become_a_slug_is_refused_and_a_collision_is_a_conflict() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    for name in ["", "   ", "!!!"] {
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Groups",
            Some(&token),
            Some(json!({"displayName": name})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name:?}: {body}");
        assert!(body.contains("invalidValue"), "{name:?}: {body}");
    }

    make_group(&db, &env, &token, "Engineering").await;
    for colliding in ["Engineering", "ENGINEERING", "engineering"] {
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Groups",
            Some(&token),
            Some(json!({"displayName": colliding})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{colliding}: {body}");
        assert!(body.contains("uniqueness"), "{colliding}: {body}");
    }

    // The control: a genuinely different name still creates.
    make_group(&db, &env, &token, "Sales").await;
}
