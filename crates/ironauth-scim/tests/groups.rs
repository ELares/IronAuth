// SPDX-License-Identifier: MIT OR Apache-2.0

//! `/scim/v2/Groups` over the real router: group push and its authorization (issue #135).
//!
//! # What group push actually is
//!
//! Not a PUT of a group with its members. Okta and Entra create the group once and then send a
//! long stream of `PATCH`es, one member at a time, in three different shapes. A server that
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
use ironauth_store::{
    CorrelationId, NewScimConnection, OrgMembershipId, OrganizationId, ScimConnectionId, Scope,
    UserId,
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

/// A seeded organization and the provisioning credential for it.
///
/// The ids are returned as well as the token because issue #136's criteria are ABOUT them: a
/// binding is torn down by the CONNECTION that pushed it, and a role is resolved within the
/// ORGANIZATION. Tests that only ever call the SCIM surface need the token alone, and
/// [`seed_org`] still hands them that.
struct Provisioner {
    token: String,
    organization: OrganizationId,
    connection: ScimConnectionId,
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str, secret: &str) -> String {
    seed_provisioner(db, env, scope, name, secret).await.token
}

async fn seed_provisioner(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    name: &str,
    secret: &str,
) -> Provisioner {
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
    Provisioner {
        token,
        organization: org,
        connection: id,
    }
}

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

/// [`call`] with explicit limits, so the scan bound can be driven rather than asserted about.
///
/// The groups harness had no such helper, which is why the group member reads were silently
/// truncated at the bound with nothing to notice.
async fn call_with(
    db: &TestDatabase,
    env: &Env,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    limits: ScimLimits,
) -> (StatusCode, String) {
    let state = ScimState::new(
        db.store().clone(),
        env.clone(),
        limits,
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

fn patch(operations: &Value) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations.clone(),
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
            &json!([{"op": "replace", "path": "displayName", "value": "Platform Team"}]),
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
            &json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
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
            &json!([{"op": "add", "path": "members", "value": [{"value": bob}]}]),
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
        Some(patch(&json!([{
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
            &json!([{"op": "remove", "path": "members", "value": [{"value": alice}]}]),
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
                &json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
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
            patch(&json!([{"op": "add", "path": "members", "value": [{"value": victim}]}])),
        ),
        (
            "PATCH",
            format!("/scim/v2/Groups/{group}"),
            patch(&json!([{"op": "replace", "value": {"members": [{"value": victim}]}}])),
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
            &json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
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
                    &json!([{"op": "replace", "path": "displayName", "value": "Hijacked"}]),
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
                &json!([{"op": "replace", "path": "displayName", "value": "Hijacked"}]),
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

// ---------------------------------------------------------------------------------------
// REVIEW ROUND 2.
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_group_larger_than_the_scan_bound_is_refused_rather_than_truncated() {
    // BLOCKER. The three group member reads passed `scan_bound()` as a plain limit with no
    // probe and no refusal, so a group larger than the bound rendered a SHORT `members` array
    // inside a 200 -- and `set_members` computes its REMOVALS from that list, so a PUT against
    // an over-large group both failed to remove people it should and tried to re-add members
    // it could not see.
    //
    // Driven by building the group under a bound that fits it and then reading it under a
    // smaller one, because a group cannot be grown PAST the bound: the write's own response
    // renders the group, and that render is one of the reads being bounded.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let roomy = ScimLimits {
        max_scan: 3,
        ..ScimLimits::default()
    };
    let tight = ScimLimits {
        max_scan: 2,
        ..ScimLimits::default()
    };

    let group = make_group(&db, &env, &token, "Engineering").await;
    let mut people = Vec::new();
    for who in ["a", "b", "c"] {
        let id = provision(&db, &env, &token, &format!("{who}@example.test")).await;
        people.push(json!({"value": id}));
    }
    let (status, body) = call_with(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": people}]),
        )),
        roomy,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(
        parsed["members"].as_array().map(Vec::len),
        Some(3),
        "at the bound, the whole membership is rendered: {body}"
    );

    // Under the tighter bound the SAME group is over it, and every door refuses rather than
    // answering a short list. The PUT matters most: it computes its removals from that list.
    for (method, request) in [
        ("GET", None),
        (
            "PUT",
            Some(json!({"displayName": "Engineering", "members": []})),
        ),
        (
            "PATCH",
            Some(patch(
                &json!([{"op": "remove", "path": "members", "value": []}]),
            )),
        ),
    ] {
        let (status, answer) = call_with(
            &db,
            &env,
            method,
            &format!("/scim/v2/Groups/{group}"),
            Some(&token),
            request,
            tight,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method}: {answer}");
        assert!(answer.contains("tooMany"), "{method}: {answer}");
    }

    // And the group is INTACT: every refusal happened before anything was removed. Read back
    // under the roomy bound, since the tight one cannot see it.
    let (status, body) = call_with(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        None,
        roomy,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(
        parsed["members"].as_array().map(Vec::len),
        Some(3),
        "{body}"
    );
}

#[tokio::test]
async fn a_group_create_naming_a_member_it_cannot_reach_creates_nothing() {
    // MAJOR. The group was created and THEN its members applied, so a create naming a member
    // this credential may not reach answered 404 with the group already committed -- and the
    // retry then answered 409 forever on the display name. The most ordinary group push there
    // is: push a group whose members are not all provisioned yet.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let initech = seed_org(&db, &env, scope, "Initech", "s3cret-initech").await;

    let victim = provision(&db, &env, &globex, "victim@example.test").await;
    for (what, member) in [
        ("a member of another organization", victim.as_str()),
        ("a member that does not exist", "usr_nobody"),
    ] {
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Groups",
            Some(&initech),
            Some(json!({"displayName": "Fresh Attackers", "members": [{"value": member}]})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{what}: {body}");

        // NOTHING was created, which the existing IDOR test could not see: it asserted only
        // that no member landed and never looked at the group list.
        let (_, body) = call(&db, &env, "GET", "/scim/v2/Groups", Some(&initech), None).await;
        let parsed: Value = serde_json::from_str(&body).expect("a list");
        assert_eq!(parsed["totalResults"], json!(0), "{what}: {body}");
    }

    // The control: the same name creates cleanly once nothing unreachable is named, which is
    // the retry the orphan used to block forever.
    make_group(&db, &env, &initech, "Fresh Attackers").await;
}

#[tokio::test]
async fn a_member_named_twice_in_one_request_is_not_a_conflict() {
    // MAJOR. `set_members` read the existing bindings once, so a payload naming one person
    // twice tried to insert the same binding twice and hit the unique index: an ordinary
    // duplicate in a client's payload became a 409.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let alice = provision(&db, &env, &token, "alice@example.test").await;

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Groups",
        Some(&token),
        Some(json!({
            "displayName": "Engineering",
            "members": [{"value": alice}, {"value": alice}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    let group = parsed["id"].as_str().expect("an id").to_owned();
    assert_eq!(
        members(&db, &env, &token, &group).await,
        vec![alice.clone()],
        "one person, once"
    );

    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(&json!([{
            "op": "add",
            "path": "members",
            "value": [{"value": alice}, {"value": alice}],
        }]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(members(&db, &env, &token, &group).await, vec![alice]);
}

#[tokio::test]
async fn a_group_patch_that_cannot_be_completed_applies_none_of_it() {
    // MAJOR. RFC 7644 section 3.5.2's atomicity requirement, implemented for /Users in round 1
    // and left as a loop on this door: a reviewer sent [add members, replace externalId], got
    // a 400 for the unsupported second operation, and found the member already added.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let alice = provision(&db, &env, &token, "alice@example.test").await;
    let group = make_group(&db, &env, &token, "Engineering").await;

    for (what, operations) in [
        (
            "an unsupported attribute after a member add",
            json!([
                {"op": "add", "path": "members", "value": [{"value": alice}]},
                {"op": "replace", "path": "externalId", "value": "x"},
            ]),
        ),
        (
            "an unreachable member after a rename",
            json!([
                {"op": "replace", "path": "displayName", "value": "Renamed"},
                {"op": "add", "path": "members", "value": [{"value": "usr_nobody"}]},
            ]),
        ),
    ] {
        let (status, body) = call(
            &db,
            &env,
            "PATCH",
            &format!("/scim/v2/Groups/{group}"),
            Some(&token),
            Some(patch(&operations)),
        )
        .await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "{what}: {status} {body}"
        );
        assert!(
            members(&db, &env, &token, &group).await.is_empty(),
            "{what}: a member landed"
        );
        let (_, body) = call(
            &db,
            &env,
            "GET",
            &format!("/scim/v2/Groups/{group}"),
            Some(&token),
            None,
        )
        .await;
        let parsed: Value = serde_json::from_str(&body).expect("a resource");
        assert_eq!(
            parsed["displayName"], "Engineering",
            "{what}: the rename landed"
        );
    }

    // The control: each first operation ALONE does apply. Without it this passes on a PATCH
    // that never applies anything.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(members(&db, &env, &token, &group).await, vec![alice]);
}

#[tokio::test]
async fn a_group_create_answers_the_location_of_the_group_it_created() {
    // MAJOR. RFC 7644 section 3.3 wants the URI of the CREATED RESOURCE; the users door was
    // fixed in round 1 and this one kept the collection constant.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;

    let state = ScimState::new(
        db.store().clone(),
        env.clone(),
        ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let request = Request::builder()
        .method("POST")
        .uri("/scim/v2/Groups")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(Body::from(
            json!({"displayName": "Engineering"}).to_string(),
        ))
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
    let parsed: Value = serde_json::from_slice(&bytes).expect("a resource");
    let id = parsed["id"].as_str().expect("an id");
    assert_eq!(location, format!("/scim/v2/Groups/{id}"));

    // And following it reaches the group, which is the only thing the header is for.
    let (status, body) = call(&db, &env, "GET", &location, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["meta"]["location"], json!(location.as_str()));
}

#[tokio::test]
async fn a_group_cannot_be_grown_past_the_scan_bound() {
    // BLOCKER. The refusal was on the RESPONSE RENDER, which runs after the writes commit, so
    // a reviewer added three members at a bound of two, got a 400, and found all three landed
    // -- and the organization's whole `GET /Groups` then failed permanently. The same shape on
    // `POST /Groups` created the group and made every retry a 409.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let tight = ScimLimits {
        max_scan: 2,
        ..ScimLimits::default()
    };
    let roomy = ScimLimits {
        max_scan: 10,
        ..ScimLimits::default()
    };

    let mut people = Vec::new();
    for who in ["a", "b", "c"] {
        let id = provision(&db, &env, &token, &format!("{who}@example.test")).await;
        people.push(json!({"value": id}));
    }

    // A create naming more members than the bound creates NOTHING.
    let (status, body) = call_with(
        &db,
        &env,
        "POST",
        "/scim/v2/Groups",
        Some(&token),
        Some(json!({"displayName": "Engineering", "members": people})),
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("tooMany"), "{body}");
    let (_, body) = call_with(
        &db,
        &env,
        "GET",
        "/scim/v2/Groups",
        Some(&token),
        None,
        roomy,
    )
    .await;
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(
        parsed["totalResults"],
        json!(0),
        "a refused create must leave no group behind: {body}"
    );

    // An ADD that would take an existing group past the bound adds NOBODY.
    let group = make_group(&db, &env, &token, "Engineering").await;
    let (status, body) = call_with(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": people}]),
        )),
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = call_with(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        None,
        roomy,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(
        parsed["members"].as_array().map(Vec::len),
        Some(0),
        "no member may have landed: {body}"
    );

    // Filling the group exactly TO the bound works, so the refusals above are the bound and
    // not a member add that never works.
    let (status, body) = call_with(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": people[..2]}]),
        )),
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(members(&db, &env, &token, &group).await.len(), 2);
}

#[tokio::test]
async fn a_group_cannot_be_grown_past_the_bound_one_member_at_a_time() {
    // The request-size check cannot catch this: ONE more member is within the bound as a
    // REQUEST and takes the group over it as a RESULT. Only the resulting-size check in
    // `set_members` sees it, and without that check a group grows past the bound one member at
    // a time -- which is how a real sync adds people.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let tight = ScimLimits {
        max_scan: 2,
        ..ScimLimits::default()
    };
    let group = make_group(&db, &env, &token, "Engineering").await;
    let mut people = Vec::new();
    for who in ["a", "b", "c"] {
        let id = provision(&db, &env, &token, &format!("{who}@example.test")).await;
        people.push(json!({"value": id}));
    }
    let (status, body) = call_with(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": people[..2]}]),
        )),
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "filling to the bound works: {body}");

    // THE INCREMENTAL CASE, which the request-size check above cannot catch: ONE more member
    // is within the bound as a request and takes the group over it as a result. Only the
    // resulting-size check sees this, and without it a group grows past the bound one member
    // at a time.
    let (status, body) = call_with(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": [people[2].clone()]}]),
        )),
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("tooMany"), "{body}");
    assert_eq!(
        members(&db, &env, &token, &group).await.len(),
        2,
        "the refused member must not have landed"
    );

    // And re-adding a member the group ALREADY holds is not growth, so it is not refused: the
    // check counts arrivals, not the size of the request.
    let (status, body) = call_with(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": [people[0].clone()]}]),
        )),
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(members(&db, &env, &token, &group).await.len(), 2);
}

#[tokio::test]
async fn one_oversized_group_does_not_hide_the_rest_of_the_listing() {
    // BLOCKER, the other half. `list_groups` rendered every group's members, so ONE group over
    // the bound made the whole listing answer `tooMany` permanently: a client could not
    // enumerate the groups it CAN see because of one it cannot.
    //
    // The listing now omits `members` entirely (RFC 7644 section 3.4.2 permits a subset), which
    // removes the failure and the O(groups x members) read with it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed_org(&db, &env, scope, "Globex", "s3cret-globex").await;
    let roomy = ScimLimits {
        max_scan: 10,
        ..ScimLimits::default()
    };
    let tight = ScimLimits {
        max_scan: 2,
        ..ScimLimits::default()
    };

    let big = make_group(&db, &env, &token, "Everyone").await;
    let small = make_group(&db, &env, &token, "Admins").await;
    let mut people = Vec::new();
    for who in ["a", "b", "c"] {
        let id = provision(&db, &env, &token, &format!("{who}@example.test")).await;
        people.push(json!({"value": id}));
    }
    let (status, _) = call_with(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{big}"),
        Some(&token),
        Some(patch(
            &json!([{"op": "add", "path": "members", "value": people}]),
        )),
        roomy,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Under the tighter bound the big group exceeds it. The listing still answers, and names
    // BOTH groups.
    let (status, body) = call_with(
        &db,
        &env,
        "GET",
        "/scim/v2/Groups",
        Some(&token),
        None,
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a list");
    assert_eq!(parsed["totalResults"], json!(2), "{body}");
    assert!(
        body.contains("Everyone") && body.contains("Admins"),
        "{body}"
    );
    // And it does NOT claim either group is empty: an empty members array is a positive claim
    // a provisioning client acts on by removing everybody.
    for resource in parsed["Resources"].as_array().expect("resources") {
        assert!(
            resource.get("members").is_none(),
            "the listing must omit members rather than send an empty array: {resource}"
        );
    }

    // The small group is still fully readable on its own, which is where members are read.
    let (status, body) = call_with(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Groups/{small}"),
        Some(&token),
        None,
        tight,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("a resource");
    assert_eq!(parsed["members"], json!([]), "{body}");
}

// =========================================================================================
// Issue #136 criteria 4 to 6: group-to-role mapping.
//
// THE MAPPING MODEL ALREADY EXISTED, and measuring that before building one is why this
// section is tests and a teardown rather than a new subsystem. The issue asks for "per
// connection mapping rules from directory group to IronAuth roles, including group-level role
// assignment (assign a role to the group object, membership implies the role)". That is
// `org_group_roles`, which #97 shipped, plus SCIM group push, which #135 shipped: a SCIM group
// IS an `org_group`, so an operator attaches the role and a push puts people into the group.
//
// The rule is enforced by a GRANT rather than by a convention. Migration 0185 gives the data
// plane nothing at all on `org_group_roles`, so a provisioning connection cannot attach a role
// to a group: all it can do is put people into groups whose roles an operator already chose.
// That is what makes the whole mapping safe to drive from the public internet.
//
// What was missing, and is here: the events (criterion 4), a test that a rule removal spares
// direct grants (criterion 5), and the teardown when a connection is revoked (criterion 6),
// which needed the provenance column migration 0188 adds.
// =========================================================================================

/// The membership binding `user` holds in `org`.
async fn membership_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> OrgMembershipId {
    db.control_store()
        .management()
        .org_memberships(scope)
        .list_for_user(user)
        .await
        .expect("list memberships")
        .into_iter()
        .find(|membership| membership.organization_id == *org)
        .expect("the provisioned person is a member")
        .id
}

/// The effective role slugs `user` holds in `org`, through the control plane.
async fn roles_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> std::collections::BTreeSet<String> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_roles(org, user, 8)
        .await
        .expect("resolve effective roles")
}

/// The feed events about `group`, waiting until at least `want` are visible.
///
/// POLLED, because `events_page_after` withholds a row until every transaction open anywhere on
/// the instance has finished, so one read after a write can legitimately return nothing. It
/// selects on the SUBJECT, which for every type here is the group: that is also what orders one
/// group's events against each other, so filtering on it is filtering on the ordering key
/// rather than on a payload field that happens to be present.
async fn events_about_group(
    db: &TestDatabase,
    scope: Scope,
    group: &str,
    want: usize,
) -> Vec<ironauth_store::OutboxMessage> {
    let outbox = db.store().scoped(scope);
    for _ in 0..100 {
        let ironauth_store::EventPage::Page(events) = outbox
            .outbox()
            .events_page_after(ironauth_store::EventCursor::beginning(), 200)
            .await
            .expect("read the event feed")
        else {
            panic!("the beginning cursor cannot age out; nothing here prunes")
        };
        let mine: Vec<_> = events
            .into_iter()
            .filter(|event| event.ordering_key == group)
            .collect();
        if mine.len() >= want {
            return mine;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("fewer than {want} events about {group} became visible within five seconds");
}

/// The `type` of each event, in feed order.
fn event_types(events: &[ironauth_store::OutboxMessage]) -> Vec<String> {
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

/// Define a role in `org` through the control plane, returning its id.
///
/// The CONTROL plane, because there is no other option and that is the point: migration 0185
/// grants the data plane nothing at all on `org_roles` or `org_group_roles`, so a provisioning
/// connection can put people into groups and can never decide what a group confers.
async fn define_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    slug: &str,
) -> ironauth_store::OrgRoleId {
    let role = ironauth_store::OrgRoleId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_roles(scope)
        .create(
            env,
            ironauth_store::NewOrgRole {
                id: &role,
                organization_id: org,
                slug,
                display_name: slug,
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the role");
    role
}

/// Attach `role` to `group`: the mapping rule itself. Every live member of the group holds the
/// role, and stops holding it the moment the binding or this assignment goes away.
async fn map_group_to_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &ironauth_store::OrgGroupId,
    role: &ironauth_store::OrgRoleId,
) -> ironauth_store::OrgGroupRoleId {
    let mapping = ironauth_store::OrgGroupRoleId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_group_roles(scope)
        .assign(
            env,
            ironauth_store::NewOrgGroupRole {
                id: &mapping,
                organization_id: org,
                group_id: group,
                role_id: role,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("map the directory group to the role");
    mapping
}

/// Push `user` into `group` through the SCIM surface, asserting it was accepted.
async fn push_member(db: &TestDatabase, env: &Env, token: &str, group: &str, user: &str) {
    let (status, body) = call(
        db,
        env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(token),
        Some(patch(&json!([{
            "op": "add",
            "path": "members",
            "value": [{"value": user}],
        }]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A SCIM group membership PATCH re-maps roles immediately and announces the delta
/// (issue #136, criterion 4).
///
/// # "Immediately" is a property of the model, and this is what proves it
///
/// There is no derived-assignment cache to re-evaluate. Effective roles are resolved from the
/// LIVE group bindings every time they are asked for, so the binding write IS the re-mapping
/// and nothing can lag behind it. The assertion that says so is the role read taken straight
/// after the PATCH's response, with no worker run and no sleep between them.
///
/// # Both event forms, because they answer different questions
///
/// The per-member types say WHO changed and are what an integrator deprovisioning one person
/// subscribes to. The delta says what the SET did and is what a mirror applies, and it is the
/// only one that can ever say "I could not fit it all, go and reconcile". Criterion 4 asks for
/// "added/removed, the delta-payload pattern, rather than full-state dumps", and a full-state
/// dump is exactly what the group form cannot afford: an enterprise group is the thing with
/// tens of thousands of members.
#[tokio::test]
async fn a_group_membership_push_maps_roles_immediately_and_announces_the_delta() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;

    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let group_id = ironauth_store::OrgGroupId::parse_in_scope(&group, &scope).expect("a group id");

    // THE MAPPING RULE, attached by an OPERATOR through the control plane. The data plane holds
    // no grant on `org_group_roles` at all (migration 0185), so this is the only way it can be
    // attached, and that is the property that makes group push safe on a public surface.
    let role = define_role(&db, &env, scope, &acme.organization, "deployer").await;
    map_group_to_role(&db, &env, scope, &acme.organization, &group_id, &role).await;

    let user = provision(&db, &env, &acme.token, "engineer@example.com").await;
    let subject = UserId::parse_in_scope(&user, &scope).expect("a user id");
    let membership = membership_of(&db, scope, &acme.organization, &subject).await;

    assert!(
        roles_of(&db, scope, &acme.organization, &subject)
            .await
            .is_empty(),
        "the person holds the role BEFORE being put in the group, so the assertion after the \
         push would pass without the push"
    );

    push_member(&db, &env, &acme.token, &group, &user).await;

    // IMMEDIATELY: read straight after the response, with nothing run in between.
    assert!(
        roles_of(&db, scope, &acme.organization, &subject)
            .await
            .contains("deployer"),
        "a directory group membership must confer the group's role at once, not at the next \
         sweep of some job"
    );

    let events = events_about_group(&db, scope, &group, 2).await;
    assert_eq!(
        event_types(&events),
        vec!["org_group.member_added", "org_group.membership_changed"],
        "both forms are emitted: the per-member type for an integrator watching one person, \
         the delta for a mirror applying a set change"
    );
    assert_eq!(
        events[0].payload["payload"]["membership_id"],
        membership.to_string()
    );
    assert_eq!(
        events[1].payload["payload"]["added_user_ids"],
        json!([user]),
        "the delta names the PERSON who joined, which is what a mirror keys on and what this \
         type's arrays have always declared; the per-member event beside it names the BINDING"
    );
    assert_eq!(events[1].payload["payload"]["removed_user_ids"], json!([]));
    assert_eq!(events[1].payload["payload"]["truncated"], false);
    assert_eq!(events[1].payload["payload"]["total"], 1);
    for event in &events {
        ironauth_store::event_catalog::validate_event(&event.payload)
            .expect("the envelope validates against the registry the fan-out enforces");
    }

    // AND THE REMOVAL, which is the half that actually takes access away.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&acme.token),
        Some(patch(&json!([{
            "op": "remove",
            "path": format!("members[value eq \"{user}\"]"),
        }]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !roles_of(&db, scope, &acme.organization, &subject)
            .await
            .contains("deployer"),
        "removing somebody from a mapped group must take the derived role away at once"
    );
    let events = events_about_group(&db, scope, &group, 4).await;
    assert_eq!(
        event_types(&events)[2..],
        ["org_group.member_removed", "org_group.membership_changed"],
        "the removal announces the same pair"
    );
    assert_eq!(
        events[3].payload["payload"]["removed_user_ids"],
        json!([user])
    );
}

/// Removing a mapping rule removes ONLY the derived assignments (issue #136, criterion 5).
///
/// The two grant paths are different rows in different tables: a role attached to a GROUP
/// (`org_group_roles`) reaches every member of it, and a role granted to a MEMBERSHIP
/// (`org_membership_roles`) reaches one person and nothing else. Un-mapping the group touches
/// the first and cannot touch the second, which is what makes "directly granted roles survive"
/// a property of the schema rather than of remembering to exclude them.
#[tokio::test]
async fn removing_a_mapping_rule_leaves_a_direct_grant_standing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let group_id = ironauth_store::OrgGroupId::parse_in_scope(&group, &scope).expect("a group id");
    let management = db.control_store();

    let mut role_ids = Vec::new();
    for slug in ["derived", "direct"] {
        let role = ironauth_store::OrgRoleId::generate(&env, &scope);
        management
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .org_roles(scope)
            .create(
                &env,
                ironauth_store::NewOrgRole {
                    id: &role,
                    organization_id: &acme.organization,
                    slug,
                    display_name: slug,
                    metadata: None,
                },
                now_micros(&env),
                None,
            )
            .await
            .expect("create the role");
        role_ids.push(role);
    }
    let mapping = ironauth_store::OrgGroupRoleId::generate(&env, &scope);
    management
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_group_roles(scope)
        .assign(
            &env,
            ironauth_store::NewOrgGroupRole {
                id: &mapping,
                organization_id: &acme.organization,
                group_id: &group_id,
                role_id: &role_ids[0],
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("map the group to the derived role");

    let user = provision(&db, &env, &acme.token, "engineer@example.com").await;
    let subject = UserId::parse_in_scope(&user, &scope).expect("a user id");
    let membership = membership_of(&db, scope, &acme.organization, &subject).await;
    management
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_membership_roles(scope)
        .assign(
            &env,
            ironauth_store::NewOrgMembershipRole {
                id: &ironauth_store::OrgMembershipRoleId::generate(&env, &scope),
                organization_id: &acme.organization,
                membership_id: &membership,
                role_id: &role_ids[1],
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("grant the direct role");

    push_member(&db, &env, &acme.token, &group, &user).await;
    assert_eq!(
        roles_of(&db, scope, &acme.organization, &subject).await,
        ["derived".to_owned(), "direct".to_owned()]
            .into_iter()
            .collect(),
        "both paths must be live before the un-mapping, or losing one proves nothing"
    );

    management
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_group_roles(scope)
        .unassign(&env, &acme.organization, &mapping)
        .await
        .expect("remove the mapping rule");

    assert_eq!(
        roles_of(&db, scope, &acme.organization, &subject).await,
        ["direct".to_owned()].into_iter().collect(),
        "removing the mapping rule must take the DERIVED role and leave the direct grant, which \
         an operator made for this person and no identity provider is responsible for"
    );
}

/// A SECOND provisioning credential for an organization that already has one.
///
/// `seed_provisioner` always creates a new organization, so nothing could drive two connections
/// against one until this existed.
async fn second_connection(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    secret: &str,
) -> Provisioner {
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
                display_name: "second",
                provider: "entra",
                token_digest: &digest_of(&token),
                expires_at_unix_micros: None,
            },
            None,
        )
        .await
        .expect("create the second connection");
    Provisioner {
        token,
        organization: *organization,
        connection: id,
    }
}

/// How many teardown audit rows `scope` holds.
async fn teardown_audit_rows(db: &TestDatabase, scope: Scope) -> usize {
    db.control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("read the audit log")
        .into_iter()
        .filter(|row| row.action == "scim_connection.bindings.revoke")
        .count()
}

/// Revoking a connection tears down the bindings IT pushed, and audits the teardown
/// (issue #136, criterion 6).
///
/// # Why this needed a schema change and the rest of the criteria did not
///
/// Nothing recorded who created a binding, so "the assignments derived from this connection"
/// had no answer: revoking a compromised identity provider disarmed the credential and undid
/// nothing it had done. Migration 0188 adds the provenance column, this is what reads it back,
/// and NULL (an operator's own binding) is the value the teardown's `= $1` predicate can never
/// match.
#[tokio::test]
async fn revoking_a_connection_tears_down_the_bindings_it_pushed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let group_id = ironauth_store::OrgGroupId::parse_in_scope(&group, &scope).expect("a group id");

    let role = define_role(&db, &env, scope, &acme.organization, "deployer").await;
    map_group_to_role(&db, &env, scope, &acme.organization, &group_id, &role).await;

    // ONE PERSON PUSHED BY THE CONNECTION, and one an OPERATOR bound by hand into the same
    // group. The pair is the whole test: a teardown that took both would be revoking access
    // nobody asked it to touch, and one that took neither would leave the compromise in place.
    let pushed = provision(&db, &env, &acme.token, "pushed@example.com").await;
    let pushed_subject = UserId::parse_in_scope(&pushed, &scope).expect("a user id");
    push_member(&db, &env, &acme.token, &group, &pushed).await;

    let by_hand = provision(&db, &env, &acme.token, "byhand@example.com").await;
    let by_hand_subject = UserId::parse_in_scope(&by_hand, &scope).expect("a user id");
    let by_hand_membership = membership_of(&db, scope, &acme.organization, &by_hand_subject).await;
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_group_members(scope)
        .add(
            &env,
            ironauth_store::NewOrgGroupMember {
                id: &ironauth_store::OrgGroupMemberId::generate(&env, &scope),
                organization_id: &acme.organization,
                group_id: &group_id,
                membership_id: &by_hand_membership,
                // NULL: an operator's binding, which no connection is responsible for.
                source_scim_connection_id: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("bind the operator's member by hand");

    for (who, subject) in [("pushed", &pushed_subject), ("by hand", &by_hand_subject)] {
        assert!(
            roles_of(&db, scope, &acme.organization, subject)
                .await
                .contains("deployer"),
            "the {who} person must hold the derived role before the revoke, or losing it proves \
             nothing"
        );
    }

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &acme.connection, now_micros(&env))
        .await
        .expect("revoke the connection");

    assert!(
        !roles_of(&db, scope, &acme.organization, &pushed_subject)
            .await
            .contains("deployer"),
        "revoking the connection left the person it pushed holding the role its group confers"
    );
    assert!(
        roles_of(&db, scope, &acme.organization, &by_hand_subject)
            .await
            .contains("deployer"),
        "the teardown reached a binding an operator made, which no identity provider is \
         responsible for and which the revoke was never asked to touch"
    );

    // AND IT IS AUDITED, with the count, in the revoke's own transaction.
    let teardown_rows: Vec<_> = db
        .control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("read the audit log")
        .into_iter()
        .filter(|row| row.action == "scim_connection.bindings.revoke")
        .collect();
    assert_eq!(
        teardown_rows.len(),
        1,
        "the teardown writes exactly one row, carrying the count, rather than one per binding: \
         an enterprise connection holds tens of thousands and the per-binding record is not \
         lost, because the rows are soft-deleted and keep their deleted_at"
    );
    assert_eq!(
        teardown_rows[0].detail.as_deref(),
        Some("bindings=1"),
        "the row carries how many bindings the teardown removed, so its blast radius is \
         readable from the audit log alone"
    );
    assert_eq!(
        teardown_rows[0].target_id,
        acme.connection.to_string(),
        "targeted at the connection, which is the thing the operator acted on"
    );
}

/// And the teardown ANNOUNCES itself (issue #136, criterion 6).
///
/// The first version enqueued nothing: a review measured the group's feed as byte-identical
/// before and after a revoke that emptied it, while `effective_roles` had already stopped
/// returning the role. Access was taken away and no consumer was told, so every downstream
/// mirror kept the membership forever.
#[tokio::test]
async fn a_teardown_announces_who_it_removed_from_which_group() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let pushed = provision(&db, &env, &acme.token, "pushed@example.com").await;
    push_member(&db, &env, &acme.token, &group, &pushed).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &acme.connection, now_micros(&env))
        .await
        .expect("revoke the connection");

    // measured the group's feed as byte-identical before and after a revoke that emptied it,
    // while `effective_roles` had already stopped returning the role. Access was taken away and
    // no consumer was told, so every downstream mirror kept the membership forever.
    //
    // One delta per affected group, naming who left as USER ids, which is the shape a mirror
    // applies. The per-member form is deliberately not used here: a connection can hold tens of
    // thousands of bindings, and the delta is the only form that can say "there was more than I
    // could carry".
    let events = events_about_group(&db, scope, &group, 3).await;
    assert_eq!(
        event_types(&events)[2..],
        ["org_group.membership_changed"],
        "the teardown removed a membership and announced nothing"
    );
    assert_eq!(
        events[2].payload["payload"]["removed_user_ids"],
        json!([pushed]),
        "it must name the person the revoke removed, and only them: the operator's member is \
         still in the group"
    );
    assert_eq!(events[2].payload["payload"]["added_user_ids"], json!([]));
    assert_eq!(events[2].payload["payload"]["total"], 1);
    ironauth_store::event_catalog::validate_event(&events[2].payload)
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// Revoking a connection that pushed nothing audits nothing, and a second revoke tears down
/// nothing twice (issue #136, criterion 6).
///
/// A teardown row claiming a removal that did not happen is the phantom-audit-row defect the
/// membership-attachment cascade documents, and an operator reading the log to answer "what did
/// revoking this credential take away" would be told a number that is not true.
#[tokio::test]
async fn a_revoke_that_tears_down_nothing_audits_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    // A connection that provisioned a person but never put them in a group.
    provision(&db, &env, &acme.token, "nobody@example.com").await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &acme.connection, now_micros(&env))
        .await
        .expect("revoke the connection");
    assert_eq!(
        teardown_audit_rows(&db, scope).await,
        0,
        "a revoke that removed no bindings wrote a row saying it had"
    );

    // AND AGAIN. The early return on an already-revoked connection is what stops a second
    // teardown; without it a repeat revoke would re-date every binding it had already removed,
    // destroying the record of when that access actually stopped.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &acme.connection, now_micros(&env))
        .await
        .expect("a repeat revoke is not an error");
    assert_eq!(teardown_audit_rows(&db, scope).await, 0);
}

/// A binding the connection had ALREADY removed is not torn down again (issue #136,
/// criterion 6).
///
/// The teardown's `deleted_at IS NULL` is what keeps a soft-deleted binding's timestamp: it is
/// the record of when that person's access actually stopped, and re-dating it destroys the only
/// evidence of that. A review deleted the guard and every suite stayed green, because nothing
/// drove a revoke over a group the connection had already emptied.
///
/// The audit count is the observable: with the guard gone the teardown matches the dead row,
/// writes a row claiming one removal, and an operator reading the log is told the revoke took
/// away access that had already been taken away weeks earlier.
#[tokio::test]
async fn a_binding_already_removed_is_not_torn_down_again() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let user = provision(&db, &env, &acme.token, "left@example.com").await;
    push_member(&db, &env, &acme.token, &group, &user).await;

    // The connection removes them itself, first.
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&acme.token),
        Some(patch(&json!([{
            "op": "remove",
            "path": format!("members[value eq \"{user}\"]"),
        }]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        members(&db, &env, &acme.token, &group).await.is_empty(),
        "the removal did not happen, so the revoke below has a live binding to find"
    );

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &acme.connection, now_micros(&env))
        .await
        .expect("revoke the connection");

    assert_eq!(
        teardown_audit_rows(&db, scope).await,
        0,
        "the teardown counted a binding that was already removed, so it re-dated the record of \
         when that access stopped"
    );
}

/// A binding attributed to another scope's connection is refused (issue #136, criterion 6).
///
/// The provenance column is the id a revoke SCANS on, so a binding attributed across a scope is
/// a row this scope's teardown can never reach and another scope's teardown must never see. A
/// review deleted this check and every suite stayed green.
#[tokio::test]
async fn a_binding_cannot_be_attributed_to_another_scopes_connection() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, here, "Acme", "s-acme").await;
    let foreign = seed_provisioner(&db, &env, elsewhere, "Foreign", "s-foreign").await;

    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let group_id = ironauth_store::OrgGroupId::parse_in_scope(&group, &here).expect("a group id");
    let user = provision(&db, &env, &acme.token, "engineer@example.com").await;
    let subject = UserId::parse_in_scope(&user, &here).expect("a user id");
    let membership = membership_of(&db, here, &acme.organization, &subject).await;

    let outcome = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_group_members(here)
        .add(
            &env,
            ironauth_store::NewOrgGroupMember {
                id: &ironauth_store::OrgGroupMemberId::generate(&env, &here),
                organization_id: &acme.organization,
                group_id: &group_id,
                membership_id: &membership,
                source_scim_connection_id: Some(&foreign.connection),
            },
            now_micros(&env),
            None,
        )
        .await;
    assert!(
        matches!(outcome, Err(ironauth_store::StoreError::NotFound)),
        "a binding was attributed to another scope's connection: {outcome:?}"
    );

    // THE CONTROL: the same write with this scope's own connection succeeds, so the refusal is
    // the scope check rather than anything else about the row.
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_group_members(here)
        .add(
            &env,
            ironauth_store::NewOrgGroupMember {
                id: &ironauth_store::OrgGroupMemberId::generate(&env, &here),
                organization_id: &acme.organization,
                group_id: &group_id,
                membership_id: &membership,
                source_scim_connection_id: Some(&acme.connection),
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("this scope's own connection may attribute a binding");
}

/// A PATCH adding TWO members announces ONE delta naming both, riding the last write
/// (issue #136, criterion 4).
///
/// # Why the plural case has its own test
///
/// Every other test here drives exactly ONE binding write per operation, and a review measured
/// what that leaves uncovered: with the delta moved to ride the FIRST write instead of the last,
/// all eighteen tests still passed. `MemberPlan`, `writes()` and the whole "computed up front so
/// the delta can ride the LAST write" design existed for a property nothing could observe.
///
/// Two members is the smallest input that can tell them apart. The delta must appear ONCE, name
/// BOTH people, and arrive AFTER both per-member events -- which is what "the operation
/// completed" means, and is the only thing that makes the announcement safe to act on.
#[tokio::test]
async fn a_two_member_push_announces_one_delta_naming_both_after_both_writes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;

    let first = provision(&db, &env, &acme.token, "first@example.com").await;
    let second = provision(&db, &env, &acme.token, "second@example.com").await;

    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&acme.token),
        Some(patch(&json!([{
            "op": "add",
            "path": "members",
            "value": [{"value": first}, {"value": second}],
        }]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let events = events_about_group(&db, scope, &group, 3).await;
    assert_eq!(
        event_types(&events),
        vec![
            "org_group.member_added",
            "org_group.member_added",
            "org_group.membership_changed",
        ],
        "one delta, LAST: riding the first write would announce a set change while the second \
         binding had not been written, and a later failure would leave the announcement standing"
    );
    let mut announced: Vec<String> = events[2].payload["payload"]["added_user_ids"]
        .as_array()
        .expect("the delta names who joined")
        .iter()
        .map(|value| value.as_str().expect("a user id").to_owned())
        .collect();
    announced.sort();
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort();
    assert_eq!(
        announced, expected,
        "the delta must name BOTH people the operation added, as USER ids"
    );
    assert_eq!(events[2].payload["payload"]["total"], 2);
}

/// A group write that changes nothing announces nothing (issue #136, criterion 4).
///
/// The ordinary output of an identity provider's sync sweep is a request that restates what is
/// already true. A delta claiming a change nobody made is the phantom-event defect the user
/// surface's activation upsert also guards against, and here it would have a mirror re-apply a
/// membership it already has and log a change that did not happen.
#[tokio::test]
async fn a_group_write_that_changes_nothing_announces_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let user = provision(&db, &env, &acme.token, "engineer@example.com").await;

    push_member(&db, &env, &acme.token, &group, &user).await;
    let after_first = events_about_group(&db, scope, &group, 2).await;
    assert_eq!(after_first.len(), 2, "the first push announces both forms");

    // THE SAME PUSH AGAIN, and then a DIFFERENT write whose events fence the count: waiting for
    // a number cannot say "and no more", because an extra event that has not crossed the feed's
    // visibility watermark looks exactly like one that was never emitted.
    push_member(&db, &env, &acme.token, &group, &user).await;
    let sentinel = make_group(&db, &env, &acme.token, "Sales").await;
    let other = provision(&db, &env, &acme.token, "sales@example.com").await;
    push_member(&db, &env, &acme.token, &sentinel, &other).await;
    let _ = events_about_group(&db, scope, &sentinel, 2).await;

    assert_eq!(
        event_types(&events_about_group(&db, scope, &group, 2).await),
        vec!["org_group.member_added", "org_group.membership_changed"],
        "re-pushing a member the group already holds announced the change again"
    );
}

/// A PUT that drops a member announces the removal on both forms (issue #136, criterion 4).
///
/// The replace path is how a sync sweep deprovisions somebody out of a group, and a review
/// measured that it could be made silent -- per-member event and delta both `None` -- with every
/// test still passing: the only removal any test drove went through the PATCH `remove` path.
#[tokio::test]
async fn a_replace_that_drops_a_member_announces_the_removal() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let user = provision(&db, &env, &acme.token, "leaving@example.com").await;
    push_member(&db, &env, &acme.token, &group, &user).await;

    // A PUT naming an EMPTY member set: the whole membership is declared, so the person leaves.
    let (status, body) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Groups/{group}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "members": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let events = events_about_group(&db, scope, &group, 4).await;
    assert_eq!(
        event_types(&events)[2..],
        ["org_group.member_removed", "org_group.membership_changed"],
        "a replace that drops somebody must announce it exactly as a PATCH remove does"
    );
    assert_eq!(
        events[3].payload["payload"]["removed_user_ids"],
        json!([user]),
        "and must name the PERSON who left"
    );
    assert!(
        members(&db, &env, &acme.token, &group).await.is_empty(),
        "the replace did not actually remove them, so the events above describe nothing"
    );
}

/// A PATCH removing TWO members announces ONE delta naming both, riding the last write
/// (issue #136, criterion 4).
///
/// The twin of the two-member ADD test, and it exists for the same measured reason: round 1
/// added the plural case on the add path only, and a review then moved the delta to ride the
/// FIRST removal on both removal loops and watched 25 tests pass. The design decision was
/// covered on one of three write loops.
#[tokio::test]
async fn a_two_member_removal_announces_one_delta_naming_both_after_both_writes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let first = provision(&db, &env, &acme.token, "first@example.com").await;
    let second = provision(&db, &env, &acme.token, "second@example.com").await;
    push_member(&db, &env, &acme.token, &group, &first).await;
    push_member(&db, &env, &acme.token, &group, &second).await;
    let before = events_about_group(&db, scope, &group, 4).await.len();

    // ONE remove operation naming TWO members, which `drop_members` applies as one plan. Two
    // SEPARATE remove operations would be two plans and two deltas, which is also correct: the
    // delta's grain is the operation, not the request. Only one operation can exercise "the
    // last write of a plan with more than one write in it".
    let (status, body) = call(
        &db,
        &env,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(&acme.token),
        Some(patch(&json!([{
            "op": "remove",
            "path": "members",
            "value": [{"value": first}, {"value": second}],
        }]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let events = events_about_group(&db, scope, &group, before + 3).await;
    let tail = event_types(&events)[before..].to_vec();
    assert_eq!(
        tail,
        vec![
            "org_group.member_removed",
            "org_group.member_removed",
            "org_group.membership_changed",
        ],
        "one delta, LAST: riding the first removal would announce a set change while the second \
         binding was still live"
    );
    let mut announced: Vec<String> = events[before + 2].payload["payload"]["removed_user_ids"]
        .as_array()
        .expect("the delta names who left")
        .iter()
        .map(|value| value.as_str().expect("a user id").to_owned())
        .collect();
    announced.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(announced, expected);
}

/// And the REPLACE path's removal loop, which is a different loop from the PATCH remove
/// (issue #136, criterion 4).
///
/// `set_members` removes as the tail of an operation that may also have added, so its "last
/// write" is the last write OVERALL rather than the last removal. A PUT that drops two people
/// and adds none is the smallest input that separates it from riding the first.
#[tokio::test]
async fn a_replace_that_drops_two_members_announces_one_delta_naming_both() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let first = provision(&db, &env, &acme.token, "first@example.com").await;
    let second = provision(&db, &env, &acme.token, "second@example.com").await;
    push_member(&db, &env, &acme.token, &group, &first).await;
    push_member(&db, &env, &acme.token, &group, &second).await;
    let before = events_about_group(&db, scope, &group, 4).await.len();

    let (status, body) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Groups/{group}"),
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "members": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let events = events_about_group(&db, scope, &group, before + 3).await;
    assert_eq!(
        event_types(&events)[before..],
        [
            "org_group.member_removed",
            "org_group.member_removed",
            "org_group.membership_changed",
        ]
    );
    let mut announced: Vec<String> = events[before + 2].payload["payload"]["removed_user_ids"]
        .as_array()
        .expect("the delta names who left")
        .iter()
        .map(|value| value.as_str().expect("a user id").to_owned())
        .collect();
    announced.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(announced, expected);
}

/// TWO CONNECTIONS ON ONE ORGANIZATION SHARE ONE BINDING, which is what migration 0188's
/// provenance note describes (issue #136, criterion 6).
///
/// The note used to say "measured" over behaviour nothing drove: `seed_provisioner` always
/// creates a NEW organization, so no test anywhere had two connections in one. This is that
/// test, and it pins all three consequences the note now states.
#[tokio::test]
async fn two_connections_on_one_organization_share_one_binding() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let second = second_connection(&db, &env, scope, &acme.organization, "s-second").await;

    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let user = provision(&db, &env, &acme.token, "shared@example.com").await;
    // Provisioned NOW, while the first connection's token is still live: it is revoked below.
    let third = provision(&db, &env, &acme.token, "third@example.com").await;
    push_member(&db, &env, &acme.token, &group, &user).await;

    // THE SECOND CONNECTION'S PUSH IS ACCEPTED AND WRITES NOTHING. The binding stays attributed
    // to the first, because there is one row per (group, membership) and it already exists.
    push_member(&db, &env, &second.token, &group, &user).await;

    // REVOKING THE FIRST REMOVES A BINDING THE SECOND STILL ASSERTS.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &acme.connection, now_micros(&env))
        .await
        .expect("revoke the first connection");
    assert!(
        members(&db, &env, &second.token, &group).await.is_empty(),
        "the second connection still asserts this membership and can no longer see it"
    );

    // AND ITS NEXT FULL-MEMBERSHIP SYNC REWRITES IT, which is the repair path the note names.
    let (status, body) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Groups/{group}"),
        Some(&second.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "members": [{"value": user}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        members(&db, &env, &second.token, &group).await,
        vec![user.clone()],
        "a full-membership sync must restore what the revoke removed, or the note's repair path \
         does not exist"
    );

    // AND THE SHARPER CASE: a replace reconciles against every existing binding regardless of
    // who wrote it, so one connection's ordinary sync DELETES another's binding whenever it does
    // not name that person. No revoke involved. This is why two connections should not push into
    // one group.
    push_member(&db, &env, &second.token, &group, &third).await;
    let (status, body) = call(
        &db,
        &env,
        "PUT",
        &format!("/scim/v2/Groups/{group}"),
        Some(&second.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "members": [{"value": third}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        members(&db, &env, &second.token, &group).await,
        vec![third],
        "a replace naming only its own person left the other one behind, so 0188's warning \
         describes something that does not happen"
    );
}

/// An operator CAN convert a connection's binding to their own, with two calls the management
/// surface already exposes (issue #136, criterion 5).
///
/// Migration 0188 used to say there was no way to do this. There is: remove the binding, add it
/// back with no source. It is not automatic and nothing prompts an operator to do it, which is
/// what the note says now.
#[tokio::test]
async fn an_operator_can_convert_a_pushed_binding_to_their_own() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_provisioner(&db, &env, scope, "Acme", "s-acme").await;
    let group = make_group(&db, &env, &acme.token, "Engineering").await;
    let group_id = ironauth_store::OrgGroupId::parse_in_scope(&group, &scope).expect("a group id");
    let role = define_role(&db, &env, scope, &acme.organization, "deployer").await;
    map_group_to_role(&db, &env, scope, &acme.organization, &group_id, &role).await;

    let user = provision(&db, &env, &acme.token, "converted@example.com").await;
    let subject = UserId::parse_in_scope(&user, &scope).expect("a user id");
    let membership = membership_of(&db, scope, &acme.organization, &subject).await;
    push_member(&db, &env, &acme.token, &group, &user).await;

    // THE CONVERSION: remove, then add back with no source.
    let acting = || {
        db.control_store()
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let binding = db
        .control_store()
        .management()
        .org_group_members(scope)
        .get_binding(&acme.organization, &group_id, &membership)
        .await
        .expect("the pushed binding");
    acting()
        .org_group_members(scope)
        .remove(&env, &acme.organization, &binding.id)
        .await
        .expect("the operator removes it");
    acting()
        .org_group_members(scope)
        .add(
            &env,
            ironauth_store::NewOrgGroupMember {
                id: &ironauth_store::OrgGroupMemberId::generate(&env, &scope),
                organization_id: &acme.organization,
                group_id: &group_id,
                membership_id: &membership,
                source_scim_connection_id: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("the operator adds it back as their own");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &acme.connection, now_micros(&env))
        .await
        .expect("revoke the connection");

    assert!(
        roles_of(&db, scope, &acme.organization, &subject)
            .await
            .contains("deployer"),
        "the converted binding did not survive the revoke, so 0188's account of what an \\
         operator can do is wrong"
    );
}
