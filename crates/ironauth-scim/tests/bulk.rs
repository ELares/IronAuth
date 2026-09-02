// SPDX-License-Identifier: MIT OR Apache-2.0

//! `POST /scim/v2/Bulk` over the real router (issue #135, criteria 4 and 5).
//!
//! # What this file is for
//!
//! Criterion 4 is that "bulk requests respect advertised limits and return per-operation
//! results". `bulk.rs`'s unit tests pin the validator; this file pins the ROUTE, because the
//! validator existed for a release while `scim_router` mounted no `/Bulk` at all and the
//! discovery document advertised the capability anyway.
//!
//! # And the batch is where criterion 5 gets interesting
//!
//! A bulk request is a list of paths inside ONE authorized request, which is exactly the shape
//! an attacker would hope earns a laxer reading than a single request does. So the
//! cross-organization cases here are driven THROUGH the batch: same hostile paths, same
//! foreign ids, same encodings, wrapped in a batch a valid token authorizes.
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

/// [`call`] with explicit limits, so a test can DRIVE a bound rather than assert about it.
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

/// The `Operations` array of a bulk response, or a panic naming what came back instead.
fn operations(body: &str) -> Vec<Value> {
    let parsed: Value = serde_json::from_str(body).unwrap_or_else(|_| panic!("not JSON: {body}"));
    assert_eq!(
        parsed["schemas"][0].as_str(),
        Some("urn:ietf:params:scim:api:messages:2.0:BulkResponse"),
        "a bulk response names its schema: {body}"
    );
    parsed["Operations"]
        .as_array()
        .unwrap_or_else(|| panic!("a bulk response carries Operations: {body}"))
        .clone()
}

fn user(user_name: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name,
        "active": true,
    })
}

#[tokio::test]
async fn a_batch_creates_every_user_in_it_and_each_result_names_where_its_resource_landed() {
    // The straight-through case, and the half that a limits-only test cannot see: the
    // operations RUN. `validate_bulk` alone would have passed a route that parsed fifty paths
    // and wrote nothing, so what this asserts is that each user is afterwards retrievable at
    // the location its own result reported.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": "a", "data": user("ada@example.com")},
                {"method": "POST", "path": "/Users", "bulkId": "b", "data": user("grace@example.com")},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = operations(&body);
    assert_eq!(results.len(), 2, "{body}");

    for (index, expected_bulk_id) in ["a", "b"].iter().enumerate() {
        let result = &results[index];
        assert_eq!(
            result["status"].as_str(),
            Some("201"),
            "operation {expected_bulk_id} did not create: {body}"
        );
        assert_eq!(
            result["bulkId"].as_str(),
            Some(*expected_bulk_id),
            "the correlation id is echoed so a client can match its result: {body}"
        );
        // AND THE RESOURCE IS THERE. This is what separates "the batch ran" from "the batch
        // parsed": follow the location the result reported and read the user back.
        let location = result["location"]
            .as_str()
            .unwrap_or_else(|| panic!("a created operation reports its location: {body}"));
        let (status, fetched) = call(&db, &env, "GET", location, Some(&acme.token), None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the location a bulk result reported does not resolve: {fetched}"
        );
    }

    // The two locations are DIFFERENT, which is the assertion that fails if every result
    // reported the same id -- a result set that looks complete while one operation's outcome
    // was reported for another's.
    assert_ne!(
        results[0]["location"], results[1]["location"],
        "two creates reported the same location: {body}"
    );
}

#[tokio::test]
async fn one_operations_failure_does_not_discard_the_others_and_carries_its_own_error() {
    // The per-operation-results half of criterion 4. A client told only "the request failed"
    // has to retry all fifty operations to find the one bad path.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": "ok-1", "data": user("first@example.com")},
                // A body that is not a SCIM user at all: the handler's own parse refuses it.
                {"method": "POST", "path": "/Users", "bulkId": "bad", "data": json!({"nonsense": 1})},
                {"method": "POST", "path": "/Users", "bulkId": "ok-2", "data": user("third@example.com")},
            ],
        })),
    )
    .await;
    // THE BATCH SUCCEEDED even though an operation inside it did not. A batch that ran is not
    // a batch that was refused.
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = operations(&body);
    assert_eq!(results.len(), 3, "{body}");
    assert_eq!(results[0]["status"].as_str(), Some("201"), "{body}");
    assert_eq!(results[1]["status"].as_str(), Some("400"), "{body}");
    assert_eq!(
        results[2]["status"].as_str(),
        Some("201"),
        "the operation AFTER the failure still ran: {body}"
    );

    // The failed operation carries the error document it would have received on its own
    // (RFC 7644 section 3.7.3), so a client debugging one operation out of fifty reads the
    // same SCIM error rather than a sentence this route invented.
    assert_eq!(
        results[1]["response"]["schemas"][0].as_str(),
        Some("urn:ietf:params:scim:api:messages:2.0:Error"),
        "a failed operation carries its own SCIM error: {body}"
    );
    // And a SUCCESSFUL one does not carry a response body: fifty resource documents in one
    // response is the shape this deliberately does not produce.
    assert!(
        results[0]["response"].is_null(),
        "a successful operation must not echo its resource: {body}"
    );
    // The two successes landed and the failure did not, so the batch is not all-or-nothing in
    // either direction.
    let (_, listed) = call(&db, &env, "GET", "/scim/v2/Users", Some(&acme.token), None).await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        parsed["totalResults"].as_u64(),
        Some(2),
        "exactly the two good creates landed: {listed}"
    );
}

#[tokio::test]
async fn the_advertised_limits_are_the_enforced_ones_over_the_real_route() {
    // Criterion 4's first half, driven end to end rather than asserted about a struct. The
    // numbers are READ OUT OF THE PUBLISHED DOCUMENT, so this cannot pass against a route that
    // enforces a different limit from the one it advertises.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    // THE PAYLOAD BUDGET IS DELIBERATELY GENEROUS. Both limits refuse with the same status,
    // so a batch that trips BOTH cannot say which one fired -- and it was measured: with
    // `max_payload_bytes: 400`, deleting the operations-count check entirely left this test
    // green, because the three-operation batch was over the byte budget anyway. The default
    // mebibyte leaves only the count able to refuse, and the assertion on the detail below
    // says which limit the server named.
    let limits = ScimLimits {
        bulk: ironauth_scim::BulkLimits {
            max_operations: 2,
            max_payload_bytes: ironauth_scim::BulkLimits::default().max_payload_bytes,
        },
        ..ScimLimits::default()
    };
    let (_, config) = call_with(
        &db,
        &env,
        "GET",
        "/scim/v2/ServiceProviderConfig",
        Some(&acme.token),
        None,
        limits,
    )
    .await;
    let document: Value = serde_json::from_str(&config).expect("json");
    let advertised = usize::try_from(
        document["bulk"]["maxOperations"]
            .as_u64()
            .expect("an advertised maximum"),
    )
    .expect("the advertised maximum fits a usize");

    let batch = |count: usize| {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": (0..count)
                .map(|index| json!({
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": index.to_string(),
                    "data": user(&format!("u{index}@example.com")),
                }))
                .collect::<Vec<_>>(),
        })
    };

    // AT the advertised limit: accepted. Without this half a route that refused every batch
    // would pass the refusal below.
    let (status, body) = call_with(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(batch(advertised)),
        limits,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a batch AT the advertised maximum must be accepted: {body}"
    );

    // ONE PAST it: refused, as a SCIM error, and the refusal names the advertised number so a
    // client can resize without guessing.
    let (status, body) = call_with(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(batch(advertised + 1)),
        limits,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a batch past the advertised maximum must be refused: {body}"
    );
    assert!(
        body.contains("urn:ietf:params:scim:api:messages:2.0:Error"),
        "the refusal is a SCIM document: {body}"
    );
    assert!(
        body.contains(&advertised.to_string()),
        "the refusal names the advertised limit: {body}"
    );
    // AND NAMES WHICH LIMIT. Both bounds answer 413, so a status-only assertion passes when
    // the payload budget refused a batch the operation count was supposed to refuse.
    assert!(
        body.contains("operations"),
        "the refusal must name the OPERATION COUNT as the limit it enforced, not the payload \
         budget: {body}"
    );
    // AND NOTHING FROM THE REFUSED BATCH LANDED. A limit enforced after doing the work is not
    // a limit, and only this assertion can tell the two apart.
    let (_, listed) = call_with(
        &db,
        &env,
        "GET",
        "/scim/v2/Users",
        Some(&acme.token),
        None,
        limits,
    )
    .await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        parsed["totalResults"].as_u64(),
        Some(advertised as u64),
        "the refused batch wrote rows anyway: {listed}"
    );
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_bulk_batch_earns_no_laxer_reading_than_the_single_requests_it_wraps() {
    // CRITERION 5, THROUGH THE BATCH. A bulk request is a list of paths inside one authorized
    // request, which is exactly where an attacker would hope the path parser were laxer.
    //
    // Every hostile path here is one `tests/users.rs` drives as a single request. Driving them
    // again through the batch is not duplication: it is the only way to see a `/Bulk` that
    // resolved paths its own way, and a batch is the one place a second path reader would be
    // easy to introduce.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;
    let globex = seed_org(&db, &env, scope, "Globex", "s-globex").await;

    // A real person in Globex, so the cross-organization operations address a row that EXISTS.
    // Against an id that never existed, a refusal proves nothing: the answer would be the same
    // from a server with no fence at all.
    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&globex.token),
        Some(user("victim@example.com")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let victim = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // And a person Acme legitimately owns, for the smuggled-tail case below.
    let (status, created) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Users",
        Some(&acme.token),
        Some(user("mine@example.com")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let mine = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Acme's token, addressing Globex's person, every way a batch lets it.
    let hostile = vec![
        json!({"method": "PATCH", "path": format!("/Users/{victim}"), "bulkId": "direct",
               "data": {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{"op": "replace", "path": "active", "value": false}]}}),
        json!({"method": "DELETE", "path": format!("/Users/{victim}"), "bulkId": "delete"}),
        json!({"method": "PUT", "path": format!("/Users/{victim}"), "bulkId": "replace",
               "data": user("stolen@example.com")}),
        json!({"method": "PATCH", "path": "/Users/%2e%2e", "bulkId": "encoded-traversal"}),
        json!({"method": "PATCH", "path": "/Users/%252e%252e", "bulkId": "double-encoded"}),
        json!({"method": "PATCH", "path": "/Users/../Groups/x", "bulkId": "traversal"}),
        json!({"method": "PATCH", "path": format!("/Users/{victim}/../{victim}"), "bulkId": "rejoin"}),
        // THE CASE THAT SEPARATES THE STRICT PARSER FROM A LAX ONE, and the reason it is
        // written against a person Acme OWNS. Every other entry here is refused by the
        // organization fence whatever the path parser did, so a `/Bulk` that split the path
        // itself and kept only the first two segments would pass all of them -- measured: that
        // exact mutation survived this test until this line existed. Here the first two
        // segments address a person Acme may legitimately PATCH, so a lax reader answers 2xx
        // and the loop below fails; the strict parser refuses the path as a whole.
        json!({"method": "PATCH", "path": format!("/Users/{mine}/../{victim}"), "bulkId": "smuggled-tail",
               "data": {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{"op": "replace", "path": "active", "value": false}]}}),
        json!({"method": "DELETE", "path": format!("/Groups/{victim}"), "bulkId": "wrong-type"}),
    ];
    let count = hostile.len();

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": hostile,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the batch itself runs: {body}");
    let results = operations(&body);
    assert_eq!(results.len(), count, "{body}");
    for result in &results {
        let status = result["status"].as_str().unwrap_or("");
        assert!(
            !status.starts_with('2'),
            "a cross-organization or hostile operation SUCCEEDED inside a batch: {result} \
             (full response: {body})"
        );
    }

    // AND THE VICTIM IS UNTOUCHED, read back through their OWN organization's token. The
    // statuses above say what Acme was told; this says what actually happened to the row, and
    // they are different questions -- a handler that answered 404 and deactivated anyway would
    // pass the loop and fail here.
    let (status, after) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{victim}"),
        Some(&globex.token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the batch deleted a person in another organization: {after}"
    );
    let parsed: Value = serde_json::from_str(&after).expect("json");
    assert_eq!(
        parsed["userName"].as_str(),
        Some("victim@example.com"),
        "the batch rewrote a person in another organization: {after}"
    );
    assert_eq!(
        parsed["active"].as_bool(),
        Some(true),
        "the batch deactivated a person in another organization: {after}"
    );

    // And Acme's OWN person is untouched too, which is the other half of the smuggled-tail
    // case: a lax reader would have deactivated them while the client believed it was
    // addressing somebody else entirely.
    let (_, mine_after) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{mine}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&mine_after).expect("json")["active"].as_bool(),
        Some(true),
        "a multi-segment path was read as its first two segments and hit a real person: \
         {mine_after}"
    );
}

#[tokio::test]
async fn a_bulk_request_without_a_credential_reaches_nothing_and_reveals_no_limit() {
    // Authentication runs BEFORE the envelope is parsed and before the limits are checked. The
    // limits are the advertised numbers, and a surface that reports them to an unauthenticated
    // caller has published its own budget.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let _acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let limits = ScimLimits {
        bulk: ironauth_scim::BulkLimits {
            max_operations: 2,
            max_payload_bytes: 400,
        },
        ..ScimLimits::default()
    };
    let over_the_limit = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations": (0..50)
            .map(|index| json!({"method": "POST", "path": "/Users", "bulkId": index.to_string()}))
            .collect::<Vec<_>>(),
    });

    for token in [None, Some("scim_notarealhandle.whatever")] {
        let (status, body) = call_with(
            &db,
            &env,
            "POST",
            "/scim/v2/Bulk",
            token,
            Some(over_the_limit.clone()),
            limits,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(
            body.contains("urn:ietf:params:scim:api:messages:2.0:Error"),
            "the refusal is a SCIM document: {body}"
        );
        // The batch was 50 operations against a limit of 2, so a route that checked limits
        // first would answer 413 and name the number.
        assert!(
            !body.contains('2') || !body.contains("maxOperations"),
            "the refusal leaked an advertised limit to an unauthenticated caller: {body}"
        );
    }
}

#[tokio::test]
async fn fail_on_errors_stops_the_batch_and_the_unattempted_operations_are_absent() {
    // RFC 7644 section 3.7.3. A client that sets `failOnErrors` is saying "stop after this many
    // failures", and the operations never attempted are simply absent from the response --
    // which is why a client reads the results rather than assuming its batch ran to the end.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let operations_sent = json!([
        {"method": "POST", "path": "/Users", "bulkId": "bad-1", "data": {"nonsense": 1}},
        {"method": "POST", "path": "/Users", "bulkId": "never", "data": user("never@example.com")},
        {"method": "POST", "path": "/Users", "bulkId": "also-never", "data": user("also@example.com")},
    ]);

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "failOnErrors": 1,
            "Operations": operations_sent.clone(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = operations(&body);
    assert_eq!(
        results.len(),
        1,
        "failOnErrors: 1 must stop after the first failure: {body}"
    );
    assert_eq!(results[0]["bulkId"].as_str(), Some("bad-1"), "{body}");
    let (_, listed) = call(&db, &env, "GET", "/scim/v2/Users", Some(&acme.token), None).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["totalResults"].as_u64(),
        Some(0),
        "the operations after the budget was spent must not have run: {listed}"
    );

    // THE CONTROL. The SAME batch without `failOnErrors` runs to the end, so the assertion
    // above is about the field and not about a route that stops at the first failure always.
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": operations_sent,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        operations(&body).len(),
        3,
        "without failOnErrors every operation is attempted: {body}"
    );
}

#[tokio::test]
async fn a_method_the_path_does_not_offer_is_that_operations_405_rather_than_the_batchs() {
    // A POST to an item and a PUT to a collection. The single-request router answers 405 for
    // both; inside a batch that has to be one operation's result, not the batch's status.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "POST", "path": "/Users/usr_somebody", "bulkId": "post-item"},
                {"method": "PUT", "path": "/Users", "bulkId": "put-collection"},
                {"method": "POST", "path": "/Users", "bulkId": "fine", "data": user("fine@example.com")},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = operations(&body);
    assert_eq!(results[0]["status"].as_str(), Some("405"), "{body}");
    assert_eq!(results[1]["status"].as_str(), Some("405"), "{body}");
    assert_eq!(
        results[2]["status"].as_str(),
        Some("201"),
        "the legal operation beside them still ran: {body}"
    );
}
