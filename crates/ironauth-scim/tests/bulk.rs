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
            None,
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
        // AND THE OVER-LIMIT BATCH IS ANSWERED IDENTICALLY TO A FINE ONE, byte for byte.
        //
        // That is the property, and it is the only formulation that cannot be gamed. This
        // began as `!body.contains('2') || !body.contains("maxOperations")` -- and no refusal
        // here contains the literal `maxOperations`, so the right disjunct was always true and
        // the assertion could not fail; a review measured the authenticate call moved below the
        // limit checks and this line still reporting ok. The obvious repair, scanning for the
        // limit numbers as substrings, is the same mistake one layer down: `"2"` occurs in
        // `urn:...:2.0:Error`, so it failed on the schema URN of a refusal that leaked nothing.
        //
        // Comparing the two responses asks the real question instead: can an unauthenticated
        // caller tell an over-limit batch from a fine one? If the limits were checked first,
        // one of these is a 413 naming a number and the other a 401, and they differ.
        let (fine_status, fine_body) = call_with(
            &db,
            &env,
            "POST",
            "/scim/v2/Bulk",
            token,
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations": [{"method": "POST", "path": "/Users", "bulkId": "one"}],
            })),
            limits,
        )
        .await;
        assert_eq!(
            (status, &body),
            (fine_status, &fine_body),
            "an unauthenticated caller can tell an over-limit batch from a fine one, so the \
             limits are being checked before the credential is"
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
    // AND EACH CARRIES ITS `response`. This arm was missed when the pre-dispatch refusals
    // gained one, so the refusal a client is most likely to hit by hand was the one giving a
    // spec-following client nothing to read -- and the test that claims to cover "every failed
    // operation" drives no 405 at all.
    for result in &results[..2] {
        assert_eq!(
            result["response"]["status"].as_str(),
            Some("405"),
            "a 405 must carry the RFC's `response` field like every other refusal: {result}"
        );
    }
    assert_eq!(
        results[2]["status"].as_str(),
        Some("201"),
        "the legal operation beside them still ran: {body}"
    );
}

/// `failOnErrors: 0` runs the batch and stops at the first failure; it does not run nothing.
///
/// The budget check sits at the top of the loop, so a literal `0` broke before the first
/// operation: a review measured `{"failOnErrors":0}` with two valid creates answering
/// `200 OK` with an empty `Operations` array and nothing provisioned, while the client that
/// sent it meant "tolerate no errors". A batch that ran nothing and reported success is the
/// worst answer available, and it is the bound-satisfied-by-zero shape -- ask what degenerate
/// input satisfies a check.
#[tokio::test]
async fn fail_on_errors_zero_still_runs_the_batch_and_stops_at_the_first_failure() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    // ALL VALID: a budget of zero must not stop a batch that never fails.
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "failOnErrors": 0,
            "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": "a", "data": user("a@example.com")},
                {"method": "POST", "path": "/Users", "bulkId": "b", "data": user("b@example.com")},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        operations(&body).len(),
        2,
        "failOnErrors: 0 ran no operations at all: {body}"
    );
    let (_, listed) = call(&db, &env, "GET", "/scim/v2/Users", Some(&acme.token), None).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["totalResults"].as_u64(),
        Some(2),
        "a batch that reported two creates provisioned none: {listed}"
    );

    // AND IT STILL STOPS AT THE FIRST FAILURE, which is what the client asking for zero
    // tolerance wanted. Without this half the fix above would have turned the field off.
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "failOnErrors": 0,
            "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": "bad", "data": {"nonsense": 1}},
                {"method": "POST", "path": "/Users", "bulkId": "never", "data": user("n@example.com")},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        operations(&body).len(),
        1,
        "a zero budget must stop at the first failure: {body}"
    );
}

/// A path inside a batch is read no more permissively than the router reads the same one.
///
/// `parse_resource_path` stripped one trailing slash unconditionally so the collection form
/// `/Groups/` would work. That made `/Users/{id}/` an item path HERE while axum's router
/// refuses it, so an operation inside a batch was routed by a laxer reading than the same
/// request sent alone -- measured: `GET /scim/v2/Users/{id}/` alone answered 404, and
/// `{"method":"PATCH","path":"/Users/{id}/"}` inside a batch APPLIED the patch.
///
/// Not exploitable across organizations -- the id was unchanged and the membership fence still
/// held -- but it is a surviving second interpretation of a path, which is the one property
/// this module claims to have eliminated.
///
/// Both directions: the collection form must still work, or the fix has broken what the strip
/// existed for.
#[tokio::test]
async fn a_trailing_slash_is_read_the_same_way_inside_a_batch_as_the_router_reads_it() {
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
        Some(user("slash@example.com")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // THE ROUTER'S ANSWER to the item path with a trailing slash, measured rather than assumed.
    let (single, _) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{id}/"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(
        single,
        StatusCode::NOT_FOUND,
        "the premise of this test is that the router refuses an item path with a trailing \
         slash; if that changed, the batch's answer should change with it"
    );

    // The BATCH must not be more permissive.
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "PATCH", "path": format!("/Users/{id}/"), "bulkId": "slash",
                 "data": {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                          "Operations": [{"op": "replace", "path": "active", "value": false}]}},
                // The COLLECTION form, which the strip existed for and must still work.
                {"method": "POST", "path": "/Groups/", "bulkId": "collection",
                 "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                          "displayName": "Engineering"}},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = operations(&body);
    assert_eq!(
        results[0]["status"].as_str(),
        Some("400"),
        "an item path with a trailing slash must be refused inside a batch too: {body}"
    );
    assert_eq!(
        results[1]["status"].as_str(),
        Some("201"),
        "the COLLECTION form must still work, or the fix broke what the strip was for: {body}"
    );

    // And the patch did not apply.
    let (_, after) = call(
        &db,
        &env,
        "GET",
        &format!("/scim/v2/Users/{id}"),
        Some(&acme.token),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&after).expect("json")["active"].as_bool(),
        Some(true),
        "the refused operation deactivated the user anyway: {after}"
    );
}

/// A malformed envelope is REFUSED, not answered `200` with an empty `Operations` array.
///
/// `schemas` and `Operations` are both `#[serde(default)]`, so `{}` and a batch whose
/// `Operations` key is misspelled both parsed into an empty request. The handler's own doc says
/// the presence of `Operations` in the response is how a client tells a batch that RAN from one
/// that was refused, so answering `200 {"Operations":[]}` to a typo made the stated
/// discriminator not discriminate. `patch_user` in this same crate already checked its URN and
/// refused an empty operation list; two doors, two rules.
#[tokio::test]
async fn a_malformed_bulk_envelope_is_refused_rather_than_answered_as_an_empty_batch() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    for (label, envelope) in [
        ("an empty object", json!({})),
        (
            "a misspelled Operations key",
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operatons": [{"method": "POST", "path": "/Users"}],
            }),
        ),
        (
            "no schema URN",
            json!({"Operations": [{"method": "POST", "path": "/Users"}]}),
        ),
        (
            "the wrong schema URN",
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"method": "POST", "path": "/Users"}],
            }),
        ),
    ] {
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Bulk",
            Some(&acme.token),
            Some(envelope),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} was answered as a batch rather than refused: {body}"
        );
        assert!(
            body.contains("urn:ietf:params:scim:api:messages:2.0:Error"),
            "{label}: the refusal is a SCIM document: {body}"
        );
        assert!(
            !body.contains("\"Operations\""),
            "{label}: a REFUSED batch must not carry Operations, which is the discriminator \
             this handler documents: {body}"
        );
    }
}

/// One operation with a broken SHAPE costs its own slot, not the whole batch.
///
/// `method` was a required `String`, so an operation that named none failed the ENVELOPE parse
/// and took every valid sibling with it: a review measured a two-operation batch answering
/// `400 the request body is not a SCIM bulk request`, with the valid create never run and
/// nothing saying which operation was bad. That is the retry-all-fifty outcome this module's
/// header opens by condemning, while the header claimed the opposite.
///
/// The refusal also carries a `response`, because RFC 7644 section 3.7.3 defines that field for
/// the operation body and defines no operation-level `detail`: a client written to the RFC read
/// nothing at all for the refusals most likely to happen.
#[tokio::test]
async fn a_broken_operation_shape_refuses_that_operation_rather_than_the_batch() {
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
                {"path": "/Users", "bulkId": "no-method"},
                {"method": "POST", "path": "/Users", "bulkId": "fine", "data": user("f@example.com")},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = operations(&body);
    assert_eq!(results.len(), 2, "{body}");
    assert_eq!(results[0]["status"].as_str(), Some("400"), "{body}");
    assert_eq!(
        results[1]["status"].as_str(),
        Some("201"),
        "the valid sibling of a malformed operation still ran: {body}"
    );
    let (_, listed) = call(&db, &env, "GET", "/scim/v2/Users", Some(&acme.token), None).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["totalResults"].as_u64(),
        Some(1),
        "{listed}"
    );

    // EVERY failed operation carries a `response`, whether it failed before dispatch or during
    // it. A client reading the RFC's field must not get nothing for the pre-dispatch half.
    let (status, body) = call(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "GET", "path": "/Users", "bulkId": "bad-method"},
                {"method": "PATCH", "path": "/Users/%2e%2e", "bulkId": "bad-path"},
                {"method": "PATCH", "path": "/Groups/bulkId:x", "bulkId": "bad-ref"},
                {"method": "PATCH", "path": "/Users/usr_nobody", "bulkId": "dispatched",
                 "data": {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                          "Operations": [{"op": "replace", "path": "active", "value": false}]}},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for result in operations(&body) {
        assert_eq!(
            result["response"]["schemas"][0].as_str(),
            Some("urn:ietf:params:scim:api:messages:2.0:Error"),
            "every failed operation must carry the RFC's `response` field, including the ones \
             refused before dispatch: {result}"
        );
    }
}

/// A payload over the CONFIGURED bulk budget is refused, and the refusal names that budget.
///
/// `validate_bulk`'s payload arm is unreachable at the shipped defaults, because
/// `max_payload_bytes` equals `MAX_REQUEST_BYTES` and the request bound fires first. So nothing
/// drove it: a review replaced the entire arm with an empty result -- answering
/// `200 {"Operations":[]}` to an over-budget batch -- and the whole suite stayed green, while
/// the handler's doc named a test that deliberately does the opposite (it sets the payload
/// budget to the default so only the operation count can fire).
///
/// This is the configuration the arm exists for: an operator who wants batches smaller than the
/// request bound.
#[tokio::test]
async fn a_payload_over_the_configured_bulk_budget_is_refused_by_name() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    // A payload budget well below the request bound, and an operation count high enough that
    // it cannot be what refuses: the two limits answer the same status, so a batch tripping
    // both could not say which one fired.
    let limits = ScimLimits {
        bulk: ironauth_scim::BulkLimits {
            max_operations: 1000,
            max_payload_bytes: 400,
        },
        ..ScimLimits::default()
    };

    // UNDER the budget: accepted. Without this half the refusal below would pass against a
    // route that refused every batch.
    let (status, body) = call_with(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": "s", "data": user("s@example.com")},
            ],
        })),
        limits,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a small batch must be accepted: {body}"
    );

    // OVER it: refused, and the refusal names the PAYLOAD budget rather than the count.
    let padding = "p".repeat(600);
    let (status, body) = call_with(
        &db,
        &env,
        "POST",
        "/scim/v2/Bulk",
        Some(&acme.token),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": &padding,
                 "data": user("big@example.com")},
            ],
        })),
        limits,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a batch over the configured payload budget must be refused: {body}"
    );
    assert!(
        body.contains("payload may be at most 400 bytes"),
        "the refusal must name the PAYLOAD budget, not the operation count: {body}"
    );

    // And nothing from the refused batch landed: exactly the one user the accepted batch made.
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
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["totalResults"].as_u64(),
        Some(1),
        "the refused batch wrote rows anyway: {listed}"
    );
}

/// A WRONG-TYPED operation field costs that operation, not the batch.
///
/// `Option<String>` was half a repair: it tolerates ABSENT and never WRONG-TYPED, so
/// `{"path": 5}` still failed the envelope parse and took every valid sibling with it, while
/// the field's own doc claimed it had cured "a missing `method` or a non-string `path`". A
/// review measured both the behaviour and the fact that nothing in the suite noticed either
/// way: making `path` accept any JSON left the whole suite green.
///
/// Each field is driven separately, because one shared assertion would pass if only one of the
/// three had been widened.
#[tokio::test]
async fn a_wrong_typed_operation_field_costs_that_operation_rather_than_the_batch() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme", "s-acme").await;

    for (field, bad) in [
        (
            "path",
            json!({"method": "POST", "path": 5, "bulkId": "bad"}),
        ),
        (
            "method",
            json!({"method": 7, "path": "/Users", "bulkId": "bad"}),
        ),
        (
            "bulkId",
            json!({"method": "POST", "path": "/Users", "bulkId": ["a"]}),
        ),
    ] {
        let (status, body) = call(
            &db,
            &env,
            "POST",
            "/scim/v2/Bulk",
            Some(&acme.token),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations": [
                    bad,
                    {"method": "POST", "path": "/Users", "bulkId": "fine",
                     "data": user(&format!("{field}@example.com"))},
                ],
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a wrong-typed {field} killed the whole envelope: {body}"
        );
        let results = operations(&body);
        assert_eq!(results.len(), 2, "{field}: {body}");
        assert_eq!(
            results[0]["status"].as_str(),
            Some("400"),
            "{field}: {body}"
        );
        assert!(
            results[0]["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains(field)),
            "the refusal must name the field that was wrong-typed: {body}"
        );
        assert_eq!(
            results[1]["status"].as_str(),
            Some("201"),
            "{field}: the valid sibling still ran: {body}"
        );
    }
}

/// A path with no leading slash is refused, so one collection has one spelling.
///
/// `parse_resource_path` stripped an OPTIONAL leading slash, so `Users` and `/Users` both
/// addressed the collection -- measured over the real route: `{"method":"POST","path":"Users"}`
/// created a user. RFC 7644 section 3.7.2 writes the path with the slash, and two spellings for
/// one collection is a second interpretation of a path, which is the property this module
/// exists to remove.
#[tokio::test]
async fn a_path_without_its_leading_slash_is_refused() {
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
                {"method": "POST", "path": "Users", "bulkId": "no-slash",
                 "data": user("noslash@example.com")},
                // The spelled-correctly control, so the refusal is about the slash and not
                // about this fixture.
                {"method": "POST", "path": "/Users", "bulkId": "slash",
                 "data": user("slash@example.com")},
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = operations(&body);
    assert_eq!(
        results[0]["status"].as_str(),
        Some("400"),
        "a path with no leading slash must be refused: {body}"
    );
    assert_eq!(
        results[1]["status"].as_str(),
        Some("201"),
        "the correctly spelled sibling must still work: {body}"
    );
    let (_, listed) = call(&db, &env, "GET", "/scim/v2/Users", Some(&acme.token), None).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["totalResults"].as_u64(),
        Some(1),
        "the refused spelling created a user anyway: {listed}"
    );
}
